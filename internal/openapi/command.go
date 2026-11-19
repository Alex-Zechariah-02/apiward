// The policy subcommands (import-openapi, export-openapi, validate): flags,
// the capacity limits they check against, and what each runs.

package openapi

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Synopses of the commands.
const (
	importUsage = `apiward policy import-openapi --spec <file.json|.yaml|.yml> --api <id> --upstream <id>
  --base <policy.json> [--max-body-bytes <n>] [--with-permits] [--config <settings>] --out <new file> --report <new file>`
	exportUsage = `apiward policy export-openapi --policy <policy.json> --api <id>
  --out <new file.json|.yaml|.yml> --report <new file> [--with-upstream] [--config <settings>]`
	validateUsage = `apiward policy validate --policy <policy.json> [--config <settings>]`
)

// command is one subcommand: its flags and what it runs once they parse.
type command struct {
	usage    string
	required []string
	optional map[string]string // flag → default
	switches []string
	run      func(values map[string]string, limits policy.Limits, stderr io.Writer) (int, error)
}

// LimitsReader reads the capacity limits of the gateway settings file at a
// path, as the gateway resolves them.
type LimitsReader func(path string) (policy.Limits, error)

var commands = map[string]command{
	"import-openapi": {importUsage, []string{"spec", "api", "upstream", "base", "out", "report"},
		map[string]string{"max-body-bytes": strconv.Itoa(DefaultBodyBytes), "config": ""}, []string{"with-permits"}, runImport},
	"validate":       {validateUsage, []string{"policy"}, map[string]string{"config": ""}, nil, runValidate},
	"export-openapi": {exportUsage, []string{"policy", "api", "out", "report"}, map[string]string{"config": ""}, []string{"with-upstream"}, runExport},
}

// Command runs "policy <subcommand>" and returns the exit status. It reads
// only the files named by flags and creates only the out and report files;
// an unknown subcommand, or a bad command line, prints the usage. With
// --config, read gives the deployment's limits; without, the defaults apply.
func Command(args []string, stderr io.Writer, read LimitsReader) int {
	var c command
	known := len(args) > 0
	if known {
		c, known = commands[args[0]]
	}
	if !known {
		fmt.Fprintln(stderr, "usage: "+importUsage+"\n       "+exportUsage+"\n       "+validateUsage)
		return ExitFailed
	}
	values, err := c.parse(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, "apiward:", err)
		if errors.Is(err, errUsage) {
			fmt.Fprintln(stderr, "usage: "+c.usage)
		}
		return ExitFailed
	}
	code, err := c.start(values, read, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "apiward:", err)
		return ExitFailed
	}
	return code
}

// start resolves the limits and runs the command.
func (c command) start(values map[string]string, read LimitsReader, stderr io.Writer) (int, error) {
	var limits policy.Limits
	if path := values["config"]; path != "" {
		var err error
		if limits, err = read(path); err != nil {
			return ExitFailed, fmt.Errorf("settings file: %w", err)
		}
	}
	limits, err := limits.Resolve()
	if err != nil {
		return ExitFailed, err
	}
	return c.run(values, limits, stderr)
}

// errUsage marks an error that the command line itself caused.
var errUsage = errors.New("invalid command line")

// single is a flag value that may be given only once.
type single struct {
	value string
	set   bool
}

func (f *single) String() string { return f.value }

func (f *single) Set(value string) error {
	if f.set {
		return errors.New("given more than once")
	}
	f.value, f.set = value, true
	return nil
}

// toggle is a switch that may be given only once.
type toggle struct{ single }

func (f *toggle) IsBoolFlag() bool { return true }

func (c command) parse(args []string) (map[string]string, error) {
	set := flag.NewFlagSet("apiward", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	values := map[string]string{}
	for _, name := range c.required {
		set.Var(new(single), name, name)
	}
	for name, value := range c.optional {
		values[name] = value
		set.Var(new(single), name, name)
	}
	for _, name := range c.switches {
		set.Var(new(toggle), name, name)
	}
	if err := set.Parse(args); err != nil {
		return nil, fmt.Errorf("%w: %v", errUsage, err)
	}
	if set.NArg() != 0 {
		return nil, errUsage
	}
	set.Visit(func(f *flag.Flag) { values[f.Name] = f.Value.String() })
	for _, name := range c.required {
		if values[name] == "" {
			return nil, fmt.Errorf("%w: --%s is required", errUsage, name)
		}
	}
	return values, nil
}

func runImport(values map[string]string, limits policy.Limits, stderr io.Writer) (int, error) {
	format, err := formatOf(values["spec"])
	if err != nil {
		return ExitFailed, err
	}
	maxBody, err := strconv.ParseInt(values["max-body-bytes"], 10, 64)
	if err != nil {
		return ExitFailed, fmt.Errorf("max-body-bytes must be 1 to %d", policy.MaxBodyLimit)
	}
	spec, err := readLimited(values["spec"], MaxSpecBytes, "spec")
	if err != nil {
		return ExitFailed, err
	}
	base, err := readPolicy(values["base"], "base", limits)
	if err != nil {
		return ExitFailed, err
	}
	result, report, err := Import(spec, format, Options{API: values["api"], Upstream: values["upstream"], Base: base,
		MaxBodyBytes: maxBody, WithPermits: values["with-permits"] == "true", Limits: limits})
	if err != nil {
		return ExitFailed, err
	}
	if err := write(values["out"], result, values["report"], report); err != nil {
		return ExitFailed, err
	}
	fmt.Fprintf(stderr, "imported %d of %d operations (%d widened, %d refused); see %s\n",
		len(report.Mapped)+len(report.Widened), report.OperationsInSpec, len(report.Widened), len(report.Refused), values["report"])
	return report.Exit(), nil
}

func runExport(values map[string]string, limits policy.Limits, stderr io.Writer) (int, error) {
	format, err := formatOf(values["out"])
	if err != nil {
		return ExitFailed, err
	}
	source, err := readPolicy(values["policy"], "policy", limits)
	if err != nil {
		return ExitFailed, err
	}
	document, report, err := Export(source, ExportOptions{API: values["api"], WithUpstream: values["with-upstream"] == "true", Limits: limits})
	if err != nil {
		return ExitFailed, err
	}
	data, err := encode(document, format)
	if err != nil {
		return ExitFailed, err
	}
	if err := write(values["out"], json.RawMessage(data), values["report"], report); err != nil {
		return ExitFailed, err
	}
	fmt.Fprintf(stderr, "exported %d of %d operations (%d changed); see %s\n",
		len(report.Exported), report.Operations, len(report.Changed), values["report"])
	return report.Exit(), nil
}

// runValidate decodes and compiles a policy file as the gateway does a
// candidate, with the default capacity limits or a deployment's, and prints
// its warnings; for
// policy kept in Git and checked in CI. Upstream addresses and TLS profiles
// depend on the gateway's settings and are checked when it is activated.
func runValidate(values map[string]string, limits policy.Limits, stderr io.Writer) (int, error) {
	source, err := readPolicy(values["policy"], "policy", limits)
	if err != nil {
		return ExitFailed, err
	}
	g, err := compile.Compile(source, 0, time.Time{}, limits)
	if err != nil {
		return ExitFailed, fmt.Errorf("policy refused: %w", checkedLimits(err, limits))
	}
	for _, warning := range g.Warnings() {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	fmt.Fprintln(stderr, "the policy is valid")
	return ExitComplete, nil
}

// readPolicy reads and strictly decodes a policy file within limits.
func readPolicy(path, name string, limits policy.Limits) (policy.Policy, error) {
	document, err := readLimited(path, int64(limits.PolicyBytes), name)
	if err != nil {
		return policy.Policy{}, err
	}
	p, err := policy.DecodePolicy(document, limits)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("%s policy refused: %w", name, err)
	}
	return p, nil
}
