// The native gateway's command line: the commands, their options, and the
// version command; run starts the gateway in native.go.

package gateway

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/Alex-Zechariah-02/apiward/internal/admin"
	"github.com/Alex-Zechariah-02/apiward/internal/operator"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

const nativeUsage = `usage: apiward run --config <file>
  apiward version
  apiward health --config <file>
  apiward install --config <file> --admin <name>
  apiward enrol --config <file> --admin <name> --permissions <list>
  apiward migrate --config <file>
  apiward jwks --config <file>
  apiward backup --config <file> --output <file>
  apiward restore --config <file> --backup <file>
  apiward recover-clock --config <file>
  apiward policy import-openapi --spec <file> --api <id> --upstream <id> --base <file> --out <file> --report <file> [--config <file>]
  apiward policy export-openapi --policy <file> --api <id> --out <file> --report <file> [--config <file>]
  apiward policy validate --policy <file> [--config <file>]
  apiward audit verify --jwks <file> <files...>`

// Main runs the native gateway command line and returns the exit status.
// Every diagnostic is a JSON log line on stderr; the usage text is printed
// as it is, after the line that says what was wrong.
func Main(args []string) int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	// Packages without a logger of their own report through the default.
	slog.SetDefault(logger)
	if len(args) == 0 {
		logger.Error("no command given")
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	command := args[0]
	switch command {
	case "version":
		return printVersion(args[1:], logger)
	case "help", "-h", "--help":
		// Asked for: the usage on standard output, and no failure.
		fmt.Println(nativeUsage)
		return 0
	}
	options := []string{"config"}
	switch command {
	case "run", "migrate", "health", "jwks", "recover-clock":
	case "install":
		options = append(options, "admin")
	case "enrol":
		options = append(options, "admin", "permissions")
	case "backup":
		options = append(options, "output")
	case "restore":
		options = append(options, "backup")
	default:
		logger.Error("unknown command", "command", command)
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	parsed := map[string]*onceFlag{}
	for _, name := range options {
		value := new(onceFlag)
		parsed[name] = value
		set.Var(value, name, "required "+name)
	}
	if err := set.Parse(args[1:]); err != nil || set.NArg() != 0 {
		logger.Error("invalid command line", "command", command, "error", fmt.Sprint(err), "arguments", set.Args())
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	values := map[string]string{}
	for _, name := range options {
		if parsed[name].value == "" {
			logger.Error("--"+name+" is required", "command", command)
			fmt.Fprintln(os.Stderr, nativeUsage)
			return exitFailed
		}
		values[name] = parsed[name].value
	}
	switch command {
	case "run":
		return runNative(values["config"], logger)
	case "health":
		return checkHealth(values["config"], logger)
	case "jwks":
		return printJWKS(values["config"], logger)
	}
	cfg, err := loadNativeConfig(values["config"])
	if err == nil {
		err = cfg.controller.Check()
	}
	if err == nil {
		_, err = pipeline.LoadVerifier(cfg.controller.JWT)
	}
	if err != nil {
		logger.Error("command refused", "command", command, "error", err)
		return exitFailed
	}
	code, err := operator.Run(command, operatorConfig(cfg), values)
	if err != nil {
		logger.Error("command failed", "command", command, "error", err)
	}
	return code
}

// onceFlag is a flag that may be given only once, so a command line cannot
// name two configuration files of which one would be silently ignored.
type onceFlag struct {
	value string
	set   bool
}

func (f *onceFlag) String() string { return f.value }

func (f *onceFlag) Set(value string) error {
	if f.set {
		return errors.New("given more than once")
	}
	f.value, f.set = value, true
	return nil
}

// printVersion runs the version command, which takes no options and reads no
// configuration.
func printVersion(args []string, logger *slog.Logger) int {
	if len(args) != 0 {
		logger.Error("version takes no options", "arguments", args)
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	if _, err := fmt.Print(admin.VersionText()); err != nil {
		logger.Error("version not written", "error", err)
		return exitFailed
	}
	return 0
}
