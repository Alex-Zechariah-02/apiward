// Command demo prepares and runs the local demonstration of the gateway. It
// writes private demonstration configuration, runs Fetch Accounts, the four
// business APIs and the gateway, resets synthetic data and prints security
// events. Policy and key commands use the protected Admin API as the signed-in
// operator. Application tokens are issued only by Fetch Accounts.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/apiward/examples/fetch/internal/ports"
)

// The demonstration addresses. The administrator dashboard and the data plane
// are on different loopback hosts because browsers scope cookies by host, not
// port: the administrator's session cookie must never accompany a data-plane
// request forwarded to a business service.
var (
	adminListen   = "127.0.0.1:9440"
	dataListen    = "127.0.0.2:9480"
	metricsListen = "127.0.0.1:9450"
)

const (
	issuerName  = "fetch-accounts"
	audience    = "fetch-gateway"
	maxTokenTTL = 15 * time.Minute
)

// demoService is one Fetch API and its control listener.
type demoService struct {
	name, listen, control string
}

var fetchServices = []demoService{
	{"inventory", "127.0.0.1:9501", "127.0.0.1:9601"},
	{"orders", "127.0.0.1:9502", "127.0.0.1:9602"},
	{"reports", "127.0.0.1:9503", "127.0.0.1:9603"},
	{"support", "127.0.0.1:9504", "127.0.0.1:9604"},
	{"accounts", "127.0.0.1:9505", "127.0.0.1:9605"},
}

// Resolve the process's environment once. Invalid offsets stop the command
// before it opens deployment state or starts any process.
var portSetupError = applyDemoPortOffset()

func applyDemoPortOffset() error {
	addresses := []*string{&adminListen, &dataListen, &metricsListen}
	for i := range fetchServices {
		addresses = append(addresses, &fetchServices[i].listen, &fetchServices[i].control)
	}
	for _, address := range addresses {
		value, err := ports.Offset(*address)
		if err != nil {
			return err
		}
		*address = value
	}
	return nil
}

// Files inside the demonstration directory.
const (
	configFile     = "gateway.json"
	privateKeyFile = "issuer-key.pem"
	publicKeyFile  = "issuer.pem"
	secretFile     = "service.secret"
	signingFile    = "accounts.json"
	auditFile      = "audit.log"
	databaseFile   = "state.db"
	baselineFile   = "baseline.json"
	denyAllFile    = "deny-all.json"
)

const usage = `usage:
  demo up     [-home H] [-fresh] [-stdin]
  demo setup  -dir D -web W -gateway G [-admin NAME]
  demo run    -dir D -gateway G -services S -accounts A [-stdin]
  demo token  -dir D -subject ID [-ttl 15m]
  demo reset  -dir D
  demo attack -dir D -scenario flood-search|flood-login|flood-orders [-from 127.0.0.50] [-count N]
  demo keys rotate -dir D
  demo keys retire -dir D -kid K
  demo policy export -dir D -out F
  demo policy stage -dir D -file F
  demo events -dir D [-request ID] [-last N]`

func main() {
	if portSetupError != nil {
		fmt.Fprintln(os.Stderr, "demo:", portSetupError)
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	commands := map[string]func([]string) error{
		"up":     up,
		"setup":  setup,
		"run":    run,
		"token":  token,
		"reset":  reset,
		"events": events,
		"attack": attack,
		"keys":   keys,
		"policy": policy,
	}
	command, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err := command(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

// parse reads a command's flags and requires -dir.
func parse(set *flag.FlagSet, args []string) (string, error) {
	dir := set.String("dir", "", "demonstration directory")
	if err := set.Parse(args); err != nil {
		return "", err
	}
	if *dir == "" || set.NArg() != 0 {
		return "", errors.New("-dir is required and no other arguments are accepted\n" + usage)
	}
	return filepath.Abs(*dir)
}
