// Command apiward runs the security policy gateway on its own Go HTTP server,
// from one strict native configuration file, and its local operator commands.
package main

import (
	"os"

	"github.com/Alex-Zechariah-02/apiward/internal/gateway"
	"github.com/Alex-Zechariah-02/apiward/internal/openapi"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run sends policy subcommands to the OpenAPI tools, audit subcommands to
// the audit chain check and everything else to the gateway.
func run(args []string) int {
	if len(args) > 0 && args[0] == "policy" {
		return openapi.Command(args[1:], os.Stderr, gateway.PolicyLimits)
	}
	if len(args) > 0 && args[0] == "audit" {
		return auditCommand(args[1:], os.Stdout, os.Stderr)
	}
	return gateway.Main(args)
}
