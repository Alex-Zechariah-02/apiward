// The migrate probes command: boundary probes of an exchange file, for comparing the gateway with the source.

package migrate

import (
	"errors"
	"fmt"
	"io"

	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
	"github.com/Alex-Zechariah-02/apiward/internal/openapi"
	"github.com/Alex-Zechariah-02/apiward/internal/probe"
)

const probesUsage = `gateway migrate probes --exchange <file> --out <new probes.json>`

// runProbes writes the probes of the operations migrate policy would
// import, with the gateway's expected class and ledger item of each.
func runProbes(values map[string]string, stderr io.Writer) (int, error) {
	if format, err := openapi.FormatOf(values["out"]); err != nil || format != openapi.JSON {
		return openapi.ExitFailed, errors.New("the probe file must be a new .json file")
	}
	_, root, _, err := readDocument(values["exchange"], "exchange")
	if err != nil {
		return openapi.ExitFailed, err
	}
	document, ledger, err := exchange.Split(root)
	if err != nil {
		return openapi.ExitFailed, err
	}
	file, err := probe.Generate(document, ledger, probe.Options{MaxBodyBytes: openapi.DefaultBodyBytes})
	if err != nil {
		return openapi.ExitFailed, err
	}
	if err := openapi.WriteOne(values["out"], file); err != nil {
		return openapi.ExitFailed, err
	}
	fmt.Fprintf(stderr, "wrote %d probes to %s\n", len(file.Probes), values["out"])
	return openapi.ExitComplete, nil
}
