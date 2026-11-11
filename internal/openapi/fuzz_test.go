// Fuzzing of the OpenAPI importer, which reads a description supplied from
// outside the gateway, in JSON or YAML.

package openapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// FuzzImport checks that no description makes the importer panic, and that
// every policy it returns is one the gateway's decoder and compiler accept.
func FuzzImport(f *testing.F) {
	f.Add(fixture(f, "orders.json"), false)
	f.Add(fixture(f, "refusals.json"), false)
	f.Add(fixture(f, "orders.yaml"), true)
	f.Add(fixture(f, "refusals.yaml"), true)
	f.Add([]byte(`{"openapi":"3.1.0","paths":{"/a":{"get":{}}}}`), false)
	f.Add([]byte("a: &a [*a]\n"), true)
	f.Fuzz(func(t *testing.T, spec []byte, yaml bool) {
		format := JSON
		if yaml {
			format = YAML
		}
		result, report, err := Import(spec, format, testOptions())
		if err != nil {
			return
		}
		if report == nil {
			t.Fatal("accepted a description without a report")
		}
		document, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := policy.DecodePolicy(document, policy.Limits{})
		if err != nil {
			t.Fatalf("imported policy is refused by the decoder: %v", err)
		}
		if _, err := compile.Compile(decoded, 1, time.Time{}, policy.Limits{}); err != nil {
			t.Fatalf("imported policy is refused by the compiler: %v", err)
		}
	})
}
