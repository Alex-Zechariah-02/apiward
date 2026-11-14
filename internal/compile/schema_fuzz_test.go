// Fuzzing of an operator's body schema against a client's body.

package compile

import (
	"encoding/json"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// FuzzSchemaBody compiles an arbitrary body schema and validates an
// arbitrary request body against it: neither may panic, and validation of
// the same document must give the same answer twice.
func FuzzSchemaBody(f *testing.F) {
	f.Add([]byte(`{"type":"object","properties":{"a":{"type":"string","maxLength":4}},"required":["a"],"additionalProperties":false}`), []byte(`{"a":"x"}`))
	f.Add([]byte(`{"type":"array","items":{"type":"integer","minimum":0},"maxItems":3}`), []byte(`[1,2,3,4]`))
	f.Add([]byte(`{"type":"object","properties":{"a":{"type":"string","pattern":"^(a+)+$"}}}`), []byte(`{"a":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}`))
	f.Add([]byte(`{"type":"object","$ref":"#"}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, schema, body []byte) {
		compiled, _, err := CompileSchema(json.RawMessage(schema), SchemaBody, "body")
		if err != nil {
			return
		}
		document, reason := policy.DecodeJSON(body)
		if reason != "" {
			return
		}
		first := compiled.Validate(document) == nil
		second := compiled.Validate(document) == nil
		if first != second {
			t.Fatalf("schema %s gave two answers for %s", schema, body)
		}
	})
}
