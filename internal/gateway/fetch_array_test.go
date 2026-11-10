// Fetch JSON array body schemas: compilation and refusals.

package gateway

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestFetchArraySchemas(t *testing.T) {
	const items = `{"type":"array","minItems":1,"maxItems":2,"items":{"type":"object","additionalProperties":false,"required":["item","quantity"],"properties":{"item":{"type":"string","minLength":7,"maxLength":7},"quantity":{"type":"integer","minimum":1,"maximum":50}}}}`
	for _, wrapped := range []bool{false, true} {
		schema := items
		if wrapped {
			schema = `{"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":` + items + `}}`
		}
		p := schemaPolicy(schema)
		g, err := compile.Compile(p, 1, time.Time{}, policy.Limits{})
		if err != nil {
			t.Errorf("wrapped=%t: array schema refused: %v", wrapped, err)
			continue
		}
		_, operation := g.Match("/orders", "POST", compile.Inbound{})
		for _, tc := range []struct {
			body string
			ok   bool
		}{
			{`[{"item":"ITM-001","quantity":1}]`, true},
			{`[{"item":"ITM-001","quantity":1},{"item":"ITM-002","quantity":50}]`, true},
			{`[]`, false},
			{`[{"item":"ITM-001","quantity":1},{"item":"ITM-001","quantity":1},{"item":"ITM-001","quantity":1}]`, false},
			{`[{"item":"ITM-001","quantity":0}]`, false},
			{`[{"item":"ITM-001","quantity":51}]`, false},
			{`[{"item":"ITM-001","quantity":1,"price_sen":1}]`, false},
			{`[{"item":"ITM-001"}]`, false},
			{`[null]`, false},
			{`{}`, false},
		} {
			body := tc.body
			if wrapped {
				body = `{"items":` + body + `}`
			}
			document, reason := policy.DecodeJSON([]byte(body))
			if reason != "" {
				t.Fatal(reason)
			}
			if got := pipeline.ValidateRequest(nil, document, operation) == ""; got != tc.ok {
				t.Errorf("wrapped=%t body %s: valid=%t, want %t", wrapped, body, got, tc.ok)
			}
		}
	}
}

func TestFetchArraySchemaRefusals(t *testing.T) {
	for _, tc := range []struct{ schema, code string }{
		{`{"type":"array"}`, "INVALID_VALUE"},
		{`{"type":"array","items":true}`, "UNSUPPORTED_FEATURE"},
		{`{"type":"array","items":{"type":"string","pattern":"x"}}`, "UNSUPPORTED_FEATURE"},
		{`{"type":"array","items":{"type":"string"},"minItems":-1}`, "INVALID_VALUE"},
		{`{"type":"array","items":{"type":"string"},"maxItems":1.5}`, "INVALID_VALUE"},
		{`{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":1}`, "INVALID_VALUE"},
		{`{"type":"array","items":{"type":"string"},"maxItems":4097}`, "INVALID_VALUE"},
		{`{"type":"array","items":{"type":"string"},"uniqueItems":true}`, "UNSUPPORTED_FEATURE"},
		{`{"type":"object","additionalProperties":true,"items":{"type":"string"}}`, "INVALID_VALUE"},
	} {
		_, _, err := compile.CompileSchema(json.RawMessage(tc.schema), compile.SchemaBody, "body")
		if code := errorCode(err); code != tc.code {
			t.Errorf("%s: %v, want %s", tc.schema, err, tc.code)
		}
	}
	if _, _, err := compile.CompileSchema(json.RawMessage(`{"type":"array","items":{"type":"string"}}`), compile.SchemaHeaders, "headers"); err == nil {
		t.Fatal("header root accepted an array")
	}
}
