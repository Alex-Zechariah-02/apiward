// Fuzzing of the bounded JSON decoder, which reads request bodies and policy
// documents from untrusted senders.

package policy

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

// FuzzDecodeJSON checks that the decoder never panics, refuses only with its
// documented reasons, accepts nothing encoding/json would refuse, and reads
// its own re-encoded value as the same value.
func FuzzDecodeJSON(f *testing.F) {
	for _, seed := range []string{
		`{"a":1}`, `[1,2.5e3,"x",null,true]`, `{"a":1,"a":2}`, `{"a":{"a":[]}}`,
		`"\ud800"`, `"😀"`, `1 2`, `[[[[[[[[`, "{\"\xff\":1}", `1e999999`, `-0`, ``,
	} {
		f.Add([]byte(seed))
	}
	reasons := []string{"invalid_encoding", "malformed_json", "duplicate_member", "limit_exceeded", "trailing_data"}
	f.Fuzz(func(t *testing.T, data []byte) {
		value, reason := DecodeJSON(data)
		if reason != "" {
			if value != nil || !slices.Contains(reasons, reason) {
				t.Fatalf("refusal %q with value %v", reason, value)
			}
			return
		}
		if !json.Valid(data) {
			t.Fatal("accepted a document encoding/json refuses")
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("accepted value does not encode: %v", err)
		}
		again, reason := DecodeJSON(encoded)
		if reason != "" || !reflect.DeepEqual(value, again) {
			t.Fatalf("re-encoded value read as %v (%q), want %v", again, reason, value)
		}
	})
}
