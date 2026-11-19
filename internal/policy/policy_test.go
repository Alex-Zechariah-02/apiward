// Policy decoding problems name the member that caused them.

package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/module"
)

func TestUnknownFieldNamed(t *testing.T) {
	head := `{"schema_version":4,"profile":"core"`
	for _, tc := range []struct{ name, document, field string }{
		{"unknown member", head + `,"extra":1}`, "extra"},
		{"case variant", head + `,"Profile":"core"}`, "Profile"},
		{"nested member", head + `,"upstreams":[{"id":"a","dial":"127.0.0.1:1","weight":2}]}`, "weight"},
	} {
		_, err := DecodePolicy([]byte(tc.document), Limits{})
		var problem *PolicyError
		if !errors.As(err, &problem) || problem.Code != "UNKNOWN_FIELD" || problem.Field != tc.field {
			t.Errorf("%s: %v, want UNKNOWN_FIELD naming %q", tc.name, err, tc.field)
		}
	}
}

// settingsProbe is a module whose settings are any JSON object.
type settingsProbe struct{}

func (settingsProbe) Info() module.Info {
	return module.Info{ID: "probe_settings", Phase: module.Validate, Version: "1.0.0"}
}

func (settingsProbe) Compile(module.Operation, json.RawMessage) (module.Check, error) {
	return nil, nil
}

var registerProbe = sync.OnceFunc(func() { module.Register(settingsProbe{}) })

// A module's settings belong to the module: their member names are not
// held to the policy's lower-case rule, as a schema's are not, while
// repeated names are still refused and the operation's own members still
// follow the rule.
func TestModuleSettingNames(t *testing.T) {
	registerProbe()
	operation := `{"id":"o","api":"a","method":"GET","target":"/o","access":"allow","auth":"none",%s}`
	document := func(member string) []byte {
		return []byte(`{"schema_version":4,"profile":"core","operations":[` + fmt.Sprintf(operation, member) + `]}`)
	}
	p, err := DecodePolicy(document(`"probe_settings":{"maxItems":2,"$ref":"#/x","x-Tag":{"Inner":true}}`), Limits{})
	if err != nil || string(p.Operations[0].Modules["probe_settings"]) == "" {
		t.Fatalf("module settings refused: %v", err)
	}
	for name, member := range map[string]string{
		"repeated setting":      `"probe_settings":{"maxItems":1,"maxItems":2}`,
		"operation member case": `"probe_settings":{},"Extra":1`,
	} {
		if _, err := DecodePolicy(document(member), Limits{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
