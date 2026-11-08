// The gateway configuration file a deployment runs with, and the default
// policy over its three receivers.

package gatewaytest

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// WriteConfig writes the gateway configuration file for opts, filling the
// defaults ConfigOptions names.
func (e *Env) WriteConfig(opts ConfigOptions) {
	if opts.HeaderTimeout == "" {
		opts.HeaderTimeout = "5s"
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = 16384
	}
	if opts.JWT == nil {
		opts.JWT = TestTrust(issuertest.Name, issuertest.Audience, e.PublicKey)
	}
	gateway := map[string]any{
		"database":       e.Database,
		"audit_log":      e.AuditLog,
		"admin_listen":   e.Admin,
		"metrics_listen": e.Metrics,
		"jwt":            opts.JWT,
	}
	maps.Copy(gateway, opts.Audit)
	maps.Copy(gateway, opts.Admin)
	settings := e.NativeSettings()
	settings["gateway"] = gateway
	Section(settings, "data")["max_body_bytes"] = opts.MaxBodyBytes
	Section(settings, "upstream")["response_header_timeout"] = opts.HeaderTimeout
	e.WriteNative(settings)
}

// NativeSettings is the configuration of e's deployment, as the JSON object
// WriteNative writes. A test may change it first.
func (e *Env) NativeSettings() map[string]any {
	return map[string]any{
		"version": ConfigVersion,
		"gateway": map[string]any{
			"database":       e.Database,
			"audit_log":      e.AuditLog,
			"admin_listen":   e.Admin,
			"metrics_listen": e.Metrics,
			"jwt":            TestTrust(issuertest.Name, issuertest.Audience, e.PublicKey),
		},
		"data": map[string]any{"listen": e.DataAddr},
	}
}

// Section returns the named object of native settings.
func Section(settings map[string]any, name string) map[string]any {
	s, ok := settings[name].(map[string]any)
	if !ok {
		s = map[string]any{}
		settings[name] = s
	}
	return s
}

// WriteNative writes settings as e's configuration file.
func (e *Env) WriteNative(settings map[string]any) {
	e.T.Helper()
	document, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		e.T.Fatal(err)
	}
	e.WriteNativeFile(document)
}

// WriteNativeFile writes content, exactly as given, as e's configuration
// file.
func (e *Env) WriteNativeFile(content []byte) {
	e.T.Helper()
	e.Config = filepath.Join(e.Dir, "gateway.json")
	if err := os.WriteFile(e.Config, content, 0o600); err != nil {
		e.T.Fatal(err)
	}
}

// Policy builds the standard test policy: /a/* and POST /a/item go to the
// given upstream, /d is denied, and /b/* exists only when withB is set. Every
// operation is public, so routing behaviour is tested without tokens.
func (e *Env) Policy(aTarget *Receiver, withB bool) policy.Policy {
	p := policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: e.A.Addr}, {ID: "B", Dial: e.B.Addr}},
		APIs:          []policy.API{{ID: "a", Upstream: aTarget.Name}, {ID: "b", Upstream: "B"}, {ID: "d", Upstream: "A"}},
		Operations: []policy.Operation{
			{ID: "read-a", API: "a", Method: "GET", Target: "/a/*", Access: "allow", Auth: "none"},
			{ID: "write-a", API: "a", Method: "POST", Target: "/a/item", Access: "allow", Auth: "none", Body: JSONBody(1024, AnyObject)},
			{ID: "denied", API: "d", Method: "GET", Target: "/d", Access: "deny", Auth: "none"},
		},
	}
	if withB {
		p.Operations = append(p.Operations, policy.Operation{ID: "read-b", API: "b", Method: "GET", Target: "/b/*", Access: "allow", Auth: "none"})
	}
	return p
}
