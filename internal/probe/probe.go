// The probe file: probes, the classes of decisions, and the request a probe stands for.

package probe

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// Version is the only probe file version written.
const Version = 1

// Class is the kind of decision a gateway makes for a request.
type Class string

const (
	Forwarded  Class = "forwarded"  // the upstream received it (seen at the upstream, never inferred from a status)
	NotFound   Class = "not_found"  // no route takes the path
	Method     Class = "method"     // a route takes the path, not the method
	Authn      Class = "authn"      // the caller is not signed in
	Authz      Class = "authz"      // the caller, its address or the operation is refused
	Rate       Class = "rate"       // over the rate limit
	Validation Class = "validation" // the request or its body is invalid
	Size       Class = "size"       // the body is too large
	Error      Class = "error"      // the gateway could not complete it
	// A preflight's answer, as a browser checks it: it may send the request, or it may not.
	PreflightAllowed Class = "preflight_allowed"
	PreflightRefused Class = "preflight_refused"
)

// BodyKind is the body a probe sends.
type BodyKind string

const (
	NoBody    BodyKind = "none"
	Valid     BodyKind = "valid"    // built from the operation's schema
	Invalid   BodyKind = "invalid"  // JSON of the wrong type for the schema
	Oversized BodyKind = "oversize" // a valid body one byte over the limit
)

// Identities a probe presents besides role:<id>.
const (
	NoRole     = "no_role" // a valid token holding no role
	rolePrefix = "role:"   // a valid token holding one role
)

// Client is the only address probes are sent from.
var Client = netip.MustParseAddr("127.0.0.1")

// File is the probe file.
type File struct {
	Version int     `json:"version"`
	Probes  []Probe `json:"probes"`
}

// Probe is one request and the gateway's expected decision. Headers may
// hold Host; a preflight's hold Origin and Access-Control-Request-*. A probe of class rate stands for a burst of the limit's count
// plus one, judged on its last request; a probe of class error is sent with
// the upstream stopped.
type Probe struct {
	ID        string            `json:"id"`
	Operation string            `json:"operation"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	BodyKind  BodyKind          `json:"body_kind"`
	Identity  string            `json:"identity"`
	Expect    Expect            `json:"expect"`
}

// Expect is the gateway's class and the ledger item that predicts a
// difference from the source on this probe.
type Expect struct {
	Class      Class  `json:"class"`
	LedgerItem string `json:"ledger_item"`
}

// Encode writes the probe file as indented JSON.
func (f *File) Encode() ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}

// Request is what the reference evaluator decides on.
type Request struct {
	Method, Path, Host string
	Header             http.Header
	Token              semantics.Token
	Roles              []string
	Body               BodyKind
	Size               int64 // body bytes
	Client             netip.Addr
}

// Request returns the request the probe stands for with a body of size bytes.
func (p Probe) Request(size int64) Request {
	header := http.Header{}
	host := ""
	for name, value := range p.Headers {
		if strings.EqualFold(name, "Host") {
			host = value
			continue
		}
		header.Set(name, value)
	}
	token, roles := semantics.Token(p.Identity), []string(nil)
	switch {
	case p.Identity == NoRole:
		token = semantics.ValidToken
	case strings.HasPrefix(p.Identity, rolePrefix):
		token, roles = semantics.ValidToken, []string{strings.TrimPrefix(p.Identity, rolePrefix)}
	}
	return Request{Method: p.Method, Path: p.Path, Host: host, Header: header, Token: token, Roles: roles,
		Body: p.BodyKind, Size: size, Client: Client}
}

// Role returns the role a role:<id> identity holds, or "".
func Role(identity string) string {
	role, _ := strings.CutPrefix(identity, rolePrefix)
	if role == identity {
		return ""
	}
	return role
}
