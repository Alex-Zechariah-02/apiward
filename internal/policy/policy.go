// Policy document types, limits and strict decoding.

package policy

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
)

// SchemaVersion is the policy document version written when nothing newer
// is needed; LatestSchemaVersion adds upstream URLs, TLS profiles and the
// Host header choice. The compiler accepts both, and compiles a version 4
// document exactly as before version 5 existed.
const (
	SchemaVersion       = 4
	LatestSchemaVersion = 5
)

// ProfileCore is the only enforcement profile that can be activated. Under it
// the gateway enforces routing, the per-operation access flag, bearer JWT
// authentication and role permits on every operation declared auth
// "required", the operation's rate rule, its body and header schemas, and the
// mandatory audit record before forwarding. Any other profile is rejected
// rather than activated with controls it cannot run.
const ProfileCore = "core"

// MaxTokenRoles bounds the roles one token may carry, whatever the policy's
// role ceiling: it is part of the token size bound.
// MaxTargetLength and MaxUpstreamURL: a policy's path and URL strings stay short to match and parse.
const (
	// MaxPolicyDepth: deeper than any policy document needs, so the member scan's stack stays small.
	MaxPolicyDepth   = 16
	MaxTokenRoles    = 64
	MaxIDLength      = 64
	MaxSubjectLength = 128
	MaxTargetLength  = 256
	MaxUpstreamURL   = 2048
	MaxBodyLimit     = 1 << 20
)

// Policy is the complete permanent policy document. Every publication carries
// a whole document; there is no partial update.
type Policy struct {
	SchemaVersion int         `json:"schema_version"`
	Profile       string      `json:"profile"`
	Upstreams     []Upstream  `json:"upstreams"`
	APIs          []API       `json:"apis"`
	Operations    []Operation `json:"operations"`
	Roles         []Role      `json:"roles"`
	Permits       []Permit    `json:"permits"`
}

// Upstream is one entry of the closed destination inventory. It holds
// exactly one of Dial (a loopback address, plain HTTP) or URL (version 5: an
// http or https origin); TLS names a TLS profile and Host chooses the Host
// header ("inbound" or "upstream"), both only with URL.
type Upstream struct {
	ID   string `json:"id"`
	Dial string `json:"dial,omitempty"`
	URL  string `json:"url,omitempty"`
	TLS  string `json:"tls,omitempty"`
	Host string `json:"host,omitempty"`
}

// Operation binds a method and target of an API to an access decision and
// the controls that apply to it.
type Operation struct {
	ID      string          `json:"id"`
	API     string          `json:"api"`
	Method  string          `json:"method"`
	Target  string          `json:"target"`
	Access  string          `json:"access"`
	Auth    string          `json:"auth"`
	Body    *BodyRule       `json:"body,omitempty"`
	Headers json.RawMessage `json:"headers,omitempty"` // JSON Schema for declared request headers
	Rate    *RateRule       `json:"rate,omitempty"`
	When    *When           `json:"when,omitempty"`
	// Modules holds the members named by compiled-in modules other than the
	// built-ins, keyed by module ID; it is encoded as those members.
	Modules map[string]json.RawMessage `json:"-"`
}

// BodyRule declares a JSON request body, its size ceiling and the JSON Schema
// it must satisfy. An operation without a BodyRule accepts no request body.
type BodyRule struct {
	MaxBytes int64           `json:"max_bytes"`
	Schema   json.RawMessage `json:"schema"`
}

// RateRule limits requests to an operation by verified subject or direct
// client address within a sliding window.
type RateRule struct {
	Algorithm     string `json:"algorithm"`
	Count         int64  `json:"count"`
	WindowSeconds int64  `json:"window_seconds"`
	Key           string `json:"key"`
}

// Role is a flat role identifier.
type Role struct {
	ID string `json:"id"`
}

// Permit grants a role an operation. Roles have no hierarchy: a permit
// applies to the named role only.
type Permit struct {
	Role      string `json:"role"`
	Operation string `json:"operation"`
}

// PolicyError is a typed candidate rejection. Field is the JSON path of the
// offending value when one applies.
type PolicyError struct {
	Code  string
	Field string
}

func (e *PolicyError) Error() string {
	if e.Field == "" {
		return e.Code
	}
	return e.Code + " at " + e.Field
}

func Invalid(code, field string, args ...any) *PolicyError {
	return &PolicyError{Code: code, Field: fmt.Sprintf(field, args...)}
}

// methods: the methods an operation may bind; the gateway routes and
// forwards exactly these. Unexported, so no package can change routing.
var methods = [...]string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// MethodCount is how many methods an operation may bind.
const MethodCount = len(methods)

// IsMethod reports whether an operation may bind method.
func IsMethod(method string) bool { return slices.Contains(methods[:], method) }

// DecodePolicy parses a policy document. It rejects input larger than
// limits.PolicyBytes (zero: the default) or deeply nested, repeated or
// non-lowercase member names, unknown fields, unsupported schema versions and
// trailing data. Limits out of range are refused as LIMITS_INVALID, a
// document over limits.PolicyBytes as POLICY_TOO_LARGE.
func DecodePolicy(document []byte, limits Limits) (Policy, error) {
	limits, err := limits.Resolve()
	if err != nil {
		return Policy{}, Invalid("LIMITS_INVALID", "")
	}
	if len(document) > limits.PolicyBytes {
		return Policy{}, Invalid("POLICY_TOO_LARGE", "policy_bytes")
	}
	modules := moduleIDs()
	if err := checkMembers(document, MaxPolicyDepth, modules); err != nil {
		return Policy{}, err
	}
	// Module members are taken out first; the scan above has refused the
	// repeated and case-folded names a map decoding would merge.
	stripped, taken, err := takeModules(document, modules)
	if err != nil {
		return Policy{}, cmp.Or(versionError(document), err)
	}
	var p Policy
	if err := DecodeStrict(stripped, &p); err != nil {
		return Policy{}, decodeError(stripped, err)
	}
	if p.SchemaVersion != SchemaVersion && p.SchemaVersion != LatestSchemaVersion {
		return Policy{}, Invalid("SCHEMA_VERSION_UNSUPPORTED", "schema_version")
	}
	for i, members := range taken {
		if len(members) > 0 && i < len(p.Operations) {
			p.Operations[i].Modules = members
		}
	}
	return p, nil
}

// decodeError explains a failed strict decoding of document. A document
// written for another version is reported as such rather than as a set of
// unknown fields; then an unknown member by name, a mistyped one by path.
func decodeError(document []byte, err error) error {
	if refused := versionError(document); refused != nil {
		return refused
	}
	if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return Invalid("SCHEMA_INVALID", "%s", typeErr.Field)
	}
	if name, found := unknownMember(document, reflect.TypeFor[Policy]()); found {
		return Invalid("UNKNOWN_FIELD", "%s", Clip(name))
	}
	return Invalid("SCHEMA_INVALID", "")
}

// versionError refuses a document whose version cannot be read or is not
// supported; nil when the version is supported.
func versionError(document []byte) error {
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if json.Unmarshal(document, &header) != nil {
		return Invalid("SCHEMA_INVALID", "")
	}
	if header.SchemaVersion != SchemaVersion && header.SchemaVersion != LatestSchemaVersion {
		return Invalid("SCHEMA_VERSION_UNSUPPORTED", "schema_version")
	}
	return nil
}

// DecodeStrict decodes exactly one JSON value, rejecting unknown fields and
// anything after the value.
func DecodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}
