// Package policy is the policy document an administrator writes for the
// gateway: its types, strict decoding, the canonical encoding (one byte form
// per meaning, so two policies compare byte for byte) and an offline check
// of how a policy decides a described request.
//
// The types are the gateway's own; a policy built or changed here is
// accepted or refused by the gateway exactly as written. Publishing a policy
// is never done here: it goes through the gateway's Admin API and its
// confirmed activation.
package policy

import (
	"fmt"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	document "github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// The policy document's types.
type (
	Policy          = document.Policy
	Upstream        = document.Upstream
	API             = document.API
	Forward         = document.Forward
	CORS            = document.CORS
	ResponseHeaders = document.ResponseHeaders
	Operation       = document.Operation
	BodyRule        = document.BodyRule
	RateRule        = document.RateRule
	Role            = document.Role
	Permit          = document.Permit
	When            = document.When
	HeaderCondition = document.HeaderCondition
	// PolicyError is a refusal: a stable code and the field it concerns.
	PolicyError = document.PolicyError
)

// SchemaVersion is the policy schema version written when nothing newer is
// needed; LatestSchemaVersion adds upstream URLs, TLS profiles and the Host
// header choice. The gateway reads both. ProfileCore is the only profile it
// supports.
const (
	SchemaVersion       = document.SchemaVersion
	LatestSchemaVersion = document.LatestSchemaVersion
	ProfileCore         = document.ProfileCore
)

// Decode strictly decodes a policy document: unknown, repeated or
// non-lower-case members, anything after the document and a document larger
// than the gateway's default limit are refused with a *PolicyError. It checks
// the document's shape; Check also checks what it means, against the
// gateway's default capacity limits.
func Decode(data []byte) (Policy, error) { return document.DecodePolicy(data, document.Limits{}) }

// Encode returns the canonical form of p: 2-space JSON with members in
// struct order and a trailing newline, lists sorted where their order
// carries no meaning. It fails only on a schema that is not valid JSON.
func Encode(p Policy) ([]byte, error) { return document.Encode(p) }

// Request describes a request to check. Roles stand for a verified token's
// roles; Host and Headers for the request's, which conditions select by.
type Request struct {
	Method  string
	Path    string
	Host    string
	Headers map[string]string
	Roles   []string
}

// Decision is how a policy decides a Request. Check and Code name the
// refusing check and its error code; NotChecked lists what an offline check
// cannot decide.
type Decision = compile.Answer

// Check compiles p as the gateway would publish it and decides req in the
// request handler's order: route, access, roles, forward path. It cannot
// check a token, rate limits, bodies, blocked accounts or addresses, which
// need a running gateway. A policy the gateway would refuse is returned as
// its *PolicyError; an invalid request names the refused field.
func Check(p Policy, req Request) (Decision, error) {
	generation, err := compile.Compile(p, 0, time.Time{}, document.Limits{})
	if err != nil {
		return Decision{}, err
	}
	question, field := compile.NewQuestion(req.Method, req.Path, req.Host, req.Headers, req.Roles)
	if field != "" {
		return Decision{}, fmt.Errorf("request %s is not valid", field)
	}
	return generation.Decide(question, func() bool { return false }), nil
}
