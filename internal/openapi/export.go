// Export: one API of a policy as an OpenAPI 3.1 description with x-apiward-* extensions.

package openapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// scheme is the bearer security scheme every signed-in operation names.
const scheme = "apiward"

// ExportOptions are the administrator's choices for one export.
type ExportOptions struct {
	API          string // the API to describe
	WithUpstream bool   // write the upstream address as a server
}

// ExportReport is the stable account of one export. Every list is present.
type ExportReport struct {
	API        string     `json:"api"`
	Operations int        `json:"operations"`
	Exported   []Exported `json:"exported"`
	Changed    []Changed  `json:"changed"`
	Omitted    []string   `json:"omitted"`
}

// Exported is one operation written to the description.
type Exported struct {
	Operation string `json:"operation"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

// Exit is partial when the description means something different from the
// policy anywhere, so a script cannot miss it.
func (r *ExportReport) Exit() int {
	if len(r.Changed) > 0 {
		return ExitPartial
	}
	return ExitComplete
}

// Export describes one API of a policy the compiler accepts. It returns the
// description as JSON-ready values and the report, or an error, in which
// case nothing may be written. It has no side effects.
func Export(p policy.Policy, options ExportOptions) (map[string]any, *ExportReport, error) {
	if _, err := compile.Compile(p, 0, time.Time{}, policy.Limits{}); err != nil {
		return nil, nil, fmt.Errorf("the policy is not valid: %w", err)
	}
	encoded, err := policy.Encode(p)
	if err != nil {
		return nil, nil, err
	}
	index := slices.IndexFunc(p.APIs, func(a policy.API) bool { return a.ID == options.API })
	if index < 0 {
		return nil, nil, fmt.Errorf("api %q is not in the policy", policy.Clip(options.API))
	}
	report := &ExportReport{API: options.API, Exported: []Exported{}, Changed: []Changed{}, Omitted: []string{}}
	roles := map[string][]any{}
	for _, permit := range p.Permits {
		roles[permit.Operation] = append(roles[permit.Operation], permit.Role)
	}
	// A path item holds one operation per method: the unconditioned one
	// is described first, so a conditioned variant never takes its place.
	ops := slices.Clone(p.Operations)
	slices.SortStableFunc(ops, func(a, b policy.Operation) int { return conditioned(a) - conditioned(b) })
	paths, signedIn := map[string]any{}, false
	for _, op := range ops {
		if op.API != options.API {
			continue
		}
		report.Operations++
		path, operation := describe(op, roles[op.ID], report)
		if operation == nil {
			continue
		}
		item, _ := paths[path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[path] = item
		}
		method := strings.ToLower(op.Method)
		if _, taken := item[method]; taken {
			report.Changed = append(report.Changed, Changed{Operation: op.ID, Field: "when",
				Note: "Not exported: an OpenAPI description holds one operation per path and method, and " + path + " already has one."})
			continue
		}
		item[method] = operation
		signedIn = signedIn || op.Auth == "required"
		report.Exported = append(report.Exported, Exported{Operation: op.ID, Method: op.Method, Path: path})
	}
	slices.SortFunc(report.Exported, func(a, b Exported) int { return strings.Compare(a.Operation, b.Operation) })

	// The version is the SHA-256 of the policy as the gateway encodes it, so a
	// description names the exact policy it was exported from.
	version := fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	document := map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": options.API, "version": version}, "paths": paths}
	if signedIn {
		document["components"] = map[string]any{"securitySchemes": map[string]any{
			scheme: map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}}
	}
	for name, value := range apiSettings(p.APIs[index]) {
		document[name] = value
	}
	upstream := p.APIs[index].Upstream
	if options.WithUpstream {
		for _, u := range p.Upstreams {
			if u.ID == upstream {
				origin := u.URL
				if origin == "" {
					origin = "http://" + u.Dial
				}
				document["servers"] = []any{map[string]any{"url": origin, "description": u.ID}}
			}
		}
	} else {
		report.Omitted = append(report.Omitted, "upstream address of "+upstream+" (--with-upstream writes it)")
	}
	return document, report, readable(document)
}

// describe returns one operation's path and OpenAPI form, or a nil form
// when it cannot be described; either way the report says what changed.
func describe(op policy.Operation, roles []any, report *ExportReport) (string, map[string]any) {
	if strings.ContainsAny(op.Target, "{}") {
		report.Changed = append(report.Changed, Changed{Operation: op.ID, Field: "target",
			Note: "Not exported: OpenAPI reads braces in a path as a template, which would widen the target."})
		return "", nil
	}
	operation := map[string]any{"operationId": op.ID, "x-apiward-access": op.Access, "security": []any{}}
	if id, cut := strings.CutPrefix(op.ID, op.API+"."); cut {
		operation["operationId"] = id
	} else {
		report.Changed = append(report.Changed, Changed{Operation: op.ID, Field: "id",
			Note: "The import names operations <api>.<operationId>, so this one returns as " + op.API + "." + op.ID + "."})
	}
	path, parameters := op.Target, []any{}
	if prefix, cut := strings.CutSuffix(op.Target, "*"); cut {
		path = prefix + "{rest}"
		operation["x-apiward-target"] = op.Target
		parameters = append(parameters, map[string]any{"name": "rest", "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		report.Changed = append(report.Changed, Changed{Operation: op.ID, Field: "target",
			Note: "In OpenAPI {rest} is one path segment; the gateway also matches deeper paths under " + prefix + "."})
	}
	if op.Auth == "required" { // the compiler permits only signed-in operations
		slices.SortFunc(roles, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
		operation["security"] = []any{map[string]any{scheme: []any{}}}
		operation["x-apiward-roles"] = append([]any{}, roles...)
	}
	parameters = append(parameters, headerParameters(op)...)
	if len(parameters) > 0 {
		operation["parameters"] = parameters
	}
	if op.Body != nil {
		operation["requestBody"] = map[string]any{"required": true,
			"description": fmt.Sprintf("At most %d bytes; the gateway refuses a larger body with 413.", op.Body.MaxBytes),
			"content":     map[string]any{"application/json": map[string]any{"schema": op.Body.Schema}}}
		operation["x-apiward-max-bytes"] = op.Body.MaxBytes
	}
	operation["responses"] = responses(op)
	if op.Rate != nil {
		operation["x-apiward-rate"] = op.Rate
	}
	if op.When != nil {
		operation[policy.WhenExtension] = op.When
	}
	return path, operation
}

// refusalSchema is the body of every answer the gateway gives itself.
var refusalSchema = map[string]any{"type": "object", "required": []any{"error", "request_id"},
	"properties": map[string]any{"error": map[string]any{"type": "string"}, "request_id": map[string]any{"type": "string"}}}

// responses lists the answers the gateway may give for op before the service
// sees the request, and the service's own answer as the default.
func responses(op policy.Operation) map[string]any {
	refusal := func(text string) map[string]any {
		return map[string]any{"description": text, "content": map[string]any{"application/json": map[string]any{"schema": refusalSchema}}}
	}
	out := map[string]any{
		"default": map[string]any{"description": "The service's answer, passed through."},
		"400":     refusal("Refused by the gateway: the path (a control character in a segment included), a declared header or the body breaks the endpoint's rules."),
		"403":     refusal("Refused by the gateway: the endpoint, the client address or the browser origin is not allowed, or the caller lacks the permission."),
		"429":     refusal("Refused by the gateway: the endpoint's rate limit, or a temporary rule's, was reached."),
		"503":     refusal("The gateway could not decide on or record the request."),
	}
	if op.Auth == "required" {
		out["401"] = refusal("Refused by the gateway: no valid bearer token.")
	}
	if op.Body != nil {
		out["413"] = refusal("Refused by the gateway: the body is larger than the endpoint allows.")
		out["415"] = refusal("Refused by the gateway: the body is not application/json.")
	}
	return out
}

// conditioned ranks operations with conditions after those without.
func conditioned(op policy.Operation) int {
	if op.When == nil {
		return 0
	}
	return 1
}

// headerParameters writes a header schema as one parameter per declared
// header. The compiler allows only type, properties, required and
// additionalProperties at the root and a schema for every required header;
// the gateway validates declared headers only, so additionalProperties has
// no effect and is not written.
func headerParameters(op policy.Operation) []any {
	var root struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if op.Headers == nil || json.Unmarshal(op.Headers, &root) != nil {
		return nil // the compiler accepted the schema, so it decodes
	}
	var parameters []any
	for _, name := range slices.Sorted(maps.Keys(root.Properties)) {
		parameter := map[string]any{"name": name, "in": "header", "schema": root.Properties[name]}
		if slices.Contains(root.Required, name) {
			parameter["required"] = true
		}
		parameters = append(parameters, parameter)
	}
	return parameters
}

// readable checks the description passes the import's own gate, so an
// export never writes a file the import would refuse.
func readable(document map[string]any) error {
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if _, reason := policy.DecodeBounded(data, policy.MaxJSONDepth, MaxSpecBytes); reason != "" {
		return errors.New("the description would not be accepted by the import: " + reason)
	}
	return nil
}

// apiSettings returns the exchange root members of an API's settings that
// are present.
func apiSettings(api policy.API) map[string]any {
	members := map[string]any{}
	if api.Forward != nil {
		members[policy.ForwardExtension] = api.Forward
	}
	if api.CORS != nil {
		members[policy.CORSExtension] = api.CORS
	}
	if api.ResponseHeaders != nil {
		members[policy.ResponseHeadersExtension] = api.ResponseHeaders
	}
	if api.AllowAddresses != nil {
		members[policy.AddressesExtension] = api.AllowAddresses
	}
	return members
}
