// Walking paths and methods: identifiers, targets and sign-in for each operation.

package openapi

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// methods in the order the OpenAPI Specification lists them.
var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// candidate is an operation that passed every check of its own; its report
// entries are kept until the checks across operations accept it.
type candidate struct {
	entry       Mapped
	widened     bool
	op          policy.Operation
	assumed     []Assumed
	changed     []Changed
	notEnforced []NotEnforced
	annotations []Removed
	scopes      []string
	roles       []string // permitted roles from x-apiward-roles; nil when not read
	maxBytes    int64    // body limit from x-apiward-max-bytes; 0 when absent
}

// mapper walks one description; settings are the API settings its root
// members state, which each operation's trial compiles with.
type mapper struct {
	root     map[string]any
	options  Options
	settings policy.API
	report   *Report
	ignored  map[string]bool
}

// The members OpenAPI 3.1 defines for a path item and an operation; any other
// name (a misspelt requestBody, an uppercase method) would leave a check out
// silently, so it is reported as ignored.
var (
	itemMembers      = []string{"$ref", "summary", "description", "servers", "parameters"}
	operationMembers = []string{"tags", "summary", "description", "externalDocs", "operationId", "parameters",
		"requestBody", "responses", "callbacks", "deprecated", "security", "servers"}
)

// operations returns the candidates in path and method order; refusals go
// straight into the report.
func (m *mapper) operations() []*candidate {
	m.notice(m.root, "servers", "webhooks", "tags")
	paths, _ := m.root["paths"].(map[string]any)
	var found []*candidate
	for _, path := range sortedKeys(paths) {
		pointer := "#/paths/" + escape(path)
		node, refused := follow(m.root, paths[path], pointer)
		item, isObject := node.(map[string]any)
		if refused == nil && !isObject {
			refused = refuse(CodeRefInvalid, pointer, "The path item is not an object.")
		}
		if refused != nil {
			m.refuse("", path, refused)
			continue
		}
		m.notice(item, "servers")
		unknown := m.unknown(item, append(slices.Clone(itemMembers), methods...))
		stated := false
		for _, method := range methods {
			if _, present := item[method]; !present {
				continue
			}
			stated = true
			m.report.OperationsInSpec++
			found = m.add(found, method, path, item, pointer)
		}
		if !stated && unknown {
			m.refuse("", path, refuse(CodeMethod, pointer, "The path item has no operation under a lowercase method name."))
		}
	}
	return found
}

// unknown adds to the ignored members every member of object that is not
// known and is not an extension, and reports whether there was one.
func (m *mapper) unknown(object map[string]any, known []string) bool {
	found := false
	for name := range object {
		if !slices.Contains(known, name) && !strings.HasPrefix(name, "x-") {
			m.ignored[policy.Clip(name)] = true
			found = true
		}
	}
	return found
}

func (m *mapper) add(found []*candidate, method, path string, item map[string]any, pointer string) []*candidate {
	c, refused := m.operation(method, path, item, pointer)
	if refused != nil {
		m.refuse(strings.ToUpper(method), path, refused)
		return found
	}
	return append(found, c)
}

// notice records ignored members present in an object.
func (m *mapper) notice(object map[string]any, names ...string) {
	for _, name := range names {
		if _, present := object[name]; present {
			m.ignored[name] = true
		}
	}
}

func (m *mapper) refuse(method, path string, r *refusal) {
	m.report.Refused = append(m.report.Refused, Refused{Method: method, Path: policy.Clip(path), Code: r.code,
		Message: r.message, Field: policy.Clip(r.field), Suggestion: r.suggestion})
}

// operation maps one method of one path item.
func (m *mapper) operation(method, path string, item map[string]any, itemPointer string) (*candidate, *refusal) {
	pointer := itemPointer + "/" + method
	upper := strings.ToUpper(method)
	// A policy allows no TRACE, which echoes a request, so it is refused.
	if method == "trace" {
		return nil, refuse(CodeMethod, "", "TRACE is never forwarded.")
	}
	object, ok := item[method].(map[string]any)
	if !ok {
		return nil, refuse(CodeRefInvalid, pointer, "The operation is not an object.")
	}
	m.notice(object, "servers", "responses", "callbacks", "tags")
	m.unknown(object, operationMembers)
	m.noticeLinks(object)

	operationID, _ := object["operationId"].(string)
	id := m.options.API + "." + operationID
	if operationID == "" || policy.CheckID(id, "id") != nil {
		refused := refuse(CodeOperationID, "", "The operationId is missing or is not a valid identifier (letters, digits, '.', '_', '-'; at most 64 characters with the API name).")
		refused.suggestion = suggest(operationID, upper, path, len(m.options.API)+1)
		return nil, refused
	}
	target, widened, refused := targetOf(path)
	if refused != nil {
		return nil, refused
	}
	c := &candidate{op: policy.Operation{ID: id, API: m.options.API, Method: upper, Target: target, Access: "allow"}, widened: widened}
	c.entry = Mapped{Method: upper, Path: policy.Clip(path), Operation: id, Target: target}
	if widened {
		c.entry.Note = "matches " + strings.TrimSuffix(target, "*") + "<anything>, including deeper paths"
	}
	if refused := m.extensions(object, c); refused != nil {
		return nil, refused
	}
	if refused := m.security(object, c); refused != nil {
		return nil, refused
	}
	if c.op.Auth != "required" && len(c.roles) > 0 {
		return nil, refuse(CodeExtension, "x-apiward-roles", "x-apiward-roles names who may call a signed-in operation; this one is public.")
	}
	c.entry.Auth = c.op.Auth
	s := &schemas{root: m.root, operation: id}
	if refused := m.parameters(item, object, itemPointer, pointer, c, s); refused != nil {
		return nil, refused
	}
	if refused := m.body(object, pointer, c, s); refused != nil {
		return nil, refused
	}
	c.assumed = append(c.assumed, s.assumed...)
	c.annotations = s.annotations
	return c, m.trial(c.op)
}

// targetOf maps a path template to a gateway target: exact, or a prefix
// when only the last segment is templated.
func targetOf(path string) (string, bool, *refusal) {
	// A gateway target ending in /* is a prefix; a literal * would import
	// as one while the report calls it exact.
	if strings.Contains(path, "*") {
		return "", false, refuse(CodePathTemplate, "", "A path containing * cannot be expressed.")
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if !strings.Contains(segment, "{") {
			continue
		}
		if i != len(segments)-1 {
			return "", false, refuse(CodePathTemplate, "", "A templated segment followed by more segments cannot be expressed.")
		}
		// A target is exact or one trailing /* prefix, so only the last
		// segment can widen. With no literal segment before it the prefix
		// would be /*, which matches every path.
		if i == 1 {
			return "", false, refuse(CodePathTemplate, "", "A path whose only segment is templated would match every path.")
		}
		return strings.Join(segments[:i], "/") + "/*", true, nil
	}
	return path, false, nil
}

// trial compiles the operation alone with the real compiler, so every rule
// it enforces (targets, header names, schema subset, and the rules that
// depend on the API's settings, such as a forward prefix) is checked by one
// code path. It uses the base's schema version, which decides the upstream
// forms allowed (an upstream URL needs version 5).
func (m *mapper) trial(op policy.Operation) *refusal {
	var upstream policy.Upstream
	for _, u := range m.options.Base.Upstreams {
		if u.ID == m.options.Upstream {
			upstream = u
		}
	}
	// CORS is left out: its methods must each belong to some operation of
	// the API, which one operation alone cannot show; the whole result checks it.
	api := m.settings
	api.ID, api.Upstream, api.CORS = m.options.API, upstream.ID, nil
	single := policy.Policy{
		SchemaVersion: m.options.Base.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams:  []policy.Upstream{upstream},
		APIs:       []policy.API{api},
		Operations: []policy.Operation{op},
	}
	_, err := compile.Compile(single, 0, time.Time{}, m.options.Limits)
	if err == nil {
		return nil
	}
	var compiled *policy.PolicyError
	if !errors.As(err, &compiled) {
		return refuse(CodeCompiler, "", "The gateway's compiler refused it.")
	}
	field := strings.TrimPrefix(strings.TrimPrefix(compiled.Field, "operations[0]"), ".")
	return refuse(CodeCompiler, field, "The gateway's compiler refused it: %s at %s.", compiled.Code, field)
}

// suggest proposes a valid operationId from the given one, or from the
// method and path when there is none.
func suggest(operationID, method, path string, prefix int) string {
	source := operationID
	if source == "" {
		source = strings.ToLower(method) + "-" + path
	}
	var b strings.Builder
	dash := false
	for _, r := range source {
		valid := r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
		if valid && r != '-' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	text := strings.TrimRight(b.String(), "-")
	if limit := policy.MaxIDLength - prefix; len(text) > limit {
		text = strings.TrimRight(text[:limit], "-")
	}
	return text
}

func (m *mapper) noticeLinks(object map[string]any) {
	responses, _ := object["responses"].(map[string]any)
	for _, response := range responses {
		if r, ok := response.(map[string]any); ok {
			m.notice(r, "links")
		}
	}
}

// follow resolves a chain of internal references of a non-schema object.
func follow(root map[string]any, node any, pointer string) (any, *refusal) {
	// A reference chain can loop, so it stops after MaxJSONDepth hops.
	for range policy.MaxJSONDepth {
		object, ok := node.(map[string]any)
		if !ok {
			return node, nil
		}
		ref, present := object["$ref"]
		if !present {
			return node, nil
		}
		var refused *refusal
		if node, refused = resolve(root, ref, pointer); refused != nil {
			return nil, refused
		}
	}
	return nil, refuse(CodeRefInvalid, pointer, "The reference chain is longer than %d.", policy.MaxJSONDepth)
}
