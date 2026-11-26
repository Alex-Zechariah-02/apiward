// The member scan of policy, operator and Admin API documents: depth,
// repeated and non-lowercase member names, and the schema and module values
// inside.

package policy

import (
	"bytes"
	"cmp"
	"encoding/json"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// CheckMembers rejects JSON nested deeper than maxDepth, and objects with a
// repeated member name or a name outside [a-z0-9_]. encoding/json keeps the
// last of repeated names and matches names case-insensitively, so without
// this check two readers of the same document could disagree about it.
//
// Values of members named "schema" or "headers" are JSON Schemas, whose
// keywords and property names are case-sensitive and not limited to
// [a-z0-9_]; the "headers" lists of "when" and "cors" objects are not. They
// are decoded as raw JSON, never into Go structs, so only the repeated-name
// and depth rules apply inside them.
func CheckMembers(data []byte, maxDepth int) error {
	return checkMembers(data, maxDepth, nil)
}

// container is one open object or array of the member scan.
type container struct {
	object   bool
	wantName bool
	names    map[string]bool // objects only, made at the first member
	lastName string
	name     string // the member this container is the value of
	free     bool   // inside a schema or module value: names are not limited
	depth    int    // document levels, or levels within its free value
}

// checkMembers is CheckMembers for a policy document whose operations may
// carry the members of the named modules: a module's settings belong to the
// module, so like a schema only the repeated-name and depth rules apply
// inside them.
func checkMembers(data []byte, maxDepth int, modules []string) error {
	// encoding/json replaces malformed Unicode. Policy, operator and Admin
	// inputs must retain the same unambiguous UTF-8 representation as bodies.
	if !utf8.Valid(data) || hasLoneSurrogate(data) {
		return Invalid("SCHEMA_INVALID", "")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var buffer [MaxPolicyDepth + 2]container
	stack := buffer[:0]
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return Invalid("SCHEMA_INVALID", "")
		}

		var parent *container
		if len(stack) > 0 {
			parent = &stack[len(stack)-1]
		}

		if delim, ok := token.(json.Delim); ok && (delim == '}' || delim == ']') {
			stack = stack[:len(stack)-1]
			continue
		}

		if parent != nil && parent.object && parent.wantName {
			name, ok := token.(string)
			if !ok {
				return Invalid("SCHEMA_INVALID", "")
			}
			if err := parent.member(name); err != nil {
				return err
			}
			continue
		}

		// A value: once it is complete, an enclosing object expects a name.
		if parent != nil && parent.object {
			parent.wantName = true
		}
		delim, ok := token.(json.Delim)
		if !ok {
			continue
		}
		free := parent != nil && (parent.free || parent.object && (freeValue(parent) || moduleValue(stack, modules)))
		// A free value has its own depth budget, counted from its root.
		depth, limit := len(stack)+1, maxDepth
		if free {
			depth, limit = 1, MaxSchemaDepth
			if parent.free {
				depth = parent.depth + 1
			}
		}
		if depth > limit {
			return Invalid("LIMIT_EXCEEDED", "")
		}
		name := ""
		if parent != nil && parent.object {
			name = parent.lastName
		}
		stack = append(stack, container{name: name, object: delim == '{', wantName: delim == '{', free: free, depth: depth})
	}
}

// member checks and records the next member name of an object.
func (c *container) member(name string) error {
	if !c.free && !isMemberName(name) {
		return Invalid("UNKNOWN_FIELD", "%s", Clip(name))
	}
	if c.names[name] {
		return Invalid("DUPLICATE_MEMBER", "%s", name)
	}
	if c.names == nil {
		c.names = map[string]bool{}
	}
	c.names[name] = true
	c.lastName = name
	c.wantName = false
	return nil
}

// freeValue reports a schema value: a member named "schema", or "headers"
// outside "when" and "cors" objects.
func freeValue(parent *container) bool {
	return parent.lastName == "schema" || parent.lastName == "headers" && parent.name != "when" && parent.name != "cors"
}

// moduleValue reports a module member of an operation: the top of stack is
// an object in the root's "operations" array.
func moduleValue(stack []container, modules []string) bool {
	if len(modules) == 0 || len(stack) != 3 || stack[1].name != "operations" || stack[1].object {
		return false
	}
	return slices.Contains(modules, stack[2].lastName)
}

func isMemberName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		lower := c >= 'a' && c <= 'z'
		digit := c >= '0' && c <= '9'
		if !lower && !digit && c != '_' {
			return false
		}
	}
	return true
}

// unknownMember returns the name of a member of document that no field of
// t (a struct) names, the member DecodeStrict refused; at each level names
// are tried in sorted order. Raw JSON fields take any members.
func unknownMember(document []byte, t reflect.Type) (string, bool) {
	var value any
	if json.Unmarshal(document, &value) != nil {
		return "", false
	}
	return unknownIn(value, t)
}

func unknownIn(value any, t reflect.Type) (string, bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeFor[json.RawMessage]() {
		return "", false
	}
	switch v := value.(type) {
	case []any:
		if t.Kind() != reflect.Slice {
			return "", false
		}
		for _, item := range v {
			if name, found := unknownIn(item, t.Elem()); found {
				return name, true
			}
		}
	case map[string]any:
		if t.Kind() != reflect.Struct {
			return "", false
		}
		fields := map[string]reflect.Type{}
		for field := range t.Fields() {
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if field.IsExported() && name != "-" {
				fields[cmp.Or(name, field.Name)] = field.Type
			}
		}
		for _, name := range slices.Sorted(maps.Keys(v)) {
			field, known := fields[name]
			if !known {
				return name, true
			}
			if inner, found := unknownIn(v[name], field); found {
				return inner, true
			}
		}
	}
	return "", false
}
