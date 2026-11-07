// Probe bodies built from an operation's schema, and the readers of decoded exchange values.

package probe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// maxDepth bounds the schema walk; the policy's own nesting limit is lower.
const maxDepth = 16

// Body returns the bytes a probe of the kind sends to the operation:
// valid is built from the schema, invalid is JSON of another type, and
// oversize is the valid body padded with whitespace to one byte over the
// limit. A kind of none, or an operation without a schema, sends nothing.
func Body(o Operation, kind BodyKind) ([]byte, error) {
	if kind == NoBody || o.Schema == nil {
		return nil, nil
	}
	if kind == Invalid {
		if typeOf(o.Schema) == "array" {
			return []byte(`{}`), nil
		}
		return []byte(`[]`), nil
	}
	value, err := example(o.Schema, 0)
	if err != nil {
		return nil, fmt.Errorf("the body schema of %s: %w", o.ID, err)
	}
	data, err := json.Marshal(value)
	if err != nil || kind == Valid {
		return data, err
	}
	limit := o.Route.MaxBytes
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("the smallest valid body of %s is over its %d-byte limit", o.ID, limit)
	}
	return append(data, bytes.Repeat([]byte(" "), int(limit+1)-len(data))...), nil
}

// example is the smallest value the schema accepts, for the keywords the
// gateway checks; composition and references are not built.
func example(schema any, depth int) (any, error) {
	s, _ := schema.(map[string]any)
	switch {
	case depth > maxDepth:
		return nil, errors.New("nested too deeply")
	case s["$ref"] != nil || s["allOf"] != nil || s["anyOf"] != nil || s["oneOf"] != nil:
		return nil, errors.New("references and composition are not built")
	case s["const"] != nil:
		return s["const"], nil
	case len(list(s["enum"])) > 0:
		return list(s["enum"])[0], nil
	}
	switch typeOf(s) {
	case "string":
		return strings.Repeat("a", max(1, int(number(s["minLength"])))), nil
	case "integer", "number":
		return bounded(s), nil
	case "boolean":
		return true, nil
	case "null":
		return nil, nil
	case "array":
		var items []any
		for range number(s["minItems"]) {
			item, err := example(s["items"], depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return append([]any{}, items...), nil
	}
	properties, _ := s["properties"].(map[string]any)
	object := map[string]any{}
	for _, name := range texts(s["required"]) {
		value, err := example(properties[name], depth+1)
		if err != nil {
			return nil, err
		}
		object[name] = value
	}
	return object, nil
}

// typeOf is the schema's type, the first that is not null of a list, or
// "object" when it states none.
func typeOf(schema any) string {
	s, _ := schema.(map[string]any)
	if name := text(s["type"]); name != "" {
		return name
	}
	for _, name := range texts(s["type"]) {
		if name != "null" {
			return name
		}
	}
	return "object"
}

// bounded is 1 kept within the schema's minimum and maximum.
func bounded(s map[string]any) int64 {
	value := int64(1)
	if s["minimum"] != nil {
		value = max(value, number(s["minimum"]))
	}
	if s["maximum"] != nil {
		value = min(value, number(s["maximum"]))
	}
	return value
}

func text(value any) string {
	s, _ := value.(string)
	return s
}

func list(value any) []any {
	l, _ := value.([]any)
	return l
}

func texts(value any) []string {
	var out []string
	for _, v := range list(value) {
		if s, isText := v.(string); isText {
			out = append(out, s)
		}
	}
	return out
}

// number reads an integer decoded as json.Number or float64; 0 otherwise.
func number(value any) int64 {
	switch v := value.(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case float64:
		return int64(v)
	}
	return 0
}

// escape encodes one JSON pointer segment (RFC 6901).
func escape(segment string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(segment)
}
