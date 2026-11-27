// Operation members that belong to compiled-in modules: read apart from the
// strict decoding, and written back as members.

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/module"
)

// takeModules removes from each operation of document the members named by
// a registered module other than the built-ins, and returns them by
// operation index. With no such module the document is returned unchanged,
// so a standard build decodes exactly as written; any other unknown member
// is then refused by the strict decoding. A module value must pass the
// bounded JSON decoding, so the canonical encoding can always write it.
// Its errors are policy problems. ids are the modules' IDs (moduleIDs).
func takeModules(document []byte, ids []string) ([]byte, []map[string]json.RawMessage, error) {
	if len(ids) == 0 {
		return document, nil, nil
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(document, &root) != nil {
		return nil, nil, Invalid("SCHEMA_INVALID", "")
	}
	var operations []map[string]json.RawMessage
	// A malformed operations member is left for the strict decoding to refuse.
	if json.Unmarshal(root["operations"], &operations) != nil {
		return document, nil, nil
	}
	taken := make([]map[string]json.RawMessage, len(operations))
	for i, op := range operations {
		for _, id := range ids {
			if raw, ok := op[id]; ok {
				if _, reason := DecodeBounded(raw, MaxSchemaDepth, MaxJSONValues); reason != "" {
					return nil, nil, Invalid("SCHEMA_INVALID", "operations[%d].%s", i, id)
				}
				if taken[i] == nil {
					taken[i] = map[string]json.RawMessage{}
				}
				taken[i][id] = raw
				delete(op, id)
			}
		}
	}
	var err error
	if root["operations"], err = json.Marshal(operations); err != nil {
		return nil, nil, Invalid("SCHEMA_INVALID", "")
	}
	stripped, err := json.Marshal(root)
	if err != nil {
		return nil, nil, Invalid("SCHEMA_INVALID", "")
	}
	return stripped, taken, nil
}

// moduleIDs lists the IDs of the registered modules other than the
// built-ins: the operation members they own.
func moduleIDs() []string {
	var ids []string
	for _, c := range module.Extensions() {
		ids = append(ids, c.Info().ID)
	}
	return ids
}

// MarshalJSON writes the operation's own members and then its module
// members in ID order, each value with its members sorted, so one meaning
// has one byte form. Without module members the output is exactly the
// default encoding.
func (o Operation) MarshalJSON() ([]byte, error) {
	type plain Operation
	data, err := json.Marshal(plain(o))
	if err != nil || len(o.Modules) == 0 {
		return data, err
	}
	var out bytes.Buffer
	out.Write(data[:len(data)-1])
	ids := make([]string, 0, len(o.Modules))
	for id := range o.Modules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		value := o.Modules[id]
		if len(value) == 0 {
			value = json.RawMessage("null")
		}
		canonical, err := canonicalValue(value)
		if err != nil {
			return nil, err
		}
		name, _ := json.Marshal(id)
		out.WriteByte(',')
		out.Write(name)
		out.WriteByte(':')
		out.Write(canonical)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// canonicalValue re-encodes a module value with its object members sorted;
// member order carries no meaning in JSON. Numbers keep their literal form.
func canonicalValue(raw json.RawMessage) ([]byte, error) {
	value, reason := DecodeBounded(raw, MaxSchemaDepth, MaxJSONValues)
	if reason != "" {
		return nil, errors.New("module value not encodable: " + reason)
	}
	return json.Marshal(value)
}
