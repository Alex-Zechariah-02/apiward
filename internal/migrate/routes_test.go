// Reference routes of an OpenAPI description: what it states for each operation, as shared primitives.

package migrate

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/probe"
	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// openapiRoutes reads every operation of a description as the description
// states it, where the import changes it: a last-segment template takes
// one segment, no stated security is public, no x-apiward-roles admits
// every signed-in caller and no x-apiward-max-bytes sets no body limit.
// Operations with templates elsewhere are left out. Paths without
// templates come first, then longer paths.
func openapiRoutes(root map[string]any) ([]semantics.Route, error) {
	paths, _ := root["paths"].(map[string]any)
	var routes []semantics.Route
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		item, _ := paths[path].(map[string]any)
		for _, method := range methods {
			op, isObject := item[method].(map[string]any)
			head, last := path[:strings.LastIndex(path, "/")+1], path[strings.LastIndex(path, "/")+1:]
			if !isObject || strings.ContainsAny(head, "{}") {
				continue
			}
			o, err := probe.Describe(root, op, path, strings.ToUpper(method), probe.Options{})
			if err != nil {
				return nil, err
			}
			route := o.Route
			if _, targeted := op["x-apiward-target"]; !targeted && strings.HasPrefix(last, "{") {
				route.Path = semantics.PathRule{Match: semantics.LastSegmentTemplate, Value: path}
			}
			if !stated(root, op) {
				route.Identity, route.Roles = nil, nil
			}
			if _, permitted := op["x-apiward-roles"]; !permitted {
				route.Roles = nil
			}
			routes = append(routes, route)
		}
	}
	slices.SortStableFunc(routes, func(a, b semantics.Route) int {
		templated := func(r semantics.Route) bool { return r.Path.Match != semantics.Exact }
		if templated(a) != templated(b) {
			return cmp.Compare(boolRank(templated(a)), boolRank(templated(b)))
		}
		return cmp.Compare(len(b.Path.Value), len(a.Path.Value))
	})
	return routes, nil
}

// stated reports whether the operation, or the root for it, states security.
func stated(root, op map[string]any) bool {
	_, onOperation := op["security"]
	_, onRoot := root["security"]
	return onOperation || onRoot
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}
