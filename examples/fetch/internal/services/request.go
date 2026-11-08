// Request reading shared by the Fetch services: bounded strict JSON bodies,
// queries, pagination and small field checks.

package services

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	josejson "github.com/go-jose/go-jose/v4/json"
)

func decodeBody(r *http.Request, body []byte, limit int, value any) *result {
	if len(body) > limit {
		v := failure(413, "payload_too_large", "The request body is too large.", "")
		return &v
	}
	values := r.Header.Values("Content-Type")
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	validMedia := len(values) == 1 && err == nil && media == "application/json"
	for name, value := range parameters {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			validMedia = false
		}
	}
	if !validMedia {
		v := failure(415, "unsupported_media_type", "Send a JSON request body.", "")
		return &v
	}
	// Reject duplicate names before decoding and permit only the lowercase
	// member names used by the service contracts, including nested objects.
	var document any
	if !utf8.Valid(body) || hasLoneSurrogate(body) || josejson.Unmarshal(body, &document) != nil || !validMembers(document, 0) {
		v := failure(400, "invalid_request", "The JSON request is invalid.", "")
		return &v
	}
	if _, ok := document.(map[string]any); !ok {
		v := failure(400, "invalid_request", "Send a JSON object.", "")
		return &v
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		v := failure(400, "invalid_request", "The JSON request is invalid.", "")
		return &v
	}
	if decoder.Decode(&document) != io.EOF {
		v := failure(400, "invalid_request", "Send exactly one JSON value.", "")
		return &v
	}
	return nil
}

func validMembers(value any, depth int) bool {
	if depth > 16 {
		return false
	}
	switch value := value.(type) {
	case nil:
		return false
	case map[string]any:
		for key, item := range value {
			if key == "" {
				return false
			}
			for _, c := range key {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
					return false
				}
			}
			if !validMembers(item, depth+1) {
				return false
			}
		}
	case []any:
		for _, item := range value {
			if !validMembers(item, depth+1) {
				return false
			}
		}
	}
	return true
}

// Preserve the gateway's strict Unicode profile instead of letting JSON
// decoders silently replace an unpaired UTF-16 escape with U+FFFD.
func hasLoneSurrogate(data []byte) bool {
	surrogate := func(i int) (rune, bool) {
		if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
			return 0, false
		}
		code, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		return rune(code), err == nil && code >= 0xd800 && code <= 0xdfff
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		code, found := surrogate(i)
		switch {
		case !found:
			i++
		case code >= 0xdc00:
			return true
		default:
			low, ok := surrogate(i + 6)
			if !ok || low < 0xdc00 {
				return true
			}
			i += 11
		}
	}
	return false
}

func query(r *http.Request, names ...string) (url.Values, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false
	}
	for name, list := range values {
		if len(list) != 1 || !slices.Contains(names, name) {
			return nil, false
		}
	}
	return values, true
}
func pagination(q url.Values) (int, string, bool) {
	n := 20
	var err error
	if text := q.Get("limit"); text != "" {
		n, err = strconv.Atoi(text)
		if strconv.Itoa(n) != text {
			return 0, "", false
		}
	}
	return n, q.Get("after"), err == nil && n >= 1 && n <= 100
}
func invalidQuery() result { return failure(400, "invalid_query", "Check the query parameters.", "") }
func length(value string, min, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= min && utf8.RuneCountInString(value) <= max
}
func hasRole(r *http.Request, role string) bool {
	return slices.Contains(strings.Split(r.Header.Get("X-Gateway-Roles"), ","), role)
}
func idempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
