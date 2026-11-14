// Request body reading and validation against the captured rule.

package pipeline

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// rejection is a request refused at a body or validation stage.
type rejection struct {
	status int
	code   string
	reason string
}

// bufferBody reads a declared request body completely, within the global
// ceiling, and replaces r.Body with the bytes read. It returns nil when the
// request declares no body, and a non-nil slice (possibly empty) when it
// does. The ceiling bounds the bytes read as well as the declared length: a
// chunked body, or an HTTP/2 body without a content-length field, declares
// no length, so a check of the declared length alone would let it pass.
func bufferBody(r *http.Request, maxBytes int64) ([]byte, *rejection) {
	if r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
		return nil, nil
	}
	body, err := readLimited(r.Body, r.ContentLength, maxBytes)
	if err != nil {
		return nil, &rejection{http.StatusBadRequest, "bad_request", "read_failed"}
	}
	if int64(len(body)) > maxBytes {
		return nil, &rejection{http.StatusRequestEntityTooLarge, "payload_too_large", "too_large"}
	}
	if body == nil {
		body = []byte{}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// readBody enforces the operation's body declaration on the body bufferBody
// read (nil when none was declared): no body for a bodyless operation;
// otherwise the operation's size ceiling, a JSON media type and a bounded,
// unambiguous JSON document. The request body is replaced with the bytes
// read, so nothing unchecked can stream upstream. It returns the decoded
// document.
func readBody(r *http.Request, body []byte, rule *compile.BodyRule, globalMaxBytes int64) (any, *rejection) {
	if rule == nil {
		if body != nil {
			return nil, &rejection{http.StatusBadRequest, "bad_request", "unexpected_body"}
		}
		return nil, nil
	}
	if int64(len(body)) > min(rule.MaxBytes(), globalMaxBytes) {
		return nil, &rejection{http.StatusRequestEntityTooLarge, "payload_too_large", "too_large"}
	}
	if !IsJSONMediaType(r.Header.Values("Content-Type")) {
		return nil, &rejection{http.StatusUnsupportedMediaType, "unsupported_media_type", "media_type"}
	}
	document, reason := policy.DecodeJSON(body)
	if reason != "" {
		return nil, &rejection{http.StatusBadRequest, "bad_request", reason}
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return document, nil
}

// readLimited reads at most maxBytes+1 bytes, so a longer body is seen to be
// too large. A body of declared length is read into one buffer of that size;
// the server ends such a body at its declared length, and one more read
// confirms it. The policy compiler bounds the ceiling, so maxBytes+1 cannot
// overflow.
func readLimited(body io.Reader, declared, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(body, maxBytes+1)
	if declared <= 0 {
		return io.ReadAll(limited)
	}
	data := make([]byte, declared, declared+1)
	if _, err := io.ReadFull(limited, data); err != nil {
		return nil, err
	}
	var extra [1]byte
	n, err := io.ReadFull(limited, extra[:])
	if n == 1 {
		return append(data, extra[0]), nil
	}
	if err != io.EOF {
		return nil, err
	}
	return data, nil
}

// IsJSONMediaType accepts exactly one Content-Type field naming
// application/json, optionally with the parameter charset=utf-8.
func IsJSONMediaType(fields []string) bool {
	if len(fields) != 1 {
		return false
	}
	mediaType, params, err := mime.ParseMediaType(fields[0])
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, value := range params {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

// ValidateRequest checks the declared request headers and the decoded body
// against the operation's schemas. It returns the rejection reason, or "".
// Library error text can quote the input, so it is never returned.
func ValidateRequest(header http.Header, document any, r *compile.Rule) string {
	// The proxy removes every field named in Connection, so a validated field
	// named there would not reach the upstream as it was checked: a declared
	// header, or the media type of a validated body. Such a request is refused
	// rather than forwarded without it.
	for _, name := range connectionNames(header) {
		validatedHeader := r.Headers() != nil && r.Headers().Declares(name)
		validatedMediaType := r.Body() != nil && name == "Content-Type"
		if validatedHeader || validatedMediaType {
			return "connection_nominated"
		}
	}
	if r.Headers() != nil {
		declared := map[string]any{}
		for name := range r.Headers().Names() {
			values := header.Values(name)
			if len(values) > 1 {
				return "repeated_header"
			}
			if len(values) == 1 {
				declared[name] = values[0]
			}
		}
		if r.Headers().Validate(declared) != nil {
			return "header_mismatch"
		}
	}
	if r.Body() != nil && r.Body().Validate(document) != nil {
		return "schema_mismatch"
	}
	return ""
}
