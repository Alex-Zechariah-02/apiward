// Error replies and response status recording.

package pipeline

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// writeError answers a data-plane refusal; its JSON body is never sniffed
// as another type. The body is appended directly, without a map or an
// encoder: code is one of the gateway's own error words and requestID hex,
// so neither needs escaping beyond a quote.
func writeError(w http.ResponseWriter, status int, code, requestID string) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	body := make([]byte, 0, 64+len(code)+len(requestID))
	body = append(body, `{"error":`...)
	body = strconv.AppendQuote(body, code)
	body = append(body, `,"request_id":`...)
	body = strconv.AppendQuote(body, requestID)
	body = append(body, "}\n"...)
	w.WriteHeader(status)
	// #nosec G705 -- a JSON body of quoted values, sent as application/json with nosniff
	if _, err := w.Write(body); err != nil {
		panic(http.ErrAbortHandler)
	}
}

// statusRecorder notes the final status the forwarder wrote, while passing
// everything through unchanged.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(status int) {
	// Informational (1xx) responses precede the final status.
	if !s.wrote && status >= http.StatusOK {
		s.status, s.wrote = status, true
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(data []byte) (int, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	return s.ResponseWriter.Write(data)
}

// Unwrap lets http.ResponseController reach the underlying writer, so a
// forwarder can flush a streamed response through the recorder.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Interface guard
var _ http.Handler = (*Handler)(nil)

// WriteJSON answers with value as JSON that no cache keeps. A body that
// could not be written in full aborts the connection, so a client never
// reads a cut-off body as a complete answer.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if json.NewEncoder(w).Encode(value) != nil {
		panic(http.ErrAbortHandler)
	}
}
