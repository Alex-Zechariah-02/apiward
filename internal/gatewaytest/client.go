// Data-plane requests to a deployment, well-formed or raw on one
// connection, the bodies they carry, and small JSON helpers.

package gatewaytest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Get sends a GET to the data plane and returns its status and body.
func (e *Env) Get(path string, header ...string) (int, string) {
	return e.Request(http.MethodGet, path, "", "", header...)
}

// Request sends one data-plane request and returns its status and body.
func (e *Env) Request(method, path, contentType, body string, header ...string) (int, string) {
	e.T.Helper()
	resp, data := e.Exchange(method, path, contentType, body, header...)
	return resp.StatusCode, data
}

// Exchange sends one request to the data plane and returns the response,
// whose body has been read into the returned string.
func (e *Env) Exchange(method, path, contentType, body string, header ...string) (*http.Response, string) {
	e.T.Helper()
	req, err := http.NewRequest(method, "http://"+e.DataAddr+path, strings.NewReader(body))
	if err != nil {
		e.T.Fatal(err)
	}
	if body == "" {
		req.Body = http.NoBody
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		e.T.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

// Raw sends bytes exactly as given, bypassing client-side normalisation.
func (e *Env) Raw(request string) (int, string) {
	e.T.Helper()
	resp, data := e.RawResponse(request)
	return resp.StatusCode, data
}

// RawResponse is raw returning the whole response, whose body has been read
// into the returned string.
func (e *Env) RawResponse(request string) (*http.Response, string) {
	e.T.Helper()
	conn, err := net.DialTimeout("tcp", e.DataAddr, 5*time.Second)
	if err != nil {
		e.T.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		e.T.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		e.T.Fatalf("reading response to %q: %v", request, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

// AnyObject is a body schema that accepts any JSON object.
const AnyObject = `{"type":"object","additionalProperties":true}`

// JSONBody declares a JSON body with the given size limit and schema.
func JSONBody(maxBytes int64, schema string) *policy.BodyRule {
	return &policy.BodyRule{MaxBytes: maxBytes, Schema: json.RawMessage(schema)}
}

// MustJSON encodes v, panicking if it cannot be encoded.
func MustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// FileSHA256 is the hex SHA-256 of a file's content.
func FileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// OpenResponse sends request byte for byte and reads the response head,
// leaving the body to the caller. The connection closes when the test ends.
func (e *Env) OpenResponse(request string) (*http.Response, net.Conn) {
	e.T.Helper()
	conn, err := net.DialTimeout("tcp", e.DataAddr, 5*time.Second)
	if err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		e.T.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		e.T.Fatalf("reading the response to %q: %v", request, err)
	}
	return resp, conn
}

// SizedBody returns a JSON object of exactly size bytes whose only member
// starts with tag, so that concurrent bodies can be told apart.
func SizedBody(tag string, size int) string {
	return `{"p":"` + tag + strings.Repeat("x", size-8-len(tag)) + `"}`
}

// ChunkedBody encodes body in chunks of at most size bytes, followed by the
// last chunk.
func ChunkedBody(body string, size int) string {
	var b strings.Builder
	for len(body) > 0 {
		n := min(size, len(body))
		fmt.Fprintf(&b, "%x\r\n%s\r\n", n, body[:n])
		body = body[n:]
	}
	b.WriteString("0\r\n\r\n")
	return b.String()
}

// SendBody posts a JSON body to path with the named framing and returns the
// status and reply. "declared" and "chunked" are HTTP/1.1 requests written
// byte for byte, the chunked body in chunks of at most 4096 bytes. header
// holds name/value pairs.
func (e *Env) SendBody(framing, path, body string, header ...string) (int, string) {
	e.T.Helper()
	head := "POST " + path + " HTTP/1.1\r\nHost: gw\r\nConnection: close\r\nContent-Type: application/json\r\n"
	for i := 0; i+1 < len(header); i += 2 {
		head += header[i] + ": " + header[i+1] + "\r\n"
	}
	if framing == "declared" {
		return e.RawExchange(fmt.Sprintf("%sContent-Length: %d\r\n\r\n%s", head, len(body), body), false)
	}
	return e.RawExchange(head+"Transfer-Encoding: chunked\r\n\r\n"+ChunkedBody(body, 4096), false)
}

// SizeRefusal returns the stage and reason expected when a body one byte over
// the effective ceiling is refused: a declared length above the global
// ceiling is refused at ingress, before any policy work; every other excess
// when the body is read.
func SizeRefusal(framing string, size, global int) (string, string) {
	if framing == "declared" && size > global {
		return "INGRESS", ""
	}
	return "BODY", "too_large"
}

// RawExchange sends a request exactly as given and returns the status and
// body of the reply. With halfClose the client then closes its sending side,
// so a body shorter than its declared length ends early.
func (e *Env) RawExchange(request string, halfClose bool) (int, string) {
	e.T.Helper()
	conn, err := net.DialTimeout("tcp", e.DataAddr, 5*time.Second)
	if err != nil {
		e.T.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		e.T.Fatal(err)
	}
	if halfClose {
		conn.(*net.TCPConn).CloseWrite()
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}
