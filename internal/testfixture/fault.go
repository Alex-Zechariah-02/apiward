//go:build faultinject

// Fault injection for testfixture: drops the response after a state write.

package testfixture

import (
	"net/http"
	"os"
)

// dropAfterWrite loses the acknowledgement only after the service changed
// state and recorded its independent receipt. No response or replay follows.
func dropAfterWrite(w http.ResponseWriter) bool {
	if os.Getenv("FIXTURE_FAULT") != "drop-after-write" {
		return false
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic(http.ErrAbortHandler)
	}
	connection, _, err := hijacker.Hijack()
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	connection.Close()
	return true
}
