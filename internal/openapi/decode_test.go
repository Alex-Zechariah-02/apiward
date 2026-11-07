// Reading limits: a description over the size limit is refused before it is parsed.

package openapi

import (
	"strings"
	"testing"
)

// TestDecodeLimit refuses a description over 1 MiB, naming the limit.
func TestDecodeLimit(t *testing.T) {
	data := []byte(`{"openapi": "3.1.0", "pad": "` + strings.Repeat("a", 2<<20) + `"}`)
	if _, err := decode(data, JSON); err == nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
		t.Fatalf("error %v", err)
	}
}
