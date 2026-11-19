// The audit log's client address setting: gateway.audit_client_address and,
// for the hash mode, the key file gateway.audit_address_key.

package gateway

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
)

// auditPrivacy checks the setting: full (the default), prefix, or hash with
// a secret key file of at least audit.MinAddressKey bytes, readable only by
// its owner. A key is refused in any other mode, so a forgotten key never
// suggests addresses are hashed.
func auditPrivacy(mode, keyFile *string) (audit.Privacy, error) {
	p := audit.Privacy{Mode: audit.AddressFull}
	if mode != nil {
		p.Mode = *mode
	}
	switch p.Mode {
	case audit.AddressFull, audit.AddressPrefix:
		if keyFile != nil {
			return audit.Privacy{}, errors.New("gateway.audit_address_key is used only with gateway.audit_client_address \"hash\"")
		}
		return p, nil
	case audit.AddressHash:
	default:
		return audit.Privacy{}, fmt.Errorf("gateway.audit_client_address must be %q, %q or %q", audit.AddressFull, audit.AddressPrefix, audit.AddressHash)
	}
	if keyFile == nil || !filepath.IsAbs(*keyFile) {
		return audit.Privacy{}, errors.New("gateway.audit_client_address \"hash\" needs gateway.audit_address_key, an absolute path")
	}
	key, err := forward.ReadPEM(*keyFile, filecheck.Secret)
	if err != nil {
		return audit.Privacy{}, fmt.Errorf("gateway.audit_address_key: %w", err)
	}
	if len(key) < audit.MinAddressKey {
		return audit.Privacy{}, fmt.Errorf("gateway.audit_address_key must hold at least %d bytes", audit.MinAddressKey)
	}
	p.Key = key
	return p, nil
}
