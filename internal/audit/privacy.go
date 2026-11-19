// Privacy of client addresses in the log, off by default: an address may be
// recorded whole (the default), as its network prefix (IPv4 /24, IPv6 /48),
// or as a keyed hash that links one client's records without naming it
// (GDPR data minimisation; Caddy's ip_mask and hash log filters). Only the
// record changes: rate keys and blocked addresses keep the whole address in
// memory, and subjects are never masked.

package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

// Client address modes.
const (
	AddressFull   = "full"
	AddressPrefix = "prefix"
	AddressHash   = "hash"
)

// Privacy is how the log records client addresses: Mode is one of the
// modes above ("" is full); Key is the HMAC key of the hash mode.
type Privacy struct {
	Mode string
	Key  []byte
}

// MinAddressKey is the shortest hash key: 32 bytes, the HMAC-SHA-256 block
// half, so the key is never the weak part (RFC 2104 section 3).
const MinAddressKey = 32

// address is how the log records a client address.
func (p Privacy) address(text string) string {
	switch p.Mode {
	case AddressPrefix:
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return text
		}
		bits := 48
		if addr.Unmap().Is4() {
			addr, bits = addr.Unmap(), 24
		}
		prefix, err := addr.Prefix(bits)
		if err != nil {
			return text
		}
		return prefix.String()
	case AddressHash:
		mac := hmac.New(sha256.New, p.Key)
		mac.Write([]byte(text))
		// 128 bits keep distinct clients apart in any log's lifetime.
		return "hmac:" + hex.EncodeToString(mac.Sum(nil)[:16])
	}
	return text
}
