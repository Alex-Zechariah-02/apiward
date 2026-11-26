// API entries: the upstream binding and the per-API forward rule, browser
// access (CORS), response headers and client address allow list.

package policy

import "net/netip"

// API registers one managed API and the single upstream that serves it.
type API struct {
	ID              string           `json:"id"`
	Upstream        string           `json:"upstream"`
	Forward         *Forward         `json:"forward,omitempty"`
	CORS            *CORS            `json:"cors,omitempty"`
	ResponseHeaders *ResponseHeaders `json:"response_headers,omitempty"`
	// AllowAddresses, when present, lists the only client address ranges
	// (CIDR) whose requests reach the API's operations.
	AllowAddresses []string `json:"allow_addresses,omitempty"`
}

// Forward rewrites the path an admitted request is forwarded with: the
// inbound path without StripPrefix, after AddPrefix. Every decision is made
// on the inbound path; the rewrite applies only to the outbound request.
//
// In an OpenAPI description the rule is the root member named
// ForwardExtension.
type Forward struct {
	StripPrefix string `json:"strip_prefix,omitempty"`
	AddPrefix   string `json:"add_prefix,omitempty"`
}

// CORS is the API's cross-origin browser access. The gateway answers
// preflights itself and adds the allowed origin to responses; it never
// decides access with it.
type CORS struct {
	Origins     []string `json:"origins"`
	Methods     []string `json:"methods"`
	Headers     []string `json:"headers,omitempty"`
	Expose      []string `json:"expose,omitempty"`
	Credentials bool     `json:"credentials,omitempty"`
	// MaxAgeSeconds is how long browsers may cache a preflight answer;
	// absent means DefaultCORSMaxAge.
	MaxAgeSeconds *int64 `json:"max_age_seconds,omitempty"`
}

// ResponseHeaders adds security headers to the API's responses when the
// upstream did not set them, and removes the named upstream headers.
type ResponseHeaders struct {
	HSTS     bool     `json:"hsts,omitempty"`
	Nosniff  bool     `json:"nosniff,omitempty"`
	Frame    string   `json:"frame,omitempty"`    // "deny" or "sameorigin"
	Referrer string   `json:"referrer,omitempty"` // "no-referrer" or "strict-origin-when-cross-origin"
	Remove   []string `json:"remove,omitempty"`
}

// Limits of the per-API settings.
// MaxCORSOrigins bounds one API's origin list; a browser rule names a few sites.
// MaxCORSHeaders bounds the allow-headers value one preflight answer carries.
// MaxCORSExpose bounds the expose-headers value the gateway builds and sends.
// MaxRemoveHeaders bounds the names deleted from an API's response headers.
// MaxAllowAddresses bounds the ranges checked against each client address.
const (
	DefaultCORSMaxAge = 600
	MaxCORSMaxAge     = 86_400
	MaxCORSOrigins    = 32
	MaxCORSHeaders    = 32
	MaxCORSExpose     = 16
	MaxRemoveHeaders  = 16
	MaxAllowAddresses = 256
)

// OpenAPI root members carrying an API's settings; one API per
// description.
const (
	ForwardExtension         = "x-apiward-forward"
	CORSExtension            = "x-apiward-cors"
	ResponseHeadersExtension = "x-apiward-response-headers"
	AddressesExtension       = "x-apiward-addresses"
)

// MappedBits is the leading bit length of an IPv4-mapped IPv6 address (::ffff:0:0/96).
const MappedBits = 96

// ParseRange parses a CIDR range whose host bits are zero. An
// IPv4-mapped IPv6 range becomes the IPv4 range it covers; callers that need
// the canonical text compare it with the returned prefix's String.
func ParseRange(text string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil || prefix.Masked() != prefix {
		return netip.Prefix{}, false
	}
	if addr := prefix.Addr(); addr.Is4In6() {
		if prefix.Bits() < MappedBits {
			return netip.Prefix{}, false
		}
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-MappedBits)
	}
	return prefix, true
}
