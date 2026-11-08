// Upstream destinations: the two upstream forms of the policy, the address
// classes an upstream may use, and the endpoint a compiled rule forwards to.

package compile

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Endpoint is one compiled upstream: how and where the forwarder connects.
// Only the compiler makes one, so a forwarder handed an Endpoint was handed
// a checked destination.
type Endpoint struct {
	field   string     // the policy member holding the destination, for refusals
	scheme  string     // "http" or "https"
	address string     // host:port to dial: a literal IP or, over https, a DNS name
	name    string     // the TLS server name: the URL host without the port
	ip      netip.Addr // the literal IP of the host; zero for a DNS name
	profile string     // TLS profile ID; "" uses the system roots and no client certificate
	host    string     // the Host header sent; "" keeps the inbound one
}

// Scheme is "http" or "https".
func (e *Endpoint) Scheme() string { return e.scheme }

// Address is the host and port the forwarder dials.
func (e *Endpoint) Address() string { return e.address }

// ServerName is the name the upstream's certificate must hold.
func (e *Endpoint) ServerName() string { return e.name }

// Profile is the TLS profile the connection uses; "" means none was named.
func (e *Endpoint) Profile() string { return e.profile }

// Host is the Host header the upstream receives; "" keeps the client's.
func (e *Endpoint) Host() string { return e.host }

// Network is what the operator allows upstream destinations to use. The
// compiler asks it whether public addresses are allowed and which TLS
// profiles exist.
type Network interface {
	Public() bool
	Has(profile string) bool
}

// metadata are cloud metadata and platform addresses outside the link-local
// ranges, refused whatever the operator allows (sources in upstream_test.go).
var metadata = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),   // AWS instance metadata over IPv6
	netip.MustParseAddr("fd20:ce::254"),    // Google Cloud metadata server over IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud instance metadata
	netip.MustParseAddr("168.63.129.16"),   // Azure platform endpoint (WireServer)
}

// shared is the shared address space of carrier-grade NAT (RFC 6598).
var shared = netip.MustParsePrefix("100.64.0.0/10")

// Refused reports an address no setting can allow: unspecified, link-local
// (where most cloud metadata services answer), multicast, broadcast or a
// named metadata address. IPv4-mapped IPv6 addresses are unmapped first.
func Refused(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.Is4() && a.As4()[0] == 0,
		a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsMulticast(),
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return true
	}
	for _, m := range metadata {
		if a == m {
			return true
		}
	}
	return false
}

// Allowed reports whether an upstream connection may use a: never a refused
// address; loopback, private and shared addresses by default; any other
// (public) address only when public is set.
func Allowed(a netip.Addr, public bool) bool {
	a = a.Unmap()
	if Refused(a) {
		return false
	}
	return public || a.IsLoopback() || a.IsPrivate() || shared.Contains(a)
}

// compileUpstreams checks the policy's upstreams and returns their endpoints
// by ID. A schema 4 document may only use the loopback dial form.
func compileUpstreams(p policy.Policy) (map[string]*Endpoint, error) {
	endpoints := map[string]*Endpoint{}
	destinations := map[string]bool{}
	for i, u := range p.Upstreams {
		if err := policy.CheckID(u.ID, "upstreams[%d].id", i); err != nil {
			return nil, err
		}
		if _, exists := endpoints[u.ID]; exists {
			return nil, policy.Invalid("DUPLICATE_ID", "upstreams[%d].id", i)
		}
		e, err := compileUpstream(u, i, p.SchemaVersion)
		if err != nil {
			return nil, err
		}
		// Two upstream identities for one destination would make receipts
		// and events ambiguous about which service was reached.
		destination := e.scheme + "://" + e.address
		if destinations[destination] {
			return nil, policy.Invalid("INVALID_UPSTREAM", "%s", e.field)
		}
		destinations[destination] = true
		endpoints[u.ID] = e
	}
	return endpoints, nil
}

// defaultPorts are the ports a URL without one uses.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

func compileUpstream(u policy.Upstream, i, version int) (*Endpoint, error) {
	if version < policy.LatestSchemaVersion {
		for _, m := range []struct{ name, value string }{{"url", u.URL}, {"tls", u.TLS}, {"host", u.Host}} {
			if m.value != "" {
				return nil, policy.Invalid("INVALID_VALUE", "upstreams[%d].%s", i, m.name)
			}
		}
	}
	if u.URL == "" {
		// The dial form has today's meaning: plain HTTP to a loopback address.
		switch {
		case u.TLS != "":
			return nil, policy.Invalid("INVALID_VALUE", "upstreams[%d].tls", i)
		case u.Host != "":
			return nil, policy.Invalid("INVALID_VALUE", "upstreams[%d].host", i)
		case !isLoopbackDial(u.Dial):
			return nil, policy.Invalid("INVALID_UPSTREAM", "upstreams[%d].dial", i)
		}
		dial := netip.MustParseAddrPort(u.Dial) // checked just above
		return &Endpoint{field: fmt.Sprintf("upstreams[%d].dial", i), scheme: "http", address: u.Dial, name: dial.Addr().String(), ip: dial.Addr()}, nil
	}
	if u.Dial != "" {
		return nil, policy.Invalid("INVALID_UPSTREAM", "upstreams[%d].dial", i)
	}
	e, ok := parseUpstreamURL(u.URL)
	if !ok {
		return nil, policy.Invalid("INVALID_UPSTREAM", "upstreams[%d].url", i)
	}
	e.field = fmt.Sprintf("upstreams[%d].url", i)
	if u.TLS != "" {
		if e.scheme != "https" {
			return nil, policy.Invalid("INVALID_VALUE", "upstreams[%d].tls", i)
		}
		if err := policy.CheckID(u.TLS, "upstreams[%d].tls", i); err != nil {
			return nil, err
		}
		e.profile = u.TLS
	}
	// Over https the upstream's certificate names its host, so by default it
	// receives that host; over http it receives the client's, as today.
	switch {
	case u.Host == "upstream", u.Host == "" && e.scheme == "https":
		e.host = hostHeader(e)
	case u.Host == "inbound", u.Host == "":
	default:
		return nil, policy.Invalid("INVALID_VALUE", "upstreams[%d].host", i)
	}
	return e, nil
}

// parseUpstreamURL accepts http://<literal IP>[:port] and
// https://<literal IP or DNS name>[:port] with nothing after the origin
// but an optional "/". Literal IPs must not be refused addresses.
func parseUpstreamURL(raw string) (*Endpoint, bool) {
	if len(raw) > policy.MaxUpstreamURL || strings.ContainsAny(raw, "?#\\ ") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || u.Host == "" {
		return nil, false
	}
	name, port := u.Hostname(), u.Port()
	if port == "" {
		port = defaultPorts[u.Scheme]
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return nil, false
	}
	e := &Endpoint{scheme: u.Scheme, name: name, address: net.JoinHostPort(name, port)}
	if ip, err := netip.ParseAddr(name); err == nil {
		if ip.Zone() != "" || Refused(ip) || ip.String() != name {
			return nil, false
		}
		e.ip = ip
		return e, true
	}
	// Only TLS proves the answering server is the named one.
	return e, u.Scheme == "https" && isDNSName(name)
}

// isDNSName accepts lower-case LDH names of at least two labels.
func isDNSName(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// hostHeader is the URL host with the port only when it is not the scheme's
// default.
func hostHeader(e *Endpoint) string {
	_, port, _ := net.SplitHostPort(e.address)
	if port == defaultPorts[e.scheme] {
		if strings.Contains(e.name, ":") {
			return "[" + e.name + "]"
		}
		return e.name
	}
	return e.address
}

// CheckNetwork refuses a generation the operator's network settings do not
// allow: a literal public address without the public switch, or a TLS
// profile the operator file does not define.
func (g *Generation) CheckNetwork(n Network) error {
	for _, e := range g.endpoints {
		if e.profile != "" && !n.Has(e.profile) {
			return policy.Invalid("UNKNOWN_TLS_PROFILE", "%s", strings.TrimSuffix(e.field, "url")+"tls")
		}
		if !e.ip.IsValid() {
			continue // a name is checked once resolved, before each connection
		}
		if !Allowed(e.ip, n.Public()) {
			return policy.Invalid("INVALID_UPSTREAM", "%s", e.field)
		}
	}
	return nil
}
