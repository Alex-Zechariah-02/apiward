// Upstream connections: the address check every connection passes just
// before it connects, and TLS to https upstreams.

package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// Connection failures before any request byte is sent, each recorded as its
// own reason.
var (
	errRefused        = errors.New("destination refused")
	errHandshake      = errors.New("TLS handshake failed")
	errCertificate    = errors.New("upstream certificate invalid")
	errProfileMissing = errors.New("the upstream's TLS profile is not loaded")
)

// checkAddress is the dialer's Control hook: it sees the address the socket
// is about to connect to, after any DNS resolution, so neither a policy nor a
// DNS answer can lead a connection to a refused address.
func (p *upstreamProxy) checkAddress(_, address string, _ syscall.RawConn) error {
	addr, err := netip.ParseAddrPort(address)
	if err != nil || !compile.Allowed(addr.Addr(), p.network().Public()) {
		return errRefused
	}
	return nil
}

// dialTLS connects to the https endpoint the request is bound to and
// completes the TLS handshake within the dial timeout. The transport passes
// the request's context, so the endpoint comes from its binding; an address
// that is not the bound endpoint's is refused.
func (p *upstreamProxy) dialTLS(ctx context.Context, network, address string) (net.Conn, error) {
	d, bound := Bound(ctx)
	e := d.Endpoint()
	if !bound || e == nil || e.Scheme() != "https" || e.Address() != address {
		return nil, errRefused
	}
	config, err := p.network().clientConfig(e)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.dialer.Timeout)
	defer cancel()
	conn, err := p.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	session := tls.Client(conn, config)
	if err := session.HandshakeContext(ctx); err != nil {
		conn.Close()
		if _, invalid := errors.AsType[*tls.CertificateVerificationError](err); invalid {
			return nil, fmt.Errorf("%w: %w", errCertificate, err)
		}
		return nil, fmt.Errorf("%w: %w", errHandshake, err)
	}
	return session, nil
}
