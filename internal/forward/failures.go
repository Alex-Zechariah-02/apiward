// Forwarding failure classification.

package forward

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

// ForwardFailure maps a forwarding failure to the gateway's answer: 504 when
// the upstream timed out, 503 when no upstream could be used, and 502
// otherwise.
func ForwardFailure(err error) (int, string) {
	switch {
	case errors.Is(err, ErrUpstreamTimeout):
		return http.StatusGatewayTimeout, "upstream_timeout"
	case errors.Is(err, ErrNoUpstream):
		return http.StatusServiceUnavailable, "gateway_unavailable"
	case errors.Is(err, errEjected):
		return http.StatusServiceUnavailable, "upstream_unavailable"
	}
	return http.StatusBadGateway, "upstream_unavailable"
}

// ExchangeFailure classifies an exchange that failed before any response by
// what is known about delivery and, for the gateway's answer, whether the
// upstream timed out.
func ExchangeFailure(err error, connected, clientGone bool) error {
	switch {
	case !connected:
		return fmt.Errorf("%w: %w", errNotSent, err)
	case clientGone:
		return fmt.Errorf("%w: %w", errClientGone, err)
	}
	// Once connected, only the response-header timeout ends the exchange
	// with a timeout error.
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return fmt.Errorf("%w: %w: %w", ErrUpstreamTimeout, errMaybeSent, err)
	}
	return fmt.Errorf("%w: %w", errMaybeSent, err)
}

// FailureReason states what is known about the delivery of a request whose
// forwarding failed before any response: "not_sent" when it never reached
// the upstream, or why not when the gateway refused the connection
// ("destination_refused": an address no setting allows; "certificate_invalid";
// "tls_handshake_failed"; "upstream_ejected": the endpoint failed to connect
// repeatedly and is ejected for a while), "outcome_unknown" when the upstream may have acted
// on it, and
// "client_cancelled" when the client went away after it was handed to an
// upstream connection, which leaves the outcome unknown too. A forwarder that
// cannot tell gives no reason.
func FailureReason(err error) string {
	switch {
	case errors.Is(err, errEjected):
		return "upstream_ejected"
	case errors.Is(err, errRefused):
		return "destination_refused"
	case errors.Is(err, errCertificate):
		return "certificate_invalid"
	case errors.Is(err, errHandshake), errors.Is(err, errProfileMissing):
		return "tls_handshake_failed"
	case errors.Is(err, errNotSent):
		return "not_sent"
	case errors.Is(err, errClientGone):
		return "client_cancelled"
	case errors.Is(err, errMaybeSent):
		return "outcome_unknown"
	}
	return ""
}
