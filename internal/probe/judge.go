// Observed classes per format, and the judgement of a difference against its ledger item.

package probe

import (
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
)

// Gateway is the format name of the gateway's own answers.
const Gateway = "apiward"

// statuses map each format's refusal statuses to classes; a status not
// listed is error. Kong has no method class: a method no route takes is 404.
var statuses = map[string]map[int]Class{
	Gateway:     {400: Validation, 401: Authn, 403: Authz, 404: NotFound, 405: Method, 413: Size, 415: Validation, 429: Rate},
	"kong-deck": {400: Validation, 401: Authn, 403: Authz, 404: NotFound, 413: Size, 429: Rate},
}

// Answer is what a gateway did with one request.
type Answer struct {
	Received bool // the upstream recorded it
	Status   int
	Header   http.Header
}

// Observed is the class of an answer: forwarded when the upstream received
// the request, whatever the status; for a preflight answered with 2xx, the
// browser's check; else the format's class of the status.
func Observed(format string, p Probe, a Answer) Class {
	switch {
	case a.Received:
		return Forwarded
	case p.Request(0).IsPreflight() && a.Status/100 == 2 && browserAllows(p, a.Header):
		return PreflightAllowed
	case p.Request(0).IsPreflight() && a.Status/100 == 2:
		return PreflightRefused
	}
	if class, listed := statuses[format][a.Status]; listed {
		return class
	}
	return Error
}

// Verdict is the judgement of one probe.
type Verdict string

const (
	Same       Verdict = "same"       // the same class
	StatusOnly Verdict = "status"     // both found no operation, one by path and one by method
	Expected   Verdict = "expected"   // a difference its ledger item predicts
	Unexpected Verdict = "unexpected" // a difference nothing predicts
)

// Judge compares the gateway's class with the source's. A difference is
// expected only when the probe's ledger item is an approximation in the
// difference's direction: stricter when only the source grants (forwards,
// or allows a preflight), looser when only the gateway does; a different
// refusal fits any direction.
func Judge(gateway, source Class, item *exchange.Item) Verdict {
	switch {
	case gateway == source:
		return Same
	case missing(gateway) && missing(source):
		return StatusOnly
	case item == nil || item.Class != exchange.Approximated:
		return Unexpected
	}
	direction := item.Direction
	switch {
	case grants(source) && direction == exchange.Looser, grants(gateway) && direction == exchange.Stricter:
		return Unexpected
	}
	return Expected
}

func grants(class Class) bool { return class == Forwarded || class == PreflightAllowed }

func missing(class Class) bool { return class == NotFound || class == Method }
