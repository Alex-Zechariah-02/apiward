// Differential runs: probes sent to a live gateway, decided again by the reference evaluator of the source, compared by class.

package migrate

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
	"github.com/Alex-Zechariah-02/apiward/internal/probe"
	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// target is a gateway under probe: its address, the format of its
// answers and the upstream that records what it forwards.
type target struct {
	format, addr string
	up           *upstream
}

// observed holds a run's class per probe and the send times of each burst.
type observed struct {
	classes map[string]probe.Class
	bursts  map[string][]int64
}

var client = &http.Client{Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// probeAll sends every probe in file order; rate probes wait for empty
// windows and send their burst from the start of a second; error probes go
// last, after the upstream is stopped.
func probeAll(t *testing.T, tg target, file *probe.File, ops map[string]probe.Operation, s *signer) observed {
	t.Helper()
	run := observed{classes: map[string]probe.Class{}, bursts: map[string][]int64{}}
	var failing []probe.Probe
	var window time.Duration // the longest window a burst filled
	for _, p := range file.Probes {
		switch p.Expect.Class {
		case probe.Error:
			failing = append(failing, p)
		case probe.Rate:
			run.classes[p.ID], run.bursts[p.ID] = burst(t, tg, p, ops[p.Operation], s)
			window = max(window, time.Duration(ops[p.Operation].Route.Rate.Window)*time.Second)
		default:
			before := tg.up.received(t)
			answer := send(t, tg.addr, p, body(t, ops[p.Operation], p), s)
			answer.Received = tg.up.received(t) > before
			run.classes[p.ID] = probe.Observed(tg.format, p, answer)
		}
	}
	tg.up.stop()
	time.Sleep(2 * window) // a full window would refuse an error probe for its rate
	for _, p := range failing {
		run.classes[p.ID] = probe.Observed(tg.format, p, send(t, tg.addr, p, body(t, ops[p.Operation], p), s))
	}
	return run
}

// burst sends count+1 requests, rate when any is refused for the rate.
func burst(t *testing.T, tg target, p probe.Probe, o probe.Operation, s *signer) (probe.Class, []int64) {
	t.Helper()
	window := time.Duration(o.Route.Rate.Window) * time.Second
	time.Sleep(2 * window) // both windows a sliding limit reads are empty
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second + 20*time.Millisecond).Sub(now))
	class, times := probe.Forwarded, []int64{}
	for range o.Route.Rate.Count + 1 {
		times = append(times, time.Now().UnixMilli())
		if probe.Observed(tg.format, p, send(t, tg.addr, p, body(t, o, p), s)) == probe.Rate {
			class = probe.Rate
		}
	}
	return class, times
}

func body(t *testing.T, o probe.Operation, p probe.Probe) []byte {
	t.Helper()
	data, err := probe.Body(o, p.BodyKind)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// send makes one probe request and returns the answer's status and headers.
func send(t *testing.T, addr string, p probe.Probe, data []byte, s *signer) probe.Answer {
	t.Helper()
	request, err := http.NewRequest(p.Method, "http://"+addr+p.Path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if data == nil {
		request.Body = http.NoBody
	} else {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range p.Headers {
		if strings.EqualFold(name, "Host") {
			request.Host = value
			continue
		}
		request.Header.Set(name, value)
	}
	if token := s.token(p.Identity); token != "" {
		request.Header.Set("Authorization", token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s: %v", p.ID, err)
	}
	response.Body.Close()
	return probe.Answer{Status: response.StatusCode, Header: response.Header}
}

// reference decides every probe on the source's routes; bursts are
// judged at the times the gateway's run sent them, and a forwarded request
// fails while the upstream is stopped.
func reference(t *testing.T, routes []semantics.Route, file *probe.File, ops map[string]probe.Operation, bursts map[string][]int64) map[string]probe.Class {
	t.Helper()
	classes := map[string]probe.Class{}
	for _, p := range file.Probes {
		class, route := probe.Decide(routes, p.Request(int64(len(body(t, ops[p.Operation], p)))))
		switch {
		case class == probe.Forwarded && p.Expect.Class == probe.Rate:
			class = probe.Burst(route, bursts[p.ID])
		case class == probe.Forwarded && p.Expect.Class == probe.Error:
			class = probe.Error
		}
		classes[p.ID] = class
	}
	return classes
}

// compare fails on a gateway decision the probe file does not expect and
// on every difference from the source its ledger item does not predict.
func compare(t *testing.T, file *probe.File, ledger *exchange.Ledger, gateway, source map[string]probe.Class) {
	t.Helper()
	items := map[string]*exchange.Item{}
	for i := range ledger.Items {
		items[ledger.Items[i].ID] = &ledger.Items[i]
	}
	verdicts := map[probe.Verdict]int{}
	for _, p := range file.Probes {
		g, src, item := gateway[p.ID], source[p.ID], items[p.Expect.LedgerItem]
		if g != p.Expect.Class {
			t.Errorf("%s: the gateway decided %s, the probe file expects %s", p.ID, g, p.Expect.Class)
		}
		verdict := probe.Judge(g, src, item)
		verdicts[verdict]++
		if verdict == probe.Unexpected {
			t.Errorf("%s: gateway %s, source %s; ledger item %s (%+v) does not predict it", p.ID, g, src, p.Expect.LedgerItem, item)
		}
	}
	t.Logf("%d probes: %d same, %d expected differences, %d status only, %d unexpected", len(file.Probes),
		verdicts[probe.Same], verdicts[probe.Expected], verdicts[probe.StatusOnly], verdicts[probe.Unexpected])
}
