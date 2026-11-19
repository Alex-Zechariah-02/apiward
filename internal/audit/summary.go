// Ingress refusals, and policy refusals beyond an address's budget, counted
// rather than recorded one by one.

package audit

import (
	"cmp"
	"maps"
	"slices"
	"sync"
	"time"
)

// Requests refused at ingress (a target not in origin form, a tunnel, an
// upgrade, a declared body over the ceiling, overload) reach no policy, so
// they are counted and written as one audit.ingress_summary record per
// SummaryInterval, with the addresses that sent the most. A flood of them
// costs a counter, not a durable record each.
const (
	// SummaryInterval keeps a flood to one record a minute while still
	// placing it in time to the minute.
	SummaryInterval = time.Minute
	// summaryTop is how many of the busiest addresses one summary names:
	// enough to see a flood's sources, few enough for one readable record.
	summaryTop = 16
	// summaryAddresses bounds the addresses counted per interval; refusals
	// from further addresses still count in their reason.
	summaryAddresses = 4096
)

// AddressCount is how many refusals one client address had.
type AddressCount struct {
	Address string `json:"address"`
	Count   uint64 `json:"count"`
}

type ingressSummary struct {
	mu        sync.Mutex
	since     time.Time
	reasons   map[string]uint64
	addresses map[string]uint64
	// refusals counts the full refusal records each address had this
	// interval (RecordRefusal).
	refusals map[string]int
}

// refusalRecords is how many policy refusals (401, 403, 429) one client
// address may have as full records per SummaryInterval; further ones are
// counted in the summary, so one cheap request type cannot force a durable
// record each and push older evidence out of the log.
const refusalRecords = 60

// RecordRefusal records a policy refusal in full while its client address
// has had fewer than refusalRecords this interval, and otherwise counts it
// in the summary under "<stage>/<reason>/<operation>", with exact counts.
// Refusals from addresses beyond the summaryAddresses tracked are counted
// too.
func (a *AuditLog) RecordRefusal(e Event) {
	if a.refusalBudget(e.ClientAddress) {
		a.Record(e)
		return
	}
	a.Summarise(e.Stage+"/"+cmp.Or(e.Reason, e.Error)+"/"+e.Operation, e.ClientAddress)
}

// refusalBudget takes one full refusal record from address's budget, or
// reports that it has none left.
func (a *AuditLog) refusalBudget(address string) bool {
	s := &a.summary
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refusals == nil {
		s.refusals = map[string]int{}
	}
	n, known := s.refusals[address]
	if n >= refusalRecords || (!known && len(s.refusals) >= summaryAddresses) {
		return false
	}
	s.refusals[address] = n + 1
	return true
}

// Summarise counts one ingress refusal by its reason and client address.
func (a *AuditLog) Summarise(reason, address string) {
	s := &a.summary
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reasons == nil {
		s.since = time.Now().UTC()
		s.reasons, s.addresses = map[string]uint64{}, map[string]uint64{}
	}
	s.reasons[reason]++
	if _, known := s.addresses[address]; known || len(s.addresses) < summaryAddresses {
		s.addresses[address]++
	}
}

// takeSummary returns the counted refusals as one event and starts a new
// interval, or false when none were counted.
func (a *AuditLog) takeSummary() (Event, bool) {
	s := &a.summary
	s.mu.Lock()
	reasons, addresses, since := s.reasons, s.addresses, s.since
	s.reasons, s.addresses, s.refusals = nil, nil, nil
	s.mu.Unlock()
	if reasons == nil {
		return Event{}, false
	}
	top := make([]AddressCount, 0, len(addresses))
	for address, count := range addresses {
		top = append(top, AddressCount{Address: address, Count: count})
	}
	slices.SortFunc(top, func(x, y AddressCount) int {
		return cmp.Or(cmp.Compare(y.Count, x.Count), cmp.Compare(x.Address, y.Address))
	})
	return Event{Kind: "audit.ingress_summary", First: since, Counts: maps.Clone(reasons), Addresses: top[:min(len(top), summaryTop)]}, true
}
