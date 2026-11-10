// Capacity ceilings of a deployment: how large a policy it accepts and how
// much request state it keeps, with their defaults and hard maxima.

package policy

import "fmt"

// Defaults of the capacity ceilings, which a deployment may raise up to the
// maxima below. A rate counter keeps 257 bytes of heap, so 1,048,576
// counters need about 257 MiB. MaxPolicyBytes is the store's own bound on a
// stored document (its CHECK constraint), so a policy is never accepted that
// the database would refuse to keep.
const (
	DefaultPolicyBytes  = 64 << 10
	DefaultAPIs         = 64
	DefaultOperations   = 256
	DefaultRoles        = 64
	DefaultPermits      = 4096
	DefaultRateCounters = 262144
	DefaultWindow       = 10000

	MaxPolicyBytes  = 64 << 10
	MaxAPIs         = 256
	MaxOperations   = 4096
	MaxRoles        = 256
	MaxPermits      = 65536
	MaxRateCounters = 1 << 20
	MaxWindow       = 100000
)

// Limits are the capacity ceilings a deployment runs with. A zero member
// takes its default. APIs bounds the upstreams too; Window is the number of
// recent requests kept for live views.
type Limits struct {
	PolicyBytes  int
	APIs         int
	Operations   int
	Roles        int
	Permits      int
	RateCounters int
	Window       int
}

// Resolve returns l with every zero member set to its default, or an error
// naming the first member outside 1 to its maximum.
func (l Limits) Resolve() (Limits, error) {
	for _, s := range []struct {
		name      string
		value     *int
		def, high int
	}{
		{"policy_bytes", &l.PolicyBytes, DefaultPolicyBytes, MaxPolicyBytes},
		{"apis", &l.APIs, DefaultAPIs, MaxAPIs},
		{"operations", &l.Operations, DefaultOperations, MaxOperations},
		{"roles", &l.Roles, DefaultRoles, MaxRoles},
		{"permits", &l.Permits, DefaultPermits, MaxPermits},
		{"rate_counters", &l.RateCounters, DefaultRateCounters, MaxRateCounters},
		{"monitor_window", &l.Window, DefaultWindow, MaxWindow},
	} {
		if *s.value == 0 {
			*s.value = s.def
		}
		if *s.value < 1 || *s.value > s.high {
			return Limits{}, fmt.Errorf("limits.%s must be 1 to %d", s.name, s.high)
		}
	}
	return l, nil
}
