// Traffic summaries: per-group counts, response-time percentiles and top lists.

package monitor

import (
	"slices"
	"strings"
)

// TrafficGroup counts the requests of one API or one endpoint and keeps
// their durations for the percentiles.
type TrafficGroup struct {
	API       string  `json:"api"`
	Operation string  `json:"operation,omitempty"`
	Total     int     `json:"total"`
	Allowed   int     `json:"allowed"`
	Refused   int     `json:"refused"`
	P50       float64 `json:"p50_ms"`
	P95       float64 `json:"p95_ms"`
	durations []float64
}

func (g *TrafficGroup) Add(event RequestView) {
	g.Total++
	g.durations = append(g.durations, event.DurationMS)
	if WasAllowed(event) {
		g.Allowed++
	} else {
		g.Refused++
	}
}

// Percentiles returns the median and the 95th percentile of durations, which
// it sorts in place; both are zero when there are none.
func Percentiles(durations []float64) (float64, float64) {
	n := len(durations)
	if n == 0 {
		return 0, 0
	}
	slices.Sort(durations)
	return durations[(n-1)/2], durations[(95*n+99)/100-1]
}

func (g *TrafficGroup) Settle() TrafficGroup {
	g.P50, g.P95 = Percentiles(g.durations)
	return *g
}

// TrafficTop keeps the groups with the most requests, at most limit of them,
// ties broken by name so the order is stable between readings.
func TrafficTop[T any](items []T, count func(T) int, name func(T) string, limit int) []T {
	slices.SortFunc(items, func(a, b T) int {
		if count(a) != count(b) {
			return count(b) - count(a)
		}
		return strings.Compare(name(a), name(b))
	})
	return items[:min(len(items), limit)]
}

const TopLimit = 10
