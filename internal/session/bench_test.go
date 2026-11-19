// Benchmarks of session lookups, as every Admin API request and streamed
// event makes them.

package session

import (
	"testing"
	"time"
)

func BenchmarkLookup(b *testing.B) {
	table := New(time.Hour, time.Hour, MaxPerAdmin)
	now := time.Now()
	tokens := make([]string, 0, 64)
	for range 64 {
		token, _, err := table.Create("admin", 1, now)
		if err != nil {
			b.Fatal(err)
		}
		tokens = append(tokens, token)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, reason := table.Lookup(tokens[i%len(tokens)], now); reason != "" {
				b.Error(reason)
				return
			}
			i++
		}
	})
}
