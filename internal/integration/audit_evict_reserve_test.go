// Dedicated eviction reserve recovery under full-disk audit faults.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// When another writer takes the space the general reserve freed, the gateway
// enters noSpace and refuses admissions; the archiver records audit.evicted
// through the eviction reserve before deleting the evicted file, then
// admission resumes. One refused write costs one file, not the whole history.
func TestEvictionReserveRecoversFullDisk(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	e.WriteConfig(gatewaytest.ConfigOptions{Audit: map[string]any{
		"audit_max_bytes":     4096,
		"audit_max_files":     4,
		"audit_when_full":     "evict_oldest",
		"audit_reserve_bytes": 1 << 20,
	}})
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	armed := filepath.Join(e.Dir, "fault-armed")
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-full-evict-reserve", "GATEWAY_FAULT_ARMED="+armed)

	dir := filepath.Dir(e.AuditLog)
	generalReserve := filepath.Join(dir, "audit.reserve")
	evictReserve := filepath.Join(dir, "audit.evict.reserve")

	stored := func() int { return len(gatewaytest.RotatedAudit(t, e.AuditLog)) }
	for range 300 {
		if code, body := e.Get("/a/x"); code != http.StatusOK {
			t.Fatalf("GET /a/x before fault: %d %s", code, body)
		}
		if stored() >= 3 {
			break
		}
	}
	gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "both reserve files and three rotated or archived files", func() bool {
		_, err1 := os.Stat(generalReserve)
		_, err2 := os.Stat(evictReserve)
		return err1 == nil && err2 == nil && stored() >= 3
	})

	metrics := scrapeMetrics(t, e.Metrics)
	if got, ok := metricValue(t, metrics, "gateway_audit_reserve_bytes"); !ok || int64(got) != 1<<20 {
		t.Fatalf("gateway_audit_reserve_bytes = (%v, %v), want %d", got, ok, 1<<20)
	}

	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.Get("/a/x"); code != http.StatusServiceUnavailable {
		t.Fatalf("protected request while disk is full: %d, want 503", code)
	}

	gatewaytest.WaitFor(t, time.Now().Add(15*time.Second), "eviction reserve recovery and admission resuming", func() bool {
		code, _ := e.Get("/a/x")
		return code == http.StatusOK
	})
	// Stop kills the process: wait until the archiver has moved every rotated
	// file, so its records no longer rotate the active file under the kill.
	gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "the archiver to finish", func() bool {
		for _, f := range gatewaytest.RotatedAudit(t, e.AuditLog) {
			if filepath.Dir(f) == dir {
				return false
			}
		}
		_, err := os.Stat(e.AuditLog)
		return err == nil
	})
	metricsAfter := scrapeMetrics(t, e.Metrics)
	evictionsMetric, _ := metricValue(t, metricsAfter, "gateway_audit_evictions_total")
	e.Stop()

	evicted, recovered := 0, 0
	for _, ev := range auditRecords(e) {
		if ev["kind"] == "audit.evicted" && ev["reason"] == "disk_pressure" {
			evicted++
		}
		if ev["kind"] == "audit.recovered" && ev["reason"] == "storage_space" {
			recovered++
		}
	}
	if evicted != 1 {
		t.Fatalf("%d disk_pressure audit.evicted records, want 1 (gateway_audit_evictions_total=%v)", evicted, evictionsMetric)
	}
	if recovered < 1 {
		t.Fatal("no audit.recovered (storage_space) record written")
	}
}

// While the log refuses writes for want of space, protected requests stay
// refused (503) and never consume the eviction reserve.
func TestEvictionReserveOnlyForEvictions(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	e.WriteConfig(gatewaytest.ConfigOptions{Audit: map[string]any{
		"audit_max_bytes":     1 << 20,
		"audit_max_files":     4,
		"audit_when_full":     "evict_oldest",
		"audit_reserve_bytes": 1 << 20,
	}})
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	armed := filepath.Join(e.Dir, "fault-armed")
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-full-evict-reserve", "GATEWAY_FAULT_ARMED="+armed)

	dir := filepath.Dir(e.AuditLog)
	evictReserve := filepath.Join(dir, "audit.evict.reserve")
	gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "eviction reserve to be created", func() bool {
		_, err := os.Stat(evictReserve)
		return err == nil
	})

	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if code, _ := e.Get("/a/x"); code != http.StatusServiceUnavailable {
			t.Fatalf("protected request while disk is full with nothing to evict: %d, want 503", code)
		}
	}
	if _, err := os.Stat(evictReserve); err != nil {
		t.Fatalf("eviction reserve was consumed by normal requests: %v", err)
	}

	if err := os.Remove(armed); err != nil {
		t.Fatal(err)
	}
	gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "admission to resume once fault clears", func() bool {
		code, _ := e.Get("/a/x")
		return code == http.StatusOK
	})
}
