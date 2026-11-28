// Audit metric snapshots own their bucket definitions and counts.

package controller

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

func TestAuditHistogramSnapshotOwnsBounds(t *testing.T) {
	var log audit.AuditLog
	read := func() *monitor.Spread {
		t.Helper()
		for _, gauge := range auditGauges(&log) {
			if gauge.Name == "gateway_audit_save_seconds" {
				return gauge.Spread
			}
		}
		t.Fatal("audit save histogram is missing")
		return nil
	}
	published := read()
	if published == nil || len(published.Bounds) == 0 {
		t.Fatal("audit save histogram has no bounds")
	}
	original := append([]float64(nil), published.Bounds...)
	t.Cleanup(func() { copy(published.Bounds, original) })
	published.Bounds[0] = -1
	current := read()
	if current.Bounds[0] != original[0] {
		t.Fatalf("editing one snapshot changed the histogram bound to %g", current.Bounds[0])
	}
	if len(current.Buckets) != len(current.Bounds)+1 {
		t.Fatalf("histogram has %d counters for %d bounds", len(current.Buckets), len(current.Bounds))
	}
}

func TestAuditHistogramSnapshotShape(t *testing.T) {
	t.Parallel()
	var log audit.AuditLog
	found := false
	for _, gauge := range auditGauges(&log) {
		if gauge.Name == "gateway_audit_archive_ok" {
			t.Fatal("an inactive archiver has an availability metric")
		}
		if gauge.Name != "gateway_audit_save_seconds" {
			continue
		}
		found = true
		histogram := gauge.Spread
		if histogram == nil || len(histogram.Bounds) == 0 {
			t.Fatal("save histogram has no bounds")
		}
		if len(histogram.Buckets) != len(histogram.Bounds)+1 {
			t.Fatal("save histogram counters do not match its bounds")
		}
		if histogram.Count != 0 || histogram.Sum != 0 {
			t.Fatal("an unused log reports save observations")
		}
	}
	if !found {
		t.Fatal("save histogram is missing")
	}
}
