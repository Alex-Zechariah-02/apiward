// The security log's storage on the metrics listener: the archive, the
// disks' free space, the reserve, recoveries after a failed sync and the
// save-wait histogram, so an alert fires before records are refused.

package controller

import (
	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// auditGauges reads the log's storage state and save waits.
func auditGauges(log *audit.AuditLog) []monitor.Gauge {
	saves := log.Saves()
	gauges := []monitor.Gauge{
		{Name: "gateway_audit_sync_recoveries_total", Value: log.Recoveries(), Counter: true},
		{Name: "gateway_audit_slow_saves_total", Value: saves.Slow, Counter: true},
		{Name: "gateway_audit_save_seconds", Spread: &monitor.Spread{Bounds: audit.SaveBounds, Buckets: saves.Buckets, Count: saves.Count, Sum: saves.Sum}},
	}
	state, ok := log.Archive()
	if !ok {
		return gauges
	}
	usable := int64(0)
	if state.Usable {
		usable = 1
	}
	return append(gauges,
		monitor.Gauge{Name: "gateway_audit_archive_ok", Value: usable},
		monitor.Gauge{Name: "gateway_audit_archive_bytes", Value: state.Bytes},
		monitor.Gauge{Name: "gateway_audit_archive_budget_bytes", Value: state.Budget},
		monitor.Gauge{Name: "gateway_audit_pending_files", Value: state.Waiting},
		monitor.Gauge{Name: "gateway_audit_free_bytes", Value: state.FreeLog, Labels: []string{"disk", "log"}},
		monitor.Gauge{Name: "gateway_audit_free_bytes", Value: state.FreeArchive, Labels: []string{"disk", "archive"}},
		monitor.Gauge{Name: "gateway_audit_reserve_bytes", Value: state.Reserve},
		monitor.Gauge{Name: "gateway_audit_pressure_evictions_total", Value: state.Pressure, Counter: true},
	)
}
