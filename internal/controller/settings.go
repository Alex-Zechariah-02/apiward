// Defaults, bounds and checks of the controller's settings.

package controller

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// Defaults and bounds of the controller's settings, which the configuration
// file check applies too.
const (
	DefaultAuditWait = 2 * time.Second
	MinAuditBytes    = 4 << 10
	MaxAuditBytes    = 1 << 30
	MaxAuditFiles    = 1000
	// History bounds: 100 revisions keep every rollback made by hand in
	// reach; 100,000 at the 64 KiB policy ceiling is 6.5 GiB of documents.
	DefaultHistory  = 1000
	MinHistory      = 100
	MaxHistory      = 100_000
	DefaultIdle     = 15 * time.Minute
	DefaultLifetime = 8 * time.Hour
	MinSession      = time.Second
	MaxSession      = 24 * time.Hour
)

// DefaultIgnoredReads are the reads the Dashboard repeats every second on a
// visible page; recording each would write one record per second per page.
var DefaultIgnoredReads = []string{"/admin/status", "/admin/traffic", "/admin/events"}

// Check checks the settings the controller needs before it opens anything.
func (cfg Config) Check() error {
	if cfg.Database == "" || cfg.AuditLog == "" || cfg.AdminListen == "" {
		return errors.New("database, audit_log and admin_listen are required")
	}
	addr, err := netip.ParseAddrPort(cfg.AdminListen)
	if err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 {
		return fmt.Errorf("admin_listen %q must be a literal loopback address with a port", cfg.AdminListen)
	}
	return nil
}

// applyDefaults sets the defaults of unset limits and checks every limit's
// bounds.
func (cfg *Config) applyDefaults() error {
	if cfg.AuditTimeout <= 0 {
		cfg.AuditTimeout = DefaultAuditWait
	}
	if cfg.AuditMaxBytes == 0 {
		cfg.AuditMaxBytes = audit.DefaultAuditBytes
	}
	if cfg.AuditMaxFiles == 0 {
		cfg.AuditMaxFiles = audit.DefaultAuditFiles
	}
	if cfg.HistoryKeep == 0 {
		cfg.HistoryKeep = DefaultHistory
	}
	if cfg.AuditWhenFull == "" {
		cfg.AuditWhenFull = audit.FullRefuse
	}
	if cfg.IgnoredReads == nil {
		cfg.IgnoredReads = DefaultIgnoredReads
	}
	if cfg.AdminIdleTimeout == 0 {
		cfg.AdminIdleTimeout = DefaultIdle
	}
	if cfg.AdminSessionLifetime == 0 {
		cfg.AdminSessionLifetime = DefaultLifetime
	}
	var err error
	if cfg.Limits, err = cfg.Limits.Resolve(); err != nil {
		return err
	}
	if cfg.AuditMaxBytes < MinAuditBytes || cfg.AuditMaxBytes > MaxAuditBytes {
		return fmt.Errorf("audit_max_bytes must be %d to %d", MinAuditBytes, MaxAuditBytes)
	}
	if cfg.AuditMaxFiles < 2 || cfg.AuditMaxFiles > MaxAuditFiles {
		return fmt.Errorf("audit_max_files must be 2 to %d", MaxAuditFiles)
	}
	if cfg.HistoryKeep < MinHistory || cfg.HistoryKeep > MaxHistory {
		return fmt.Errorf("history_keep must be %d to %d", MinHistory, MaxHistory)
	}
	if cfg.AuditWhenFull != audit.FullRefuse && cfg.AuditWhenFull != audit.FullEvict {
		return fmt.Errorf("audit_when_full must be %q or %q", audit.FullRefuse, audit.FullEvict)
	}
	for _, setting := range []time.Duration{cfg.AdminIdleTimeout, cfg.AdminSessionLifetime} {
		if setting < MinSession || setting > MaxSession {
			return fmt.Errorf("admin_idle_timeout and admin_session_lifetime must be %s to %s", MinSession, MaxSession)
		}
	}
	return nil
}
