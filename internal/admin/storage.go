// Alert A3's storage conditions: the archive folder failing, a disk low on
// free space and rotated files piling up unarchived, each raised before the
// security log can no longer save records.

package admin

import (
	"fmt"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// waitingLimit is how many rotated files may wait for the archiver: one is
// normal right after a rotation, more means it is falling behind.
const waitingLimit = 2

// storageAlerts lists A3's storage conditions; none without an archiver.
func storageAlerts(state audit.ArchiveState, archives bool) []monitor.Finding {
	if !archives {
		return nil
	}
	var items []monitor.Finding
	if !state.Usable {
		items = append(items, monitor.Finding{ID: "A3", Severity: "critical", Object: "security_log",
			Message: "The security log archive folder " + state.Folder + " cannot be written. Rotated files are compressed in the log folder and the oldest are evicted there. Check the disk, mount and permissions."})
	}
	for _, disk := range []struct {
		name        string
		free, total int64
	}{{"log", state.FreeLog, state.TotalLog}, {"archive", state.FreeArchive, state.TotalArchive}} {
		if disk.free < 0 || disk.total <= 0 {
			continue
		}
		switch {
		case disk.free < state.ReserveSize:
			items = append(items, monitor.Finding{ID: "A3", Severity: "critical", Object: "security_log",
				Message: fmt.Sprintf("The security log's %s disk has %s free, less than the reserve. Free space now: the gateway refuses requests once no record can be saved.", disk.name, size(disk.free))})
		case float64(disk.free) < state.MinFree*float64(disk.total):
			items = append(items, monitor.Finding{ID: "A3", Severity: "medium", Object: "security_log",
				Message: fmt.Sprintf("The security log's %s disk has %s free, below its threshold; the oldest log files are being evicted early.", disk.name, size(disk.free))})
		}
	}
	if state.Waiting > waitingLimit {
		items = append(items, monitor.Finding{ID: "A3", Severity: "medium", Object: "security_log",
			Message: fmt.Sprintf("%d rotated security log files are waiting to be archived; the archiver is falling behind or failing.", state.Waiting)})
	}
	return items
}

const (
	mib = 1 << 20
	gib = 1 << 30
)

// size words a byte count in MiB or GiB.
func size(bytes int64) string {
	if bytes >= gib {
		return fmt.Sprintf("%.1f GiB", float64(bytes)/gib)
	}
	return fmt.Sprintf("%.0f MiB", float64(bytes)/mib)
}

func (s *Server) certAlerts(now time.Time) []monitor.Finding {
	var items []monitor.Finding
	if s.config.DataCertificateExpiry != nil {
		if exp, ok := s.config.DataCertificateExpiry(); ok {
			if f := certAlert("data", "", exp, now); f != nil {
				items = append(items, *f)
			}
		}
	}
	if network := s.control.Network(); network != nil {
		for _, p := range network.Profiles() {
			if p.ClientCertificate && p.ExpiresAt != nil {
				if f := certAlert("upstream", p.ID, *p.ExpiresAt, now); f != nil {
					items = append(items, *f)
				}
			}
		}
	}
	return items
}

func certAlert(role, profile string, exp, now time.Time) *monitor.Finding {
	left := exp.Sub(now)
	if left >= monitor.CertWarnDays {
		return nil
	}
	severity := "medium"
	if left < monitor.CertCriticalDays {
		severity = "critical"
	}
	object := "tls:" + role
	subject := "The data listener TLS certificate"
	if profile != "" {
		object = "tls:" + role + ":" + profile
		subject = fmt.Sprintf("The upstream TLS profile %q client certificate", profile)
	}
	var msg string
	if left <= 0 {
		msg = fmt.Sprintf("%s expired at %s. Replace it and reload keys.", subject, exp.UTC().Format(time.RFC3339))
	} else {
		msg = fmt.Sprintf("%s expires in %s (%s). Replace it and reload keys.", subject, about(left.Seconds()), exp.UTC().Format(time.RFC3339))
	}
	return &monitor.Finding{ID: "A5", Severity: severity, Object: object, Message: msg}
}
