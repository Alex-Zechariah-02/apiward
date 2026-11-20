// The security log's storage settings: the archive folder and its bound,
// compression, the free-space threshold and the reserve file , each with its default and range.

package gateway

import (
	"errors"
	"path/filepath"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// Defaults and ranges of the storage settings. 10 GiB holds about a day and
// a half of a 750 requests/s load once compressed; 10 % free is the kubelet's eviction threshold; the reserve holds one rotation
// of records at the default file size.
const (
	defaultArchiveBytes = 10 << 30
	minArchiveBytes     = 64 << 20
	maxArchiveBytes     = 16 << 40
	defaultMinFree      = 10
	maxMinFree          = 50
	defaultReserve      = audit.DefaultAuditBytes
	minReserve          = 1 << 20
	maxReserve          = 1 << 30
)

// auditStorage checks the storage settings; the archive folder defaults to
// "archive" beside the active file and must be an absolute path.
func auditStorage(g gatewaySettings) (audit.Storage, error) {
	s := audit.Storage{Archive: filepath.Join(filepath.Dir(g.AuditLog), "archive"), Plain: g.AuditCompress != nil && !*g.AuditCompress}
	if g.AuditArchive != nil {
		if !filepath.IsAbs(*g.AuditArchive) {
			return audit.Storage{}, errors.New("gateway.audit_archive must be an absolute path")
		}
		s.Archive = *g.AuditArchive
	}
	var err error
	if s.ArchiveBytes, err = numberSetting("gateway.audit_archive_max_bytes", g.AuditArchiveMaxBytes, defaultArchiveBytes, minArchiveBytes, maxArchiveBytes); err != nil {
		return audit.Storage{}, err
	}
	if s.MinFree, err = numberSetting("gateway.audit_min_free_percent", g.AuditMinFreePercent, defaultMinFree, 1, maxMinFree); err != nil {
		return audit.Storage{}, err
	}
	if s.Reserve, err = numberSetting("gateway.audit_reserve_bytes", g.AuditReserveBytes, defaultReserve, minReserve, maxReserve); err != nil {
		return audit.Storage{}, err
	}
	return s, nil
}
