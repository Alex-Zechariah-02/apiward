// What a start reports: each setting that weakens protection as a warning,
// the identity assertion key in force, and the security log records of the
// configuration file and the keys a start loaded.

package gateway

import (
	"log/slog"
	"net/netip"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
)

// warnSettings names at start each setting that weakens protection, and the
// identity assertion's key ID, which an upstream's key set must hold.
func warnSettings(cfg nativeConfig, logger *slog.Logger) {
	if cfg.unsigned {
		logger.Warn("identity assertion off (upstream.unsigned_identity): upstreams receive unsigned X-Gateway-Subject and X-Gateway-Roles and must accept requests only from the gateway")
	}
	if cfg.signer != nil {
		logger.Info("identity assertion", "kid", cfg.signer.KeyID())
	}
	if listen, err := netip.ParseAddrPort(cfg.listen); err == nil && listen.Addr().Unmap().IsUnspecified() {
		logger.Warn("data listener on every interface (data.listen_all_interfaces): every network the host reaches can send requests")
	}
	if metrics, err := netip.ParseAddrPort(cfg.metricsListen); err == nil && !metrics.Addr().IsLoopback() {
		logger.Warn("metrics and health off loopback (gateway.metrics_listen_any): /metrics, /livez and /readyz answer anyone who reaches the address, without authentication or TLS; allow only the scraper and the load balancer by firewall")
	}
	if slices.ContainsFunc(cfg.limits.TrustedProxies, func(p netip.Prefix) bool { return p.Bits() == 0 }) {
		logger.Warn("every peer is a trusted proxy (data.trusted_proxies holds 0.0.0.0/0 or ::/0): clients choose their own address through X-Forwarded-For, so address blocks, address rate limits and allow_addresses no longer bind them")
	}
	if cfg.file.Upstream.AllowPublicAddresses {
		logger.Warn("upstreams may use public addresses (upstream.allow_public_addresses)")
	}
	warnAudit(cfg.controller, logger)
}

// warnAudit names at start each security log setting that keeps fewer
// records than the defaults: eviction deletes the oldest rotated file, and
// reads added to the ignored ones write no admin.read record.
func warnAudit(cfg controller.Config, logger *slog.Logger) {
	if cfg.AuditWhenFull == audit.FullEvict {
		logger.Warn("security log eviction on (gateway.audit_when_full): the oldest rotated file is deleted when the file limit is reached")
	}
	if extra := slices.DeleteFunc(slices.Clone(cfg.IgnoredReads), func(path string) bool { return slices.Contains(controller.DefaultIgnoredReads, path) }); len(extra) > 0 {
		logger.Warn("security log skips more reads (gateway.audit_ignore_reads): these reads write no admin.read record", "paths", extra)
	}
}

// recordStart writes what a start loaded to the security log: the
// configuration file with its SHA-256, then each token verification key
// (its ID and fingerprint) and the identity assertion key (its ID, a
// thumbprint).
func recordStart(c *controller.Controller, cfg nativeConfig) {
	log := c.Audit()
	log.Record(audit.Event{Kind: "gateway.started", File: cfg.source.path, Digest: cfg.source.digest})
	for _, key := range c.Verifier().Keys() {
		log.Record(audit.Event{Kind: "gateway.key", Target: key.Kid, Digest: key.Fingerprint, Reason: "verification"})
	}
	if cfg.signer != nil {
		log.Record(audit.Event{Kind: "gateway.key", Target: cfg.signer.KeyID(), Reason: "assertion"})
	}
}
