// What a start reports: each setting that weakens protection as a warning,
// the identity assertion key in force, and the security log records of the
// configuration file and the keys a start loaded.

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
)

// weakening is one setting in force that weakens protection.
type weakening struct{ setting, message string }

// weakenings lists the settings in force that weaken protection.
func weakenings(cfg nativeConfig) []weakening {
	var list []weakening
	if cfg.unsigned {
		list = append(list, weakening{"upstream.unsigned_identity", "identity assertion off: upstreams receive unsigned X-Gateway-Subject and X-Gateway-Roles and must accept requests only from the gateway"})
	}
	if listen, err := netip.ParseAddrPort(cfg.listen); err == nil && listen.Addr().Unmap().IsUnspecified() {
		list = append(list, weakening{"data.listen_all_interfaces", "data listener on every interface: every network the host reaches can send requests"})
	}
	if metrics, err := netip.ParseAddrPort(cfg.metricsListen); err == nil && !metrics.Addr().IsLoopback() {
		list = append(list, weakening{"gateway.metrics_listen_any", "metrics and health off loopback: /metrics, /livez and /readyz answer anyone who reaches the address, without authentication or TLS; allow only the scraper and the load balancer by firewall"})
	}
	if health, err := netip.ParseAddrPort(cfg.healthListen); err == nil && !health.Addr().IsLoopback() {
		list = append(list, weakening{"gateway.health_listen_any", "health off loopback: /livez and /readyz answer anyone who reaches the address; allow only the load balancer by firewall"})
	}
	if slices.ContainsFunc(cfg.limits.TrustedProxies, func(p netip.Prefix) bool { return p.Bits() == 0 }) {
		list = append(list, weakening{"data.trusted_proxies", "every peer is a trusted proxy (0.0.0.0/0 or ::/0): clients choose their own address through X-Forwarded-For, so address blocks, address rate limits and allow_addresses no longer bind them"})
	}
	if cfg.file.Upstream.AllowPublicAddresses {
		list = append(list, weakening{"upstream.allow_public_addresses", "upstreams may use public addresses"})
	}
	if cfg.controller.AuditWhenFull == audit.FullEvict {
		list = append(list, weakening{"gateway.audit_when_full", "security log eviction on: the oldest rotated file is deleted when the file limit is reached"})
	}
	return list
}

// warnSettings names at start each setting that weakens protection, and the
// identity assertion's key ID, which an upstream's key set must hold.
func warnSettings(cfg nativeConfig, logger *slog.Logger) {
	if cfg.signer != nil {
		logger.Info("identity assertion", "kid", cfg.signer.KeyID())
	}
	for _, w := range weakenings(cfg) {
		logger.Warn(w.message, "setting", w.setting)
	}
	warnAudit(cfg.controller, logger)
}

// warnAudit names at start each security log setting that keeps fewer
// records than the defaults: eviction deletes the oldest rotated file, and
// reads added to the ignored ones write no admin.read record.
func warnAudit(cfg controller.Config, logger *slog.Logger) {
	if extra := slices.DeleteFunc(slices.Clone(cfg.IgnoredReads), func(path string) bool { return slices.Contains(controller.DefaultIgnoredReads, path) }); len(extra) > 0 {
		logger.Warn("security log skips more reads (gateway.audit_ignore_reads): these reads write no admin.read record", "paths", extra)
	}
}

// recordStart writes what a start loaded to the security log, once every
// listener is bound, so a start that failed to bind leaves no
// gateway.started: the configuration file with its SHA-256 and the SHA-256
// of the settings as resolved (after ${NAME} substitution), one
// gateway.weakened per setting that weakens protection, then each token
// verification key (its ID and fingerprint) and the identity assertion key
// (its ID, a thumbprint).
func recordStart(c *controller.Controller, cfg nativeConfig) {
	log := c.Audit()
	log.Record(audit.Event{Kind: "gateway.started", File: cfg.source.path, Digest: cfg.source.digest, ResolvedDigest: resolvedDigest(cfg.file)})
	for _, w := range weakenings(cfg) {
		log.Record(audit.Event{Kind: "gateway.weakened", Target: w.setting, Reason: w.message})
	}
	for _, key := range c.Verifier().Keys() {
		log.Record(audit.Event{Kind: "gateway.key", Target: key.Kid, Digest: key.Fingerprint, Reason: "verification"})
	}
	if cfg.signer != nil {
		log.Record(audit.Event{Kind: "gateway.key", Target: cfg.signer.KeyID(), Reason: "assertion"})
	}
}

// resolvedDigest is the SHA-256 of the settings as resolved: the file's
// digest alone does not say what a ${NAME} reference resolved to.
func resolvedDigest(f nativeFile) string {
	data, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
