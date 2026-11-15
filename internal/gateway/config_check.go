// Configuration file checks and setting ranges.

package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// check resolves defaults and checks every setting the controller does not
// check itself.
func (f nativeFile) check() (nativeConfig, error) {
	g, d, u := f.Gateway, f.Data, f.Upstream
	cfg := nativeConfig{
		file: f,
		controller: controller.Config{
			Database:    g.Database,
			AuditLog:    g.AuditLog,
			AdminListen: g.AdminListen,
			JWT:         g.JWT,
		},
		listen: d.Listen,
	}
	for _, required := range []struct{ name, value string }{
		{"gateway.database", g.Database},
		{"gateway.audit_log", g.AuditLog},
		{"gateway.admin_listen", g.AdminListen},
		{"gateway.jwt.issuer", g.JWT.Issuer},
		{"gateway.jwt.audience", g.JWT.Audience},
		{"data.listen", d.Listen},
	} {
		if required.value == "" {
			return nativeConfig{}, fmt.Errorf("%s is required", required.name)
		}
	}
	if len(g.JWT.Keys) == 0 || len(g.JWT.Keys) > pipeline.MaxKeys {
		return nativeConfig{}, fmt.Errorf("gateway.jwt.keys must contain 1 to %d keys", pipeline.MaxKeys)
	}
	for i, key := range g.JWT.Keys {
		if key.PublicKeyFile == "" || !filepath.IsAbs(key.PublicKeyFile) {
			return nativeConfig{}, fmt.Errorf("gateway.jwt.keys[%d].public_key_file must be an absolute path", i)
		}
	}
	// A relative path would depend on the directory the gateway is started
	// in.
	for _, file := range []struct {
		name  string
		value *string
	}{
		{"gateway.database", &g.Database},
		{"gateway.audit_log", &g.AuditLog},
		{"gateway.admin_ui", g.AdminUI},
		{"upstream.identity_key", u.IdentityKey},
	} {
		if file.value != nil && !filepath.IsAbs(*file.value) {
			return nativeConfig{}, fmt.Errorf("%s must be an absolute path", file.name)
		}
	}
	if err := checkDataListen(d.Listen, d.ListenAllInterfaces); err != nil {
		return nativeConfig{}, err
	}
	metrics := defaultMetricsListen
	if g.MetricsListen != nil {
		metrics = *g.MetricsListen
	}
	address, err := netip.ParseAddrPort(metrics)
	if err != nil || (!address.Addr().IsLoopback() && !g.MetricsListenAny) || address.Port() == 0 {
		return nativeConfig{}, errors.New("gateway.metrics_listen must be a loopback address with a nonzero port (any address only with gateway.metrics_listen_any)")
	}
	cfg.metricsListen = metrics
	if err := checkTransport(d); err != nil {
		return nativeConfig{}, err
	}
	if err := checkDistinct(d, g.AdminListen, metrics); err != nil {
		return nativeConfig{}, err
	}
	cfg.tls, cfg.redirect = d.TLS, d.RedirectHTTP
	cfg.http2 = d.HTTP2 == nil || *d.HTTP2

	durations := []struct {
		name      string
		value     *string
		def       time.Duration
		low, high time.Duration
		into      *time.Duration
	}{
		{"gateway.admin_idle_timeout", g.AdminIdleTimeout, controller.DefaultIdle, controller.MinSession, controller.MaxSession, &cfg.controller.AdminIdleTimeout},
		{"gateway.admin_session_lifetime", g.AdminSessionLifetime, controller.DefaultLifetime, controller.MinSession, controller.MaxSession, &cfg.controller.AdminSessionLifetime},
		{"gateway.audit_timeout", g.AuditTimeout, controller.DefaultAuditWait, minAuditTimeout, maxAuditTimeout, &cfg.controller.AuditTimeout},
		{"gateway.audit_sync_window", g.AuditSyncWindow, 0, 0, maxSyncWindow, &cfg.controller.AuditSyncWindow},
		{"gateway.shutdown_grace", g.ShutdownGrace, controller.ShutdownWait, minServerTimeout, maxServerTimeout, &cfg.shutdownGrace},
		{"gateway.shutdown_delay", g.ShutdownDelay, 0, 0, maxShutdownDelay, &cfg.shutdownDelay},
		{"data.read_header_timeout", d.ReadHeaderTimeout, defaultReadHeader, minServerTimeout, maxServerTimeout, &cfg.readHeaderTimeout},
		{"data.read_timeout", d.ReadTimeout, defaultRead, minServerTimeout, maxServerTimeout, &cfg.readTimeout},
		{"data.write_timeout", d.WriteTimeout, defaultWrite, minServerTimeout, maxServerTimeout, &cfg.writeTimeout},
		{"data.idle_timeout", d.IdleTimeout, defaultIdleKeepAlive, minServerTimeout, maxServerTimeout, &cfg.idleTimeout},
		{"upstream.dial_timeout", u.DialTimeout, defaultDial, minUpstreamTimeout, maxUpstreamTimeout, &cfg.upstream.Dial},
		{"upstream.response_header_timeout", u.ResponseHeaderTimeout, defaultUpstreamWait, minUpstreamTimeout, maxUpstreamTimeout, &cfg.upstream.ResponseHeader},
		{"upstream.read_idle_timeout", u.ReadIdleTimeout, defaultUpstreamWait, minUpstreamTimeout, maxUpstreamTimeout, &cfg.upstream.ReadIdle},
		{"upstream.idle_conn_timeout", u.IdleConnTimeout, defaultIdleConn, minUpstreamTimeout, maxUpstreamTimeout, &cfg.pool.IdleTimeout},
		{"upstream.tls_session_lifetime", u.TLSSessionLifetime, defaultSessionLife, minSessionLife, maxSessionLife, &cfg.sessionLife},
	}
	for _, s := range durations {
		if *s.into, err = durationSetting(s.name, s.value, s.def, s.low, s.high); err != nil {
			return nativeConfig{}, err
		}
	}
	// The header must arrive within the time allowed for the whole request.
	if cfg.readHeaderTimeout > cfg.readTimeout {
		return nativeConfig{}, errors.New("data.read_header_timeout must not exceed data.read_timeout")
	}

	if cfg.controller.AuditMaxBytes, err = numberSetting("gateway.audit_max_bytes", g.AuditMaxBytes, audit.DefaultAuditBytes, controller.MinAuditBytes, controller.MaxAuditBytes); err != nil {
		return nativeConfig{}, err
	}
	if cfg.controller.AuditMaxFiles, err = numberSetting("gateway.audit_max_files", g.AuditMaxFiles, audit.DefaultAuditFiles, 2, controller.MaxAuditFiles); err != nil {
		return nativeConfig{}, err
	}
	if cfg.controller.HistoryKeep, err = numberSetting("gateway.history_keep", g.HistoryKeep, controller.DefaultHistory, controller.MinHistory, controller.MaxHistory); err != nil {
		return nativeConfig{}, err
	}
	if cfg.limits.MaxBodyBytes, err = numberSetting("data.max_body_bytes", d.MaxBodyBytes, pipeline.DefaultMaxBody, 1, policy.MaxBodyLimit); err != nil {
		return nativeConfig{}, err
	}
	if cfg.limits.MaxInFlight, err = numberSetting("data.max_in_flight", d.MaxInFlight, pipeline.DefaultMaxInFlight, 1, maxInFlightLimit); err != nil {
		return nativeConfig{}, err
	}
	cfg.controller.AuditQueue = audit.QueueSize(cfg.limits.MaxInFlight)
	cfg.controller.AuditWhenFull = g.AuditWhenFull
	cfg.controller.AuditAppend = g.AuditPrefill != nil && !*g.AuditPrefill
	if cfg.controller.IgnoredReads, err = ignoredReads(g.AuditIgnoreReads); err != nil {
		return nativeConfig{}, err
	}
	if cfg.limits.IPv6RatePrefix, err = numberSetting("data.ipv6_rate_prefix", d.IPv6RatePrefix, pipeline.DefaultIPv6RatePrefix, pipeline.MinIPv6RatePrefix, 128); err != nil {
		return nativeConfig{}, err
	}
	if cfg.limits.TrustedProxies, err = pipeline.ParseProxies(d.TrustedProxies); err != nil {
		return nativeConfig{}, fmt.Errorf("data.trusted_proxies: %w", err)
	}
	if cfg.maxConnections, err = numberSetting("data.max_connections", d.MaxConnections, defaultMaxConnections, 16, maxConnectionsLimit); err != nil {
		return nativeConfig{}, err
	}
	if cfg.headerLimit, err = numberSetting("data.max_header_bytes", d.MaxHeaderBytes, defaultHeaderBytes, minHeaderBytes, maxHeaderBytes); err != nil {
		return nativeConfig{}, err
	}

	if cfg.controller.Limits, err = f.Limits.check(); err != nil {
		return nativeConfig{}, err
	}

	if cfg.pool.EjectAfter, err = numberSetting("upstream.eject_after", u.EjectAfter, defaultEjectAfter, 0, maxEjectAfter); err != nil {
		return nativeConfig{}, err
	}
	if cfg.pool.MaxIdle, err = numberSetting("upstream.max_idle_per_upstream", u.MaxIdlePerUpstream, defaultMaxIdle, 0, maxIdlePerUpstream); err != nil {
		return nativeConfig{}, err
	}
	if u.UnsignedIdentity && u.IdentityKey != nil {
		return nativeConfig{}, errors.New("upstream.identity_key and upstream.unsigned_identity exclude each other")
	}

	if g.AdminUI != nil {
		cfg.adminUI = *g.AdminUI
	}
	return cfg, nil
}

// check resolves the capacity ceilings: each omitted one takes its default,
// a written one must be 1 to its maximum (policy.Limits.Resolve).
func (s limitSettings) check() (policy.Limits, error) {
	var l policy.Limits
	for _, setting := range []struct {
		name  string
		value *int
		into  *int
	}{
		{"policy_bytes", s.PolicyBytes, &l.PolicyBytes},
		{"apis", s.APIs, &l.APIs},
		{"operations", s.Operations, &l.Operations},
		{"roles", s.Roles, &l.Roles},
		{"permits", s.Permits, &l.Permits},
		{"rate_counters", s.RateCounters, &l.RateCounters},
		{"monitor_window", s.MonitorWindow, &l.Window},
	} {
		if setting.value == nil {
			continue
		}
		// Zero means "default" to Resolve, so a written zero is refused here.
		if *setting.value < 1 {
			return policy.Limits{}, fmt.Errorf("limits.%s must be at least 1", setting.name)
		}
		*setting.into = *setting.value
	}
	return l.Resolve()
}

// checkDataListen requires the data-plane address to be a literal IP address
// and port that names one interface, or every interface when all is set. An
// IPv4-mapped IPv6 address is checked as the IPv4 address it binds:
// "[::ffff:0.0.0.0]" listens on every interface.
func checkDataListen(listen string, all bool) error {
	addr, err := netip.ParseAddrPort(listen)
	ip := addr.Addr().Unmap()
	if err != nil || addr.Port() == 0 || (ip.IsUnspecified() && !all) || ip.IsMulticast() {
		return fmt.Errorf("data.listen %q must be a literal IP address of one interface with a port (all interfaces only with data.listen_all_interfaces)", listen)
	}
	return nil
}

// checkDistinct refuses two listeners that would bind the same port on a
// shared address, so the conflict is named here rather than met at the bind.
func checkDistinct(d dataSettings, admin, metrics string) error {
	listeners := []struct{ name, address string }{{"data.listen", d.Listen}, {"gateway.admin_listen", admin}, {"gateway.metrics_listen", metrics}}
	if d.RedirectHTTP != nil {
		listeners = append(listeners, struct{ name, address string }{"data.redirect_http.listen", d.RedirectHTTP.Listen})
	}
	for i, a := range listeners {
		for _, b := range listeners[:i] {
			if overlap(a.address, b.address) {
				return fmt.Errorf("%s and %s must not share an address and port", b.name, a.name)
			}
		}
	}
	return nil
}

// overlap reports whether two listen addresses take the same port on a
// shared address: the same address, or a wildcard of the other's family. An
// IPv6 wildcard ("[::]") also takes IPv4, as Go listens dual-stack there. An
// address that is not a literal IP and port is compared as written.
func overlap(a, b string) bool {
	x, errX := netip.ParseAddrPort(a)
	y, errY := netip.ParseAddrPort(b)
	if errX != nil || errY != nil {
		return a == b
	}
	p, q := x.Addr().Unmap(), y.Addr().Unmap()
	if x.Port() != y.Port() {
		return false
	}
	covers := func(wild, other netip.Addr) bool { return wild.IsUnspecified() && (wild.Is6() || other.Is4()) }
	return p == q || covers(p, q) || covers(q, p)
}

// durationSetting resolves an optional duration: def when omitted, otherwise
// a Go duration string within [low, high].
func durationSetting(name string, value *string, def, low, high time.Duration) (time.Duration, error) {
	if value == nil {
		return def, nil
	}
	d, err := time.ParseDuration(*value)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration such as \"5s\"", name, *value)
	}
	if d < low || d > high {
		return 0, fmt.Errorf("%s must be %s to %s", name, low, high)
	}
	return d, nil
}

// numberSetting resolves an optional integer: def when omitted, otherwise a
// value within [low, high].
func numberSetting[N int | int64](name string, value *N, def, low, high N) (N, error) {
	if value == nil {
		return def, nil
	}
	if *value < low || *value > high {
		return 0, fmt.Errorf("%s must be %d to %d", name, low, high)
	}
	return *value, nil
}

// ignoredReads checks gateway.audit_ignore_reads: absent takes the
// controller's default (nil), [] records every read; each entry is a
// distinct Admin API path.
func ignoredReads(value *[]string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	paths := *value
	if len(paths) > maxIgnoredReads {
		return nil, fmt.Errorf("gateway.audit_ignore_reads lists at most %d paths", maxIgnoredReads)
	}
	for i, path := range paths {
		if !strings.HasPrefix(path, "/admin/") || slices.Contains(paths[:i], path) {
			return nil, errors.New("gateway.audit_ignore_reads must list distinct paths beginning with /admin/")
		}
	}
	return append([]string{}, paths...), nil
}
