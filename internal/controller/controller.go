// Controller configuration, state and construction.

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

const (
	// clockTolerance is how far the wall clock may sit behind the highest
	// time recorded by a committed transition before startup refuses to trust
	// persisted deadlines.
	clockTolerance  = 5 * time.Second
	maxTransitionID = 128
	// A provisional base must be confirmed within this many seconds of its
	// activation. A shorter period only brings the automatic rollback forward;
	// the upper bound limits how long an unconfirmed policy can serve.
	minConfirmSeconds = 1
	maxConfirmSeconds = 24 * 60 * 60
	// stateStopping is the state of a controller whose stop has begun, and
	// stateStopped the state after Stop.
	stateStopping = "stopping"
	stateStopped  = "stopped"
)

// Defaults and bounds of the controller's settings, which the configuration
// file check applies too.
const (
	DefaultAuditWait = 2 * time.Second
	MinAuditBytes    = 4 << 10
	MaxAuditBytes    = 1 << 30
	MaxAuditFiles    = 1000
	DefaultIdle      = 15 * time.Minute
	DefaultLifetime  = 8 * time.Hour
	MinSession       = time.Second
	MaxSession       = 24 * time.Hour
)

// Config is the controller's configuration. Zero limits take their defaults.
type Config struct {
	Database             string
	AuditLog             string
	AdminListen          string
	AdminIdleTimeout     time.Duration
	AdminSessionLifetime time.Duration
	AuditTimeout         time.Duration
	AuditMaxBytes        int64
	AuditMaxFiles        int
	// AuditWhenFull is audit.FullRefuse (the default) or audit.FullEvict.
	AuditWhenFull string
	// AuditQueue is the audit queue's size; audit.QueueSize derives it.
	AuditQueue int
	// AuditSyncWindow is how long the audit writer gathers a batch with
	// siblings before its sync; 0 syncs each batch at once.
	AuditSyncWindow time.Duration
	// AuditAppend appends to the active audit file instead of zero-filling
	// it ahead of the writer on Linux (gateway.audit_prefill false).
	AuditAppend bool
	JWT         pipeline.TrustConfig
	// Limits are the capacity ceilings: policy size and counts, rate
	// counters, recent requests kept.
	Limits policy.Limits
	// Network holds the upstream network settings; nil allows no public
	// address and defines no TLS profile.
	Network *forward.Network

	// ReloadKeys reads the trust and upstream network settings again from
	// the startup configuration, never from HTTP; nil refuses every key
	// reload.
	ReloadKeys func() (pipeline.TrustConfig, *forward.Network, error)
	// ReloadCertificate reads the data listener's certificate files again
	// on every key reload, whatever its result; it records its own failure.
	// nil when the data listener has no certificate.
	ReloadCertificate func()
}

// Controller is the only component that changes the effective policy. It owns
// the database, compiles generations and publishes them by atomic pointer
// swap. Request handlers only read the current pointer.
//
// Prepare creates it, Open opens its deployment, Start serves its Admin API
// and Stop releases everything it owns. The application that calls them owns
// its lifecycle.
type Controller struct {
	config Config

	current atomic.Pointer[compile.Generation]

	// Trust and account containment are published independently of policy.
	verifier atomic.Pointer[pipeline.Verifier]
	network  atomic.Pointer[forward.Network]
	blocked  atomic.Pointer[store.BlockedAccounts]
	// addresses is the blocked address list; nil until read from the store.
	addresses atomic.Pointer[store.BlockedAddresses]

	observations *monitor.Observations

	// Administrator authentication state, in memory only.
	sessions *session.Table

	// mu serialises every mutation, including timer-driven ones, and the
	// lifecycle changes of Start and Stop.
	mu sync.Mutex
	// state holds a string: a deployment mode, or the reason no authority
	// is served. Written under mu, read without it (see State).
	state     atomic.Value
	stopping  bool // set when the stop begins; see BeginStop
	ownership *os.File
	store     *store.DB
	audit     *audit.AuditLog
	timer     *time.Timer
	admin     *http.Server
	logger    *slog.Logger

	// stopOnce runs the one stop of the controller, whose result is stopErr;
	// see Stop.
	stopOnce sync.Once
	stopErr  error

	// expiring is set while a request-triggered deadline check is pending, so
	// requests that see an expired generation start at most one.
	expiring atomic.Bool
}

// Prepare checks cfg and builds the controller, opening nothing; its errors
// are about the settings only.
func Prepare(cfg Config, logger *slog.Logger) (*Controller, error) {
	if logger == nil {
		return nil, errors.New("a logger is required")
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	// Without valid trust material no token can be verified, so the gateway
	// refuses to start rather than run without authentication.
	verifier, err := pipeline.LoadVerifier(cfg.JWT)
	if err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if cfg.Network == nil {
		if cfg.Network, err = forward.LoadNetwork(false, nil, 0); err != nil {
			return nil, err
		}
	}
	c := &Controller{
		config:       cfg,
		observations: monitor.New(cfg.Limits.Window, cfg.Limits.APIs),
		sessions:     session.New(cfg.AdminIdleTimeout, cfg.AdminSessionLifetime),
		logger:       logger,
	}
	c.verifier.Store(verifier)
	c.network.Store(cfg.Network)
	return c, nil
}

// Open takes the deployment lock, opens the database and the audit log and
// publishes the effective policy; it opens no listener, Start does. Its
// errors are store errors (store.ErrHeld when another process holds the
// deployment); on one, nothing it opened is left open. A database without
// usable authority is not an error: the controller serves no protected
// request, and its health and audit log say why.
func (c *Controller) Open() error {
	cfg := c.config
	// The database's exclusive lock is taken before the audit log is opened,
	// so a second gateway for the same deployment stops here and never
	// becomes a second writer of its audit log.
	ownership, err := store.LockDeployment(cfg.Database)
	if err != nil {
		return err
	}
	c.ownership = ownership
	st, err := store.OpenStore(cfg.Database)
	if err != nil && !errors.Is(err, store.ErrUnavailable) {
		ownership.Close()
		return err
	}
	c.audit = audit.OpenAudit(cfg.AuditLog, audit.Settings{MaxBytes: cfg.AuditMaxBytes, MaxFiles: cfg.AuditMaxFiles, WhenFull: cfg.AuditWhenFull, Queue: cfg.AuditQueue, Window: cfg.AuditSyncWindow, Append: cfg.AuditAppend})

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.unavailable(err.Error())
		return nil
	}
	c.store = st
	blocked, err := st.BlockedAccounts(context.Background())
	if err != nil {
		c.unavailable("reading blocked accounts: " + err.Error())
		return nil
	}
	c.blocked.Store(&blocked)
	addresses, err := st.BlockedAddresses(context.Background())
	if err != nil {
		c.unavailable("reading blocked addresses: " + err.Error())
		return nil
	}
	c.addresses.Store(&addresses)
	c.reconcile(compile.TrustedNow())
	return nil
}

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
	if cfg.AuditWhenFull == "" {
		cfg.AuditWhenFull = audit.FullRefuse
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
