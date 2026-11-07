// Package apiward runs the APIWard security gateway inside a Go program.
//
// The host program owns the data-plane listener and mounts the gateway's
// handler on its own server, at the root or under a prefix with
// http.StripPrefix. The gateway keeps everything else: its Admin API and
// metrics listeners, its database, its audit log, startup recovery and its
// stop. Every request the handler receives runs the full pipeline the
// standalone binary runs; nothing here publishes policy or skips a stage.
//
// A gateway is loaded, opened, started once and stopped once:
//
//	cfg, err := apiward.LoadConfig(path)
//	gw, err := apiward.New(cfg, logger)
//	err = gw.Start()
//	mux.Handle("/api/", http.StripPrefix("/api", gw))
//	gw.ServerSettings().Apply(server)
//	...
//	err = gw.Stop(ctx)
//
// The host must apply ServerSettings to its server (header size and
// timeouts bound slow and oversized clients) and must not rewrite a
// request's RemoteAddr from client-supplied headers: address lists and
// per-address rate limits read it.
package apiward

import (
	"log/slog"

	core "github.com/Alex-Zechariah-02/apiward/internal/gateway"
)

// Config is a configuration file checked as the standalone binary's run
// command checks it. Only LoadConfig makes one; New refuses the zero value.
// The file's data.listen is still required and checked, but a gateway run
// here never binds it.
type Config = core.Settings

// Gateway is one running gateway; it is the data plane's http.Handler.
// Before Start completes and from Stop on, every request is refused with
// 503 gateway_unavailable and recorded. Its methods are safe for concurrent
// use.
type Gateway = core.Embedded

// ServerSettings are the configured limits for the host's server; Apply
// sets them.
type ServerSettings = core.ServerSettings

// Kinds of failure. Every error from LoadConfig, New, Start and Stop
// matches exactly one with errors.Is; its text names the setting or file
// involved. Request refusals are HTTP responses, never Go errors.
var (
	ErrConfig     = core.ErrConfig     // the configuration, or a file it names, is refused
	ErrLocked     = core.ErrLocked     // another process holds the deployment
	ErrStorage    = core.ErrStorage    // the database or the audit log cannot be used
	ErrListen     = core.ErrListen     // the admin or metrics address cannot be bound
	ErrStarted    = core.ErrStarted    // Start was called again
	ErrStopped    = core.ErrStopped    // Start was called after Stop
	ErrIncomplete = core.ErrIncomplete // Stop could not finish every step in time
)

// LoadConfig reads and strictly checks the configuration file at path.
func LoadConfig(path string) (Config, error) { return core.LoadSettings(path) }

// New opens the deployment cfg names: it takes the deployment lock, opens
// the database and the audit log and recovers the stored authority. It binds
// no listener; Start does. When it fails, nothing stays open.
func New(cfg Config, logger *slog.Logger) (*Gateway, error) { return core.OpenEmbedded(cfg, logger) }
