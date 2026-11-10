// The native gateway: the controller, its enforcement handler and the native
// proxy, served by the project's own net/http data-plane server, and the
// command line that runs it.

package gateway

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Alex-Zechariah-02/apiward/internal/admin"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/operator"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// Exit statuses of the native run command.
const (
	exitStopped    = 0 // stopped gracefully and completely
	exitFailed     = 1 // could not start, or the data plane failed
	exitForced     = 2 // a second signal ended the graceful stop
	exitIncomplete = 3 // the graceful stop did not complete
)

const nativeUsage = `usage: gateway run --config <file>
  gateway version
  gateway health --config <file>
  gateway install --config <file> --admin <name>
  gateway enrol --config <file> --admin <name> --permissions <list>
  gateway migrate --config <file>
  gateway backup --config <file> --output <file>
  gateway restore --config <file> --backup <file>
  gateway policy import-openapi --spec <file> --api <id> --upstream <id> --base <file> --out <file> --report <file>
  gateway policy export-openapi --policy <file> --api <id> --out <file> --report <file>`

// Main runs the native gateway command line and returns the exit status.
func Main(args []string) int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	command := args[0]
	if command == "version" {
		return printVersion(args[1:])
	}
	options := []string{"config"}
	switch command {
	case "run", "migrate", "health":
	case "install":
		options = append(options, "admin")
	case "enrol":
		options = append(options, "admin", "permissions")
	case "backup":
		options = append(options, "output")
	case "restore":
		options = append(options, "backup")
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", command)
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	parsed := map[string]*onceFlag{}
	for _, name := range options {
		value := new(onceFlag)
		parsed[name] = value
		set.Var(value, name, "required "+name)
	}
	if err := set.Parse(args[1:]); err != nil || set.NArg() != 0 {
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	values := map[string]string{}
	for _, name := range options {
		if parsed[name].value == "" {
			fmt.Fprintln(os.Stderr, "--"+name+" is required")
			fmt.Fprintln(os.Stderr, nativeUsage)
			return exitFailed
		}
		values[name] = parsed[name].value
	}
	switch command {
	case "run":
		return runNative(values["config"], logger)
	case "health":
		return checkHealth(values["config"])
	}
	cfg, err := loadNativeConfig(values["config"])
	if err == nil {
		err = cfg.controller.Check()
	}
	if err == nil {
		_, err = pipeline.LoadVerifier(cfg.controller.JWT)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		return exitFailed
	}
	code, err := operator.Run(command, operatorConfig(cfg.controller), values)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
	}
	return code
}

// onceFlag is a flag that may be given only once, so a command line cannot
// name two configuration files of which one would be silently ignored.
type onceFlag struct {
	value string
	set   bool
}

func (f *onceFlag) String() string { return f.value }

func (f *onceFlag) Set(value string) error {
	if f.set {
		return errors.New("given more than once")
	}
	f.value, f.set = value, true
	return nil
}

// runNative starts the gateway, serves until the first interrupt or
// termination signal, then stops it gracefully. A second signal forces the
// process to exit at once.
func runNative(configPath string, logger *slog.Logger) int {
	// Signals are taken before startup, so one that arrives while the
	// gateway is starting stops it gracefully once it has started.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	// SIGHUP reloads the data listener's certificate (no effect on Windows).
	hangups := make(chan os.Signal, 1)
	signal.Notify(hangups, syscall.SIGHUP)
	defer signal.Stop(hangups)

	settings, err := LoadSettings(configPath)
	if err != nil {
		logger.Error("configuration refused", "error", err)
		return exitFailed
	}
	g, err := startNative(*settings.native, logger)
	if err != nil {
		logger.Error("startup failed", "error", err)
		return exitFailed
	}

	status := exitStopped
	for running := true; running; {
		select {
		case <-hangups:
			if g.certificate != nil {
				g.certificate.reload()
			}
		case sig := <-signals:
			logger.Info("stopping", "signal", sig.String())
			running = false
		case err := <-g.served:
			logger.Error("a listener failed; stopping", "error", err)
			status, running = exitFailed, false
		}
	}
	go func() {
		<-signals
		logger.Error("forced exit: a second signal arrived before the graceful stop completed")
		os.Exit(exitForced)
	}()
	if err := g.stop(); err != nil {
		logger.Error("stop incomplete", "error", err)
		return exitIncomplete
	}
	logger.Info("stopped")
	return status
}

// nativeGateway is one running native gateway.
type nativeGateway struct {
	controller *controller.Controller
	data       *http.Server
	metrics    *http.Server
	redirect   *http.Server // nil without a redirect listener
	// certificate is the data listener's; nil when it serves plain HTTP.
	certificate *servingCertificate
	upstreams   upstreams
	// served receives the data-plane, metrics and redirect servers' Serve
	// results; done closes when the stop begins.
	served chan error
	done   chan struct{}
	stop   func() error
}

// startNative opens the deployment for cfg and serves it: the controller with
// its Admin API, and the data plane. Nothing listens before the controller
// holds the database and has published, or refused to publish, the effective
// policy, and the data-plane address is bound before the Admin API starts, so
// a failure leaves nothing served. When it returns an error, everything it
// acquired is released.
func startNative(cfg nativeConfig, logger *slog.Logger) (*nativeGateway, error) {
	d, err := openDeployment(cfg, logger)
	if err != nil {
		return nil, err
	}
	c := d.controller
	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return nil, errors.Join(classify(ErrListen, fmt.Errorf("data listener: %w", err)), c.Stop())
	}
	redirectListener, err := listenRedirect(cfg.redirect)
	if err != nil {
		listener.Close()
		return nil, errors.Join(err, c.Stop())
	}
	metricsListener, err := d.listen(true)
	if err != nil {
		closeListeners(listener, redirectListener)
		return nil, errors.Join(err, c.Stop())
	}
	listener = capConnections(listener, cfg.maxConnections, c.Observations().ConnectionRefused)
	if d.certificate != nil {
		listener = tls.NewListener(listener, d.certificate.config())
	}

	// HTTP/1.0 and HTTP/1.1 only, over plain TCP or TLS.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	data := &http.Server{
		Handler:   d.enforcement,
		Protocols: protocols,
		// "OPTIONS *" reaches enforcement, which refuses every target that
		// is not in origin form, instead of being answered by net/http.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	cfg.server().Apply(data)
	g := &nativeGateway{controller: c, data: data, metrics: d.metrics, certificate: d.certificate, upstreams: d.upstreams, served: make(chan error, 3), done: make(chan struct{})}
	g.stop = sync.OnceValue(g.shutdown)
	go func() { g.served <- g.data.Serve(listener) }()
	go func() { g.served <- g.metrics.Serve(metricsListener) }()
	if redirectListener != nil {
		g.redirect = redirectServer(cfg.redirect.Origin, c.Observations())
		go func() { g.served <- g.redirect.Serve(redirectListener) }()
	}
	if g.certificate != nil {
		go g.certificate.watchExpiry(g.done)
	}

	logger.Info("listening", "data", listener.Addr().String(), "admin", cfg.controller.AdminListen)
	d.logAdmission(logger)
	return g, nil
}

// printVersion runs the version command, which takes no options and reads no
// configuration.
func printVersion(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, nativeUsage)
		return exitFailed
	}
	fmt.Print(admin.VersionText())
	return 0
}
