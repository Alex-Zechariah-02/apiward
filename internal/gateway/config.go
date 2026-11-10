// Configuration file types, loading and strict decoding.

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/operator"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// The native gateway reads all of its settings from one strict JSON file. The
// file is checked completely before anything of the deployment is opened.

const (
	// nativeConfigVersion is the only configuration file version this gateway
	// reads.
	nativeConfigVersion = 1
	maxConfigBytes      = 64 << 10
	maxConfigDepth      = 6
)

// Bounds of the native settings. Data-plane and upstream timeouts default to
// the legacy values; every timeout is at least a second, so no setting can
// make ordinary requests fail, and has an upper bound, so none leaves a phase
// practically unbounded.
const (
	minServerTimeout     = time.Second
	maxServerTimeout     = 10 * time.Minute
	minUpstreamTimeout   = time.Second
	maxUpstreamTimeout   = 5 * time.Minute
	minAuditTimeout      = 100 * time.Millisecond
	maxAuditTimeout      = 30 * time.Second
	defaultHeaderBytes   = 16 << 10
	minHeaderBytes       = 8 << 10 // a token of maxTokenBytes and ordinary headers fit
	maxHeaderBytes       = 1 << 20
	defaultReadHeader    = 5 * time.Second
	defaultRead          = 10 * time.Second
	defaultWrite         = 30 * time.Second
	defaultIdleKeepAlive = 5 * time.Minute
	defaultDial          = 2 * time.Second
	defaultUpstreamWait  = 5 * time.Second
	// Upstream connection reuse: idle connections per endpoint, closed
	// after defaultIdleConn, which must stay below the upstream server's
	// own idle timeout (an upstream with a shorter one needs a lower
	// setting), and TLS sessions resumed for at most defaultSessionLife.
	// Data-plane connections: an idle TLS connection measured 20 to 42 KiB
	// of resident memory, so the default bounds them to about 43 MiB.
	defaultMaxConnections = 1024
	maxConnectionsLimit   = 65536
	maxInFlightLimit      = 65536
	defaultMaxIdle        = 16
	maxIdlePerUpstream    = 1024
	defaultIdleConn       = 30 * time.Second
	defaultSessionLife    = time.Hour
	minSessionLife        = time.Minute
	maxSessionLife        = 24 * time.Hour
)

// nativeFile is the configuration file as written. A setting that may be
// omitted is a pointer: omitted, it takes its default; written, it must be
// valid, so a zero or empty value is refused rather than read as "default".
type nativeFile struct {
	Version  int              `json:"version"`
	Gateway  gatewaySettings  `json:"gateway"`
	Data     dataSettings     `json:"data"`
	Upstream upstreamSettings `json:"upstream"`
	Limits   limitSettings    `json:"limits"`
}

// limitSettings raise or lower the capacity ceilings; each omitted one keeps
// its default (policy.Limits).
type limitSettings struct {
	PolicyBytes   *int `json:"policy_bytes"`
	APIs          *int `json:"apis"`
	Operations    *int `json:"operations"`
	Roles         *int `json:"roles"`
	Permits       *int `json:"permits"`
	RateCounters  *int `json:"rate_counters"`
	MonitorWindow *int `json:"monitor_window"`
}

// gatewaySettings are the controller's settings, under the names the legacy
// Caddy "gateway" app used.
type gatewaySettings struct {
	Database             string               `json:"database"`
	AuditLog             string               `json:"audit_log"`
	AdminListen          string               `json:"admin_listen"`
	MetricsListen        *string              `json:"metrics_listen"`
	MetricsListenAny     bool                 `json:"metrics_listen_any"`
	AdminIdleTimeout     *string              `json:"admin_idle_timeout"`
	AdminSessionLifetime *string              `json:"admin_session_lifetime"`
	AuditTimeout         *string              `json:"audit_timeout"`
	AuditMaxBytes        *int64               `json:"audit_max_bytes"`
	AuditMaxFiles        *int                 `json:"audit_max_files"`
	JWT                  pipeline.TrustConfig `json:"jwt"`
	AdminUI              *string              `json:"admin_ui"`
}

// dataSettings are the data-plane server's settings.
type dataSettings struct {
	Listen string `json:"listen"`
	// ListenAllInterfaces allows an unspecified listen address, which binds
	// every interface: a deliberate choice, for containers and servers.
	ListenAllInterfaces bool              `json:"listen_all_interfaces"`
	TLS                 *dataTLS          `json:"tls"`
	RedirectHTTP        *redirectSettings `json:"redirect_http"`
	MaxBodyBytes        *int64            `json:"max_body_bytes"`
	MaxHeaderBytes      *int              `json:"max_header_bytes"`
	MaxConnections      *int              `json:"max_connections"`
	MaxInFlight         *int64            `json:"max_in_flight"`
	IPv6RatePrefix      *int              `json:"ipv6_rate_prefix"`
	ReadHeaderTimeout   *string           `json:"read_header_timeout"`
	ReadTimeout         *string           `json:"read_timeout"`
	WriteTimeout        *string           `json:"write_timeout"`
	IdleTimeout         *string           `json:"idle_timeout"`
}

// upstreamSettings bound each exchange with an upstream and say which
// destinations upstreams may use: public addresses only when allowed, and
// the TLS profiles policies name.
type upstreamSettings struct {
	DialTimeout           *string                   `json:"dial_timeout"`
	ResponseHeaderTimeout *string                   `json:"response_header_timeout"`
	ReadIdleTimeout       *string                   `json:"read_idle_timeout"`
	MaxIdlePerUpstream    *int                      `json:"max_idle_per_upstream"`
	IdleConnTimeout       *string                   `json:"idle_conn_timeout"`
	TLSSessionLifetime    *string                   `json:"tls_session_lifetime"`
	AllowPublicAddresses  bool                      `json:"allow_public_addresses"`
	TLSProfiles           []forward.ProfileSettings `json:"tls_profiles"`
}

// nativeConfig is a checked configuration of the native gateway.
type nativeConfig struct {
	controller    controller.Config
	listen        string
	metricsListen string
	// limits bound enforcement: body ceiling, requests in flight, IPv6 rate
	// key prefix.
	limits pipeline.Limits
	// maxConnections bounds the data listener's open connections.
	maxConnections    int
	headerLimit       int
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
	upstream          forward.UpstreamTimeouts
	pool              forward.PoolSettings
	// tls is the data listener's TLS; nil serves plain HTTP. redirect is
	// the HTTP-to-HTTPS listener; nil when there is none.
	tls      *dataTLS
	redirect *redirectSettings
	// adminUI is an optional directory of built dashboard files, served by
	// the admin listener so the dashboard shares the Admin API's origin.
	adminUI string
}

// operatorConfig is what the operator commands need of the controller's
// settings.
func operatorConfig(c controller.Config) operator.Config {
	keys := make([]string, len(c.JWT.Keys))
	for i, key := range c.JWT.Keys {
		keys[i] = key.PublicKeyFile
	}
	return operator.Config{Database: c.Database, AuditLog: c.AuditLog, AuditMaxBytes: c.AuditMaxBytes,
		AuditMaxFiles: c.AuditMaxFiles, AuditTimeout: c.AuditTimeout, KeyFiles: keys}
}

// loadNativeConfig reads and checks the configuration file at path. The
// controller checks the rest of its own settings, the admin address and the
// trust key, before it opens the database.
func loadNativeConfig(path string) (nativeConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nativeConfig{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nativeConfig{}, err
	}
	if len(data) > maxConfigBytes {
		return nativeConfig{}, fmt.Errorf("the file is larger than %d bytes", maxConfigBytes)
	}
	settings, err := decodeNativeFile(data)
	if err != nil {
		return nativeConfig{}, err
	}
	cfg, err := settings.check()
	if err != nil {
		return nativeConfig{}, err
	}
	settingsFile, err := filepath.Abs(path)
	cfg.controller.ReloadKeys = func() (pipeline.TrustConfig, *forward.Network, error) {
		reloaded, err := loadNativeConfig(settingsFile)
		return reloaded.controller.JWT, reloaded.controller.Network, err
	}
	return cfg, err
}

// decodeNativeFile parses the configuration document. It refuses what
// encoding/json alone would accept ambiguously: repeated or non-lowercase
// member names, unknown members and anything after the document.
func decodeNativeFile(data []byte) (nativeFile, error) {
	// The document's kind and version are read first, so a file written for
	// another gateway or version is reported as such rather than as a set of
	// unknown members.
	decoder := json.NewDecoder(bytes.NewReader(data))
	var header map[string]json.RawMessage
	if err := decoder.Decode(&header); err != nil || header == nil {
		if _, wrongType := errors.AsType[*json.UnmarshalTypeError](err); wrongType || err == nil {
			return nativeFile{}, errors.New("the file is not a JSON object")
		}
		return nativeFile{}, errors.New("the file is not valid JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nativeFile{}, errors.New("the file holds data after the JSON value")
	}
	if _, legacy := header["apps"]; legacy {
		return nativeFile{}, errors.New("this is a Caddy configuration (top-level \"apps\"); write a native configuration instead, it is not converted automatically")
	}
	if err := policy.CheckMembers(data, maxConfigDepth); err != nil {
		policyErr, _ := errors.AsType[*policy.PolicyError](err)
		switch {
		case policyErr != nil && policyErr.Code == "DUPLICATE_MEMBER":
			return nativeFile{}, fmt.Errorf("member %q is repeated in one object", policyErr.Field)
		case policyErr != nil && policyErr.Code == "UNKNOWN_FIELD":
			return nativeFile{}, errors.New("a member name is not made of lower-case letters, digits and underscores")
		case policyErr != nil && policyErr.Code == "LIMIT_EXCEEDED":
			return nativeFile{}, errors.New("the document is nested too deeply")
		}
		return nativeFile{}, errors.New("the file is not valid JSON")
	}
	var version int
	if err := json.Unmarshal(header["version"], &version); err != nil || version != nativeConfigVersion {
		return nativeFile{}, fmt.Errorf("version must be %d, the only configuration version this gateway reads", nativeConfigVersion)
	}

	var settings nativeFile
	if err := policy.DecodeStrict(data, &settings); err != nil {
		if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
			return nativeFile{}, fmt.Errorf("%s: a JSON %s is not a valid value", typeErr.Field, typeErr.Value)
		}
		return nativeFile{}, errors.New(strings.TrimPrefix(err.Error(), "json: "))
	}
	return settings, nil
}
