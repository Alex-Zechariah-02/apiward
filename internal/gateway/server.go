// The limits of the server that runs the data plane, as the standalone
// binary applies them to its own server and a host program to its server.

package gateway

import (
	"net/http"
	"time"
)

// ServerSettings are the configured limits of the server that runs the data
// plane. Header size and the timeouts bound slow and oversized clients; the
// gateway cannot enforce them on a server it does not own. HTTP2 allows
// HTTP/2, which net/http serves only over TLS.
type ServerSettings struct {
	MaxHeaderBytes    int
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	HTTP2             bool
	// countError counts each HTTP/2 protocol error by its type; nil counts
	// none.
	countError func(errType string)
}

// HTTP/2 bounds: concurrent streams per connection (Go's default is 250,
// nginx's 128), and request bytes the server buffers per connection and per
// stream before the handler reads them. Go's default buffers of 1 MiB would
// let 1,024 connections hold 1 GiB; flow control only slows larger uploads.
const (
	maxStreams    = 100
	receiveBuffer = 64 << 10
)

// Apply sets the limits and protocols on server, replacing its own values
// for them, so a host never serves a protocol the gateway did not configure.
// The header list of an HTTP/2 request is bounded by MaxHeaderBytes too.
func (s ServerSettings) Apply(server *http.Server) {
	server.MaxHeaderBytes = s.MaxHeaderBytes
	server.ReadHeaderTimeout = s.ReadHeaderTimeout
	server.ReadTimeout = s.ReadTimeout
	server.WriteTimeout = s.WriteTimeout
	server.IdleTimeout = s.IdleTimeout
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(s.HTTP2)
	server.Protocols = protocols
	server.HTTP2 = &http.HTTP2Config{
		MaxConcurrentStreams:          maxStreams,
		MaxReceiveBufferPerConnection: receiveBuffer,
		MaxReceiveBufferPerStream:     receiveBuffer,
		WriteByteTimeout:              s.WriteTimeout,
		CountError:                    s.countError,
	}
}

func (cfg nativeConfig) server() ServerSettings {
	return ServerSettings{
		MaxHeaderBytes:    cfg.headerLimit,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       cfg.idleTimeout,
		HTTP2:             cfg.http2,
	}
}
