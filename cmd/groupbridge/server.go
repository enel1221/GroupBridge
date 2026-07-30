package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/enel1221/GroupBridge/internal/config"
)

type certificateReloader struct {
	certFile string
	keyFile  string
	logger   *slog.Logger

	mu             sync.Mutex
	current        *tls.Certificate
	lastLoadFailed bool
}

func newCertificateReloader(
	certFile string,
	keyFile string,
	logger *slog.Logger,
) (*certificateReloader, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load initial GroupBridge TLS certificate: %w", err)
	}
	return &certificateReloader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
		current:  &certificate,
	}, nil
}

// GetCertificate reloads the projected certificate pair for every new TLS
// handshake. A transient Secret rotation mismatch retains the last known-good
// pair, while startup fails closed when no valid pair has ever been loaded.
func (r *certificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certificate, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if !r.lastLoadFailed {
			r.logger.Warn("TLS certificate reload failed; retaining last known-good pair")
			r.lastLoadFailed = true
		}
		return r.current, nil
	}
	r.current = &certificate
	r.lastLoadFailed = false
	return r.current, nil
}

func listenAndServe(
	server *http.Server,
	serverTLS config.ServerTLS,
	logger *slog.Logger,
) error {
	if serverTLS.CertFile == "" {
		return server.ListenAndServe()
	}

	reloader, err := newCertificateReloader(serverTLS.CertFile, serverTLS.KeyFile, logger)
	if err != nil {
		return err
	}
	tlsConfig := server.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.Certificates = nil
	tlsConfig.GetCertificate = reloader.GetCertificate

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	return server.Serve(tls.NewListener(listener, tlsConfig))
}
