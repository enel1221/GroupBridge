package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/enel1221/GroupBridge/internal/app"
	"github.com/enel1221/GroupBridge/internal/config"
	"github.com/enel1221/GroupBridge/internal/metrics"
	"github.com/enel1221/GroupBridge/internal/provider"
	"github.com/enel1221/GroupBridge/internal/provider/gitlab"
	"github.com/enel1221/GroupBridge/internal/reconcile"
	"github.com/enel1221/GroupBridge/internal/source/keycloak"
	"github.com/enel1221/GroupBridge/internal/state"
	"github.com/enel1221/GroupBridge/internal/webhook"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(); err != nil {
		slog.Error("GroupBridge stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	defaultConfig := os.Getenv("GROUPBRIDGE_CONFIG")
	if defaultConfig == "" {
		defaultConfig = "/etc/groupbridge/config.yaml"
	}
	configPath := flag.String("config", defaultConfig, "path to configuration YAML")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("groupbridge %s (%s)\n", version, commit)
		return nil
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	keycloakSecret, err := config.Secret(cfg.Source.ClientSecretEnv)
	if err != nil {
		return err
	}
	webhookSecret, err := config.Secret(cfg.Webhook.SecretEnv)
	if err != nil {
		return err
	}
	if len([]byte(webhookSecret)) < 32 {
		return errors.New("webhook secret must contain at least 32 bytes")
	}
	store, err := state.Open(cfg.State.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	httpClient := &http.Client{
		Timeout:       20 * time.Second,
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	src := keycloak.New(cfg.Source.BaseURL, cfg.Source.Realm, cfg.Source.ClientID, keycloakSecret, httpClient)
	providers := make([]provider.Provider, 0, len(cfg.Targets))
	for _, target := range cfg.Targets {
		token, secretErr := config.Secret(target.TokenEnv)
		if secretErr != nil {
			return secretErr
		}
		switch target.Type {
		case "gitlab":
			resolverToken := token
			if target.ResolverTokenEnv != "" {
				resolverToken, secretErr = config.Secret(target.ResolverTokenEnv)
				if secretErr != nil {
					return secretErr
				}
			}
			providers = append(providers, gitlab.New(target.Name, target.BaseURL, token, resolverToken, target.OIDCProvider, httpClient, store))
		default:
			return fmt.Errorf("target provider type %q is not compiled in", target.Type)
		}
	}
	registry := provider.NewRegistry(providers...)
	m := &metrics.Metrics{}
	trigger := make(chan struct{}, 1)
	requestReconcile := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	requestEventReconcile := func() {
		requestReconcile()
		// OIDC login can create the GitLab user just after Keycloak emits its
		// login event. One coalesced delayed read closes that JIT race without a
		// permanent high-frequency retry loop for identities that do not exist.
		time.AfterFunc(3*time.Second, requestReconcile)
	}
	wh := webhook.New(webhookSecret, cfg.Source.Realm, cfg.Webhook.MaxSkew.Duration, requestEventReconcile, m)
	httpSurface := app.NewServer(wh, m, version)
	reconciler := reconcile.New(src, registry, cfg.Rules, store, m, logger, func() { httpSurface.SetReady(true) })

	workerCtx, forceStopWorkers := context.WithCancel(context.Background())
	defer forceStopWorkers()
	stopWorkers := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		reconciler.Run(workerCtx, cfg.Source.PollInterval.Duration, trigger, stopWorkers)
	}()
	server := &http.Server{
		Addr: cfg.Server.Address, Handler: httpSurface.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("GroupBridge listening", "address", cfg.Server.Address, "version", version, "commit", commit)
		serverErr <- server.ListenAndServe()
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	httpSurface.SetReady(false)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		forceStopWorkers()
		return fmt.Errorf("shut down HTTP server: %w", err)
	}
	close(stopWorkers)
	workersDone := make(chan struct{})
	go func() { workers.Wait(); close(workersDone) }()
	select {
	case <-workersDone:
	case <-shutdownCtx.Done():
		forceStopWorkers()
		<-workersDone
		return errors.New("timed out waiting for reconciliation to finish safely")
	}
	logger.Info("GroupBridge stopped")
	return nil
}
