// Command envoy-control-plane watches the Docker socket for containers
// carrying envoy.* labels and an optional static routes file, and serves
// Envoy xDS (ADS) so that Envoy automatically exposes each one as
// <subdomain>.<BASE_DOMAIN> over HTTPS, redirecting plain HTTP to HTTPS.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bryanpfremm/envoy-control-plane/internal/config"
	"github.com/bryanpfremm/envoy-control-plane/internal/dockerwatch"
	"github.com/bryanpfremm/envoy-control-plane/internal/infoserver"
	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/staticconfig"
	"github.com/bryanpfremm/envoy-control-plane/internal/xds"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := run(logger); err != nil {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	staticRoutes, err := staticconfig.Load(cfg.StaticConfigPath)
	if err != nil {
		return fmt.Errorf("loading static config: %w", err)
	}
	logger.Info("loaded static routes", "count", len(staticRoutes))

	watcher, err := dockerwatch.New(cfg.DockerHost, cfg.DockerNetwork, cfg.ResyncInterval, logger)
	if err != nil {
		return fmt.Errorf("creating docker watcher: %w", err)
	}
	defer watcher.Close()

	adsServer := xds.NewServer(logger)

	snapCfg := xds.Config{
		BaseDomain:             cfg.BaseDomain,
		HTTPPort:               cfg.HTTPPort,
		HTTPSPort:              cfg.HTTPSPort,
		CertSecretName:         cfg.CertSecretName,
		ACMESDSClusterName:     cfg.ACMESDSClusterName,
		TCPEntrypoints:         cfg.TCPEntrypoints,
		DefaultTCPEntrypoint:   cfg.DefaultTCPEntrypoint,
		HTTPEntrypoints:        cfg.HTTPEntrypoints,
		DefaultHTTPEntrypoint:  cfg.DefaultHTTPEntrypoint,
		DefaultHTTPEntrypoints: cfg.DefaultHTTPEntrypoints,
		Logger:                 logger,
	}

	var infoSrv *infoserver.Server
	if cfg.InfoEndpointEnabled {
		infoSrv = infoserver.New()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	updates := make(chan model.Configuration)

	var version atomic.Uint64

	applyUpdate := func(dockerConfig model.Configuration) error {
		merged := xds.Merge(dockerConfig.HTTP.Routes, staticRoutes, logger)
		httpConfig := model.HTTPConfiguration{Routes: merged, Services: dockerConfig.HTTP.Services, Middlewares: dockerConfig.HTTP.Middlewares}
		v := version.Add(1)
		snap, err := xds.BuildSnapshotForConfigWithTCP(strconv.FormatUint(v, 10), httpConfig, dockerConfig.TCP, snapCfg)
		if err != nil {
			return fmt.Errorf("building snapshot: %w", err)
		}
		if err := adsServer.SetSnapshot(ctx, snap); err != nil {
			return fmt.Errorf("publishing snapshot: %w", err)
		}
		logger.Info("published snapshot", "version", v, "routes", len(merged), "tcp_routers", len(dockerConfig.TCP.Routers))

		if infoSrv != nil {
			infoSrv.Update(buildInfoView(cfg, merged, strconv.FormatUint(v, 10)))
		}
		return nil
	}

	// Publish once immediately with just the static routes (if any), so
	// static-only backends stay routable even if the docker daemon is
	// unreachable or slow to answer the first scan.
	if err := applyUpdate(model.Configuration{HTTP: model.HTTPConfiguration{Routes: map[string]model.Route{}, Services: map[string]model.HTTPService{}}}); err != nil {
		logger.Error("failed to publish initial snapshot", "error", err)
	}

	watchErrCh := make(chan error, 1)
	go func() {
		watchErrCh <- watcher.Run(ctx, updates)
	}()

	applyErrCh := make(chan error, 1)
	go func() {
		for routes := range updates {
			if err := applyUpdate(routes); err != nil {
				logger.Error("failed to apply docker route update", "error", err)
			}
		}
		applyErrCh <- nil
	}()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.XDSPort))
	if err != nil {
		return fmt.Errorf("listening on xds port %d: %w", cfg.XDSPort, err)
	}

	serveErrCh := make(chan error, 1)
	go func() {
		logger.Info("ads server listening", "port", cfg.XDSPort)
		serveErrCh <- adsServer.Serve(ln)
	}()

	var infoHTTPSrv *http.Server
	infoErrCh := make(chan error, 1)
	if infoSrv != nil {
		infoHTTPSrv = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.InfoPort),
			Handler: infoSrv.Handler(),
		}
		go func() {
			logger.Info("info page listening", "port", cfg.InfoPort)
			if err := infoHTTPSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				infoErrCh <- err
				return
			}
			infoErrCh <- nil
		}()
	}

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		adsServer.GracefulStop()
		if infoHTTPSrv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = infoHTTPSrv.Shutdown(shutdownCtx)
			<-infoErrCh
		}
		<-watchErrCh
		<-applyErrCh
		return nil
	case err := <-watchErrCh:
		adsServer.GracefulStop()
		return fmt.Errorf("docker watcher stopped: %w", err)
	case err := <-serveErrCh:
		return fmt.Errorf("ads server stopped: %w", err)
	case err := <-infoErrCh:
		adsServer.GracefulStop()
		return fmt.Errorf("info server stopped: %w", err)
	}
}

// buildInfoView converts the current merged route map into the read-only
// view the info page renders.
func buildInfoView(cfg config.Config, routes map[string]model.Route, version string) infoserver.View {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)

	views := make([]infoserver.Route, 0, len(names))
	for _, name := range names {
		route := routes[name]
		endpoints := make([]string, 0, len(route.Endpoints))
		for _, ep := range route.Endpoints {
			endpoints = append(endpoints, fmt.Sprintf("%s:%d", ep.Address, ep.Port))
		}
		views = append(views, infoserver.Route{
			Subdomain: route.Subdomain,
			Host:      route.Subdomain + "." + cfg.BaseDomain,
			Source:    string(route.Source),
			Endpoints: endpoints,
			Origin:    route.Origin,
		})
	}

	return infoserver.View{
		Settings: infoserver.Settings{
			BaseDomain:         cfg.BaseDomain,
			HTTPPort:           cfg.HTTPPort,
			HTTPSPort:          cfg.HTTPSPort,
			XDSPort:            cfg.XDSPort,
			DockerNetwork:      cfg.DockerNetwork,
			CertSecretName:     cfg.CertSecretName,
			ACMESDSClusterName: cfg.ACMESDSClusterName,
			StaticConfigPath:   cfg.StaticConfigPath,
		},
		Routes:    views,
		Version:   version,
		UpdatedAt: time.Now(),
	}
}
