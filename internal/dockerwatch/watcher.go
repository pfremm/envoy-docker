// Package dockerwatch watches the Docker socket for containers carrying
// envoy.* labels and turns them into a routing table, updating it on
// container lifecycle events.
package dockerwatch

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

const (
	enableLabel  = "envoy.enable"
	routerPrefix = "envoy.http.routers."
)

type Watcher struct {
	cli            *client.Client
	defaultNetwork string
	resyncInterval time.Duration
	logger         *slog.Logger
}

func New(dockerHost, defaultNetwork string, resyncInterval time.Duration, logger *slog.Logger) (*Watcher, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if dockerHost != "" {
		opts = append(opts, client.WithHost(dockerHost))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating docker client: %w", err)
	}
	return &Watcher{
		cli:            cli,
		defaultNetwork: defaultNetwork,
		resyncInterval: resyncInterval,
		logger:         logger,
	}, nil
}

func (w *Watcher) Close() error {
	return w.cli.Close()
}

// Run watches docker container state and sends the current full route map
// on updates whenever it changes: once at startup, on every container
// lifecycle event, and periodically as a fallback in case an event is
// missed. It blocks until ctx is cancelled, closing updates on return.
func (w *Watcher) Run(ctx context.Context, updates chan<- map[string]model.Route) error {
	defer close(updates)

	resync := func() bool {
		routes, err := w.scan(ctx)
		if err != nil {
			w.logger.Error("docker resync failed", "error", err)
			return true
		}
		select {
		case updates <- routes:
			return true
		case <-ctx.Done():
			return false
		}
	}

	if !resync() {
		return ctx.Err()
	}

	ticker := time.NewTicker(w.resyncInterval)
	defer ticker.Stop()

	evFilter := filters.NewArgs(filters.Arg("type", string(events.ContainerEventType)))
	evCh, errCh := w.cli.Events(ctx, events.ListOptions{Filters: evFilter})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !resync() {
				return ctx.Err()
			}
		case _, ok := <-evCh:
			if !ok {
				return fmt.Errorf("docker event stream closed unexpectedly")
			}
			if !resync() {
				return ctx.Err()
			}
		case err, ok := <-errCh:
			if !ok {
				continue
			}
			if err != nil {
				w.logger.Error("docker event stream error, relying on periodic resync", "error", err)
			}
		}
	}
}

// scan lists all containers and builds a full route map from their labels.
func (w *Watcher) scan(ctx context.Context) (map[string]model.Route, error) {
	containers, err := w.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	// Deterministic order so results are stable across scans.
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })

	routes := map[string]model.Route{}

	for _, c := range containers {
		name := containerName(c)
		if c.Labels[enableLabel] != "true" {
			continue
		}

		routers, err := parseRouters(c.Labels)
		if err != nil {
			w.logger.Warn("skipping container with invalid envoy labels", "container", name, "error", err)
			continue
		}

		for routerName, r := range routers {
			network := r.network
			if network == "" {
				network = w.defaultNetwork
			}
			if network == "" {
				w.logger.Warn("skipping router: no docker network configured (set DOCKER_NETWORK or the envoy.http.routers.<name>.network label)",
					"container", name, "router", routerName)
				continue
			}

			addr, err := containerIP(c, network)
			if err != nil {
				w.logger.Warn("skipping router: could not resolve container IP",
					"container", name, "router", routerName, "network", network, "error", err)
				continue
			}

			endpoint := model.Endpoint{Address: addr, Port: r.port}
			origin := name + "/" + routerName

			// Multiple containers advertising the same subdomain are treated
			// as replicas of the same route and merged into one multi-
			// endpoint route (basic round robin), matching Traefik's
			// behavior when a compose service is scaled.
			if existing, ok := routes[r.subdomain]; ok {
				existing.Endpoints = append(existing.Endpoints, endpoint)
				existing.Origin = existing.Origin + "," + origin
				routes[r.subdomain] = existing
				continue
			}

			routes[r.subdomain] = model.Route{
				Subdomain: r.subdomain,
				Endpoints: []model.Endpoint{endpoint},
				Source:    model.SourceDocker,
				Origin:    origin,
			}
		}
	}

	return routes, nil
}

type parsedRouter struct {
	subdomain string
	port      uint32
	network   string
}

// parseRouters extracts envoy.http.routers.<name>.{subdomain,port,network}
// labels into one parsedRouter per <name>, validating that each has the
// required fields.
func parseRouters(labels map[string]string) (map[string]parsedRouter, error) {
	routers := map[string]parsedRouter{}

	for key, value := range labels {
		if !strings.HasPrefix(key, routerPrefix) {
			continue
		}
		rest := strings.TrimPrefix(key, routerPrefix)
		name, field, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}

		r := routers[name]
		switch field {
		case "subdomain":
			r.subdomain = value
		case "port":
			p, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("router %q: invalid port %q: %w", name, value, err)
			}
			r.port = uint32(p)
		case "network":
			r.network = value
		default:
			continue
		}
		routers[name] = r
	}

	for name, r := range routers {
		if r.subdomain == "" {
			return nil, fmt.Errorf("router %q missing %s%s.subdomain label", name, routerPrefix, name)
		}
		if r.port == 0 {
			return nil, fmt.Errorf("router %q missing %s%s.port label", name, routerPrefix, name)
		}
	}

	return routers, nil
}

func containerName(c container.Summary) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	return c.ID
}

func containerIP(c container.Summary, networkName string) (string, error) {
	if c.NetworkSettings == nil {
		return "", fmt.Errorf("container has no network settings")
	}
	ep, ok := c.NetworkSettings.Networks[networkName]
	if !ok {
		return "", fmt.Errorf("container is not attached to network %q", networkName)
	}
	if ep.IPAddress == "" {
		return "", fmt.Errorf("container has no IP address on network %q yet", networkName)
	}
	return ep.IPAddress, nil
}
