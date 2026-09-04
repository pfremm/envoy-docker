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
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
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

		routers, badRouters, err := parseRouters(c.Labels)
		if err != nil {
			w.logger.Warn("skipping container with invalid envoy labels", "container", name, "error", err)
			continue
		}

		// Routers rejected on their own (invalid priority/port, missing
		// subdomain): log and skip them individually; the rest of the
		// container's routers are unaffected.
		badNames := make([]string, 0, len(badRouters))
		for rn := range badRouters {
			badNames = append(badNames, rn)
		}
		sort.Strings(badNames)
		for _, rn := range badNames {
			w.logger.Warn("skipping router: invalid envoy labels",
				"container", name, "router", rn, "error", badRouters[rn])
		}

		// Deterministic router iteration order so merge-conflict resolution
		// and log output are stable across scans.
		routerNames := make([]string, 0, len(routers))
		for rn := range routers {
			routerNames = append(routerNames, rn)
		}
		sort.Strings(routerNames)

		for _, routerName := range routerNames {
			r := routers[routerName]

			// Parse the rule expression (if any) into the typed AST. A bad
			// rule rejects only this router, with an actionable log; the
			// rest of the container's routers are unaffected.
			if r.ruleExpr != "" {
				parsed, perr := rule.Parse(r.ruleExpr)
				if perr != nil {
					w.logger.Warn("skipping router: invalid rule expression",
						"container", name, "router", routerName,
						"rule", r.ruleExpr, "error", perr,
						"hint", "check the rule grammar in docs/LABELS.md (matchers: Host, Path, PathPrefix, Headers, Method, Query, ClientIP; operators: &&, ||, !, parentheses)")
					continue
				}
				r.rule = parsed
			}

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

			existing, exists := routes[r.subdomain]
			if action, msg := mergeDecision(existing, exists, r.ruleExpr, origin); action == mergeSkip {
				w.logger.Warn("skipping router: "+msg,
					"container", name, "router", routerName, "subdomain", r.subdomain)
				continue
			}

			if exists {
				existing.Endpoints = append(existing.Endpoints, endpoint)
				existing.Origin = existing.Origin + "," + origin
				routes[r.subdomain] = existing
				continue
			}

			routes[r.subdomain] = model.Route{
				Subdomain:   r.subdomain,
				Endpoints:   []model.Endpoint{endpoint},
				Source:      model.SourceDocker,
				Origin:      origin,
				Rule:        r.rule,
				RuleExpr:    r.ruleExpr,
				Priority:    r.priority,
				PrioritySet: r.prioritySet,
				RouterName:  routerName,
			}
		}
	}

	return routes, nil
}

type mergeAction int

const (
	mergeAdd   mergeAction = iota // no existing route: add a new one
	mergeMerge                    // same rule: merge as a replica
	mergeSkip                     // conflicting rule: reject this router
)

// mergeDecision decides how a new router for an already-seen subdomain is
// handled. Multiple containers advertising the same subdomain with the same
// rule are replicas of one route and merge into a multi-endpoint route
// (basic round robin), matching Traefik's behavior when a compose service is
// scaled. A different rule on the same subdomain is a configuration conflict:
// the later router is rejected rather than guessing which intent wins.
func mergeDecision(existing model.Route, exists bool, newRuleExpr, newOrigin string) (mergeAction, string) {
	if !exists {
		return mergeAdd, ""
	}
	if existing.RuleExpr != newRuleExpr {
		return mergeSkip, fmt.Sprintf(
			"subdomain already claimed by a different rule (existing %q from %s, new %q from %s); use different subdomains, or make the rules identical so the routers merge as replicas",
			existing.RuleExpr, existing.Origin, newRuleExpr, newOrigin)
	}
	return mergeMerge, ""
}

type parsedRouter struct {
	subdomain string
	port      uint32
	network   string
	// ruleExpr is the raw rule expression ("" for legacy subdomain-only
	// routers). rule is its parsed form.
	ruleExpr string
	rule     model.Rule
	// priority is the explicit integer priority (0 with prioritySet=false
	// when the label is absent).
	priority    int
	prioritySet bool
}

// parseRouters extracts envoy.http.routers.<name>.{subdomain,port,network,
// rule,priority} labels into one parsedRouter per <name>.
//
// It returns (routers, badRouters, err):
//
//   - routers: the valid routers, ready to be turned into routes.
//   - badRouters: a name -> error map for routers that were rejected on
//     their own (an invalid priority value, or missing subdomain/port).
//     Callers log these and skip only the affected router; the rest of the
//     container's routers are unaffected.
//   - err: non-nil only for a structurally broken label set (no router at
//     all, or a label that cannot be attributed to a single router), which
//     the caller should treat as "skip the whole container".
func parseRouters(labels map[string]string) (map[string]parsedRouter, map[string]error, error) {
	routers := map[string]parsedRouter{}
	badRouters := map[string]error{}

	for key, value := range labels {
		if !strings.HasPrefix(key, routerPrefix) {
			continue
		}
		rest := strings.TrimPrefix(key, routerPrefix)
		name, field, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		if name == "" {
			return nil, nil, fmt.Errorf("router label %q has an empty router name", key)
		}

		r := routers[name]
		switch field {
		case "subdomain":
			r.subdomain = value
		case "port":
			p, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				// An invalid port belongs to this router only: reject it
				// individually rather than the whole container.
				badRouters[name] = fmt.Errorf("router %q: invalid port %q (must be an integer 1-65535)", name, value)
				continue
			}
			if p == 0 {
				badRouters[name] = fmt.Errorf("router %q: port %q is out of range (must be 1-65535)", name, value)
				continue
			}
			r.port = uint32(p)
		case "network":
			r.network = value
		case "rule":
			r.ruleExpr = value
		case "priority":
			p, err := strconv.Atoi(value)
			if err != nil {
				// An invalid priority belongs to this router only: reject it
				// individually rather than the whole container.
				badRouters[name] = fmt.Errorf("router %q: invalid priority %q (must be an integer)", name, value)
				continue
			}
			r.priority = p
			r.prioritySet = true
		default:
			continue
		}
		routers[name] = r
	}

	for name, r := range routers {
		if _, bad := badRouters[name]; bad {
			continue
		}
		if r.subdomain == "" {
			badRouters[name] = fmt.Errorf("router %q missing %s%s.subdomain label", name, routerPrefix, name)
		} else if r.port == 0 {
			badRouters[name] = fmt.Errorf("router %q missing %s%s.port label", name, routerPrefix, name)
		}
	}

	for name := range badRouters {
		delete(routers, name)
	}

	return routers, badRouters, nil
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
