// Package dockerwatch watches the Docker socket for containers carrying
// envoy.* labels and turns them into a routing table, updating it on
// container lifecycle events.
package dockerwatch

import (
	"context"
	"fmt"
	"log/slog"
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
func (w *Watcher) Run(ctx context.Context, updates chan<- model.Configuration) error {
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
	service   string
	// ruleExpr is the raw rule expression ("" for legacy subdomain-only
	// routers). rule is its parsed form.
	ruleExpr string
	rule     model.Rule
	// priority is the explicit integer priority (0 with prioritySet=false
	// when the label is absent).
	priority    int
	prioritySet bool
	timeout     *time.Duration
	idleTimeout *time.Duration
	retry       *model.RetryPolicy
	// websocketDisabled is set by .websocket=false (upgrades are on by
	// default).
	websocketDisabled bool
	middlewares       []string
	// entrypoints is the .entrypoints label: the HTTP entrypoint names this
	// router is served on. Empty means the default HTTP/HTTPS entrypoints.
	entrypoints []string
	// tracing carries the .tracing / .tracing.operationname hooks. tracingSet
	// records whether the .tracing hook was present (so false is distinct
	// from unset); operationName is the .tracing.operationname span name.
	tracingSet    bool
	tracing       bool
	operationName string
	// accesslogSet records whether the .accesslog hook was present; accesslog
	// is its value.
	accesslogSet bool
	accesslog    bool
	// ssoProfile is the .sso label: the operator SSO profile name. It is
	// resolved against SSO_CONFIG_PATH at snapshot build time.
	ssoProfile string
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
		case "service":
			r.service = value
		case "rule":
			r.ruleExpr = value
		case "timeout":
			d, err := parseDurationLabel(key, value, true)
			if err != nil {
				badRouters[name] = err
				continue
			}
			r.timeout = &d
		case "idletimeout":
			d, err := parseDurationLabel(key, value, true)
			if err != nil {
				badRouters[name] = err
				continue
			}
			r.idleTimeout = &d
		case "websocket":
			b, err := parseBoolLabel(key, value)
			if err != nil {
				badRouters[name] = err
				continue
			}
			r.websocketDisabled = !b
		case "retries.attempts":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || n == 0 {
				badRouters[name] = fmt.Errorf("router %q: invalid retries.attempts %q (must be a positive integer)", name, value)
				continue
			}
			if r.retry == nil {
				r.retry = &model.RetryPolicy{}
			}
			r.retry.Attempts = uint32(n)
		case "retries.pertrytimeout":
			d, err := parseDurationLabel(key, value, false)
			if err != nil {
				badRouters[name] = err
				continue
			}
			if r.retry == nil {
				r.retry = &model.RetryPolicy{}
			}
			r.retry.PerTryTimeout = d
		case "retries.retryon":
			if strings.TrimSpace(value) == "" {
				badRouters[name] = fmt.Errorf("router %q: retries.retryon cannot be empty", name)
				continue
			}
			if r.retry == nil {
				r.retry = &model.RetryPolicy{}
			}
			r.retry.RetryOn = value
		case "middlewares":
			chain, err := splitEscapedList(key, value)
			if err != nil {
				badRouters[name] = err
				continue
			}
			r.middlewares = chain
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
		case "entrypoints":
			eps, err := splitEscapedList(key, value)
			if err != nil {
				badRouters[name] = err
				continue
			}
			for _, ep := range eps {
				if ep == "" {
					badRouters[name] = fmt.Errorf("router %q: entrypoints list contains an empty entrypoint name", name)
					break
				}
			}
			if badRouters[name] == nil {
				r.entrypoints = eps
			}
		case "tracing":
			b, err := parseBoolLabel(key, value)
			if err != nil {
				badRouters[name] = err
				continue
			}
			r.tracingSet = true
			r.tracing = b
		case "tracing.operationname":
			if strings.TrimSpace(value) == "" {
				badRouters[name] = fmt.Errorf("router %q: tracing.operationname cannot be empty", name)
				continue
			}
			r.operationName = value
		case "accesslog":
			b, err := parseBoolLabel(key, value)
			if err != nil {
				badRouters[name] = err
				continue
			}
			r.accesslogSet = true
			r.accesslog = b
		case "sso":
			v := strings.TrimSpace(value)
			if v == "" {
				badRouters[name] = fmt.Errorf("router %q: sso cannot be empty (omit the label for a public router)", name)
				continue
			}
			r.ssoProfile = v
		default:
			continue
		}
		routers[name] = r
	}

	for name, r := range routers {
		if _, bad := badRouters[name]; bad {
			continue
		}
		if r.retry != nil && strings.TrimSpace(r.retry.RetryOn) == "" {
			badRouters[name] = fmt.Errorf("router %q sets retry options but is missing %s%s.retries.retryon", name, routerPrefix, name)
			continue
		}
		if r.subdomain == "" {
			badRouters[name] = fmt.Errorf("router %q missing %s%s.subdomain label", name, routerPrefix, name)
		} else if r.port != 0 && r.service != "" {
			badRouters[name] = fmt.Errorf("router %q cannot set both %s%s.port and %s%s.service", name, routerPrefix, name, routerPrefix, name)
		} else if r.port == 0 && r.service == "" {
			badRouters[name] = fmt.Errorf("router %q must set either %s%s.port (legacy) or %s%s.service", name, routerPrefix, name, routerPrefix, name)
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
