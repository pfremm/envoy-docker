package dockerwatch

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
)

const servicePrefix = "envoy.http.services."

type weightedDraft struct {
	name               string
	weight             uint32
	hasName, hasWeight bool
}
type serviceDraft struct {
	name       string
	ports      map[int]uint32
	hasSugar   bool
	hasIndexed bool
	weighted   map[int]weightedDraft
	protocol   model.UpstreamProtocol
	health     *model.HealthCheck
	outlier    *model.OutlierDetection
	sticky     *model.StickyCookie
}

func parseDurationLabel(key, value string, allowZero bool) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 || (!allowZero && d == 0) {
		qualifier := "non-negative"
		if !allowZero {
			qualifier = "positive"
		}
		return 0, fmt.Errorf("label %s has invalid duration %q (must be a %s Go duration such as 500ms or 10s)", key, value, qualifier)
	}
	return d, nil
}

func parseBoolLabel(key, value string) (bool, error) {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("label %s has invalid boolean %q (want true or false)", key, value)
	}
	return v, nil
}

func parseUint32Label(key, value string, positive bool) (uint32, error) {
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || (positive && n == 0) {
		return 0, fmt.Errorf("label %s has invalid integer %q", key, value)
	}
	return uint32(n), nil
}

func parseServices(labels map[string]string) (map[string]serviceDraft, map[string]error, error) {
	drafts := map[string]serviceDraft{}
	bad := map[string]error{}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.HasPrefix(key, servicePrefix) {
			continue
		}
		value := labels[key]
		rest := strings.TrimPrefix(key, servicePrefix)
		name, field, ok := strings.Cut(rest, ".")
		if !ok || name == "" {
			return nil, nil, fmt.Errorf("service label %q has an empty or missing service name", key)
		}
		d := drafts[name]
		d.name = name
		if d.ports == nil {
			d.ports = map[int]uint32{}
		}
		if d.weighted == nil {
			d.weighted = map[int]weightedDraft{}
		}
		var err error
		switch {
		case field == "loadbalancer.port":
			d.hasSugar = true
			var p uint32
			p, err = parseUint32Label(key, value, true)
			if p > 65535 {
				err = fmt.Errorf("label %s port %q is out of range", key, value)
			}
			d.ports[0] = p
		case strings.HasPrefix(field, "loadbalancer.servers.") && strings.HasSuffix(field, ".port"):
			d.hasIndexed = true
			idxText := strings.TrimSuffix(strings.TrimPrefix(field, "loadbalancer.servers."), ".port")
			var idx int
			idx, err = strconv.Atoi(idxText)
			if err == nil && idx < 0 {
				err = fmt.Errorf("label %s has invalid server index", key)
			}
			var p uint32
			if err == nil {
				p, err = parseUint32Label(key, value, true)
				if p > 65535 {
					err = fmt.Errorf("label %s port %q is out of range", key, value)
				}
				d.ports[idx] = p
			}
		case strings.HasPrefix(field, "weighted.services."):
			part := strings.TrimPrefix(field, "weighted.services.")
			idxText, attr, found := strings.Cut(part, ".")
			var idx int
			if !found {
				err = fmt.Errorf("label %s must end in .name or .weight", key)
			} else {
				idx, err = strconv.Atoi(idxText)
			}
			if err == nil && idx < 0 {
				err = fmt.Errorf("label %s has invalid weighted service index", key)
			}
			if err == nil {
				w := d.weighted[idx]
				switch attr {
				case "name":
					w.name = value
					w.hasName = true
				case "weight":
					w.weight, err = parseUint32Label(key, value, true)
					w.hasWeight = true
				default:
					err = fmt.Errorf("label %s has unknown weighted service field %q", key, attr)
				}
				d.weighted[idx] = w
			}
		case field == "loadbalancer.protocol":
			d.protocol = model.UpstreamProtocol(strings.ToLower(value))
		case strings.HasPrefix(field, "loadbalancer.healthcheck."):
			if d.health == nil {
				d.health = &model.HealthCheck{Interval: 10 * time.Second, Timeout: 2 * time.Second, UnhealthyThreshold: 3, HealthyThreshold: 1}
			}
			attr := strings.TrimPrefix(field, "loadbalancer.healthcheck.")
			switch attr {
			case "path":
				d.health.Path = value
			case "interval":
				d.health.Interval, err = parseDurationLabel(key, value, false)
			case "timeout":
				d.health.Timeout, err = parseDurationLabel(key, value, false)
			case "unhealthythreshold":
				d.health.UnhealthyThreshold, err = parseUint32Label(key, value, true)
			case "healthythreshold":
				d.health.HealthyThreshold, err = parseUint32Label(key, value, true)
			default:
				err = fmt.Errorf("label %s has unknown healthcheck field %q", key, attr)
			}
		case strings.HasPrefix(field, "loadbalancer.outlier."):
			if d.outlier == nil {
				d.outlier = &model.OutlierDetection{}
			}
			attr := strings.TrimPrefix(field, "loadbalancer.outlier.")
			switch attr {
			case "consecutive5xx":
				d.outlier.Consecutive5xx, err = parseUint32Label(key, value, true)
			case "interval":
				d.outlier.Interval, err = parseDurationLabel(key, value, false)
			case "baseejectiontime":
				d.outlier.BaseEjectionTime, err = parseDurationLabel(key, value, false)
			case "maxejectionpercent":
				value, parseErr := parseUint32Label(key, value, false)
				err = parseErr
				if parseErr == nil {
					d.outlier.MaxEjectionPercent = &value
				}
			default:
				err = fmt.Errorf("label %s has unknown outlier field %q", key, attr)
			}
		case strings.HasPrefix(field, "loadbalancer.sticky.cookie."):
			if d.sticky == nil {
				d.sticky = &model.StickyCookie{}
			}
			attr := strings.TrimPrefix(field, "loadbalancer.sticky.cookie.")
			switch attr {
			case "name":
				d.sticky.Name = value
			case "secure":
				d.sticky.Secure, err = parseBoolLabel(key, value)
			case "httponly":
				d.sticky.HTTPOnly, err = parseBoolLabel(key, value)
			case "samesite":
				d.sticky.SameSite = strings.ToLower(value)
			case "ttl":
				d.sticky.TTL, err = parseDurationLabel(key, value, true)
			default:
				err = fmt.Errorf("label %s has unknown sticky cookie field %q", key, attr)
			}
		default:
			err = fmt.Errorf("label %s has unknown service field %q", key, field)
		}
		if err != nil {
			bad[name] = err
		}
		drafts[name] = d
	}
	for name, d := range drafts {
		if _, exists := bad[name]; exists {
			delete(drafts, name)
			continue
		}
		if d.hasSugar && d.hasIndexed {
			bad[name] = fmt.Errorf("service %q cannot combine loadbalancer.port with indexed loadbalancer.servers", name)
			delete(drafts, name)
			continue
		}
		if len(d.ports) > 0 && len(d.weighted) > 0 {
			bad[name] = fmt.Errorf("service %q cannot define both loadbalancer servers and weighted services", name)
			delete(drafts, name)
			continue
		}
		for idx, w := range d.weighted {
			if !w.hasName || !w.hasWeight {
				bad[name] = fmt.Errorf("service %q weighted.services.%d requires both name and weight", name, idx)
				break
			}
		}
		if _, exists := bad[name]; exists {
			delete(drafts, name)
			continue
		}
	}
	return drafts, bad, nil
}

func (w *Watcher) scan(ctx context.Context) (model.Configuration, error) {
	containers, err := w.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return model.Configuration{}, fmt.Errorf("listing containers: %w", err)
	}
	return model.Configuration{
		HTTP: discover(containers, w.defaultNetwork, w.logger),
		TCP:  discoverTCP(containers, w.defaultNetwork, w.logger),
	}, nil
}

func discover(containers []container.Summary, defaultNetwork string, logger *slog.Logger) model.HTTPConfiguration {
	if logger == nil {
		logger = slog.Default()
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
	type parsedContainer struct {
		c       container.Summary
		routers map[string]parsedRouter
	}
	parsed := make([]parsedContainer, 0, len(containers))
	services := map[string]model.HTTPService{}
	invalidServices := map[string]error{}
	middlewares := map[string]model.Middleware{}
	invalidMiddlewares := map[string]error{}
	for _, c := range containers {
		if c.Labels[enableLabel] != "true" {
			continue
		}
		name := containerName(c)
		routers, badRouters, err := parseRouters(c.Labels)
		if err != nil {
			logger.Warn("skipping container with invalid envoy labels", "container", name, "error", err)
			continue
		}
		for rn, e := range badRouters {
			logger.Warn("skipping router: invalid envoy labels", "container", name, "router", rn, "error", e)
		}
		defs, badDefs, err := parseMiddlewares(c.Labels)
		if err != nil {
			logger.Warn("skipping container with structurally invalid middleware labels", "container", name, "error", err)
			continue
		}
		for mn, e := range badDefs {
			invalidMiddlewares[mn] = e
			delete(middlewares, mn)
			logger.Warn("discarding invalid middleware", "container", name, "middleware", mn, "error", e)
		}
		for mn, def := range defs {
			if _, bad := invalidMiddlewares[mn]; bad {
				continue
			}
			if old, exists := middlewares[mn]; exists && !reflect.DeepEqual(old, def) {
				invalidMiddlewares[mn] = fmt.Errorf("middleware %q has conflicting definitions", mn)
				delete(middlewares, mn)
				logger.Warn("discarding conflicting middleware", "container", name, "middleware", mn)
			} else {
				middlewares[mn] = def
			}
		}
		drafts, badServices, err := parseServices(c.Labels)
		if err != nil {
			logger.Warn("skipping container with invalid service labels", "container", name, "error", err)
			continue
		}
		for sn, e := range badServices {
			invalidServices[sn] = e
			logger.Warn("skipping service: invalid envoy labels", "container", name, "service", sn, "error", e)
		}
		parsed = append(parsed, parsedContainer{c, routers})
		for sn, d := range drafts {
			protocol := d.protocol
			if len(d.ports) > 0 && protocol == "" {
				protocol = model.ProtocolHTTP1
			}
			s := model.HTTPService{Name: sn, Protocol: protocol, HealthCheck: d.health, Outlier: d.outlier, Sticky: d.sticky, Origin: name}
			idxs := make([]int, 0, len(d.weighted))
			for i := range d.weighted {
				idxs = append(idxs, i)
			}
			sort.Ints(idxs)
			for _, i := range idxs {
				wd := d.weighted[i]
				s.Weighted = append(s.Weighted, model.WeightedService{Name: wd.name, Weight: wd.weight})
			}
			if len(d.ports) > 0 {
				network := defaultNetwork
				explicitNetworks := map[string]struct{}{}
				for _, r := range routers {
					if r.service == sn && r.network != "" {
						explicitNetworks[r.network] = struct{}{}
					}
				}
				if len(explicitNetworks) > 1 {
					invalidServices[sn] = fmt.Errorf("service %q is referenced with conflicting networks", sn)
				} else {
					for selected := range explicitNetworks {
						network = selected
					}
				}
				s.DiscoveryNetwork = network
				addr, e := containerIP(c, network)
				if e != nil {
					invalidServices[sn] = fmt.Errorf("service %q cannot resolve endpoint on network %q: %w", sn, network, e)
				} else {
					pidx := make([]int, 0, len(d.ports))
					for i := range d.ports {
						pidx = append(pidx, i)
					}
					sort.Ints(pidx)
					for _, i := range pidx {
						s.Endpoints = append(s.Endpoints, model.Endpoint{Address: addr, Port: d.ports[i]})
					}
				}
			}
			if old, ok := services[sn]; ok {
				oldShape, newShape := old, s
				oldShape.Endpoints = nil
				oldShape.Origin = ""
				newShape.Endpoints = nil
				newShape.Origin = ""
				if !reflect.DeepEqual(oldShape, newShape) {
					invalidServices[sn] = fmt.Errorf("service %q has conflicting definitions from %s and %s", sn, old.Origin, name)
				} else {
					old.Endpoints = append(old.Endpoints, s.Endpoints...)
					old.Origin += "," + name
					services[sn] = old
				}
			} else {
				services[sn] = s
			}
		}
	}
	for sn, e := range invalidServices {
		delete(services, sn)
		logger.Warn("discarding invalid service", "service", sn, "error", e)
	}
	// Validate references and cycles after every container has been parsed.
	cfg := model.HTTPConfiguration{Routes: map[string]model.Route{}, Services: services, Middlewares: middlewares}
	// routerSubdomain records which subdomain first claimed each router
	// name. Router names become global xDS route resource names
	// (routeResourceName), so the same name on two DIFFERENT subdomains
	// would collide at the build layer and reject the whole snapshot; skip
	// the later router (containers are ID-sorted, so this is
	// deterministic) with a warning instead, mirroring the TCP guard.
	// The same name on the SAME subdomain is the replica/conflict path
	// handled below via routesCompatible/precedence.
	routerSubdomain := map[string]string{}
	// bySubdomain accumulates every router accepted for a subdomain.
	// DISTINCT routers (different router names) sharing one subdomain are
	// ALL preserved rather than resolved here: discovery must not decide
	// which router wins, because that decision belongs to the xDS
	// precedence/fallback evaluation, which sees the rules. The routes are
	// materialised into cfg.Routes after every container is parsed (the
	// subdomain's highest-precedence router keeps the bare subdomain key
	// and legacy cluster name; the others get a derived key and their own
	// ClusterKey).
	bySubdomain := map[string][]model.Route{}
	for sn, s := range services {
		if err := s.Validate(); err != nil {
			invalidServices[sn] = err
			delete(cfg.Services, sn)
		}
	}
	for sn := range cfg.Services {
		if _, err := cfg.ResolveService(sn); err != nil {
			invalidServices[sn] = err
			delete(cfg.Services, sn)
		}
	}
	for _, pc := range parsed {
		name := containerName(pc.c)
		rnames := make([]string, 0, len(pc.routers))
		for rn := range pc.routers {
			rnames = append(rnames, rn)
		}
		sort.Strings(rnames)
		for _, rn := range rnames {
			r := pc.routers[rn]
			if r.service != "" {
				if _, ok := cfg.Services[r.service]; !ok {
					logger.Warn("skipping router: referenced service is unknown or invalid", "container", name, "router", rn, "service", r.service, "error", invalidServices[r.service])
					continue
				}
			}
			resolvedMiddlewares := make([]model.Middleware, 0, len(r.middlewares))
			validChain := true
			for _, mn := range r.middlewares {
				def, ok := cfg.Middlewares[mn]
				if !ok {
					logger.Warn("skipping router: referenced middleware is unknown or invalid", "container", name, "router", rn, "middleware", mn, "error", invalidMiddlewares[mn])
					validChain = false
					break
				}
				resolvedMiddlewares = append(resolvedMiddlewares, def)
			}
			if !validChain {
				continue
			}
			if err := model.ValidateMiddlewareChain(resolvedMiddlewares); err != nil {
				logger.Warn("skipping router: invalid middleware chain", "container", name, "router", rn, "error", err)
				continue
			}
			if r.ruleExpr != "" {
				rr, e := rule.Parse(r.ruleExpr)
				if e != nil {
					logger.Warn("skipping router: invalid rule expression", "container", name, "router", rn, "rule", r.ruleExpr, "error", e)
					continue
				}
				r.rule = rr
			}
			effectiveNetwork := r.network
			if effectiveNetwork == "" {
				effectiveNetwork = defaultNetwork
			}
			route := model.Route{Subdomain: r.subdomain, Source: model.SourceDocker, Origin: name + "/" + rn, Rule: r.rule, RuleExpr: r.ruleExpr, Priority: r.priority, PrioritySet: r.prioritySet, RouterName: rn, ServiceName: r.service, Timeout: r.timeout, IdleTimeout: r.idleTimeout, WebSocketDisabled: r.websocketDisabled, Retry: r.retry, MiddlewareNames: append([]string(nil), r.middlewares...), Middlewares: resolvedMiddlewares, DiscoveryNetwork: effectiveNetwork, Entrypoints: append([]string(nil), r.entrypoints...), SSOProfile: r.ssoProfile}
			if r.tracingSet || r.operationName != "" {
				route.Tracing = &model.TracingConfig{Enabled: r.tracing, OperationName: r.operationName}
			}
			if r.accesslogSet {
				v := r.accesslog
				route.AccessLog = &v
			}
			if r.service == "" {
				addr, e := containerIP(pc.c, effectiveNetwork)
				if e != nil {
					logger.Warn("skipping router: could not resolve container IP", "container", name, "router", rn, "network", effectiveNetwork, "error", e)
					continue
				}
				route.Endpoints = []model.Endpoint{{Address: addr, Port: r.port}}
			}
			if claimed, dup := routerSubdomain[rn]; dup && claimed != r.subdomain {
				logger.Warn("skipping router: duplicate router name across containers",
					"container", name, "router", rn, "subdomain", r.subdomain, "claimed_by_subdomain", claimed)
				continue
			}
			// Find an existing route for the SAME router name on this
			// subdomain: that is the replica path (a scaled compose
			// service), which merges endpoints. A router with a
			// DIFFERENT name is a distinct router and is preserved
			// alongside, so xDS can order both by precedence.
			existing := bySubdomain[r.subdomain]
			replica := -1
			for i, old := range existing {
				if old.RouterName == rn {
					replica = i
					break
				}
			}
			if replica >= 0 {
				old := existing[replica]
				if !routesCompatible(old, route) {
					// Same router name, same subdomain, incompatible
					// definition: the two containers disagree about what
					// this one router is. There is no second router to
					// preserve here, so keep the deterministic
					// higher-precedence definition.
					if model.Precedence(route, old) {
						logger.Warn("replacing lower-precedence router conflict", "subdomain", r.subdomain, "router", rn, "kept", route.Origin, "skipped", old.Origin)
						existing[replica] = route
					} else {
						logger.Warn("skipping lower-precedence router conflict", "subdomain", r.subdomain, "router", rn, "kept", old.Origin, "skipped", route.Origin)
					}
					continue
				}
				old.Endpoints = append(old.Endpoints, route.Endpoints...)
				old.Origin += "," + route.Origin
				existing[replica] = old
				continue
			}
			routerSubdomain[rn] = r.subdomain
			bySubdomain[r.subdomain] = append(existing, route)
		}
	}
	// Materialise the accepted routers into cfg.Routes. Every distinct
	// router survives discovery: the subdomain's highest-precedence router
	// keeps the bare subdomain key and the legacy subdomain-named cluster
	// (so single-router subdomains, the overwhelmingly common case, are
	// byte-identical to before), and each remaining router is stored under
	// "<subdomain>#<router>" with its own ClusterKey so it reaches xDS with
	// distinct cluster/endpoint resources.
	for subdomain, routes := range bySubdomain {
		ordered := model.SortByPrecedence(routes)
		for i, route := range ordered {
			if i == 0 {
				cfg.Routes[subdomain] = route
				continue
			}
			route.ClusterKey = derivedClusterName(subdomain, route.RouterName)
			cfg.Routes[derivedRouteKey(subdomain, route.RouterName)] = route
		}
		if len(ordered) > 1 {
			names := make([]string, 0, len(ordered))
			for _, route := range ordered {
				names = append(names, route.RouterName)
			}
			logger.Info("subdomain served by several routers; all preserved for precedence evaluation",
				"subdomain", subdomain, "routers", strings.Join(names, ","))
		}
	}
	for sn, s := range cfg.Services {
		sort.Slice(s.Endpoints, func(i, j int) bool {
			if s.Endpoints[i].Address != s.Endpoints[j].Address {
				return s.Endpoints[i].Address < s.Endpoints[j].Address
			}
			return s.Endpoints[i].Port < s.Endpoints[j].Port
		})
		cfg.Services[sn] = s
	}
	return cfg
}

// derivedRouteKey is the HTTPConfiguration.Routes map key for a router that
// shares its subdomain with a higher-precedence router. The "#" separator
// cannot appear in a subdomain or a router label name, so a derived key can
// never collide with a bare subdomain key.
func derivedRouteKey(subdomain, routerName string) string {
	return subdomain + "#" + routerName
}

// derivedClusterName is the Envoy cluster/endpoint name for such a router.
// It must be distinct from the subdomain-named cluster the subdomain's
// highest-precedence router keeps, and stable across rebuilds.
func derivedClusterName(subdomain, routerName string) string {
	return subdomain + "#" + routerName
}

func routesCompatible(a, b model.Route) bool {
	if a.RuleExpr != b.RuleExpr || a.ServiceName != b.ServiceName || a.Priority != b.Priority ||
		a.PrioritySet != b.PrioritySet || a.DiscoveryNetwork != b.DiscoveryNetwork ||
		!reflect.DeepEqual(a.MiddlewareNames, b.MiddlewareNames) ||
		!reflect.DeepEqual(a.Timeout, b.Timeout) || !reflect.DeepEqual(a.IdleTimeout, b.IdleTimeout) || a.WebSocketDisabled != b.WebSocketDisabled || !reflect.DeepEqual(a.Retry, b.Retry) ||
		!reflect.DeepEqual(a.Entrypoints, b.Entrypoints) || !reflect.DeepEqual(a.Tracing, b.Tracing) || !reflect.DeepEqual(a.AccessLog, b.AccessLog) || a.SSOProfile != b.SSOProfile {
		return false
	}
	if a.ServiceName == "" && len(a.Endpoints) > 0 && len(b.Endpoints) > 0 && a.Endpoints[0].Port != b.Endpoints[0].Port {
		return false
	}
	return true
}
