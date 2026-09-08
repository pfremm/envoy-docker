// TCP router and service label parsing. Mirrors the HTTP router/service
// parsers in watcher.go/discovery.go: fields accumulate into a draft struct
// per label key, validation happens once every label has been seen, and one
// router/service's failure never affects its siblings.
package dockerwatch

import (
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types/container"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
)

const (
	tcpRouterPrefix  = "envoy.tcp.routers."
	tcpServicePrefix = "envoy.tcp.services."
)

type parsedTCPRouter struct {
	ruleExpr       string
	rule           model.Rule
	service        string
	entrypoints    []string
	priority       int
	prioritySet    bool
	tlsPassthrough bool
	network        string
}

// parseTCPRouters extracts envoy.tcp.routers.<name>.{rule,service,
// entrypoints,priority,tls.passthrough,network} labels into one
// parsedTCPRouter per <name>. Return shape mirrors parseRouters: valid
// routers, a name -> error map for routers rejected on their own, and a
// structural error (empty router name) that skips the whole container.
func parseTCPRouters(labels map[string]string) (map[string]parsedTCPRouter, map[string]error, error) {
	routers := map[string]parsedTCPRouter{}
	bad := map[string]error{}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !strings.HasPrefix(key, tcpRouterPrefix) {
			continue
		}
		value := labels[key]
		rest := strings.TrimPrefix(key, tcpRouterPrefix)
		name, field, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		if name == "" {
			return nil, nil, fmt.Errorf("tcp router label %q has an empty router name", key)
		}

		r := routers[name]
		switch field {
		case "rule":
			r.ruleExpr = value
		case "service":
			r.service = value
		case "entrypoints":
			eps, err := splitEscapedList(key, value)
			if err != nil {
				bad[name] = err
				continue
			}
			r.entrypoints = eps
		case "priority":
			p, err := strconv.Atoi(value)
			if err != nil {
				bad[name] = fmt.Errorf("tcp router %q: invalid priority %q (must be an integer)", name, value)
				continue
			}
			r.priority = p
			r.prioritySet = true
		case "tls.passthrough":
			v, err := parseBoolLabel(key, value)
			if err != nil {
				bad[name] = err
				continue
			}
			r.tlsPassthrough = v
		case "network":
			r.network = value
		default:
			continue
		}
		routers[name] = r
	}

	for name, r := range routers {
		if _, isBad := bad[name]; isBad {
			continue
		}
		if r.ruleExpr == "" {
			bad[name] = fmt.Errorf("tcp router %q missing %s%s.rule (a HostSNI(...) rule is required)", name, tcpRouterPrefix, name)
			continue
		}
		if r.service == "" {
			bad[name] = fmt.Errorf("tcp router %q missing %s%s.service", name, tcpRouterPrefix, name)
			continue
		}
	}
	for name := range bad {
		delete(routers, name)
	}
	return routers, bad, nil
}

type tcpWeightedDraft struct {
	name               string
	weight             uint32
	hasName, hasWeight bool
}

type tcpServiceDraft struct {
	name     string
	ports    map[int]uint32
	weighted map[int]tcpWeightedDraft
}

// parseTCPServices extracts envoy.tcp.services.<name>.{loadbalancer.servers.
// <n>.port,weighted.services.<n>.{name,weight}} labels, mirroring
// parseServices for the HTTP named-service label shape.
func parseTCPServices(labels map[string]string) (map[string]tcpServiceDraft, map[string]error, error) {
	drafts := map[string]tcpServiceDraft{}
	bad := map[string]error{}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !strings.HasPrefix(key, tcpServicePrefix) {
			continue
		}
		value := labels[key]
		rest := strings.TrimPrefix(key, tcpServicePrefix)
		name, field, ok := strings.Cut(rest, ".")
		if !ok || name == "" {
			return nil, nil, fmt.Errorf("tcp service label %q has an empty or missing service name", key)
		}
		d := drafts[name]
		d.name = name
		if d.ports == nil {
			d.ports = map[int]uint32{}
		}
		if d.weighted == nil {
			d.weighted = map[int]tcpWeightedDraft{}
		}
		var err error
		switch {
		case strings.HasPrefix(field, "loadbalancer.servers.") && strings.HasSuffix(field, ".port"):
			idxText := strings.TrimSuffix(strings.TrimPrefix(field, "loadbalancer.servers."), ".port")
			var idx int
			idx, err = strconv.Atoi(idxText)
			if err == nil && idx < 0 {
				err = fmt.Errorf("label %s has invalid server index", key)
			}
			if err == nil {
				var p uint32
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
		default:
			err = fmt.Errorf("label %s has unknown tcp service field %q", key, field)
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
		if len(d.ports) > 0 && len(d.weighted) > 0 {
			bad[name] = fmt.Errorf("tcp service %q cannot define both loadbalancer servers and weighted services", name)
			delete(drafts, name)
			continue
		}
		for idx, w := range d.weighted {
			if !w.hasName || !w.hasWeight {
				bad[name] = fmt.Errorf("tcp service %q weighted.services.%d requires both name and weight", name, idx)
				break
			}
		}
		if _, exists := bad[name]; exists {
			delete(drafts, name)
		}
	}
	return drafts, bad, nil
}

// discoverTCP scans the same container set as discover (HTTP) for
// envoy.tcp.* labels and builds a model.TCPConfiguration. It follows the
// same isolation discipline: one bad router/service is dropped with an
// actionable warning without affecting its siblings, and results are
// deterministic regardless of container/label map iteration order.
func discoverTCP(containers []container.Summary, defaultNetwork string, logger *slog.Logger) model.TCPConfiguration {
	if logger == nil {
		logger = slog.Default()
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })

	type parsedTCPContainer struct {
		c       container.Summary
		routers map[string]parsedTCPRouter
	}
	parsed := make([]parsedTCPContainer, 0, len(containers))
	services := map[string]model.TCPService{}
	invalidServices := map[string]error{}

	for _, c := range containers {
		if c.Labels[enableLabel] != "true" {
			continue
		}
		name := containerName(c)
		routers, badRouters, err := parseTCPRouters(c.Labels)
		if err != nil {
			logger.Warn("skipping container with invalid envoy tcp labels", "container", name, "error", err)
			continue
		}
		for rn, e := range badRouters {
			logger.Warn("skipping tcp router: invalid envoy labels", "container", name, "router", rn, "error", e)
		}
		drafts, badServices, err := parseTCPServices(c.Labels)
		if err != nil {
			logger.Warn("skipping container with invalid tcp service labels", "container", name, "error", err)
			continue
		}
		for sn, e := range badServices {
			invalidServices[sn] = e
			logger.Warn("skipping tcp service: invalid envoy labels", "container", name, "service", sn, "error", e)
		}
		parsed = append(parsed, parsedTCPContainer{c, routers})
		for sn, d := range drafts {
			s := model.TCPService{Name: sn, Origin: name}
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
					invalidServices[sn] = fmt.Errorf("tcp service %q is referenced with conflicting networks", sn)
				} else {
					for selected := range explicitNetworks {
						network = selected
					}
				}
				s.DiscoveryNetwork = network
				addr, e := containerIP(c, network)
				if e != nil {
					invalidServices[sn] = fmt.Errorf("tcp service %q cannot resolve endpoint on network %q: %w", sn, network, e)
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
					invalidServices[sn] = fmt.Errorf("tcp service %q has conflicting definitions from %s and %s", sn, old.Origin, name)
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
		logger.Warn("discarding invalid tcp service", "service", sn, "error", e)
	}

	cfg := model.TCPConfiguration{Routers: map[string]model.TCPRouter{}, Services: services}
	for sn, s := range cfg.Services {
		if err := s.Validate(); err != nil {
			invalidServices[sn] = err
			delete(cfg.Services, sn)
		}
	}
	for sn := range cfg.Services {
		if _, err := cfg.ResolveTCPService(sn); err != nil {
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
			if _, ok := cfg.Services[r.service]; !ok {
				logger.Warn("skipping tcp router: referenced service is unknown or invalid", "container", name, "router", rn, "service", r.service, "error", invalidServices[r.service])
				continue
			}
			parsedRule, perr := rule.Parse(r.ruleExpr)
			if perr != nil {
				logger.Warn("skipping tcp router: invalid rule expression", "container", name, "router", rn, "rule", r.ruleExpr, "error", perr)
				continue
			}
			router := model.TCPRouter{
				Name:           rn,
				Rule:           parsedRule,
				RuleExpr:       r.ruleExpr,
				ServiceName:    r.service,
				Entrypoints:    append([]string(nil), r.entrypoints...),
				Priority:       r.priority,
				PrioritySet:    r.prioritySet,
				TLSPassthrough: r.tlsPassthrough,
				Origin:         name + "/" + rn,
			}
			if err := router.Validate(); err != nil {
				logger.Warn("skipping tcp router: invalid router", "container", name, "router", rn, "error", err)
				continue
			}
			if old, exists := cfg.Routers[rn]; exists {
				logger.Warn("skipping tcp router: duplicate router name across containers", "container", name, "router", rn, "existing_origin", old.Origin)
				continue
			}
			cfg.Routers[rn] = router
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
