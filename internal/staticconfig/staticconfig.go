// Package staticconfig loads routes for non-Docker backends from a YAML file,
// so they can be merged into the same routing table as docker-discovered
// routes.
package staticconfig

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// fileFormat keeps each router as a raw node so a router with a malformed
// protocol/tls setting can be rejected on its own (see Load).
type fileFormat struct {
	Routers []yaml.Node `yaml:"routers"`
}

// routerEntry holds the fields whose errors are fatal for the whole file.
type routerEntry struct {
	Subdomain string   `yaml:"subdomain"`
	Port      uint32   `yaml:"port"`
	Addresses []string `yaml:"addresses"`
}

// upstreamEntry holds the per-router upstream protocol settings. Errors in
// these fields reject only their router.
type upstreamEntry struct {
	// Protocol is "http" (default when empty) or "https", case-insensitive.
	Protocol string `yaml:"protocol"`
	// TLS is the optional tls block, only valid with protocol https. It is
	// kept raw so unknown keys and wrong value types can be reported; a zero
	// Kind means the key is absent.
	TLS yaml.Node `yaml:"tls"`
}

// Rejection describes one router that was skipped because of an invalid
// protocol/tls setting. The other routers in the file still load.
type Rejection struct {
	// Origin is the router's position in the file, as path[index].
	Origin    string
	Subdomain string
	Reason    string
}

// Load reads and parses a static routers YAML file into a route map keyed
// by subdomain. An empty path returns an empty map with no error.
//
// File-level problems (unreadable file, YAML syntax error, a router missing
// its subdomain/port/addresses or with a wrongly typed one, a duplicate
// subdomain) are returned as an error. An invalid protocol or tls block only
// rejects that router: it is left out of the map and reported in the
// returned rejections.
func Load(path string) (map[string]model.Route, []Rejection, error) {
	routes := map[string]model.Route{}
	if path == "" {
		return routes, nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading static config %s: %w", path, err)
	}

	var parsed fileFormat
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, nil, fmt.Errorf("parsing static config %s: %w", path, err)
	}

	// Subdomains are claimed by every router, rejected or not, so a
	// duplicate subdomain stays a file-level error.
	seen := map[string]bool{}
	var rejections []Rejection
	for i := range parsed.Routers {
		node := &parsed.Routers[i]
		origin := fmt.Sprintf("%s[%d]", path, i)

		var r routerEntry
		if err := node.Decode(&r); err != nil {
			return nil, nil, fmt.Errorf("parsing static config %s: router at index %d: %w", path, i, err)
		}
		if r.Subdomain == "" {
			return nil, nil, fmt.Errorf("%s: router at index %d missing subdomain", path, i)
		}
		if r.Port == 0 {
			return nil, nil, fmt.Errorf("%s: router %q missing port", path, r.Subdomain)
		}
		if len(r.Addresses) == 0 {
			return nil, nil, fmt.Errorf("%s: router %q has no addresses", path, r.Subdomain)
		}
		if seen[r.Subdomain] {
			return nil, nil, fmt.Errorf("%s: duplicate subdomain %q", path, r.Subdomain)
		}
		seen[r.Subdomain] = true

		upstreamTLS, err := parseUpstream(node)
		if err != nil {
			rejections = append(rejections, Rejection{Origin: origin, Subdomain: r.Subdomain, Reason: err.Error()})
			continue
		}

		endpoints := make([]model.Endpoint, 0, len(r.Addresses))
		for _, addr := range r.Addresses {
			endpoints = append(endpoints, model.Endpoint{Address: addr, Port: r.Port})
		}

		routes[r.Subdomain] = model.Route{
			Subdomain:   r.Subdomain,
			Endpoints:   endpoints,
			Source:      model.SourceStatic,
			Origin:      origin,
			UpstreamTLS: upstreamTLS,
		}
	}

	return routes, rejections, nil
}

// parseUpstream validates a router's protocol and tls block and returns its
// upstream TLS policy: nil for http, non-nil for https.
func parseUpstream(node *yaml.Node) (*model.UpstreamTLS, error) {
	var u upstreamEntry
	if err := node.Decode(&u); err != nil {
		return nil, fmt.Errorf("invalid protocol/tls: %w", err)
	}
	switch strings.ToLower(u.Protocol) {
	case "", "http":
		if u.TLS.Kind != 0 {
			return nil, fmt.Errorf("tls block requires protocol: https (protocol is %q)", u.Protocol)
		}
		return nil, nil
	case "https":
	default:
		return nil, fmt.Errorf("unsupported protocol %q (want http or https)", u.Protocol)
	}

	tls := &model.UpstreamTLS{}
	if u.TLS.Kind == 0 {
		return tls, nil
	}
	if u.TLS.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("tls must be a mapping (line %d)", u.TLS.Line)
	}
	for j := 0; j+1 < len(u.TLS.Content); j += 2 {
		key, value := u.TLS.Content[j], u.TLS.Content[j+1]
		switch key.Value {
		case "insecure_skip_verify":
			if err := value.Decode(&tls.InsecureSkipVerify); err != nil {
				return nil, fmt.Errorf("tls.insecure_skip_verify must be true or false: %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown tls key %q (line %d)", key.Value, key.Line)
		}
	}
	return tls, nil
}
