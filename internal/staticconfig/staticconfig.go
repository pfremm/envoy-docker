// Package staticconfig loads routes for non-Docker backends from a YAML file,
// so they can be merged into the same routing table as docker-discovered
// routes.
package staticconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

type fileFormat struct {
	Routers []routerEntry `yaml:"routers"`
}

type routerEntry struct {
	Subdomain string   `yaml:"subdomain"`
	Port      uint32   `yaml:"port"`
	Addresses []string `yaml:"addresses"`
}

// Load reads and parses a static routers YAML file into a route map keyed
// by subdomain. An empty path returns an empty map with no error.
func Load(path string) (map[string]model.Route, error) {
	routes := map[string]model.Route{}
	if path == "" {
		return routes, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading static config %s: %w", path, err)
	}

	var parsed fileFormat
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parsing static config %s: %w", path, err)
	}

	for i, r := range parsed.Routers {
		origin := fmt.Sprintf("%s[%d]", path, i)

		if r.Subdomain == "" {
			return nil, fmt.Errorf("%s: router at index %d missing subdomain", path, i)
		}
		if r.Port == 0 {
			return nil, fmt.Errorf("%s: router %q missing port", path, r.Subdomain)
		}
		if len(r.Addresses) == 0 {
			return nil, fmt.Errorf("%s: router %q has no addresses", path, r.Subdomain)
		}

		if _, exists := routes[r.Subdomain]; exists {
			return nil, fmt.Errorf("%s: duplicate subdomain %q", path, r.Subdomain)
		}

		endpoints := make([]model.Endpoint, 0, len(r.Addresses))
		for _, addr := range r.Addresses {
			endpoints = append(endpoints, model.Endpoint{Address: addr, Port: r.Port})
		}

		routes[r.Subdomain] = model.Route{
			Subdomain: r.Subdomain,
			Endpoints: endpoints,
			Source:    model.SourceStatic,
			Origin:    origin,
		}
	}

	return routes, nil
}
