// Package model holds the route representation shared between the docker
// watcher, the static config loader, and the xDS snapshot builder.
package model

import "fmt"

// Endpoint is a single backend address:port a route can be load balanced to.
type Endpoint struct {
	Address string
	Port    uint32
}

// Source identifies where a Route was discovered, for logging/diagnostics.
type Source string

const (
	SourceDocker Source = "docker"
	SourceStatic Source = "static"
)

// Route describes one subdomain's worth of routing: the unique subdomain
// label and the set of backend endpoints to load balance across.
type Route struct {
	Subdomain string
	Endpoints []Endpoint
	Source    Source
	// Origin is a human-readable identifier of what produced this route
	// (container name, or static config entry index) used in log messages.
	Origin string
}

func (r Route) String() string {
	return fmt.Sprintf("%s (%s, %d endpoint(s), from %s)", r.Subdomain, r.Source, len(r.Endpoints), r.Origin)
}

// ClusterName returns the Envoy cluster/route name for this route. Since
// subdomains must be globally unique, the subdomain is used directly.
func (r Route) ClusterName() string {
	return r.Subdomain
}
