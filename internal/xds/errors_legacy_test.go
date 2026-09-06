package xds

import (
	"testing"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func TestBuildSnapshot_ErrorsLegacyPathResolvesBySubdomain(t *testing.T) {
	routes := map[string]model.Route{
		"app": {Subdomain: "app", RouterName: "web", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Middlewares: []model.Middleware{{Name: "err", Errors: &model.ErrorsMiddleware{Status: []string{"500"}, Service: "errpage"}}}},
		"errpage": {Subdomain: "errpage", RouterName: "errpage", Endpoints: []model.Endpoint{{Address: "10.0.0.9", Port: 9999}}},
	}
	snap, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	var found bool
	for _, vh := range rc.VirtualHosts {
		for _, d := range vh.Domains {
			if d == errorPageHost("errpage") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected synthetic error page vhost in legacy path")
	}
}
