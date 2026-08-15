package dockerwatch

import (
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

func TestParseRouters(t *testing.T) {
	tests := []struct {
		name    string
		labels  map[string]string
		want    map[string]parsedRouter
		wantErr bool
	}{
		{
			name: "single valid router",
			labels: map[string]string{
				"envoy.enable":                     "true",
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "8080",
			},
			want: map[string]parsedRouter{
				"web": {subdomain: "myapp", port: 8080},
			},
		},
		{
			name: "router with network override",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "8080",
				"envoy.http.routers.web.network":   "proxy-net",
			},
			want: map[string]parsedRouter{
				"web": {subdomain: "myapp", port: 8080, network: "proxy-net"},
			},
		},
		{
			name: "multiple routers on one container",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain":   "myapp",
				"envoy.http.routers.web.port":        "8080",
				"envoy.http.routers.admin.subdomain": "myapp-admin",
				"envoy.http.routers.admin.port":      "9090",
			},
			want: map[string]parsedRouter{
				"web":   {subdomain: "myapp", port: 8080},
				"admin": {subdomain: "myapp-admin", port: 9090},
			},
		},
		{
			name: "missing subdomain",
			labels: map[string]string{
				"envoy.http.routers.web.port": "8080",
			},
			wantErr: true,
		},
		{
			name: "missing port",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain": "myapp",
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "not-a-port",
			},
			wantErr: true,
		},
		{
			name:   "no router labels",
			labels: map[string]string{"envoy.enable": "true"},
			want:   map[string]parsedRouter{},
		},
		{
			name: "unrelated labels are ignored",
			labels: map[string]string{
				"com.docker.compose.project":       "stack",
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "8080",
				"envoy.http.routers.web.unknown":   "ignored",
			},
			want: map[string]parsedRouter{
				"web": {subdomain: "myapp", port: 8080},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRouters(tt.labels)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRouters() expected error, got nil (result: %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRouters() unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseRouters() = %+v, want %+v", got, tt.want)
			}
			for name, wantRouter := range tt.want {
				gotRouter, ok := got[name]
				if !ok {
					t.Fatalf("parseRouters() missing router %q, got %+v", name, got)
				}
				if gotRouter != wantRouter {
					t.Fatalf("parseRouters()[%q] = %+v, want %+v", name, gotRouter, wantRouter)
				}
			}
		})
	}
}

func TestContainerName(t *testing.T) {
	c := container.Summary{Names: []string{"/myapp-1"}}
	if got := containerName(c); got != "myapp-1" {
		t.Errorf("containerName() = %q, want %q", got, "myapp-1")
	}

	c = container.Summary{ID: "abcdef0123456789"}
	if got := containerName(c); got != "abcdef012345" {
		t.Errorf("containerName() = %q, want %q", got, "abcdef012345")
	}
}

func TestContainerIP(t *testing.T) {
	c := container.Summary{
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				"proxy-net": {IPAddress: "172.20.0.5"},
			},
		},
	}

	addr, err := containerIP(c, "proxy-net")
	if err != nil {
		t.Fatalf("containerIP() unexpected error: %v", err)
	}
	if addr != "172.20.0.5" {
		t.Errorf("containerIP() = %q, want %q", addr, "172.20.0.5")
	}

	if _, err := containerIP(c, "other-net"); err == nil {
		t.Error("containerIP() expected error for network the container isn't attached to")
	}

	noNetworks := container.Summary{}
	if _, err := containerIP(noNetworks, "proxy-net"); err == nil {
		t.Error("containerIP() expected error when NetworkSettings is nil")
	}
}
