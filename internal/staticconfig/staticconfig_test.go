package staticconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_EmptyPath(t *testing.T) {
	routes, rejected, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") unexpected error: %v", err)
	}
	if len(routes) != 0 || len(rejected) != 0 {
		t.Errorf("Load(\"\") = %+v, %+v, want empty", routes, rejected)
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "static-routes.yaml")
	contents := `
routers:
  - subdomain: nas
    port: 5000
    addresses: ["192.168.1.10"]
  - subdomain: printer
    port: 631
    addresses: ["192.168.1.11", "192.168.1.12"]
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	routes, rejected, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if len(rejected) != 0 {
		t.Fatalf("Load() rejected %+v, want none", rejected)
	}
	if len(routes) != 2 {
		t.Fatalf("Load() = %d routes, want 2: %+v", len(routes), routes)
	}
	if len(routes["printer"].Endpoints) != 2 {
		t.Errorf("printer route has %d endpoints, want 2", len(routes["printer"].Endpoints))
	}
	if routes["nas"].Endpoints[0].Port != 5000 {
		t.Errorf("nas route port = %d, want 5000", routes["nas"].Endpoints[0].Port)
	}
	// No protocol means plain HTTP: no upstream TLS.
	if routes["nas"].UpstreamTLS != nil {
		t.Errorf("nas route UpstreamTLS = %+v, want nil (http default)", routes["nas"].UpstreamTLS)
	}
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{"missing subdomain", `routers: [{port: 5000, addresses: ["1.2.3.4"]}]`},
		{"missing port", `routers: [{subdomain: nas, addresses: ["1.2.3.4"]}]`},
		{"missing addresses", `routers: [{subdomain: nas, port: 5000}]`},
		{"duplicate subdomain", `routers: [{subdomain: nas, port: 1, addresses: ["1.1.1.1"]}, {subdomain: nas, port: 2, addresses: ["2.2.2.2"]}]`},
		{"yaml syntax error", "routers: [{subdomain: nas"},
		{"wrong port type", `routers: [{subdomain: nas, port: abc, addresses: ["1.2.3.4"]}]`},
		{"router not a mapping", `routers: ["nas"]`},
		// A rejected router still claims its subdomain: the duplicate stays fatal.
		{"duplicate of rejected router", `routers: [{subdomain: nas, port: 1, addresses: ["1.1.1.1"], protocol: ftp}, {subdomain: nas, port: 2, addresses: ["2.2.2.2"]}]`},
		// A fatal error after a per-router rejection is still fatal.
		{"fatal after rejection", `routers: [{subdomain: a, port: 1, addresses: ["1.1.1.1"], protocol: ftp}, {subdomain: b, addresses: ["2.2.2.2"]}]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "static-routes.yaml")
			if err := os.WriteFile(path, []byte(tt.contents), 0o644); err != nil {
				t.Fatalf("writing test file: %v", err)
			}
			if _, _, err := Load(path); err == nil {
				t.Error("Load() expected error, got nil")
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, _, err := Load("/nonexistent/static-routes.yaml"); err == nil {
		t.Error("Load() expected error for missing file, got nil")
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "static-routes.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	return path
}

func TestLoad_UpstreamProtocol(t *testing.T) {
	path := writeConfig(t, `
routers:
  - subdomain: plain
    port: 80
    addresses: ["10.0.0.1"]
    protocol: http
  - subdomain: secure
    port: 443
    addresses: ["10.0.0.2"]
    protocol: https
  - subdomain: emptytls
    port: 443
    addresses: ["10.0.0.3"]
    protocol: https
    tls: {}
  - subdomain: explicit
    port: 443
    addresses: ["10.0.0.4"]
    protocol: https
    tls: {insecure_skip_verify: false}
  - subdomain: truenas
    port: 8443
    addresses: ["10.10.2.42"]
    protocol: https
    tls:
      insecure_skip_verify: true
  - subdomain: upper
    port: 443
    addresses: ["10.0.0.5"]
    protocol: HTTPS
`)
	routes, rejected, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if len(rejected) != 0 {
		t.Fatalf("Load() rejected %+v, want none", rejected)
	}
	if routes["plain"].UpstreamTLS != nil {
		t.Errorf("plain: UpstreamTLS = %+v, want nil", routes["plain"].UpstreamTLS)
	}
	// https without (or with an empty/false) tls block verifies the backend.
	for _, name := range []string{"secure", "emptytls", "explicit", "upper"} {
		if tls := routes[name].UpstreamTLS; tls == nil || tls.InsecureSkipVerify {
			t.Errorf("%s: UpstreamTLS = %+v, want non-nil with InsecureSkipVerify=false", name, tls)
		}
	}
	if tls := routes["truenas"].UpstreamTLS; tls == nil || !tls.InsecureSkipVerify {
		t.Errorf("truenas: UpstreamTLS = %+v, want InsecureSkipVerify=true", tls)
	}
}

// TestLoad_RejectsRouterInIsolation checks that an invalid protocol/tls
// setting rejects only its router: the file still loads and the valid
// router is kept.
func TestLoad_RejectsRouterInIsolation(t *testing.T) {
	tests := []struct {
		name   string
		router string
		reason string
	}{
		{"unsupported protocol", `protocol: ftp`, "unsupported protocol"},
		{"protocol wrong type", `protocol: {a: b}`, "invalid protocol/tls"},
		{"tls on implicit http", `tls: {insecure_skip_verify: true}`, "requires protocol: https"},
		{"tls on explicit http", "protocol: http\n    tls: {}", "requires protocol: https"},
		{"insecure_skip_verify wrong type", "protocol: https\n    tls: {insecure_skip_verify: maybe}", "insecure_skip_verify must be true or false"},
		{"unknown tls key", "protocol: https\n    tls: {insecure: true}", `unknown tls key "insecure"`},
		{"tls not a mapping", "protocol: https\n    tls: true", "tls must be a mapping"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, `
routers:
  - subdomain: good
    port: 80
    addresses: ["10.0.0.1"]
  - subdomain: bad
    port: 443
    addresses: ["10.0.0.2"]
    `+tt.router+`
`)
			routes, rejected, err := Load(path)
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if _, ok := routes["good"]; !ok || len(routes) != 1 {
				t.Errorf("routes = %+v, want only \"good\"", routes)
			}
			if len(rejected) != 1 {
				t.Fatalf("rejected = %+v, want exactly the bad router", rejected)
			}
			r := rejected[0]
			if r.Subdomain != "bad" || r.Origin != path+"[1]" || !strings.Contains(r.Reason, tt.reason) {
				t.Errorf("rejection = %+v, want subdomain bad, origin %s[1], reason containing %q", r, path, tt.reason)
			}
		})
	}
}
