package staticconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_EmptyPath(t *testing.T) {
	routes, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") unexpected error: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("Load(\"\") = %+v, want empty map", routes)
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

	routes, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "static-routes.yaml")
			if err := os.WriteFile(path, []byte(tt.contents), 0o644); err != nil {
				t.Fatalf("writing test file: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Error("Load() expected error, got nil")
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/static-routes.yaml"); err == nil {
		t.Error("Load() expected error for missing file, got nil")
	}
}
