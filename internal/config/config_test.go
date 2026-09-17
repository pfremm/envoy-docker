package config

import (
	"os"
	"strings"
	"testing"
)

func withEnv(t *testing.T, values map[string]string, fn func()) {
	t.Helper()
	old := map[string]string{}
	for k, v := range values {
		old[k] = os.Getenv(k)
		_ = os.Setenv(k, v)
		t.Cleanup(func() { _ = os.Setenv(k, old[k]) })
	}
	fn()
}

func TestLoadHTTPDefaultEntrypointList(t *testing.T) {
	withEnv(t, map[string]string{"BASE_DOMAIN": "example.com", "HTTP_ENTRYPOINTS": "public=8443,internal=9443", "HTTP_DEFAULT_ENTRYPOINTS": "public, internal"}, func() {
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(cfg.DefaultHTTPEntrypoints, ",") != "public,internal" {
			t.Fatalf("defaults=%v", cfg.DefaultHTTPEntrypoints)
		}
	})
}

func TestLoadRejectsSharedHTTPAndTCPEntrypointPort(t *testing.T) {
	withEnv(t, map[string]string{"BASE_DOMAIN": "example.com", "HTTP_ENTRYPOINTS": "public=8443", "TCP_ENTRYPOINTS": "db=8443"}, func() {
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "collides") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestLoadRejectsDefaultHTTPHTTPSPortCollision(t *testing.T) {
	withEnv(t, map[string]string{"BASE_DOMAIN": "example.com", "HTTP_PORT": "8443", "HTTPS_PORT": "8443"}, func() {
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "default HTTP and HTTPS") {
			t.Fatalf("err=%v", err)
		}
	})
}
