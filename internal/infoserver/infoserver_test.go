package infoserver

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandler_NoViewYet(t *testing.T) {
	s := New()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No routes discovered or configured yet.") {
		t.Errorf("expected empty-state message, got:\n%s", body)
	}
}

func TestHandler_RendersRoutes(t *testing.T) {
	s := New()
	s.Update(View{
		Settings: Settings{
			BaseDomain:         "nas.pfrem.me",
			HTTPPort:           80,
			HTTPSPort:          443,
			XDSPort:            18000,
			DockerNetwork:      "proxy",
			CertSecretName:     "wildcard-cert",
			ACMESDSClusterName: "acme_sds_cluster",
		},
		Routes: []Route{
			{
				Subdomain: "myapp",
				Host:      "myapp.nas.pfrem.me",
				Source:    "docker",
				Endpoints: []string{"172.20.0.5:8080"},
				Origin:    "myapp-1/web",
			},
		},
		Version:   "3",
		UpdatedAt: time.Now(),
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"myapp.nas.pfrem.me", "172.20.0.5:8080", "badge-docker", "nas.pfrem.me"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected body to contain %q, got:\n%s", want, body)
		}
	}
}

func TestHandler_EscapesUntrustedLabelValues(t *testing.T) {
	s := New()
	s.Update(View{
		Routes: []Route{
			{
				Subdomain: "myapp",
				Host:      "myapp.nas.pfrem.me",
				Source:    "docker",
				Origin:    `<script>alert(1)</script>`,
			},
		},
	})

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("expected origin to be HTML-escaped, got raw script tag in body:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected escaped script tag, got:\n%s", body)
	}
}

func TestHandler_NotFoundForOtherPaths(t *testing.T) {
	s := New()
	req := httptest.NewRequest("GET", "/other", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
