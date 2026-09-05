package model

import (
	"testing"
	"time"
)

func TestHTTPConfigurationResolveServiceFlattensWeights(t *testing.T) {
	cfg := HTTPConfiguration{Services: map[string]HTTPService{
		"blue":   {Name: "blue", Endpoints: []Endpoint{{Address: "10.0.0.1", Port: 8080}}},
		"green":  {Name: "green", Endpoints: []Endpoint{{Address: "10.0.0.2", Port: 8080}}},
		"canary": {Name: "canary", Weighted: []WeightedService{{Name: "blue", Weight: 9}, {Name: "green", Weight: 1}}},
	}}
	got, err := cfg.ResolveService("canary")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "blue" || got[0].Weight != 9 || got[1].Name != "green" || got[1].Weight != 1 {
		t.Fatalf("ResolveService() = %+v", got)
	}
}

func TestHTTPConfigurationResolveServiceDetectsCycles(t *testing.T) {
	cfg := HTTPConfiguration{Services: map[string]HTTPService{
		"a": {Name: "a", Weighted: []WeightedService{{Name: "b", Weight: 1}}},
		"b": {Name: "b", Weighted: []WeightedService{{Name: "a", Weight: 1}}},
	}}
	if _, err := cfg.ResolveService("a"); err == nil {
		t.Fatal("expected a cycle error")
	}
}

func TestHTTPConfigurationResolveServiceRejectsTotalWeightOverflow(t *testing.T) {
	cfg := HTTPConfiguration{Services: map[string]HTTPService{
		"a":   {Name: "a", Endpoints: []Endpoint{{Address: "10.0.0.1", Port: 8080}}},
		"b":   {Name: "b", Endpoints: []Endpoint{{Address: "10.0.0.2", Port: 8080}}},
		"all": {Name: "all", Weighted: []WeightedService{{Name: "a", Weight: ^uint32(0)}, {Name: "b", Weight: 1}}},
	}}
	if _, err := cfg.ResolveService("all"); err == nil {
		t.Fatal("expected total weight overflow error")
	}
}

func TestHTTPServiceValidation(t *testing.T) {
	valid := HTTPService{Name: "api", Endpoints: []Endpoint{{Address: "10.0.0.1", Port: 8443}}, Protocol: ProtocolHTTPS,
		HealthCheck: &HealthCheck{Path: "/health", Interval: 10 * time.Second, Timeout: 2 * time.Second, UnhealthyThreshold: 3, HealthyThreshold: 2},
		Sticky:      &StickyCookie{Name: "affinity", Secure: true, HTTPOnly: true, SameSite: "lax", TTL: time.Hour},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid service: %v", err)
	}
	bad := valid
	bad.Protocol = ProtocolGRPC
	if err := bad.Validate(); err == nil {
		t.Fatal("expected grpc + sticky to be rejected")
	}
}
