package model

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type UpstreamProtocol string

const (
	ProtocolHTTP1 UpstreamProtocol = "http1"
	ProtocolHTTP2 UpstreamProtocol = "http2"
	ProtocolGRPC  UpstreamProtocol = "grpc"
	ProtocolHTTPS UpstreamProtocol = "https"
)

type WeightedService struct {
	Name   string
	Weight uint32
}

type HealthCheck struct {
	Path               string
	Interval           time.Duration
	Timeout            time.Duration
	UnhealthyThreshold uint32
	HealthyThreshold   uint32
}

type OutlierDetection struct {
	Consecutive5xx     uint32
	Interval           time.Duration
	BaseEjectionTime   time.Duration
	MaxEjectionPercent *uint32
}

type StickyCookie struct {
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string
	TTL      time.Duration
}

type HTTPService struct {
	Name             string
	Endpoints        []Endpoint
	Weighted         []WeightedService
	Protocol         UpstreamProtocol
	HealthCheck      *HealthCheck
	Outlier          *OutlierDetection
	Sticky           *StickyCookie
	Origin           string
	DiscoveryNetwork string
}

func (s HTTPService) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("service name is empty")
	}
	if len(s.Endpoints) > 0 && len(s.Weighted) > 0 {
		return fmt.Errorf("service %q cannot define both loadbalancer servers and weighted services", s.Name)
	}
	if len(s.Weighted) > 0 && (s.Protocol != "" || s.HealthCheck != nil || s.Outlier != nil || s.Sticky != nil) {
		return fmt.Errorf("weighted service %q cannot define leaf loadbalancer protocol, healthcheck, outlier, or sticky policy", s.Name)
	}
	if len(s.Endpoints) == 0 && len(s.Weighted) == 0 {
		return fmt.Errorf("service %q has no servers or weighted services", s.Name)
	}
	if s.Protocol == "" {
		s.Protocol = ProtocolHTTP1
	}
	switch s.Protocol {
	case ProtocolHTTP1, ProtocolHTTP2, ProtocolGRPC, ProtocolHTTPS:
	default:
		return fmt.Errorf("service %q has invalid protocol %q (want http1, http2, grpc, or https)", s.Name, s.Protocol)
	}
	if s.Protocol == ProtocolGRPC && s.Sticky != nil {
		return fmt.Errorf("service %q: sticky cookies are incompatible with grpc", s.Name)
	}
	for _, ep := range s.Endpoints {
		if ep.Address == "" || ep.Port == 0 {
			return fmt.Errorf("service %q has invalid endpoint %q:%d", s.Name, ep.Address, ep.Port)
		}
	}
	for _, w := range s.Weighted {
		if w.Name == "" || w.Weight == 0 {
			return fmt.Errorf("service %q has invalid weighted target %q with weight %d", s.Name, w.Name, w.Weight)
		}
	}
	if h := s.HealthCheck; h != nil {
		if !strings.HasPrefix(h.Path, "/") {
			return fmt.Errorf("service %q healthcheck path must start with /", s.Name)
		}
		if h.Interval <= 0 || h.Timeout <= 0 || h.UnhealthyThreshold == 0 || h.HealthyThreshold == 0 {
			return fmt.Errorf("service %q healthcheck interval, timeout, and thresholds must be positive", s.Name)
		}
	}
	if o := s.Outlier; o != nil {
		if o.MaxEjectionPercent != nil && *o.MaxEjectionPercent > 100 {
			return fmt.Errorf("service %q outlier maxejectionpercent must be 0-100", s.Name)
		}
	}
	if c := s.Sticky; c != nil {
		if c.Name == "" {
			return fmt.Errorf("service %q sticky cookie name is required", s.Name)
		}
		switch strings.ToLower(c.SameSite) {
		case "", "lax", "strict", "none":
		default:
			return fmt.Errorf("service %q sticky cookie samesite must be lax, strict, or none", s.Name)
		}
		if strings.EqualFold(c.SameSite, "none") && !c.Secure {
			return fmt.Errorf("service %q sticky cookie samesite=none requires secure=true", s.Name)
		}
		if c.TTL < 0 {
			return fmt.Errorf("service %q sticky cookie ttl cannot be negative", s.Name)
		}
	}
	return nil
}

type RetryPolicy struct {
	Attempts      uint32
	PerTryTimeout time.Duration
	RetryOn       string
}

type HTTPConfiguration struct {
	Routes      map[string]Route
	Services    map[string]HTTPService
	Middlewares map[string]Middleware
}

type ResolvedService struct {
	Name   string
	Weight uint32
}

func (c HTTPConfiguration) ResolveService(name string) ([]ResolvedService, error) {
	weights := map[string]uint64{}
	stack := map[string]bool{}
	var walk func(string, uint64) error
	walk = func(current string, multiplier uint64) error {
		s, ok := c.Services[current]
		if !ok {
			return fmt.Errorf("service %q references unknown service %q", name, current)
		}
		if stack[current] {
			return fmt.Errorf("weighted service cycle detected at %q while resolving %q", current, name)
		}
		if err := s.Validate(); err != nil {
			return err
		}
		if len(s.Weighted) == 0 {
			if math.MaxUint64-weights[current] < multiplier {
				return fmt.Errorf("service %q resolved weight overflows uint64", name)
			}
			weights[current] += multiplier
			return nil
		}
		stack[current] = true
		defer delete(stack, current)
		for _, child := range s.Weighted {
			if multiplier > math.MaxUint64/uint64(child.Weight) {
				return fmt.Errorf("service %q resolved weight overflows uint64", name)
			}
			if err := walk(child.Name, multiplier*uint64(child.Weight)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(name, 1); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(weights))
	for n := range weights {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]ResolvedService, 0, len(names))
	root := c.Services[name]
	var total uint64
	for _, n := range names {
		if math.MaxUint64-total < weights[n] {
			return nil, fmt.Errorf("service %q total resolved weight overflows uint64", name)
		}
		total += weights[n]
	}
	if total > math.MaxUint32 {
		return nil, fmt.Errorf("service %q total resolved weight exceeds uint32", name)
	}
	for _, n := range names {
		if len(root.Weighted) > 0 && c.Services[n].Sticky != nil {
			return nil, fmt.Errorf("weighted service %q cannot include sticky service %q", name, n)
		}
		if weights[n] > uint64(^uint32(0)) {
			return nil, fmt.Errorf("service %q resolved weight overflows uint32", name)
		}
		out = append(out, ResolvedService{Name: n, Weight: uint32(weights[n])})
	}
	return out, nil
}

func NamedServiceClusterName(name string) string { return "http-service/" + name }
