package xds

import (
	"fmt"

	grpcwebv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_web/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// grpcWebHTTPFilter builds the listener-level grpc_web HTTP filter. It has no
// configurable fields.
func grpcWebHTTPFilter() *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{
		Name:       grpcWebFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&grpcwebv3.GrpcWeb{})},
	}
}

// validateGRPCWebUpstream enforces that a route carrying a grpcweb
// middleware forwards to an upstream configured for HTTP/2 (protocol grpc
// or http2): the grpc_web filter translates a browser gRPC-Web request into
// standard gRPC framing, which only round-trips correctly over an HTTP/2
// upstream connection. A legacy route (no named service, implicit HTTP/1.1
// upstream) or a named service using http1/https protocol is rejected with
// an actionable error rather than silently producing broken responses.
func validateGRPCWebUpstream(route model.Route, cfg model.HTTPConfiguration) error {
	if route.ServiceName == "" {
		return fmt.Errorf("router %q: grpcweb middleware requires a named HTTP service with loadbalancer.protocol=grpc or http2 (legacy port-only routes default to an HTTP/1.1 upstream)", route.RouterName)
	}
	svc, ok := cfg.Services[route.ServiceName]
	if !ok {
		return fmt.Errorf("router %q: grpcweb middleware references unresolvable service %q", route.RouterName, route.ServiceName)
	}
	if len(svc.Weighted) > 0 {
		for _, child := range svc.Weighted {
			if err := validateGRPCWebUpstream(model.Route{RouterName: route.RouterName, ServiceName: child.Name}, cfg); err != nil {
				return err
			}
		}
		return nil
	}
	switch svc.Protocol {
	case model.ProtocolGRPC, model.ProtocolHTTP2:
		return nil
	default:
		return fmt.Errorf("router %q: grpcweb middleware requires service %q to use loadbalancer.protocol=grpc or http2, got %q", route.RouterName, route.ServiceName, svc.Protocol)
	}
}
