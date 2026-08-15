package xds

import (
	"context"
	"log/slog"
	"net"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// constantNodeID is the single node-hash key every connecting Envoy is
// grouped under, regardless of the node.id it reports. There is only ever
// one snapshot in this control plane, so every Envoy replica gets the same
// config without any per-node bookkeeping.
const constantNodeID = "envoy"

type constantHash struct{}

func (constantHash) ID(*corev3.Node) string { return constantNodeID }

// Server wraps the go-control-plane ADS implementation with a gRPC server
// and a snapshot cache keyed by a single constant node ID.
type Server struct {
	cache cachev3.SnapshotCache
	grpc  *grpc.Server
}

func NewServer(logger *slog.Logger) *Server {
	cache := cachev3.NewSnapshotCache(false, constantHash{}, nil)
	adsServer := serverv3.NewServer(context.Background(), cache, nil)

	grpcServer := grpc.NewServer()
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, adsServer)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, adsServer)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, adsServer)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, adsServer)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, adsServer)

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	return &Server{cache: cache, grpc: grpcServer}
}

// SetSnapshot publishes a new snapshot to every connected Envoy.
func (s *Server) SetSnapshot(ctx context.Context, snap cachev3.ResourceSnapshot) error {
	return s.cache.SetSnapshot(ctx, constantNodeID, snap)
}

// Serve blocks, serving ADS on ln until the server is stopped.
func (s *Server) Serve(ln net.Listener) error {
	return s.grpc.Serve(ln)
}

// GracefulStop stops accepting new streams and waits for existing ones to
// finish.
func (s *Server) GracefulStop() {
	s.grpc.GracefulStop()
}
