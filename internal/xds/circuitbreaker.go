package xds

import (
	"fmt"
	"sort"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// circuitBreakerKey is a canonical, comparable identity for a circuit
// breaker policy. Two middlewares with the same four thresholds produce the
// same key, which is how identical policies are deduplicated into one
// cluster variant instead of one per middleware/route.
type circuitBreakerKey struct {
	maxConnections, maxPendingRequests, maxRequests, maxRetries uint32
}

func circuitBreakerKeyFor(cb *model.CircuitBreakerMiddleware) circuitBreakerKey {
	if cb == nil {
		return circuitBreakerKey{}
	}
	return circuitBreakerKey{cb.MaxConnections, cb.MaxPendingRequests, cb.MaxRequests, cb.MaxRetries}
}

// variantSuffix renders a circuit breaker policy into a deterministic,
// Envoy-cluster-name-safe suffix so the same policy always produces the same
// variant cluster name regardless of which middleware/route requested it.
func (k circuitBreakerKey) variantSuffix() string {
	return fmt.Sprintf("cb-c%d-p%d-r%d-t%d", k.maxConnections, k.maxPendingRequests, k.maxRequests, k.maxRetries)
}

// applyCircuitBreakerThresholds sets a cluster's CircuitBreakers from a
// middleware policy. A nil policy is a no-op (the cluster keeps Envoy's
// built-in defaults).
func applyCircuitBreakerThresholds(c *clusterv3.Cluster, cb *model.CircuitBreakerMiddleware) {
	if cb == nil {
		return
	}
	th := &clusterv3.CircuitBreakers_Thresholds{}
	if cb.MaxConnections > 0 {
		th.MaxConnections = wrapperspb.UInt32(cb.MaxConnections)
	}
	if cb.MaxPendingRequests > 0 {
		th.MaxPendingRequests = wrapperspb.UInt32(cb.MaxPendingRequests)
	}
	if cb.MaxRequests > 0 {
		th.MaxRequests = wrapperspb.UInt32(cb.MaxRequests)
	}
	if cb.MaxRetries > 0 {
		th.MaxRetries = wrapperspb.UInt32(cb.MaxRetries)
	}
	c.CircuitBreakers = &clusterv3.CircuitBreakers{Thresholds: []*clusterv3.CircuitBreakers_Thresholds{th}}
}

// circuitBreakerRef identifies one route's circuit-breaker policy request
// against a specific base (named-service) cluster. routeKey is the xDS route
// resource name (routeResourceName) used later to redirect that route's
// RouteAction to the derived variant cluster, if one is created.
type circuitBreakerRef struct {
	routeKey    string
	baseCluster string
	policy      *model.CircuitBreakerMiddleware
}

// planCircuitBreakerVariants groups circuit-breaker requests by base
// (named-service) cluster. Because Envoy circuit breakers are cluster-scoped
// but this control plane's circuitbreaker middleware is per-route, routes
// that share one named-service cluster with different policies cannot all be
// satisfied by that one cluster: this function derives one deterministic,
// deduplicated variant cluster per distinct non-nil policy sharing a base
// cluster, and returns which routes must be redirected to which variant.
//
// Routes that share a base cluster and request the SAME policy collapse onto
// one variant (dedup). If every CB-bearing route sharing a base cluster asks
// for the identical policy, that policy is applied directly to the base
// cluster and no variant is created.
func planCircuitBreakerVariants(refs []circuitBreakerRef, baseClusters map[string]*clusterv3.Cluster, baseEndpoints map[string]*endpointv3.ClusterLoadAssignment) (variantClusters []*clusterv3.Cluster, variantEndpoints []*endpointv3.ClusterLoadAssignment, routeOverride map[string]string, err error) {
	byBase := map[string][]circuitBreakerRef{}
	for _, r := range refs {
		byBase[r.baseCluster] = append(byBase[r.baseCluster], r)
	}
	routeOverride = map[string]string{}

	baseNames := make([]string, 0, len(byBase))
	for name := range byBase {
		baseNames = append(baseNames, name)
	}
	sort.Strings(baseNames)

	for _, baseName := range baseNames {
		base, ok := baseClusters[baseName]
		if !ok {
			return nil, nil, nil, fmt.Errorf("circuitbreaker: internal error: no base cluster found for %q", baseName)
		}
		byPolicy := map[circuitBreakerKey][]circuitBreakerRef{}
		policyKeys := make([]circuitBreakerKey, 0, 2)
		for _, r := range byBase[baseName] {
			key := circuitBreakerKeyFor(r.policy)
			if _, seen := byPolicy[key]; !seen {
				policyKeys = append(policyKeys, key)
			}
			byPolicy[key] = append(byPolicy[key], r)
		}
		if len(byPolicy) == 1 {
			// Every CB-bearing route sharing this cluster asked for the
			// identical policy: apply it directly, no variant needed.
			applyCircuitBreakerThresholds(base, byPolicy[policyKeys[0]][0].policy)
			continue
		}
		// Policies differ: leave the base cluster with Envoy's default
		// (unmodified) circuit breaker, and give each distinct policy its
		// own deterministic, deduplicated variant.
		sort.Slice(policyKeys, func(i, j int) bool { return policyKeys[i].variantSuffix() < policyKeys[j].variantSuffix() })
		for _, key := range policyKeys {
			group := byPolicy[key]
			variantName := baseName + "~" + key.variantSuffix()
			variantCluster := proto.Clone(base).(*clusterv3.Cluster)
			variantCluster.Name = variantName
			applyCircuitBreakerThresholds(variantCluster, group[0].policy)
			variantClusters = append(variantClusters, variantCluster)

			if baseCLA, ok := baseEndpoints[baseName]; ok {
				variantCLA := proto.Clone(baseCLA).(*endpointv3.ClusterLoadAssignment)
				variantCLA.ClusterName = variantName
				variantEndpoints = append(variantEndpoints, variantCLA)
			}
			for _, r := range group {
				routeOverride[r.routeKey] = variantName
			}
		}
	}
	return variantClusters, variantEndpoints, routeOverride, nil
}
