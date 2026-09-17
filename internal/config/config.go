// Package config loads and validates the control plane's configuration from
// environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// BaseDomain is the parent domain routes are built under, e.g.
	// "nas.pfrem.me" turns a "myapp" subdomain into "myapp.nas.pfrem.me".
	BaseDomain string

	// HTTPPort is the Envoy listener port that redirects to HTTPS.
	HTTPPort uint32
	// HTTPSPort is the Envoy listener port that serves routed traffic.
	HTTPSPort uint32
	// XDSPort is the port this control plane's ADS gRPC server listens on.
	XDSPort uint32

	// DockerNetwork is the default docker network name used to resolve a
	// matched container's IP address, unless overridden per-router via the
	// "network" label.
	DockerNetwork string

	// CertSecretName is the SDS secret name referenced by the generated
	// HTTPS listener's TLS context. Must match a secret envoy-acme serves.
	CertSecretName string
	// ACMESDSClusterName is the name of the static Envoy cluster (defined in
	// the Envoy bootstrap, not by this control plane) used to reach
	// envoy-acme for SDS.
	ACMESDSClusterName string

	// StaticConfigPath, if set, points at a YAML file of non-Docker routers
	// to merge into the routing table.
	StaticConfigPath string

	// DockerHost, if set, overrides the Docker client's default connection
	// target (e.g. a non-default socket path).
	DockerHost string

	// ResyncInterval is how often the docker watcher does a full resync of
	// container state, in addition to reacting to docker events.
	ResyncInterval time.Duration

	// InfoEndpointEnabled turns on a read-only HTML page showing the
	// current discovered/configured routes. Off by default.
	InfoEndpointEnabled bool
	// InfoPort is the port the info page listens on, when enabled.
	InfoPort uint32

	// TCPEntrypoints maps a statically configured TCP entrypoint name to
	// the port its listener binds, from the TCP_ENTRYPOINTS environment
	// variable (format "name=port,name2=port2"). Entrypoint addresses/
	// ports are daemon (operator) configuration: a container label can
	// only select among these names via envoy.tcp.routers.<r>.entrypoints,
	// never bind a new host socket of its own.
	TCPEntrypoints map[string]uint32
	// DefaultTCPEntrypoint is the entrypoint name a TCP router with no
	// explicit .entrypoints label is served on, from the
	// TCP_DEFAULT_ENTRYPOINT environment variable. Empty means a TCP
	// router must set .entrypoints explicitly (no implicit default).
	DefaultTCPEntrypoint string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPPort:           80,
		HTTPSPort:          443,
		XDSPort:            18000,
		CertSecretName:     "wildcard-cert",
		ACMESDSClusterName: "acme_sds_cluster",
		ResyncInterval:     30 * time.Second,
		InfoPort:           9902,
	}

	cfg.BaseDomain = os.Getenv("BASE_DOMAIN")
	if cfg.BaseDomain == "" {
		return Config{}, fmt.Errorf("BASE_DOMAIN is required")
	}

	var err error
	if cfg.HTTPPort, err = envPort("HTTP_PORT", cfg.HTTPPort); err != nil {
		return Config{}, err
	}
	if cfg.HTTPSPort, err = envPort("HTTPS_PORT", cfg.HTTPSPort); err != nil {
		return Config{}, err
	}
	if cfg.XDSPort, err = envPort("XDS_PORT", cfg.XDSPort); err != nil {
		return Config{}, err
	}

	cfg.DockerNetwork = os.Getenv("DOCKER_NETWORK")

	if v := os.Getenv("CERT_SECRET_NAME"); v != "" {
		cfg.CertSecretName = v
	}
	if v := os.Getenv("ACME_SDS_CLUSTER_NAME"); v != "" {
		cfg.ACMESDSClusterName = v
	}

	cfg.StaticConfigPath = os.Getenv("STATIC_CONFIG_PATH")
	cfg.DockerHost = os.Getenv("DOCKER_HOST")

	if v := os.Getenv("RESYNC_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("RESYNC_INTERVAL: %w", err)
		}
		cfg.ResyncInterval = d
	}

	if v := os.Getenv("INFO_ENDPOINT_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("INFO_ENDPOINT_ENABLED: invalid bool %q: %w", v, err)
		}
		cfg.InfoEndpointEnabled = b
	}
	if cfg.InfoPort, err = envPort("INFO_PORT", cfg.InfoPort); err != nil {
		return Config{}, err
	}

	cfg.TCPEntrypoints, err = parseTCPEntrypoints(os.Getenv("TCP_ENTRYPOINTS"))
	if err != nil {
		return Config{}, err
	}
	cfg.DefaultTCPEntrypoint = os.Getenv("TCP_DEFAULT_ENTRYPOINT")
	if cfg.DefaultTCPEntrypoint != "" {
		if _, ok := cfg.TCPEntrypoints[cfg.DefaultTCPEntrypoint]; !ok {
			return Config{}, fmt.Errorf("TCP_DEFAULT_ENTRYPOINT %q is not one of the configured TCP_ENTRYPOINTS", cfg.DefaultTCPEntrypoint)
		}
	}

	return cfg, nil
}

// parseTCPEntrypoints parses the TCP_ENTRYPOINTS environment variable
// ("name=port,name2=port2") into a name -> port map. An empty string
// returns an empty (non-nil) map: TCP is simply unconfigured.
func parseTCPEntrypoints(v string) (map[string]uint32, error) {
	out := map[string]uint32{}
	if v == "" {
		return out, nil
	}
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, portStr, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		portStr = strings.TrimSpace(portStr)
		if !ok || name == "" || portStr == "" {
			return nil, fmt.Errorf("TCP_ENTRYPOINTS entry %q must be name=port", entry)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("TCP_ENTRYPOINTS entry %q: invalid port %q", entry, portStr)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("TCP_ENTRYPOINTS defines entrypoint %q more than once", name)
		}
		out[name] = uint32(port)
	}
	return out, nil
}

func envPort(name string, def uint32) (uint32, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid port %q: %w", name, v, err)
	}
	return uint32(n), nil
}
