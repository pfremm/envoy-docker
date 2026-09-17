package model

// Configuration is the full docker-discovered routing table: HTTP routers/
// services/middlewares plus TCP routers/services. The two are independent
// label namespaces (envoy.http.* vs envoy.tcp.*) discovered from the same
// container scan and carried together so one watcher update publishes both.
type Configuration struct {
	HTTP HTTPConfiguration
	TCP  TCPConfiguration
}
