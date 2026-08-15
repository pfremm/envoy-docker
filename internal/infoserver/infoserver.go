// Package infoserver serves an optional, read-only HTML page showing the
// control plane's current settings and discovered/configured routes.
package infoserver

import (
	"html/template"
	"net/http"
	"sync/atomic"
	"time"
)

// Settings mirrors the subset of config.Config worth showing on the page.
type Settings struct {
	BaseDomain         string
	HTTPPort           uint32
	HTTPSPort          uint32
	XDSPort            uint32
	DockerNetwork      string
	CertSecretName     string
	ACMESDSClusterName string
	StaticConfigPath   string
}

// Route is one row of the rendered routing table.
type Route struct {
	Subdomain string
	Host      string
	Source    string
	Endpoints []string
	Origin    string
}

// View is the full snapshot of state the page renders. It's replaced
// wholesale on every update, so rendering never observes a partial update.
type View struct {
	Settings  Settings
	Routes    []Route
	Version   string
	UpdatedAt time.Time
}

// Server holds the latest View and serves it as HTML. The zero value (via
// New) is ready to use; Update and the HTTP handler are safe to call
// concurrently.
type Server struct {
	view atomic.Pointer[View]
}

func New() *Server {
	return &Server{}
}

// Update publishes a new View for subsequent requests to render.
func (s *Server) Update(v View) {
	s.view.Store(&v)
}

// Handler returns the http.Handler serving the info page at "/".
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	var view View
	if v := s.view.Load(); v != nil {
		view = *v
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var pageTemplate = template.Must(template.New("index").Parse(pageHTML))

const pageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="15">
<title>envoy-control-plane</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         margin: 2rem auto; max-width: 960px; padding: 0 1rem; line-height: 1.4; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
  h2 { font-size: 1.1rem; margin-top: 2rem; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1.5rem; margin-top: 1rem; }
  dt { opacity: 0.65; }
  dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  table { border-collapse: collapse; width: 100%; margin-top: 0.75rem; }
  th, td { text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid rgba(128,128,128,0.3); vertical-align: top; }
  th { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.02em; opacity: 0.65; }
  td code, dd code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
  .badge { display: inline-block; padding: 0.1rem 0.55rem; border-radius: 1rem; font-size: 0.75rem; font-weight: 600; }
  .badge-docker { background: rgba(37,99,235,0.15); color: #2563eb; }
  .badge-static { background: rgba(124,58,237,0.15); color: #7c3aed; }
  .empty { opacity: 0.6; font-style: italic; }
  a { color: inherit; }
</style>
</head>
<body>
<h1>envoy-control-plane</h1>
<p class="empty">Auto-refreshes every 15s. Read-only.</p>

<dl>
  <dt>Base domain</dt><dd>{{.Settings.BaseDomain}}</dd>
  <dt>HTTP port (redirects)</dt><dd>{{.Settings.HTTPPort}}</dd>
  <dt>HTTPS port</dt><dd>{{.Settings.HTTPSPort}}</dd>
  <dt>ADS (xDS) port</dt><dd>{{.Settings.XDSPort}}</dd>
  <dt>Docker network</dt><dd>{{if .Settings.DockerNetwork}}{{.Settings.DockerNetwork}}{{else}}<span class="empty">none (per-router only)</span>{{end}}</dd>
  <dt>Cert secret name</dt><dd>{{.Settings.CertSecretName}}</dd>
  <dt>ACME SDS cluster name</dt><dd>{{.Settings.ACMESDSClusterName}}</dd>
  <dt>Static config path</dt><dd>{{if .Settings.StaticConfigPath}}{{.Settings.StaticConfigPath}}{{else}}<span class="empty">none</span>{{end}}</dd>
  <dt>Snapshot version</dt><dd>{{if .Version}}{{.Version}}{{else}}<span class="empty">none published yet</span>{{end}}</dd>
  <dt>Last updated</dt><dd>{{if not .UpdatedAt.IsZero}}{{.UpdatedAt.Format "2006-01-02T15:04:05Z07:00"}}{{else}}<span class="empty">never</span>{{end}}</dd>
</dl>

<h2>Routes ({{len .Routes}})</h2>
{{if .Routes}}
<table>
  <tr><th>Subdomain</th><th>Host</th><th>Source</th><th>Endpoints</th><th>Origin</th></tr>
  {{range .Routes}}
  <tr>
    <td>{{.Subdomain}}</td>
    <td><a href="https://{{.Host}}">{{.Host}}</a></td>
    <td><span class="badge badge-{{.Source}}">{{.Source}}</span></td>
    <td>{{range .Endpoints}}<code>{{.}}</code><br>{{end}}</td>
    <td>{{.Origin}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">No routes discovered or configured yet.</p>
{{end}}
</body>
</html>
`
