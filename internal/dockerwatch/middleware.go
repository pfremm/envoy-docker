package dockerwatch

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

const middlewarePrefix = "envoy.http.middlewares."

type middlewareDraft struct {
	name, typ string
	fields    map[string]string
}

func splitEscapedList(key, value string) ([]string, error) {
	var out []string
	var b strings.Builder
	escaped := false
	flush := func() error {
		v := strings.TrimSpace(b.String())
		b.Reset()
		if v == "" {
			return fmt.Errorf("label %s contains an empty list item", key)
		}
		out = append(out, v)
		return nil
	}
	for _, r := range value {
		if escaped {
			switch r {
			case ',', '\\':
				b.WriteRune(r)
			default:
				return nil, fmt.Errorf("label %s uses unsupported escape \\%c (only \\, and \\\\ are accepted)", key, r)
			}
			escaped = false
		} else if r == '\\' {
			escaped = true
		} else if r == ',' {
			if err := flush(); err != nil {
				return nil, err
			}
		} else {
			b.WriteRune(r)
		}
	}
	if escaped {
		return nil, fmt.Errorf("label %s has a dangling backslash escape", key)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func listField(d middlewareDraft, base string) ([]string, error) {
	if raw, ok := d.fields[base]; ok {
		for field := range d.fields {
			if strings.HasPrefix(field, base+".") {
				return nil, fmt.Errorf("middleware %q cannot combine %s with indexed %s.<n> values", d.name, base, base)
			}
		}
		return splitEscapedList(middlewarePrefix+d.name+"."+d.typ+"."+base, raw)
	}
	indexed := map[int]string{}
	for field, value := range d.fields {
		if !strings.HasPrefix(field, base+".") {
			continue
		}
		i, err := strconv.Atoi(strings.TrimPrefix(field, base+"."))
		if err != nil || i < 0 {
			return nil, fmt.Errorf("middleware %q has invalid list index in %s", d.name, field)
		}
		if _, dup := indexed[i]; dup {
			return nil, fmt.Errorf("middleware %q repeats list index %d", d.name, i)
		}
		indexed[i] = value
	}
	idx := make([]int, 0, len(indexed))
	for i := range indexed {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	out := make([]string, 0, len(idx))
	for _, i := range idx {
		items, err := splitEscapedList(fmt.Sprintf("%s%s.%s.%s.%d", middlewarePrefix, d.name, d.typ, base, i), indexed[i])
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func parseMiddlewares(labels map[string]string) (map[string]model.Middleware, map[string]error, error) {
	drafts := map[string]middlewareDraft{}
	bad := map[string]error{}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.HasPrefix(key, middlewarePrefix) {
			continue
		}
		rest := strings.TrimPrefix(key, middlewarePrefix)
		name, rest, ok := strings.Cut(rest, ".")
		if !ok || name == "" {
			return nil, nil, fmt.Errorf("middleware label %q has an empty or missing middleware name", key)
		}
		typ, field, ok := strings.Cut(rest, ".")
		if !ok || typ == "" || field == "" {
			bad[name] = fmt.Errorf("middleware label %q must include type and field", key)
			continue
		}
		d := drafts[name]
		if d.fields == nil {
			d = middlewareDraft{name: name, typ: typ, fields: map[string]string{}}
		}
		if d.typ != typ {
			bad[name] = fmt.Errorf("middleware %q defines multiple types %q and %q", name, d.typ, typ)
		}
		d.fields[field] = labels[key]
		drafts[name] = d
	}
	out := map[string]model.Middleware{}
	names := make([]string, 0, len(drafts))
	for n := range drafts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, exists := bad[name]; exists {
			continue
		}
		d := drafts[name]
		m, err := buildMiddleware(d)
		if err == nil {
			err = m.Validate()
		}
		if err != nil {
			bad[name] = err
			continue
		}
		out[name] = m
	}
	return out, bad, nil
}

func onlyFields(d middlewareDraft, allowed ...string) error {
	for field := range d.fields {
		ok := false
		for _, a := range allowed {
			if field == a || strings.HasPrefix(field, a+".") {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("middleware %q type %s has unknown field %q", d.name, d.typ, field)
		}
	}
	return nil
}
func boolField(d middlewareDraft, name string) (bool, error) {
	if v, ok := d.fields[name]; ok {
		return parseBoolLabel(middlewarePrefix+d.name+"."+d.typ+"."+name, v)
	}
	return false, nil
}
func portField(d middlewareDraft, name string) (uint32, error) {
	if v, ok := d.fields[name]; ok {
		p, err := parseUint32Label(middlewarePrefix+d.name+"."+d.typ+"."+name, v, true)
		if p > 65535 {
			err = fmt.Errorf("middleware %q port is out of range", d.name)
		}
		return p, err
	}
	return 0, nil
}

func buildMiddleware(d middlewareDraft) (model.Middleware, error) {
	m := model.Middleware{Name: d.name}
	scalar := func(name string) string { return d.fields[name] }
	switch d.typ {
	case "redirectscheme":
		if err := onlyFields(d, "scheme", "port", "permanent"); err != nil {
			return m, err
		}
		p, err := portField(d, "port")
		if err != nil {
			return m, err
		}
		permanent, err := boolField(d, "permanent")
		if err != nil {
			return m, err
		}
		m.RedirectScheme = &model.RedirectSchemeMiddleware{Scheme: scalar("scheme"), Port: p, Permanent: permanent}
	case "redirectregex":
		if err := onlyFields(d, "regex", "replacement", "permanent"); err != nil {
			return m, err
		}
		permanent, err := boolField(d, "permanent")
		if err != nil {
			return m, err
		}
		m.RedirectRegex = &model.RedirectRegexMiddleware{Regex: scalar("regex"), Replacement: scalar("replacement"), Permanent: permanent}
	case "stripprefix":
		if err := onlyFields(d, "prefixes"); err != nil {
			return m, err
		}
		values, err := listField(d, "prefixes")
		if err != nil {
			return m, err
		}
		m.StripPrefix = &model.StripPrefixMiddleware{Prefixes: values}
	case "addprefix":
		if err := onlyFields(d, "prefix"); err != nil {
			return m, err
		}
		m.AddPrefix = &model.AddPrefixMiddleware{Prefix: scalar("prefix")}
	case "replacepath":
		if err := onlyFields(d, "path"); err != nil {
			return m, err
		}
		m.ReplacePath = &model.ReplacePathMiddleware{Path: scalar("path")}
	case "replacepathregex":
		if err := onlyFields(d, "regex", "replacement"); err != nil {
			return m, err
		}
		m.ReplacePathRegex = &model.ReplacePathRegexMiddleware{Regex: scalar("regex"), Replacement: scalar("replacement")}
	case "headers":
		h := &model.HeadersMiddleware{Request: map[string]string{}, Response: map[string]string{}}
		for field, value := range d.fields {
			switch {
			case strings.HasPrefix(field, "request."):
				h.Request[strings.ToLower(strings.TrimPrefix(field, "request."))] = value
			case strings.HasPrefix(field, "response."):
				h.Response[strings.ToLower(strings.TrimPrefix(field, "response."))] = value
			}
		}
		hasList := func(base string) bool {
			if _, ok := d.fields[base]; ok {
				return true
			}
			for field := range d.fields {
				if strings.HasPrefix(field, base+".") {
					return true
				}
			}
			return false
		}
		var err error
		if hasList("removerequest") {
			h.RemoveRequest, err = listField(d, "removerequest")
			if err != nil {
				return m, err
			}
			for i := range h.RemoveRequest {
				h.RemoveRequest[i] = strings.ToLower(h.RemoveRequest[i])
			}
		}
		if hasList("removeresponse") {
			h.RemoveResponse, err = listField(d, "removeresponse")
			if err != nil {
				return m, err
			}
			for i := range h.RemoveResponse {
				h.RemoveResponse[i] = strings.ToLower(h.RemoveResponse[i])
			}
		}
		for field := range d.fields {
			if !strings.HasPrefix(field, "request.") && !strings.HasPrefix(field, "response.") && field != "removerequest" && field != "removeresponse" && !strings.HasPrefix(field, "removerequest.") && !strings.HasPrefix(field, "removeresponse.") {
				return m, fmt.Errorf("middleware %q headers has unknown field %q", d.name, field)
			}
		}
		m.Headers = h
	case "cors":
		if err := onlyFields(d, "alloworigins", "allowmethods", "allowheaders", "exposeheaders", "maxage", "allowcredentials"); err != nil {
			return m, err
		}
		c := &model.CORSMiddleware{MaxAge: scalar("maxage")}
		var err error
		for field, dst := range map[string]*[]string{"alloworigins": &c.AllowOrigins, "allowmethods": &c.AllowMethods, "allowheaders": &c.AllowHeaders, "exposeheaders": &c.ExposeHeaders} {
			*dst, err = listField(d, field)
			if err != nil {
				return m, err
			}
		}
		c.AllowCredentials, err = boolField(d, "allowcredentials")
		if err != nil {
			return m, err
		}
		m.CORS = c
	case "basicauth":
		if err := onlyFields(d, "users", "realm", "headerfield", "removeheader"); err != nil {
			return m, err
		}
		users, err := listField(d, "users")
		if err != nil {
			return m, err
		}
		removeHeader, err := boolField(d, "removeheader")
		if err != nil {
			return m, err
		}
		m.BasicAuth = &model.BasicAuthMiddleware{
			Users:        users,
			Realm:        scalar("realm"),
			HeaderField:  scalar("headerfield"),
			RemoveHeader: removeHeader,
		}
	case "forwardauth":
		if err := onlyFields(d, "address", "trustforwardheader", "authrequestheaders",
			"authresponseheaders", "authresponseheaderregex", "tls.insecure", "tls.servername"); err != nil {
			return m, err
		}
		fa := &model.ForwardAuthMiddleware{
			Address:       scalar("address"),
			TLSInsecure:   false,
			TLSServerName: scalar("tls.servername"),
		}
		var err error
		if fa.TrustForwardHeader, err = boolField(d, "trustforwardheader"); err != nil {
			return m, err
		}
		if fa.TLSInsecure, err = boolField(d, "tls.insecure"); err != nil {
			return m, err
		}
		if fa.AuthRequestHeaders, err = listField(d, "authrequestheaders"); err != nil {
			return m, err
		}
		if fa.AuthResponseHeaders, err = listField(d, "authresponseheaders"); err != nil {
			return m, err
		}
		if fa.AuthResponseHeaderRegex, err = listField(d, "authresponseheaderregex"); err != nil {
			return m, err
		}
		m.ForwardAuth = fa
	case "ipallowlist":
		if err := onlyFields(d, "sourcerange", "ipstrategy.depth", "ipstrategy.excludedips"); err != nil {
			return m, err
		}
		allow := &model.IPAllowListMiddleware{}
		var err error
		if allow.SourceRange, err = listField(d, "sourcerange"); err != nil {
			return m, err
		}
		if allow.Strategy.Depth, err = parseUint32Field(d, "ipstrategy.depth"); err != nil {
			return m, err
		}
		if allow.Strategy.ExcludedIPs, err = listField(d, "ipstrategy.excludedips"); err != nil {
			return m, err
		}
		m.IPAllowList = allow
	case "ipdenylist":
		if err := onlyFields(d, "sourcerange", "ipstrategy.depth", "ipstrategy.excludedips"); err != nil {
			return m, err
		}
		deny := &model.IPDenyListMiddleware{}
		var err error
		if deny.SourceRange, err = listField(d, "sourcerange"); err != nil {
			return m, err
		}
		if deny.Strategy.Depth, err = parseUint32Field(d, "ipstrategy.depth"); err != nil {
			return m, err
		}
		if deny.Strategy.ExcludedIPs, err = listField(d, "ipstrategy.excludedips"); err != nil {
			return m, err
		}
		m.IPDenyList = deny
	case "ratelimit":
		if err := onlyFields(d, "average", "burst", "period"); err != nil {
			return m, err
		}
		rl := &model.RateLimitMiddleware{Period: scalar("period")}
		var err error
		if rl.Average, err = parseUint32Field(d, "average"); err != nil {
			return m, err
		}
		if rl.Burst, err = parseUint32Field(d, "burst"); err != nil {
			return m, err
		}
		m.RateLimit = rl
	case "compress":
		if err := onlyFields(d, "minresponsebytes", "contenttypes", "excludedcontenttypes", "disableonetagheader"); err != nil {
			return m, err
		}
		c := &model.CompressMiddleware{}
		var err error
		if c.MinResponseBytes, err = parseUint32Field(d, "minresponsebytes"); err != nil {
			return m, err
		}
		if c.ContentTypes, err = listField(d, "contenttypes"); err != nil {
			return m, err
		}
		if c.ExcludedContentTypes, err = listField(d, "excludedcontenttypes"); err != nil {
			return m, err
		}
		if c.DisableOnETagHeader, err = boolField(d, "disableonetagheader"); err != nil {
			return m, err
		}
		m.Compress = c
	case "retry":
		if err := onlyFields(d, "attempts", "pertrytimeout", "retryon"); err != nil {
			return m, err
		}
		r := &model.RetryMiddleware{
			PerTryTimeout: scalar("pertrytimeout"),
			RetryOn:       scalar("retryon"),
		}
		var err error
		if r.Attempts, err = parseUint32Field(d, "attempts"); err != nil {
			return m, err
		}
		m.Retry = r
	case "circuitbreaker":
		if err := onlyFields(d, "maxconnections", "maxpendingrequests", "maxrequests", "maxretries"); err != nil {
			return m, err
		}
		cb := &model.CircuitBreakerMiddleware{}
		var err error
		if cb.MaxConnections, err = parseUint32Field(d, "maxconnections"); err != nil {
			return m, err
		}
		if cb.MaxPendingRequests, err = parseUint32Field(d, "maxpendingrequests"); err != nil {
			return m, err
		}
		if cb.MaxRequests, err = parseUint32Field(d, "maxrequests"); err != nil {
			return m, err
		}
		if cb.MaxRetries, err = parseUint32Field(d, "maxretries"); err != nil {
			return m, err
		}
		m.CircuitBreaker = cb
	case "buffering":
		if err := onlyFields(d, "maxrequestbytes", "maxresponsebytes", "memrequestbytes", "memresponsebytes", "retryexpression"); err != nil {
			return m, err
		}
		b := &model.BufferingMiddleware{RetryExpression: scalar("retryexpression")}
		var err error
		if b.MaxRequestBytes, err = parseUint32Field(d, "maxrequestbytes"); err != nil {
			return m, err
		}
		if b.MaxResponseBytes, err = parseUint32Field(d, "maxresponsebytes"); err != nil {
			return m, err
		}
		if b.MemRequestBytes, err = parseUint32Field(d, "memrequestbytes"); err != nil {
			return m, err
		}
		if b.MemResponseBytes, err = parseUint32Field(d, "memresponsebytes"); err != nil {
			return m, err
		}
		m.Buffering = b
	case "errors":
		if err := onlyFields(d, "status", "service", "query"); err != nil {
			return m, err
		}
		e := &model.ErrorsMiddleware{
			Service: scalar("service"),
			Query:   scalar("query"),
		}
		var err error
		if e.Status, err = listField(d, "status"); err != nil {
			return m, err
		}
		m.Errors = e
	case "grpcweb":
		if err := onlyFields(d, "enabled"); err != nil {
			return m, err
		}
		enabled, err := boolField(d, "enabled")
		if err != nil {
			return m, err
		}
		m.GRPCWeb = &model.GRPCWebMiddleware{Enabled: enabled}
	default:
		return m, fmt.Errorf("middleware %q has unknown type %q", d.name, d.typ)
	}
	return m, nil
}

// parseUint32Field reads an optional non-negative integer field.
func parseUint32Field(d middlewareDraft, name string) (uint32, error) {
	v, ok := d.fields[name]
	if !ok {
		return 0, nil
	}
	return parseUint32Label(middlewarePrefix+d.name+"."+d.typ+"."+name, v, true)
}
