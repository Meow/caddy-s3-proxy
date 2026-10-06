// Package s3proxy provides s3_proxy, a Caddy HTTP handler that fetches an
// object from an S3-compatible bucket with exactly one signed request per
// handler call and streams the response to the client.
package s3proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("s3_proxy", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("s3_proxy", httpcaddyfile.After, "reverse_proxy")
}

const (
	defaultDialTimeout           = 10 * time.Second
	defaultResponseHeaderTimeout = 30 * time.Second
)

// Handler fetches objects from an S3-compatible bucket. It is a terminal
// handler: it never calls the next one.
//
// The handler reads nothing from the environment. Every value, credentials
// included, is whatever string the configuration holds; in a Caddyfile that
// is typically a {$VAR} placeholder, which the Caddyfile adapter substitutes
// before the module sees it.
type Handler struct {
	// Endpoint is the URL of the S3 service: scheme and host[:port], with no
	// path. Required.
	Endpoint string `json:"endpoint,omitempty"`

	// Bucket is the name of the bucket. Required.
	Bucket string `json:"bucket,omitempty"`

	// Region is the signing region; "auto" for Cloudflare R2. Required.
	Region string `json:"region,omitempty"`

	// AccessKey is the access key ID. Required.
	AccessKey string `json:"access_key,omitempty"`

	// SecretKey is the secret access key. Required.
	SecretKey string `json:"secret_key,omitempty"`

	// VirtualHosted selects virtual-hosted-style requests
	// (https://<bucket>.<endpoint host>/<key>). The default is path style
	// (<endpoint>/<bucket>/<key>).
	VirtualHosted bool `json:"virtual_hosted,omitempty"`

	// DialTimeout bounds each of the TCP connection and the TLS handshake
	// to the endpoint. Default 10s.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// ResponseHeaderTimeout bounds the wait for the response headers once
	// the request has been sent. Default 30s.
	ResponseHeaderTimeout caddy.Duration `json:"response_header_timeout,omitempty"`

	scheme       string // "http" or "https"
	upstreamHost string // Host header and dial target, e.g. "acct.r2.cloudflarestorage.com"
	pathPrefix   string // "/<bucket>" for path style, "" for virtual hosted
	transport    *http.Transport
	signer       *signer
	logger       *zap.Logger
	now          func() time.Time
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.s3_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision resolves placeholders in the options, checks them and prepares
// the signer and the transport.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	// Runtime placeholders such as {env.VAR} are resolved here, once. This
	// is still the configuration naming the variable: the module itself
	// never looks one up.
	repl := caddy.NewReplacer()
	for _, p := range []*string{&h.Endpoint, &h.Bucket, &h.Region, &h.AccessKey, &h.SecretKey} {
		*p = repl.ReplaceKnown(*p, "")
	}

	if err := h.Validate(); err != nil {
		return err
	}

	u, _ := url.Parse(h.Endpoint) // Validate checked it
	h.scheme = u.Scheme
	if h.VirtualHosted {
		h.upstreamHost = h.Bucket + "." + u.Host
		h.pathPrefix = ""
	} else {
		h.upstreamHost = u.Host
		h.pathPrefix = "/" + h.Bucket
	}

	if h.DialTimeout == 0 {
		h.DialTimeout = caddy.Duration(defaultDialTimeout)
	}
	if h.ResponseHeaderTimeout == 0 {
		h.ResponseHeaderTimeout = caddy.Duration(defaultResponseHeaderTimeout)
	}

	dialer := &net.Dialer{Timeout: time.Duration(h.DialTimeout)}
	h.transport = &http.Transport{
		// Proxy is left nil on purpose: the usual proxy function reads
		// the environment.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   time.Duration(h.DialTimeout),
		ResponseHeaderTimeout: time.Duration(h.ResponseHeaderTimeout),
		// The transport must not add Accept-Encoding: the upstream request
		// carries exactly the headers that are signed.
		DisableCompression:  true,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}

	h.signer = newSigner(h.AccessKey, h.SecretKey, h.Region)
	if h.now == nil {
		h.now = time.Now
	}

	return nil
}

// Validate checks the options. It never applies defaults or fallbacks: a
// missing endpoint is an error, not a hint to look elsewhere.
func (h *Handler) Validate() error {
	if h.Endpoint == "" {
		return errors.New("s3_proxy: endpoint is required")
	}
	u, err := url.Parse(h.Endpoint)
	if err != nil {
		return fmt.Errorf("s3_proxy: endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("s3_proxy: endpoint: scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("s3_proxy: endpoint: host is required")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("s3_proxy: endpoint must be scheme and host only, got %q", h.Endpoint)
	}
	if h.Bucket == "" {
		return errors.New("s3_proxy: bucket is required")
	}
	if h.Region == "" {
		return errors.New("s3_proxy: region is required")
	}
	if h.AccessKey == "" {
		return errors.New("s3_proxy: access_key is required")
	}
	if h.SecretKey == "" {
		return errors.New("s3_proxy: secret_key is required")
	}
	if h.DialTimeout < 0 {
		return errors.New("s3_proxy: dial_timeout must not be negative")
	}
	if h.ResponseHeaderTimeout < 0 {
		return errors.New("s3_proxy: response_header_timeout must not be negative")
	}
	return nil
}

// Cleanup closes the idle connections to the endpoint.
func (h *Handler) Cleanup() error {
	if h.transport != nil {
		h.transport.CloseIdleConnections()
	}
	return nil
}

// UnmarshalCaddyfile parses the directive:
//
//	s3_proxy [<matcher>] {
//	    endpoint   <url>
//	    bucket     <name>
//	    region     <region>
//	    access_key <id>
//	    secret_key <secret>
//	    virtual_hosted
//	    dial_timeout            <duration>
//	    response_header_timeout <duration>
//	}
//
// The directive takes no inline arguments; every option is in the block.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the directive name
	if d.NextArg() {
		return d.ArgErr()
	}

	stringOpts := map[string]*string{
		"endpoint":   &h.Endpoint,
		"bucket":     &h.Bucket,
		"region":     &h.Region,
		"access_key": &h.AccessKey,
		"secret_key": &h.SecretKey,
	}
	durationOpts := map[string]*caddy.Duration{
		"dial_timeout":            &h.DialTimeout,
		"response_header_timeout": &h.ResponseHeaderTimeout,
	}
	seen := map[string]bool{}
	for d.NextBlock(0) {
		name := d.Val()
		if seen[name] {
			return d.Errf("duplicate option %s", name)
		}
		seen[name] = true

		switch {
		case stringOpts[name] != nil:
			if !d.AllArgs(stringOpts[name]) {
				return d.ArgErr()
			}
		case durationOpts[name] != nil:
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("%s: bad duration %q: %v", name, d.Val(), err)
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			*durationOpts[name] = caddy.Duration(dur)
		case name == "virtual_hosted":
			if d.NextArg() {
				return d.ArgErr()
			}
			h.VirtualHosted = true
		default:
			return d.Errf("unknown option %s", name)
		}
	}
	return nil
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h := new(Handler)
	if err := h.UnmarshalCaddyfile(helper.Dispenser); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
