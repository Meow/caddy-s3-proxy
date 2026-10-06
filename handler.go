package s3proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// forwardedHeaders are the only upstream response headers passed to the
// client, in canonical form. Everything else (x-amz-*, cf-*, Server, Date,
// hop-by-hop headers) is dropped.
var forwardedHeaders = canonical(
	"Content-Type",
	"Content-Length",
	"Content-Range",
	"Accept-Ranges",
	"ETag",
	"Last-Modified",
	"Content-Encoding",
	"Content-Disposition",
	"Cache-Control",
	"Expires",
)

func canonical(names ...string) []string {
	for i, n := range names {
		names[i] = http.CanonicalHeaderKey(n)
	}
	return names
}

// bufPool holds the buffers used to stream bodies.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// ServeHTTP sends exactly one signed GET or HEAD to the bucket and streams
// the response. It never calls next.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
	}

	// The key is the request path, as left by any rewrite in front, without
	// its leading slash. Go has already percent-decoded it.
	key := strings.TrimPrefix(r.URL.Path, "/")
	if key == "" || strings.HasSuffix(key, "/") {
		return caddyhttp.Error(http.StatusNotFound, errors.New("no object key in the request path"))
	}

	// Whether the request reached the upstream decides between 502 and 504
	// when a timeout follows. The trace hook runs on the transport's write
	// goroutine, hence the atomic.
	var wrote atomic.Bool
	trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote.Store(true) }}
	ctx := httptrace.WithClientTrace(r.Context(), trace)

	req := h.upstreamRequest(ctx, r.Method, key, r.Header.Get("Range"))
	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		// A timeout after the request went out is the upstream's fault:
		// 504. Everything else is 502, including the request's own context
		// ending by cancellation or deadline; the transport reports the
		// latter as a timeout too, so the context is asked directly.
		status := http.StatusBadGateway
		var netErr net.Error
		if wrote.Load() && errors.As(err, &netErr) && netErr.Timeout() && r.Context().Err() == nil {
			status = http.StatusGatewayTimeout
		}
		h.logger.Error("upstream request failed",
			zap.String("key", key),
			zap.String("upstream", h.upstreamHost),
			zap.Int("status", status),
			zap.Error(err))
		return caddyhttp.Error(status, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// A header already set earlier in the route, by a header directive
	// for instance, is kept and the bucket's value dropped, as file_server
	// does. That is how a wrong Content-Type stored with an object is
	// overridden from the configuration.
	header := w.Header()
	for _, name := range forwardedHeaders {
		if values := resp.Header[name]; len(values) > 0 && len(header[name]) == 0 {
			header[name] = values
		}
	}
	w.WriteHeader(resp.StatusCode)

	if r.Method == http.MethodHead {
		return nil
	}

	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	if _, err := io.CopyBuffer(w, resp.Body, *buf); err != nil {
		// The headers are out, so the response cannot be turned into an
		// error page. Abort the connection, as reverse_proxy does, so that
		// nothing in front mistakes a truncated body for a complete one.
		h.logger.Error("streaming the upstream body failed",
			zap.String("key", key),
			zap.String("upstream", h.upstreamHost),
			zap.Error(err))
		panic(http.ErrAbortHandler)
	}
	return nil
}

// upstreamRequest builds and signs the request for key. It carries only
// Host, Range (when given), X-Amz-Date, X-Amz-Content-Sha256 and
// Authorization.
//
// The URL holds the key both decoded (Path) and in its S3 canonical
// encoding (RawPath). The transport writes EscapedPath on the wire and the
// signer signs EscapedPath, so the two are the same string by construction;
// TestEncodeKey checks that EscapedPath is indeed the canonical encoding
// for every byte a key can contain.
func (h *Handler) upstreamRequest(ctx context.Context, method, key, rangeValue string) *http.Request {
	path := h.pathPrefix + "/" + key
	req := &http.Request{
		Method:     method,
		URL:        &url.URL{Scheme: h.scheme, Host: h.upstreamHost, Path: path, RawPath: h.pathPrefix + "/" + encodeKey(key)},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header, 5),
		Host:       h.upstreamHost,
	}
	req = req.WithContext(ctx)
	// An empty User-Agent makes the transport send none.
	req.Header.Set("User-Agent", "")
	// The value is sent in the form the signature covers (trimmed, runs of
	// spaces collapsed), so the two cannot disagree whatever the client sent.
	if rangeValue = trimAll(rangeValue); rangeValue != "" {
		req.Header.Set("Range", rangeValue)
	}
	h.signer.sign(req, h.now())
	return req
}

const upperHex = "0123456789ABCDEF"

// encodeKey percent-encodes an object key per the S3 canonical rules: every
// byte outside A-Za-z0-9-_.~ becomes %XX uppercase, except "/" which is
// kept.
func encodeKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for i := range len(key) {
		c := key[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&15])
		}
	}
	return b.String()
}
