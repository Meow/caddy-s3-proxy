package s3proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	testBucket    = "testbucket"
	testRegion    = "auto"
	testAccessKey = "AKIDTEST"
	testSecretKey = "SECRETTEST"
)

// object is what the fake bucket holds for a key.
type object struct {
	body        []byte
	contentType string
	modTime     time.Time
}

// fakeS3 is an S3 look-alike: it verifies the signature of each request,
// insists on the exact header set the module is meant to send, serves
// ranges, and counts requests per method and path.
type fakeS3 struct {
	*httptest.Server
	signer *signer

	mu       sync.Mutex
	objects  map[string]object
	counts   map[string]int
	problems []string

	// hook, when set, runs before normal handling and takes over when it
	// returns true.
	hook func(w http.ResponseWriter, r *http.Request) bool
}

var (
	bigObject  = make([]byte, 20*1024*1024)
	testObjMod = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
)

func init() {
	for i := range bigObject {
		bigObject[i] = byte(i * 7)
	}
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{
		signer: newSigner(testAccessKey, testSecretKey, testRegion),
		objects: map[string]object{
			"images/1/2/3.png":    {[]byte("PNG-BYTES"), "image/png", testObjMod},
			"video/big.webm":      {bigObject, "video/webm", testObjMod},
			"odd/a b+c%d#e/ü.txt": {[]byte("odd"), "text/plain", testObjMod},
		},
		counts: map[string]int{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeS3) problem(format string, args ...any) {
	f.mu.Lock()
	f.problems = append(f.problems, fmt.Sprintf(format, args...))
	f.mu.Unlock()
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.counts[r.Method+" "+r.URL.EscapedPath()]++
	f.mu.Unlock()

	if r.URL.RawQuery != "" {
		f.problem("query string sent upstream: %q", r.URL.RawQuery)
	}
	allowed := map[string]bool{"Range": true, "X-Amz-Date": true, "X-Amz-Content-Sha256": true, "Authorization": true}
	for name := range r.Header {
		if !allowed[name] {
			f.problem("unexpected upstream header %s: %q", name, r.Header.Get(name))
		}
	}
	if r.Header.Get("X-Amz-Content-Sha256") != emptyPayloadHash {
		f.problem("bad payload hash %q", r.Header.Get("X-Amz-Content-Sha256"))
	}

	// Recompute the signature from the request as received.
	want := f.signer.authorization(r.Method, r.Host, r.URL.EscapedPath(), r.Header.Get("Range"), r.Header.Get("X-Amz-Date"))
	if got := r.Header.Get("Authorization"); got != want {
		f.problem("signature mismatch for %s %s:\n got %s\nwant %s", r.Method, r.URL.EscapedPath(), got, want)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if f.hook != nil && f.hook(w, r) {
		return
	}

	prefix := "/" + testBucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		f.problem("path %q not under the bucket", r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)

	h := w.Header()
	h.Set("X-Amz-Request-Id", "req-123")
	h.Set("Server", "cloudflare")
	h.Set("CF-Ray", "abc")

	f.mu.Lock()
	obj, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		h.Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code></Error>`)
		return
	}
	h.Set("Content-Type", obj.contentType)
	h.Set("ETag", `"etag-`+key+`"`)
	http.ServeContent(w, r, "", obj.modTime, strings.NewReader(string(obj.body)))
}

func (f *fakeS3) count(method, key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[method+" /"+testBucket+"/"+encodeKey(key)]
}

func (f *fakeS3) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.counts {
		n += c
	}
	return n
}

func (f *fakeS3) check(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.problems {
		t.Error("fake S3: " + p)
	}
}

// newHandler provisions a handler against endpoint with the test
// credentials; mod can change the options before provisioning.
func newHandler(t *testing.T, endpoint string, mod func(*Handler)) *Handler {
	t.Helper()
	h := &Handler{
		Endpoint:  endpoint,
		Bucket:    testBucket,
		Region:    testRegion,
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	}
	if mod != nil {
		mod(h)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	return h
}

// serve runs one request through the handler and returns the recorder and
// the error.
func serve(h *Handler, method, path string, headers ...string) (*httptest.ResponseRecorder, error) {
	req := httptest.NewRequest(method, "http://example.com"+path, nil)
	for _, hd := range headers {
		name, value, _ := strings.Cut(hd, ": ")
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	return rec, h.ServeHTTP(rec, req, nil)
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) {
		t.Fatalf("error %v is not a caddyhttp.HandlerError", err)
	}
	return he.StatusCode
}

func TestGetWholeObject(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	rec, err := serve(h, http.MethodGet, "/images/1/2/3.png")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Body.String(); got != "PNG-BYTES" {
		t.Errorf("body %q", got)
	}
	want := http.Header{
		"Content-Type":   {"image/png"},
		"Content-Length": {"9"},
		"Accept-Ranges":  {"bytes"},
		"Etag":           {`"etag-images/1/2/3.png"`},
		"Last-Modified":  {testObjMod.Format(http.TimeFormat)},
	}
	for name, values := range want {
		if got := rec.Header().Values(name); strings.Join(got, ",") != strings.Join(values, ",") {
			t.Errorf("header %s = %q, want %q", name, got, values)
		}
	}
	for name := range rec.Header() {
		if _, ok := want[name]; !ok {
			t.Errorf("header %s forwarded, not in the allowlist", name)
		}
	}
	if n := f.count(http.MethodGet, "images/1/2/3.png"); n != 1 {
		t.Errorf("%d upstream requests, want 1", n)
	}
	if n := f.total(); n != 1 {
		t.Errorf("%d upstream requests in total, want 1", n)
	}
	f.check(t)
}

// TestPresetHeaderKept checks that a header set before the handler runs,
// as a header directive in front of it does, wins over the bucket's value.
func TestPresetHeaderKept(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/images/1/2/3.png", nil)
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "image/forced")
	rec.Header().Set("Cache-Control", "public, max-age=1")
	if err := h.ServeHTTP(rec, req, nil); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Values("Content-Type"); len(got) != 1 || got[0] != "image/forced" {
		t.Errorf("Content-Type = %q, want the preset value only", got)
	}
	if got := rec.Header().Values("Cache-Control"); len(got) != 1 || got[0] != "public, max-age=1" {
		t.Errorf("Cache-Control = %q, want the preset value only", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "9" {
		t.Errorf("Content-Length %q: headers not preset must still be forwarded", got)
	}
	f.check(t)
}

func TestGetRange(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	rec, err := serve(h, http.MethodGet, "/video/big.webm", "Range: bytes=8388608-16777215")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Range"); got != fmt.Sprintf("bytes 8388608-16777215/%d", len(bigObject)) {
		t.Errorf("Content-Range %q", got)
	}
	if got := rec.Body.Bytes(); string(got) != string(bigObject[8388608:16777216]) {
		t.Errorf("wrong slice: %d bytes", len(got))
	}
	if n := f.total(); n != 1 {
		t.Errorf("%d upstream requests, want 1", n)
	}
	f.check(t)
}

func TestHead(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	rec, err := serve(h, http.MethodHead, "/images/1/2/3.png")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Length"); got != "9" {
		t.Errorf("Content-Length %q", got)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body of %d bytes on HEAD", rec.Body.Len())
	}
	if n := f.count(http.MethodHead, "images/1/2/3.png"); n != 1 {
		t.Errorf("%d upstream HEADs, want 1", n)
	}
	if n := f.total(); n != 1 {
		t.Errorf("%d upstream requests in total, want 1", n)
	}
	f.check(t)
}

func TestMissingKey(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	rec, err := serve(h, http.MethodGet, "/images/nope.png")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "NoSuchKey") {
		t.Errorf("404 body not forwarded: %q", rec.Body.String())
	}
	if n := f.total(); n != 1 {
		t.Errorf("%d upstream requests, want exactly 1 (no HEAD, no listing)", n)
	}
	f.check(t)
}

func TestQueryStringIgnored(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	rec, err := serve(h, http.MethodGet, "/images/1/2/3.png?x=1&token=abc")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if n := f.count(http.MethodGet, "images/1/2/3.png"); n != 1 {
		t.Errorf("%d upstream requests, want 1", n)
	}
	f.check(t)
}

func TestRequestHeadersNotForwarded(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	rec, err := serve(h, http.MethodGet, "/images/1/2/3.png",
		"Cookie: session=1", "If-None-Match: \"x\"", "Accept-Encoding: gzip",
		"User-Agent: test", "Authorization: Bearer nope", "X-Forwarded-For: 1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	// The fake records any header outside the signed set as a problem.
	f.check(t)
}

func TestKeysNeedingEncoding(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	// The client URL is what a browser would send for the key "odd/a b+c%d#e/ü.txt".
	rec, err := serve(h, http.MethodGet, "/odd/a%20b+c%25d%23e/%C3%BC.txt")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "odd" {
		t.Errorf("body %q", rec.Body.String())
	}
	if n := f.count(http.MethodGet, "odd/a b+c%d#e/ü.txt"); n != 1 {
		t.Errorf("%d upstream requests for the encoded key, want 1; counts %v", n, f.counts)
	}
	f.check(t)
}

func TestEmptyOrDirectoryKey(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	for _, path := range []string{"/", "/images/", "/images/1/"} {
		rec, err := serve(h, http.MethodGet, path)
		if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Errorf("%s: something was written: %d %q", path, rec.Code, rec.Body.String())
		}
		if got := statusOf(t, err); got != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, got)
		}
	}
	if n := f.total(); n != 0 {
		t.Errorf("%d upstream requests, want 0", n)
	}
	f.check(t)
}

func TestMethodNotAllowed(t *testing.T) {
	f := newFakeS3(t)
	h := newHandler(t, f.URL, nil)

	for _, method := range []string{http.MethodPost, http.MethodOptions, http.MethodPut, http.MethodDelete} {
		rec, err := serve(h, method, "/images/1/2/3.png")
		if got := statusOf(t, err); got != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, got)
		}
		if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s: Allow %q", method, got)
		}
	}
	if n := f.total(); n != 0 {
		t.Errorf("%d upstream requests, want 0", n)
	}
}

func TestUpstreamRefusesConnection(t *testing.T) {
	// A listener closed right away gives an address nothing listens on.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	h := newHandler(t, "http://"+addr, nil)
	rec, err := serve(h, http.MethodGet, "/images/1/2/3.png")
	if got := statusOf(t, err); got != http.StatusBadGateway {
		t.Errorf("status %d, want 502 (%v)", got, err)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("something was written: %d %q", rec.Code, rec.Body.String())
	}
}

func TestResponseHeaderTimeout(t *testing.T) {
	f := newFakeS3(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}
	h := newHandler(t, f.URL, func(h *Handler) {
		h.ResponseHeaderTimeout = caddy.Duration(100 * time.Millisecond)
	})

	_, err := serve(h, http.MethodGet, "/images/1/2/3.png")
	if got := statusOf(t, err); got != http.StatusGatewayTimeout {
		t.Errorf("status %d, want 504 (%v)", got, err)
	}
	if n := f.total(); n != 1 {
		t.Errorf("%d upstream requests, want 1", n)
	}
}

func TestUpstreamClosesMidBody(t *testing.T) {
	f := newFakeS3(t)
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			f.problem("hijack: %v", err)
			return true
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: video/webm\r\nContent-Length: 1000\r\n\r\n")
		_, _ = buf.WriteString(strings.Repeat("x", 100))
		_ = buf.Flush()
		_ = conn.Close()
		return true
	}
	h := newHandler(t, f.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/video/big.webm", nil)
	rec := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = h.ServeHTTP(rec, req, nil)
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want http.ErrAbortHandler", recovered)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status %d: the headers should have been written before the abort", rec.Code)
	}
	if got := rec.Header().Get("Content-Length"); got != "1000" {
		t.Errorf("Content-Length %q", got)
	}
	if rec.Body.Len() != 100 {
		t.Errorf("%d bytes written before the abort, want 100", rec.Body.Len())
	}
	f.check(t)
}

func TestRequestContextCanceled(t *testing.T) {
	f := newFakeS3(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	reached := make(chan struct{})
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		close(reached)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}
	h := newHandler(t, f.URL, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/images/1/2/3.png", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	go func() {
		<-reached
		cancel()
	}()
	err := h.ServeHTTP(rec, req, nil)
	if err == nil {
		t.Fatal("no error on a canceled request")
	}
	if got := statusOf(t, err); got != http.StatusBadGateway {
		t.Errorf("status %d, want 502 (%v)", got, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not wrap context.Canceled", err)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("something was written: %d %q", rec.Code, rec.Body.String())
	}
}

// TestRequestDeadlineExceeded checks that the request's own deadline, which
// is a timeout from the transport's point of view, is still reported as 502
// and not mistaken for the upstream timing out.
func TestRequestDeadlineExceeded(t *testing.T) {
	f := newFakeS3(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}
	h := newHandler(t, f.URL, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/images/1/2/3.png", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, nil)
	if got := statusOf(t, err); got != http.StatusBadGateway {
		t.Errorf("status %d, want 502 (%v)", got, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not wrap context.DeadlineExceeded", err)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("something was written: %d %q", rec.Code, rec.Body.String())
	}
}

// TestRangeNormalised sends a Range value with excess spaces: the upstream
// gets it in the canonical form the signature covers, and the fake, which
// recomputes the signature from what it received, accepts it.
func TestRangeNormalised(t *testing.T) {
	f := newFakeS3(t)
	var sent string
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		sent = r.Header.Get("Range")
		return false
	}
	h := newHandler(t, f.URL, nil)

	rec, err := serve(h, http.MethodGet, "/video/big.webm", "Range:   bytes=0-9,   20-29  ")
	if err != nil {
		t.Fatal(err)
	}
	if sent != "bytes=0-9, 20-29" {
		t.Errorf("upstream Range %q", sent)
	}
	// Go's ServeContent answers a multi-range request with a multipart
	// body; the status is enough to show the request went through.
	if rec.Code != http.StatusPartialContent {
		t.Errorf("status %d", rec.Code)
	}
	if n := f.total(); n != 1 {
		t.Errorf("%d upstream requests, want 1", n)
	}
	f.check(t)
}

func TestVirtualHostedRequest(t *testing.T) {
	// No network: virtual-hosted hosts cannot be dialed in a test, so only
	// the request the handler would send is checked.
	h := newHandler(t, "https://acct.r2.cloudflarestorage.com", func(h *Handler) {
		h.VirtualHosted = true
		h.now = func() time.Time { return time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC) }
	})
	req := h.upstreamRequest(context.Background(), http.MethodGet, "images/a b.png", "bytes=0-1")
	if req.Host != "testbucket.acct.r2.cloudflarestorage.com" || req.URL.Host != req.Host {
		t.Errorf("host %q / URL host %q", req.Host, req.URL.Host)
	}
	if got := req.URL.String(); got != "https://testbucket.acct.r2.cloudflarestorage.com/images/a%20b.png" {
		t.Errorf("URL %q", got)
	}
	want := h.signer.authorization(http.MethodGet, req.Host, "/images/a%20b.png", "bytes=0-1", "20260304T050607Z")
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization\n got %s\nwant %s", got, want)
	}
	wantHeaders := map[string]bool{"Range": true, "X-Amz-Date": true, "X-Amz-Content-Sha256": true, "Authorization": true, "User-Agent": true}
	for name := range req.Header {
		if !wantHeaders[name] {
			t.Errorf("unexpected header %s", name)
		}
	}
	if got := req.Header.Get("User-Agent"); got != "" {
		t.Errorf("User-Agent %q should be empty so that none is sent", got)
	}
}

func TestPathStyleRequestWithPort(t *testing.T) {
	h := newHandler(t, "http://127.0.0.1:9000", nil)
	req := h.upstreamRequest(context.Background(), http.MethodHead, "k/é", "")
	if req.Host != "127.0.0.1:9000" {
		t.Errorf("Host %q should keep the explicit port", req.Host)
	}
	if got := req.URL.String(); got != "http://127.0.0.1:9000/testbucket/k/%C3%A9" {
		t.Errorf("URL %q", got)
	}
	if req.Header.Get("Range") != "" {
		t.Error("Range sent without one on the request")
	}
}

func TestProvisionValidate(t *testing.T) {
	base := func() *Handler {
		return &Handler{
			Endpoint:  "https://acct.r2.cloudflarestorage.com",
			Bucket:    testBucket,
			Region:    testRegion,
			AccessKey: testAccessKey,
			SecretKey: testSecretKey,
		}
	}
	cases := []struct {
		name string
		mod  func(*Handler)
		want string // substring of the error; empty means success
	}{
		{"valid", func(*Handler) {}, ""},
		{"missing endpoint", func(h *Handler) { h.Endpoint = "" }, "endpoint"},
		{"endpoint with path", func(h *Handler) { h.Endpoint = "https://host/bucket" }, "endpoint"},
		{"endpoint with query", func(h *Handler) { h.Endpoint = "https://host?x=1" }, "endpoint"},
		{"endpoint without scheme", func(h *Handler) { h.Endpoint = "host.example" }, "endpoint"},
		{"endpoint with bad scheme", func(h *Handler) { h.Endpoint = "ftp://host" }, "endpoint"},
		{"endpoint unparsable", func(h *Handler) { h.Endpoint = "https://[::1" }, "endpoint"},
		{"endpoint without host", func(h *Handler) { h.Endpoint = "https://" }, "endpoint"},
		{"endpoint with userinfo", func(h *Handler) { h.Endpoint = "https://ak:sk@host" }, "endpoint"},
		{"endpoint with fragment", func(h *Handler) { h.Endpoint = "https://host#x" }, "endpoint"},
		{"endpoint with port", func(h *Handler) { h.Endpoint = "http://[::1]:9000" }, ""},
		{"missing bucket", func(h *Handler) { h.Bucket = "" }, "bucket"},
		{"missing region", func(h *Handler) { h.Region = "" }, "region"},
		{"missing access key", func(h *Handler) { h.AccessKey = "" }, "access_key"},
		{"missing secret key", func(h *Handler) { h.SecretKey = "" }, "secret_key"},
		{"negative dial timeout", func(h *Handler) { h.DialTimeout = -1 }, "dial_timeout"},
		{"negative response header timeout", func(h *Handler) { h.ResponseHeaderTimeout = -1 }, "response_header_timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := base()
			tc.mod(h)
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			err := h.Provision(ctx)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Provision: %v", err)
				}
				_ = h.Cleanup()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one naming %s", err, tc.want)
			}
		})
	}
}

func TestProvisionResolvesEnvPlaceholders(t *testing.T) {
	// The test sets the variable; the module only sees the placeholder the
	// configuration names, which Caddy's replacer resolves.
	t.Setenv("S3PROXY_TEST_BUCKET", "frombucket")
	t.Setenv("S3PROXY_TEST_SECRET", "fromsecret")
	h := newHandler(t, "https://acct.r2.cloudflarestorage.com", func(h *Handler) {
		h.Bucket = "{env.S3PROXY_TEST_BUCKET}"
		h.SecretKey = "{env.S3PROXY_TEST_SECRET}"
	})
	if h.Bucket != "frombucket" || h.SecretKey != "fromsecret" {
		t.Errorf("bucket %q secret %q", h.Bucket, h.SecretKey)
	}
	if h.pathPrefix != "/frombucket" {
		t.Errorf("path prefix %q", h.pathPrefix)
	}

	// An unset variable leaves an empty value, which Validate rejects.
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	bad := &Handler{Endpoint: "https://h", Bucket: "{env.S3PROXY_TEST_UNSET_VAR}", Region: "r", AccessKey: "a", SecretKey: "s"}
	if err := bad.Provision(ctx); err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Errorf("unset placeholder: error %v, want one naming bucket", err)
	}
}

func TestDefaults(t *testing.T) {
	h := newHandler(t, "https://acct.r2.cloudflarestorage.com", nil)
	if time.Duration(h.DialTimeout) != defaultDialTimeout {
		t.Errorf("dial timeout %v", h.DialTimeout)
	}
	if time.Duration(h.ResponseHeaderTimeout) != defaultResponseHeaderTimeout {
		t.Errorf("response header timeout %v", h.ResponseHeaderTimeout)
	}
	if h.transport.Proxy != nil {
		t.Error("the transport must not use a proxy function (it would read the environment)")
	}
	if !h.transport.DisableCompression {
		t.Error("compression must be disabled so that no Accept-Encoding is added")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  *Handler
		err   string
	}{
		{
			name: "all options",
			input: `s3_proxy {
				endpoint https://acct.r2.cloudflarestorage.com
				bucket b
				region auto
				access_key AK
				secret_key SK
				virtual_hosted
				dial_timeout 5s
				response_header_timeout 1m
			}`,
			want: &Handler{
				Endpoint: "https://acct.r2.cloudflarestorage.com", Bucket: "b", Region: "auto",
				AccessKey: "AK", SecretKey: "SK", VirtualHosted: true,
				DialTimeout: caddy.Duration(5 * time.Second), ResponseHeaderTimeout: caddy.Duration(time.Minute),
			},
		},
		{
			name: "minimal",
			input: `s3_proxy {
				endpoint http://127.0.0.1:9000
				bucket b
				region auto
				access_key AK
				secret_key SK
			}`,
			want: &Handler{Endpoint: "http://127.0.0.1:9000", Bucket: "b", Region: "auto", AccessKey: "AK", SecretKey: "SK"},
		},
		{name: "inline argument", input: `s3_proxy https://x {
			}`, err: "wrong argument count"},
		{name: "unknown option", input: `s3_proxy {
				bukkit b
			}`, err: "unknown option bukkit"},
		{name: "duplicate option", input: `s3_proxy {
				bucket a
				bucket b
			}`, err: "duplicate option bucket"},
		{name: "virtual_hosted with argument", input: `s3_proxy {
				virtual_hosted yes
			}`, err: "wrong argument count"},
		{name: "bad dial_timeout", input: `s3_proxy {
				dial_timeout soon
			}`, err: "dial_timeout: bad duration"},
		{name: "bad response_header_timeout", input: `s3_proxy {
				response_header_timeout later
			}`, err: "response_header_timeout: bad duration"},
		{name: "dial_timeout without value", input: `s3_proxy {
				dial_timeout
			}`, err: "wrong argument count"},
		{name: "dial_timeout with two values", input: `s3_proxy {
				dial_timeout 5s 6s
			}`, err: "wrong argument count"},
	}
	for _, opt := range []string{"endpoint", "bucket", "region", "access_key", "secret_key"} {
		cases = append(cases,
			struct {
				name  string
				input string
				want  *Handler
				err   string
			}{name: opt + " without value", input: "s3_proxy {\n" + opt + "\n}", err: "wrong argument count"},
			struct {
				name  string
				input string
				want  *Handler
				err   string
			}{name: opt + " with two values", input: "s3_proxy {\n" + opt + " a b\n}", err: "wrong argument count"},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := new(Handler)
			err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error %v, want one containing %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, want := *h, *tc.want
			if got.Endpoint != want.Endpoint || got.Bucket != want.Bucket || got.Region != want.Region ||
				got.AccessKey != want.AccessKey || got.SecretKey != want.SecretKey ||
				got.VirtualHosted != want.VirtualHosted || got.DialTimeout != want.DialTimeout ||
				got.ResponseHeaderTimeout != want.ResponseHeaderTimeout {
				t.Errorf("got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestParseCaddyfile(t *testing.T) {
	helper := func(input string) httpcaddyfile.Helper {
		return httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser(input)}
	}
	mh, err := parseCaddyfile(helper(`s3_proxy {
		endpoint https://acct.r2.cloudflarestorage.com
		bucket b
		region auto
		access_key AK
		secret_key SK
	}`))
	if err != nil {
		t.Fatal(err)
	}
	h, ok := mh.(*Handler)
	if !ok || h.Bucket != "b" || !strings.HasPrefix(h.Endpoint, "https://acct") {
		t.Errorf("parsed %#v", mh)
	}
	if _, err := parseCaddyfile(helper(`s3_proxy {
		bukkit b
	}`)); err == nil || !strings.Contains(err.Error(), "unknown option bukkit") {
		t.Errorf("error %v, want unknown option", err)
	}
}

// TestFakeRejectsBadSignature guards the fake itself: a wrong signature
// must be refused, so a passing suite proves the signatures.
func TestFakeRejectsBadSignature(t *testing.T) {
	f := newFakeS3(t)
	u, _ := url.Parse(f.URL)
	req, _ := http.NewRequest(http.MethodGet, f.URL+"/"+testBucket+"/images/1/2/3.png", nil)
	req.Host = u.Host
	req.Header.Set("User-Agent", "")
	newSigner(testAccessKey, "WRONG", testRegion).sign(req, time.Now())
	tr := &http.Transport{DisableCompression: true}
	t.Cleanup(tr.CloseIdleConnections)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
}
