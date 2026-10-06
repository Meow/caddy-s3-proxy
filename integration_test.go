package s3proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

const (
	integrationURL = "http://localhost:9080"
)

// TestIntegration boots Caddy with a Caddyfile shaped like production's
// (s3path) snippet and checks the directive order, parsing and the rewrite
// interplay end to end. Fixed ports: not parallel.
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped with -short")
	}

	f := newFakeS3(t)
	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		admin localhost:2999
		http_port 9080
	}
	localhost:9080 {
		@img path_regexp ^/img/(.+)$
		handle @img {
			rewrite /img/* /images/{re.img.1}
			s3_proxy {
				endpoint   %s
				bucket     %s
				region     %s
				access_key %s
				secret_key %s
			}
		}
		@vid path_regexp ^/vid/(.+)$
		handle @vid {
			rewrite /vid/* /video/{re.vid.1}
			s3_proxy {
				endpoint   %s
				bucket     %s
				region     %s
				access_key %s
				secret_key %s
			}
		}
	}`, f.URL, testBucket, testRegion, testAccessKey, testSecretKey,
		f.URL, testBucket, testRegion, testAccessKey, testSecretKey), "caddyfile")

	fetch := func(method, path string, headers ...string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(method, integrationURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range headers {
			name, value, _ := strings.Cut(h, ": ")
			req.Header.Set(name, value)
		}
		resp, err := tester.Client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s %s: reading the body: %v", method, path, err)
		}
		return resp, string(body)
	}

	t.Run("whole", func(t *testing.T) {
		resp, body := fetch(http.MethodGet, "/img/1/2/3.png")
		if resp.StatusCode != http.StatusOK || body != "PNG-BYTES" {
			t.Fatalf("%d %q", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Content-Type"); got != "image/png" {
			t.Errorf("Content-Type %q", got)
		}
		if got := resp.Header.Get("X-Amz-Request-Id"); got != "" {
			t.Errorf("x-amz header leaked: %q", got)
		}
		if n := f.count(http.MethodGet, "images/1/2/3.png"); n != 1 {
			t.Errorf("%d upstream requests, want 1", n)
		}
	})

	t.Run("range", func(t *testing.T) {
		resp, body := fetch(http.MethodGet, "/vid/big.webm", "Range: bytes=8388608-16777215")
		if resp.StatusCode != http.StatusPartialContent {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Range"); got != fmt.Sprintf("bytes 8388608-16777215/%d", len(bigObject)) {
			t.Errorf("Content-Range %q", got)
		}
		if body != string(bigObject[8388608:16777216]) {
			t.Errorf("wrong slice: %d bytes", len(body))
		}
		if n := f.count(http.MethodGet, "video/big.webm"); n != 1 {
			t.Errorf("%d upstream requests, want 1", n)
		}
	})

	t.Run("head", func(t *testing.T) {
		resp, body := fetch(http.MethodHead, "/img/1/2/3.png")
		if resp.StatusCode != http.StatusOK || body != "" {
			t.Fatalf("%d %q", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Content-Length"); got != "9" {
			t.Errorf("Content-Length %q", got)
		}
		if n := f.count(http.MethodHead, "images/1/2/3.png"); n != 1 {
			t.Errorf("%d upstream HEADs, want 1", n)
		}
	})

	t.Run("missing", func(t *testing.T) {
		resp, body := fetch(http.MethodGet, "/img/nope.png")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if !strings.Contains(body, "NoSuchKey") {
			t.Errorf("404 body not forwarded: %q", body)
		}
		if n := f.count(http.MethodGet, "images/nope.png"); n != 1 {
			t.Errorf("%d upstream requests, want 1", n)
		}
	})

	t.Run("method", func(t *testing.T) {
		resp, _ := fetch(http.MethodPost, "/img/1/2/3.png")
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
			t.Errorf("Allow %q", got)
		}
	})

	if n := f.total(); n != 4 {
		t.Errorf("%d upstream requests in total, want 4", n)
	}
	f.check(t)
}
