package s3proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The vector from the AWS documentation, "Signature Calculations for the
// Authorization Header: Transferring Payload in a Single Chunk", example
// "GET Object" with a Range header.
const (
	vectorAccessKey = "AKIAIOSFODNN7EXAMPLE"
	vectorSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	vectorRegion    = "us-east-1"
	vectorHost      = "examplebucket.s3.amazonaws.com"
	vectorDate      = "20130524T000000Z"
	vectorHashedCR  = "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
	vectorSignature = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
)

func TestSignerAWSVector(t *testing.T) {
	headers := signedHeaders(vectorHost, "bytes=0-9", vectorDate)
	signed := "host;range;x-amz-content-sha256;x-amz-date"
	if got := hexSHA256(canonicalRequest(http.MethodGet, "/test.txt", headers, signed)); got != vectorHashedCR {
		t.Errorf("hashed canonical request = %s, want %s", got, vectorHashedCR)
	}

	s := newSigner(vectorAccessKey, vectorSecretKey, vectorRegion)
	got := s.authorization(http.MethodGet, vectorHost, "/test.txt", "bytes=0-9", vectorDate)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=" + signed + ", Signature=" + vectorSignature
	if got != want {
		t.Errorf("authorization =\n%s\nwant\n%s", got, want)
	}
}

func TestSignerSignRequest(t *testing.T) {
	s := newSigner(vectorAccessKey, vectorSecretKey, vectorRegion)
	req, err := http.NewRequest(http.MethodGet, "https://"+vectorHost+"/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-9")
	now, _ := time.Parse(amzDateFormat, vectorDate)
	s.sign(req, now)

	if got := req.Header.Get("X-Amz-Date"); got != vectorDate {
		t.Errorf("X-Amz-Date = %q", got)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != emptyPayloadHash {
		t.Errorf("X-Amz-Content-Sha256 = %q", got)
	}
	if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, "Signature="+vectorSignature) {
		t.Errorf("Authorization = %q", got)
	}
}

func TestSignedHeadersOrder(t *testing.T) {
	names := func(h [][2]string) string {
		var out []string
		for _, x := range h {
			out = append(out, x[0])
		}
		return strings.Join(out, ";")
	}
	if got := names(signedHeaders("h", "", "d")); got != "host;x-amz-content-sha256;x-amz-date" {
		t.Errorf("without range: %s", got)
	}
	if got := names(signedHeaders("h", "bytes=0-1", "d")); got != "host;range;x-amz-content-sha256;x-amz-date" {
		t.Errorf("with range: %s", got)
	}
	// Values are trimmed and runs of spaces collapsed, as the canonical
	// form requires.
	h := signedHeaders("  example.com ", " bytes=0-1,   5-6 ", "d")
	if h[0][1] != "example.com" || h[1][1] != "bytes=0-1, 5-6" {
		t.Errorf("values not normalised: %v", h)
	}
}

func TestTrimAll(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"   ":              "",
		"a":                "a",
		" a b ":            "a b",
		"a  b":             "a b",
		"  a   b    c  ":   "a b c",
		"bytes=0-9,  1-2":  "bytes=0-9, 1-2",
		"tab\there":        "tab\there",
		"\t a \t":          "a",
		"no change at all": "no change at all",
	}
	for in, want := range cases {
		if got := trimAll(in); got != want {
			t.Errorf("trimAll(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSigningKeyMemoized(t *testing.T) {
	s := newSigner("k", "s", "r")
	a := s.key("20260101")
	b := s.key("20260101")
	if &a[0] != &b[0] {
		t.Error("the signing key was derived twice for the same date")
	}
	c := s.key("20260102")
	if string(a) == string(c) {
		t.Error("the signing key did not change with the date")
	}
}

func TestEncodeKey(t *testing.T) {
	cases := map[string]string{
		"images/1/2/3.png":     "images/1/2/3.png",
		"a b":                  "a%20b",
		"a+b":                  "a%2Bb",
		"100%":                 "100%25",
		"ünïcode/é.png":        "%C3%BCn%C3%AFcode/%C3%A9.png",
		"a#b?c&d=e":            "a%23b%3Fc%26d%3De",
		"safe-_.~chars":        "safe-_.~chars",
		"quote'paren()star*":   "quote%27paren%28%29star%2A",
		"tab\tnewline\n":       "tab%09newline%0A",
		"nested//slashes/":     "nested//slashes/",
		"\x00\xff":             "%00%FF",
		"at@colon:semi;comma,": "at%40colon%3Asemi%3Bcomma%2C",
	}
	// Every byte value, alone and between slashes, so that the wire form
	// is known for whatever a key can contain.
	for c := range 256 {
		key := "x/" + string([]byte{byte(c)}) + "/y"
		switch b := byte(c); {
		case 'A' <= b && b <= 'Z', 'a' <= b && b <= 'z', '0' <= b && b <= '9', b == '-', b == '_', b == '.', b == '~', b == '/':
			cases[key] = key
		default:
			cases[key] = fmt.Sprintf("x/%%%02X/y", b)
		}
	}
	for in, want := range cases {
		if got := encodeKey(in); got != want {
			t.Errorf("encodeKey(%q) = %q, want %q", in, got, want)
		}
		// The handler puts the key decoded in Path and encoded in RawPath,
		// and the transport writes EscapedPath on the wire. EscapedPath
		// must therefore be exactly the canonical encoding, which is also
		// what the signer signs.
		u := &url.URL{Path: "/" + in, RawPath: "/" + want}
		if got := u.EscapedPath(); got != "/"+want {
			t.Errorf("EscapedPath for %q = %q, want %q", in, got, "/"+want)
		}
	}
}
