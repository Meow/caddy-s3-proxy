package s3proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// emptyPayloadHash is the SHA-256 of the empty string, the payload hash of
// every request this module sends: GET and HEAD carry no body.
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const (
	amzDateFormat = "20060102T150405Z"
	scopeDateFmt  = "20060102"
	signingAlgo   = "AWS4-HMAC-SHA256"
	service       = "s3"
)

// signer computes AWS Signature Version 4 for the S3 service. It mirrors the
// Lua signer the nginx deployment used: three signed headers, plus Range when
// one is sent, and an empty payload.
type signer struct {
	accessKey string
	secretKey string
	region    string

	// The signing key derives from the scope date only, so it is computed
	// once a day instead of once per request.
	mu         sync.Mutex
	keyDate    string
	signingKey []byte
}

func newSigner(accessKey, secretKey, region string) *signer {
	return &signer{accessKey: accessKey, secretKey: secretKey, region: region}
}

// sign adds X-Amz-Date, X-Amz-Content-Sha256 and Authorization to req. The
// request must already carry its final Host, URL path and Range header.
func (s *signer) sign(req *http.Request, now time.Time) {
	amzDate := now.UTC().Format(amzDateFormat)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("Authorization", s.authorization(req.Method, req.Host, req.URL.EscapedPath(), req.Header.Get("Range"), amzDate))
}

// authorization returns the value of the Authorization header for a request
// with the given method, Host, canonical URI (the path as sent on the wire),
// Range header (empty when none) and X-Amz-Date.
func (s *signer) authorization(method, host, canonicalURI, rangeValue, amzDate string) string {
	headers := signedHeaders(host, rangeValue, amzDate)
	names := make([]string, len(headers))
	for i, h := range headers {
		names[i] = h[0]
	}
	signed := strings.Join(names, ";")

	scopeDate := amzDate[:len(scopeDateFmt)]
	scope := scopeDate + "/" + s.region + "/" + service + "/aws4_request"

	canonical := canonicalRequest(method, canonicalURI, headers, signed)
	stringToSign := signingAlgo + "\n" + amzDate + "\n" + scope + "\n" + hexSHA256(canonical)
	signature := hex.EncodeToString(hmacSHA256(s.key(scopeDate), stringToSign))

	return signingAlgo + " Credential=" + s.accessKey + "/" + scope +
		", SignedHeaders=" + signed +
		", Signature=" + signature
}

// signedHeaders returns the headers covered by the signature as name/value
// pairs, sorted by name, which is the order the canonical request needs.
func signedHeaders(host, rangeValue, amzDate string) [][2]string {
	headers := [][2]string{
		{"host", trimAll(host)},
		{"x-amz-content-sha256", emptyPayloadHash},
		{"x-amz-date", amzDate},
	}
	if rangeValue != "" {
		headers = append(headers, [2]string{"range", trimAll(rangeValue)})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i][0] < headers[j][0] })
	return headers
}

// trimAll normalises a header value the way the canonical request requires:
// leading and trailing spaces removed, sequential spaces collapsed to one.
func trimAll(value string) string {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "  ") {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	prevSpace := false
	for i := range len(value) {
		c := value[i]
		if c == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// canonicalRequest builds the SigV4 canonical request. The query string is
// always empty: the module never sends one.
func canonicalRequest(method, canonicalURI string, headers [][2]string, signed string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(canonicalURI)
	b.WriteByte('\n')
	b.WriteByte('\n') // empty canonical query string
	for _, h := range headers {
		b.WriteString(h[0])
		b.WriteByte(':')
		b.WriteString(h[1])
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(signed)
	b.WriteByte('\n')
	b.WriteString(emptyPayloadHash)
	return b.String()
}

// key returns the signing key for the scope date, deriving it on the first
// use of each day.
func (s *signer) key(scopeDate string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyDate != scopeDate {
		k := hmacSHA256([]byte("AWS4"+s.secretKey), scopeDate)
		k = hmacSHA256(k, s.region)
		k = hmacSHA256(k, service)
		k = hmacSHA256(k, "aws4_request")
		s.keyDate, s.signingKey = scopeDate, k
	}
	return s.signingKey
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hexSHA256(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
