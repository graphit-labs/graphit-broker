package broker

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Signature Version 4 as S3 clients produce it. The gateway verifies rather than signs: it
// rebuilds the canonical request from what arrived and compares the result, so a request whose
// method, path, query, signed headers, or declared payload digest was altered cannot verify.
const (
	sigV4Algorithm       = "AWS4-HMAC-SHA256"
	sigV4ChunkAlgorithm  = "AWS4-HMAC-SHA256-PAYLOAD"
	sigV4Service         = "s3"
	sigV4Terminator      = "aws4_request"
	sigV4TimeFormat      = "20060102T150405Z"
	sigV4DateFormat      = "20060102"
	sigV4MaximumSkew     = 15 * time.Minute
	unsignedPayload      = "UNSIGNED-PAYLOAD"
	streamingSignedBody  = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingSignedTrail = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	streamingUnsigned    = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	emptyPayloadSHA256   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	errSignatureMalformed = errors.New("the authorization header is malformed")
	errSignatureMismatch  = errors.New("the request signature does not match")
	errSignatureSkew      = errors.New("the request time is too far from the server time")
)

// sigV4Request is everything the Authorization header declares.
type sigV4Request struct {
	AccessKeyID   string
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
	Timestamp     time.Time
	PayloadHash   string
}

func (r sigV4Request) scope() string {
	return strings.Join([]string{r.Date, r.Region, r.Service, sigV4Terminator}, "/")
}

// parseSigV4Request reads the Authorization and date headers without trusting either.
func parseSigV4Request(r *http.Request) (sigV4Request, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authorization, sigV4Algorithm+" ") {
		return sigV4Request{}, errSignatureMalformed
	}
	request := sigV4Request{}
	for _, part := range strings.Split(strings.TrimPrefix(authorization, sigV4Algorithm+" "), ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			return sigV4Request{}, errSignatureMalformed
		}
		switch key {
		case "Credential":
			fields := strings.Split(value, "/")
			if len(fields) != 5 || fields[4] != sigV4Terminator {
				return sigV4Request{}, errSignatureMalformed
			}
			request.AccessKeyID, request.Date, request.Region, request.Service = fields[0], fields[1], fields[2], fields[3]
		case "SignedHeaders":
			request.SignedHeaders = strings.Split(strings.ToLower(value), ";")
		case "Signature":
			request.Signature = strings.ToLower(value)
		}
	}
	if request.AccessKeyID == "" || request.Signature == "" || len(request.SignedHeaders) == 0 || request.Service != sigV4Service {
		return sigV4Request{}, errSignatureMalformed
	}
	stamp := strings.TrimSpace(r.Header.Get("X-Amz-Date"))
	if stamp == "" {
		stamp = strings.TrimSpace(r.Header.Get("Date"))
	}
	timestamp, err := time.Parse(sigV4TimeFormat, stamp)
	if err != nil {
		return sigV4Request{}, errSignatureMalformed
	}
	request.Timestamp = timestamp
	if timestamp.UTC().Format(sigV4DateFormat) != request.Date {
		return sigV4Request{}, errSignatureMalformed
	}
	request.PayloadHash = strings.TrimSpace(r.Header.Get("X-Amz-Content-Sha256"))
	if request.PayloadHash == "" {
		request.PayloadHash = unsignedPayload
	}
	return request, nil
}

// verifySigV4 recomputes the signature of an arrived request from the secret the broker minted.
func verifySigV4(r *http.Request, request sigV4Request, secret string, now time.Time) error {
	if difference := now.Sub(request.Timestamp); difference > sigV4MaximumSkew || difference < -sigV4MaximumSkew {
		return errSignatureSkew
	}
	canonical, err := canonicalRequest(r, request)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(canonical))
	toSign := strings.Join([]string{sigV4Algorithm, request.Timestamp.UTC().Format(sigV4TimeFormat),
		request.scope(), hex.EncodeToString(digest[:])}, "\n")
	expected := hex.EncodeToString(sigV4Sign(sigV4SigningKey(secret, request), toSign))
	if !hmac.Equal([]byte(expected), []byte(request.Signature)) {
		return errSignatureMismatch
	}
	return nil
}

func canonicalRequest(r *http.Request, request sigV4Request) (string, error) {
	headers, signed, err := canonicalHeaders(r, request.SignedHeaders)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		r.Method,
		canonicalURI(r),
		canonicalQuery(r.URL),
		headers,
		signed,
		request.PayloadHash,
	}, "\n"), nil
}

// canonicalURI is the path exactly as the client encoded it, because S3 signs the sent form.
func canonicalURI(r *http.Request) string {
	escaped := r.URL.EscapedPath()
	if escaped == "" {
		return "/"
	}
	return escaped
}

func canonicalQuery(u *url.URL) string {
	values := u.Query()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(values))
	for _, key := range keys {
		entries := append([]string(nil), values[key]...)
		sort.Strings(entries)
		for _, value := range entries {
			parts = append(parts, uriEncode(key, true)+"="+uriEncode(value, true))
		}
	}
	return strings.Join(parts, "&")
}

func canonicalHeaders(r *http.Request, signed []string) (string, string, error) {
	names := append([]string(nil), signed...)
	sort.Strings(names)
	builder := strings.Builder{}
	for _, name := range names {
		value := ""
		switch name {
		case "host":
			value = r.Host
		case "content-length":
			value = strconv.FormatInt(r.ContentLength, 10)
		default:
			values := r.Header.Values(http.CanonicalHeaderKey(name))
			if len(values) == 0 {
				return "", "", errSignatureMalformed
			}
			trimmed := make([]string, 0, len(values))
			for _, entry := range values {
				trimmed = append(trimmed, collapseSpaces(entry))
			}
			value = strings.Join(trimmed, ",")
		}
		builder.WriteString(name + ":" + value + "\n")
	}
	return builder.String(), strings.Join(names, ";"), nil
}

func collapseSpaces(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

// uriEncode follows RFC 3986 as AWS specifies it rather than Go's form encoding.
func uriEncode(value string, encodeSlash bool) string {
	builder := strings.Builder{}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			builder.WriteByte(c)
		case c == '/' && !encodeSlash:
			builder.WriteByte('/')
		default:
			builder.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return builder.String()
}

func sigV4SigningKey(secret string, request sigV4Request) []byte {
	key := sigV4Sign([]byte("AWS4"+secret), request.Date)
	key = sigV4Sign(key, request.Region)
	key = sigV4Sign(key, request.Service)
	return sigV4Sign(key, sigV4Terminator)
}

func sigV4Sign(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

// payloadExpectation reports the digest the body must have, and whether the body arrives in
// the aws-chunked framing the AWS SDKs use when they stream a signed payload.
func payloadExpectation(hash string) (digest string, chunked bool) {
	switch hash {
	case unsignedPayload, "", streamingUnsigned:
		return "", hash == streamingUnsigned
	case streamingSignedBody, streamingSignedTrail:
		return "", true
	}
	if len(hash) == 64 && isHex(hash) {
		return strings.ToLower(hash), false
	}
	return "", false
}

func isHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

// chunkedPayloadReader decodes the aws-chunked framing and, when the client signed each chunk,
// verifies the chunk signature chain seeded by the request signature.
//
// One chunk is held at a time. The AWS SDKs send 64 KiB chunks; a declared chunk beyond
// maximumUploadChunkBytes is refused rather than allocated.
type chunkedPayloadReader struct {
	source     *bufio.Reader
	signingKey []byte
	scope      string
	timestamp  string
	previous   string
	verify     bool
	pending    []byte
	finished   bool
}

const maximumUploadChunkBytes = 32 << 20

func newChunkedPayloadReader(body io.Reader, request sigV4Request, secret string) *chunkedPayloadReader {
	reader := &chunkedPayloadReader{source: bufio.NewReader(body), previous: request.Signature,
		scope: request.scope(), timestamp: request.Timestamp.UTC().Format(sigV4TimeFormat),
		verify: request.PayloadHash == streamingSignedBody || request.PayloadHash == streamingSignedTrail}
	if reader.verify {
		reader.signingKey = sigV4SigningKey(secret, request)
	}
	return reader
}

func (c *chunkedPayloadReader) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.finished {
			return 0, io.EOF
		}
		if err := c.nextChunk(); err != nil {
			return 0, err
		}
	}
	read := copy(p, c.pending)
	c.pending = c.pending[read:]
	return read, nil
}

func (c *chunkedPayloadReader) nextChunk() error {
	line, err := c.source.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read chunked upload: %w", err)
	}
	header, signature, _ := strings.Cut(strings.TrimRight(line, "\r\n"), ";chunk-signature=")
	size, err := strconv.ParseInt(strings.TrimSpace(header), 16, 64)
	if err != nil || size < 0 || size > maximumUploadChunkBytes {
		return errors.New("malformed chunked upload")
	}
	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(c.source, payload); err != nil {
			return fmt.Errorf("read chunked upload: %w", err)
		}
	}
	if c.verify {
		if err := c.verifyChunk(payload, signature); err != nil {
			return err
		}
	}
	if size == 0 {
		// The terminating chunk is followed by optional trailers the gateway does not use.
		c.finished = true
		return nil
	}
	if err := c.consumeCRLF(); err != nil {
		return err
	}
	c.pending = payload
	return nil
}

func (c *chunkedPayloadReader) verifyChunk(payload []byte, signature string) error {
	digest := sha256.Sum256(payload)
	toSign := strings.Join([]string{sigV4ChunkAlgorithm, c.timestamp, c.scope, c.previous,
		emptyPayloadSHA256, hex.EncodeToString(digest[:])}, "\n")
	expected := hex.EncodeToString(sigV4Sign(c.signingKey, toSign))
	if !hmac.Equal([]byte(expected), []byte(strings.ToLower(strings.TrimSpace(signature)))) {
		return errSignatureMismatch
	}
	c.previous = expected
	return nil
}

func (c *chunkedPayloadReader) consumeCRLF() error {
	for range 2 {
		if _, err := c.source.ReadByte(); err != nil {
			return fmt.Errorf("read chunked upload: %w", err)
		}
	}
	return nil
}
