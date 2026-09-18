package broker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const testStoragePepper = "filesystem-storage-pepper-of-sufficient-length"

func testFilesystemRoute(t *testing.T) S3RouteConfig {
	t.Helper()
	return S3RouteConfig{Driver: storageDriverFilesystem, Region: "us-east-1", Bucket: "graphit-artifacts",
		BasePrefix: "graphit", Directory: t.TempDir(), Endpoint: "http://127.0.0.1", SessionDuration: time.Hour,
		MaxObjectBytes: 1 << 20}
}

// newFilesystemStorageFixture starts the gateway alone so a test drives it with the same AWS
// client a Graphit installation uses.
func newFilesystemStorageFixture(t *testing.T, route S3RouteConfig) (*httptest.Server, *FilesystemCredentialService) {
	t.Helper()
	handler, credentials := newFilesystemStorageHandler(t, route)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, credentials
}

func newFilesystemStorageHandler(t *testing.T, route S3RouteConfig) (http.Handler, *FilesystemCredentialService) {
	t.Helper()
	cfg := Config{}
	cfg.Services.S3 = S3ServiceConfig{Enabled: true, DefaultRoute: "local", Routes: map[string]S3RouteConfig{"local": route}}
	credentials := NewFilesystemCredentialService(testStoragePepper)
	gateway, err := newStorageGateway(cfg, credentials)
	if err != nil {
		t.Fatal(err)
	}
	if gateway == nil {
		t.Fatal("the filesystem route did not produce a gateway")
	}
	mux := http.NewServeMux()
	gateway.register(mux)
	return mux, credentials
}

func issueTestCredentials(t *testing.T, credentials *FilesystemCredentialService, route S3RouteConfig, access map[string][]string, project string) S3CredentialsResponse {
	t.Helper()
	grant := S3SessionGrant{Revision: "7", Route: "local", Access: access,
		Scope: S3SessionScope{Kind: "project", ProjectID: project}}
	response, err := credentials.Issue(context.Background(), route, grant, Principal{Issuer: "https://id", Subject: "alice", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func newTestS3Client(t *testing.T, endpoint string, response S3CredentialsResponse) *s3.Client {
	t.Helper()
	return s3.New(s3.Options{
		Region:       response.Region,
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
		Credentials: awscredentials.NewStaticCredentialsProvider(response.AccessKeyID,
			response.SecretAccessKey, response.SessionToken),
	})
}

func TestFilesystemStorageServesTheObjectContractGraphitClientsUse(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	response := issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a")
	if response.Endpoint != route.Endpoint || response.Bucket != route.Bucket || len(response.Prefixes) != 1 || response.Prefixes[0] != "graphit" {
		t.Fatalf("credential topology=%#v", response)
	}
	client := newTestS3Client(t, server.URL, response)
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/index/manifest.json"

	put, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		Body: bytes.NewReader([]byte(`{"format":"icebug"}`))})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(put.ETag) == "" {
		t.Fatal("PutObject returned no ETag")
	}
	get, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if string(body) != `{"format":"icebug"}` || aws.ToString(get.ETag) != aws.ToString(put.ETag) {
		t.Fatalf("body=%q etag=%q", body, aws.ToString(get.ETag))
	}
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &route.Bucket, Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToInt64(head.ContentLength) != int64(len(body)) {
		t.Fatalf("head=%#v", head)
	}
	ranged, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		Range: aws.String("bytes=1-7")})
	if err != nil {
		t.Fatal(err)
	}
	partial, _ := io.ReadAll(ranged.Body)
	_ = ranged.Body.Close()
	if string(partial) != `"format` {
		t.Fatalf("ranged read=%q", partial)
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &route.Bucket, Key: aws.String(key)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &route.Bucket, Key: aws.String(key)}); err == nil {
		t.Fatal("the deleted object is still readable")
	}
}

func TestFilesystemStorageEnforcesConditionalWrites(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	client := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a"))
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/catalog.json"

	created, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		Body: bytes.NewReader([]byte("first")), IfNoneMatch: aws.String("*")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		Body: bytes.NewReader([]byte("second")), IfNoneMatch: aws.String("*")}); !isPreconditionFailure(err) {
		t.Fatalf("a create over an existing key returned %v", err)
	}
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		Body: bytes.NewReader([]byte("second")), IfMatch: aws.String(`"not-the-current-etag"`)}); !isPreconditionFailure(err) {
		t.Fatalf("a stale compare-and-swap returned %v", err)
	}
	replaced, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		Body: bytes.NewReader([]byte("second")), IfMatch: created.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(replaced.ETag) == aws.ToString(created.ETag) {
		t.Fatal("replacing the object did not change its ETag")
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		IfMatch: created.ETag}); !isPreconditionFailure(err) {
		t.Fatalf("a stale conditional delete returned %v", err)
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
		IfMatch: replaced.ETag}); err != nil {
		t.Fatal(err)
	}
}

func isPreconditionFailure(err error) bool {
	var api interface{ ErrorCode() string }
	return err != nil && errors.As(err, &api) &&
		(api.ErrorCode() == "PreconditionFailed" || api.ErrorCode() == "412")
}

func isAccessDenied(err error) bool {
	var api interface{ ErrorCode() string }
	return err != nil && errors.As(err, &api) && api.ErrorCode() == "AccessDenied"
}

func TestFilesystemStorageListsPagesAndGroupsByDelimiter(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	client := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a"))
	ctx := context.Background()
	root := "graphit/v2/projects/project-a/"
	for _, suffix := range []string{"a.txt", "index/one.parquet", "index/two.parquet", "memory/notes.md"} {
		if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket,
			Key: aws.String(root + suffix), Body: bytes.NewReader([]byte(suffix))}); err != nil {
			t.Fatal(err)
		}
	}
	listing, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &route.Bucket, Prefix: aws.String(root)})
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(listing.Contents))
	for _, object := range listing.Contents {
		keys = append(keys, strings.TrimPrefix(aws.ToString(object.Key), root))
	}
	// S3 orders by key bytes, where "." sorts before "/": a full walk must not report the
	// directory contents first just because the directory entry sorts first on disk.
	if strings.Join(keys, ",") != "a.txt,index/one.parquet,index/two.parquet,memory/notes.md" {
		t.Fatalf("keys=%v", keys)
	}
	grouped, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &route.Bucket,
		Prefix: aws.String(root), Delimiter: aws.String("/")})
	if err != nil {
		t.Fatal(err)
	}
	if len(grouped.Contents) != 1 || aws.ToString(grouped.Contents[0].Key) != root+"a.txt" {
		t.Fatalf("grouped contents=%#v", grouped.Contents)
	}
	prefixes := make([]string, 0, len(grouped.CommonPrefixes))
	for _, prefix := range grouped.CommonPrefixes {
		prefixes = append(prefixes, strings.TrimPrefix(aws.ToString(prefix.Prefix), root))
	}
	if strings.Join(prefixes, ",") != "index/,memory/" {
		t.Fatalf("common prefixes=%v", prefixes)
	}

	page, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &route.Bucket,
		Prefix: aws.String(root), MaxKeys: aws.Int32(2)})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Contents) != 2 || !aws.ToBool(page.IsTruncated) || aws.ToString(page.NextContinuationToken) == "" {
		t.Fatalf("first page=%#v", page)
	}
	rest, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &route.Bucket,
		Prefix: aws.String(root), ContinuationToken: page.NextContinuationToken})
	if err != nil {
		t.Fatal(err)
	}
	if len(rest.Contents) != 2 || aws.ToBool(rest.IsTruncated) ||
		aws.ToString(rest.Contents[0].Key) != root+"index/two.parquet" {
		t.Fatalf("second page=%#v", rest)
	}

	deleted, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &route.Bucket,
		Delete: &s3types.Delete{Objects: []s3types.ObjectIdentifier{
			{Key: aws.String(root + "index/one.parquet")}, {Key: aws.String(root + "index/two.parquet")}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.Deleted) != 2 || len(deleted.Errors) != 0 {
		t.Fatalf("batch delete=%#v", deleted)
	}
	remaining, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &route.Bucket, Prefix: aws.String(root)})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Contents) != 2 {
		t.Fatalf("remaining=%#v", remaining.Contents)
	}
	// An emptied directory leaves nothing behind that a delimited listing would report.
	if _, err := os.Stat(filepath.Join(route.Directory, filesystemDataDirectory, root+"index")); !os.IsNotExist(err) {
		t.Fatalf("the emptied directory survived: %v", err)
	}
}

func TestFilesystemStorageConfinesASessionToItsIssuedPrefixes(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	ctx := context.Background()
	publisher := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a"))
	if _, err := publisher.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket,
		Key: aws.String("graphit/v2/projects/project-a/own.txt"), Body: bytes.NewReader([]byte("mine"))}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"graphit/v2/projects/project-b/other.txt",
		"graphit/v2/users/bob/memory/notes.md",
		"other-root/v2/projects/project-a/escape.txt",
		"graphit/v2/projects/project-a-evil/lookalike.txt",
	} {
		if _, err := publisher.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: aws.String(key),
			Body: bytes.NewReader([]byte("x"))}); !isAccessDenied(err) {
			t.Fatalf("writing %s returned %v", key, err)
		}
		if _, err := publisher.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)}); !isAccessDenied(err) {
			t.Fatalf("reading %s returned %v", key, err)
		}
	}
	if _, err := publisher.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &route.Bucket}); !isAccessDenied(err) {
		t.Fatal("an unscoped listing was allowed")
	}

	reader := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"read": {"v2/projects/project-a"}}, "project-a"))
	if _, err := reader.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket,
		Key: aws.String("graphit/v2/projects/project-a/own.txt")}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket,
		Key: aws.String("graphit/v2/projects/project-a/own.txt"), Body: bytes.NewReader([]byte("x"))}); !isAccessDenied(err) {
		t.Fatalf("a read-only session wrote an object: %v", err)
	}
	if _, err := reader.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &route.Bucket,
		Key: aws.String("graphit/v2/projects/project-a/own.txt")}); !isAccessDenied(err) {
		t.Fatalf("a read-only session deleted an object: %v", err)
	}
}

func TestFilesystemStorageRejectsForgedExpiredAndForeignCredentials(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	issued := issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a")
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/probe.txt"

	forgedSecret := issued
	forgedSecret.SecretAccessKey = "not-the-minted-secret"
	if _, err := newTestS3Client(t, server.URL, forgedSecret).GetObject(ctx,
		&s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)}); err == nil {
		t.Fatal("a wrong secret was accepted")
	}

	// The token carries the authorization snapshot, so widening it must break its signature.
	widened := issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-b"}}, "project-b")
	mixed := issued
	mixed.SessionToken = widened.SessionToken
	if _, err := newTestS3Client(t, server.URL, mixed).GetObject(ctx,
		&s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)}); err == nil {
		t.Fatal("a session token from another credential set was accepted")
	}

	expired := NewFilesystemCredentialService(testStoragePepper)
	expired.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	stale := issueTestCredentials(t, expired, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a")
	if _, err := newTestS3Client(t, server.URL, stale).GetObject(ctx,
		&s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)}); err == nil {
		t.Fatal("an expired session was accepted")
	}

	foreign := NewFilesystemCredentialService("a-different-broker-token-pepper-value")
	other := issueTestCredentials(t, foreign, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a")
	if _, err := newTestS3Client(t, server.URL, other).GetObject(ctx,
		&s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)}); err == nil {
		t.Fatal("a session minted with another pepper was accepted")
	}

	unsigned, err := http.Get(server.URL + "/" + route.Bucket + "/" + key)
	if err != nil {
		t.Fatal(err)
	}
	defer unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusForbidden && unsigned.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unsigned request returned %d", unsigned.StatusCode)
	}
}

func TestFilesystemStoreRejectsUnstorableKeysAndOversizeObjects(t *testing.T) {
	route := testFilesystemRoute(t)
	route.MaxObjectBytes = 16
	store, err := newFilesystemStore(route)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "/leading", "trailing/", "a//b", "../escape", "a/../../escape", strings.Repeat("k", 1025)} {
		if _, err := store.Put(key, strings.NewReader("x"), "", "", putConditions{}); !errors.Is(err, errStorageInvalidKey) {
			t.Fatalf("key %q returned %v", key, err)
		}
	}
	if _, err := store.Put("fits", strings.NewReader(strings.Repeat("x", 16)), "", "", putConditions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("too-big", strings.NewReader(strings.Repeat("x", 17)), "", "", putConditions{}); !errors.Is(err, errStorageTooLarge) {
		t.Fatalf("an oversize object returned %v", err)
	}
	if _, err := store.Head("too-big"); !errors.Is(err, errStorageNotFound) {
		t.Fatal("a refused upload became an object")
	}
	if _, err := store.Put("digest", strings.NewReader("payload"), "", strings.Repeat("a", 64), putConditions{}); !errors.Is(err, errStorageBadDigest) {
		t.Fatal("a payload that contradicts its signed digest was stored")
	}
}

func TestFilesystemStoreRepairsMetadataForObjectsPlacedOnTheVolume(t *testing.T) {
	route := testFilesystemRoute(t)
	store, err := newFilesystemStore(route)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(route.Directory, filesystemDataDirectory, "seeded", "file.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"seeded":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	object, err := store.Head("seeded/file.json")
	if err != nil {
		t.Fatal(err)
	}
	// The ETag of an object the broker never wrote is still the digest of its content.
	if object.ETag != `"12f9c0fb0b9880f1a47bceb61538a12f"` || object.Size != 15 {
		t.Fatalf("object=%#v", object)
	}
	if object.ContentType != "application/json" {
		t.Fatalf("content type=%q", object.ContentType)
	}
	if _, err := os.Stat(store.metaPath("seeded/file.json")); err != nil {
		t.Fatalf("the sidecar was not written: %v", err)
	}
}

// The AWS SDKs frame an upload as aws-chunked when they attach a trailing checksum, which is
// what a plain-HTTP deployment produces. The gateway must strip that framing rather than store
// it, so this records how the client signed and compares what reached the volume.
func TestFilesystemStorageDecodesTheChunkedUploadFramingTheAWSSDKSends(t *testing.T) {
	route := testFilesystemRoute(t)
	handler, credentials := newFilesystemStorageHandler(t, route)
	declared := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			declared = r.Header.Get("X-Amz-Content-Sha256")
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()

	client := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a"))
	key := "graphit/v2/projects/project-a/chunked.bin"
	payload := bytes.Repeat([]byte("graphit"), 40000)
	if _, err := client.PutObject(context.Background(), &s3.PutObjectInput{Bucket: &route.Bucket,
		Key: aws.String(key), Body: bytes.NewReader(payload)}); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(route.Directory, filesystemDataDirectory, filepath.FromSlash(key)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("stored %d bytes of %d: the upload framing was not decoded", len(stored), len(payload))
	}
	if !strings.HasPrefix(declared, "STREAMING-") {
		t.Skipf("this SDK signed the upload as %q, so the chunked path was not exercised by it", declared)
	}
}

// A client that cannot rewind its body streams the upload in the aws-chunked framing with a
// trailing checksum instead of a payload digest. The gateway has to unwrap that framing, so
// this drives the exact wire form with the AWS signer rather than a hand-made signature.
func TestFilesystemStorageAcceptsAStreamingChunkedUpload(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	issued := issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a")
	key := "graphit/v2/projects/project-a/streamed.bin"
	payload := bytes.Repeat([]byte("ladybug"), 20000)

	framed := &bytes.Buffer{}
	for offset := 0; offset < len(payload); offset += 65536 {
		chunk := payload[offset:min(offset+65536, len(payload))]
		framed.WriteString(strconv.FormatInt(int64(len(chunk)), 16) + "\r\n")
		framed.Write(chunk)
		framed.WriteString("\r\n")
	}
	framed.WriteString("0\r\n")
	framed.WriteString("x-amz-checksum-crc32:AAAAAA==\r\n\r\n")

	request, err := http.NewRequest(http.MethodPut, server.URL+"/"+route.Bucket+"/"+key, bytes.NewReader(framed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Encoding", "aws-chunked")
	request.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(payload)))
	request.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
	request.Header.Set("X-Amz-Content-Sha256", streamingUnsigned)
	request.Header.Set("X-Amz-Security-Token", issued.SessionToken)
	signer := v4.NewSigner()
	if err := signer.SignHTTP(context.Background(), aws.Credentials{AccessKeyID: issued.AccessKeyID,
		SecretAccessKey: issued.SecretAccessKey, SessionToken: issued.SessionToken},
		request, streamingUnsigned, "s3", route.Region, time.Now()); err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	stored, err := os.ReadFile(filepath.Join(route.Directory, filesystemDataDirectory, filepath.FromSlash(key)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("stored %d bytes of %d: the chunk framing reached the volume", len(stored), len(payload))
	}
}

// The older streaming form signs every chunk in a chain seeded by the request signature. The
// chunk signatures here come from the AWS stream signer, so the chain the gateway verifies is
// the one an AWS client produces.
func TestFilesystemStorageVerifiesSignedUploadChunks(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	issued := issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a")
	awsCredentials := aws.Credentials{AccessKeyID: issued.AccessKeyID,
		SecretAccessKey: issued.SecretAccessKey, SessionToken: issued.SessionToken}
	key := "graphit/v2/projects/project-a/signed-chunks.bin"
	payload := bytes.Repeat([]byte("icebug"), 30000)
	signedAt := time.Now()

	chunks := [][]byte{}
	for offset := 0; offset < len(payload); offset += 65536 {
		chunks = append(chunks, payload[offset:min(offset+65536, len(payload))])
	}
	chunks = append(chunks, nil)
	// Every chunk signature is 64 hexadecimal characters, so the framed length is known before
	// the seed signature that the framing itself depends on.
	framedLength := 0
	for _, chunk := range chunks {
		framedLength += len(strconv.FormatInt(int64(len(chunk)), 16)) + len(";chunk-signature=") + 64 + 2 + len(chunk) + 2
	}

	newSignedRequest := func() *http.Request {
		request, err := http.NewRequest(http.MethodPut, server.URL+"/"+route.Bucket+"/"+key, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.ContentLength = int64(framedLength)
		request.Header.Set("Content-Encoding", "aws-chunked")
		request.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(payload)))
		request.Header.Set("X-Amz-Content-Sha256", streamingSignedBody)
		request.Header.Set("X-Amz-Security-Token", issued.SessionToken)
		if err := v4.NewSigner().SignHTTP(context.Background(), awsCredentials, request,
			streamingSignedBody, "s3", route.Region, signedAt); err != nil {
			t.Fatal(err)
		}
		return request
	}
	authorization := newSignedRequest().Header.Get("Authorization")
	seed, err := hex.DecodeString(authorization[strings.Index(authorization, "Signature=")+len("Signature="):])
	if err != nil {
		t.Fatal(err)
	}
	frame := func(corrupt bool) []byte {
		streamSigner := v4.NewStreamSigner(awsCredentials, "s3", route.Region, seed)
		framed := &bytes.Buffer{}
		for _, chunk := range chunks {
			signature, err := streamSigner.GetSignature(context.Background(), nil, chunk, signedAt)
			if err != nil {
				t.Fatal(err)
			}
			if corrupt {
				signature[0] ^= 0xff
			}
			framed.WriteString(strconv.FormatInt(int64(len(chunk)), 16) + ";chunk-signature=" + hex.EncodeToString(signature) + "\r\n")
			framed.Write(chunk)
			framed.WriteString("\r\n")
		}
		return framed.Bytes()
	}
	send := func(framed []byte) *http.Response {
		if len(framed) != framedLength {
			t.Fatalf("framed %d bytes but signed %d", len(framed), framedLength)
		}
		request := newSignedRequest()
		request.Body = io.NopCloser(bytes.NewReader(framed))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	response := send(frame(false))
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	stored, err := os.ReadFile(filepath.Join(route.Directory, filesystemDataDirectory, filepath.FromSlash(key)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("stored %d bytes of %d", len(stored), len(payload))
	}

	tampered := send(frame(true))
	_ = tampered.Body.Close()
	if tampered.StatusCode == http.StatusOK {
		t.Fatal("an upload with a broken chunk signature chain was accepted")
	}
}

// The complete path a Graphit installation takes: ask the broker for project credentials, then
// use them against the storage the same broker serves.
func TestBrokerIssuedCredentialsOpenItsOwnFilesystemStorage(t *testing.T) {
	route := testFilesystemRoute(t)
	cfg := Config{}
	cfg.Authentication.TokenPepper = testStoragePepper
	cfg.Server.MaxRequestBytes = 1 << 20
	cfg.Services.S3 = S3ServiceConfig{Enabled: true, DefaultRoute: "local",
		Routes: map[string]S3RouteConfig{"local": route}}
	filesystem := NewFilesystemCredentialService(testStoragePepper)
	gateway, err := newStorageGateway(cfg, filesystem)
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{Issuer: "https://id", Subject: "s", Username: "alice", Organization: "acme", Teams: []string{"platform"}}
	runtime := &runtimeState{config: cfg, ai: NewAIService(cfg.Services), storage: gateway,
		authenticator: authFunc(func(_ context.Context, token string) (Principal, error) {
			if token != "valid" {
				return Principal{}, ErrUnauthenticated
			}
			return principal, nil
		}),
		acl:           NewACL(&resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: defaultTestRules()}}),
		s3Credentials: routedS3CredentialService{sts: NewAWSSTSCredentialService(), filesystem: filesystem},
	}
	broker, err := newServerFromRuntime(runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(broker)
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/s3/credentials",
		strings.NewReader(`{"scope":"project","project_id":"project-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer valid")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	var issued S3CredentialsResponse
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		t.Fatal(err)
	}
	if issued.Endpoint != route.Endpoint || issued.Bucket != route.Bucket || issued.Scope != "project" ||
		issued.ProjectID != "project-a" || issued.AuthorizationRevision != "1" || issued.SessionToken == "" {
		t.Fatalf("credentials=%#v", issued)
	}
	if !issued.ExpiresAt.After(time.Now()) {
		t.Fatalf("expires_at=%s", issued.ExpiresAt)
	}

	client := newTestS3Client(t, server.URL, issued)
	key := "graphit/v2/projects/project-a/wiki/page.md"
	if _, err := client.PutObject(context.Background(), &s3.PutObjectInput{Bucket: &route.Bucket,
		Key: aws.String(key), Body: bytes.NewReader([]byte("# page"))}); err != nil {
		t.Fatal(err)
	}
	stored, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(stored.Body)
	_ = stored.Body.Close()
	if string(body) != "# page" {
		t.Fatalf("body=%q", body)
	}
	// The grant covers project-a only, whichever broker route the client asks through.
	if _, err := client.PutObject(context.Background(), &s3.PutObjectInput{Bucket: &route.Bucket,
		Key: aws.String("graphit/v2/projects/project-b/page.md"), Body: bytes.NewReader([]byte("x"))}); !isAccessDenied(err) {
		t.Fatalf("a foreign project write returned %v", err)
	}
}

// The Hub relies on the conditional write being a real compare-and-swap: concurrent writers of
// the same key must not both believe they created or replaced it.
func TestFilesystemStoreSerializesConcurrentConditionalWrites(t *testing.T) {
	store, err := newFilesystemStore(testFilesystemRoute(t))
	if err != nil {
		t.Fatal(err)
	}
	const writers = 16
	creations := make(chan error, writers)
	start := make(chan struct{})
	for i := range writers {
		go func() {
			<-start
			_, err := store.Put("catalog.json", strings.NewReader(strconv.Itoa(i)), "", "",
				putConditions{IfNoneMatch: "*"})
			creations <- err
		}()
	}
	close(start)
	created := 0
	for range writers {
		switch err := <-creations; {
		case err == nil:
			created++
		case errors.Is(err, errStoragePrecondition):
		default:
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatalf("%d writers created the same key", created)
	}

	current, err := store.Head("catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	replacements := make(chan error, writers)
	for i := range writers {
		go func() {
			_, err := store.Put("catalog.json", strings.NewReader("replacement "+strconv.Itoa(i)), "", "",
				putConditions{IfMatch: current.ETag})
			replacements <- err
		}()
	}
	replaced := 0
	for range writers {
		switch err := <-replacements; {
		case err == nil:
			replaced++
		case errors.Is(err, errStoragePrecondition):
		default:
			t.Fatal(err)
		}
	}
	if replaced != 1 {
		t.Fatalf("%d writers replaced the same version", replaced)
	}
}

// A client that cannot buffer a whole object uploads it in parts: LanceDB starts a multipart
// upload for any data file past 5 MiB, so a store without this cannot hold a dataset.
func TestFilesystemStorageServesMultipartUpload(t *testing.T) {
	route := testFilesystemRoute(t)
	route.MaxObjectBytes = 32 << 20
	server, credentials := newFilesystemStorageFixture(t, route)
	client := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a"))
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/index/graph.lance"

	started, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &route.Bucket, Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	chunks := [][]byte{bytes.Repeat([]byte("a"), 5<<20), bytes.Repeat([]byte("b"), 5<<20), []byte("tail")}
	completed := make([]s3types.CompletedPart, 0, len(chunks))
	for i, chunk := range chunks {
		part, err := client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &route.Bucket, Key: aws.String(key),
			UploadId: started.UploadId, PartNumber: aws.Int32(int32(i + 1)), Body: bytes.NewReader(chunk)})
		if err != nil {
			t.Fatal(err)
		}
		completed = append(completed, s3types.CompletedPart{ETag: part.ETag, PartNumber: aws.Int32(int32(i + 1))})
	}
	listed, err := client.ListParts(ctx, &s3.ListPartsInput{Bucket: &route.Bucket, Key: aws.String(key),
		UploadId: started.UploadId})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Parts) != 3 || aws.ToInt64(listed.Parts[0].Size) != 5<<20 {
		t.Fatalf("listed parts=%#v", listed.Parts)
	}
	if _, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &route.Bucket, Key: aws.String(key), UploadId: started.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: completed}}); err != nil {
		t.Fatal(err)
	}
	stored, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(stored.Body)
	_ = stored.Body.Close()
	if !bytes.Equal(body, bytes.Join(chunks, nil)) {
		t.Fatalf("assembled %d bytes of %d", len(body), len(bytes.Join(chunks, nil)))
	}
	// Nothing of the upload survives its completion.
	if entries, err := os.ReadDir(filepath.Join(route.Directory, filesystemUploadDirectory)); err != nil || len(entries) != 0 {
		t.Fatalf("staging entries=%v err=%v", entries, err)
	}

	// An aborted upload leaves no object and no parts.
	aborted, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &route.Bucket, Key: aws.String(key + ".aborted")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &route.Bucket, Key: aws.String(key + ".aborted"),
		UploadId: aborted.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("x"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &route.Bucket,
		Key: aws.String(key + ".aborted"), UploadId: aborted.UploadId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &route.Bucket, Key: aws.String(key + ".aborted")}); err == nil {
		t.Fatal("an aborted upload produced an object")
	}
	if entries, err := os.ReadDir(filepath.Join(route.Directory, filesystemUploadDirectory)); err != nil || len(entries) != 0 {
		t.Fatalf("an aborted upload left %v", entries)
	}
}

func TestFilesystemStorageRefusesMisdirectedAndCorruptUploads(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	client := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a"))
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/index/graph.lance"
	started, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &route.Bucket, Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	part, err := client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &route.Bucket, Key: aws.String(key),
		UploadId: started.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("payload"))})
	if err != nil {
		t.Fatal(err)
	}
	// The upload belongs to one key: it cannot be redirected onto another one.
	if _, err := client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &route.Bucket,
		Key: aws.String("graphit/v2/projects/project-a/elsewhere.lance"), UploadId: started.UploadId,
		PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("x"))}); err == nil {
		t.Fatal("a part was accepted for another key")
	}
	if _, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &route.Bucket,
		Key: aws.String("graphit/v2/projects/project-b/graph.lance")}); !isAccessDenied(err) {
		t.Fatalf("an upload outside the granted prefix returned %v", err)
	}
	// A completion that quotes an ETag the store never issued is a corrupt upload.
	if _, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &route.Bucket, Key: aws.String(key), UploadId: started.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{
			{ETag: aws.String(`"00000000000000000000000000000000"`), PartNumber: aws.Int32(1)}}}}); err == nil {
		t.Fatal("a completion with a wrong part ETag was accepted")
	}
	if _, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &route.Bucket, Key: aws.String(key), UploadId: started.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{
			{ETag: part.ETag, PartNumber: aws.Int32(2)}}}}); err == nil {
		t.Fatal("a completion naming a part that was never uploaded was accepted")
	}
}

func TestFilesystemStorageCopiesInsideTheBucketUnderBothGrants(t *testing.T) {
	route := testFilesystemRoute(t)
	server, credentials := newFilesystemStorageFixture(t, route)
	client := newTestS3Client(t, server.URL, issueTestCredentials(t, credentials, route,
		map[string][]string{"publish": {"v2/projects/project-a"}}, "project-a"))
	ctx := context.Background()
	source := "graphit/v2/projects/project-a/manifest.json"
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: aws.String(source),
		Body: bytes.NewReader([]byte(`{"version":1}`))}); err != nil {
		t.Fatal(err)
	}
	destination := "graphit/v2/projects/project-a/versions/1/manifest.json"
	if _, err := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &route.Bucket,
		Key: aws.String(destination), CopySource: aws.String(route.Bucket + "/" + source)}); err != nil {
		t.Fatal(err)
	}
	copied, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: aws.String(destination)})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(copied.Body)
	_ = copied.Body.Close()
	if string(body) != `{"version":1}` {
		t.Fatalf("copied body=%q", body)
	}
	// Both ends of a copy are authorized, so neither can reach outside the grant.
	if _, err := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &route.Bucket,
		Key:        aws.String("graphit/v2/projects/project-b/manifest.json"),
		CopySource: aws.String(route.Bucket + "/" + source)}); !isAccessDenied(err) {
		t.Fatalf("a copy into another project returned %v", err)
	}
	if _, err := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &route.Bucket,
		Key:        aws.String(destination),
		CopySource: aws.String(route.Bucket + "/graphit/v2/projects/project-b/manifest.json")}); !isAccessDenied(err) {
		t.Fatalf("a copy out of another project returned %v", err)
	}
}

// Parts of an upload nobody finished are the one thing on the volume with no object to belong
// to, so this pins when they are collected: on restart and when the next upload begins, never
// while the upload is still receiving parts.
func TestFilesystemStoreCollectsAbandonedUploadsAtStartupAndOnTheNextUpload(t *testing.T) {
	route := testFilesystemRoute(t)
	store, err := newFilesystemStore(route)
	if err != nil {
		t.Fatal(err)
	}
	abandoned, err := store.CreateUpload("stale.bin", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UploadPart(abandoned, "stale.bin", 1, strings.NewReader("staged bytes")); err != nil {
		t.Fatal(err)
	}
	live, err := store.CreateUpload("live.bin", "")
	if err != nil {
		t.Fatal(err)
	}
	// A fresh upload survives a collection that runs while it is open.
	if _, err := store.CreateUpload("other.bin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListUploadParts(live, "live.bin"); err != nil {
		t.Fatalf("an upload opened moments ago was collected: %v", err)
	}

	stale := time.Now().Add(-abandonedUploadLifetime - time.Hour)
	// The collection clock is the upload directory's modification time, and receiving a part
	// has to advance it: otherwise a slow upload would be collected underneath its client.
	if err := os.Chtimes(store.uploadPath(live), stale, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UploadPart(live, "live.bin", 1, strings.NewReader("more bytes")); err != nil {
		t.Fatal(err)
	}
	aged, err := os.Stat(store.uploadPath(live))
	if err != nil {
		t.Fatal(err)
	}
	if !aged.ModTime().After(stale) {
		t.Fatalf("receiving a part left the upload looking %s old", time.Since(aged.ModTime()))
	}

	// Age the abandoned upload past its lifetime.
	if err := os.Chtimes(store.uploadPath(abandoned), stale, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUpload("next.bin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListUploadParts(abandoned, "stale.bin"); !errors.Is(err, errStorageNoSuchUpload) {
		t.Fatalf("beginning an upload did not collect the abandoned one: %v", err)
	}

	// And a restart collects what no later upload would have swept, because a deployment may
	// never start another one.
	second, err := store.CreateUpload("restart.bin", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(store.uploadPath(second), stale, stale); err != nil {
		t.Fatal(err)
	}
	reopened, err := newFilesystemStore(route)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ListUploadParts(second, "restart.bin"); !errors.Is(err, errStorageNoSuchUpload) {
		t.Fatalf("a restart did not collect the abandoned upload: %v", err)
	}
	if _, err := reopened.ListUploadParts(live, "live.bin"); err != nil {
		t.Fatalf("a restart collected an upload a client could still resume: %v", err)
	}
}

// Completion is where the parts stop being needed, and where a refused completion must leave
// them: a client whose conditional write lost a race retries the completion, it does not
// re-upload gigabytes.
func TestFilesystemStoreDiscardsPartsOnCompletionAndKeepsThemWhenItFails(t *testing.T) {
	route := testFilesystemRoute(t)
	store, err := newFilesystemStore(route)
	if err != nil {
		t.Fatal(err)
	}
	staged := func(key string) (string, []completedPart) {
		t.Helper()
		id, err := store.CreateUpload(key, "")
		if err != nil {
			t.Fatal(err)
		}
		parts := make([]completedPart, 0, 2)
		for number, chunk := range []string{"first half ", "second half"} {
			etag, err := store.UploadPart(id, key, number+1, strings.NewReader(chunk))
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, completedPart{Number: number + 1, ETag: etag})
		}
		return id, parts
	}
	openUploads := func() int {
		t.Helper()
		entries, err := os.ReadDir(filepath.Join(route.Directory, filesystemUploadDirectory))
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}

	// A completion that cannot land keeps the parts, and the retry that can land succeeds
	// from them without another byte on the wire.
	id, parts := staged("contested.bin")
	if _, err := store.Put("contested.bin", strings.NewReader("someone else"), "", "", putConditions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteUpload(id, "contested.bin", parts, putConditions{IfNoneMatch: "*"}); !errors.Is(err, errStoragePrecondition) {
		t.Fatalf("a refused completion returned %v", err)
	}
	if openUploads() != 1 {
		t.Fatal("a refused completion discarded the parts the client would retry with")
	}
	if entries, err := os.ReadDir(filepath.Join(route.Directory, filesystemTempDirectory)); err != nil || len(entries) != 0 {
		t.Fatalf("a refused completion left its assembled copy behind: %v %v", entries, err)
	}
	object, err := store.CompleteUpload(id, "contested.bin", parts, putConditions{})
	if err != nil {
		t.Fatal(err)
	}
	if object.Size != int64(len("first half second half")) {
		t.Fatalf("object=%#v", object)
	}
	// Consolidation releases the parts at once rather than leaving them for the sweep.
	if openUploads() != 0 {
		t.Fatal("completion left the parts on the volume")
	}
	body, _, err := store.Get("contested.bin")
	if err != nil {
		t.Fatal(err)
	}
	contents, _ := io.ReadAll(body)
	_ = body.Close()
	if string(contents) != "first half second half" {
		t.Fatalf("assembled %q", contents)
	}
}
