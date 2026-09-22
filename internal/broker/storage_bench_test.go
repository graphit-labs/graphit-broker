package broker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// These measure the gateway as a client meets it: over HTTP, through the AWS SDK, with every
// request signed and every session verified.
func benchmarkStorageClient(b *testing.B) (*s3.Client, S3RouteConfig) {
	b.Helper()
	route := S3RouteConfig{Driver: storageDriverFilesystem, Region: "us-east-1", Bucket: "graphit-artifacts",
		BasePrefix: "graphit", Directory: b.TempDir(), Endpoint: "http://127.0.0.1", SessionDuration: time.Hour,
		MaxObjectBytes: 1 << 30}
	cfg := Config{}
	cfg.Services.S3 = S3ServiceConfig{Enabled: true, DefaultRoute: "local", Routes: map[string]S3RouteConfig{"local": route}}
	credentials := NewFilesystemCredentialService(testStoragePepper)
	gateway, err := newStorageGateway(cfg, credentials)
	if err != nil {
		b.Fatal(err)
	}
	mux := http.NewServeMux()
	gateway.register(mux)
	server := httptest.NewServer(mux)
	b.Cleanup(server.Close)
	grant := S3SessionGrant{Revision: "1", Route: "local",
		Access: map[string][]string{"publish": {"v2/projects/project-a"}},
		Scope:  S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "hub"}}
	issued, err := credentials.Issue(context.Background(), route, grant, Principal{Issuer: "https://id", Subject: "alice", Username: "alice"})
	if err != nil {
		b.Fatal(err)
	}
	return s3.New(s3.Options{Region: issued.Region, BaseEndpoint: aws.String(server.URL), UsePathStyle: true,
		Credentials: staticCredentials(issued)}), route
}

func BenchmarkStorageGatewayGetSmallObject(b *testing.B) {
	client, route := benchmarkStorageClient(b)
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/manifest.json"
	payload := bytes.Repeat([]byte("x"), 4096)
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: &key, Body: bytes.NewReader(payload)}); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: &key})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, out.Body); err != nil {
			b.Fatal(err)
		}
		_ = out.Body.Close()
	}
}

func BenchmarkStorageGatewayReadLargeObject(b *testing.B) {
	client, route := benchmarkStorageClient(b)
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/index/graph.parquet"
	payload := bytes.Repeat([]byte("ladybug!"), 32<<20/8)
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: &key, Body: bytes.NewReader(payload)}); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: &key})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, out.Body); err != nil {
			b.Fatal(err)
		}
		_ = out.Body.Close()
	}
}

// The query engine reads a remote artifact as a stream of ranged GETs, which is the shape that
// decides whether a query over httpfs feels local.
func BenchmarkStorageGatewayRangedRead(b *testing.B) {
	client, route := benchmarkStorageClient(b)
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/index/graph.parquet"
	payload := bytes.Repeat([]byte("ladybug!"), 256<<20/8)
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: &key, Body: bytes.NewReader(payload)}); err != nil {
		b.Fatal(err)
	}
	const window = 1 << 20
	offset := 0
	b.SetBytes(window)
	b.ResetTimer()
	for b.Loop() {
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: &key,
			Range: aws.String(fmt.Sprintf("bytes=%d-%d", offset, offset+window-1))})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, out.Body); err != nil {
			b.Fatal(err)
		}
		_ = out.Body.Close()
		offset = (offset + window) % (len(payload) - window)
	}
}

func BenchmarkStorageGatewayPutSmallObject(b *testing.B) {
	client, route := benchmarkStorageClient(b)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("x"), 4096)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		key := fmt.Sprintf("graphit/v2/projects/project-a/wiki/page-%d.md", i)
		if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: &key,
			Body: bytes.NewReader(payload)}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStorageGatewayListOneThousandObjects(b *testing.B) {
	client, route := benchmarkStorageClient(b)
	ctx := context.Background()
	prefix := "graphit/v2/projects/project-a/index/"
	for i := range 1000 {
		key := fmt.Sprintf("%spart-%04d.parquet", prefix, i)
		if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: &key,
			Body: bytes.NewReader([]byte("x"))}); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for b.Loop() {
		out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &route.Bucket, Prefix: &prefix})
		if err != nil {
			b.Fatal(err)
		}
		if len(out.Contents) != 1000 {
			b.Fatalf("listed %d objects", len(out.Contents))
		}
	}
}

func staticCredentials(issued S3CredentialsResponse) aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: issued.AccessKeyID, SecretAccessKey: issued.SecretAccessKey,
			SessionToken: issued.SessionToken, Source: "graphit-broker"}, nil
	})
}

// The client-driven benchmarks include the AWS SDK's own middleware and a loopback round trip.
// This one replays one signed request straight into the handler to show what the gateway itself
// costs per request: signature verification, session verification, and the object lookup.
func BenchmarkStorageGatewayHandlerGet(b *testing.B) {
	route := S3RouteConfig{Driver: storageDriverFilesystem, Region: "us-east-1", Bucket: "graphit-artifacts",
		BasePrefix: "graphit", Directory: b.TempDir(), Endpoint: "http://127.0.0.1", SessionDuration: time.Hour,
		MaxObjectBytes: 1 << 30}
	cfg := Config{}
	cfg.Services.S3 = S3ServiceConfig{Enabled: true, DefaultRoute: "local", Routes: map[string]S3RouteConfig{"local": route}}
	credentials := NewFilesystemCredentialService(testStoragePepper)
	gateway, err := newStorageGateway(cfg, credentials)
	if err != nil {
		b.Fatal(err)
	}
	mux := http.NewServeMux()
	gateway.register(mux)
	store := gateway.stores[route.Bucket]
	key := "graphit/v2/projects/project-a/manifest.json"
	if _, err := store.Put(key, bytes.NewReader(bytes.Repeat([]byte("x"), 4096)), "", "", putConditions{}); err != nil {
		b.Fatal(err)
	}
	grant := S3SessionGrant{Revision: "1", Route: "local",
		Access: map[string][]string{"publish": {"v2/projects/project-a"}},
		Scope:  S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "hub"}}
	issued, err := credentials.Issue(context.Background(), route, grant, Principal{Issuer: "https://id", Subject: "alice", Username: "alice"})
	if err != nil {
		b.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/"+route.Bucket+"/"+key, nil)
	if err != nil {
		b.Fatal(err)
	}
	request.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	request.Header.Set("X-Amz-Security-Token", issued.SessionToken)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: issued.AccessKeyID,
		SecretAccessKey: issued.SecretAccessKey, SessionToken: issued.SessionToken}, request,
		emptyPayloadSHA256, "s3", route.Region, time.Now()); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(4096)
	b.ResetTimer()
	for b.Loop() {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			b.Fatalf("status=%d", recorder.Code)
		}
	}
}

// The engine issues its ranged reads concurrently, so this measures what the gateway sustains
// with many readers rather than one.
func BenchmarkStorageGatewayRangedReadParallel(b *testing.B) {
	client, route := benchmarkStorageClient(b)
	ctx := context.Background()
	key := "graphit/v2/projects/project-a/index/graph.parquet"
	payload := bytes.Repeat([]byte("ladybug!"), 256<<20/8)
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &route.Bucket, Key: &key, Body: bytes.NewReader(payload)}); err != nil {
		b.Fatal(err)
	}
	const window = 1 << 20
	b.SetBytes(window)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		offset := 0
		for pb.Next() {
			out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &route.Bucket, Key: &key,
				Range: aws.String(fmt.Sprintf("bytes=%d-%d", offset, offset+window-1))})
			if err != nil {
				b.Error(err)
				return
			}
			if _, err := io.Copy(io.Discard, out.Body); err != nil {
				b.Error(err)
				return
			}
			_ = out.Body.Close()
			offset = (offset + window) % (len(payload) - window)
		}
	})
}
