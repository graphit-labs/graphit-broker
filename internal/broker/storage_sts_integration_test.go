package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Run with a MinIO server whose signing user can call AssumeRole:
// GRAPHIT_MINIO_STS_ENDPOINT=http://127.0.0.1:19000 \
// GRAPHIT_MINIO_ACCESS_KEY=... GRAPHIT_MINIO_SECRET_KEY=... \
// GRAPHIT_MINIO_BUCKET=artifacts go test ./internal/broker -run TestMinIOSTSIntegration -v
func TestMinIOSTSIntegration(t *testing.T) {
	endpoint := os.Getenv("GRAPHIT_MINIO_STS_ENDPOINT")
	if endpoint == "" {
		t.Skip("GRAPHIT_MINIO_STS_ENDPOINT is not set")
	}
	route := S3RouteConfig{
		Region: "us-east-1", Endpoint: endpoint, STSEndpoint: endpoint,
		Bucket: os.Getenv("GRAPHIT_MINIO_BUCKET"), BasePrefix: "graphit",
		AccessKeyID: os.Getenv("GRAPHIT_MINIO_ACCESS_KEY"), SecretAccessKey: os.Getenv("GRAPHIT_MINIO_SECRET_KEY"),
		STSRoleARN: "arn:aws:iam::000000000000:role/graphit-broker", STSSessionName: "graphit-test", STSDuration: 15 * time.Minute,
	}
	if route.Bucket == "" || route.AccessKeyID == "" || route.SecretAccessKey == "" {
		t.Fatal("MinIO bucket, access key, and secret key are required")
	}
	ctx := context.Background()
	grant := S3SessionGrant{Revision: "1", Route: "primary", Access: map[string][]string{"publish": {"v2/projects/project-a"}}, Scope: S3SessionScope{Kind: "project", ProjectID: "project-a"}}
	temporary, err := NewAWSSTSCredentialService().Issue(ctx, route, grant, Principal{Issuer: "test", Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if credentialFile := os.Getenv("GRAPHIT_MINIO_STS_CREDENTIAL_FILE"); credentialFile != "" {
		payload, marshalErr := json.Marshal(temporary)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.WriteFile(credentialFile, payload, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	client := s3.NewFromConfig(aws.Config{
		Region:      route.Region,
		Credentials: credentials.NewStaticCredentialsProvider(temporary.AccessKeyID, temporary.SecretAccessKey, temporary.SessionToken),
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = true
	})
	key := "graphit/v2/projects/project-a/integration/object"
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(key), Body: bytes.NewReader([]byte("payload"))}); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	if _, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(key)}); err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(object.Body)
	_ = object.Body.Close()
	if string(body) != "payload" {
		t.Fatalf("GET body=%q", body)
	}
	ranged, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(key), Range: aws.String("bytes=1-3")})
	if err != nil {
		t.Fatalf("RANGE GET: %v", err)
	}
	rangeBody, _ := io.ReadAll(ranged.Body)
	_ = ranged.Body.Close()
	if string(rangeBody) != "ayl" {
		t.Fatalf("RANGE GET body=%q", rangeBody)
	}
	listed, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(route.Bucket), Prefix: aws.String("graphit/v2/projects/project-a/")})
	if err != nil || len(listed.Contents) != 1 {
		t.Fatalf("LIST contents=%d err=%v", len(listed.Contents), err)
	}
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String("graphit/v2/projects/project-b/forbidden"), Body: bytes.NewReader([]byte("no"))}); err == nil {
		t.Fatal("PUT outside the granted prefix succeeded")
	}
	if _, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(route.Bucket), Prefix: aws.String("graphit/v2/projects/project-b/")}); err == nil {
		t.Fatal("LIST outside the granted prefix succeeded")
	}
	multipartKey := "graphit/v2/projects/project-a/integration/multipart"
	created, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(route.Bucket), Key: aws.String(multipartKey)})
	if err != nil {
		t.Fatalf("CREATE MULTIPART: %v", err)
	}
	part, err := client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket: aws.String(route.Bucket), Key: aws.String(multipartKey), UploadId: created.UploadId,
		PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("multipart payload")),
	})
	if err != nil {
		t.Fatalf("UPLOAD PART: %v", err)
	}
	if _, err := client.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String(route.Bucket), Key: aws.String(multipartKey), UploadId: created.UploadId}); err != nil {
		t.Fatalf("LIST PARTS: %v", err)
	}
	if _, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: aws.String(route.Bucket), Key: aws.String(multipartKey), UploadId: created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{ETag: part.ETag, PartNumber: aws.Int32(1)}}},
	}); err != nil {
		t.Fatalf("COMPLETE MULTIPART: %v", err)
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(multipartKey)}); err != nil {
		t.Fatalf("DELETE MULTIPART OBJECT: %v", err)
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(key)}); err != nil {
		t.Fatalf("DELETE: %v", err)
	}
}
