package broker

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAWSPresignServiceSignsEverySupportedRequestWithoutReturningSecrets(t *testing.T) {
	service := NewAWSPresignService(S3ServiceConfig{DefaultRoute: "primary", Routes: map[string]S3RouteConfig{"primary": {Bucket: "artifacts", Region: "us-east-1", Endpoint: "https://s3.example.com", BasePrefix: "base", AccessKeyID: "ROUTEACCESS", SecretAccessKey: "never-return-this-secret"}}, PresignExpiry: 2 * time.Minute, MaxPresignExpiry: 10 * time.Minute})
	service.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	grant := S3Grant{Project: "project-a", Operation: "publish", Route: "primary", Prefixes: []string{"v2/projects/project-a"}}

	for _, operation := range []string{"get", "head", "put", "delete", "list"} {
		request := PresignRequest{Project: "project-a", Operation: operation, Key: "v2/projects/project-a/artifacts/item", IfMatch: `"etag"`, Limit: 25, Cursor: "next"}
		response, err := service.Presign(context.Background(), grant, request)
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
		parsed, err := url.Parse(response.URL)
		if err != nil || parsed.Query().Get("X-Amz-Signature") == "" {
			t.Fatalf("%s URL was not signed: %q err=%v", operation, response.URL, err)
		}
		if response.Method == "" || response.ExpiresAt.IsZero() || response.AuthorizationRevision != "" {
			t.Fatalf("%s response=%#v", operation, response)
		}
		if response.Key != request.Key {
			t.Fatalf("%s exposed the wrong logical key contract: %#v", operation, response)
		}
		if strings.Contains(response.URL, "never-return-this-secret") {
			t.Fatalf("%s leaked secret key", operation)
		}
		if !strings.Contains(parsed.Query().Get("X-Amz-Credential"), "ROUTEACCESS") {
			t.Fatalf("%s did not use the selected route credential", operation)
		}
		if operation == "list" && response.Method != http.MethodGet {
			t.Fatalf("list method=%s", response.Method)
		}
		if operation == "list" && parsed.Query().Get("prefix") != "base/v2/projects/project-a/artifacts/item/" {
			t.Fatalf("list prefix=%q", parsed.Query().Get("prefix"))
		}
	}
}

func TestAWSPresignServiceRejectsTraversalOutsideGrantAndExcessiveExpiry(t *testing.T) {
	service := NewAWSPresignService(S3ServiceConfig{DefaultRoute: "primary", Routes: map[string]S3RouteConfig{"primary": {Bucket: "b", Region: "r", BasePrefix: "base", AccessKeyID: "ACCESS", SecretAccessKey: "SECRET"}}, PresignExpiry: time.Minute, MaxPresignExpiry: 2 * time.Minute})
	grant := S3Grant{Route: "primary", Prefixes: []string{"v2/projects/allowed"}}
	for _, request := range []PresignRequest{
		{Operation: "get", Key: "v2/projects/allowed/../secret"},
		{Operation: "get", Key: "v2/projects/other/secret"},
		{Operation: "get", Key: "v2/projects/allowed/object", ExpiresIn: 121},
	} {
		if _, err := service.Presign(context.Background(), grant, request); err == nil {
			t.Fatalf("request accepted: %#v", request)
		}
	}
}

func TestAWSPresignServiceSelectsBrokerRouteWithoutExposingItAsConfiguration(t *testing.T) {
	service := NewAWSPresignService(S3ServiceConfig{
		DefaultRoute: "primary",
		Routes: map[string]S3RouteConfig{
			"primary": {Bucket: "primary-bucket", Region: "us-east-1", Endpoint: "https://primary.example", AccessKeyID: "PRIMARY", SecretAccessKey: "PRIMARY-SECRET"},
			"archive": {Bucket: "archive-bucket", Region: "us-west-2", Endpoint: "https://archive.example", BasePrefix: "tenant-b", AccessKeyID: "ARCHIVE", SecretAccessKey: "ARCHIVE-SECRET"},
		},
		PresignExpiry: time.Minute, MaxPresignExpiry: 5 * time.Minute,
	})
	response, err := service.Presign(context.Background(), S3Grant{Project: "project-a", Operation: "read", Route: "archive", Prefixes: []string{"v2/projects/project-a"}}, PresignRequest{Project: "project-a", Operation: "get", Key: "v2/projects/project-a/object"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(response.URL)
	if parsed.Host != "archive.example" || !strings.Contains(parsed.Path, "/archive-bucket/tenant-b/v2/projects/project-a/object") {
		t.Fatalf("route URL=%s", response.URL)
	}
	if !strings.Contains(parsed.Query().Get("X-Amz-Credential"), "ARCHIVE") || response.AuthorizationRevision != "" {
		t.Fatalf("selected route credential/revision missing: %#v", response)
	}
	if response.Key != "v2/projects/project-a/object" {
		t.Fatalf("public response leaked physical mapping: %#v", response)
	}
}
