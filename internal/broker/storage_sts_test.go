package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type assumeRoleFunc func(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)

func (f assumeRoleFunc) AssumeRole(ctx context.Context, input *sts.AssumeRoleInput, options ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return f(ctx, input, options...)
}

func TestAWSSTSCredentialServiceIssuesCompleteTemporaryTopology(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	var captured *sts.AssumeRoleInput
	service := &AWSSTSCredentialService{
		now: func() time.Time { return now },
		newClient: func(route S3RouteConfig) assumeRoleAPI {
			if route.AccessKeyID != "broker-access" || route.SecretAccessKey != "broker-secret" {
				t.Fatalf("route credentials not supplied internally: %#v", route)
			}
			return assumeRoleFunc(func(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				captured = input
				return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
					AccessKeyId: aws.String("temporary-access"), SecretAccessKey: aws.String("temporary-secret"),
					SessionToken: aws.String("temporary-token"), Expiration: aws.Time(now.Add(time.Hour)),
				}}, nil
			})
		},
	}
	route := S3RouteConfig{Bucket: "artifacts", Region: "us-east-1", Endpoint: "https://s3.example", BasePrefix: "tenant/root", AccessKeyID: "broker-access", SecretAccessKey: "broker-secret", STSRoleARN: "arn:aws:iam::123456789012:role/graphit", STSSessionName: "graphit", STSDuration: time.Hour}
	grant := S3SessionGrant{Revision: "42", Route: "primary", Access: map[string][]string{"read": {"v2/projects/a"}, "publish": {"v2/projects/b"}}}
	response, err := service.Issue(context.Background(), route, grant, Principal{Issuer: "issuer", Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if response.AccessKeyID != "temporary-access" || response.SecretAccessKey != "temporary-secret" || response.SessionToken != "temporary-token" || response.AuthorizationRevision != "42" || response.Bucket != "artifacts" || response.Region != "us-east-1" || len(response.Prefixes) != 1 || response.Prefixes[0] != "tenant/root" || !response.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("response=%#v", response)
	}
	if captured == nil || aws.ToString(captured.RoleArn) != route.STSRoleARN || aws.ToInt32(captured.DurationSeconds) != 3600 || !strings.HasPrefix(aws.ToString(captured.RoleSessionName), "graphit-") {
		t.Fatalf("AssumeRole input=%#v", captured)
	}
	policy := aws.ToString(captured.Policy)
	if strings.Contains(policy, "broker-secret") || !strings.Contains(policy, "arn:aws:s3:::artifacts/tenant/root/v2/projects/a") || !strings.Contains(policy, "s3:DeleteObject") {
		t.Fatalf("policy=%s", policy)
	}
}

func TestS3SessionPolicyMapsReadWritePublishAndDeleteWithoutBroadening(t *testing.T) {
	route := S3RouteConfig{Bucket: "bucket", BasePrefix: "base"}
	policy, err := buildS3SessionPolicy(route, S3SessionGrant{Access: map[string][]string{
		"read": {"read-only"}, "write": {"write"}, "publish": {"publish"}, "delete": {"delete-only"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var document sessionPolicy
	if err := json.Unmarshal([]byte(policy), &document); err != nil {
		t.Fatal(err)
	}
	assertResourceAction := func(resource, action string, want bool) {
		t.Helper()
		got := false
		for _, statement := range document.Statement {
			if contains(statement.Resource, resource) && contains(statement.Action, action) {
				got = true
			}
		}
		if got != want {
			t.Fatalf("resource=%q action=%q got=%v want=%v policy=%s", resource, action, got, want, policy)
		}
	}
	assertResourceAction("arn:aws:s3:::bucket/base/read-only/*", "s3:GetObject", true)
	assertResourceAction("arn:aws:s3:::bucket/base/read-only/*", "s3:PutObject", false)
	assertResourceAction("arn:aws:s3:::bucket/base/write/*", "s3:PutObject", true)
	assertResourceAction("arn:aws:s3:::bucket/base/write/*", "s3:DeleteObject", false)
	assertResourceAction("arn:aws:s3:::bucket/base/publish/*", "s3:DeleteObject", true)
	assertResourceAction("arn:aws:s3:::bucket/base/delete-only/*", "s3:GetObject", false)
	assertResourceAction("arn:aws:s3:::bucket/base/delete-only/*", "s3:DeleteObject", true)
}

func TestS3SessionPolicyRejectsEmptyAndOversizedAuthorization(t *testing.T) {
	if _, err := buildS3SessionPolicy(S3RouteConfig{Bucket: "bucket", BasePrefix: "base"}, S3SessionGrant{Access: map[string][]string{}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("empty policy error=%v", err)
	}
	prefixes := make([]string, 80)
	for index := range prefixes {
		prefixes[index] = fmt.Sprintf("v2/projects/project-%03d/very-long-authorized-subtree", index)
	}
	if _, err := buildS3SessionPolicy(S3RouteConfig{Bucket: "bucket", BasePrefix: "base"}, S3SessionGrant{Access: map[string][]string{"publish": prefixes}}); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Fatalf("oversized policy error=%v", err)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
