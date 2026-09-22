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
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
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
		newClient: func(_ context.Context, route S3RouteConfig) (assumeRoleAPI, error) {
			if route.AccessKeyID != "broker-access" || route.SecretAccessKey != "broker-secret" {
				t.Fatalf("route credentials not supplied internally: %#v", route)
			}
			return assumeRoleFunc(func(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				captured = input
				return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
					AccessKeyId: aws.String("temporary-access"), SecretAccessKey: aws.String("temporary-secret"),
					SessionToken: aws.String("temporary-token"), Expiration: aws.Time(now.Add(time.Hour)),
				}}, nil
			}), nil
		},
	}
	route := S3RouteConfig{Bucket: "artifacts", Region: "us-east-1", Endpoint: "https://s3.example", BasePrefix: "tenant/root", AccessKeyID: "broker-access", SecretAccessKey: "broker-secret", STSRoleARN: "arn:aws:iam::123456789012:role/graphit", STSSessionName: "graphit", STSDuration: time.Hour}
	grant := S3SessionGrant{Revision: "42", Route: "primary", Access: map[string][]string{"read": {"v2/projects/a/ast"}, "publish": {"v2/projects/b/ast"}}, Scope: S3SessionScope{Kind: "project", ProjectID: "a", Module: "ast"}}
	response, err := service.Issue(context.Background(), route, grant, Principal{Issuer: "issuer", Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if response.AccessKeyID != "temporary-access" || response.SecretAccessKey != "temporary-secret" || response.SessionToken != "temporary-token" || response.AuthorizationRevision != "42" || response.Scope != "project" || response.ProjectID != "a" || response.Module != "ast" || response.Bucket != "artifacts" || response.Region != "us-east-1" || len(response.Prefixes) != 1 || response.Prefixes[0] != "tenant/root" || !response.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("response=%#v", response)
	}
	if captured == nil || aws.ToString(captured.RoleArn) != route.STSRoleARN || aws.ToInt32(captured.DurationSeconds) != 3600 || !strings.HasPrefix(aws.ToString(captured.RoleSessionName), "graphit-") {
		t.Fatalf("AssumeRole input=%#v", captured)
	}
	policy := aws.ToString(captured.Policy)
	if strings.Contains(policy, "broker-secret") || !strings.Contains(policy, "arn:aws:s3:::artifacts/tenant/root/v2/projects/a/ast") || strings.Contains(policy, "/memory") || !strings.Contains(policy, "s3:DeleteObject") {
		t.Fatalf("policy=%s", policy)
	}
}

func TestLoadSTSConfigUsesDefaultCredentialsUnlessStaticPairIsConfigured(t *testing.T) {
	loaderCalls := 0
	loader := func(_ context.Context, options ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
		loaderCalls++
		loaded := awsconfig.LoadOptions{}
		for _, option := range options {
			if err := option(&loaded); err != nil {
				return aws.Config{}, err
			}
		}
		if loaded.Region != "us-east-1" {
			t.Fatalf("loaded region=%q", loaded.Region)
		}
		return aws.Config{Credentials: credentials.NewStaticCredentialsProvider("ambient-access", "ambient-secret", "ambient-token")}, nil
	}

	for name, test := range map[string]struct {
		route      S3RouteConfig
		wantAccess string
		wantSecret string
		wantToken  string
	}{
		"default chain": {
			route:      S3RouteConfig{Region: "us-east-1"},
			wantAccess: "ambient-access",
			wantSecret: "ambient-secret",
			wantToken:  "ambient-token",
		},
		"explicit static pair": {
			route:      S3RouteConfig{Region: "us-east-1", AccessKeyID: "route-access", SecretAccessKey: "route-secret"},
			wantAccess: "route-access",
			wantSecret: "route-secret",
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, err := loadSTSConfig(context.Background(), test.route, loader)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := config.Credentials.Retrieve(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if credential.AccessKeyID != test.wantAccess || credential.SecretAccessKey != test.wantSecret || credential.SessionToken != test.wantToken {
				t.Fatalf("credential=%#v", credential)
			}
		})
	}
	if loaderCalls != 1 {
		t.Fatalf("default loader calls=%d", loaderCalls)
	}
}

func TestLoadSTSConfigUsesAWSEnvironmentCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "environment-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret")
	t.Setenv("AWS_SESSION_TOKEN", "environment-token")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	config, err := loadSTSConfig(context.Background(), S3RouteConfig{Region: "us-east-1"}, awsconfig.LoadDefaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := config.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if credential.AccessKeyID != "environment-access" || credential.SecretAccessKey != "environment-secret" || credential.SessionToken != "environment-token" {
		t.Fatalf("credential=%#v", credential)
	}
}

func TestLoadSTSConfigReportsDefaultConfigurationFailure(t *testing.T) {
	_, err := loadSTSConfig(context.Background(), S3RouteConfig{Region: "us-east-1"}, func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, errors.New("configuration unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "load AWS configuration: configuration unavailable") {
		t.Fatalf("loadSTSConfig error=%v", err)
	}
}

func TestAWSSTSCredentialServiceReportsClientConfigurationFailure(t *testing.T) {
	service := &AWSSTSCredentialService{
		now: time.Now,
		newClient: func(context.Context, S3RouteConfig) (assumeRoleAPI, error) {
			return nil, errors.New("configuration unavailable")
		},
	}
	route := S3RouteConfig{Bucket: "artifacts", Region: "us-east-1", BasePrefix: "graphit", STSRoleARN: "arn:aws:iam::123456789012:role/graphit", STSSessionName: "graphit", STSDuration: time.Hour}
	grant := S3SessionGrant{Access: map[string][]string{"read": {"v2/projects/a/tasks"}}, Scope: S3SessionScope{Kind: "project", ProjectID: "a", Module: "task"}}
	if _, err := service.Issue(context.Background(), route, grant, Principal{Subject: "alice"}); err == nil || !strings.Contains(err.Error(), "create STS client: configuration unavailable") {
		t.Fatalf("Issue error=%v", err)
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
