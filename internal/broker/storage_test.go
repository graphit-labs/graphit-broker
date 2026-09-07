package broker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type fakeSTS struct {
	assume *sts.AssumeRoleInput
	web    *sts.AssumeRoleWithWebIdentityInput
}

func (f *fakeSTS) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.assume = input
	return &sts.AssumeRoleOutput{Credentials: fakeAWSCredentials()}, nil
}
func (f *fakeSTS) AssumeRoleWithWebIdentity(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.web = input
	return &sts.AssumeRoleWithWebIdentityOutput{Credentials: fakeAWSCredentials()}, nil
}
func fakeAWSCredentials() *types.Credentials {
	expiry := time.Now().Add(time.Hour)
	return &types.Credentials{AccessKeyId: aws.String("AKIA_TEST"), SecretAccessKey: aws.String("secret"), SessionToken: aws.String("session"), Expiration: &expiry}
}

func TestSessionPolicyScopesActionsAndPrefixes(t *testing.T) {
	policy, err := sessionPolicy("artifacts", S3Grant{Operation: "publish", Prefixes: []string{"org/acme/project/a"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"s3:PutObject", "s3:DeleteObject", "arn:aws:s3:::artifacts/org/acme/project/a/*", "s3:prefix"} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy missing %q: %s", want, policy)
		}
	}
}

func TestAWSCredentialIssuerSupportsAssumeRoleAndWebIdentity(t *testing.T) {
	for _, mode := range []string{"assume_role", "web_identity"} {
		t.Run(mode, func(t *testing.T) {
			client := &fakeSTS{}
			issuer := &AWSCredentialIssuer{config: S3ServiceConfig{Mode: mode, Bucket: "artifacts", Region: "us-east-1", RoleARN: "arn:role", Duration: time.Hour, AuthorizationRevision: "acl-1"}, client: client}
			response, err := issuer.Issue(context.Background(), Principal{Issuer: "https://id", Subject: "subject"}, "caller-token", S3Grant{Project: "p", Operation: "read", Prefixes: []string{"projects/p"}})
			if err != nil {
				t.Fatal(err)
			}
			if response.AccessKeyID != "AKIA_TEST" || response.AuthorizationRevision != "acl-1" {
				t.Fatalf("response=%#v", response)
			}
			if mode == "assume_role" {
				if client.assume == nil || !strings.Contains(aws.ToString(client.assume.Policy), "projects/p") {
					t.Fatal("AssumeRole request missing scoped policy")
				}
			}
			if mode == "web_identity" {
				if client.web == nil || aws.ToString(client.web.WebIdentityToken) != "caller-token" {
					t.Fatal("web identity token not forwarded")
				}
			}
		})
	}
}
