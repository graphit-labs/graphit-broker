package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type CredentialRequest struct {
	Project   string `json:"project"`
	Operation string `json:"operation"`
}

type CredentialResponse struct {
	AccessKeyID           string    `json:"access_key_id"`
	SecretAccessKey       string    `json:"secret_access_key"`
	SessionToken          string    `json:"session_token"`
	ExpiresAt             time.Time `json:"expires_at"`
	Bucket                string    `json:"bucket"`
	Region                string    `json:"region"`
	Endpoint              string    `json:"endpoint,omitempty"`
	Prefixes              []string  `json:"prefixes"`
	AuthorizationRevision string    `json:"authorization_revision"`
}

type CredentialIssuer interface {
	Issue(context.Context, Principal, string, S3Grant) (CredentialResponse, error)
}

type stsAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type AWSCredentialIssuer struct {
	config S3ServiceConfig
	client stsAPI
}

func NewAWSCredentialIssuer(ctx context.Context, cfg S3ServiceConfig) (*AWSCredentialIssuer, error) {
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.Region)}
	if cfg.Mode == "web_identity" {
		options = append(options, awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("configure AWS STS client: %w", err)
	}
	client := sts.NewFromConfig(awsCfg, func(options *sts.Options) {
		if cfg.STSEndpoint != "" {
			options.BaseEndpoint = aws.String(cfg.STSEndpoint)
		}
	})
	return &AWSCredentialIssuer{config: cfg, client: client}, nil
}

func (i *AWSCredentialIssuer) Issue(ctx context.Context, principal Principal, rawToken string, grant S3Grant) (CredentialResponse, error) {
	if i == nil || i.client == nil {
		return CredentialResponse{}, errors.New("S3 credential issuer is unavailable")
	}
	policy, err := sessionPolicy(i.config.Bucket, grant)
	if err != nil {
		return CredentialResponse{}, err
	}
	sessionName := roleSessionName(principal)
	duration := int32(i.config.Duration / time.Second)
	var accessKey, secretKey, sessionToken string
	var expiration time.Time
	switch i.config.Mode {
	case "assume_role":
		output, err := i.client.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn: aws.String(i.config.RoleARN), RoleSessionName: aws.String(sessionName),
			DurationSeconds: aws.Int32(duration), Policy: aws.String(policy),
		})
		if err != nil {
			return CredentialResponse{}, fmt.Errorf("AWS AssumeRole: %w", err)
		}
		if output.Credentials == nil {
			return CredentialResponse{}, errors.New("AWS AssumeRole response omitted credentials")
		}
		accessKey, secretKey, sessionToken, expiration = credentialsFields(output.Credentials.AccessKeyId, output.Credentials.SecretAccessKey, output.Credentials.SessionToken, output.Credentials.Expiration)
	case "web_identity":
		if rawToken == "" {
			return CredentialResponse{}, errors.New("web identity mode requires the authenticated bearer token")
		}
		output, err := i.client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
			RoleArn: aws.String(i.config.RoleARN), RoleSessionName: aws.String(sessionName), WebIdentityToken: aws.String(rawToken),
			DurationSeconds: aws.Int32(duration), Policy: aws.String(policy),
		})
		if err != nil {
			return CredentialResponse{}, fmt.Errorf("AWS AssumeRoleWithWebIdentity: %w", err)
		}
		if output.Credentials == nil {
			return CredentialResponse{}, errors.New("AWS AssumeRoleWithWebIdentity response omitted credentials")
		}
		accessKey, secretKey, sessionToken, expiration = credentialsFields(output.Credentials.AccessKeyId, output.Credentials.SecretAccessKey, output.Credentials.SessionToken, output.Credentials.Expiration)
	default:
		return CredentialResponse{}, fmt.Errorf("unsupported S3 credential mode %q", i.config.Mode)
	}
	if accessKey == "" || secretKey == "" || sessionToken == "" || expiration.IsZero() {
		return CredentialResponse{}, errors.New("AWS STS response contained incomplete credentials")
	}
	return CredentialResponse{AccessKeyID: accessKey, SecretAccessKey: secretKey, SessionToken: sessionToken,
		ExpiresAt: expiration.UTC(), Bucket: i.config.Bucket, Region: i.config.Region, Endpoint: i.config.Endpoint,
		Prefixes: append([]string(nil), grant.Prefixes...), AuthorizationRevision: i.config.AuthorizationRevision}, nil
}

func credentialsFields(access, secret, token *string, expiration *time.Time) (string, string, string, time.Time) {
	var a, s, t string
	var e time.Time
	if access != nil {
		a = *access
	}
	if secret != nil {
		s = *secret
	}
	if token != nil {
		t = *token
	}
	if expiration != nil {
		e = *expiration
	}
	return a, s, t, e
}

func roleSessionName(principal Principal) string {
	hash := sha256.Sum256([]byte(principal.CanonicalSubject()))
	return "graphit-" + hex.EncodeToString(hash[:12])
}

func sessionPolicy(bucket string, grant S3Grant) (string, error) {
	if bucket == "" || len(grant.Prefixes) == 0 {
		return "", errors.New("cannot create S3 session policy without bucket and prefixes")
	}
	objectActions := []string{"s3:GetObject"}
	switch grant.Operation {
	case "write":
		objectActions = []string{"s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload"}
	case "publish":
		objectActions = []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"}
	case "delete":
		objectActions = []string{"s3:DeleteObject"}
	case "read":
	default:
		return "", fmt.Errorf("unsupported S3 operation %q", grant.Operation)
	}
	prefixConditions := make([]string, 0, len(grant.Prefixes)*2)
	resources := make([]string, 0, len(grant.Prefixes))
	for _, prefix := range grant.Prefixes {
		prefix = strings.Trim(prefix, "/")
		prefixConditions = append(prefixConditions, prefix, prefix+"/*")
		resources = append(resources, "arn:aws:s3:::"+bucket+"/"+prefix+"/*")
	}
	policy := map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Action": []string{"s3:GetBucketLocation"}, "Resource": "arn:aws:s3:::" + bucket},
		map[string]any{"Effect": "Allow", "Action": []string{"s3:ListBucket"}, "Resource": "arn:aws:s3:::" + bucket,
			"Condition": map[string]any{"StringLike": map[string]any{"s3:prefix": prefixConditions}}},
		map[string]any{"Effect": "Allow", "Action": objectActions, "Resource": resources},
	}}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode S3 session policy: %w", err)
	}
	if len(encoded) > 2048 {
		return "", errors.New("generated S3 session policy exceeds the AWS inline policy limit")
	}
	return string(encoded), nil
}
