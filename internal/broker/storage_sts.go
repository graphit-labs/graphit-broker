package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type S3CredentialsResponse struct {
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

type S3CredentialService interface {
	Issue(context.Context, S3RouteConfig, S3SessionGrant, Principal) (S3CredentialsResponse, error)
}

type assumeRoleAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type AWSSTSCredentialService struct {
	now       func() time.Time
	newClient func(S3RouteConfig) assumeRoleAPI
}

func NewAWSSTSCredentialService() *AWSSTSCredentialService {
	return &AWSSTSCredentialService{now: time.Now, newClient: newSTSClient}
}

func newSTSClient(route S3RouteConfig) assumeRoleAPI {
	config := aws.Config{
		Region:      route.Region,
		Credentials: credentials.NewStaticCredentialsProvider(route.AccessKeyID, route.SecretAccessKey, ""),
	}
	return sts.NewFromConfig(config, func(options *sts.Options) {
		endpoint := strings.TrimSpace(route.STSEndpoint)
		if endpoint == "" && route.Endpoint != "" {
			endpoint = route.Endpoint
		}
		if endpoint != "" {
			options.BaseEndpoint = aws.String(endpoint)
		}
	})
}

func (s *AWSSTSCredentialService) Issue(ctx context.Context, route S3RouteConfig, grant S3SessionGrant, principal Principal) (S3CredentialsResponse, error) {
	if s == nil || s.newClient == nil {
		return S3CredentialsResponse{}, errors.New("S3 credential service is unavailable")
	}
	policy, err := buildS3SessionPolicy(route, grant)
	if err != nil {
		return S3CredentialsResponse{}, err
	}
	duration := int32(route.STSDuration / time.Second)
	output, err := s.newClient(route).AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(route.STSRoleARN),
		RoleSessionName: aws.String(roleSessionName(route.STSSessionName, principal)),
		DurationSeconds: aws.Int32(duration),
		Policy:          aws.String(policy),
	})
	if err != nil {
		return S3CredentialsResponse{}, fmt.Errorf("assume S3 role: %w", err)
	}
	if output == nil || output.Credentials == nil {
		return S3CredentialsResponse{}, errors.New("STS returned no credentials")
	}
	credential := output.Credentials
	result := S3CredentialsResponse{
		AccessKeyID:           aws.ToString(credential.AccessKeyId),
		SecretAccessKey:       aws.ToString(credential.SecretAccessKey),
		SessionToken:          aws.ToString(credential.SessionToken),
		ExpiresAt:             aws.ToTime(credential.Expiration).UTC(),
		Bucket:                route.Bucket,
		Region:                route.Region,
		Endpoint:              route.Endpoint,
		Prefixes:              []string{strings.Trim(route.BasePrefix, "/")},
		AuthorizationRevision: grant.Revision,
	}
	if result.AccessKeyID == "" || result.SecretAccessKey == "" || result.SessionToken == "" || !result.ExpiresAt.After(s.now()) {
		return S3CredentialsResponse{}, errors.New("STS returned incomplete or expired credentials")
	}
	return result, nil
}

type sessionPolicy struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect    string                 `json:"Effect"`
	Action    []string               `json:"Action"`
	Resource  []string               `json:"Resource"`
	Condition map[string]interface{} `json:"Condition,omitempty"`
}

func buildS3SessionPolicy(route S3RouteConfig, grant S3SessionGrant) (string, error) {
	type permissionSet struct {
		list    bool
		actions map[string]struct{}
	}
	permissions := map[string]*permissionSet{}
	for operation, prefixes := range grant.Access {
		for _, prefix := range prefixes {
			prefix = joinPrefix(route.BasePrefix, prefix)
			permission := permissions[prefix]
			if permission == nil {
				permission = &permissionSet{actions: map[string]struct{}{}}
				permissions[prefix] = permission
			}
			switch operation {
			case "read":
				permission.list = true
				permission.actions["s3:GetObject"] = struct{}{}
			case "write":
				permission.list = true
				addS3Actions(permission.actions, "s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts")
			case "publish":
				permission.list = true
				addS3Actions(permission.actions, "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts")
			case "delete":
				permission.actions["s3:DeleteObject"] = struct{}{}
			}
		}
	}
	if len(permissions) == 0 {
		return "", ErrForbidden
	}
	prefixes := make([]string, 0, len(permissions))
	for prefix := range permissions {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	policy := sessionPolicy{Version: "2012-10-17"}
	bucketARN := "arn:aws:s3:::" + route.Bucket
	policy.Statement = append(policy.Statement, policyStatement{Effect: "Allow", Action: []string{"s3:GetBucketLocation"}, Resource: []string{bucketARN}})
	listPrefixes := make([]string, 0, len(prefixes)*2)
	objectResources := map[string][]string{}
	for _, prefix := range prefixes {
		permission := permissions[prefix]
		if permission.list {
			listPrefixes = append(listPrefixes, prefix, strings.TrimSuffix(prefix, "/")+"/*")
		}
		actions := sortedKeys(permission.actions)
		if len(actions) > 0 {
			key := strings.Join(actions, "\x00")
			objectResources[key] = append(objectResources[key], bucketARN+"/"+prefix, bucketARN+"/"+strings.TrimSuffix(prefix, "/")+"/*")
		}
	}
	if len(listPrefixes) > 0 {
		policy.Statement = append(policy.Statement, policyStatement{
			Effect: "Allow", Action: []string{"s3:ListBucket"}, Resource: []string{bucketARN},
			Condition: map[string]interface{}{"StringLike": map[string][]string{"s3:prefix": listPrefixes}},
		})
	}
	actionSets := make([]string, 0, len(objectResources))
	for actionSet := range objectResources {
		actionSets = append(actionSets, actionSet)
	}
	sort.Strings(actionSets)
	for _, actionSet := range actionSets {
		policy.Statement = append(policy.Statement, policyStatement{Effect: "Allow", Action: strings.Split(actionSet, "\x00"), Resource: objectResources[actionSet]})
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode S3 session policy: %w", err)
	}
	if len(raw) > 2048 {
		return "", fmt.Errorf("S3 session policy is %d bytes; AWS STS permits at most 2048", len(raw))
	}
	return string(raw), nil
}

func addS3Actions(set map[string]struct{}, actions ...string) {
	for _, action := range actions {
		set[action] = struct{}{}
	}
}

func sortedKeys(set map[string]struct{}) []string {
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func roleSessionName(base string, principal Principal) string {
	hash := sha256.Sum256([]byte(principal.CanonicalSubject()))
	suffix := hex.EncodeToString(hash[:8])
	base = strings.Trim(strings.TrimSpace(base), "-_")
	if len(base) > 47 {
		base = base[:47]
	}
	return base + "-" + suffix
}
