package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type PresignRequest struct {
	Project     string `json:"project"`
	Operation   string `json:"operation"`
	Key         string `json:"key"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	IfMatch     string `json:"if_match,omitempty"`
	IfNoneMatch string `json:"if_none_match,omitempty"`
	Limit       int32  `json:"limit,omitempty"`
	Cursor      string `json:"cursor,omitempty"`
}

type PresignResponse struct {
	Method                string              `json:"method"`
	URL                   string              `json:"url"`
	Headers               map[string][]string `json:"headers,omitempty"`
	ExpiresAt             time.Time           `json:"expires_at"`
	Key                   string              `json:"key"`
	Operation             string              `json:"operation"`
	AuthorizationRevision string              `json:"authorization_revision"`
}

type PresignService interface {
	Presign(context.Context, S3Grant, PresignRequest) (PresignResponse, error)
}

type AWSPresignService struct {
	config S3ServiceConfig
	now    func() time.Time
}

func NewAWSPresignService(config S3ServiceConfig) *AWSPresignService {
	return &AWSPresignService{config: config, now: time.Now}
}

func (s *AWSPresignService) Presign(ctx context.Context, grant S3Grant, request PresignRequest) (PresignResponse, error) {
	if s == nil {
		return PresignResponse{}, errors.New("S3 presign service is unavailable")
	}
	routeName := grant.Route
	if routeName == "" {
		routeName = s.config.DefaultRoute
	}
	route, ok := s.config.Routes[routeName]
	if !ok || route.AccessKeyID == "" || route.SecretAccessKey == "" {
		return PresignResponse{}, errors.New("S3 storage route is unavailable")
	}
	duration := s.config.PresignExpiry
	if request.ExpiresIn > 0 {
		duration = time.Duration(request.ExpiresIn) * time.Second
	}
	if duration <= 0 || duration > s.config.MaxPresignExpiry {
		return PresignResponse{}, fmt.Errorf("expires_in must be between 1 and %d seconds", int64(s.config.MaxPresignExpiry/time.Second))
	}
	logicalKey, err := validatePresignKey("", request.Key)
	if err != nil {
		return PresignResponse{}, err
	}
	if !keyWithinPrefixes(logicalKey, grant.Prefixes) {
		return PresignResponse{}, ErrForbidden
	}
	fullKey := joinPrefix(route.BasePrefix, logicalKey)
	awsConfig := aws.Config{Region: route.Region, Credentials: credentials.NewStaticCredentialsProvider(route.AccessKeyID, route.SecretAccessKey, "")}
	client := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		if route.Endpoint != "" {
			options.BaseEndpoint = aws.String(route.Endpoint)
			options.UsePathStyle = true
		}
	})
	presigner := s3.NewPresignClient(client)
	options := []func(*s3.PresignOptions){s3.WithPresignExpires(duration)}
	var signedURL, method string
	var signedHeaders http.Header
	switch strings.ToLower(strings.TrimSpace(request.Operation)) {
	case "get":
		result, signErr := presigner.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(fullKey)}, options...)
		if signErr != nil {
			err = signErr
		} else {
			signedURL, method, signedHeaders = result.URL, result.Method, result.SignedHeader
		}
	case "head":
		result, signErr := presigner.PresignHeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(fullKey)}, options...)
		if signErr != nil {
			err = signErr
		} else {
			signedURL, method, signedHeaders = result.URL, result.Method, result.SignedHeader
		}
	case "put":
		input := &s3.PutObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(fullKey)}
		if request.IfMatch != "" {
			input.IfMatch = aws.String(request.IfMatch)
		}
		if request.IfNoneMatch != "" {
			input.IfNoneMatch = aws.String(request.IfNoneMatch)
		}
		result, signErr := presigner.PresignPutObject(ctx, input, options...)
		if signErr != nil {
			err = signErr
		} else {
			signedURL, method, signedHeaders = result.URL, result.Method, result.SignedHeader
		}
	case "delete":
		input := &s3.DeleteObjectInput{Bucket: aws.String(route.Bucket), Key: aws.String(fullKey)}
		if request.IfMatch != "" {
			input.IfMatch = aws.String(request.IfMatch)
		}
		result, signErr := presigner.PresignDeleteObject(ctx, input, options...)
		if signErr != nil {
			err = signErr
		} else {
			signedURL, method, signedHeaders = result.URL, result.Method, result.SignedHeader
		}
	case "list":
		// S3 prefix matching is lexical. The slash prevents a grant for `projects/a` from
		// listing sibling `projects/ab` objects.
		listPrefix := strings.TrimSuffix(fullKey, "/") + "/"
		signedURL, signedHeaders, err = presignList(ctx, route, listPrefix, request.Limit, request.Cursor, duration, s.now())
		method = http.MethodGet
	default:
		return PresignResponse{}, errors.New("operation must be get, head, put, delete, or list")
	}
	if err != nil {
		return PresignResponse{}, fmt.Errorf("presign S3 %s: %w", request.Operation, err)
	}
	return PresignResponse{Method: method, URL: signedURL, Headers: cloneHeader(signedHeaders), ExpiresAt: s.now().Add(duration).UTC(), Key: strings.Trim(request.Key, "/"), Operation: strings.ToLower(request.Operation)}, nil
}

func presignList(ctx context.Context, config S3RouteConfig, prefix string, limit int32, cursor string, expires time.Duration, now time.Time) (string, http.Header, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	endpoint := strings.TrimRight(config.Endpoint, "/")
	pathValue := "/" + config.Bucket + "/"
	if endpoint == "" {
		endpoint = "https://" + config.Bucket + ".s3." + config.Region + ".amazonaws.com"
		pathValue = "/"
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return "", nil, err
	}
	target.Path = strings.TrimRight(target.Path, "/") + pathValue
	query := target.Query()
	query.Set("list-type", "2")
	query.Set("prefix", prefix)
	query.Set("max-keys", strconv.Itoa(int(limit)))
	query.Set("X-Amz-Expires", strconv.FormatInt(int64(expires/time.Second), 10))
	if cursor != "" {
		query.Set("continuation-token", cursor)
	}
	target.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", nil, err
	}
	credential := aws.Credentials{AccessKeyID: config.AccessKeyID, SecretAccessKey: config.SecretAccessKey}
	return v4.NewSigner().PresignHTTP(ctx, credential, request, "UNSIGNED-PAYLOAD", "s3", config.Region, now, func(options *v4.SignerOptions) {
		options.DisableURIPathEscaping = true
	})
}

func validatePresignKey(basePrefix, key string) (string, error) {
	key = strings.Trim(strings.TrimSpace(key), "/")
	if key == "" || len(key) > 1024 || strings.Contains(key, "\\") {
		return "", errors.New("key must be a non-empty relative S3 key")
	}
	for _, value := range key {
		if unicode.IsControl(value) {
			return "", errors.New("key contains control characters")
		}
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+key), "/")
	if cleaned != key {
		return "", errors.New("key contains traversal or non-canonical segments")
	}
	return joinPrefix(basePrefix, key), nil
}

func keyWithinPrefixes(key string, prefixes []string) bool {
	key = strings.Trim(key, "/")
	for _, prefix := range prefixes {
		prefix = strings.Trim(prefix, "/")
		if key == prefix || strings.HasPrefix(key, prefix+"/") {
			return true
		}
	}
	return false
}

func cloneHeader(header http.Header) map[string][]string {
	if len(header) == 0 {
		return nil
	}
	result := make(map[string][]string, len(header))
	for key, values := range header {
		result[key] = append([]string(nil), values...)
	}
	return result
}
