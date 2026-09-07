package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Authentication AuthenticationConfig `yaml:"authentication"`
	Authorization  AuthorizationConfig  `yaml:"authorization"`
	Services       ServicesConfig       `yaml:"services"`
}

type ServerConfig struct {
	Address         string        `yaml:"address"`
	PublicURL       string        `yaml:"public_url"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	IdleTimeout     time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	MaxRequestBytes int64         `yaml:"max_request_bytes"`
}

type AuthenticationConfig struct {
	OIDC    []OIDCIssuerConfig `yaml:"oidc"`
	APIKeys []APIKeyConfig     `yaml:"api_keys"`
}

type OIDCIssuerConfig struct {
	Issuer            string   `yaml:"issuer"`
	Audiences         []string `yaml:"audiences"`
	RequiredScopes    []string `yaml:"required_scopes"`
	UsernameClaim     string   `yaml:"username_claim"`
	OrganizationClaim string   `yaml:"organization_claim"`
	TeamsClaim        string   `yaml:"teams_claim"`
}

type APIKeyConfig struct {
	Name         string   `yaml:"name"`
	Token        string   `yaml:"token"`
	TokenSHA256  string   `yaml:"token_sha256"`
	Subject      string   `yaml:"subject"`
	Username     string   `yaml:"username"`
	Organization string   `yaml:"organization"`
	Teams        []string `yaml:"teams"`
}

type AuthorizationConfig struct {
	Rules []ACLRuleConfig `yaml:"rules"`
}

type ACLRuleConfig struct {
	Name          string   `yaml:"name"`
	Subjects      []string `yaml:"subjects"`
	Users         []string `yaml:"users"`
	Organizations []string `yaml:"organizations"`
	Teams         []string `yaml:"teams"`
	Capabilities  []string `yaml:"capabilities"`
	Projects      []string `yaml:"projects"`
	S3Operations  []string `yaml:"s3_operations"`
	S3Prefixes    []string `yaml:"s3_prefixes"`
}

type ServicesConfig struct {
	Embeddings EmbeddingServiceConfig `yaml:"embeddings"`
	Rerank     RerankServiceConfig    `yaml:"rerank"`
	S3         S3ServiceConfig        `yaml:"s3"`
}

type HTTPUpstreamConfig struct {
	URL            string        `yaml:"url"`
	Protocol       string        `yaml:"protocol"`
	Model          string        `yaml:"model"`
	APIKey         string        `yaml:"api_key"`
	APIKeyHeader   string        `yaml:"api_key_header"`
	APIKeyScheme   string        `yaml:"api_key_scheme"`
	SendDimensions bool          `yaml:"send_dimensions"`
	Timeout        time.Duration `yaml:"timeout"`
}

type CacheConfig struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}

type EmbeddingServiceConfig struct {
	Enabled       bool               `yaml:"enabled"`
	Route         string             `yaml:"route"`
	Revision      string             `yaml:"revision"`
	Dimensions    int                `yaml:"dimensions"`
	MaxBatch      int                `yaml:"max_batch"`
	MaxInputBytes int                `yaml:"max_input_bytes"`
	Upstream      HTTPUpstreamConfig `yaml:"upstream"`
	Cache         CacheConfig        `yaml:"cache"`
}

type RerankServiceConfig struct {
	Enabled          bool               `yaml:"enabled"`
	Route            string             `yaml:"route"`
	Revision         string             `yaml:"revision"`
	MaxDocuments     int                `yaml:"max_documents"`
	MaxDocumentBytes int                `yaml:"max_document_bytes"`
	Upstream         HTTPUpstreamConfig `yaml:"upstream"`
	Cache            CacheConfig        `yaml:"cache"`
}

type S3ServiceConfig struct {
	Enabled               bool          `yaml:"enabled"`
	Mode                  string        `yaml:"mode"`
	Region                string        `yaml:"region"`
	Endpoint              string        `yaml:"endpoint"`
	Bucket                string        `yaml:"bucket"`
	BasePrefix            string        `yaml:"base_prefix"`
	RoleARN               string        `yaml:"role_arn"`
	STSEndpoint           string        `yaml:"sts_endpoint"`
	Duration              time.Duration `yaml:"duration"`
	AuthorizationRevision string        `yaml:"authorization_revision"`
}

func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	return DecodeConfig(f, os.Getenv)
}

func DecodeConfig(r io.Reader, getenv func(string) string) (Config, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	expanded, err := expandEnvironment(string(raw), getenv)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(expanded))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	cfg.defaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

var environmentReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:\?([^}]*))?\}`)

func expandEnvironment(input string, getenv func(string) string) (string, error) {
	var firstErr error
	result := environmentReference.ReplaceAllStringFunc(input, func(match string) string {
		parts := environmentReference.FindStringSubmatch(match)
		value := getenv(parts[1])
		if value == "" && parts[2] != "" && firstErr == nil {
			message := parts[3]
			if message == "" {
				message = "required environment variable is empty"
			}
			firstErr = fmt.Errorf("environment variable %s: %s", parts[1], message)
		}
		return value
	})
	if firstErr != nil {
		return "", firstErr
	}
	return result, nil
}

func (c *Config) defaults() {
	if c.Server.Address == "" {
		c.Server.Address = ":8080"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 15 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 60 * time.Second
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = 120 * time.Second
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = 15 * time.Second
	}
	if c.Server.MaxRequestBytes == 0 {
		c.Server.MaxRequestBytes = 4 << 20
	}
	if c.Services.Embeddings.Route == "" {
		c.Services.Embeddings.Route = "graphit-default"
	}
	if c.Services.Embeddings.MaxBatch == 0 {
		c.Services.Embeddings.MaxBatch = 256
	}
	if c.Services.Embeddings.MaxInputBytes == 0 {
		c.Services.Embeddings.MaxInputBytes = 1 << 20
	}
	if c.Services.Embeddings.Upstream.Timeout == 0 {
		c.Services.Embeddings.Upstream.Timeout = 45 * time.Second
	}
	if c.Services.Rerank.Route == "" {
		c.Services.Rerank.Route = "graphit-default"
	}
	if c.Services.Rerank.MaxDocuments == 0 {
		c.Services.Rerank.MaxDocuments = 1000
	}
	if c.Services.Rerank.MaxDocumentBytes == 0 {
		c.Services.Rerank.MaxDocumentBytes = 1 << 20
	}
	if c.Services.Rerank.Upstream.Timeout == 0 {
		c.Services.Rerank.Upstream.Timeout = 45 * time.Second
	}
	if c.Services.S3.Mode == "" {
		c.Services.S3.Mode = "assume_role"
	}
	if c.Services.S3.Region == "" {
		c.Services.S3.Region = "us-east-1"
	}
	if c.Services.S3.Duration == 0 {
		c.Services.S3.Duration = time.Hour
	}
	if c.Services.S3.AuthorizationRevision == "" {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%#v", c.Authorization.Rules)))
		c.Services.S3.AuthorizationRevision = hex.EncodeToString(sum[:8])
	}
	c.Services.Embeddings.Cache.setDefaults()
	c.Services.Rerank.Cache.setDefaults()
}

func (c *CacheConfig) setDefaults() {
	if c.TTL == 0 {
		c.TTL = 5 * time.Minute
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = 1000
	}
}

func (c Config) Validate() error {
	if len(c.Authentication.OIDC) == 0 && len(c.Authentication.APIKeys) == 0 {
		return errors.New("configuration needs at least one OIDC issuer or API key")
	}
	for i, issuer := range c.Authentication.OIDC {
		if err := validateHTTPSURL(issuer.Issuer, "OIDC issuer"); err != nil {
			return fmt.Errorf("authentication.oidc[%d]: %w", i, err)
		}
		if len(issuer.Audiences) == 0 {
			return fmt.Errorf("authentication.oidc[%d]: at least one audience is required", i)
		}
		if issuer.UsernameClaim == "" {
			return fmt.Errorf("authentication.oidc[%d]: username_claim is required", i)
		}
	}
	for i, key := range c.Authentication.APIKeys {
		if key.Token == "" && key.TokenSHA256 == "" {
			return fmt.Errorf("authentication.api_keys[%d]: token or token_sha256 is required", i)
		}
		if key.Token != "" && key.TokenSHA256 != "" {
			return fmt.Errorf("authentication.api_keys[%d]: token and token_sha256 are mutually exclusive", i)
		}
		if key.Subject == "" || key.Username == "" {
			return fmt.Errorf("authentication.api_keys[%d]: subject and username are required", i)
		}
		if key.TokenSHA256 != "" {
			decoded, err := hex.DecodeString(key.TokenSHA256)
			if err != nil || len(decoded) != sha256.Size {
				return fmt.Errorf("authentication.api_keys[%d]: token_sha256 must be a 64-character hexadecimal SHA-256", i)
			}
		}
	}
	for i, rule := range c.Authorization.Rules {
		if rule.Name == "" {
			return fmt.Errorf("authorization.rules[%d]: name is required", i)
		}
		if len(rule.Subjects)+len(rule.Users)+len(rule.Organizations)+len(rule.Teams) == 0 {
			return fmt.Errorf("authorization.rules[%d]: at least one identity selector is required", i)
		}
		if len(rule.Capabilities) == 0 {
			return fmt.Errorf("authorization.rules[%d]: at least one capability is required", i)
		}
	}
	if c.Services.Embeddings.Enabled {
		if c.Services.Embeddings.Revision == "" || c.Services.Embeddings.Dimensions <= 0 {
			return errors.New("services.embeddings needs revision and positive dimensions")
		}
		if err := c.Services.Embeddings.Upstream.validate("services.embeddings.upstream", "openai-embeddings-v1"); err != nil {
			return err
		}
	}
	if c.Services.Rerank.Enabled {
		if c.Services.Rerank.Revision == "" {
			return errors.New("services.rerank.revision is required")
		}
		if err := c.Services.Rerank.Upstream.validate("services.rerank.upstream", "cohere-v2", "jina-v1", "voyage-v1", "graphit-rerank-v1"); err != nil {
			return err
		}
	}
	if c.Services.S3.Enabled {
		if c.Services.S3.Bucket == "" || c.Services.S3.RoleARN == "" {
			return errors.New("services.s3 needs bucket and role_arn")
		}
		if c.Services.S3.Mode != "assume_role" && c.Services.S3.Mode != "web_identity" {
			return errors.New("services.s3.mode must be assume_role or web_identity")
		}
		if c.Services.S3.Duration < 15*time.Minute || c.Services.S3.Duration > 12*time.Hour {
			return errors.New("services.s3.duration must be between 15m and 12h")
		}
		if c.Services.S3.Endpoint != "" {
			if _, err := url.ParseRequestURI(c.Services.S3.Endpoint); err != nil {
				return fmt.Errorf("services.s3.endpoint: %w", err)
			}
		}
	}
	if c.Server.PublicURL != "" {
		if err := validateHTTPSURL(c.Server.PublicURL, "server public URL"); err != nil {
			return err
		}
	}
	return nil
}

func (c HTTPUpstreamConfig) validate(name string, protocols ...string) error {
	if err := validateHTTPURL(c.URL, name+" URL"); err != nil {
		return err
	}
	found := false
	for _, protocol := range protocols {
		if c.Protocol == protocol {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%s.protocol %q is unsupported", name, c.Protocol)
	}
	if c.Model == "" {
		return fmt.Errorf("%s.model is required for the broker's internal upstream routing", name)
	}
	return nil
}

func validateHTTPSURL(raw, name string) error {
	if err := validateHTTPURL(raw, name); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use HTTPS", name)
	}
	return nil
}

func validateHTTPURL(raw, name string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL", name)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain URL credentials", name)
	}
	return nil
}
