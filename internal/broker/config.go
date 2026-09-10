package broker

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database       DatabaseConfig       `yaml:"database" json:"database"`
	Server         ServerConfig         `yaml:"server" json:"server"`
	Authentication AuthenticationConfig `yaml:"authentication" json:"authentication"`
	Administration AdministrationConfig `yaml:"administration" json:"administration"`
	Services       ServicesConfig       `yaml:"services" json:"services"`
}

type DatabaseConfig struct {
	Driver          string        `yaml:"driver" json:"driver"`
	DSN             string        `yaml:"dsn" json:"dsn"`
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
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
	TokenPepper string                    `yaml:"token_pepper" json:"token_pepper,omitempty"`
	Local       LocalAuthenticationConfig `yaml:"local" json:"local"`
	OIDC        []OIDCIssuerConfig        `yaml:"oidc" json:"oidc,omitempty"`
}

type LocalAuthenticationConfig struct {
	Login     LocalLoginConfig             `yaml:"login" json:"login"`
	RateLimit LocalAuthenticationRateLimit `yaml:"rate_limit" json:"rate_limit"`
	Captcha   LocalCaptchaConfig           `yaml:"captcha" json:"captcha"`
	MFA       LocalMFAConfig               `yaml:"mfa" json:"mfa"`
	Tokens    LocalTokenConfig             `yaml:"tokens" json:"tokens"`
}

type LocalLoginConfig struct {
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

func (c LocalLoginConfig) isEnabled() bool { return c.Enabled == nil || *c.Enabled }

type LocalCaptchaConfig struct {
	Enabled             bool          `yaml:"enabled" json:"enabled"`
	Provider            string        `yaml:"provider" json:"provider,omitempty"`
	SiteKey             string        `yaml:"site_key" json:"site_key,omitempty"`
	SecretKey           string        `yaml:"secret_key" json:"secret_key,omitempty"`
	TriggerMultiplier   float64       `yaml:"trigger_multiplier" json:"trigger_multiplier"`
	VerificationTimeout time.Duration `yaml:"verification_timeout" json:"verification_timeout"`
}

const defaultLocalCaptchaTriggerMultiplier = 1.5

type LocalMFAConfig struct {
	Required     *bool         `yaml:"required" json:"required"`
	Issuer       string        `yaml:"issuer" json:"issuer"`
	ChallengeTTL time.Duration `yaml:"challenge_ttl" json:"challenge_ttl"`
}

type LocalTokenConfig struct {
	Audience           string        `yaml:"audience" json:"audience"`
	CLIClientID        string        `yaml:"cli_client_id" json:"cli_client_id"`
	CLIRedirectPath    string        `yaml:"cli_redirect_path" json:"cli_redirect_path"`
	AccessTTL          time.Duration `yaml:"access_ttl" json:"access_ttl"`
	RefreshTTL         time.Duration `yaml:"refresh_ttl" json:"refresh_ttl"`
	AuthorizationTTL   time.Duration `yaml:"authorization_code_ttl" json:"authorization_code_ttl"`
	DeviceTTL          time.Duration `yaml:"device_code_ttl" json:"device_code_ttl"`
	DevicePollInterval time.Duration `yaml:"device_poll_interval" json:"device_poll_interval"`
	ServiceMaxTTL      time.Duration `yaml:"service_credential_max_ttl" json:"service_credential_max_ttl"`
}

type LocalAuthenticationRateLimit struct {
	MaxFailures          int           `yaml:"max_failures" json:"max_failures"`
	Window               time.Duration `yaml:"window" json:"window"`
	Lockout              time.Duration `yaml:"lockout" json:"lockout"`
	MaxConcurrent        int           `yaml:"max_concurrent" json:"max_concurrent"`
	SaturationMultiplier int           `yaml:"saturation_multiplier" json:"saturation_multiplier"`
}

type OIDCIssuerConfig struct {
	Enabled           *bool    `yaml:"enabled" json:"enabled"`
	Issuer            string   `yaml:"issuer" json:"issuer"`
	Audiences         []string `yaml:"audiences" json:"audiences"`
	RequiredScopes    []string `yaml:"required_scopes" json:"required_scopes,omitempty"`
	ClientID          string   `yaml:"client_id" json:"client_id,omitempty"`
	ClientSecret      string   `yaml:"client_secret" json:"client_secret,omitempty"`
	RedirectURL       string   `yaml:"redirect_url" json:"redirect_url,omitempty"`
	Scopes            []string `yaml:"scopes" json:"scopes,omitempty"`
	SubjectClaim      string   `yaml:"subject_claim" json:"subject_claim"`
	NameClaim         string   `yaml:"name_claim" json:"name_claim,omitempty"`
	EmailClaim        string   `yaml:"email_claim" json:"email_claim,omitempty"`
	UsernameClaim     string   `yaml:"username_claim" json:"username_claim"`
	OrganizationClaim string   `yaml:"organization_claim" json:"organization_claim,omitempty"`
	TeamsClaim        string   `yaml:"teams_claim" json:"teams_claim,omitempty"`
	RoleClaim         string   `yaml:"role_claim" json:"role_claim,omitempty"`
}

type AdministrationConfig struct {
	Enabled      bool             `yaml:"enabled" json:"enabled"`
	SessionTTL   time.Duration    `yaml:"session_ttl" json:"session_ttl"`
	CookieSecure *bool            `yaml:"cookie_secure" json:"cookie_secure"`
	CLI          GraphitCLIConfig `yaml:"cli" json:"cli"`
}

type GraphitCLIConfig struct {
	ProviderName string `yaml:"provider_name" json:"provider_name"`
	ProfileName  string `yaml:"profile_name" json:"profile_name"`
}

func (c OIDCIssuerConfig) isEnabled() bool { return c.Enabled == nil || *c.Enabled }

func (c OIDCIssuerConfig) loginConfigured() bool {
	return c.isEnabled() && (strings.TrimSpace(c.ClientID) != "" || strings.TrimSpace(c.ClientSecret) != "" ||
		strings.TrimSpace(c.RedirectURL) != "")
}

type ACLRuleConfig struct {
	ID           string   `yaml:"id" json:"id"`
	Name         string   `yaml:"name" json:"name"`
	Access       string   `yaml:"access" json:"access"`
	Principal    string   `yaml:"principal" json:"principal,omitempty"`
	Capabilities []string `yaml:"capabilities" json:"capabilities"`
	Projects     []string `yaml:"projects" json:"projects,omitempty"`
	S3Operations []string `yaml:"s3_operations" json:"s3_operations,omitempty"`
	S3Prefixes   []string `yaml:"s3_prefixes" json:"s3_prefixes,omitempty"`
	S3Route      string   `yaml:"s3_route" json:"s3_route,omitempty"`
}

type ServicesConfig struct {
	Embeddings EmbeddingServiceConfig `yaml:"embeddings" json:"embeddings"`
	Rerank     RerankServiceConfig    `yaml:"rerank" json:"rerank"`
	S3         S3ServiceConfig        `yaml:"s3" json:"s3"`
}

// UpstreamConfig selects an HTTP adapter or the in-process ONNX runtime.
type UpstreamConfig struct {
	URL            string        `yaml:"url" json:"url"`
	Protocol       string        `yaml:"protocol" json:"protocol"`
	Model          string        `yaml:"model" json:"model"`
	APIKey         string        `yaml:"api_key" json:"api_key"`
	APIKeyHeader   string        `yaml:"api_key_header" json:"api_key_header"`
	APIKeyScheme   string        `yaml:"api_key_scheme" json:"api_key_scheme"`
	SendDimensions bool          `yaml:"send_dimensions" json:"send_dimensions"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	Directory      string        `yaml:"directory" json:"directory,omitempty"`
	Device         string        `yaml:"device" json:"device,omitempty"`
	DeviceID       int           `yaml:"device_id" json:"device_id,omitempty"`
	resolvedModel  *ResolvedModel
}

type CacheConfig struct {
	TTL        time.Duration `yaml:"ttl" json:"ttl"`
	MaxEntries int           `yaml:"max_entries" json:"max_entries"`
}

type EmbeddingServiceConfig struct {
	Enabled       bool           `yaml:"enabled" json:"enabled"`
	Route         string         `yaml:"route" json:"route"`
	Revision      string         `yaml:"revision" json:"revision"`
	Dimensions    int            `yaml:"dimensions" json:"dimensions"`
	MaxBatch      int            `yaml:"max_batch" json:"max_batch"`
	MaxInputBytes int            `yaml:"max_input_bytes" json:"max_input_bytes"`
	Upstream      UpstreamConfig `yaml:"upstream" json:"upstream"`
	Cache         CacheConfig    `yaml:"cache" json:"cache"`
}

type RerankServiceConfig struct {
	Enabled          bool           `yaml:"enabled" json:"enabled"`
	Route            string         `yaml:"route" json:"route"`
	Revision         string         `yaml:"revision" json:"revision"`
	MaxDocuments     int            `yaml:"max_documents" json:"max_documents"`
	MaxDocumentBytes int            `yaml:"max_document_bytes" json:"max_document_bytes"`
	Upstream         UpstreamConfig `yaml:"upstream" json:"upstream"`
	Cache            CacheConfig    `yaml:"cache" json:"cache"`
}

type S3ServiceConfig struct {
	Enabled      bool                     `yaml:"enabled"`
	DefaultRoute string                   `yaml:"default_route"`
	Routes       map[string]S3RouteConfig `yaml:"routes"`
}

type S3RouteConfig struct {
	Region          string        `yaml:"region"`
	Endpoint        string        `yaml:"endpoint"`
	Bucket          string        `yaml:"bucket"`
	BasePrefix      string        `yaml:"base_prefix"`
	AccessKeyID     string        `yaml:"access_key_id"`
	SecretAccessKey string        `yaml:"secret_access_key"`
	STSEndpoint     string        `yaml:"sts_endpoint"`
	STSRoleARN      string        `yaml:"sts_role_arn"`
	STSSessionName  string        `yaml:"sts_session_name"`
	STSDuration     time.Duration `yaml:"sts_duration"`
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
	// Seed defaults whose zero value has explicit meaning before YAML decoding so
	// an omitted field remains distinguishable from an explicitly configured zero.
	cfg := Config{Authentication: AuthenticationConfig{Local: LocalAuthenticationConfig{Captcha: LocalCaptchaConfig{
		TriggerMultiplier: defaultLocalCaptchaTriggerMultiplier,
	}}}}
	decoder := yaml.NewDecoder(strings.NewReader(expanded))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if driver := strings.TrimSpace(getenv("BROKER_DATABASE_DRIVER")); driver != "" {
		cfg.Database.Driver = driver
	}
	if dsn := strings.TrimSpace(getenv("BROKER_DATABASE_DSN")); dsn != "" {
		cfg.Database.DSN = dsn
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
	c.Database.Driver = strings.ToLower(strings.TrimSpace(c.Database.Driver))
	if c.Database.Driver == "" {
		c.Database.Driver = "sqlite"
	}
	if c.Database.DSN == "" && c.Database.Driver == "sqlite" {
		c.Database.DSN = "/var/lib/graphit-broker/broker.db"
	}
	if c.Database.MaxOpenConns == 0 {
		if c.Database.Driver == "sqlite" {
			c.Database.MaxOpenConns = 1
		} else {
			c.Database.MaxOpenConns = 20
		}
	}
	if c.Database.MaxIdleConns == 0 {
		if c.Database.Driver == "sqlite" {
			c.Database.MaxIdleConns = 1
		} else {
			c.Database.MaxIdleConns = 10
		}
	}
	if c.Database.ConnMaxLifetime == 0 {
		c.Database.ConnMaxLifetime = 3 * time.Minute
	}
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
	c.Authentication.Local.RateLimit.setDefaults()
	c.Authentication.Local.Captcha.setDefaults()
	if c.Authentication.Local.Login.Enabled == nil {
		enabled := c.Administration.Enabled
		c.Authentication.Local.Login.Enabled = &enabled
	}
	c.Authentication.Local.MFA.setDefaults()
	c.Authentication.Local.Tokens.setDefaults()
	if c.Administration.SessionTTL == 0 {
		c.Administration.SessionTTL = 8 * time.Hour
	}
	if c.Administration.CookieSecure == nil {
		secure := true
		c.Administration.CookieSecure = &secure
	}
	if c.Administration.CLI.ProviderName == "" {
		c.Administration.CLI.ProviderName = "organization-broker"
	}
	if c.Administration.CLI.ProfileName == "" {
		c.Administration.CLI.ProfileName = c.Administration.CLI.ProviderName
	}
	for i := range c.Authentication.OIDC {
		issuer := &c.Authentication.OIDC[i]
		if issuer.Enabled == nil {
			enabled := true
			issuer.Enabled = &enabled
		}
		if issuer.SubjectClaim == "" {
			issuer.SubjectClaim = "sub"
		}
		if issuer.NameClaim == "" {
			issuer.NameClaim = "name"
		}
		if issuer.EmailClaim == "" {
			issuer.EmailClaim = "email"
		}
		if len(issuer.Scopes) == 0 && issuer.loginConfigured() {
			issuer.Scopes = []string{"openid", "profile", "email"}
		}
	}
	if c.Services.Embeddings.Route == "" {
		c.Services.Embeddings.Route = "graphit-default"
	}
	c.Services.Embeddings.setDefaults()
	if c.Services.Embeddings.MaxBatch == 0 {
		c.Services.Embeddings.MaxBatch = 256
	}
	if c.Services.Embeddings.MaxInputBytes == 0 {
		c.Services.Embeddings.MaxInputBytes = 1 << 20
	}
	if !c.Services.Embeddings.Upstream.isONNX() && c.Services.Embeddings.Upstream.Timeout == 0 {
		c.Services.Embeddings.Upstream.Timeout = 45 * time.Second
	}
	if c.Services.Rerank.Route == "" {
		c.Services.Rerank.Route = "graphit-default"
	}
	c.Services.Rerank.setDefaults()
	if c.Services.Rerank.MaxDocuments == 0 {
		c.Services.Rerank.MaxDocuments = 1000
	}
	if c.Services.Rerank.MaxDocumentBytes == 0 {
		c.Services.Rerank.MaxDocumentBytes = 1 << 20
	}
	if !c.Services.Rerank.Upstream.isONNX() && c.Services.Rerank.Upstream.Timeout == 0 {
		c.Services.Rerank.Upstream.Timeout = 45 * time.Second
	}
	if c.Services.S3.DefaultRoute == "" && len(c.Services.S3.Routes) == 1 {
		for name := range c.Services.S3.Routes {
			c.Services.S3.DefaultRoute = name
		}
	}
	for name, route := range c.Services.S3.Routes {
		if route.Region == "" {
			route.Region = "us-east-1"
		}
		c.Services.S3.Routes[name] = route
	}
	for name, route := range c.Services.S3.Routes {
		if route.STSSessionName == "" {
			route.STSSessionName = "graphit-broker"
		}
		if route.STSDuration == 0 {
			route.STSDuration = time.Hour
		}
		c.Services.S3.Routes[name] = route
	}
	c.Services.Embeddings.Cache.setDefaults()
	c.Services.Rerank.Cache.setDefaults()
}

func (c *LocalTokenConfig) setDefaults() {
	if strings.TrimSpace(c.Audience) == "" {
		c.Audience = "graphit-broker"
	}
	if strings.TrimSpace(c.CLIClientID) == "" {
		c.CLIClientID = "graphit-cli"
	}
	if strings.TrimSpace(c.CLIRedirectPath) == "" {
		c.CLIRedirectPath = "/oauth/callback"
	}
	if c.AccessTTL == 0 {
		c.AccessTTL = 10 * time.Minute
	}
	if c.RefreshTTL == 0 {
		c.RefreshTTL = 30 * 24 * time.Hour
	}
	if c.AuthorizationTTL == 0 {
		c.AuthorizationTTL = time.Minute
	}
	if c.DeviceTTL == 0 {
		c.DeviceTTL = 10 * time.Minute
	}
	if c.DevicePollInterval == 0 {
		c.DevicePollInterval = 5 * time.Second
	}
	if c.ServiceMaxTTL == 0 {
		c.ServiceMaxTTL = 365 * 24 * time.Hour
	}
}

func (c *LocalMFAConfig) setDefaults() {
	if c.Required == nil {
		required := true
		c.Required = &required
	}
	if strings.TrimSpace(c.Issuer) == "" {
		c.Issuer = "Graphit Broker"
	}
	if c.ChallengeTTL == 0 {
		c.ChallengeTTL = 10 * time.Minute
	}
}

func (c LocalMFAConfig) validate() error {
	issuer := strings.TrimSpace(c.Issuer)
	if issuer == "" || len(issuer) > 128 || strings.ContainsAny(issuer, "\r\n") {
		return errors.New("authentication.local.mfa.issuer must contain 1 to 128 characters without line breaks")
	}
	if c.ChallengeTTL < 2*time.Minute || c.ChallengeTTL > 30*time.Minute {
		return errors.New("authentication.local.mfa.challenge_ttl must be between 2m and 30m")
	}
	return nil
}

func (c LocalMFAConfig) isRequired() bool { return c.Required == nil || *c.Required }

func (c LocalTokenConfig) validate() error {
	if !safeSegment(c.Audience) || !safeSegment(c.CLIClientID) {
		return errors.New("authentication.local.tokens audience and cli_client_id must be safe names")
	}
	if !strings.HasPrefix(c.CLIRedirectPath, "/") || strings.ContainsAny(c.CLIRedirectPath, "?#") {
		return errors.New("authentication.local.tokens.cli_redirect_path must be an absolute path without query or fragment")
	}
	if c.AccessTTL < time.Minute || c.AccessTTL > time.Hour {
		return errors.New("authentication.local.tokens.access_ttl must be between 1m and 1h")
	}
	if c.RefreshTTL < c.AccessTTL || c.RefreshTTL > 90*24*time.Hour {
		return errors.New("authentication.local.tokens.refresh_ttl must be between access_ttl and 2160h")
	}
	if c.AuthorizationTTL < 30*time.Second || c.AuthorizationTTL > 10*time.Minute {
		return errors.New("authentication.local.tokens.authorization_code_ttl must be between 30s and 10m")
	}
	if c.DeviceTTL < 5*time.Minute || c.DeviceTTL > 30*time.Minute {
		return errors.New("authentication.local.tokens.device_code_ttl must be between 5m and 30m")
	}
	if c.DevicePollInterval < time.Second || c.DevicePollInterval > 30*time.Second {
		return errors.New("authentication.local.tokens.device_poll_interval must be between 1s and 30s")
	}
	if c.ServiceMaxTTL < time.Hour || c.ServiceMaxTTL > 5*365*24*time.Hour {
		return errors.New("authentication.local.tokens.service_credential_max_ttl must be between 1h and 43800h")
	}
	return nil
}

func (c *LocalAuthenticationRateLimit) setDefaults() {
	if c.MaxFailures == 0 {
		c.MaxFailures = 5
	}
	if c.Window == 0 {
		c.Window = time.Minute
	}
	if c.Lockout == 0 {
		c.Lockout = 5 * time.Minute
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = 2
	}
	if c.SaturationMultiplier == 0 {
		c.SaturationMultiplier = 4
	}
}

func (c *LocalCaptchaConfig) setDefaults() {
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	if c.VerificationTimeout == 0 {
		c.VerificationTimeout = 3 * time.Second
	}
}

func (c LocalCaptchaConfig) validate(rateLimit LocalAuthenticationRateLimit, localLoginEnabled bool, publicURL string) error {
	if c.Provider != "" && c.Provider != localCaptchaProviderTurnstile && c.Provider != localCaptchaProviderRecaptcha {
		return fmt.Errorf("authentication.local.captcha.provider %q is unsupported (use turnstile or recaptcha)", c.Provider)
	}
	if !c.Enabled {
		return nil
	}
	if math.IsNaN(c.TriggerMultiplier) || math.IsInf(c.TriggerMultiplier, 0) || c.TriggerMultiplier < 0 || c.TriggerMultiplier > float64(rateLimit.SaturationMultiplier) {
		return errors.New("authentication.local.captcha.trigger_multiplier must be between 0 and local.rate_limit.saturation_multiplier")
	}
	if c.VerificationTimeout < 500*time.Millisecond || c.VerificationTimeout > 10*time.Second {
		return errors.New("authentication.local.captcha.verification_timeout must be between 500ms and 10s")
	}
	if !localLoginEnabled {
		return errors.New("authentication.local.captcha requires local.login.enabled")
	}
	if c.Provider == "" {
		return errors.New("authentication.local.captcha.provider is required when enabled")
	}
	if strings.TrimSpace(c.SiteKey) == "" || strings.ContainsAny(c.SiteKey, "\r\n") {
		return errors.New("authentication.local.captcha.site_key is required without line breaks when enabled")
	}
	if strings.TrimSpace(c.SecretKey) == "" || strings.ContainsAny(c.SecretKey, "\r\n") {
		return errors.New("authentication.local.captcha.secret_key is required without line breaks when enabled")
	}
	if strings.TrimSpace(publicURL) == "" {
		return errors.New("server.public_url is required when authentication.local.captcha is enabled")
	}
	return nil
}

func (c LocalCaptchaConfig) threshold(maxConcurrent int) int {
	return max(1, int(math.Ceil(float64(maxConcurrent)*c.TriggerMultiplier)))
}

func (c LocalAuthenticationRateLimit) validate() error {
	if c.MaxFailures <= 0 {
		return errors.New("authentication.local.rate_limit.max_failures must be positive")
	}
	if c.Window <= 0 || c.Lockout <= 0 {
		return errors.New("authentication.local.rate_limit window and lockout must be positive")
	}
	if c.MaxConcurrent <= 0 {
		return errors.New("authentication.local.rate_limit.max_concurrent must be positive")
	}
	if c.SaturationMultiplier <= 0 {
		return errors.New("authentication.local.rate_limit.saturation_multiplier must be positive")
	}
	if c.MaxConcurrent > int(^uint(0)>>1)/c.SaturationMultiplier {
		return errors.New("authentication.local.rate_limit concurrency saturation capacity overflows int")
	}
	return nil
}

func (c *EmbeddingServiceConfig) setDefaults() { c.Upstream.setDefaults("embedding") }
func (c *RerankServiceConfig) setDefaults()    { c.Upstream.setDefaults("rerank") }

const defaultModelDirectory = "/var/cache/graphit-broker/models"

func (c UpstreamConfig) isONNX() bool { return c.Protocol == "onnx" }

func (c *UpstreamConfig) setDefaults(task string) {
	c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	if !c.isONNX() {
		return
	}
	if strings.TrimSpace(c.Directory) == "" {
		c.Directory = defaultModelDirectory
	}
	c.Model = strings.TrimSpace(c.Model)
	if c.Model == "" {
		switch task {
		case "embedding":
			c.Model = "coderankembed"
		case "rerank":
			c.Model = "bge-reranker-base"
		}
	}
	c.Device = strings.ToLower(strings.TrimSpace(c.Device))
	if c.Device == "" {
		c.Device = "auto"
	}
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
	switch strings.ToLower(strings.TrimSpace(c.Database.Driver)) {
	case "sqlite", "postgres", "mysql":
	default:
		return errors.New("database.driver must be sqlite, postgres, or mysql")
	}
	if strings.TrimSpace(c.Database.DSN) == "" {
		return errors.New("database.dsn is required")
	}
	if c.Database.MaxOpenConns <= 0 || c.Database.MaxIdleConns < 0 || c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return errors.New("database connection limits require max_open_conns > 0 and 0 <= max_idle_conns <= max_open_conns")
	}
	if c.Database.ConnMaxLifetime <= 0 {
		return errors.New("database.conn_max_lifetime must be positive")
	}
	if err := c.Authentication.Local.RateLimit.validate(); err != nil {
		return err
	}
	if err := c.Authentication.Local.Captcha.validate(c.Authentication.Local.RateLimit, c.Authentication.Local.Login.isEnabled(), c.Server.PublicURL); err != nil {
		return err
	}
	if err := c.Authentication.Local.MFA.validate(); err != nil {
		return err
	}
	if err := c.Authentication.Local.Tokens.validate(); err != nil {
		return err
	}
	loginProviders := 0
	for i, issuer := range c.Authentication.OIDC {
		if !issuer.isEnabled() {
			continue
		}
		if err := validateHTTPSURL(issuer.Issuer, "OIDC issuer"); err != nil {
			return fmt.Errorf("authentication.oidc[%d]: %w", i, err)
		}
		if len(issuer.Audiences) == 0 {
			return fmt.Errorf("authentication.oidc[%d]: at least one audience is required", i)
		}
		if strings.TrimSpace(issuer.SubjectClaim) == "" {
			return fmt.Errorf("authentication.oidc[%d]: subject_claim is required", i)
		}
		if issuer.UsernameClaim == "" {
			return fmt.Errorf("authentication.oidc[%d]: username_claim is required", i)
		}
		for _, mapping := range []struct{ field, selector string }{
			{"subject_claim", issuer.SubjectClaim}, {"name_claim", issuer.NameClaim}, {"email_claim", issuer.EmailClaim},
			{"username_claim", issuer.UsernameClaim}, {"organization_claim", issuer.OrganizationClaim},
			{"teams_claim", issuer.TeamsClaim}, {"role_claim", issuer.RoleClaim},
		} {
			if err := validateClaimSelector(mapping.selector); err != nil {
				return fmt.Errorf("authentication.oidc[%d].%s: %w", i, mapping.field, err)
			}
		}
		if issuer.loginConfigured() {
			loginProviders++
			if strings.TrimSpace(issuer.ClientID) == "" {
				return fmt.Errorf("authentication.oidc[%d].client_id is required for browser login", i)
			}
			if err := validateHTTPSOrLoopbackURL(issuer.RedirectURL, "OIDC redirect URL"); err != nil {
				return fmt.Errorf("authentication.oidc[%d]: %w", i, err)
			}
		}
	}
	if loginProviders > 1 {
		return errors.New("authentication.oidc must configure at most one browser login client")
	}
	if (c.Authentication.Local.Login.isEnabled() || loginProviders > 0) && strings.TrimSpace(c.Server.PublicURL) == "" {
		return errors.New("server.public_url is required when browser authentication is enabled")
	}
	if c.Administration.Enabled || c.Authentication.Local.Login.isEnabled() || loginProviders > 0 {
		if len(c.Authentication.TokenPepper) < tokenPepperMinimumBytes {
			return fmt.Errorf("authentication.token_pepper must contain at least %d bytes when browser authentication is enabled", tokenPepperMinimumBytes)
		}
	}
	if c.Administration.Enabled {
		if c.Administration.SessionTTL < 5*time.Minute || c.Administration.SessionTTL > 7*24*time.Hour {
			return errors.New("administration.session_ttl must be between 5m and 168h")
		}
		if !safeSegment(c.Administration.CLI.ProviderName) || !safeSegment(c.Administration.CLI.ProfileName) {
			return errors.New("administration.cli provider_name and profile_name must be safe names")
		}
	}
	if c.Services.Embeddings.Enabled {
		cfg := c.Services.Embeddings
		if err := cfg.Upstream.validate("services.embeddings.upstream", embeddingUpstreamProtocols...); err != nil {
			return err
		}
		if cfg.Upstream.isONNX() {
			if cfg.Dimensions < 0 {
				return errors.New("services.embeddings.dimensions must not be negative")
			}
		} else if cfg.Revision == "" || cfg.Dimensions <= 0 {
			return errors.New("HTTP services.embeddings needs revision and positive dimensions")
		}
	}
	if c.Services.Rerank.Enabled {
		cfg := c.Services.Rerank
		if err := cfg.Upstream.validate("services.rerank.upstream", rerankUpstreamProtocols...); err != nil {
			return err
		}
		if !cfg.Upstream.isONNX() && cfg.Revision == "" {
			return errors.New("HTTP services.rerank.revision is required")
		}
	}
	if c.Services.S3.Enabled {
		if len(c.Services.S3.Routes) == 0 || c.Services.S3.DefaultRoute == "" {
			return errors.New("services.s3 needs routes and default_route")
		}
		if _, ok := c.Services.S3.Routes[c.Services.S3.DefaultRoute]; !ok {
			return errors.New("services.s3.default_route must name a configured route")
		}
		for name, route := range c.Services.S3.Routes {
			if !safeSegment(name) {
				return fmt.Errorf("services.s3.routes contains unsafe route name %q", name)
			}
			if route.Bucket == "" || strings.Trim(route.BasePrefix, "/") == "" || route.AccessKeyID == "" || route.SecretAccessKey == "" || route.STSRoleARN == "" {
				return fmt.Errorf("services.s3.routes.%s needs bucket, base_prefix, access_key_id, secret_access_key, and sts_role_arn", name)
			}
			for _, segment := range strings.Split(strings.Trim(route.BasePrefix, "/"), "/") {
				if !safeSegment(segment) {
					return fmt.Errorf("services.s3.routes.%s.base_prefix contains unsafe segment %q", name, segment)
				}
			}
			if route.Endpoint != "" {
				if err := validateHTTPSOrLoopbackURL(route.Endpoint, "S3 endpoint"); err != nil {
					return fmt.Errorf("services.s3.routes.%s.endpoint: %w", name, err)
				}
			}
			if route.STSEndpoint != "" {
				if err := validateHTTPSOrLoopbackURL(route.STSEndpoint, "STS endpoint"); err != nil {
					return fmt.Errorf("services.s3.routes.%s.sts_endpoint: %w", name, err)
				}
			}
			if !regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{2,64}$`).MatchString(route.STSSessionName) {
				return fmt.Errorf("services.s3.routes.%s.sts_session_name must contain 2 to 64 AWS-safe characters", name)
			}
			if route.STSDuration < 15*time.Minute || route.STSDuration > 12*time.Hour {
				return fmt.Errorf("services.s3.routes.%s.sts_duration must be between 15m and 12h", name)
			}
		}
	}
	if c.Server.PublicURL != "" {
		if err := validatePublicURL(c.Server.PublicURL); err != nil {
			return err
		}
	}
	return nil
}

var embeddingUpstreamProtocols = []string{
	"openai", "openai-compatible", "openai-embeddings-v1",
	"cohere", "cohere-embed-v2", "voyage", "voyage-embeddings-v1",
	"google", "google-embed-content-v1beta", "gemini", "gemini-embed-content-v1beta",
}

var rerankUpstreamProtocols = []string{
	"cohere", "cohere-v2", "jina", "jina-v1", "voyage", "voyage-v1", "graphit-rerank-v1",
	"openai", "openai-compatible", "openai-embeddings-v1",
	"cohere-embed-v2", "voyage-embeddings-v1",
	"google", "google-embed-content-v1beta", "gemini", "gemini-embed-content-v1beta",
}

func (c UpstreamConfig) validateONNX(name string) error {
	if !filepath.IsAbs(c.Directory) {
		return fmt.Errorf("%s.directory must be an absolute path", name)
	}
	if !safeSegment(c.Model) {
		return fmt.Errorf("%s.model must be a safe model ID", name)
	}
	if c.URL != "" || c.APIKey != "" || c.APIKeyHeader != "" || c.APIKeyScheme != "" || c.SendDimensions || c.Timeout != 0 {
		return fmt.Errorf("%s with protocol onnx does not accept HTTP URL, authentication, send_dimensions, or timeout", name)
	}
	switch c.Device {
	case "auto", "cpu", "cuda", "coreml":
	default:
		return fmt.Errorf("%s.device %q is unsupported (use auto, cpu, cuda, or coreml)", name, c.Device)
	}
	if c.DeviceID < 0 {
		return fmt.Errorf("%s.device_id must not be negative", name)
	}
	if c.Device == "coreml" && c.DeviceID != 0 {
		return fmt.Errorf("%s.device_id must be 0 for coreml", name)
	}
	return nil
}

func validateACLRule(rule ACLRuleConfig) error {
	if !safeSegment(strings.TrimSpace(rule.ID)) {
		return errors.New("id must be a safe non-empty identifier")
	}
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("name is required")
	}
	if len(rule.Capabilities) == 0 {
		return errors.New("at least one capability is required")
	}
	if rule.S3Route != "" && !safeSegment(rule.S3Route) {
		return errors.New("s3_route must be a safe route name")
	}
	for _, project := range rule.Projects {
		project = strings.TrimSpace(project)
		if project == "*" {
			continue
		}
		if !safeSegment(project) {
			return fmt.Errorf("project selector %q must be an exact safe ID or *", project)
		}
	}
	access := strings.ToLower(strings.TrimSpace(rule.Access))
	if access == "" {
		return errors.New("access is required (global, anonymous, authenticated, user, team, organization, or subject)")
	}
	switch access {
	case "global", "anonymous", "authenticated":
		if strings.TrimSpace(rule.Principal) != "" {
			return fmt.Errorf("access %s does not accept principal", access)
		}
	case "user", "team", "organization", "subject":
		if strings.TrimSpace(rule.Principal) == "" {
			return fmt.Errorf("access %s requires principal", access)
		}
	default:
		return fmt.Errorf("unsupported access %q", rule.Access)
	}
	return nil
}

func (c UpstreamConfig) validate(name string, protocols ...string) error {
	if c.isONNX() {
		return c.validateONNX(name)
	}
	if c.Directory != "" || c.Device != "" || c.DeviceID != 0 {
		return fmt.Errorf("%s.directory, device, and device_id require protocol onnx", name)
	}
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

func validatePublicURL(raw string) error {
	if err := validateHTTPSURL(raw, "server public URL"); err != nil {
		return err
	}
	u, _ := url.Parse(strings.TrimSpace(raw))
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("server public URL must be an HTTPS origin without path, query, or fragment")
	}
	return nil
}

func validateHTTPSOrLoopbackURL(raw, name string) error {
	if err := validateHTTPURL(raw, name); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("%s must use HTTPS except on loopback", name)
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
