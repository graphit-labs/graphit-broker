package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	Models         ModelsConfig         `yaml:"models" json:"models"`
	Services       ServicesConfig       `yaml:"services" json:"services"`
}

// ModelsConfig selects task models from the persistent global model catalog.
// Each selected ID resolves below Directory as <id>/manifest.json.
type ModelsConfig struct {
	Directory string `yaml:"directory" json:"directory"`
	Embedding string `yaml:"embedding" json:"embedding"`
	Rerank    string `yaml:"rerank" json:"rerank"`
	Generate  string `yaml:"generate" json:"generate"`
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

type AdministrationConfig struct {
	Enabled           bool             `yaml:"enabled" json:"enabled"`
	SuperadminSubject string           `yaml:"superadmin_subject" json:"superadmin_subject"`
	SessionTTL        time.Duration    `yaml:"session_ttl" json:"session_ttl"`
	OIDC              AdminOIDCConfig  `yaml:"oidc" json:"oidc"`
	CLI               GraphitCLIConfig `yaml:"cli" json:"cli"`
}

type GraphitCLIConfig struct {
	ProviderName    string `yaml:"provider_name" json:"provider_name"`
	ProfileName     string `yaml:"profile_name" json:"profile_name"`
	OIDCClientID    string `yaml:"oidc_client_id" json:"oidc_client_id"`
	OIDCRedirectURI string `yaml:"oidc_redirect_uri" json:"oidc_redirect_uri,omitempty"`
}

type AdminOIDCConfig struct {
	Issuer            string   `yaml:"issuer" json:"issuer"`
	ClientID          string   `yaml:"client_id" json:"client_id"`
	ClientSecret      string   `yaml:"client_secret" json:"client_secret,omitempty"`
	RedirectURL       string   `yaml:"redirect_url" json:"redirect_url"`
	Scopes            []string `yaml:"scopes" json:"scopes,omitempty"`
	UsernameClaim     string   `yaml:"username_claim" json:"username_claim,omitempty"`
	OrganizationClaim string   `yaml:"organization_claim" json:"organization_claim,omitempty"`
	TeamsClaim        string   `yaml:"teams_claim" json:"teams_claim,omitempty"`
}

func (c AdminOIDCConfig) configured() bool {
	return strings.TrimSpace(c.Issuer) != "" || strings.TrimSpace(c.ClientID) != "" ||
		strings.TrimSpace(c.ClientSecret) != "" || strings.TrimSpace(c.RedirectURL) != ""
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

// LocalModelConfig controls only execution placement. Model selection and all
// model semantics live in the global models catalog and its manifests.
type LocalModelConfig struct {
	Device        string `yaml:"device" json:"device"`
	DeviceID      int    `yaml:"device_id" json:"device_id"`
	resolvedModel *ResolvedModel
}

type CacheConfig struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}

type EmbeddingServiceConfig struct {
	Enabled       bool               `yaml:"enabled"`
	Backend       string             `yaml:"backend"`
	Route         string             `yaml:"route"`
	Revision      string             `yaml:"revision"`
	Dimensions    int                `yaml:"dimensions"`
	MaxBatch      int                `yaml:"max_batch"`
	MaxInputBytes int                `yaml:"max_input_bytes"`
	Upstream      HTTPUpstreamConfig `yaml:"upstream"`
	Local         LocalModelConfig   `yaml:"local"`
	Cache         CacheConfig        `yaml:"cache"`
}

type RerankServiceConfig struct {
	Enabled          bool               `yaml:"enabled"`
	Backend          string             `yaml:"backend"`
	Route            string             `yaml:"route"`
	Revision         string             `yaml:"revision"`
	MaxDocuments     int                `yaml:"max_documents"`
	MaxDocumentBytes int                `yaml:"max_document_bytes"`
	Upstream         HTTPUpstreamConfig `yaml:"upstream"`
	Local            LocalModelConfig   `yaml:"local"`
	Cache            CacheConfig        `yaml:"cache"`
}

type S3ServiceConfig struct {
	Enabled          bool                     `yaml:"enabled"`
	DefaultRoute     string                   `yaml:"default_route"`
	Routes           map[string]S3RouteConfig `yaml:"routes"`
	PresignExpiry    time.Duration            `yaml:"presign_expiry"`
	MaxPresignExpiry time.Duration            `yaml:"max_presign_expiry"`
}

type S3RouteConfig struct {
	Region          string `yaml:"region"`
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	BasePrefix      string `yaml:"base_prefix"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
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
	if subject := strings.TrimSpace(getenv("BROKER_SUPERADMIN_SUBJECT")); subject != "" {
		cfg.Administration.SuperadminSubject = subject
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
	if c.Administration.SessionTTL == 0 {
		c.Administration.SessionTTL = 8 * time.Hour
	}
	if len(c.Administration.OIDC.Scopes) == 0 {
		c.Administration.OIDC.Scopes = []string{"openid", "profile", "email"}
	}
	if c.Administration.CLI.ProviderName == "" {
		c.Administration.CLI.ProviderName = "organization-broker"
	}
	if c.Administration.CLI.ProfileName == "" {
		c.Administration.CLI.ProfileName = c.Administration.CLI.ProviderName
	}
	for _, issuer := range c.Authentication.OIDC {
		if strings.TrimRight(strings.TrimSpace(issuer.Issuer), "/") != strings.TrimRight(strings.TrimSpace(c.Administration.OIDC.Issuer), "/") {
			continue
		}
		if c.Administration.OIDC.UsernameClaim == "" {
			c.Administration.OIDC.UsernameClaim = issuer.UsernameClaim
		}
		if c.Administration.OIDC.OrganizationClaim == "" {
			c.Administration.OIDC.OrganizationClaim = issuer.OrganizationClaim
		}
		if c.Administration.OIDC.TeamsClaim == "" {
			c.Administration.OIDC.TeamsClaim = issuer.TeamsClaim
		}
		break
	}
	if strings.TrimSpace(c.Models.Directory) == "" {
		c.Models.Directory = "/var/cache/graphit-broker/models"
	}
	if strings.TrimSpace(c.Models.Embedding) == "" {
		c.Models.Embedding = "coderankembed"
	}
	if strings.TrimSpace(c.Models.Rerank) == "" {
		c.Models.Rerank = "bge-reranker-base"
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
	if c.Services.Embeddings.Upstream.Timeout == 0 {
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
	if c.Services.Rerank.Upstream.Timeout == 0 {
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
	if c.Services.S3.PresignExpiry == 0 {
		c.Services.S3.PresignExpiry = 5 * time.Minute
	}
	if c.Services.S3.MaxPresignExpiry == 0 {
		c.Services.S3.MaxPresignExpiry = 15 * time.Minute
	}
	c.Services.Embeddings.Cache.setDefaults()
	c.Services.Rerank.Cache.setDefaults()
}

func (c *EmbeddingServiceConfig) setDefaults() {
	c.Backend = strings.ToLower(strings.TrimSpace(c.Backend))
	if c.Backend == "" {
		c.Backend = "upstream"
	}
	c.Local.setDefaults()
}

func (c *RerankServiceConfig) setDefaults() {
	c.Backend = strings.ToLower(strings.TrimSpace(c.Backend))
	if c.Backend == "" {
		c.Backend = "upstream"
	}
	c.Local.setDefaults()
}

func (c *LocalModelConfig) setDefaults() {
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
	if c.Administration.Enabled {
		if strings.TrimSpace(c.Administration.SuperadminSubject) == "" {
			return errors.New("administration.superadmin_subject or BROKER_SUPERADMIN_SUBJECT is required when administration is enabled")
		}
		if c.Administration.OIDC.configured() {
			if err := validateHTTPSURL(c.Administration.OIDC.Issuer, "administration OIDC issuer"); err != nil {
				return err
			}
			if strings.TrimSpace(c.Administration.OIDC.ClientID) == "" {
				return errors.New("administration.oidc.client_id is required when administration OIDC is configured")
			}
			if err := validateHTTPSOrLoopbackURL(c.Administration.OIDC.RedirectURL, "administration OIDC redirect URL"); err != nil {
				return err
			}
		} else if len(c.Authentication.APIKeys) == 0 {
			return errors.New("administration requires an OIDC client or at least one authentication.api_keys identity")
		}
		if c.Administration.SessionTTL < 5*time.Minute || c.Administration.SessionTTL > 7*24*time.Hour {
			return errors.New("administration.session_ttl must be between 5m and 168h")
		}
		if !safeSegment(c.Administration.CLI.ProviderName) || !safeSegment(c.Administration.CLI.ProfileName) {
			return errors.New("administration.cli provider_name and profile_name must be safe names")
		}
		if c.Administration.CLI.OIDCRedirectURI != "" {
			if err := validateGraphitCLIRedirect(c.Administration.CLI.OIDCRedirectURI); err != nil {
				return err
			}
		}
	}
	if !filepath.IsAbs(c.Models.Directory) {
		return errors.New("models.directory must be an absolute path")
	}
	for task, id := range map[string]string{"embedding": c.Models.Embedding, "rerank": c.Models.Rerank, "generate": c.Models.Generate} {
		if strings.TrimSpace(id) != "" && !safeSegment(id) {
			return fmt.Errorf("models.%s must be a safe model ID", task)
		}
	}
	if c.Services.Embeddings.Enabled {
		switch c.Services.Embeddings.Backend {
		case "local":
			if c.Services.Embeddings.Dimensions < 0 {
				return errors.New("services.embeddings.dimensions must not be negative")
			}
			if err := c.Services.Embeddings.Local.validate("services.embeddings.local"); err != nil {
				return err
			}
		case "upstream":
			if c.Services.Embeddings.Revision == "" || c.Services.Embeddings.Dimensions <= 0 {
				return errors.New("upstream services.embeddings needs revision and positive dimensions")
			}
			if err := c.Services.Embeddings.Upstream.validate("services.embeddings.upstream", embeddingUpstreamProtocols...); err != nil {
				return err
			}
		default:
			return fmt.Errorf("services.embeddings.backend %q is unsupported (use local or upstream)", c.Services.Embeddings.Backend)
		}
	}
	if c.Services.Rerank.Enabled {
		switch c.Services.Rerank.Backend {
		case "local":
			if err := c.Services.Rerank.Local.validate("services.rerank.local"); err != nil {
				return err
			}
		case "upstream":
			if c.Services.Rerank.Revision == "" {
				return errors.New("upstream services.rerank.revision is required")
			}
			if err := c.Services.Rerank.Upstream.validate("services.rerank.upstream", rerankUpstreamProtocols...); err != nil {
				return err
			}
		default:
			return fmt.Errorf("services.rerank.backend %q is unsupported (use local or upstream)", c.Services.Rerank.Backend)
		}
	}
	if c.Services.S3.Enabled {
		if len(c.Services.S3.Routes) == 0 || c.Services.S3.DefaultRoute == "" {
			return errors.New("services.s3 needs routes and default_route")
		}
		if _, ok := c.Services.S3.Routes[c.Services.S3.DefaultRoute]; !ok {
			return errors.New("services.s3.default_route must name a configured route")
		}
		if c.Services.S3.PresignExpiry <= 0 || c.Services.S3.MaxPresignExpiry <= 0 || c.Services.S3.PresignExpiry > c.Services.S3.MaxPresignExpiry || c.Services.S3.MaxPresignExpiry > time.Hour {
			return errors.New("services.s3 presign expiry must be positive, default <= max, and max <= 1h")
		}
		for name, route := range c.Services.S3.Routes {
			if !safeSegment(name) {
				return fmt.Errorf("services.s3.routes contains unsafe route name %q", name)
			}
			if route.Bucket == "" || route.AccessKeyID == "" || route.SecretAccessKey == "" {
				return fmt.Errorf("services.s3.routes.%s needs bucket, access_key_id, and secret_access_key", name)
			}
			if route.Endpoint != "" {
				if _, err := url.ParseRequestURI(route.Endpoint); err != nil {
					return fmt.Errorf("services.s3.routes.%s.endpoint: %w", name, err)
				}
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

var embeddingUpstreamProtocols = []string{
	"openai", "openai-compatible", "openai-embeddings-v1",
	"cohere", "cohere-embed-v2", "voyage", "voyage-embeddings-v1",
	"google", "google-embed-content-v1beta",
}

var rerankUpstreamProtocols = []string{
	"cohere", "cohere-v2", "jina", "jina-v1", "voyage", "voyage-v1", "graphit-rerank-v1",
}

func (c LocalModelConfig) validate(name string) error {
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

func validateGraphitCLIRedirect(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.Port() == "" {
		return errors.New("Graphit CLI OIDC redirect URI must be an HTTP loopback URL with an explicit port")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("Graphit CLI OIDC redirect URI must be an HTTP loopback URL with an explicit port")
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
