package broker

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var topLevelDatabaseConfig = regexp.MustCompile(`(?m)^database:`)

func decodeConfigForTest(r io.Reader, getenv func(string) string) (Config, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Config{}, err
	}
	if !topLevelDatabaseConfig.Match(raw) {
		raw = append([]byte("database: {dsn: ':memory:'}\n"), raw...)
	}
	return DecodeConfig(strings.NewReader(string(raw)), getenv)
}

func TestDecodeConfigExpandsRequiredEnvironmentAndDefaults(t *testing.T) {
	input := `
authentication:
  token_pepper: "${TOKEN_PEPPER:?TOKEN_PEPPER is required}"
services:
  embeddings:
    enabled: true
    revision: route-1
    dimensions: 3
    upstream:
      protocol: openai-embeddings-v1
      url: http://127.0.0.1:9999/v1/embeddings
      model: internal-model
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(name string) string {
		if name == "TOKEN_PEPPER" {
			return testPasswordPepper
		}
		return ""
	})
	if err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if cfg.Server.Address != ":8080" || cfg.Services.Embeddings.MaxBatch != 256 {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	if cfg.Authentication.Local.RateLimit.MaxFailures != 5 || cfg.Authentication.Local.RateLimit.Window != time.Minute || cfg.Authentication.Local.RateLimit.Lockout != 5*time.Minute || cfg.Authentication.Local.RateLimit.MaxConcurrent != 2 || cfg.Authentication.Local.RateLimit.SaturationMultiplier != 4 {
		t.Fatalf("local authentication rate limit defaults=%#v", cfg.Authentication.Local.RateLimit)
	}
	if cfg.Authentication.Local.MFA.Required == nil || !*cfg.Authentication.Local.MFA.Required || cfg.Authentication.Local.MFA.Issuer != "Graphit Broker" || cfg.Authentication.Local.MFA.ChallengeTTL != 10*time.Minute {
		t.Fatalf("local MFA defaults=%#v", cfg.Authentication.Local.MFA)
	}
	if cfg.Authentication.Local.Captcha.Enabled || cfg.Authentication.Local.Captcha.Provider != "" || cfg.Authentication.Local.Captcha.TriggerMultiplier != defaultLocalCaptchaTriggerMultiplier || cfg.Authentication.Local.Captcha.VerificationTimeout != 3*time.Second {
		t.Fatalf("local CAPTCHA defaults=%#v", cfg.Authentication.Local.Captcha)
	}
	if cfg.Authentication.TokenPepper != testPasswordPepper {
		t.Fatal("environment value was not expanded")
	}
	if cfg.Administration.CookieSecure == nil || !*cfg.Administration.CookieSecure {
		t.Fatalf("administration.cookie_secure default=%v", cfg.Administration.CookieSecure)
	}
	localTokens := cfg.Authentication.Local.Tokens
	if localTokens.Audience != "graphit-broker" || localTokens.CLIClientID != "graphit-cli" || localTokens.CLIRedirectPath != "/oauth/callback" || localTokens.AccessTTL != 10*time.Minute || localTokens.RefreshTTL != 30*24*time.Hour {
		t.Fatalf("local token defaults=%#v", localTokens)
	}
}

func TestLocalCaptchaSupportsTurnstileAndRecaptchaWithStrictConfiguration(t *testing.T) {
	for _, provider := range []string{localCaptchaProviderTurnstile, localCaptchaProviderRecaptcha} {
		t.Run(provider, func(t *testing.T) {
			cfg, err := decodeConfigForTest(strings.NewReader(`
server:
  public_url: https://broker.example.com
authentication:
  token_pepper: 0123456789abcdef0123456789abcdef
  local:
    login:
      enabled: true
    captcha:
      enabled: true
      provider: `+provider+`
      site_key: public-site-key
      secret_key: private-secret-key
      trigger_multiplier: 2.5
      verification_timeout: 2s
`), func(string) string { return "" })
			if err != nil {
				t.Fatal(err)
			}
			captcha := cfg.Authentication.Local.Captcha
			if !captcha.Enabled || captcha.Provider != provider || captcha.SiteKey != "public-site-key" || captcha.SecretKey != "private-secret-key" || captcha.TriggerMultiplier != 2.5 || captcha.VerificationTimeout != 2*time.Second {
				t.Fatalf("local CAPTCHA config=%#v", captcha)
			}
		})
	}

	localLoginEnabled := true
	base := Config{Database: DatabaseConfig{DSN: ":memory:"}, Server: ServerConfig{PublicURL: "https://broker.example.com"}, Authentication: AuthenticationConfig{
		TokenPepper: testPasswordPepper, Local: LocalAuthenticationConfig{
			Login:   LocalLoginConfig{Enabled: &localLoginEnabled},
			Captcha: LocalCaptchaConfig{Enabled: true, Provider: localCaptchaProviderTurnstile, SiteKey: "site", SecretKey: "secret"}},
	}}
	base.defaults()
	for name, mutate := range map[string]func(*Config){
		"unsupported provider": func(c *Config) { c.Authentication.Local.Captcha.Provider = "other" },
		"missing provider":     func(c *Config) { c.Authentication.Local.Captcha.Provider = "" },
		"missing site key":     func(c *Config) { c.Authentication.Local.Captcha.SiteKey = "" },
		"missing secret key":   func(c *Config) { c.Authentication.Local.Captcha.SecretKey = "" },
		"negative trigger":     func(c *Config) { c.Authentication.Local.Captcha.TriggerMultiplier = -.1 },
		"NaN trigger":          func(c *Config) { c.Authentication.Local.Captcha.TriggerMultiplier = math.NaN() },
		"infinite trigger":     func(c *Config) { c.Authentication.Local.Captcha.TriggerMultiplier = math.Inf(1) },
		"unreachable trigger":  func(c *Config) { c.Authentication.Local.Captcha.TriggerMultiplier = 5 },
		"short timeout":        func(c *Config) { c.Authentication.Local.Captcha.VerificationTimeout = 100 * time.Millisecond },
		"missing public URL":   func(c *Config) { c.Server.PublicURL = "" },
		"disabled local login": func(c *Config) { disabled := false; c.Authentication.Local.Login.Enabled = &disabled },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := base
			mutate(&invalid)
			if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "local.captcha") {
				t.Fatalf("invalid CAPTCHA configuration accepted: %#v error=%v", invalid.Authentication.Local.Captcha, err)
			}
		})
	}
}

func TestServerPublicURLRequiresHTTPSOrLoopbackOrigin(t *testing.T) {
	enabled := true
	base := Config{Database: DatabaseConfig{DSN: ":memory:"}, Server: ServerConfig{PublicURL: "https://broker.example.com"}, Authentication: AuthenticationConfig{
		TokenPepper: testPasswordPepper, Local: LocalAuthenticationConfig{Login: LocalLoginConfig{Enabled: &enabled}},
	}}
	base.defaults()
	for _, raw := range []string{
		"https://broker.example.com",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://127.0.0.2:8080/",
		"http://[::1]:8080",
	} {
		valid := base
		valid.Server.PublicURL = raw
		if err := valid.Validate(); err != nil {
			t.Fatalf("valid server.public_url %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://broker.example.com",
		"http://192.168.1.10:8080",
		"http://0.0.0.0:8080",
		"http://[::]:8080",
		"http://localhost.example.com:8080",
		"http://localhost:8080/base",
		"http://localhost:8080?tenant=one",
		"http://localhost:8080#fragment",
		"http://user:password@localhost:8080",
		"ftp://localhost:8080",
		"https://broker.example.com/base",
		"https://broker.example.com?tenant=one",
		"https://broker.example.com#fragment",
	} {
		invalid := base
		invalid.Server.PublicURL = raw
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "server public URL") {
			t.Fatalf("invalid server.public_url %q accepted: %v", raw, err)
		}
	}
}

func TestLocalCaptchaTriggerMultiplierSupportsZeroAndFractions(t *testing.T) {
	for _, test := range []struct {
		name           string
		configured     string
		wantMultiplier float64
		maxConcurrent  int
		wantThreshold  int
	}{
		{name: "omitted uses default", wantMultiplier: defaultLocalCaptchaTriggerMultiplier, maxConcurrent: 2, wantThreshold: 3},
		{name: "zero is always", configured: "      trigger_multiplier: 0\n", wantMultiplier: 0, maxConcurrent: 2, wantThreshold: 1},
		{name: "fraction starts early", configured: "      trigger_multiplier: 0.5\n", wantMultiplier: .5, maxConcurrent: 4, wantThreshold: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := decodeConfigForTest(strings.NewReader(`
server:
  public_url: https://broker.example.com
authentication:
  token_pepper: 0123456789abcdef0123456789abcdef
  local:
    login:
      enabled: true
    captcha:
      enabled: true
      provider: turnstile
      site_key: public-site-key
      secret_key: private-secret-key
`+test.configured), func(string) string { return "" })
			if err != nil {
				t.Fatal(err)
			}
			captcha := cfg.Authentication.Local.Captcha
			if captcha.TriggerMultiplier != test.wantMultiplier || captcha.threshold(test.maxConcurrent) != test.wantThreshold {
				t.Fatalf("multiplier=%v threshold=%d", captcha.TriggerMultiplier, captcha.threshold(test.maxConcurrent))
			}
		})
	}
}

func TestAdministrationCookieSecureCanBeExplicitlyDisabled(t *testing.T) {
	cfg, err := decodeConfigForTest(strings.NewReader(`
server:
  public_url: https://broker.example.com
authentication:
  token_pepper: 0123456789abcdef0123456789abcdef
administration:
  enabled: true
  cookie_secure: false
`), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Administration.CookieSecure == nil || *cfg.Administration.CookieSecure {
		t.Fatalf("administration.cookie_secure=%v", cfg.Administration.CookieSecure)
	}
}

func TestLocalMFACanBeExplicitlyDisabledAndConfigured(t *testing.T) {
	cfg, err := decodeConfigForTest(strings.NewReader(`
authentication:
  local:
    mfa:
      required: false
      issuer: Example Broker
      challenge_ttl: 5m
`), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authentication.Local.MFA.Required == nil || *cfg.Authentication.Local.MFA.Required || cfg.Authentication.Local.MFA.Issuer != "Example Broker" || cfg.Authentication.Local.MFA.ChallengeTTL != 5*time.Minute {
		t.Fatalf("local MFA config=%#v", cfg.Authentication.Local.MFA)
	}
}

func TestLocalAuthenticationRateLimitConfiguration(t *testing.T) {
	input := `
authentication:
  local:
    rate_limit:
      max_failures: 7
      window: 2m
      lockout: 10m
      max_concurrent: 3
      saturation_multiplier: 5
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authentication.Local.RateLimit != (LocalAuthenticationRateLimit{MaxFailures: 7, Window: 2 * time.Minute, Lockout: 10 * time.Minute, MaxConcurrent: 3, SaturationMultiplier: 5}) {
		t.Fatalf("custom rate limit=%#v", cfg.Authentication.Local.RateLimit)
	}
	for name, limit := range map[string]LocalAuthenticationRateLimit{
		"negative maximum":     {MaxFailures: -1, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: 2, SaturationMultiplier: 4},
		"negative window":      {MaxFailures: 5, Window: -time.Minute, Lockout: time.Minute, MaxConcurrent: 2, SaturationMultiplier: 4},
		"negative lockout":     {MaxFailures: 5, Window: time.Minute, Lockout: -time.Minute, MaxConcurrent: 2, SaturationMultiplier: 4},
		"negative concurrency": {MaxFailures: 5, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: -1, SaturationMultiplier: 4},
		"negative saturation":  {MaxFailures: 5, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: 2, SaturationMultiplier: -1},
		"capacity overflow":    {MaxFailures: 5, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: int(^uint(0) >> 1), SaturationMultiplier: 2},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := cfg
			invalid.Authentication.Local.RateLimit = limit
			if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "local.rate_limit") {
				t.Fatalf("invalid rate limit accepted: %#v error=%v", limit, err)
			}
		})
	}
}

func TestDecodeConfigRejectsUnknownFieldsAndMissingEnvironment(t *testing.T) {
	for name, input := range map[string]string{
		"unknown":     "unknown: true\n",
		"environment": "authentication:\n  token_pepper: '${TOKEN_PEPPER:?required}'\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" }); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestConfigRejectsInsecureOIDCIssuer(t *testing.T) {
	cfg := Config{Database: DatabaseConfig{DSN: ":memory:"}, Authentication: AuthenticationConfig{TokenPepper: testPasswordPepper, OIDC: []OIDCIssuerConfig{{Issuer: "http://id.example", Audiences: []string{"broker"}, SubjectClaim: "sub", UsernameClaim: "sub"}}}}
	cfg.defaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestAdministrationConfigRejectsRemoteHTTPCallback(t *testing.T) {
	input := `
database:
  driver: sqlite
  dsn: /tmp/broker.db
server:
  public_url: https://broker.example.com
authentication:
  token_pepper: 0123456789abcdef0123456789abcdef
  oidc:
    - issuer: https://identity.example.com
      display_name: Corporate SSO
      audiences: [graphit-broker]
      subject_claim: sub
      username_claim: preferred_username
      organization_claim: $.organization.id
      teams_claim: $.groups[*]
      client_id: broker-admin
      client_secret: secret
      redirect_url: http://localhost:8080/oauth/oidc/callback
      role_claim: $.realm_access.roles[*]
administration:
  enabled: true
  session_ttl: 1h
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	issuer := &cfg.Authentication.OIDC[0]
	if cfg.Administration.CLI.ProviderName != "organization-broker" || issuer.UsernameClaim != "preferred_username" || issuer.TeamsClaim != "$.groups[*]" || issuer.RoleClaim != "$.realm_access.roles[*]" || issuer.SubjectClaim != "sub" || issuer.NameClaim != "name" || issuer.EmailClaim != "email" {
		t.Fatalf("authentication defaults=%#v", cfg.Authentication)
	}
	issuer.RedirectURL = "http://broker.example.com/oauth/oidc/callback"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS except on loopback") {
		t.Fatalf("remote HTTP callback validation=%v", err)
	}
	issuer.RedirectURL = "http://localhost:8080/oauth/oidc/callback"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback OIDC callback validation=%v", err)
	}
}

func TestConfigRejectsInvalidClaimJSONPath(t *testing.T) {
	input := `
authentication:
  token_pepper: 0123456789abcdef0123456789abcdef
  oidc:
    - issuer: https://identity.example.com
      audiences: [graphit-broker]
      username_claim: $.profile[
`
	_, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "username_claim") || !strings.Contains(err.Error(), "invalid JSONPath") {
		t.Fatalf("invalid claim JSONPath error=%v", err)
	}
}

func TestAdministrationAllowsLocalUsersWithoutOIDC(t *testing.T) {
	input := `
database:
  driver: sqlite
  dsn: /tmp/broker.db
server:
  public_url: https://broker.example.com
authentication:
  token_pepper: 0123456789abcdef0123456789abcdef
administration:
  enabled: true
  session_ttl: 1h
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Authentication.OIDC) != 0 || cfg.Administration.CLI.ProviderName != "organization-broker" {
		t.Fatalf("local administration config=%#v", cfg.Administration)
	}
}

func TestAuthenticationRequiresExternalTokenPepper(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Administration = AdministrationConfig{Enabled: true, SessionTTL: time.Hour}
	cfg.defaults()
	for _, pepper := range []string{"", "too-short"} {
		cfg.Authentication.TokenPepper = pepper
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "token_pepper") {
			t.Fatalf("pepper %q validation=%v", pepper, err)
		}
	}
	cfg.Authentication.TokenPepper = testTokenPepper
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid pepper rejected: %v", err)
	}
}

func TestConfigRejectsLegacyAuthenticationFields(t *testing.T) {
	for name, input := range map[string]string{
		"local users in config": "authentication:\n  token_pepper: " + testPasswordPepper + "\n  api_keys: []\n",
		"administration OIDC":   "authentication:\n  token_pepper: " + testPasswordPepper + "\nadministration:\n  oidc:\n    issuer: https://identity.example\n",
		"administration pepper": "authentication:\n  token_pepper: " + testPasswordPepper + "\nadministration:\n  token_pepper: " + testPasswordPepper + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" }); err == nil {
				t.Fatal("legacy authentication field was accepted")
			}
		})
	}
}

func TestConfigRejectsAIRouteFields(t *testing.T) {
	for _, service := range []string{"embeddings", "rerank"} {
		t.Run(service, func(t *testing.T) {
			input := "services:\n  " + service + ":\n    route: removed\n"
			_, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
			if err == nil || !strings.Contains(err.Error(), "field route not found") {
				t.Fatalf("expected unknown route field, got %v", err)
			}
		})
	}
}

func TestRepositoryConfigurationExamplesDecodeWithInjectedSecrets(t *testing.T) {
	secrets := map[string]string{
		"BROKER_AUTH_TOKEN_PEPPER":  testPasswordPepper,
		"BROKER_OIDC_CLIENT_ID":     "broker-admin",
		"BROKER_OIDC_CLIENT_SECRET": "oidc-secret",
		"BROKER_OIDC_REDIRECT_URL":  "https://broker.example.com/oauth/oidc/callback",
		"OPENAI_API_KEY":            "openai-secret", "COHERE_API_KEY": "cohere-secret",
		"PRIMARY_S3_ACCESS_KEY_ID": "primary-access", "PRIMARY_S3_SECRET_ACCESS_KEY": "primary-secret",
		"PUBLIC_S3_ACCESS_KEY_ID": "public-access", "PUBLIC_S3_SECRET_ACCESS_KEY": "public-secret",
	}
	for _, path := range []string{"../../config.example.yaml", "../../examples/health-only.yaml", "../../examples/local-models.yaml"} {
		t.Run(path, func(t *testing.T) {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := decodeConfigForTest(file, func(name string) string { return secrets[name] }); err != nil {
				t.Fatalf("DecodeConfig: %v", err)
			}
		})
	}
}

func TestS3RoutesAreBrokerPrivateAndDatabaseGrantsSelectThem(t *testing.T) {
	input := `
services:
  s3:
    enabled: true
    default_route: primary
    routes:
      primary:
        bucket: primary
        base_prefix: graphit
        access_key_id: primary-access
        secret_access_key: primary-secret
        sts_role_arn: arn:aws:iam::123456789012:role/graphit
      archive:
        region: us-west-2
        endpoint: https://objects.example.com
        bucket: archive
        base_prefix: tenant-a
        access_key_id: archive-access
        secret_access_key: archive-secret
        sts_role_arn: arn:aws:iam::123456789012:role/graphit-archive
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Services.S3.Routes["primary"].Region != "us-east-1" || cfg.Services.S3.Routes["archive"].Bucket != "archive" {
		t.Fatalf("routes=%#v", cfg.Services.S3.Routes)
	}
	rule := ACLRuleConfig{ID: "tenant-archive", Name: "tenant archive", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Route: "missing"}
	if err := validateGrantRoute(rule, cfg.Services.S3); err == nil {
		t.Fatal("grant accepted an unknown storage route")
	}
}

func TestConfigAcceptsSTSStorageRouteAndRejectsUnknownFields(t *testing.T) {
	input := `
services:
  s3:
    enabled: true
    default_route: oidc
    routes:
      oidc:
        bucket: private
        base_prefix: graphit
        access_key_id: public-access
        secret_access_key: public-secret
        sts_role_arn: arn:aws:iam::123456789012:role/graphit
`
	if _, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" }); err != nil {
		t.Fatalf("DecodeConfig error=%v", err)
	}
	unsupported := strings.Replace(input, "        access_key_id: public-access\n", "        unsupported_storage_field: removed\n", 1)
	if _, err := decodeConfigForTest(strings.NewReader(unsupported), func(string) string { return "" }); err == nil {
		t.Fatal("removed storage field was accepted")
	}
	legacy := "authorization:\n  rules: []\n"
	if _, err := decodeConfigForTest(strings.NewReader(legacy), func(string) string { return "" }); err == nil {
		t.Fatal("legacy authorization configuration was accepted")
	}
}

func TestConfigSupportsONNXAndHTTPUpstreams(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	input := `
database:
  dsn: ':memory:'
services:
  embeddings:
    enabled: true
    upstream:
      protocol: ONNX
      directory: ~/.graphit/broker/models
  rerank:
    enabled: true
    upstream:
      protocol: onnx
      directory: ~/.graphit/broker/models
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	e, r := cfg.Services.Embeddings.Upstream, cfg.Services.Rerank.Upstream
	wantDirectory := filepath.Join(home, ".graphit", "broker", "models")
	if e.Protocol != "onnx" || e.Device != "cpu" || r.Device != "cpu" || e.Directory != wantDirectory || r.Directory != wantDirectory || e.Model != "coderankembed" || r.Model != "bge-reranker-base" || e.Timeout != 0 {
		t.Fatalf("ONNX defaults=%#v", cfg.Services)
	}
	auto, err := decodeConfigForTest(strings.NewReader("database: {dsn: ':memory:'}\nservices: {embeddings: {upstream: {protocol: onnx, directory: /models, device: auto}}, rerank: {upstream: {protocol: onnx, directory: /models, device: auto}}}"), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if auto.Services.Embeddings.Upstream.Device != "auto" || auto.Services.Rerank.Upstream.Device != "auto" {
		t.Fatalf("explicit ONNX auto devices=%#v", auto.Services)
	}
	remote := Config{Database: DatabaseConfig{DSN: ":memory:"}, Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
		Enabled: true, Revision: "r", Dimensions: 3,
		Upstream: UpstreamConfig{Protocol: "openai-embeddings-v1", URL: "http://127.0.0.1/embeddings", Model: "remote"},
	}}}
	remote.defaults()
	if err := remote.Validate(); err != nil {
		t.Fatalf("HTTP upstream rejected: %v", err)
	}
	if u := remote.Services.Embeddings.Upstream; u.Device != "" || u.Directory != "" || u.Timeout != 45*time.Second {
		t.Fatalf("HTTP defaults=%#v", u)
	}
}

func TestConfigAcceptsEmbeddingProviderParityAndRejectsInvalidLocalDevice(t *testing.T) {
	for _, protocol := range embeddingUpstreamProtocols {
		cfg := Config{Database: DatabaseConfig{DSN: ":memory:"}, Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
			Enabled: true, Revision: "r", Dimensions: 3,
			Upstream: UpstreamConfig{Protocol: protocol, URL: "https://provider.example/v1", Model: "model"},
		}}}
		cfg.defaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("protocol %q rejected: %v", protocol, err)
		}
	}
	coreML := Config{Database: DatabaseConfig{DSN: ":memory:"}, Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
		Enabled: true, Revision: "r", Dimensions: localEmbeddingDimensions,
		Upstream: UpstreamConfig{Protocol: "onnx", Directory: "/models", Device: "coreml"},
	}}}
	coreML.defaults()
	if err := coreML.Validate(); err != nil {
		t.Fatalf("CoreML local device rejected: %v", err)
	}
	cfg := Config{Database: DatabaseConfig{DSN: ":memory:"}, Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
		Enabled: true, Revision: "r", Dimensions: localEmbeddingDimensions,
		Upstream: UpstreamConfig{Protocol: "onnx", Directory: "/models", Device: "metal"},
	}}}
	cfg.defaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "auto, cpu, cuda, or coreml") {
		t.Fatalf("invalid local device error=%v", err)
	}
}

func TestConfigAcceptsRerankProviderParity(t *testing.T) {
	for _, protocol := range rerankUpstreamProtocols {
		cfg := Config{Database: DatabaseConfig{DSN: ":memory:"}, Services: ServicesConfig{Rerank: RerankServiceConfig{
			Enabled: true, Revision: "r",
			Upstream: UpstreamConfig{Protocol: protocol, URL: "https://provider.example/v1", Model: "model"},
		}}}
		cfg.defaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("protocol %q rejected: %v", protocol, err)
		}
	}
}

func TestConfigSelectsONNXModelsAndRejectsLegacyFields(t *testing.T) {
	input := `
services:
  embeddings:
    enabled: true
    upstream:
      protocol: onnx
      directory: /embedding-models
      model: custom-embedding
      device: cpu
  rerank:
    enabled: true
    upstream:
      protocol: onnx
      directory: /rerank-models
      model: custom-rerank
      device: cuda
      device_id: 2
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	e, r := cfg.Services.Embeddings.Upstream, cfg.Services.Rerank.Upstream
	if e.Directory != "/embedding-models" || e.Model != "custom-embedding" || r.Directory != "/rerank-models" || r.Model != "custom-rerank" || r.DeviceID != 2 {
		t.Fatalf("selection=%#v", cfg.Services)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Services struct {
			Embeddings struct{ Upstream UpstreamConfig }
			Rerank     struct{ Upstream UpstreamConfig }
		}
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Services.Embeddings.Upstream != e || decoded.Services.Rerank.Upstream != r || strings.Contains(string(data), `"models":`) || strings.Contains(string(data), `"backend":`) {
		t.Fatalf("unexpected JSON: %s", data)
	}
	for _, legacy := range []string{
		"models: {}", "models: {generate: reserved}",
		"services: {embeddings: {backend: local}}", "services: {rerank: {backend: upstream}}",
		"services: {embeddings: {local: {device: cpu}}}", "services: {rerank: {local: {}}}",
		"services: {embeddings: {upstream: {model_path: /model.onnx}}}",
	} {
		if _, err := decodeConfigForTest(strings.NewReader(legacy), func(string) string { return "" }); err == nil {
			t.Errorf("legacy accepted: %s", legacy)
		}
	}
}

func TestConfigRejectsIncompatibleUpstreamOptions(t *testing.T) {
	for _, service := range []string{"embeddings", "rerank"} {
		for _, options := range []string{
			"protocol: onnx, directory: relative", "protocol: onnx, model: ../escape",
			"protocol: onnx, device: metal", "protocol: onnx, device_id: -1",
			"protocol: onnx, device: coreml, device_id: 1",
			"protocol: onnx, url: https://example.com", "protocol: onnx, api_key: secret",
			"protocol: onnx, api_key_header: Authorization", "protocol: onnx, api_key_scheme: Bearer",
			"protocol: onnx, send_dimensions: true", "protocol: onnx, timeout: 1s",
			"protocol: openai, url: https://example.com, model: m, directory: /models",
			"protocol: openai, url: https://example.com, model: m, device: cpu",
			"protocol: openai, url: https://example.com, model: m, device_id: 1",
			"protocol: unknown, url: https://example.com, model: m",
		} {
			input := "services: {" + service + ": {enabled: true, revision: r, "
			if service == "embeddings" {
				input += "dimensions: 3, "
			}
			input += "upstream: {" + options + "}}}"
			if _, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" }); err == nil {
				t.Errorf("invalid config accepted: %s", input)
			}
		}
	}
}

func TestConfigRejectsFlatLocalBlocks(t *testing.T) {
	for _, field := range []string{"local_login", "local_rate_limit", "local_captcha", "local_mfa", "local_tokens"} {
		t.Run(field, func(t *testing.T) {
			_, err := decodeConfigForTest(strings.NewReader("authentication:\n  "+field+": {}\n"), func(string) string { return "" })
			if err == nil || !strings.Contains(err.Error(), "field "+field+" not found") {
				t.Fatalf("flat field must be rejected: %v", err)
			}
		})
	}
}

func TestOIDCIssuerEnabledConfiguration(t *testing.T) {
	for _, enabled := range []string{"", "      enabled: true\n", "      enabled: false\n"} {
		cfg, err := decodeConfigForTest(strings.NewReader(`authentication:
  oidc:
    - issuer: https://identity.example.com
      audiences: [graphit-broker]
      username_claim: preferred_username
`+enabled), func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		issuer := cfg.Authentication.OIDC[0]
		if issuer.Enabled == nil || issuer.isEnabled() != !strings.Contains(enabled, "false") {
			t.Fatalf("unexpected enabled default for %q", enabled)
		}
	}
	input := `authentication:
  oidc:
    - enabled: false
      issuer: invalid-placeholder
      client_id: disabled-browser
      redirect_url: invalid-placeholder
`
	if _, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" }); err != nil {
		t.Fatalf("disabled issuer should not need valid integration settings: %v", err)
	}
	if _, err := decodeConfigForTest(strings.NewReader(strings.Replace(input, "enabled: false", "enabled: true", 1)), func(string) string { return "" }); err == nil {
		t.Fatal("enabled invalid issuer was accepted")
	}
	input = `server:
  public_url: https://broker.example.com
authentication:
  token_pepper: ` + testPasswordPepper + `
  oidc:
    - enabled: false
      client_id: disabled-browser
    - enabled: true
      display_name: Corporate SSO
      issuer: https://identity.example.com
      audiences: [graphit-broker]
      username_claim: preferred_username
      client_id: active-browser
      redirect_url: https://broker.example.com/oauth/oidc/callback
`
	cfg, err := decodeConfigForTest(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	selected := browserLoginOIDCConfigs(cfg.Authentication.OIDC)
	if len(selected) != 1 || selected[0].ClientID != "active-browser" || selected[0].DisplayName != "Corporate SSO" {
		t.Fatalf("browser issuers=%#v", selected)
	}
	missingName := cfg
	missingName.Authentication.OIDC = append([]OIDCIssuerConfig(nil), cfg.Authentication.OIDC...)
	missingName.Authentication.OIDC[1].DisplayName = ""
	if err := missingName.Validate(); err == nil || !strings.Contains(err.Error(), "display_name is required") {
		t.Fatalf("browser client without display_name accepted: %v", err)
	}
	second := cfg.Authentication.OIDC[1]
	second.DisplayName = "Partner SSO"
	second.Issuer = "https://partner.example.com"
	second.ClientID = "partner-browser"
	cfg.Authentication.OIDC = append(cfg.Authentication.OIDC, second)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("multiple active browser clients rejected: %v", err)
	}
	if selected = browserLoginOIDCConfigs(cfg.Authentication.OIDC); len(selected) != 2 || selected[1].DisplayName != "Partner SSO" {
		t.Fatalf("multiple browser issuers=%#v", selected)
	}
}

func TestNestedLocalConfigurationJSONAndSecretRedaction(t *testing.T) {
	cfg, err := decodeConfigForTest(strings.NewReader(`authentication:
  local:
    login:
      enabled: false
    captcha:
      secret_key: private-captcha-secret
    tokens:
      audience: custom-audience
  oidc:
    - enabled: false
      client_secret: private-oidc-secret
`), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	redacted := redactConfig(cfg)
	data, err := json.Marshal(redacted.Authentication)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Local struct {
			Login   struct{ Enabled bool } `json:"login"`
			Captcha struct {
				SecretKey         string  `json:"secret_key"`
				TriggerMultiplier float64 `json:"trigger_multiplier"`
			} `json:"captcha"`
			Tokens struct{ Audience string } `json:"tokens"`
		} `json:"local"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Local.Login.Enabled || decoded.Local.Tokens.Audience != "custom-audience" || decoded.Local.Captcha.SecretKey != configuredSecret || decoded.Local.Captcha.TriggerMultiplier != 1.5 {
		t.Fatalf("nested config was not preserved/redacted: %s", data)
	}
	if strings.Contains(string(data), "local_") || strings.Contains(string(data), "private-") {
		t.Fatalf("legacy fields or secret leaked: %s", data)
	}
	if cfg.Authentication.Local.Captcha.SecretKey != "private-captcha-secret" || cfg.Authentication.OIDC[0].ClientSecret != "private-oidc-secret" {
		t.Fatal("redaction mutated runtime secrets")
	}
}
