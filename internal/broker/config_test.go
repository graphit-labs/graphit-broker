package broker

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

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
	cfg, err := DecodeConfig(strings.NewReader(input), func(name string) string {
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
			cfg, err := DecodeConfig(strings.NewReader(`
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
	base := Config{Server: ServerConfig{PublicURL: "https://broker.example.com"}, Authentication: AuthenticationConfig{
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

func TestServerPublicURLMustBeHTTPSOrigin(t *testing.T) {
	enabled := true
	base := Config{Server: ServerConfig{PublicURL: "https://broker.example.com"}, Authentication: AuthenticationConfig{
		TokenPepper: testPasswordPepper, Local: LocalAuthenticationConfig{Login: LocalLoginConfig{Enabled: &enabled}},
	}}
	base.defaults()
	for _, raw := range []string{
		"http://broker.example.com",
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
			cfg, err := DecodeConfig(strings.NewReader(`
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
	cfg, err := DecodeConfig(strings.NewReader(`
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
	cfg, err := DecodeConfig(strings.NewReader(`
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
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
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
			if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestConfigRejectsInsecureOIDCIssuer(t *testing.T) {
	cfg := Config{Authentication: AuthenticationConfig{TokenPepper: testPasswordPepper, OIDC: []OIDCIssuerConfig{{Issuer: "http://id.example", Audiences: []string{"broker"}, SubjectClaim: "sub", UsernameClaim: "sub"}}}}
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
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
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
	_, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
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
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
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
			if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err == nil {
				t.Fatal("legacy authentication field was accepted")
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
			if _, err := DecodeConfig(file, func(name string) string { return secrets[name] }); err != nil {
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
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
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
	if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err != nil {
		t.Fatalf("DecodeConfig error=%v", err)
	}
	unsupported := strings.Replace(input, "        access_key_id: public-access\n", "        unsupported_storage_field: removed\n", 1)
	if _, err := DecodeConfig(strings.NewReader(unsupported), func(string) string { return "" }); err == nil {
		t.Fatal("removed storage field was accepted")
	}
	legacy := "authorization:\n  rules: []\n"
	if _, err := DecodeConfig(strings.NewReader(legacy), func(string) string { return "" }); err == nil {
		t.Fatal("legacy authorization configuration was accepted")
	}
}

func TestConfigSupportsLocalBackendsDevicesAndLegacyUpstreams(t *testing.T) {
	input := `
services:
  embeddings:
    enabled: true
    backend: local
    revision: local-embedding-v1
    dimensions: 768
    local:
      device: auto
  rerank:
    enabled: true
    backend: local
    revision: local-rerank-v1
    local:
      device: cpu
`
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Services.Embeddings.Backend != "local" || cfg.Services.Embeddings.Local.Device != "auto" || cfg.Services.Rerank.Local.Device != "cpu" {
		t.Fatalf("local defaults=%#v", cfg.Services)
	}
	if cfg.Models.Directory != "/var/cache/graphit-broker/models" || cfg.Models.Embedding != "coderankembed" || cfg.Models.Rerank != "bge-reranker-base" {
		t.Fatalf("catalog defaults=%#v", cfg.Models)
	}

	legacy := Config{Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
		Enabled: true, Revision: "legacy", Dimensions: 3,
		Upstream: HTTPUpstreamConfig{Protocol: "openai-embeddings-v1", URL: "http://127.0.0.1/embeddings", Model: "legacy"},
	}}}
	legacy.defaults()
	if legacy.Services.Embeddings.Backend != "upstream" {
		t.Fatalf("legacy backend=%q", legacy.Services.Embeddings.Backend)
	}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy upstream rejected: %v", err)
	}
}

func TestConfigAcceptsEmbeddingProviderParityAndRejectsInvalidLocalDevice(t *testing.T) {
	for _, protocol := range embeddingUpstreamProtocols {
		cfg := Config{Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
			Enabled: true, Backend: "upstream", Revision: "r", Dimensions: 3,
			Upstream: HTTPUpstreamConfig{Protocol: protocol, URL: "https://provider.example/v1", Model: "model"},
		}}}
		cfg.defaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("protocol %q rejected: %v", protocol, err)
		}
	}
	coreML := Config{Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
		Enabled: true, Backend: "local", Revision: "r", Dimensions: localEmbeddingDimensions,
		Local: LocalModelConfig{Device: "coreml"},
	}}}
	coreML.defaults()
	if err := coreML.Validate(); err != nil {
		t.Fatalf("CoreML local device rejected: %v", err)
	}
	cfg := Config{Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
		Enabled: true, Backend: "local", Revision: "r", Dimensions: localEmbeddingDimensions,
		Local: LocalModelConfig{Device: "metal"},
	}}}
	cfg.defaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "auto, cpu, cuda, or coreml") {
		t.Fatalf("invalid local device error=%v", err)
	}
}

func TestConfigAcceptsRerankProviderParity(t *testing.T) {
	for _, protocol := range rerankUpstreamProtocols {
		cfg := Config{Services: ServicesConfig{Rerank: RerankServiceConfig{
			Enabled: true, Backend: "upstream", Revision: "r",
			Upstream: HTTPUpstreamConfig{Protocol: protocol, URL: "https://provider.example/v1", Model: "model"},
		}}}
		cfg.defaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("protocol %q rejected: %v", protocol, err)
		}
	}
}

func TestConfigSelectsCatalogModelsAndRejectsRemovedLegacyLocalFields(t *testing.T) {
	input := `
models:
  directory: /models
  embedding: custom-embedding
  rerank: custom-rerank
services:
  embeddings:
    enabled: true
    backend: local
    local:
      device: cpu
`
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatalf("catalog selection rejected: %v", err)
	}
	if cfg.Models.Directory != "/models" || cfg.Models.Embedding != "custom-embedding" {
		t.Fatalf("models=%#v", cfg.Models)
	}
	legacy := strings.Replace(input, "      device: cpu\n", "      device: cpu\n      model_path: /models/model.onnx\n", 1)
	if _, err := DecodeConfig(strings.NewReader(legacy), func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "field model_path not found") {
		t.Fatalf("removed legacy field error=%v", err)
	}
}

func TestConfigRejectsFlatLocalBlocks(t *testing.T) {
	for _, field := range []string{"local_login", "local_rate_limit", "local_captcha", "local_mfa", "local_tokens"} {
		t.Run(field, func(t *testing.T) {
			_, err := DecodeConfig(strings.NewReader("authentication:\n  "+field+": {}\n"), func(string) string { return "" })
			if err == nil || !strings.Contains(err.Error(), "field "+field+" not found") {
				t.Fatalf("flat field must be rejected: %v", err)
			}
		})
	}
}

func TestOIDCIssuerEnabledConfiguration(t *testing.T) {
	for _, enabled := range []string{"", "      enabled: true\n", "      enabled: false\n"} {
		cfg, err := DecodeConfig(strings.NewReader(`authentication:
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
	if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err != nil {
		t.Fatalf("disabled issuer should not need valid integration settings: %v", err)
	}
	if _, err := DecodeConfig(strings.NewReader(strings.Replace(input, "enabled: false", "enabled: true", 1)), func(string) string { return "" }); err == nil {
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
      issuer: https://identity.example.com
      audiences: [graphit-broker]
      username_claim: preferred_username
      client_id: active-browser
      redirect_url: https://broker.example.com/oauth/oidc/callback
`
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if selected, ok := browserLoginOIDC(cfg.Authentication.OIDC); !ok || selected.ClientID != "active-browser" {
		t.Fatal("did not select the active browser issuer")
	}
	cfg.Authentication.OIDC = append(cfg.Authentication.OIDC, cfg.Authentication.OIDC[1])
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("multiple active browser clients accepted: %v", err)
	}
}

func TestNestedLocalConfigurationJSONAndSecretRedaction(t *testing.T) {
	cfg, err := DecodeConfig(strings.NewReader(`authentication:
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
