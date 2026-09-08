package broker

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestDecodeConfigExpandsRequiredEnvironmentAndDefaults(t *testing.T) {
	input := `
authentication:
  api_keys:
    - username: service
      password_hash: "${PASSWORD_HASH:?PASSWORD_HASH is required}"
      pepper: "${PASSWORD_PEPPER:?PASSWORD_PEPPER is required}"
      subject: service
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
		switch name {
		case "PASSWORD_HASH":
			return mustPasswordHash(t, "secret")
		case "PASSWORD_PEPPER":
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
	if cfg.Authentication.APIKeys[0].PasswordHash == "" {
		t.Fatal("environment value was not expanded")
	}
}

func TestDecodeConfigRejectsUnknownFieldsAndMissingEnvironment(t *testing.T) {
	for name, input := range map[string]string{
		"unknown":     "unknown: true\n",
		"environment": "authentication:\n  api_keys:\n    - password_hash: '${PASSWORD_HASH:?required}'\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestConfigRejectsInsecureOIDCIssuer(t *testing.T) {
	cfg := Config{Authentication: AuthenticationConfig{OIDC: []OIDCIssuerConfig{{Issuer: "http://id.example", Audiences: []string{"broker"}, UsernameClaim: "sub"}}}}
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
authentication:
  oidc:
    - issuer: https://identity.example.com
      audiences: [graphit-broker]
      username_claim: preferred_username
      organization_claim: $.organization.id
      teams_claim: $.groups[*]
administration:
  enabled: true
  token_pepper: 0123456789abcdef0123456789abcdef
  session_ttl: 1h
  cli:
    oidc_client_id: graphit-cli
  oidc:
    issuer: https://identity.example.com
    client_id: broker-admin
    client_secret: secret
    redirect_url: http://localhost:8080/admin/auth/callback
    role_claim: $.realm_access.roles[*]
`
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Administration.CLI.ProviderName != "organization-broker" || cfg.Administration.OIDC.UsernameClaim != "preferred_username" || cfg.Administration.OIDC.TeamsClaim != "$.groups[*]" || cfg.Administration.OIDC.RoleClaim != "$.realm_access.roles[*]" || cfg.Administration.OIDC.NameClaim != "name" || cfg.Administration.OIDC.EmailClaim != "email" {
		t.Fatalf("administration defaults=%#v", cfg.Administration)
	}
	cfg.Administration.OIDC.RedirectURL = "http://broker.example.com/admin/auth/callback"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS except on loopback") {
		t.Fatalf("remote HTTP callback validation=%v", err)
	}
	cfg.Administration.OIDC.RedirectURL = "http://localhost:8080/admin/auth/callback"
	cfg.Administration.CLI.OIDCRedirectURI = "https://identity.example.com/callback"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTP loopback") {
		t.Fatalf("CLI callback validation=%v", err)
	}
}

func TestConfigRejectsInvalidClaimJSONPath(t *testing.T) {
	input := `
authentication:
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

func TestAdministrationAllowsLocalAPIKeyWithoutOIDC(t *testing.T) {
	input := `
database:
  driver: sqlite
  dsn: /tmp/broker.db
authentication:
  api_keys:
    - username: root
      password_hash: "${PASSWORD_HASH:?required}"
      pepper: "${PASSWORD_PEPPER:?required}"
      subject: local-root
      roles: [admin]
administration:
  enabled: true
  token_pepper: 0123456789abcdef0123456789abcdef
  session_ttl: 1h
`
	cfg, err := DecodeConfig(strings.NewReader(input), func(name string) string {
		switch name {
		case "PASSWORD_HASH":
			return mustPasswordHash(t, "local-secret")
		case "PASSWORD_PEPPER":
			return testPasswordPepper
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Administration.OIDC.configured() || cfg.Administration.CLI.ProviderName != "organization-broker" {
		t.Fatalf("local administration config=%#v", cfg.Administration)
	}
}

func TestAdministrationRequiresExternalTokenPepper(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Authentication.APIKeys = []APIKeyConfig{{Username: "admin", PasswordHash: mustPasswordHash(t, "password"), Pepper: testPasswordPepper, Subject: "admin", Roles: []string{adminRole}}}
	cfg.Administration = AdministrationConfig{Enabled: true, SessionTTL: time.Hour}
	cfg.defaults()
	for _, pepper := range []string{"", "too-short"} {
		cfg.Administration.TokenPepper = pepper
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "token_pepper") {
			t.Fatalf("pepper %q validation=%v", pepper, err)
		}
	}
	cfg.Administration.TokenPepper = testTokenPepper
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid pepper rejected: %v", err)
	}
}

func TestConfigRejectsLegacyLocalCredentialFields(t *testing.T) {
	for _, field := range []string{"token", "token_" + "sha256"} {
		input := "authentication:\n  api_keys:\n    - username: local\n      " + field + ": secret\n      pepper: " + testPasswordPepper + "\n      subject: local\n"
		if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err == nil {
			t.Fatalf("legacy field %s was accepted", field)
		}
	}
}

func TestConfigRequiresUniqueUsernameAndStrongPasswordPepper(t *testing.T) {
	validHash := mustPasswordHash(t, "password")
	for name, input := range map[string]string{
		"legacy name":        "authentication:\n  api_keys:\n    - name: local\n      username: local\n      password_hash: '" + validHash + "'\n      pepper: " + testPasswordPepper + "\n      subject: local\n",
		"missing pepper":     "authentication:\n  api_keys:\n    - username: local\n      password_hash: '" + validHash + "'\n      subject: local\n",
		"short pepper":       "authentication:\n  api_keys:\n    - username: local\n      password_hash: '" + validHash + "'\n      pepper: too-short\n      subject: local\n",
		"duplicate username": "authentication:\n  api_keys:\n    - username: local\n      password_hash: '" + validHash + "'\n      pepper: " + testPasswordPepper + "\n      subject: one\n    - username: local\n      password_hash: '" + validHash + "'\n      pepper: " + testPasswordPepper + "\n      subject: two\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err == nil {
				t.Fatal("invalid local identity configuration was accepted")
			}
		})
	}
}

func TestConfigAcceptsLiteralOrEnvironmentPasswordPepper(t *testing.T) {
	hash := mustPasswordHash(t, "password")
	for name, pepper := range map[string]string{
		"literal":     testPasswordPepper,
		"environment": "${PASSWORD_PEPPER:?required}",
	} {
		t.Run(name, func(t *testing.T) {
			input := "authentication:\n  api_keys:\n    - username: local\n      password_hash: '" + hash + "'\n      pepper: '" + pepper + "'\n      subject: local\n"
			cfg, err := DecodeConfig(strings.NewReader(input), func(variable string) string {
				if variable == "PASSWORD_PEPPER" {
					return testPasswordPepper
				}
				return ""
			})
			if err != nil || cfg.Authentication.APIKeys[0].Pepper != testPasswordPepper {
				t.Fatalf("pepper=%q err=%v", cfg.Authentication.APIKeys[0].Pepper, err)
			}
		})
	}
}

func TestRepositoryConfigurationExamplesDecodeWithInjectedSecrets(t *testing.T) {
	hash := mustPasswordHash(t, "example-password")
	secrets := map[string]string{
		"BROKER_EXAMPLE_PASSWORD_HASH":    hash,
		"BROKER_EXAMPLE_PASSWORD_PEPPER":  testPasswordPepper,
		"BROKER_ADMIN_TOKEN_PEPPER":       testTokenPepper,
		"BROKER_ADMIN_OIDC_ISSUER":        "https://identity.example.com",
		"BROKER_ADMIN_OIDC_CLIENT_ID":     "broker-admin",
		"BROKER_ADMIN_OIDC_CLIENT_SECRET": "oidc-secret",
		"BROKER_ADMIN_OIDC_REDIRECT_URL":  "https://broker.example.com/admin/auth/callback",
		"OPENAI_API_KEY":                  "openai-secret", "COHERE_API_KEY": "cohere-secret",
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
    presign_expiry: 1m
    max_presign_expiry: 5m
    routes:
      primary:
        bucket: primary
        access_key_id: primary-access
        secret_access_key: primary-secret
      archive:
        region: us-west-2
        endpoint: https://objects.example.com
        bucket: archive
        base_prefix: tenant-a
        access_key_id: archive-access
        secret_access_key: archive-secret
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

func TestConfigAllowsAnonymousDirectStorageRouteAndRejectsLegacyFields(t *testing.T) {
	input := `
services:
  s3:
    enabled: true
    default_route: oidc
    routes:
      oidc:
        bucket: private
        access_key_id: public-access
        secret_access_key: public-secret
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
