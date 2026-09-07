package broker

import (
	"strings"
	"testing"
)

func TestDecodeConfigExpandsRequiredEnvironmentAndDefaults(t *testing.T) {
	input := `
authentication:
  api_keys:
    - name: local
      token: "${TOKEN:?TOKEN is required}"
      subject: service
      username: service
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
		if name == "TOKEN" {
			return "secret"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if cfg.Server.Address != ":8080" || cfg.Services.Embeddings.MaxBatch != 256 {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	if cfg.Authentication.APIKeys[0].Token != "secret" {
		t.Fatal("environment value was not expanded")
	}
}

func TestDecodeConfigRejectsUnknownFieldsAndMissingEnvironment(t *testing.T) {
	for name, input := range map[string]string{
		"unknown":     "unknown: true\n",
		"environment": "authentication:\n  api_keys:\n    - token: '${TOKEN:?required}'\n",
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

func TestAdministrationConfigUsesEnvironmentSuperadminAndRejectsRemoteHTTPCallback(t *testing.T) {
	input := `
database:
  driver: sqlite
  dsn: /tmp/broker.db
administration:
  enabled: true
  superadmin_subject: yaml-subject
  session_ttl: 1h
  oidc:
    issuer: https://identity.example.com
    client_id: broker-admin
    client_secret: secret
    redirect_url: http://localhost:8080/admin/auth/callback
`
	cfg, err := DecodeConfig(strings.NewReader(input), func(name string) string {
		if name == "BROKER_SUPERADMIN_SUBJECT" {
			return "environment-subject"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Administration.SuperadminSubject != "environment-subject" {
		t.Fatalf("superadmin=%q", cfg.Administration.SuperadminSubject)
	}
	cfg.Administration.OIDC.RedirectURL = "http://broker.example.com/admin/auth/callback"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS except on loopback") {
		t.Fatalf("remote HTTP callback validation=%v", err)
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
      cache_dir: /tmp/models/embedding
  rerank:
    enabled: true
    backend: local
    revision: local-rerank-v1
    local:
      device: cpu
      cache_dir: /tmp/models/rerank
`
	cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Services.Embeddings.Backend != "local" || cfg.Services.Embeddings.Local.Device != "auto" || cfg.Services.Rerank.Local.Device != "cpu" {
		t.Fatalf("local defaults=%#v", cfg.Services)
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
	cfg := Config{Services: ServicesConfig{Embeddings: EmbeddingServiceConfig{
		Enabled: true, Backend: "local", Revision: "r", Dimensions: localEmbeddingDimensions,
		Local: LocalModelConfig{Device: "metal", CacheDir: "/tmp/models"},
	}}}
	cfg.defaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "auto, cpu, or cuda") {
		t.Fatalf("invalid local device error=%v", err)
	}
}

func TestConfigAcceptsOperatorProvidedEmbeddingModelAndValidatesItsPaths(t *testing.T) {
	input := `
services:
  embeddings:
    enabled: true
    backend: local
    revision: custom-embedding-v1
    dimensions: 1024
    local:
      device: cpu
      cache_dir: /var/cache/graphit-broker/models/custom
      model_path: /models/custom/model.onnx
      tokenizer_path: /models/custom/tokenizer.json
      model_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      tokenizer_sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      output_name: sentence_embedding
      query_prefix: "query: "
      max_length: 1024
`
	if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err != nil {
		t.Fatalf("custom local embedding rejected: %v", err)
	}
	missingTokenizer := strings.Replace(input, "      tokenizer_path: /models/custom/tokenizer.json\n", "", 1)
	if _, err := DecodeConfig(strings.NewReader(missingTokenizer), func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "must be set together") {
		t.Fatalf("unpaired paths error=%v", err)
	}
}
