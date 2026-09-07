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
authorization:
  rules:
    - name: allow
      subjects: [service]
      capabilities: [embeddings]
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

func TestS3RoutesAreBrokerPrivateAndACLSelectable(t *testing.T) {
	input := `
authorization:
  rules:
    - name: tenant archive
      access: authenticated
      capabilities: [s3]
      projects: [project-a]
      s3_route: archive
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
	cfg.Authorization.Rules[0].S3Route = "missing"
	if err := cfg.Validate(); err == nil {
		t.Fatal("ACL accepted an unknown storage route")
	}
}

func TestConfigAllowsAnonymousDirectStorageRouteAndRejectsLegacyFields(t *testing.T) {
	input := `
authorization:
  rules:
    - name: public
      access: anonymous
      capabilities: [s3]
      s3_route: oidc
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
	legacy := strings.Replace(input, "        access_key_id: public-access\n", "        unsupported_storage_field: legacy\n", 1)
	if _, err := DecodeConfig(strings.NewReader(legacy), func(string) string { return "" }); err == nil {
		t.Fatal("legacy storage field was accepted")
	}
}
