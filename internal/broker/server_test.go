package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type authFunc func(context.Context, string) (Principal, error)

func (f authFunc) Authenticate(ctx context.Context, token string) (Principal, error) {
	return f(ctx, token)
}

type presignFunc func(context.Context, S3Grant, PresignRequest) (PresignResponse, error)

func (f presignFunc) Presign(ctx context.Context, grant S3Grant, request PresignRequest) (PresignResponse, error) {
	return f(ctx, grant, request)
}

type failingGrantReader struct{}

func (failingGrantReader) ResourceGrants(context.Context) (PolicyDocument, error) {
	return PolicyDocument{}, errors.New("synthetic database outage")
}

func defaultTestRules() []ACLRuleConfig {
	return []ACLRuleConfig{
		{ID: "ai", Name: "ai", Access: "organization", Principal: "acme", Capabilities: []string{"embeddings", "rerank"}},
		{ID: "s3", Name: "s3", Access: "team", Principal: "platform", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"publish"}, S3Prefixes: []string{"v2/projects/{project}"}},
	}
}

func newServer(cfg Config, authenticator Authenticator, ai *AIService) *Server {
	var presigner PresignService
	if cfg.Services.S3.Enabled {
		presigner = NewAWSPresignService(cfg.Services.S3)
	}
	return newServerWithDependencies(cfg, authenticator, ai, presigner, &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: defaultTestRules()}}, nil, nil)
}

func TestServerDiscoveryHealthAuthenticationACLAndCapabilities(t *testing.T) {
	embeddingUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["model"] != "internal-embedding" {
			t.Errorf("model=%v", body["model"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}}})
	}))
	defer embeddingUpstream.Close()
	rerankUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{map[string]any{"index": 0, "relevance_score": 0.8}}})
	}))
	defer rerankUpstream.Close()
	cfg := testServerConfig(embeddingUpstream.URL, rerankUpstream.URL)
	cfg.Services.S3.PresignExpiry = time.Minute
	cfg.Services.S3.MaxPresignExpiry = 5 * time.Minute
	principal := Principal{Issuer: "https://id", Subject: "s", Username: "alice", Organization: "acme", Teams: []string{"platform"}}
	authenticator := authFunc(func(_ context.Context, token string) (Principal, error) {
		if token != "valid" {
			return Principal{}, ErrUnauthenticated
		}
		return principal, nil
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
	defer server.Close()

	for _, path := range []string{"/healthz", "/readyz", "/.well-known/graphit-broker"} {
		resp, err := http.Get(server.URL + path)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%v err=%v", path, status(resp), err)
		}
		_ = resp.Body.Close()
	}
	resp := post(t, server.URL+"/v1/embeddings", "", `{"input":"hello"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous denied status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/embeddings", "valid", `{"model":"user-cannot-select-this","input":"hello"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("embedding status=%d", resp.StatusCode)
	}
	if resp.Header.Get("X-Graphit-Embedding-Revision") != "embed-r1" {
		t.Fatal("missing embedding revision")
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/rerank", "valid", `{"query":"q","documents":["a"],"top_n":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rerank status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/presign", "valid", `{"project":"project-a","operation":"put","key":"v2/projects/project-a/object"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("s3 status=%d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("presign response is cacheable")
	}
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte("secret_access_key")) || bytes.Contains(body, []byte("access_key_id")) || bytes.Contains(body, []byte(`"bucket"`)) {
		t.Fatalf("presign response exposed broker-owned storage details: %s", body)
	}
	_ = resp.Body.Close()
}

func TestAuthorizationBackendFailureReturnsServiceUnavailable(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1", "http://127.0.0.1")
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "https://id", Subject: "subject", Username: "alice"}, nil
	})
	server := httptest.NewServer(newServerWithDependencies(cfg, authenticator, NewAIService(cfg.Services), nil, failingGrantReader{}, nil, nil))
	defer server.Close()

	response := post(t, server.URL+"/v1/embeddings", "synthetic-token", `{"input":"hello"}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestServerAllowsOnlyExplicitAnonymousAndNeverDowngradesInvalidBearer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}}})
	}))
	defer upstream.Close()
	cfg := testServerConfig(upstream.URL, upstream.URL)
	authenticator := authFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrUnauthenticated })
	grants := &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: []ACLRuleConfig{{
		ID: "anonymous-embeddings", Name: "anonymous embeddings", Access: "anonymous", Capabilities: []string{"embeddings"},
	}}}}
	server := httptest.NewServer(newServerWithDependencies(cfg, authenticator, NewAIService(cfg.Services), nil, grants, nil, nil))
	defer server.Close()

	resp := post(t, server.URL+"/v1/embeddings", "", `{"input":"hello"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/embeddings", "invalid", `{"input":"hello"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid bearer was downgraded to anonymous: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestServerPresignsAnonymousRequestOnlyWhenACLAllowsIt(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Services.S3.PresignExpiry = time.Minute
	cfg.Services.S3.MaxPresignExpiry = 5 * time.Minute
	grants := &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: []ACLRuleConfig{{
		ID: "public-project", Name: "public project", Access: "anonymous", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"read"}, S3Prefixes: []string{"v2/projects/{project}"},
	}}}}
	called := false
	presigner := presignFunc(func(_ context.Context, grant S3Grant, request PresignRequest) (PresignResponse, error) {
		called = true
		if request.Operation != "get" || grant.Project != "project-a" {
			t.Fatalf("grant=%#v request=%#v", grant, request)
		}
		return PresignResponse{Method: http.MethodGet, URL: "https://s3.example/signed", ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	server := httptest.NewServer(newServerWithDependencies(cfg, authFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrUnauthenticated }), NewAIService(cfg.Services), presigner, grants, nil, nil))
	defer server.Close()
	resp := post(t, server.URL+"/v1/s3/presign", "", `{"project":"project-a","operation":"get","key":"v2/projects/project-a/object"}`)
	if resp.StatusCode != http.StatusOK || !called {
		t.Fatalf("presign status=%d called=%v", resp.StatusCode, called)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/presign", "", `{"project":"project-a","operation":"put","key":"v2/projects/project-a/object"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous write status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/presign", "", `{"project":"project-a","operation":"get","key":"v2/projects/other/object"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched project/key status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestServerHubAccessResolutionUsesVerifiedBearerOrAnonymousPrincipal(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	grants := &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 7, Rules: []ACLRuleConfig{
		{ID: "public", Name: "public", Access: "anonymous", Capabilities: []string{"hub"}, Projects: []string{"public-project"}},
		{ID: "team", Name: "team", Access: "team", Principal: "platform", Capabilities: []string{"hub"}, Projects: []string{"project-a", "project-b"}},
	}}}
	authenticator := authFunc(func(_ context.Context, token string) (Principal, error) {
		if token != "verified-token" {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{Issuer: "https://id.example", Subject: "subject-1", Teams: []string{"platform"}, AuthMethod: "oidc"}, nil
	})
	server := httptest.NewServer(newServerWithDependencies(cfg, authenticator, NewAIService(cfg.Services), nil, grants, nil, nil))
	defer server.Close()

	response := post(t, server.URL+"/v1/hub/access/resolve", "verified-token", `{}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var body struct {
		Revision  string               `json:"authorization_revision"`
		Subject   string               `json:"subject"`
		Selectors []hubProjectSelector `json:"selectors"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Revision != "7" || body.Subject != "https://id.example|subject-1" || len(body.Selectors) != 2 {
		t.Fatalf("body=%#v", body)
	}

	anonymous := post(t, server.URL+"/v1/hub/access/resolve", "", `{}`)
	defer anonymous.Body.Close()
	var anonymousBody struct {
		Selectors []hubProjectSelector `json:"selectors"`
	}
	_ = json.NewDecoder(anonymous.Body).Decode(&anonymousBody)
	if anonymous.StatusCode != http.StatusOK || len(anonymousBody.Selectors) != 1 || anonymousBody.Selectors[0].ID != "public-project" {
		t.Fatalf("anonymous status=%d body=%#v", anonymous.StatusCode, anonymousBody)
	}
}

func TestServerFailsClosedForACLAndStrictJSON(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "i", Subject: "s", Username: "mallory", Organization: "other"}, nil
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
	defer server.Close()
	resp := post(t, server.URL+"/v1/embeddings", "anything", `{"input":"x"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ACL status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	allowed := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "i", Subject: "s", Username: "alice", Organization: "acme"}, nil
	})
	strictServer := httptest.NewServer(newServer(cfg, allowed, NewAIService(cfg.Services)))
	defer strictServer.Close()
	resp = post(t, strictServer.URL+"/v1/embeddings", "anything", `{"input":"x","unexpected":true}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("strict JSON status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestServerDoesNotExposeUpstreamErrorBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `provider rejected secret upstream-key-value`, http.StatusUnauthorized)
	}))
	defer upstream.Close()
	cfg := testServerConfig(upstream.URL, upstream.URL)
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "i", Subject: "s", Username: "alice", Organization: "acme"}, nil
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
	defer server.Close()
	resp := post(t, server.URL+"/v1/embeddings", "valid", `{"input":"x"}`)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("upstream-key-value")) || bytes.Contains(body, []byte("provider rejected")) {
		t.Fatalf("upstream details leaked: %s", body)
	}
}

func TestServerEmbeddingInputTypeDefaultsToDocumentAndRejectsUnknownValue(t *testing.T) {
	seen := make(chan map[string]any, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen <- body
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}}})
	}))
	defer upstream.Close()
	cfg := testServerConfig(upstream.URL, upstream.URL)
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "i", Subject: "s", Organization: "acme"}, nil
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
	defer server.Close()

	response := post(t, server.URL+"/v1/embeddings", "valid", `{"input":"hello"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("default input_type status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
	if body := <-seen; body["input_type"] != nil {
		t.Fatalf("OpenAI upstream unexpectedly received broker extension: %#v", body)
	}

	response = post(t, server.URL+"/v1/embeddings", "valid", `{"input":"hello","input_type":"classification"}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid input_type status=%d", response.StatusCode)
	}
}

func testServerConfig(embeddingURL, rerankURL string) Config {
	return Config{
		Database: DatabaseConfig{Driver: "sqlite", DSN: ":memory:", MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute},
		Server:   ServerConfig{MaxRequestBytes: 1 << 20},
		Services: ServicesConfig{
			Embeddings: EmbeddingServiceConfig{Enabled: true, Route: "default", Revision: "embed-r1", Dimensions: 3, MaxBatch: 10, MaxInputBytes: 1000, Upstream: HTTPUpstreamConfig{URL: embeddingURL, Protocol: "openai-embeddings-v1", Model: "internal-embedding", Timeout: time.Second}},
			Rerank:     RerankServiceConfig{Enabled: true, Route: "default", Revision: "rerank-r1", MaxDocuments: 10, MaxDocumentBytes: 1000, Upstream: HTTPUpstreamConfig{URL: rerankURL, Protocol: "graphit-rerank-v1", Model: "internal-rerank", Timeout: time.Second}},
			S3:         S3ServiceConfig{Enabled: true, DefaultRoute: "primary", Routes: map[string]S3RouteConfig{"primary": {Bucket: "bucket", Region: "us-east-1", BasePrefix: "base", AccessKeyID: "TESTACCESS", SecretAccessKey: "TESTSECRET"}}, PresignExpiry: time.Minute, MaxPresignExpiry: 5 * time.Minute},
		},
	}
}

func post(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func status(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

func statusText(resp *http.Response) string {
	if resp == nil {
		return "<nil>"
	}
	return resp.Status
}
