package broker

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestServerAllowsOnlyExplicitAnonymousAndNeverDowngradesInvalidBearer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}}})
	}))
	defer upstream.Close()
	cfg := testServerConfig(upstream.URL, upstream.URL)
	cfg.Authorization.Rules = []ACLRuleConfig{{Name: "anonymous embeddings", Access: "anonymous", Capabilities: []string{"embeddings"}}}
	authenticator := authFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrUnauthenticated })
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
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

func TestServerAdminAPIProtectsAndAtomicallyUpdatesPolicy(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Administration = AdministrationConfig{Enabled: true, StateFile: t.TempDir() + "/access.json", APIKeys: []AdminKeyConfig{{Name: "owner", Token: "admin-secret"}}}
	policy, err := NewPolicyStore(cfg.Administration, cfg.Authorization, "acl-1", cfg.Services.S3)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServerWithDependencies(cfg, authFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrUnauthenticated }), NewAdminAuthenticator(cfg.Administration), NewAIService(cfg.Services), nil, policy))
	defer server.Close()

	page, err := http.Get(server.URL + "/admin/")
	if err != nil || page.StatusCode != http.StatusOK {
		t.Fatalf("admin page status=%s err=%v", statusText(page), err)
	}
	if page.Header.Get("Content-Security-Policy") == "" || page.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("admin page security headers missing: %#v", page.Header)
	}
	_ = page.Body.Close()
	unauthorized, _ := http.Get(server.URL + "/admin/api/v1/access")
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin API without token=%d", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()

	get, _ := http.NewRequest(http.MethodGet, server.URL+"/admin/api/v1/access", nil)
	get.Header.Set("Authorization", "Bearer admin-secret")
	current, err := http.DefaultClient.Do(get)
	if err != nil || current.StatusCode != http.StatusOK || current.Header.Get("ETag") != `"1"` {
		t.Fatalf("admin get status=%s etag=%q err=%v", statusText(current), current.Header.Get("ETag"), err)
	}
	_ = current.Body.Close()

	body := `{"v":1,"rules":[{"name":"public embeddings","access":"anonymous","capabilities":["embeddings"]}]}`
	put, _ := http.NewRequest(http.MethodPut, server.URL+"/admin/api/v1/access", bytes.NewBufferString(body))
	put.Header.Set("Authorization", "Bearer admin-secret")
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("If-Match", `"1"`)
	updated, err := http.DefaultClient.Do(put)
	if err != nil || updated.StatusCode != http.StatusOK || updated.Header.Get("ETag") != `"2"` {
		t.Fatalf("admin put status=%s etag=%q err=%v", statusText(updated), updated.Header.Get("ETag"), err)
	}
	_ = updated.Body.Close()
	if err := newServer(cfg, nil, nil).acl.AuthorizeCapability(AnonymousPrincipal(), "embeddings"); err == nil {
		t.Fatal("separate server unexpectedly shared policy")
	}
	if err := NewACLWithPolicy(policy).AuthorizeCapability(AnonymousPrincipal(), "embeddings"); err != nil {
		t.Fatalf("updated policy not effective: %v", err)
	}

	stale, _ := http.NewRequest(http.MethodPut, server.URL+"/admin/api/v1/access", bytes.NewBufferString(body))
	stale.Header.Set("Authorization", "Bearer admin-secret")
	stale.Header.Set("Content-Type", "application/json")
	stale.Header.Set("If-Match", `"1"`)
	conflict, err := http.DefaultClient.Do(stale)
	if err != nil || conflict.StatusCode != http.StatusConflict {
		t.Fatalf("stale update status=%s err=%v", statusText(conflict), err)
	}
	_ = conflict.Body.Close()
}

func TestServerPresignsAnonymousRequestOnlyWhenACLAllowsIt(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Services.S3.PresignExpiry = time.Minute
	cfg.Services.S3.MaxPresignExpiry = 5 * time.Minute
	cfg.Authorization.Rules = []ACLRuleConfig{{Name: "public project", Access: "anonymous", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"read"}, S3Prefixes: []string{"v2/projects/{project}"}}}
	policy, _ := NewPolicyStore(AdministrationConfig{}, cfg.Authorization, "acl-1", cfg.Services.S3)
	called := false
	presigner := presignFunc(func(_ context.Context, grant S3Grant, request PresignRequest) (PresignResponse, error) {
		called = true
		if request.Operation != "get" || grant.Project != "project-a" {
			t.Fatalf("grant=%#v request=%#v", grant, request)
		}
		return PresignResponse{Method: http.MethodGet, URL: "https://s3.example/signed", ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	server := httptest.NewServer(newServerWithDependencies(cfg, authFunc(func(context.Context, string) (Principal, error) { return Principal{}, ErrUnauthenticated }), nil, NewAIService(cfg.Services), presigner, policy))
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

func testServerConfig(embeddingURL, rerankURL string) Config {
	return Config{
		Server: ServerConfig{MaxRequestBytes: 1 << 20},
		Authorization: AuthorizationConfig{Rules: []ACLRuleConfig{
			{Name: "ai", Organizations: []string{"acme"}, Capabilities: []string{"embeddings", "rerank"}},
			{Name: "s3", Organizations: []string{"acme"}, Teams: []string{"platform"}, Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"publish"}, S3Prefixes: []string{"v2/projects/{project}"}},
		}},
		Services: ServicesConfig{
			Embeddings: EmbeddingServiceConfig{Enabled: true, Route: "default", Revision: "embed-r1", Dimensions: 3, MaxBatch: 10, MaxInputBytes: 1000, Upstream: HTTPUpstreamConfig{URL: embeddingURL, Protocol: "openai-embeddings-v1", Model: "internal-embedding", Timeout: time.Second}},
			Rerank:     RerankServiceConfig{Enabled: true, Route: "default", Revision: "rerank-r1", MaxDocuments: 10, MaxDocumentBytes: 1000, Upstream: HTTPUpstreamConfig{URL: rerankURL, Protocol: "graphit-rerank-v1", Model: "internal-rerank", Timeout: time.Second}},
			S3:         S3ServiceConfig{Enabled: true, DefaultRoute: "primary", Routes: map[string]S3RouteConfig{"primary": {Bucket: "bucket", Region: "us-east-1", BasePrefix: "base", AccessKeyID: "TESTACCESS", SecretAccessKey: "TESTSECRET"}}, AuthorizationRevision: "acl-1", PresignExpiry: time.Minute, MaxPresignExpiry: 5 * time.Minute},
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
