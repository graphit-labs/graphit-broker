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

type credentialFunc func(context.Context, Principal, string, S3Grant) (CredentialResponse, error)

func (f credentialFunc) Issue(ctx context.Context, p Principal, t string, g S3Grant) (CredentialResponse, error) {
	return f(ctx, p, t, g)
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
	principal := Principal{Issuer: "https://id", Subject: "s", Username: "alice", Organization: "acme", Teams: []string{"platform"}}
	authenticator := authFunc(func(_ context.Context, token string) (Principal, error) {
		if token != "valid" {
			return Principal{}, ErrUnauthenticated
		}
		return principal, nil
	})
	issued := false
	issuer := credentialFunc(func(_ context.Context, p Principal, token string, grant S3Grant) (CredentialResponse, error) {
		issued = true
		if token != "valid" || grant.Project != "project-a" {
			t.Fatalf("token=%q grant=%#v", token, grant)
		}
		return CredentialResponse{AccessKeyID: "A", SecretAccessKey: "S", SessionToken: "T", ExpiresAt: time.Now().Add(time.Hour), Bucket: "bucket", Region: "us-east-1", Prefixes: grant.Prefixes, AuthorizationRevision: "acl-1"}, nil
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services), issuer))
	defer server.Close()

	for _, path := range []string{"/healthz", "/readyz", "/.well-known/graphit-broker"} {
		resp, err := http.Get(server.URL + path)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%v err=%v", path, status(resp), err)
		}
		_ = resp.Body.Close()
	}
	resp := post(t, server.URL+"/v1/embeddings", "", `{"input":"hello"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", resp.StatusCode)
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
	resp = post(t, server.URL+"/v1/s3/credentials", "valid", `{"project":"project-a","operation":"publish"}`)
	if resp.StatusCode != http.StatusOK || !issued {
		t.Fatalf("s3 status=%d issued=%v", resp.StatusCode, issued)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("credential response is cacheable")
	}
	_ = resp.Body.Close()
}

func TestServerFailsClosedForACLAndStrictJSON(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "i", Subject: "s", Username: "mallory", Organization: "other"}, nil
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services), credentialFunc(func(context.Context, Principal, string, S3Grant) (CredentialResponse, error) {
		return CredentialResponse{}, errors.New("must not run")
	})))
	defer server.Close()
	resp := post(t, server.URL+"/v1/embeddings", "anything", `{"input":"x"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ACL status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	allowed := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "i", Subject: "s", Username: "alice", Organization: "acme"}, nil
	})
	strictServer := httptest.NewServer(newServer(cfg, allowed, NewAIService(cfg.Services), nil))
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
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services), nil))
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
			{Name: "s3", Organizations: []string{"acme"}, Teams: []string{"platform"}, Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"publish"}, S3Prefixes: []string{"projects/{project}"}},
		}},
		Services: ServicesConfig{
			Embeddings: EmbeddingServiceConfig{Enabled: true, Route: "default", Revision: "embed-r1", Dimensions: 3, MaxBatch: 10, MaxInputBytes: 1000, Upstream: HTTPUpstreamConfig{URL: embeddingURL, Protocol: "openai-embeddings-v1", Model: "internal-embedding", Timeout: time.Second}},
			Rerank:     RerankServiceConfig{Enabled: true, Route: "default", Revision: "rerank-r1", MaxDocuments: 10, MaxDocumentBytes: 1000, Upstream: HTTPUpstreamConfig{URL: rerankURL, Protocol: "graphit-rerank-v1", Model: "internal-rerank", Timeout: time.Second}},
			S3:         S3ServiceConfig{Enabled: true, Bucket: "bucket", Region: "us-east-1", BasePrefix: "base", AuthorizationRevision: "acl-1"},
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
