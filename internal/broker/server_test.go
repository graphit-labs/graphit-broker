package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type authFunc func(context.Context, string) (Principal, error)

func (f authFunc) Authenticate(ctx context.Context, token string) (Principal, error) {
	return f(ctx, token)
}

type credentialFunc func(context.Context, S3RouteConfig, S3SessionGrant, Principal) (S3CredentialsResponse, error)

func (f credentialFunc) Issue(ctx context.Context, route S3RouteConfig, grant S3SessionGrant, principal Principal) (S3CredentialsResponse, error) {
	return f(ctx, route, grant, principal)
}

type failingGrantReader struct{}

func (failingGrantReader) ResourceGrants(context.Context) (PolicyDocument, error) {
	return PolicyDocument{}, errors.New("synthetic database outage")
}

func newServerWithDependencies(cfg Config, authenticator Authenticator, ai *AIService, credentials S3CredentialService, grants ResourceGrantReader, control *ControlStore, adminOIDC AdminIdentityProvider) *Server {
	var browserProviders []browserOIDCProvider
	if adminOIDC != nil {
		configs := browserLoginOIDCConfigs(cfg.Authentication.OIDC)
		if len(configs) != 1 {
			panic("test server with OIDC identity requires exactly one browser configuration")
		}
		browserProviders = []browserOIDCProvider{{ID: browserOIDCProviderID(configs[0]), Name: browserOIDCProviderName(configs[0]), Identity: adminOIDC}}
	}
	runtime := &runtimeState{config: cfg, authenticator: authenticator, acl: NewACL(grants), ai: ai, s3Credentials: credentials, browserOIDC: browserProviders}
	server, err := newServerFromRuntime(runtime, control)
	if err != nil {
		panic(err)
	}
	return server
}

func defaultTestRules() []ACLRuleConfig {
	return []ACLRuleConfig{
		{ID: "ai", Name: "ai", Access: "organization", Principal: "acme", Capabilities: []string{"embeddings", "rerank"}},
		{ID: "s3", Name: "s3", Access: "team", Principal: "platform", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"publish"}, S3Prefixes: []string{"v2/projects/{project}"}},
	}
}

func newServer(cfg Config, authenticator Authenticator, ai *AIService) *Server {
	var credentials S3CredentialService
	if cfg.Services.S3.Enabled {
		credentials = credentialFunc(func(_ context.Context, route S3RouteConfig, grant S3SessionGrant, _ Principal) (S3CredentialsResponse, error) {
			return S3CredentialsResponse{AccessKeyID: "temporary-access", SecretAccessKey: "temporary-secret", SessionToken: "temporary-token", ExpiresAt: time.Now().Add(time.Hour), Bucket: route.Bucket, Region: route.Region, Endpoint: route.Endpoint, Prefixes: []string{route.BasePrefix}, AuthorizationRevision: grant.Revision, Scope: grant.Scope.Kind, ProjectID: grant.Scope.ProjectID}, nil
		})
	}
	return newServerWithDependencies(cfg, authenticator, ai, credentials, &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: defaultTestRules()}}, nil, nil)
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
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
	defer server.Close()

	for _, path := range []string{"/healthz", "/readyz", "/.well-known/graphit-broker"} {
		resp, err := http.Get(server.URL + path)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%v err=%v", path, status(resp), err)
		}
		_ = resp.Body.Close()
	}
	discoveryResponse, err := http.Get(server.URL + "/.well-known/graphit-broker")
	if err != nil {
		t.Fatal(err)
	}
	var discovery struct {
		Services map[string]struct {
			Protocol string          `json:"protocol"`
			Path     string          `json:"path"`
			Route    json.RawMessage `json:"route"`
		} `json:"services"`
	}
	if err := json.NewDecoder(discoveryResponse.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	_ = discoveryResponse.Body.Close()
	for _, name := range []string{"embeddings", "rerank"} {
		service, ok := discovery.Services[name]
		if !ok || service.Path != "/v1/"+name || len(service.Route) != 0 {
			t.Fatalf("%s discovery=%#v", name, service)
		}
	}
	storage, ok := discovery.Services["s3_credentials"]
	if !ok || storage.Protocol != "graphit-s3-credentials-v2" || storage.Path != "/v1/s3/credentials" {
		t.Fatalf("storage discovery=%#v", discovery.Services)
	}
	if _, legacy := discovery.Services["s3_presign"]; legacy {
		t.Fatalf("legacy presign discovery remains: %#v", discovery.Services)
	}
	resp := post(t, server.URL+"/v1/embeddings", "", `{"input":"hello"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous denied status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/embeddings", "valid", `{"input":"hello"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("embedding status=%d", resp.StatusCode)
	}
	if resp.Header.Get("X-Graphit-Embedding-Revision") != "embed-r1" {
		t.Fatal("missing embedding revision")
	}
	var embeddingResponse map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&embeddingResponse); err != nil {
		t.Fatal(err)
	}
	if _, ok := embeddingResponse["model"]; ok {
		t.Fatalf("embedding response exposes model: %s", embeddingResponse["model"])
	}
	if len(embeddingResponse["data"]) == 0 || len(embeddingResponse["graphit"]) == 0 {
		t.Fatalf("incomplete embedding response: %v", embeddingResponse)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/rerank", "valid", `{"query":"q","documents":["a"],"top_n":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rerank status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/credentials", "valid", `{"scope":"project","project_id":"project-a"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("s3 status=%d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("credential response is cacheable")
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("secret_access_key")) || !bytes.Contains(body, []byte("session_token")) || !bytes.Contains(body, []byte(`"bucket"`)) {
		t.Fatalf("credential response is incomplete: %s", body)
	}
	_ = resp.Body.Close()
}

func TestServerRejectsAIModelAndRouteFields(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request with removed selector reached upstream")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()
	cfg := testServerConfig(upstream.URL, upstream.URL)
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "https://id", Subject: "s", Organization: "acme"}, nil
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
	defer server.Close()
	for _, service := range []string{"embeddings", "rerank"} {
		for _, field := range []string{"model", "route"} {
			t.Run(service+"/"+field, func(t *testing.T) {
				body := map[string]any{field: "removed"}
				if service == "embeddings" {
					body["input"] = "hello"
				} else {
					body["query"] = "q"
					body["documents"] = []string{"a"}
				}
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				resp := post(t, server.URL+"/v1/"+service, "valid", string(encoded))
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("removed %s accepted: status=%d", field, resp.StatusCode)
				}
			})
		}
	}
}

func TestS3CredentialRenewalUsesFreshAuthorizationSnapshot(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	reader := &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 3, Rules: []ACLRuleConfig{{
		ID: "reader", Name: "reader", Access: "user", Principal: "alice", Capabilities: []string{"s3:read"}, Projects: []string{"project-a"},
	}}}}
	var issued []S3SessionGrant
	credentials := credentialFunc(func(_ context.Context, route S3RouteConfig, grant S3SessionGrant, _ Principal) (S3CredentialsResponse, error) {
		issued = append(issued, grant)
		return S3CredentialsResponse{AccessKeyID: "temporary-access", SecretAccessKey: "temporary-secret", SessionToken: "temporary-token", ExpiresAt: time.Now().Add(time.Hour), Bucket: route.Bucket, Region: route.Region, Prefixes: []string{route.BasePrefix}, AuthorizationRevision: grant.Revision, Scope: grant.Scope.Kind, ProjectID: grant.Scope.ProjectID}, nil
	})
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{Issuer: "issuer", Subject: "subject", Username: "alice"}, nil
	})
	server := httptest.NewServer(newServerWithDependencies(cfg, authenticator, NewAIService(cfg.Services), credentials, reader, nil, nil))
	defer server.Close()
	for _, revision := range []uint64{3, 4} {
		reader.document.Revision = revision
		response := post(t, server.URL+"/v1/s3/credentials", "valid", `{"scope":"project","project_id":"project-a"}`)
		var body S3CredentialsResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&body) != nil || body.AuthorizationRevision != strconv.FormatUint(revision, 10) || body.Scope != "project" || body.ProjectID != "project-a" {
			t.Fatalf("revision=%d status=%d body=%#v", revision, response.StatusCode, body)
		}
		_ = response.Body.Close()
	}
	if len(issued) != 2 || issued[0].Revision != "3" || issued[1].Revision != "4" {
		t.Fatalf("issued=%#v", issued)
	}
}

func TestServerReturnsRetryAfterWhenAuthenticationIsRateLimited(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	authenticator := authFunc(func(context.Context, string) (Principal, error) {
		return Principal{}, &authenticationRateLimitError{retryAfter: 90 * time.Second}
	})
	server := httptest.NewServer(newServer(cfg, authenticator, NewAIService(cfg.Services)))
	defer server.Close()
	response := post(t, server.URL+"/v1/embeddings", "limited", `{"input":"hello"}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "90" {
		t.Fatalf("rate limit status=%d retry-after=%q", response.StatusCode, response.Header.Get("Retry-After"))
	}
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

func TestServerRequiresAuthenticationAndDerivesCredentialScopeFromACL(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	grants := &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: []ACLRuleConfig{{
		ID: "private-project", Name: "private project", Access: "user", Principal: "alice", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"read"}, S3Prefixes: []string{"v2/projects/{project}"},
	}}}}
	called := false
	credentials := credentialFunc(func(_ context.Context, route S3RouteConfig, grant S3SessionGrant, principal Principal) (S3CredentialsResponse, error) {
		called = true
		if principal.Username != "alice" || grant.Route != "primary" || len(grant.Access["read"]) != 1 || grant.Access["read"][0] != "v2/projects/project-a" {
			t.Fatalf("principal=%#v grant=%#v", principal, grant)
		}
		return S3CredentialsResponse{AccessKeyID: "temp-access", SecretAccessKey: "temp-secret", SessionToken: "temp-token", ExpiresAt: time.Now().Add(time.Hour), Bucket: route.Bucket, Region: route.Region, Prefixes: []string{route.BasePrefix}, AuthorizationRevision: grant.Revision, Scope: grant.Scope.Kind, ProjectID: grant.Scope.ProjectID}, nil
	})
	server := httptest.NewServer(newServerWithDependencies(cfg, authFunc(func(_ context.Context, token string) (Principal, error) {
		if token == "valid" {
			return Principal{Issuer: "i", Subject: "s", Username: "alice"}, nil
		}
		return Principal{}, ErrUnauthenticated
	}), NewAIService(cfg.Services), credentials, grants, nil, nil))
	defer server.Close()
	resp := post(t, server.URL+"/v1/s3/credentials", "", `{}`)
	if resp.StatusCode != http.StatusUnauthorized || called {
		t.Fatalf("anonymous status=%d called=%v", resp.StatusCode, called)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/credentials", "valid", `{"scope":"project","project_id":"project-a"}`)
	if resp.StatusCode != http.StatusOK || !called {
		t.Fatalf("credential status=%d called=%v", resp.StatusCode, called)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/credentials", "valid", `{"scope":"project","project_id":"project-a","prefix":"v2"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("client-selected scope status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/credentials", "valid", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing scope status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = post(t, server.URL+"/v1/s3/credentials", "valid", `{"scope":"project","project_id":"project-b"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized project status=%d", resp.StatusCode)
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
		Database:       DatabaseConfig{Driver: "sqlite", DSN: ":memory:", MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute},
		Server:         ServerConfig{PublicURL: "https://broker.example.com", MaxRequestBytes: 1 << 20},
		Authentication: AuthenticationConfig{TokenPepper: testTokenPepper},
		Services: ServicesConfig{
			Embeddings: EmbeddingServiceConfig{Enabled: true, Revision: "embed-r1", Dimensions: 3, MaxBatch: 10, MaxInputBytes: 1000, Upstream: UpstreamConfig{URL: embeddingURL, Protocol: "openai-embeddings-v1", Model: "internal-embedding", Timeout: time.Second}},
			Rerank:     RerankServiceConfig{Enabled: true, Revision: "rerank-r1", MaxDocuments: 10, MaxDocumentBytes: 1000, Upstream: UpstreamConfig{URL: rerankURL, Protocol: "graphit-rerank-v1", Model: "internal-rerank", Timeout: time.Second}},
			S3: S3ServiceConfig{Enabled: true, DefaultRoute: "primary", Routes: map[string]S3RouteConfig{"primary": {
				Bucket: "bucket", Region: "us-east-1", BasePrefix: "base", AccessKeyID: "TESTACCESS", SecretAccessKey: "TESTSECRET",
				STSRoleARN: "arn:aws:iam::123456789012:role/graphit", STSSessionName: "graphit-broker", STSDuration: time.Hour,
			}}},
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

func TestDisabledOIDCIssuerIsExcludedFromDiscoverySessionsAndGrants(t *testing.T) {
	disabled := false
	cfg := Config{Authentication: AuthenticationConfig{OIDC: []OIDCIssuerConfig{
		{Enabled: &disabled, Issuer: "https://disabled.example", Audiences: []string{"disabled-audience"}, ClientID: "disabled-browser"},
		{Issuer: "https://active.example", Audiences: []string{"active-audience"}, ClientID: "active-browser", DisplayName: "Active SSO"},
	}}}
	cfg.defaults()
	server := newServer(cfg, nil, NewAIService(cfg.Services))
	defer server.Close()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/graphit-broker", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("discovery status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Authentication struct {
			Audiences           []string `json:"audiences"`
			AccessTokenAudience string   `json:"access_token_audience"`
		} `json:"authentication"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if containsString(body.Authentication.Audiences, "disabled-audience") || !containsString(body.Authentication.Audiences, "active-audience") {
		t.Fatalf("unexpected audiences=%v", body.Authentication.Audiences)
	}
	if body.Authentication.AccessTokenAudience != cfg.Authentication.Local.Tokens.Audience {
		t.Fatalf("access token audience=%q expected=%q", body.Authentication.AccessTokenAudience, cfg.Authentication.Local.Tokens.Audience)
	}
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	storage := &brokerOIDCStorage{control: store, cfg: cfg}
	for _, issuer := range []string{"https://disabled.example", "https://active.example"} {
		inactive := issuer == "https://disabled.example"
		session := AdminSession{Issuer: issuer, Subject: "alice", Username: "alice"}
		if server.sessionNeedsRoleRefresh(context.Background(), session) != inactive {
			t.Fatalf("incorrect session validity for %s", issuer)
		}
		grant := LocalTokenGrant{Principal: Principal{Issuer: issuer, Subject: "alice", Username: "alice", AuthMethod: "oidc"}}
		_, err := storage.validPrincipal(context.Background(), grant)
		if (err != nil) != inactive {
			t.Fatalf("incorrect grant validity for %s: %v", issuer, err)
		}
	}
}
