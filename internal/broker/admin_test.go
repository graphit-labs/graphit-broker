package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type fakeAdminOIDC struct {
	identities  map[string]AdminIdentity
	state       string
	nonce       string
	verifier    string
	exchangeErr error
}

func (f *fakeAdminOIDC) AuthorizationURL(state, nonce, verifier string) string {
	f.state, f.nonce, f.verifier = state, nonce, verifier
	values := url.Values{"state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}}
	return "https://identity.example/authorize?" + values.Encode()
}

func (f *fakeAdminOIDC) Exchange(_ context.Context, code, verifier, nonce string) (AdminIdentity, error) {
	if f.exchangeErr != nil {
		return AdminIdentity{}, f.exchangeErr
	}
	if code != "valid-code" || verifier == "" || verifier != f.verifier || nonce == "" || nonce != f.nonce {
		return AdminIdentity{}, errors.New("invalid code, PKCE verifier, or nonce")
	}
	return f.identities["root-token"], nil
}

func (f *fakeAdminOIDC) Verify(_ context.Context, raw string) (AdminIdentity, error) {
	identity, ok := f.identities[raw]
	if !ok {
		return AdminIdentity{}, errors.New("invalid ID token")
	}
	return identity, nil
}

func TestAdminOIDCLoginSessionCSRFAndLogout(t *testing.T) {
	service, httpServer, provider := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	page, err := http.Get(httpServer.URL + "/admin/")
	if err != nil || page.StatusCode != http.StatusOK {
		t.Fatalf("admin page status=%s err=%v", statusText(page), err)
	}
	if page.Header.Get("Content-Security-Policy") == "" || page.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("admin page security headers missing: %#v", page.Header)
	}
	pageBody, _ := io.ReadAll(page.Body)
	if !bytes.Contains(pageBody, []byte("Sign in with OIDC")) || !bytes.Contains(pageBody, []byte("Complete broker configuration")) || !bytes.Contains(pageBody, []byte("Assign role to OIDC subject")) {
		t.Fatalf("administration UI is incomplete: %s", pageBody)
	}
	if bytes.Contains(pageBody, []byte("sessionStorage")) || bytes.Contains(pageBody, []byte("Administrator bearer token")) {
		t.Fatal("administration UI retained the obsolete static-token login")
	}
	_ = page.Body.Close()

	client := noRedirectClient()
	login, err := client.Get(httpServer.URL + "/admin/auth/login")
	if err != nil || login.StatusCode != http.StatusFound {
		t.Fatalf("login status=%s err=%v", statusText(login), err)
	}
	location, _ := url.Parse(login.Header.Get("Location"))
	if location.Query().Get("state") == "" || provider.nonce == "" || provider.verifier == "" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("OIDC redirect did not include state/nonce/PKCE: %s", location)
	}
	_ = login.Body.Close()

	invalid, err := client.Get(httpServer.URL + "/admin/auth/callback?state=not-the-state&code=valid-code")
	if err != nil || invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid state status=%s err=%v", statusText(invalid), err)
	}
	_ = invalid.Body.Close()

	callback, err := client.Get(httpServer.URL + "/admin/auth/callback?state=" + url.QueryEscape(provider.state) + "&code=valid-code")
	if err != nil || callback.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status=%s err=%v", statusText(callback), err)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range callback.Cookies() {
		if cookie.Name == adminCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("invalid administration cookie: %#v", sessionCookie)
	}
	_ = callback.Body.Close()

	sessionRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/admin/api/v1/session", nil)
	sessionRequest.AddCookie(sessionCookie)
	sessionResponse, err := http.DefaultClient.Do(sessionRequest)
	if err != nil || sessionResponse.StatusCode != http.StatusOK {
		t.Fatalf("session status=%s err=%v", statusText(sessionResponse), err)
	}
	var sessionBody struct {
		Subject    string `json:"subject"`
		Superadmin bool   `json:"superadmin"`
		CSRFToken  string `json:"csrf_token"`
	}
	_ = json.NewDecoder(sessionResponse.Body).Decode(&sessionBody)
	_ = sessionResponse.Body.Close()
	if sessionBody.Subject != "root-subject" || !sessionBody.Superadmin || sessionBody.CSRFToken == "" {
		t.Fatalf("session=%#v", sessionBody)
	}
	failedLogin, _ := client.Get(httpServer.URL + "/admin/auth/login")
	_ = failedLogin.Body.Close()
	provider.exchangeErr = errors.New("synthetic token endpoint failure")
	failedCallback, err := client.Get(httpServer.URL + "/admin/auth/callback?state=" + url.QueryEscape(provider.state) + "&code=valid-code")
	if err != nil || failedCallback.StatusCode != http.StatusUnauthorized {
		t.Fatalf("failed exchange callback status=%s err=%v", statusText(failedCallback), err)
	}
	_ = failedCallback.Body.Close()
	provider.exchangeErr = nil

	withoutCSRF, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/api/v1/grants", strings.NewReader(`{"id":"public","name":"public","access":"global","capabilities":["hub"]}`))
	withoutCSRF.Header.Set("Content-Type", "application/json")
	withoutCSRF.Header.Set("If-Match", `"1"`)
	withoutCSRF.AddCookie(sessionCookie)
	denied, err := http.DefaultClient.Do(withoutCSRF)
	if err != nil || denied.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%s err=%v", statusText(denied), err)
	}
	_ = denied.Body.Close()

	logout, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/auth/logout", nil)
	logout.Header.Set("X-CSRF-Token", sessionBody.CSRFToken)
	logout.AddCookie(sessionCookie)
	loggedOut, err := http.DefaultClient.Do(logout)
	if err != nil || loggedOut.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%s err=%v", statusText(loggedOut), err)
	}
	_ = loggedOut.Body.Close()
	sessionAfterLogout, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/admin/api/v1/session", nil)
	sessionAfterLogout.AddCookie(sessionCookie)
	response, _ := http.DefaultClient.Do(sessionAfterLogout)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deleted session status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestAdminRBACBootstrapAssignmentAndRevocation(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	if status := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/roles", "other-token", "").StatusCode; status != http.StatusForbidden {
		t.Fatalf("unassigned administrator status=%d", status)
	}
	assignment := `{"subject":"other-subject","role":"admin"}`
	assigned := bearerRequest(t, http.MethodPost, httpServer.URL+"/admin/api/v1/role-assignments", "root-token", assignment)
	if assigned.StatusCode != http.StatusNoContent {
		t.Fatalf("assign role status=%d", assigned.StatusCode)
	}
	_ = assigned.Body.Close()
	allowed := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "other-token", "")
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("assigned administrator status=%d", allowed.StatusCode)
	}
	_ = allowed.Body.Close()
	revoked := bearerRequest(t, http.MethodDelete, httpServer.URL+"/admin/api/v1/role-assignments", "root-token", assignment)
	if revoked.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke role status=%d", revoked.StatusCode)
	}
	_ = revoked.Body.Close()
	denied := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "other-token", "")
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked administrator status=%d", denied.StatusCode)
	}
	_ = denied.Body.Close()
}

func TestAdminFullConfigurationRedactionUpdateAndConsumerHotReload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}}})
	}))
	defer upstream.Close()
	service, httpServer, _ := newAdminTestServer(t, upstream.URL)
	defer service.Close()
	defer httpServer.Close()

	configResponse := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "root-token", "")
	if configResponse.StatusCode != http.StatusOK || configResponse.Header.Get("ETag") != `"1"` {
		t.Fatalf("config status=%d etag=%q", configResponse.StatusCode, configResponse.Header.Get("ETag"))
	}
	configBody, _ := io.ReadAll(configResponse.Body)
	_ = configResponse.Body.Close()
	for _, secret := range []string{"admin-client-secret", "consumer-secret", "embedding-secret", "rerank-secret", "TESTSECRET"} {
		if bytes.Contains(configBody, []byte(secret)) {
			t.Fatalf("configuration response leaked %q: %s", secret, configBody)
		}
	}
	var envelope struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(configBody, &envelope); err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(envelope.YAML, configuredSecret); count < 5 {
		t.Fatalf("expected redacted placeholders, count=%d YAML=%s", count, envelope.YAML)
	}
	var editable Config
	if err := yaml.Unmarshal([]byte(envelope.YAML), &editable); err != nil {
		t.Fatal(err)
	}
	editable.Services.Rerank.Enabled = false
	updatedYAML, _ := yaml.Marshal(editable)
	requestBody, _ := json.Marshal(map[string]string{"yaml": string(updatedYAML)})
	update, _ := http.NewRequest(http.MethodPut, httpServer.URL+"/admin/api/v1/config", bytes.NewReader(requestBody))
	update.Header.Set("Authorization", "Bearer root-token")
	update.Header.Set("Content-Type", "application/json")
	update.Header.Set("If-Match", `"1"`)
	updated, err := http.DefaultClient.Do(update)
	if err != nil || updated.StatusCode != http.StatusOK || updated.Header.Get("ETag") != `"2"` {
		t.Fatalf("config update status=%s etag=%q err=%v", statusText(updated), updated.Header.Get("ETag"), err)
	}
	_ = updated.Body.Close()
	persisted, err := service.control.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Config.Administration.OIDC.ClientSecret != "admin-client-secret" || persisted.Config.Authentication.APIKeys[0].Token != "consumer-secret" || persisted.Config.Services.S3.Routes["primary"].SecretAccessKey != "TESTSECRET" {
		t.Fatalf("redacted secrets were not retained: %#v", persisted.Config)
	}
	discovery, _ := http.Get(httpServer.URL + "/.well-known/graphit-broker")
	discoveryBody, _ := io.ReadAll(discovery.Body)
	_ = discovery.Body.Close()
	if bytes.Contains(discoveryBody, []byte(`"rerank"`)) {
		t.Fatalf("disabled rerank remained in hot runtime: %s", discoveryBody)
	}

	access := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/grants", "root-token", "")
	etag := access.Header.Get("ETag")
	_ = access.Body.Close()
	grant := `{"id":"public-embeddings","name":"public embeddings","access":"anonymous","capabilities":["embeddings"]}`
	put, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/api/v1/grants", strings.NewReader(grant))
	put.Header.Set("Authorization", "Bearer root-token")
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("If-Match", etag)
	accessUpdated, err := http.DefaultClient.Do(put)
	if err != nil || accessUpdated.StatusCode != http.StatusCreated {
		t.Fatalf("access update status=%s err=%v", statusText(accessUpdated), err)
	}
	_ = accessUpdated.Body.Close()
	embedding := post(t, httpServer.URL+"/v1/embeddings", "", `{"input":"hello"}`)
	if embedding.StatusCode != http.StatusOK {
		t.Fatalf("hot-reloaded consumer ACL status=%d", embedding.StatusCode)
	}
	_ = embedding.Body.Close()

	stale, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/api/v1/grants", strings.NewReader(grant))
	stale.Header.Set("Authorization", "Bearer root-token")
	stale.Header.Set("Content-Type", "application/json")
	stale.Header.Set("If-Match", etag)
	conflict, _ := http.DefaultClient.Do(stale)
	if conflict.StatusCode != http.StatusConflict {
		t.Fatalf("stale access update status=%d", conflict.StatusCode)
	}
	_ = conflict.Body.Close()

	current := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/grants", "root-token", "")
	currentETag := current.Header.Get("ETag")
	_ = current.Body.Close()
	updatedGrant := `{"id":"ignored-by-path","name":"signed-in embeddings","access":"authenticated","capabilities":["embeddings"]}`
	edit, _ := http.NewRequest(http.MethodPut, httpServer.URL+"/admin/api/v1/grants/public-embeddings", strings.NewReader(updatedGrant))
	edit.Header.Set("Authorization", "Bearer root-token")
	edit.Header.Set("Content-Type", "application/json")
	edit.Header.Set("If-Match", currentETag)
	edited, err := http.DefaultClient.Do(edit)
	if err != nil || edited.StatusCode != http.StatusOK {
		t.Fatalf("grant update status=%s err=%v", statusText(edited), err)
	}
	deleteETag := edited.Header.Get("ETag")
	_ = edited.Body.Close()
	remove, _ := http.NewRequest(http.MethodDelete, httpServer.URL+"/admin/api/v1/grants/public-embeddings", nil)
	remove.Header.Set("Authorization", "Bearer root-token")
	remove.Header.Set("If-Match", deleteETag)
	deleted, err := http.DefaultClient.Do(remove)
	if err != nil || deleted.StatusCode != http.StatusOK {
		t.Fatalf("grant delete status=%s err=%v", statusText(deleted), err)
	}
	_ = deleted.Body.Close()
}

func newAdminTestServer(t *testing.T, embeddingURL string) (*Server, *httptest.Server, *fakeAdminOIDC) {
	t.Helper()
	cfg := testServerConfig(embeddingURL, "http://127.0.0.1:1")
	cfg.Authentication.APIKeys = []APIKeyConfig{{Name: "consumer", Token: "consumer-secret", Subject: "consumer-subject", Username: "consumer"}}
	cfg.Services.Embeddings.Upstream.APIKey = "embedding-secret"
	cfg.Services.Rerank.Upstream.APIKey = "rerank-secret"
	cfg.Database.DSN = t.TempDir() + "/broker.db"
	cfg.Administration = AdministrationConfig{Enabled: true, SuperadminSubject: "root-subject", SessionTTL: time.Hour,
		OIDC: AdminOIDCConfig{Issuer: "https://identity.example", ClientID: "admin-client", ClientSecret: "admin-client-secret", RedirectURL: "http://127.0.0.1/admin/auth/callback", Scopes: []string{"openid", "profile", "email"}}}
	provider := &fakeAdminOIDC{identities: map[string]AdminIdentity{
		"root-token":  {Subject: "root-subject", Name: "Root", Email: "root@example.test"},
		"other-token": {Subject: "other-subject", Name: "Other"},
	}}
	service, err := newServerWithFactory(context.Background(), cfg, func(context.Context, AdminOIDCConfig) (AdminIdentityProvider, error) { return provider, nil })
	if err != nil {
		t.Fatal(err)
	}
	return service, httptest.NewServer(service), provider
}

func bearerRequest(t *testing.T, method, endpoint, token, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
