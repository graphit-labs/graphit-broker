package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newRegistrationTestServer builds a broker whose OpenID Provider is enabled, optionally
// accepting dynamic client registration.
func newRegistrationTestServer(t *testing.T, dynamicRegistration bool) (*Server, *httptest.Server) {
	t.Helper()
	httpServer := httptest.NewUnstartedServer(nil)

	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Server.PublicURL = "http://" + httpServer.Listener.Addr().String()
	cfg.Database.DSN = t.TempDir() + "/broker.db"
	cfg.Authentication = AuthenticationConfig{TokenPepper: testPasswordPepper}
	localLogin := true
	cfg.Authentication.Local.Login.Enabled = &localLogin
	requireMFA := false
	cfg.Authentication.Local.MFA.Required = &requireMFA
	cfg.Authentication.Local.Tokens.setDefaults()
	cfg.Authentication.Local.Tokens.DynamicRegistration = dynamicRegistration
	cfg.Services.Embeddings.Upstream.APIKey = "embedding-secret"
	cfg.Services.Rerank.Upstream.APIKey = "rerank-secret"

	control, err := OpenControlStore(cfg.Database, cfg.Authentication.TokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })

	authenticator, err := NewAuthenticator(context.Background(), cfg.Authentication, control)
	if err != nil {
		t.Fatal(err)
	}
	service := newServerWithDependencies(cfg, authenticator, NewAIService(cfg.Services), nil, control, control, nil)
	t.Cleanup(func() { _ = service.Close() })

	httpServer.Config.Handler = service
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	return service, httpServer
}

func registerClient(t *testing.T, endpoint string, body string) (*http.Response, map[string]any) {
	t.Helper()
	response, err := http.Post(endpoint+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	var decoded map[string]any
	_ = json.NewDecoder(response.Body).Decode(&decoded)
	return response, decoded
}

func TestDynamicRegistrationIssuesPublicClient(t *testing.T) {
	service, httpServer := newRegistrationTestServer(t, true)

	response, decoded := registerClient(t, httpServer.URL, `{
		"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
		"token_endpoint_auth_method": "none",
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"client_name": "Hosted Agent",
		"scope": "openid profile"
	}`)

	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body %v)", response.StatusCode, http.StatusCreated, decoded)
	}
	clientID, _ := decoded["client_id"].(string)
	if clientID == "" {
		t.Fatalf("client_id missing from %v", decoded)
	}
	if _, present := decoded["client_secret"]; present {
		t.Fatalf("registration issued a client_secret: %v", decoded)
	}
	if method, _ := decoded["token_endpoint_auth_method"].(string); method != "none" {
		t.Errorf("token_endpoint_auth_method = %q; want none", method)
	}

	// The provider must now resolve it, with exactly the redirect it registered.
	client, err := service.oidcProvider.storage.GetClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("registered client is not resolvable: %v", err)
	}
	if client.GetID() != clientID {
		t.Errorf("resolved client id = %q; want %q", client.GetID(), clientID)
	}
	if uris := client.RedirectURIs(); len(uris) != 1 || uris[0] != "https://claude.ai/api/mcp/auth_callback" {
		t.Errorf("redirect URIs = %v; want the registered callback", uris)
	}
	if client.AuthMethod() != "none" {
		t.Errorf("auth method = %q; want none", client.AuthMethod())
	}
	// An HTTPS callback is a web client, which is what makes the provider accept it.
	if got := client.ApplicationType(); got.String() != "web" {
		t.Errorf("application type = %v; want web for an HTTPS callback", got)
	}

	// A public client authenticates with no secret, and never with one.
	if err := service.oidcProvider.storage.AuthorizeClientIDSecret(context.Background(), clientID, ""); err != nil {
		t.Errorf("public client rejected with empty secret: %v", err)
	}
	if err := service.oidcProvider.storage.AuthorizeClientIDSecret(context.Background(), clientID, "anything"); err == nil {
		t.Error("a supplied secret was accepted for a public client")
	}
}

func TestDynamicRegistrationRejectsNonPublicOrUnsafeMetadata(t *testing.T) {
	_, httpServer := newRegistrationTestServer(t, true)

	for _, testCase := range []struct {
		name string
		body string
	}{
		{
			name: "confidential client authentication",
			body: `{"redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		},
		{
			name: "omitted auth method would default to confidential",
			body: `{"redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
		},
		{
			name: "grant type outside the allowed set",
			body: `{"redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"none","grant_types":["client_credentials"]}`,
		},
		{
			name: "implicit response type",
			body: `{"redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"none","response_types":["token"]}`,
		},
		{
			name: "scope the broker does not support",
			body: `{"redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"none","scope":"openid admin.write"}`,
		},
		{
			name: "plain http on a public host",
			body: `{"redirect_uris":["http://agent.example/cb"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "custom scheme redirect",
			body: `{"redirect_uris":["myapp://callback"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "redirect with a fragment",
			body: `{"redirect_uris":["https://agent.example/cb#x"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "redirect with embedded credentials",
			body: `{"redirect_uris":["https://user:pass@agent.example/cb"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "no redirect at all",
			body: `{"token_endpoint_auth_method":"none"}`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response, decoded := registerClient(t, httpServer.URL, testCase.body)
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d; want %d", response.StatusCode, http.StatusBadRequest)
			}
			if code, _ := decoded["error"].(string); code != "invalid_client_metadata" {
				t.Fatalf("error = %q; want invalid_client_metadata", code)
			}
			if _, present := decoded["client_id"]; present {
				t.Fatal("a rejected registration returned a client_id")
			}
		})
	}
}

func TestDynamicRegistrationAcceptsLoopbackRedirect(t *testing.T) {
	service, httpServer := newRegistrationTestServer(t, true)

	response, decoded := registerClient(t, httpServer.URL,
		`{"redirect_uris":["http://127.0.0.1:7777/callback"],"token_endpoint_auth_method":"none"}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body %v)", response.StatusCode, http.StatusCreated, decoded)
	}
	clientID, _ := decoded["client_id"].(string)
	client, err := service.oidcProvider.storage.GetClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	// A loopback callback is a native client, which is how the provider allows its port to vary.
	if got := client.ApplicationType(); got.String() != "native" {
		t.Errorf("application type = %v; want native for a loopback callback", got)
	}
}

func TestDynamicRegistrationDisabledHidesEndpointAndDiscovery(t *testing.T) {
	_, httpServer := newRegistrationTestServer(t, false)

	response, _ := registerClient(t, httpServer.URL, `{"redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"none"}`)
	if response.StatusCode == http.StatusCreated {
		t.Fatalf("registration succeeded while disabled")
	}

	discovery := fetchDiscovery(t, httpServer.URL)
	if _, present := discovery["registration_endpoint"]; present {
		t.Fatalf("registration_endpoint announced while disabled: %v", discovery["registration_endpoint"])
	}
}

func TestDiscoveryAnnouncesRegistrationEndpointAndKeepsLibraryFields(t *testing.T) {
	_, httpServer := newRegistrationTestServer(t, true)

	discovery := fetchDiscovery(t, httpServer.URL)
	want := httpServer.URL + "/oauth/register"
	if got, _ := discovery["registration_endpoint"].(string); got != want {
		t.Fatalf("registration_endpoint = %q; want %q", got, want)
	}
	// The decorator must add one field, not replace the library's document.
	for _, field := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "response_types_supported", "grant_types_supported", "code_challenge_methods_supported"} {
		if _, present := discovery[field]; !present {
			t.Errorf("discovery lost the library field %q", field)
		}
	}
}

func fetchDiscovery(t *testing.T, base string) map[string]any {
	t.Helper()
	response, err := http.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", response.StatusCode)
	}
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestStaticCLIClientRemainsUnchanged(t *testing.T) {
	// Registration must not disturb the configured client the CLI relies on.
	service, _ := newRegistrationTestServer(t, true)

	client, err := service.oidcProvider.storage.GetClientByClientID(context.Background(), "graphit-cli")
	if err != nil {
		t.Fatalf("static CLI client is not resolvable: %v", err)
	}
	if uris := client.RedirectURIs(); len(uris) != 1 || uris[0] != "http://127.0.0.1/oauth/callback" {
		t.Errorf("CLI redirect URIs = %v; want the configured loopback callback", uris)
	}
	if got := client.ApplicationType(); got.String() != "native" {
		t.Errorf("CLI application type = %v; want native", got)
	}
	if err := service.oidcProvider.storage.AuthorizeClientIDSecret(context.Background(), "graphit-cli", ""); err != nil {
		t.Errorf("CLI client rejected: %v", err)
	}
	if _, err := service.oidcProvider.storage.GetClientByClientID(context.Background(), "never-registered"); err == nil {
		t.Error("an unregistered client id resolved")
	}
}

func TestDynamicClientRoundTripsThroughTheStore(t *testing.T) {
	service, _ := newRegistrationTestServer(t, true)
	record := dynamicClientRecord{
		ClientID: "stored-client", ClientName: "Stored", RedirectURIs: []string{"https://agent.example/cb"},
		Scopes: []string{"openid", testFixtureScope}, ApplicationType: applicationTypeWeb, CreatedAt: time.Now().UTC(),
	}
	if err := service.control.SaveDynamicClient(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := service.control.DynamicClient(context.Background(), "stored-client")
	if err != nil || !found {
		t.Fatalf("stored client not found: found=%v err=%v", found, err)
	}
	if loaded.ClientName != "Stored" || len(loaded.RedirectURIs) != 1 || loaded.RedirectURIs[0] != "https://agent.example/cb" {
		t.Fatalf("round trip lost data: %#v", loaded)
	}
	if _, found, err := service.control.DynamicClient(context.Background(), "absent"); err != nil || found {
		t.Fatalf("absent client reported as found: found=%v err=%v", found, err)
	}
}
