package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

func TestValidateRequestedResourceAcceptsOnlyConfiguredTargets(t *testing.T) {
	accepted := []string{"https://graphit.example.com/mcp", "https://other.example.com/mcp"}
	for _, testCase := range []struct {
		name      string
		accepted  []string
		values    []string
		want      []string
		wantError bool
	}{
		{name: "configured resource is accepted", accepted: accepted, values: []string{"https://graphit.example.com/mcp"}, want: []string{"https://graphit.example.com/mcp"}},
		{name: "no indicator is not an error", accepted: accepted},
		{name: "empty indicator is treated as absent", accepted: accepted, values: []string{"  "}},
		{name: "unconfigured target is refused", accepted: accepted, values: []string{"https://attacker.example/mcp"}, wantError: true},
		{name: "relative URI is refused", accepted: accepted, values: []string{"/mcp"}, wantError: true},
		{name: "fragment is refused", accepted: accepted, values: []string{"https://graphit.example.com/mcp#x"}, wantError: true},
		// RFC 8707 permits several indicators, but the broker deliberately narrows each
		// grant to one resource to avoid a bearer token reusable at sibling resources.
		{name: "several configured indicators are refused", accepted: accepted, values: []string{"https://graphit.example.com/mcp", "https://other.example.com/mcp"}, wantError: true},
		{name: "a repeated indicator is still more than one value", accepted: accepted, values: []string{"https://graphit.example.com/mcp", "https://graphit.example.com/mcp"}, wantError: true},
		{name: "one unconfigured indicator rejects the whole request", accepted: accepted, values: []string{"https://graphit.example.com/mcp", "https://attacker.example/mcp"}, wantError: true},
		// Without a configured list the deployment never declared a resource, so honouring
		// any indicator would mint an audience the operator never authorized.
		{name: "no configuration accepts nothing", accepted: nil, values: []string{"https://graphit.example.com/mcp"}, wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := validateRequestedResource(testCase.accepted, testCase.values)
			if testCase.wantError {
				if err == nil {
					t.Fatalf("validateRequestedResource(%v) = %v, nil; want an error", testCase.values, got)
				}
				return
			}
			if err != nil || strings.Join(got, " ") != strings.Join(testCase.want, " ") {
				t.Fatalf("validateRequestedResource(%v) = (%v, %v); want (%v, nil)", testCase.values, got, err, testCase.want)
			}
		})
	}
}

func TestValidateTokenRequestResourceCannotChangeTheGrant(t *testing.T) {
	accepted := []string{"https://graphit.example.com/mcp", "https://other.example.com/mcp"}
	granted := "https://graphit.example.com/mcp"
	for _, testCase := range []struct {
		name      string
		values    []string
		wantError bool
	}{
		{name: "omitted preserves the grant"},
		{name: "same resource is accepted", values: []string{granted}},
		{name: "another configured resource cannot replace the grant", values: []string{"https://other.example.com/mcp"}, wantError: true},
		{name: "several resources cannot widen the grant", values: accepted, wantError: true},
		{name: "unknown resource is refused", values: []string{"https://attacker.example/mcp"}, wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateTokenRequestResource(accepted, testCase.values, granted)
			if (err != nil) != testCase.wantError {
				t.Fatalf("validateTokenRequestResource(%v) error = %v; wantError=%v", testCase.values, err, testCase.wantError)
			}
		})
	}
}

func TestLocalTokenConfigCleansAndValidatesMCPResources(t *testing.T) {
	cfg := LocalTokenConfig{MCPResources: []string{" https://graphit.example.com/mcp ", "https://graphit.example.com/mcp", ""}}
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.MCPResources) != 1 || cfg.MCPResources[0] != "https://graphit.example.com/mcp" {
		t.Fatalf("cleaned mcp_resources=%v", cfg.MCPResources)
	}
	for _, resource := range []string{"/mcp", "https://graphit.example.com/mcp#fragment"} {
		invalid := cfg
		invalid.MCPResources = []string{resource}
		if err := invalid.validate(); err == nil {
			t.Fatalf("invalid mcp_resources entry %q was accepted", resource)
		}
	}
}

func TestAudienceForAlwaysKeepsTheBrokerAudience(t *testing.T) {
	// Losing the broker audience would make the token useless against the broker's own API,
	// which the Graphit daemon relays to on behalf of the caller.
	if got := audienceFor("graphit-broker", ""); len(got) != 1 || got[0] != "graphit-broker" {
		t.Fatalf("audienceFor without resource = %v", got)
	}
	got := audienceFor("graphit-broker", "https://graphit.example.com/mcp")
	if len(got) != 2 || got[0] != "graphit-broker" || got[1] != "https://graphit.example.com/mcp" {
		t.Fatalf("audienceFor with resource = %v; want both audiences", got)
	}
	if got := audienceFor("graphit-broker", "graphit-broker"); len(got) != 1 {
		t.Fatalf("audienceFor duplicated the audience: %v", got)
	}
}

func TestAuthRequestAndRefreshCarryTheSameAudience(t *testing.T) {
	request := &brokerOIDCAuthRequest{Audience: "graphit-broker", Resource: "https://graphit.example.com/mcp"}
	authAudience := request.GetAudience()

	// A refreshed token must not silently drop the resource it was granted for.
	refresh := &brokerOIDCRefreshRequest{grant: LocalTokenGrant{Audience: "graphit-broker", Resource: "https://graphit.example.com/mcp"}}
	refreshAudience := refresh.GetAudience()

	if strings.Join(authAudience, ",") != strings.Join(refreshAudience, ",") {
		t.Fatalf("authorization audience %v differs from refresh audience %v", authAudience, refreshAudience)
	}
	if len(authAudience) != 2 {
		t.Fatalf("audience = %v; want the broker audience and the resource", authAudience)
	}
}

func TestAuthorizeRejectsUnknownResourceWithInvalidTarget(t *testing.T) {
	_, httpServer := newResourceTestServer(t, []string{"https://graphit.example.com/mcp"})

	for _, testCase := range []struct {
		name     string
		resource string
	}{
		{name: "unconfigured target", resource: "https://attacker.example/mcp"},
		{name: "relative URI", resource: "/mcp"},
		{name: "fragment", resource: "https://graphit.example.com/mcp#x"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			endpoint := httpServer.URL + "/oauth/authorize?" + url.Values{
				"client_id": {"graphit-cli"}, "response_type": {"code"},
				"redirect_uri": {"http://127.0.0.1:7777/oauth/callback"},
				"scope":        {"openid profile"}, "state": {"state-value"}, "nonce": {"nonce-value"},
				"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
				"resource": {testCase.resource},
			}.Encode()

			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			response, err := client.Get(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()

			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d; want %d", response.StatusCode, http.StatusBadRequest)
			}
			var body map[string]any
			_ = json.NewDecoder(response.Body).Decode(&body)
			if code, _ := body["error"].(string); code != "invalid_target" {
				t.Fatalf("error = %q; want invalid_target (body %v)", code, body)
			}
			if location := response.Header.Get("Location"); location != "" {
				t.Fatalf("a rejected resource still redirected to %q", location)
			}
		})
	}
}

func TestBrokerDiscoveryAdvertisesConfiguredMCPResources(t *testing.T) {
	_, httpServer := newResourceTestServer(t, []string{"https://graphit.example.com/mcp", " ", "https://other.example.com/mcp"})

	response, err := http.Get(httpServer.URL + "/.well-known/graphit-broker")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var document struct {
		Authentication struct {
			MCPResources        []string `json:"mcp_resources"`
			AccessTokenAudience string   `json:"access_token_audience"`
		} `json:"authentication"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if len(document.Authentication.MCPResources) != 2 {
		t.Fatalf("mcp_resources = %v; want the two configured entries with the blank dropped", document.Authentication.MCPResources)
	}
	if document.Authentication.AccessTokenAudience != "graphit-broker" {
		t.Fatalf("access_token_audience = %q; the existing contract must be preserved", document.Authentication.AccessTokenAudience)
	}
}

func TestBrokerDiscoveryOmitsResourcesWhenNoneConfigured(t *testing.T) {
	_, httpServer := newResourceTestServer(t, nil)

	response, err := http.Get(httpServer.URL + "/.well-known/graphit-broker")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var document struct {
		Authentication struct {
			MCPResources []string `json:"mcp_resources"`
		} `json:"authentication"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if len(document.Authentication.MCPResources) != 0 {
		t.Fatalf("mcp_resources = %v; want none", document.Authentication.MCPResources)
	}
}

func TestGrantWithoutResourceKeepsTheConfiguredAudienceAlone(t *testing.T) {
	// This is the CLI's flow: no resource indicator, so the audience must be exactly what it
	// was before resource support existed.
	request := &brokerOIDCAuthRequest{Audience: "graphit-broker"}
	if got := request.GetAudience(); len(got) != 1 || got[0] != "graphit-broker" {
		t.Fatalf("audience without resource = %v; want only the configured audience", got)
	}
}

func TestResourceSurvivesAuthorizationCodeAndDynamicClientRefresh(t *testing.T) {
	resource := "https://graphit.example.com/mcp"
	otherResource := "https://other.example.com/mcp"
	_, httpServer := newResourceTestServer(t, []string{resource, otherResource})
	redirectURI := "http://127.0.0.1:49152/oauth/callback"
	registration, registered := registerClient(t, httpServer.URL, `{
		"redirect_uris":["`+redirectURI+`"],
		"token_endpoint_auth_method":"none",
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"scope":"openid profile email offline_access"
	}`)
	if registration.StatusCode != http.StatusCreated {
		t.Fatalf("dynamic registration status=%d body=%v", registration.StatusCode, registered)
	}
	clientID, _ := registered["client_id"].(string)
	if clientID == "" {
		t.Fatalf("dynamic registration omitted client_id: %v", registered)
	}

	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	query := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"openid"}}
	withoutResource, err := noRedirectClient().Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	assertOAuthError(t, withoutResource, "invalid_target")
	query.Set("resource", resource)
	query.Del("code_challenge")
	withoutPKCE, err := noRedirectClient().Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	assertOAuthError(t, withoutPKCE, "invalid_request")
	code := authorizeLocalClient(t, httpServer.URL, clientID, redirectURI, challenge, "offline_access", resource)
	tokenValues := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}}

	wrongValues := cloneValues(tokenValues)
	wrongValues.Set("resource", otherResource)
	assertOAuthError(t, oauthForm(t, httpServer.URL+"/oauth/token", wrongValues), "invalid_target")
	multipleValues := cloneValues(tokenValues)
	multipleValues["resource"] = []string{resource, otherResource}
	assertOAuthError(t, oauthForm(t, httpServer.URL+"/oauth/token", multipleValues), "invalid_target")

	tokenValues.Set("resource", resource)
	issued := decodeTokenResponse(t, oauthForm(t, httpServer.URL+"/oauth/token", tokenValues))
	claims := verifyResourceAccessToken(t, httpServer.URL, issued.AccessToken, clientID, resource)
	if claims["client_id"] != clientID {
		t.Fatalf("client_id=%v; want dynamically registered %q", claims["client_id"], clientID)
	}

	// Keeping the broker audience makes the resource token usable at the broker API that
	// Graphit calls on the principal's behalf.
	apiResponse := bearerRequest(t, http.MethodPost, httpServer.URL+"/v1/hub/access/resolve", issued.AccessToken, `{}`)
	defer apiResponse.Body.Close()
	if apiResponse.StatusCode != http.StatusOK {
		t.Fatalf("resource token at broker /v1 API status=%d", apiResponse.StatusCode)
	}

	wrongRefresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID},
		"refresh_token": {issued.RefreshToken}, "resource": {otherResource}}
	assertOAuthError(t, oauthForm(t, httpServer.URL+"/oauth/token", wrongRefresh), "invalid_target")

	// MCP clients must identify the protected resource on every token request.
	assertOAuthError(t, oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {issued.RefreshToken},
	}), "invalid_target")
	refreshed := decodeTokenResponse(t, oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {issued.RefreshToken}, "resource": {resource},
	}))
	verifyResourceAccessToken(t, httpServer.URL, refreshed.AccessToken, clientID, resource)

	// Repeating the same resource is also accepted and the dynamically registered client can
	// rotate again; TokenRequestByRefreshToken must not be pinned to graphit-cli.
	refreshedAgain := decodeTokenResponse(t, oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshed.RefreshToken}, "resource": {resource},
	}))
	verifyResourceAccessToken(t, httpServer.URL, refreshedAgain.AccessToken, clientID, resource)

	// An authorization code also requires the resource on the token request.
	omittedCode := authorizeLocalClient(t, httpServer.URL, clientID, redirectURI, challenge, "offline_access", resource)
	assertOAuthError(t, oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {omittedCode},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}), "invalid_target")
	omitted := decodeTokenResponse(t, oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {omittedCode},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {resource},
	}))
	verifyResourceAccessToken(t, httpServer.URL, omitted.AccessToken, clientID, resource)
}

func TestWebClientCanTargetBrokerAPIWithoutMCPResource(t *testing.T) {
	_, httpServer := newResourceTestServer(t, nil)
	resource := httpServer.URL + "/v1"
	redirectURI := "http://127.0.0.1:49152/api/auth/callback"
	registration, registered := registerClient(t, httpServer.URL, `{
		"redirect_uris":["`+redirectURI+`"],
		"token_endpoint_auth_method":"none",
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"application_type":"web",
		"scope":"openid profile email offline_access"
	}`)
	if registration.StatusCode != http.StatusCreated {
		t.Fatalf("dynamic registration status=%d body=%v", registration.StatusCode, registered)
	}
	clientID, _ := registered["client_id"].(string)
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	code := authorizeLocalClient(t, httpServer.URL, clientID, redirectURI, challenge, "offline_access", resource)
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {resource}}
	issued := decodeTokenResponse(t, oauthForm(t, httpServer.URL+"/oauth/token", values))
	verifyResourceAccessToken(t, httpServer.URL, issued.AccessToken, clientID, resource)
	api := bearerRequest(t, http.MethodPost, httpServer.URL+"/v1/hub/access/resolve", issued.AccessToken, `{}`)
	defer api.Body.Close()
	if api.StatusCode != http.StatusOK {
		t.Fatalf("Broker API status=%d", api.StatusCode)
	}
	refreshed := decodeTokenResponse(t, oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {issued.RefreshToken}, "resource": {resource},
	}))
	verifyResourceAccessToken(t, httpServer.URL, refreshed.AccessToken, clientID, resource)
	assertOAuthError(t, oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshed.RefreshToken}, "resource": {"https://unknown.example/v1"},
	}), "invalid_target")
}

type resourceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func decodeTokenResponse(t *testing.T, response *http.Response) resourceTokenResponse {
	t.Helper()
	defer response.Body.Close()
	var tokens resourceTokenResponse
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&tokens) != nil {
		t.Fatalf("token endpoint status=%d", response.StatusCode)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("incomplete token response: %#v", tokens)
	}
	return tokens
}

func assertOAuthError(t *testing.T, response *http.Response, want string) {
	t.Helper()
	defer response.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(response.Body).Decode(&body)
	if response.StatusCode != http.StatusBadRequest || body["error"] != want {
		t.Fatalf("OAuth error status=%d body=%v; want %q", response.StatusCode, body, want)
	}
}

func cloneValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = append([]string(nil), entries...)
	}
	return clone
}

func verifyResourceAccessToken(t *testing.T, issuer, raw, clientID, resource string) map[string]any {
	t.Helper()
	ctx := coreoidc.InsecureIssuerURLContext(context.Background(), issuer)
	provider, err := coreoidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := provider.Verifier(&coreoidc.Config{SkipClientIDCheck: true}).Verify(ctx, raw)
	if err != nil {
		t.Fatalf("verify resource access token: %v", err)
	}
	var claims map[string]any
	if err := verified.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims["client_id"] != clientID || claims["token_use"] != "access" || !claimContains(claims["aud"], "graphit-broker") || !claimContains(claims["aud"], resource) {
		t.Fatalf("resource access claims=%#v; want access token for client_id=%q and both audiences", claims, clientID)
	}
	return claims
}

func claimContains(value any, want string) bool {
	switch values := value.(type) {
	case string:
		return values == want
	case []any:
		for _, value := range values {
			if value == want {
				return true
			}
		}
	case []string:
		for _, value := range values {
			if value == want {
				return true
			}
		}
	}
	return false
}

// newResourceTestServer builds a broker whose OpenID Provider is enabled and whose operator
// declared the given MCP resources.
func newResourceTestServer(t *testing.T, resources []string) (*Server, *httptest.Server) {
	t.Helper()
	return newResourceTestServerWithCORS2(t, resources, nil)
}

// newResourceTestServerWithCORS builds the same broker with a declared CORS origin list.
func newResourceTestServerWithCORS(t *testing.T, origins []string) (*Server, *httptest.Server) {
	t.Helper()
	return newResourceTestServerWithCORS2(t, nil, origins)
}

func newResourceTestServerWithCORS2(t *testing.T, resources, corsOrigins []string) (*Server, *httptest.Server) {
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
	cfg.Authentication.Local.Tokens.MCPResources = resources
	cfg.Server.CORS = CORSConfig{AllowedOrigins: corsOrigins}
	cfg.Authentication.Local.Tokens.DynamicRegistration = true
	cfg.Services.Embeddings.Upstream.APIKey = "embedding-secret"
	cfg.Services.Rerank.Upstream.APIKey = "rerank-secret"

	control, err := OpenControlStore(cfg.Database, cfg.Authentication.TokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	if err := control.CreateLocalUser(context.Background(), LocalUser{Username: "consumer", Subject: "consumer-subject", PasswordHash: mustPasswordHash(t, "consumer-secret"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.db.Exec(`UPDATE local_users SET password_change_required=0 WHERE username='consumer'`); err != nil {
		t.Fatal(err)
	}

	authenticator, err := NewAuthenticator(context.Background(), cfg.Authentication, control)
	if err != nil {
		t.Fatal(err)
	}
	service := newServerWithDependencies(cfg, authenticator, NewAIService(cfg.Services), nil, control, control, nil)
	t.Cleanup(func() { _ = service.Close() })
	localPasswords, err := newLocalPasswordAuthenticator(context.Background(), cfg.Authentication, control)
	if err != nil {
		t.Fatal(err)
	}
	runtime := *service.runtime()
	runtime.localPasswords = localPasswords
	runtime.localAuth, err = newLocalAuthenticationService(cfg.Authentication, control, localPasswords)
	if err != nil {
		t.Fatal(err)
	}
	service.state.Store(&runtime)

	httpServer.Config.Handler = service
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	return service, httpServer
}
