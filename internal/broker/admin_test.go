package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

type fakeAdminOIDC struct {
	identities  map[string]AdminIdentity
	flows       map[string]struct{ nonce, verifier string }
	state       string
	nonce       string
	verifier    string
	exchangeErr error
}

func (f *fakeAdminOIDC) AuthorizationURL(state, nonce, verifier string) string {
	f.state, f.nonce, f.verifier = state, nonce, verifier
	if f.flows == nil {
		f.flows = make(map[string]struct{ nonce, verifier string })
	}
	f.flows[state] = struct{ nonce, verifier string }{nonce: nonce, verifier: verifier}
	values := url.Values{"state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}}
	return "https://identity.example/authorize?" + values.Encode()
}

func (f *fakeAdminOIDC) Exchange(_ context.Context, code, verifier, nonce string) (AdminIdentity, error) {
	if f.exchangeErr != nil {
		return AdminIdentity{}, f.exchangeErr
	}
	validFlow := false
	for _, flow := range f.flows {
		if verifier == flow.verifier && nonce == flow.nonce {
			validFlow = true
			break
		}
	}
	if code != "valid-code" || verifier == "" || nonce == "" || !validFlow {
		return AdminIdentity{}, errors.New("invalid code, PKCE verifier, or nonce")
	}
	return f.identities["root-token"], nil
}

type testAdminAuthenticator struct {
	local      Authenticator
	store      *ControlStore
	identities map[string]AdminIdentity
}

func (a testAdminAuthenticator) Authenticate(ctx context.Context, raw string) (Principal, error) {
	if identity, ok := a.identities[raw]; ok {
		return Principal{Issuer: identity.Issuer, Subject: identity.Subject, Username: identity.Username,
			Organization: identity.Organization, Teams: identity.Teams, Roles: identity.Roles,
			RolesFromClaim: identity.RolesFromClaim, RoleClaimSelector: identity.RoleClaimSelector, AuthMethod: "oidc"}, nil
	}
	if strings.HasPrefix(raw, localAccessTokenPrefix) && a.store != nil {
		return a.store.AuthenticateLocalToken(ctx, raw, "graphit-broker", []string{localAPIScope})
	}
	return a.local.Authenticate(ctx, raw)
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
	if !bytes.Contains(pageBody, []byte("Sign in with OIDC")) || !bytes.Contains(pageBody, []byte("Sign in locally")) || !bytes.Contains(pageBody, []byte("Projects you can access")) || !bytes.Contains(pageBody, []byte("Configure Graphit CLI")) || !bytes.Contains(pageBody, []byte("Complete broker configuration")) || !bytes.Contains(pageBody, []byte("Local users")) || !bytes.Contains(pageBody, []byte("Assign role to an identity")) {
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

	invalid, err := client.Get(httpServer.URL + "/oauth/oidc/callback?state=not-the-state&code=valid-code")
	if err != nil || invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid state status=%s err=%v", statusText(invalid), err)
	}
	_ = invalid.Body.Close()

	foreignClient := noRedirectClient()
	foreign, err := foreignClient.Get(httpServer.URL + "/oauth/oidc/callback?state=" + url.QueryEscape(provider.state) + "&code=valid-code")
	if err != nil || foreign.StatusCode != http.StatusUnauthorized {
		t.Fatalf("callback without browser binding status=%s err=%v", statusText(foreign), err)
	}
	_ = foreign.Body.Close()

	callback, err := client.Get(httpServer.URL + "/oauth/oidc/callback?state=" + url.QueryEscape(provider.state) + "&code=valid-code")
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
		Subject   string `json:"subject"`
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.NewDecoder(sessionResponse.Body).Decode(&sessionBody)
	_ = sessionResponse.Body.Close()
	if sessionBody.Subject != "root-subject" || sessionBody.CSRFToken == "" {
		t.Fatalf("session=%#v", sessionBody)
	}
	failedLogin, _ := client.Get(httpServer.URL + "/admin/auth/login")
	_ = failedLogin.Body.Close()
	provider.exchangeErr = errors.New("synthetic token endpoint failure")
	failedCallback, err := client.Get(httpServer.URL + "/oauth/oidc/callback?state=" + url.QueryEscape(provider.state) + "&code=valid-code")
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

func TestAdminOIDCAllowsConcurrentBrowserFlows(t *testing.T) {
	service, httpServer, provider := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	client := noRedirectClient()

	states := make([]string, 0, 2)
	for range 2 {
		login, err := client.Get(httpServer.URL + "/admin/auth/login")
		if err != nil || login.StatusCode != http.StatusFound {
			t.Fatalf("login status=%s err=%v", statusText(login), err)
		}
		location, _ := url.Parse(login.Header.Get("Location"))
		states = append(states, location.Query().Get("state"))
		_ = login.Body.Close()
	}
	if states[0] == states[1] || len(provider.flows) != 2 {
		t.Fatalf("flows were not independent: states=%v provider=%v", states, provider.flows)
	}
	for _, state := range states {
		callback, err := client.Get(httpServer.URL + "/oauth/oidc/callback?state=" + url.QueryEscape(state) + "&code=valid-code")
		if err != nil || callback.StatusCode != http.StatusSeeOther {
			t.Fatalf("callback state=%q status=%s err=%v", state, statusText(callback), err)
		}
		_ = callback.Body.Close()
	}
}

func TestOIDCFlowCookieSecurityAttributes(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	expires := time.Now().Add(oidcFlowTTL)

	loopback := service.oidcFlowCookie("state-a", "binding", expires)
	if loopback.Name == service.oidcFlowCookieName("state-b") || strings.HasPrefix(loopback.Name, "__Host-") {
		t.Fatalf("loopback flow cookie name=%q", loopback.Name)
	}
	if !loopback.HttpOnly || loopback.SameSite != http.SameSiteLaxMode || loopback.Secure || loopback.Path != "/" || loopback.MaxAge <= 0 {
		t.Fatalf("loopback flow cookie=%#v", loopback)
	}
	loopbackSession := service.adminCookie("session", expires)
	if loopbackSession.Secure || !loopbackSession.HttpOnly || loopbackSession.SameSite != http.SameSiteLaxMode {
		t.Fatalf("loopback session cookie=%#v", loopbackSession)
	}

	state := *service.runtime()
	state.config.Administration.CookieSecure = nil
	service.state.Store(&state)
	production := service.oidcFlowCookie("state-a", "binding", expires)
	if !strings.HasPrefix(production.Name, "__Host-graphit_oidc_flow_") || !production.Secure || !production.HttpOnly || production.Path != "/" || production.SameSite != http.SameSiteLaxMode {
		t.Fatalf("production flow cookie=%#v", production)
	}
	productionSession := service.adminCookie("session", expires)
	if !productionSession.Secure || !productionSession.HttpOnly || productionSession.SameSite != http.SameSiteLaxMode {
		t.Fatalf("production session cookie=%#v", productionSession)
	}
}

func TestAdminRBACBootstrapAssignmentAndRevocation(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	if status := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/roles", "other-token", "").StatusCode; status != http.StatusForbidden {
		t.Fatalf("unassigned administrator status=%d", status)
	}
	assignment := `{"subject":"https://identity.example|other-subject","role":"admin"}`
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

func TestClaimRolesOverrideLocalRoleAssignments(t *testing.T) {
	service, httpServer, provider := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	state := *service.runtime()
	state.config.Authentication.OIDC[0].RoleClaim = "$.realm_access.roles[*]"
	service.state.Store(&state)
	ctx := context.Background()
	if err := service.control.AssignRole(ctx, "https://identity.example|other-subject", adminRole); err != nil {
		t.Fatal(err)
	}
	identity := provider.identities["other-token"]
	identity.Roles = []string{userRole}
	identity.RolesFromClaim = true
	identity.RoleClaimSelector = "$.realm_access.roles[*]"
	provider.identities["other-token"] = identity

	denied := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "other-token", "")
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("local admin assignment overrode claimed user role: status=%d", denied.StatusCode)
	}
	projects := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/projects", "other-token", "")
	_ = projects.Body.Close()
	if projects.StatusCode != http.StatusOK {
		t.Fatalf("claimed user role projects status=%d", projects.StatusCode)
	}
	session := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/session", "other-token", "")
	var sessionBody struct {
		Roles      []string `json:"roles"`
		RoleSource string   `json:"role_source"`
	}
	if err := json.NewDecoder(session.Body).Decode(&sessionBody); err != nil {
		t.Fatal(err)
	}
	_ = session.Body.Close()
	if sessionBody.RoleSource != "claim" || len(sessionBody.Roles) != 1 || sessionBody.Roles[0] != userRole {
		t.Fatalf("session role view=%#v", sessionBody)
	}

	if err := service.control.RevokeRole(ctx, "https://identity.example|other-subject", adminRole); err != nil {
		t.Fatal(err)
	}
	if err := service.control.AssignRole(ctx, "https://identity.example|other-subject", userRole); err != nil {
		t.Fatal(err)
	}
	identity.Roles = []string{adminRole}
	provider.identities["other-token"] = identity
	allowed := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "other-token", "")
	_ = allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("claimed admin role did not override local user assignment: status=%d", allowed.StatusCode)
	}

	state = *service.runtime()
	state.config.Authentication.OIDC[0].RoleClaim = ""
	service.state.Store(&state)
	databaseRole := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "other-token", "")
	_ = databaseRole.Body.Close()
	if databaseRole.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled role claim did not restore local user assignment: status=%d", databaseRole.StatusCode)
	}
}

func TestUserRoleListsOnlyAccessibleProjectsAndProviderCommand(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	ctx := context.Background()
	if err := service.control.AssignRole(ctx, "https://identity.example|other-subject", userRole); err != nil {
		t.Fatal(err)
	}
	document, err := service.control.CreateResourceGrant(ctx, 1, ACLRuleConfig{
		ID: "alice-projects", Name: "Alice projects", Access: "user", Principal: "alice",
		Capabilities: []string{"hub"}, Projects: []string{"project-b", "project-a"},
	}, service.runtime().config.Services.S3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.control.CreateResourceGrant(ctx, document.Revision, ACLRuleConfig{
		ID: "other-project", Name: "Other project", Access: "user", Principal: "bob",
		Capabilities: []string{"hub"}, Projects: []string{"secret-project"},
	}, service.runtime().config.Services.S3); err != nil {
		t.Fatal(err)
	}

	projectsResponse := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/projects", "other-token", "")
	defer projectsResponse.Body.Close()
	if projectsResponse.StatusCode != http.StatusOK {
		t.Fatalf("projects status=%d", projectsResponse.StatusCode)
	}
	var body struct {
		Projects        []userProject `json:"projects"`
		ProviderCommand string        `json:"provider_command"`
	}
	if err := json.NewDecoder(projectsResponse.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Projects) != 2 || body.Projects[0].ID != "project-a" || body.Projects[1].ID != "project-b" {
		t.Fatalf("projects=%#v", body.Projects)
	}
	if strings.Contains(body.ProviderCommand, "secret") || !strings.Contains(body.ProviderCommand, "provider add") || !strings.Contains(body.ProviderCommand, "--broker-endpoint") {
		t.Fatalf("provider command=%q", body.ProviderCommand)
	}

	configResponse := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "other-token", "")
	defer configResponse.Body.Close()
	if configResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("user role configuration status=%d", configResponse.StatusCode)
	}
}

func TestBrokerProviderAndLoginSnippetMatchesGraphitCLIContract(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	state := *service.runtime()
	state.config.Server.PublicURL = "https://broker.example.com"
	state.config.Authentication.OIDC = []OIDCIssuerConfig{{
		Issuer: "https://identity.example", Audiences: []string{"graphit-broker"},
		RequiredScopes: []string{"graphit.use"}, UsernameClaim: "preferred_username",
		OrganizationClaim: "organization.id", TeamsClaim: "groups",
	}}
	state.config.Administration.CLI = GraphitCLIConfig{ProviderName: "company", ProfileName: "alice-company"}
	service.state.Store(&state)

	command := service.graphitProviderCommand(AdminSession{Issuer: "https://identity.example", Subject: "alice"})
	for _, expected := range []string{
		"graphit --non-interactive provider add 'company' --type broker",
		"--broker-endpoint 'https://broker.example.com'",
		"graphit login --provider 'company' --profile 'alice-company'",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("OIDC CLI snippet omitted %q:\n%s", expected, command)
		}
	}
}

func TestLocalPasswordIsRejectedAsBearerAndCanCreateUISession(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	ctx := context.Background()
	if err := service.control.AssignRole(ctx, "local|consumer-subject", userRole); err != nil {
		t.Fatal(err)
	}
	if _, err := service.control.CreateResourceGrant(ctx, 1, ACLRuleConfig{
		ID: "local-project", Name: "Local token project", Access: "user", Principal: "consumer",
		Capabilities: []string{"hub"}, Projects: []string{"project-local"},
	}, service.runtime().config.Services.S3); err != nil {
		t.Fatal(err)
	}
	bearerProjects := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/projects", "consumer:consumer-secret", "")
	if bearerProjects.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password bearer projects status=%d", bearerProjects.StatusCode)
	}
	_ = bearerProjects.Body.Close()
	bearerConfig := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "consumer:consumer-secret", "")
	if bearerConfig.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password bearer configuration status=%d", bearerConfig.StatusCode)
	}
	_ = bearerConfig.Body.Close()

	invalid := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"wrong"}`)
	if invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid local login status=%d", invalid.StatusCode)
	}
	_ = invalid.Body.Close()

	login := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"consumer-secret"}`)
	if login.StatusCode != http.StatusNoContent {
		t.Fatalf("local login status=%d", login.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range login.Cookies() {
		if cookie.Name == adminCookieName {
			sessionCookie = cookie
		}
	}
	_ = login.Body.Close()
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		t.Fatalf("local session cookie=%#v", sessionCookie)
	}

	request, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/admin/api/v1/projects", nil)
	request.AddCookie(sessionCookie)
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("local projects status=%s err=%v", statusText(response), err)
	}
	defer response.Body.Close()
	var body struct {
		Projects        []userProject `json:"projects"`
		ProviderCommand string        `json:"provider_command"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Projects) != 1 || body.Projects[0].ID != "project-local" {
		t.Fatalf("local projects=%#v", body.Projects)
	}
	if !strings.Contains(body.ProviderCommand, "--type broker") || strings.Contains(body.ProviderCommand, "GRAPHIT_BROKER_KEY") || strings.Contains(body.ProviderCommand, "consumer-secret") {
		t.Fatalf("local provider command=%q", body.ProviderCommand)
	}
}

func TestAdminLocalLoginReturnsRetryAfterAfterDefaultFailureLimit(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	for range 5 {
		response := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"incorrect-password"}`)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failed login status=%d", response.StatusCode)
		}
		_ = response.Body.Close()
	}
	limited := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"consumer-secret"}`)
	defer limited.Body.Close()
	if limited.StatusCode != http.StatusTooManyRequests || limited.Header.Get("Retry-After") == "" {
		t.Fatalf("rate-limited login status=%d retry-after=%q", limited.StatusCode, limited.Header.Get("Retry-After"))
	}
	direct := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "consumer:consumer-secret", "")
	defer direct.Body.Close()
	if direct.StatusCode != http.StatusUnauthorized || direct.Header.Get("Retry-After") != "" {
		t.Fatalf("password bearer status=%d retry-after=%q", direct.StatusCode, direct.Header.Get("Retry-After"))
	}
}

func TestAdminLocalLoginRequiresAdaptiveCaptchaBeforePasswordWork(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	state := service.runtime()
	state.config.Authentication.Local.Captcha = LocalCaptchaConfig{Enabled: true, Provider: localCaptchaProviderTurnstile, SiteKey: "public-site-key", SecretKey: "private-secret-key", TriggerMultiplier: 1.5, VerificationTimeout: time.Second}
	verifier := &stubLocalCaptchaVerifier{provider: localCaptchaProviderTurnstile, valid: "valid-proof"}
	state.localPasswords.captcha = verifier
	state.localPasswords.captchaThreshold = 1
	checks := 0
	originalCheck := state.localPasswords.passwordCheck
	state.localPasswords.passwordCheck = func(ctx context.Context, verifier passwordVerifier, pepper []byte, password string) bool {
		checks++
		return originalCheck(ctx, verifier, pepper, password)
	}

	page, err := http.Get(httpServer.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	_ = page.Body.Close()
	if !strings.Contains(page.Header.Get("Content-Security-Policy"), "https://challenges.cloudflare.com") {
		t.Fatalf("admin CAPTCHA CSP=%q", page.Header.Get("Content-Security-Policy"))
	}

	options, err := http.Get(httpServer.URL + "/admin/api/v1/login-options")
	if err != nil {
		t.Fatal(err)
	}
	var optionsBody struct {
		Captcha *localCaptchaChallenge `json:"captcha"`
	}
	if options.StatusCode != http.StatusOK || json.NewDecoder(options.Body).Decode(&optionsBody) != nil || optionsBody.Captcha == nil || optionsBody.Captcha.Provider != localCaptchaProviderTurnstile || optionsBody.Captcha.Action != localCaptchaActionAdmin {
		t.Fatalf("login options status=%d body=%#v", options.StatusCode, optionsBody)
	}
	_ = options.Body.Close()

	missing := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"consumer-secret"}`)
	var missingBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		Captcha localCaptchaChallenge `json:"captcha"`
	}
	if missing.StatusCode != http.StatusForbidden || json.NewDecoder(missing.Body).Decode(&missingBody) != nil || missingBody.Error.Code != "captcha_required" || missingBody.Captcha.SiteKey != "site-key" || checks != 0 {
		t.Fatalf("missing CAPTCHA status=%d body=%#v password_checks=%d", missing.StatusCode, missingBody, checks)
	}
	_ = missing.Body.Close()

	valid := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"consumer-secret","captcha_token":"valid-proof"}`)
	defer valid.Body.Close()
	if valid.StatusCode != http.StatusNoContent || checks != 1 {
		t.Fatalf("valid CAPTCHA login status=%d password_checks=%d", valid.StatusCode, checks)
	}
}

func TestAdminLocalLoginEnrollsMFAAndAdministrativeResetForcesReenrollment(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	required := true
	service.runtime().localAuth.config.Required = &required
	if _, err := service.control.db.Exec(`UPDATE local_users SET password_change_required=1 WHERE username='consumer'`); err != nil {
		t.Fatal(err)
	}

	login := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"consumer-secret"}`)
	var passwordStep LocalAuthStep
	if login.StatusCode != http.StatusOK || json.NewDecoder(login.Body).Decode(&passwordStep) != nil || passwordStep.Status != localAuthStagePassword {
		t.Fatalf("password step status=%d step=%#v", login.StatusCode, passwordStep)
	}
	_ = login.Body.Close()
	changed := postJSON(t, httpServer.URL+"/admin/auth/local/continue", fmt.Sprintf(`{"challenge_token":%q,"new_password":"consumer-permanent"}`, passwordStep.ChallengeToken))
	var enrollment LocalAuthStep
	if changed.StatusCode != http.StatusOK || json.NewDecoder(changed.Body).Decode(&enrollment) != nil || enrollment.Status != localAuthStageEnroll || enrollment.Secret == "" || enrollment.QRCodeDataURL == "" {
		t.Fatalf("enrollment status=%d step=%#v", changed.StatusCode, enrollment)
	}
	_ = changed.Body.Close()
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verified := postJSON(t, httpServer.URL+"/admin/auth/local/continue", fmt.Sprintf(`{"challenge_token":%q,"code":%q}`, enrollment.ChallengeToken, code))
	var complete LocalAuthStep
	if verified.StatusCode != http.StatusOK || json.NewDecoder(verified.Body).Decode(&complete) != nil || complete.Status != "complete" || len(complete.RecoveryCodes) != localMFARecoveryCodeCount || len(verified.Cookies()) == 0 {
		t.Fatalf("MFA completion status=%d step=%#v cookies=%#v", verified.StatusCode, complete, verified.Cookies())
	}
	cookie := verified.Cookies()[0]
	_ = verified.Body.Close()

	reset := bearerRequest(t, http.MethodPost, httpServer.URL+"/admin/api/v1/local-users/consumer/mfa/reset", "root-token", "")
	if reset.StatusCode != http.StatusNoContent {
		t.Fatalf("MFA reset status=%d", reset.StatusCode)
	}
	_ = reset.Body.Close()
	stale, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/admin/api/v1/session", nil)
	stale.AddCookie(cookie)
	staleResponse, err := http.DefaultClient.Do(stale)
	if err != nil || staleResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after MFA reset status=%s err=%v", statusText(staleResponse), err)
	}
	_ = staleResponse.Body.Close()
	relogin := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"consumer","password":"consumer-permanent"}`)
	var reenrollment LocalAuthStep
	if relogin.StatusCode != http.StatusOK || json.NewDecoder(relogin.Body).Decode(&reenrollment) != nil || reenrollment.Status != localAuthStageEnroll || reenrollment.Secret == enrollment.Secret {
		t.Fatalf("reenrollment status=%d step=%#v", relogin.StatusCode, reenrollment)
	}
	_ = relogin.Body.Close()
}

func TestLocalOnlyUserCanBootstrapAdministrationWithoutOIDC(t *testing.T) {
	cfg := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Authentication.TokenPepper = testPasswordPepper
	requireMFA := false
	cfg.Authentication.Local.MFA.Required = &requireMFA
	cfg.Database.DSN = t.TempDir() + "/broker.db"
	cfg.Administration = AdministrationConfig{Enabled: true, SessionTTL: time.Hour,
		CLI: GraphitCLIConfig{ProviderName: "local-broker", ProfileName: "local-root"}}
	service, err := newServerWithFactory(context.Background(), cfg, func(context.Context, OIDCIssuerConfig) (AdminIdentityProvider, error) {
		t.Fatal("OIDC provider factory was called for local-only administration")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := service.control.BootstrapLocalAdmin(context.Background(), mustPasswordHash(t, "bootstrap-password")); err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(service)
	defer httpServer.Close()

	optionsResponse, err := http.Get(httpServer.URL + "/admin/api/v1/login-options")
	if err != nil || optionsResponse.StatusCode != http.StatusOK {
		t.Fatalf("login options status=%s err=%v", statusText(optionsResponse), err)
	}
	var options map[string]bool
	_ = json.NewDecoder(optionsResponse.Body).Decode(&options)
	_ = optionsResponse.Body.Close()
	if options["oidc"] || !options["local"] {
		t.Fatalf("login options=%#v", options)
	}

	login := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"admin","password":"bootstrap-password"}`)
	var passwordStep LocalAuthStep
	if login.StatusCode != http.StatusOK || json.NewDecoder(login.Body).Decode(&passwordStep) != nil || passwordStep.Status != localAuthStagePassword {
		t.Fatalf("local bootstrap password step status=%d step=%#v", login.StatusCode, passwordStep)
	}
	_ = login.Body.Close()
	login = postJSON(t, httpServer.URL+"/admin/auth/local/continue", fmt.Sprintf(`{"challenge_token":%q,"new_password":"bootstrap-password-replaced"}`, passwordStep.ChallengeToken))
	if login.StatusCode != http.StatusNoContent || len(login.Cookies()) == 0 {
		t.Fatalf("local bootstrap login completion status=%d cookies=%#v", login.StatusCode, login.Cookies())
	}
	cookie := login.Cookies()[0]
	_ = login.Body.Close()
	configRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/admin/api/v1/config", nil)
	configRequest.AddCookie(cookie)
	configResponse, err := http.DefaultClient.Do(configRequest)
	if err != nil || configResponse.StatusCode != http.StatusOK {
		t.Fatalf("local bootstrap configuration status=%s err=%v", statusText(configResponse), err)
	}
	_ = configResponse.Body.Close()
	sessionRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/admin/api/v1/session", nil)
	sessionRequest.AddCookie(cookie)
	sessionResponse, err := http.DefaultClient.Do(sessionRequest)
	if err != nil || sessionResponse.StatusCode != http.StatusOK {
		t.Fatalf("local bootstrap session status=%s err=%v", statusText(sessionResponse), err)
	}
	var sessionBody struct {
		RoleSource string `json:"role_source"`
	}
	_ = json.NewDecoder(sessionResponse.Body).Decode(&sessionBody)
	_ = sessionResponse.Body.Close()
	if sessionBody.RoleSource != "database" {
		t.Fatalf("local bootstrap role source=%q", sessionBody.RoleSource)
	}
	user, err := service.control.LocalUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	user.PasswordHash = mustPasswordHash(t, "replacement-password")
	if err := service.control.UpdateLocalUser(context.Background(), "admin", user); err != nil {
		t.Fatal(err)
	}
	staleRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/admin/api/v1/config", nil)
	staleRequest.AddCookie(cookie)
	staleResponse, err := http.DefaultClient.Do(staleRequest)
	if err != nil || staleResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale configured roles status=%s err=%v", statusText(staleResponse), err)
	}
	_ = staleResponse.Body.Close()
}

func TestLocalSessionRefreshesAfterUserRevisionChanges(t *testing.T) {
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.BootstrapLocalAdmin(context.Background(), mustPasswordHash(t, "bootstrap-password")); err != nil {
		t.Fatal(err)
	}
	user, err := store.LocalUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{control: store}
	server.state.Store(&runtimeState{config: Config{Authentication: AuthenticationConfig{TokenPepper: testPasswordPepper}}})
	session := AdminSession{Issuer: localIdentityIssuer, Subject: user.Subject, Username: user.Username, LocalUserRevision: user.Revision}
	if server.sessionNeedsRoleRefresh(context.Background(), session) {
		t.Fatal("unchanged local credential required a refresh")
	}
	user.Name = "Changed"
	if err := store.UpdateLocalUser(context.Background(), "admin", user); err != nil {
		t.Fatal(err)
	}
	if !server.sessionNeedsRoleRefresh(context.Background(), session) {
		t.Fatal("changed local user did not require a refresh")
	}
}

func TestAdminLocalUserCRUDIsProtectedAndNeverReturnsPasswordHash(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	rawSession := "root-cookie-session"
	csrf := "root-csrf-token"
	if err := service.control.CreateSession(context.Background(), rawSession, AdminSession{
		Issuer: "https://identity.example", Subject: "root-subject", Username: "root", CSRFToken: csrf, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	short := bearerRequest(t, http.MethodPost, httpServer.URL+"/admin/api/v1/local-users", "root-token", `{"username":"short","subject":"local-short","password":"short-password","enabled":true}`)
	if short.StatusCode != http.StatusBadRequest {
		t.Fatalf("short local password status=%d", short.StatusCode)
	}
	_ = short.Body.Close()
	body := `{"username":"alice","subject":"local-alice","password":"initial-password","name":"Alice","roles":[],"enabled":true}`
	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/api/v1/local-users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: adminCookieName, Value: rawSession})
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%s err=%v", statusText(response), err)
	}
	_ = response.Body.Close()
	request, _ = http.NewRequest(http.MethodPost, httpServer.URL+"/admin/api/v1/local-users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(&http.Cookie{Name: adminCookieName, Value: rawSession})
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		t.Fatalf("create local user status=%s err=%v", statusText(response), err)
	}
	_ = response.Body.Close()
	listed := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/local-users", "root-token", "")
	encoded, _ := io.ReadAll(listed.Body)
	_ = listed.Body.Close()
	if listed.StatusCode != http.StatusOK || bytes.Contains(encoded, []byte("password_hash")) || bytes.Contains(encoded, []byte("initial-secret")) || !bytes.Contains(encoded, []byte(`"roles":["user"]`)) {
		t.Fatalf("local user list status=%d body=%s", listed.StatusCode, encoded)
	}
	updated := `{"username":"alice-renamed","subject":"local-alice","password":"replacement-secret","name":"Alice Updated","roles":["admin"],"enabled":true}`
	put := bearerRequest(t, http.MethodPut, httpServer.URL+"/admin/api/v1/local-users/alice", "root-token", updated)
	if put.StatusCode != http.StatusNoContent {
		t.Fatalf("update local user status=%d", put.StatusCode)
	}
	_ = put.Body.Close()
	login := postJSON(t, httpServer.URL+"/admin/auth/local", `{"username":"alice-renamed","password":"replacement-secret"}`)
	var step LocalAuthStep
	if login.StatusCode != http.StatusOK || json.NewDecoder(login.Body).Decode(&step) != nil || step.Status != localAuthStagePassword {
		t.Fatalf("updated local user login status=%d step=%#v", login.StatusCode, step)
	}
	_ = login.Body.Close()
	deleted := bearerRequest(t, http.MethodDelete, httpServer.URL+"/admin/api/v1/local-users/alice-renamed", "root-token", "")
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("delete local user status=%d", deleted.StatusCode)
	}
	_ = deleted.Body.Close()
}

func postJSON(t *testing.T, endpoint, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestAdminConfigurationIsRedactedReadOnlyDeploymentState(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}}})
	}))
	defer upstream.Close()
	service, httpServer, _ := newAdminTestServer(t, upstream.URL)
	defer service.Close()
	defer httpServer.Close()
	service.runtime().config.Authentication.Local.Captcha = LocalCaptchaConfig{Enabled: true, Provider: localCaptchaProviderRecaptcha, SiteKey: "public-captcha-key", SecretKey: "private-captcha-secret", TriggerMultiplier: 1.5, VerificationTimeout: 3 * time.Second}

	configResponse := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/config", "root-token", "")
	if configResponse.StatusCode != http.StatusOK || configResponse.Header.Get("ETag") != "" {
		t.Fatalf("config status=%d etag=%q", configResponse.StatusCode, configResponse.Header.Get("ETag"))
	}
	configBody, _ := io.ReadAll(configResponse.Body)
	_ = configResponse.Body.Close()
	for _, secret := range []string{"admin-client-secret", "consumer-secret", "embedding-secret", "rerank-secret", "TESTACCESS", "TESTSECRET", "private-captcha-secret", testPasswordPepper, service.runtime().config.Database.DSN} {
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
	if count := strings.Count(envelope.YAML, configuredSecret); count < 6 {
		t.Fatalf("expected redacted placeholders, count=%d YAML=%s", count, envelope.YAML)
	}
	if !strings.Contains(envelope.YAML, "public-captcha-key") || !strings.Contains(envelope.YAML, "provider: recaptcha") {
		t.Fatalf("non-secret CAPTCHA configuration missing from redacted YAML: %s", envelope.YAML)
	}
	update, _ := http.NewRequest(http.MethodPut, httpServer.URL+"/admin/api/v1/config", strings.NewReader(`{"yaml":"services: {}"}`))
	update.Header.Set("Authorization", "Bearer root-token")
	update.Header.Set("Content-Type", "application/json")
	updated, err := http.DefaultClient.Do(update)
	if err != nil || updated.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("config update status=%s etag=%q err=%v", statusText(updated), updated.Header.Get("ETag"), err)
	}
	_ = updated.Body.Close()
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		request, _ := http.NewRequest(method, httpServer.URL+"/admin/api/v1/config", strings.NewReader(`{"yaml":"database: {}"}`))
		request.Header.Set("Authorization", "Bearer root-token")
		response, err := http.DefaultClient.Do(request)
		if err != nil || response.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("config %s status=%s err=%v", method, statusText(response), err)
		}
		_ = response.Body.Close()
	}
	discovery, _ := http.Get(httpServer.URL + "/.well-known/graphit-broker")
	discoveryBody, _ := io.ReadAll(discovery.Body)
	_ = discovery.Body.Close()
	if !bytes.Contains(discoveryBody, []byte(`"rerank"`)) {
		t.Fatalf("read-only request changed runtime configuration: %s", discoveryBody)
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
	httpServer := httptest.NewUnstartedServer(nil)
	cfg := testServerConfig(embeddingURL, "http://127.0.0.1:1")
	cfg.Server.PublicURL = "http://" + httpServer.Listener.Addr().String()
	cfg.Authentication = AuthenticationConfig{TokenPepper: testPasswordPepper, OIDC: []OIDCIssuerConfig{{
		Issuer: "https://identity.example", Audiences: []string{"graphit-broker"}, SubjectClaim: "sub", UsernameClaim: "preferred_username",
		ClientID: "admin-client", ClientSecret: "admin-client-secret", RedirectURL: "http://127.0.0.1/oauth/oidc/callback", Scopes: []string{"openid", "profile", "email"},
	}}}
	requireMFA := false
	cfg.Authentication.Local.MFA.Required = &requireMFA
	cfg.Services.Embeddings.Upstream.APIKey = "embedding-secret"
	cfg.Services.Rerank.Upstream.APIKey = "rerank-secret"
	cfg.Database.DSN = t.TempDir() + "/broker.db"
	cookieSecure := false
	cfg.Administration = AdministrationConfig{Enabled: true, SessionTTL: time.Hour, CookieSecure: &cookieSecure}
	cfg.Authentication.Local.Tokens.setDefaults()
	provider := &fakeAdminOIDC{identities: map[string]AdminIdentity{
		"root-token": {Issuer: "https://identity.example", Subject: "root-subject", Name: "Root", Email: "root@example.test",
			Username: "root", Organization: "acme", Teams: []string{"platform"}},
		"other-token": {Issuer: "https://identity.example", Subject: "other-subject", Name: "Other",
			Username: "alice", Organization: "acme", Teams: []string{"platform"}},
	}}
	control, err := OpenControlStore(cfg.Database, cfg.Authentication.TokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.CreateLocalUser(context.Background(), LocalUser{Username: "consumer", Subject: "consumer-subject", PasswordHash: mustPasswordHash(t, "consumer-secret"), Enabled: true}); err != nil {
		control.Close()
		t.Fatal(err)
	}
	if _, err := control.db.Exec(`UPDATE local_users SET password_change_required=0 WHERE username='consumer'`); err != nil {
		control.Close()
		t.Fatal(err)
	}
	localConfig := cfg.Authentication
	localConfig.OIDC = nil
	localAuthenticator, err := NewAuthenticator(context.Background(), localConfig, control)
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	authenticator := testAdminAuthenticator{local: localAuthenticator, store: control, identities: provider.identities}
	service := newServerWithDependencies(cfg, authenticator, NewAIService(cfg.Services), nil, control, control, provider)
	localPasswords, err := newLocalPasswordAuthenticator(context.Background(), cfg.Authentication, control)
	if err != nil {
		service.Close()
		t.Fatal(err)
	}
	runtime := *service.runtime()
	runtime.localPasswords = localPasswords
	runtime.localAuth, err = newLocalAuthenticationService(cfg.Authentication, control, localPasswords)
	if err != nil {
		service.Close()
		t.Fatal(err)
	}
	service.state.Store(&runtime)
	if err := service.control.AssignRole(context.Background(), "https://identity.example|root-subject", adminRole); err != nil {
		service.Close()
		t.Fatal(err)
	}
	httpServer.Config.Handler = service
	httpServer.Start()
	return service, httpServer, provider
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
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
