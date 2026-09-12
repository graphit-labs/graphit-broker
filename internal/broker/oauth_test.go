package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/pquerna/otp/totp"
	zitcrypto "github.com/zitadel/oidc/v3/pkg/crypto"
	zitoidc "github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestLocalAuthorizationCodeRequiresPKCEAndRotatesRefreshTokens(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	metadataResponse, err := http.Get(httpServer.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		UserinfoEndpoint      string   `json:"userinfo_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		GrantTypes            []string `json:"grant_types_supported"`
		CodeChallenges        []string `json:"code_challenge_methods_supported"`
		TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
		SigningAlgorithms     []string `json:"id_token_signing_alg_values_supported"`
	}
	if metadataResponse.StatusCode != http.StatusOK || json.NewDecoder(metadataResponse.Body).Decode(&metadata) != nil {
		t.Fatalf("OpenID discovery status=%d", metadataResponse.StatusCode)
	}
	_ = metadataResponse.Body.Close()
	if metadata.Issuer != httpServer.URL || metadata.AuthorizationEndpoint != httpServer.URL+"/oauth/authorize" || metadata.TokenEndpoint != httpServer.URL+"/oauth/token" ||
		metadata.UserinfoEndpoint != httpServer.URL+"/oauth/userinfo" || metadata.JWKSURI != httpServer.URL+"/oauth/keys" ||
		!containsString(metadata.GrantTypes, "authorization_code") || !containsString(metadata.GrantTypes, "refresh_token") ||
		!containsString(metadata.CodeChallenges, "S256") || !containsString(metadata.TokenAuthMethods, "none") || !containsString(metadata.SigningAlgorithms, "EdDSA") {
		t.Fatalf("incomplete OpenID discovery: %#v", metadata)
	}

	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	redirectURI := "http://127.0.0.1:49152/oauth/callback"
	code := authorizeLocalCLI(t, httpServer.URL, redirectURI, challenge, "graphit.use offline_access")

	wrong := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"graphit-cli"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {strings.Repeat("w", 64)},
	})
	if wrong.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong PKCE status=%d", wrong.StatusCode)
	}
	_ = wrong.Body.Close()
	corrected := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"graphit-cli"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	if corrected.StatusCode != http.StatusOK {
		t.Fatalf("authorization code correction status=%d", corrected.StatusCode)
	}
	_ = corrected.Body.Close()
	replay := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"graphit-cli"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("authorization code replay status=%d", replay.StatusCode)
	}
	_ = replay.Body.Close()

	code = authorizeLocalCLI(t, httpServer.URL, redirectURI, challenge, "graphit.use offline_access")
	wrongRedirect := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"graphit-cli"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:49153/oauth/callback"}, "code_verifier": {verifier},
	})
	if wrongRedirect.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong redirect status=%d", wrongRedirect.StatusCode)
	}
	_ = wrongRedirect.Body.Close()

	code = authorizeLocalCLI(t, httpServer.URL, redirectURI, challenge, "graphit.use offline_access")
	tokenResponse := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"graphit-cli"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if tokenResponse.StatusCode != http.StatusOK || json.NewDecoder(tokenResponse.Body).Decode(&tokens) != nil {
		t.Fatalf("token exchange status=%d", tokenResponse.StatusCode)
	}
	_ = tokenResponse.Body.Close()
	if tokens.AccessToken == "" || strings.HasPrefix(tokens.AccessToken, localAccessTokenPrefix) || !strings.HasPrefix(tokens.RefreshToken, localRefreshTokenPrefix) || tokens.IDToken == "" {
		t.Fatalf("issued tokens=%#v", tokens)
	}
	providerContext := coreoidc.InsecureIssuerURLContext(context.Background(), httpServer.URL)
	provider, err := coreoidc.NewProvider(providerContext, httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := provider.Verifier(&coreoidc.Config{ClientID: "graphit-cli"}).Verify(providerContext, tokens.IDToken)
	if err != nil {
		t.Fatalf("verify Broker ID token: %v", err)
	}
	var claims map[string]any
	if err := verified.Claims(&claims); err != nil || claims["nonce"] != "client-nonce" || claims["preferred_username"] != "consumer" || !strings.HasPrefix(verified.Subject, "gb_sub_") {
		t.Fatalf("local ID token claims=%#v subject=%q err=%v", claims, verified.Subject, err)
	}
	if _, exists := claims["organization"]; exists {
		t.Fatalf("local ID token must omit empty optional organization claim: %#v", claims)
	}
	accessClaims := verifyBrokerAccessToken(t, providerContext, provider, tokens.AccessToken, "consumer", "", nil)
	if principal, err := service.oidcProvider.AuthenticateAccessToken(context.Background(), tokens.AccessToken); err != nil || principal.Username != "consumer" {
		t.Fatalf("authenticate Broker access token principal=%#v err=%v claims=%#v", principal, err, accessClaims)
	}
	userinfo := bearerRequest(t, http.MethodGet, httpServer.URL+"/oauth/userinfo", tokens.AccessToken, "")
	var userinfoClaims map[string]any
	if userinfo.StatusCode != http.StatusOK || json.NewDecoder(userinfo.Body).Decode(&userinfoClaims) != nil ||
		userinfoClaims["sub"] != verified.Subject || userinfoClaims["preferred_username"] != "consumer" {
		t.Fatalf("local userinfo status=%d claims=%#v", userinfo.StatusCode, userinfoClaims)
	}
	_ = userinfo.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", tokens.AccessToken, http.StatusOK)
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", "consumer:consumer-secret", http.StatusUnauthorized)

	rotatedResponse := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"graphit-cli"}, "refresh_token": {tokens.RefreshToken},
	})
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if rotatedResponse.StatusCode != http.StatusOK || json.NewDecoder(rotatedResponse.Body).Decode(&rotated) != nil {
		t.Fatalf("refresh rotation status=%d", rotatedResponse.StatusCode)
	}
	_ = rotatedResponse.Body.Close()
	if rotated.RefreshToken == "" || rotated.RefreshToken == tokens.RefreshToken {
		t.Fatalf("refresh token was not rotated: %#v", rotated)
	}
	rotatedClaims := verifyBrokerAccessToken(t, providerContext, provider, rotated.AccessToken, "consumer", "", nil)
	if rotated.AccessToken == tokens.AccessToken || rotatedClaims["jti"] == accessClaims["jti"] || rotatedClaims["sub"] != accessClaims["sub"] {
		t.Fatalf("refresh did not issue a distinct JWT for the same subject: first=%#v rotated=%#v", accessClaims, rotatedClaims)
	}

	reused := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"graphit-cli"}, "refresh_token": {tokens.RefreshToken},
	})
	if reused.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh reuse status=%d", reused.StatusCode)
	}
	_ = reused.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", rotated.AccessToken, http.StatusUnauthorized)

	code = authorizeLocalCLI(t, httpServer.URL, redirectURI, challenge, localAPIScope)
	revocableResponse := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"graphit-cli"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	var revocable struct {
		AccessToken string `json:"access_token"`
	}
	if revocableResponse.StatusCode != http.StatusOK || json.NewDecoder(revocableResponse.Body).Decode(&revocable) != nil {
		t.Fatalf("revocable token status=%d", revocableResponse.StatusCode)
	}
	_ = revocableResponse.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", revocable.AccessToken, http.StatusOK)
	revoked := oauthForm(t, httpServer.URL+"/oauth/revoke", url.Values{"token": {revocable.AccessToken}, "client_id": {"graphit-cli"}})
	if revoked.StatusCode != http.StatusOK {
		t.Fatalf("revocation status=%d", revoked.StatusCode)
	}
	_ = revoked.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", revocable.AccessToken, http.StatusUnauthorized)
	verifyBrokerAccessToken(t, providerContext, provider, revocable.AccessToken, "consumer", "", nil)

	validVerifier := provider.Verifier(&coreoidc.Config{ClientID: "graphit-broker"})
	invalidTokens := map[string]string{
		"tampered signature": tamperJWT(tokens.AccessToken),
		"wrong issuer":       signedBrokerAccessToken(t, service, "https://other-issuer.example", "graphit-broker", time.Now().Add(time.Minute)),
		"wrong audience":     signedBrokerAccessToken(t, service, httpServer.URL, "other-audience", time.Now().Add(time.Minute)),
		"expired":            signedBrokerAccessToken(t, service, httpServer.URL, "graphit-broker", time.Now().Add(-time.Minute)),
	}
	for name, raw := range invalidTokens {
		t.Run(name, func(t *testing.T) {
			if _, err := validVerifier.Verify(providerContext, raw); err == nil {
				t.Fatal("public discovery/JWKS verifier accepted invalid access token")
			}
			if _, err := service.oidcProvider.AuthenticateAccessToken(context.Background(), raw); err == nil {
				t.Fatal("Broker internal verifier accepted invalid access token")
			}
		})
	}

	var rawPersisted int
	if err := service.control.db.QueryRow(`SELECT COUNT(*) FROM local_tokens WHERE token_hash=? OR token_id=?`, tokens.AccessToken, tokens.AccessToken).Scan(&rawPersisted); err != nil || rawPersisted != 0 {
		t.Fatalf("raw token persisted count=%d err=%v", rawPersisted, err)
	}
}

func TestBrokerOIDCPageOffersConfiguredMethodsAndCompletesUpstreamOIDC(t *testing.T) {
	service, httpServer, upstream := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	if _, err := service.control.db.Exec(`UPDATE local_users SET enabled=0`); err != nil {
		t.Fatal(err)
	}
	if count, err := service.control.EnabledLocalHumanCount(context.Background()); err != nil || count != 0 {
		t.Fatalf("enabled local human count=%d err=%v", count, err)
	}

	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	redirectURI := "http://127.0.0.1:49152/oauth/callback"
	query := url.Values{"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {redirectURI},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
		"state": {"graphit-state"}, "nonce": {"graphit-nonce"}, "scope": {"openid profile email graphit.use offline_access"}}

	client := noRedirectClient()
	start, err := client.Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
	if err != nil || start.StatusCode != http.StatusFound {
		t.Fatalf("authorization start status=%s err=%v", statusText(start), err)
	}
	loginURL := absoluteTestURL(httpServer.URL, start.Header.Get("Location"))
	_ = start.Body.Close()
	page, err := client.Get(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.HasPrefix(page.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(page.Header.Get("Content-Security-Policy"), "form-action 'self'") ||
		!strings.Contains(string(pageBody), `data-ui="graphit-auth"`) || !strings.Contains(string(pageBody), `class="auth-shell"`) ||
		!strings.Contains(string(pageBody), `class="provider-list"`) ||
		!strings.Contains(string(pageBody), `<form method="post">`) || !strings.Contains(string(pageBody), "Sign in locally") ||
		!strings.Contains(string(pageBody), "Continue with Corporate SSO") {
		t.Fatalf("authorization methods status=%d body=%s", page.StatusCode, pageBody)
	}

	oidcLink := regexp.MustCompile(`href="([^"]+login_method=oidc[^"]*)"`).FindStringSubmatch(string(pageBody))
	if len(oidcLink) != 2 {
		t.Fatalf("authorization page omitted OIDC navigation link: %s", pageBody)
	}
	oidcStartURL := absoluteTestURL(httpServer.URL, html.UnescapeString(oidcLink[1]))
	loginLocation, err := url.Parse(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	oidcLocation, err := url.Parse(oidcStartURL)
	if err != nil || oidcLocation.Query().Get("id") != loginLocation.Query().Get("id") || oidcLocation.Query().Get("login_method") != "oidc" || oidcLocation.Query().Get("provider") == "" {
		t.Fatalf("OIDC navigation URL=%q err=%v", oidcStartURL, err)
	}
	oidcStart, err := client.Get(oidcStartURL)
	if err != nil {
		t.Fatal(err)
	}
	if oidcStart.StatusCode != http.StatusFound || !strings.HasPrefix(oidcStart.Header.Get("Location"), "https://identity.example/authorize?") {
		t.Fatalf("OIDC start status=%d location=%q", oidcStart.StatusCode, oidcStart.Header.Get("Location"))
	}
	_ = oidcStart.Body.Close()

	callback, err := client.Get(httpServer.URL + "/oauth/oidc/callback?state=" + url.QueryEscape(upstream.state) + "&code=valid-code")
	if err != nil || callback.StatusCode != http.StatusFound {
		t.Fatalf("OIDC callback status=%s err=%v", statusText(callback), err)
	}
	opCallback := absoluteTestURL(httpServer.URL, callback.Header.Get("Location"))
	_ = callback.Body.Close()
	callback, err = client.Get(opCallback)
	if err != nil || callback.StatusCode != http.StatusFound {
		t.Fatalf("OP callback status=%s err=%v", statusText(callback), err)
	}
	location, err := url.Parse(callback.Header.Get("Location"))
	_ = callback.Body.Close()
	if err != nil || location.String() == "" || location.Query().Get("state") != "graphit-state" || location.Query().Get("code") == "" {
		t.Fatalf("Graphit callback location=%q err=%v", location, err)
	}

	tokenResponse := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"graphit-cli"},
		"code": {location.Query().Get("code")}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}})
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if tokenResponse.StatusCode != http.StatusOK || json.NewDecoder(tokenResponse.Body).Decode(&token) != nil {
		t.Fatalf("OIDC token status=%d", tokenResponse.StatusCode)
	}
	_ = tokenResponse.Body.Close()
	providerContext := coreoidc.InsecureIssuerURLContext(context.Background(), httpServer.URL)
	provider, err := coreoidc.NewProvider(providerContext, httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := provider.Verifier(&coreoidc.Config{ClientID: "graphit-cli"}).Verify(providerContext, token.IDToken)
	var claims map[string]any
	verifiedSubject := ""
	if err == nil {
		err = verified.Claims(&claims)
		verifiedSubject = verified.Subject
	}
	if err != nil || claims["preferred_username"] != "root" || claims["nonce"] != "graphit-nonce" || !strings.HasPrefix(verifiedSubject, "gb_sub_") {
		t.Fatalf("OIDC token claims=%#v subject=%q err=%v", claims, verifiedSubject, err)
	}
	accessClaims := verifyBrokerAccessToken(t, providerContext, provider, token.AccessToken, "root", "acme", []string{"platform"})
	if token.RefreshToken == "" {
		t.Fatal("upstream-authenticated Broker OIDC login omitted refresh token")
	}
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", token.AccessToken, http.StatusOK)
	userinfo := bearerRequest(t, http.MethodGet, httpServer.URL+"/oauth/userinfo", token.AccessToken, "")
	var userinfoClaims map[string]any
	if userinfo.StatusCode != http.StatusOK || json.NewDecoder(userinfo.Body).Decode(&userinfoClaims) != nil || userinfoClaims["sub"] != verifiedSubject || userinfoClaims["preferred_username"] != "root" {
		t.Fatalf("userinfo status=%d claims=%#v", userinfo.StatusCode, userinfoClaims)
	}
	_ = userinfo.Body.Close()
	refreshResponse := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"graphit-cli"}, "refresh_token": {token.RefreshToken},
	})
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if refreshResponse.StatusCode != http.StatusOK || json.NewDecoder(refreshResponse.Body).Decode(&refreshed) != nil {
		t.Fatalf("upstream-authenticated refresh status=%d", refreshResponse.StatusCode)
	}
	_ = refreshResponse.Body.Close()
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == token.RefreshToken {
		t.Fatalf("upstream-authenticated refresh did not rotate: %#v", refreshed)
	}
	refreshedClaims := verifyBrokerAccessToken(t, providerContext, provider, refreshed.AccessToken, "root", "acme", []string{"platform"})
	if refreshed.AccessToken == token.AccessToken || refreshedClaims["jti"] == accessClaims["jti"] || refreshedClaims["sub"] != accessClaims["sub"] {
		t.Fatalf("upstream refresh did not issue a distinct Broker JWT for the same subject: first=%#v refreshed=%#v", accessClaims, refreshedClaims)
	}
	userinfo = bearerRequest(t, http.MethodGet, httpServer.URL+"/oauth/userinfo", refreshed.AccessToken, "")
	userinfoClaims = map[string]any{}
	if userinfo.StatusCode != http.StatusOK || json.NewDecoder(userinfo.Body).Decode(&userinfoClaims) != nil ||
		userinfoClaims["sub"] != verifiedSubject || userinfoClaims["preferred_username"] != "root" {
		t.Fatalf("refreshed upstream userinfo status=%d claims=%#v", userinfo.StatusCode, userinfoClaims)
	}
	_ = userinfo.Body.Close()

	disabled := *service.runtime()
	localDisabled := false
	disabled.config.Authentication.Local.Login.Enabled = &localDisabled
	service.state.Store(&disabled)
	onlyOIDCStart, _ := client.Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
	onlyOIDCLogin := absoluteTestURL(httpServer.URL, onlyOIDCStart.Header.Get("Location"))
	_ = onlyOIDCStart.Body.Close()
	onlyOIDC, _ := client.Get(onlyOIDCLogin)
	if onlyOIDC.StatusCode != http.StatusFound || !strings.HasPrefix(onlyOIDC.Header.Get("Location"), "https://identity.example/authorize?") {
		t.Fatalf("OIDC-only login status=%d location=%q", onlyOIDC.StatusCode, onlyOIDC.Header.Get("Location"))
	}
	_ = onlyOIDC.Body.Close()

	localOnly := *service.runtime()
	localEnabled := true
	localOnly.config.Authentication.Local.Login.Enabled = &localEnabled
	localOnly.browserOIDC = nil
	service.state.Store(&localOnly)
	onlyLocalStart, _ := client.Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
	onlyLocalLogin := absoluteTestURL(httpServer.URL, onlyLocalStart.Header.Get("Location"))
	_ = onlyLocalStart.Body.Close()
	onlyLocal, _ := client.Get(onlyLocalLogin)
	onlyLocalBody, _ := io.ReadAll(onlyLocal.Body)
	_ = onlyLocal.Body.Close()
	if !strings.Contains(string(onlyLocalBody), "Sign in locally") || strings.Contains(string(onlyLocalBody), "Choose an organization account") {
		t.Fatalf("local-only login page=%s", onlyLocalBody)
	}
	unavailableOIDC, err := client.Get(onlyLocalLogin + "&login_method=oidc")
	if err != nil {
		t.Fatal(err)
	}
	if unavailableOIDC.StatusCode != http.StatusBadRequest {
		t.Fatalf("unavailable OIDC GET status=%d", unavailableOIDC.StatusCode)
	}
	_ = unavailableOIDC.Body.Close()
	unavailableOIDC = oauthFormWithClient(t, client, onlyLocalLogin, url.Values{"login_method": {"oidc"}})
	if unavailableOIDC.StatusCode != http.StatusBadRequest {
		t.Fatalf("unavailable OIDC method status=%d", unavailableOIDC.StatusCode)
	}
	_ = unavailableOIDC.Body.Close()
}

func TestBrokerOIDCPageLetsUserChooseAmongMultipleProviders(t *testing.T) {
	service, httpServer, corporate := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	partner := &fakeAdminOIDC{
		authorizationBase: "https://partner.example/authorize",
		identities: map[string]AdminIdentity{
			"root-token": {Issuer: "https://partner.example", Subject: "partner-subject", Username: "partner-admin"},
		},
	}
	runtime := *service.runtime()
	localDisabled := false
	runtime.config.Authentication.Local.Login.Enabled = &localDisabled
	runtime.browserOIDC = []browserOIDCProvider{
		{ID: "corporate", Name: "Corporate SSO", Identity: corporate},
		{ID: "partner", Name: "Partner Login", Identity: partner},
	}
	service.state.Store(&runtime)

	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {"http://127.0.0.1:49152/oauth/callback"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
		"state": {"graphit-state"}, "nonce": {"graphit-nonce"}, "scope": {"openid graphit.use"},
	}
	client := noRedirectClient()
	start, err := client.Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
	if err != nil || start.StatusCode != http.StatusFound {
		t.Fatalf("authorization start status=%s err=%v", statusText(start), err)
	}
	loginURL := absoluteTestURL(httpServer.URL, start.Header.Get("Location"))
	_ = start.Body.Close()
	page, err := client.Get(loginURL)
	if err != nil || page.StatusCode != http.StatusOK {
		t.Fatalf("provider selection status=%s err=%v", statusText(page), err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if !bytes.Contains(body, []byte("Continue with Corporate SSO")) || !bytes.Contains(body, []byte("Continue with Partner Login")) {
		t.Fatalf("provider selection page=%s", body)
	}
	partnerLink := regexp.MustCompile(`href="([^"]*provider=partner[^"]*)"`).FindStringSubmatch(string(body))
	if len(partnerLink) != 2 {
		t.Fatalf("partner provider link missing: %s", body)
	}
	selected, err := client.Get(absoluteTestURL(httpServer.URL, html.UnescapeString(partnerLink[1])))
	if err != nil || selected.StatusCode != http.StatusFound || !strings.HasPrefix(selected.Header.Get("Location"), "https://partner.example/authorize?") {
		t.Fatalf("partner selection status=%s location=%q err=%v", statusText(selected), selected.Header.Get("Location"), err)
	}
	_ = selected.Body.Close()
	if partner.state == "" || corporate.state != "" {
		t.Fatalf("wrong provider started: partner state=%q corporate state=%q", partner.state, corporate.state)
	}
	callback, err := client.Get(httpServer.URL + "/oauth/oidc/callback?state=" + url.QueryEscape(partner.state) + "&code=valid-code")
	if err != nil || callback.StatusCode != http.StatusFound {
		t.Fatalf("partner callback status=%s err=%v", statusText(callback), err)
	}
	_ = callback.Body.Close()
}

func verifyBrokerAccessToken(t *testing.T, ctx context.Context, provider *coreoidc.Provider, raw, username, organization string, groups []string) map[string]any {
	t.Helper()
	if strings.Count(raw, ".") != 2 {
		t.Fatalf("Broker access token is not a compact signed JWT")
	}
	verified, err := provider.Verifier(&coreoidc.Config{ClientID: "graphit-broker"}).Verify(ctx, raw)
	if err != nil {
		t.Fatalf("verify Broker access token through discovery/JWKS: %v", err)
	}
	var claims map[string]any
	if err := verified.Claims(&claims); err != nil {
		t.Fatalf("decode verified Broker access token claims: %v", err)
	}
	scope, scopeOK := claims["scope"].(string)
	if verified.Issuer == "" || verified.Subject == "" || verified.Expiry.Before(time.Now()) || claims["iat"] == nil || claims["jti"] == "" ||
		claims["client_id"] != "graphit-cli" || claims["preferred_username"] != username || !scopeOK || !strings.Contains(scope, localAPIScope) {
		t.Fatalf("incomplete Broker access token claims=%#v", claims)
	}
	if organization == "" {
		if _, exists := claims["organization"]; exists {
			t.Fatalf("empty optional organization claim must be omitted: %#v", claims)
		}
	} else if claims["organization"] != organization {
		t.Fatalf("organization claim=%#v expected=%q", claims["organization"], organization)
	}
	if len(groups) == 0 {
		if _, exists := claims["groups"]; exists {
			t.Fatalf("empty optional groups claim must be omitted: %#v", claims)
		}
	} else {
		got, _ := claims["groups"].([]any)
		if len(got) != len(groups) {
			t.Fatalf("groups claim=%#v expected=%v", claims["groups"], groups)
		}
		for i := range groups {
			if got[i] != groups[i] {
				t.Fatalf("groups claim=%#v expected=%v", claims["groups"], groups)
			}
		}
	}
	return claims
}

func signedBrokerAccessToken(t *testing.T, service *Server, issuer, audience string, expiry time.Time) string {
	t.Helper()
	claims := zitoidc.NewAccessTokenClaims(issuer, "gb_sub_test", []string{audience}, expiry, "test-jti", "graphit-cli", 0)
	claims.Scopes = zitoidc.SpaceDelimitedArray{localAPIScope}
	signer, err := op.SignerFromKey(service.oidcProvider.storage.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := zitcrypto.Sign(claims, signer)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func tamperJWT(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[2] == "" {
		return raw + "invalid"
	}
	first := parts[2][0]
	replacement := byte('A')
	if first == replacement {
		replacement = 'B'
	}
	parts[2] = string(replacement) + parts[2][1:]
	return strings.Join(parts, ".")
}

func TestOAuthOIDCStartURLPreservesRequestID(t *testing.T) {
	requestID := "request with spaces & symbols/=?"
	service := &Server{}
	service.state.Store(&runtimeState{browserOIDC: []browserOIDCProvider{{ID: "corporate", Name: "Corporate SSO"}}})
	data := service.oauthLoginPageData(requestID, localLoginPageData{})
	if len(data.OIDCProviders) != 1 || data.OIDCProviders[0].Name != "Corporate SSO" {
		t.Fatalf("OIDC options=%#v", data.OIDCProviders)
	}
	location, err := url.Parse(data.OIDCProviders[0].StartURL)
	if err != nil || location.Path != oidcLoginPath || location.Query().Get("id") != requestID || location.Query().Get("login_method") != "oidc" || location.Query().Get("provider") != "corporate" {
		t.Fatalf("OIDC start URL=%q err=%v", location, err)
	}
	service.state.Store(&runtimeState{})
	if disabled := service.oauthLoginPageData(requestID, localLoginPageData{}); disabled.OIDC || len(disabled.OIDCProviders) != 0 {
		t.Fatalf("disabled OIDC options=%#v", disabled.OIDCProviders)
	}
}

func TestOAuthLoginInvalidRequestRendersStyledBrowserError(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/oauth/login?id=xpto")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") || response.Header.Get("X-Frame-Options") != "DENY" ||
		!bytes.Contains(body, []byte(`data-ui="graphit-auth"`)) || !bytes.Contains(body, []byte(`class="alert" role="alert"`)) ||
		!bytes.Contains(body, []byte("authorization request is invalid or has expired")) || !bytes.Contains(body, []byte("Authorization cannot continue")) ||
		bytes.Contains(body, []byte(`name="username"`)) || bytes.Contains(body, []byte(`"error":"invalid_request"`)) {
		t.Fatalf("invalid OAuth login status=%d content-type=%q body=%s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
}

func absoluteTestURL(base, target string) string {
	if strings.HasPrefix(target, "/") {
		return base + target
	}
	return target
}

func TestDeviceAuthorizationRequiresApprovalAndIsOneTime(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	response := oauthForm(t, httpServer.URL+"/oauth/device/authorize", url.Values{"client_id": {"graphit-cli"}, "scope": {localAPIScope}})
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&device) != nil {
		t.Fatalf("device authorization status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
	verification, err := http.Get(httpServer.URL + "/oauth/device?user_code=" + url.QueryEscape(device.UserCode))
	if err != nil {
		t.Fatal(err)
	}
	verificationBody, _ := io.ReadAll(verification.Body)
	_ = verification.Body.Close()
	if verification.StatusCode != http.StatusOK || !strings.HasPrefix(verification.Header.Get("Content-Type"), "text/html") ||
		!bytes.Contains(verificationBody, []byte(`data-ui="graphit-auth"`)) || !bytes.Contains(verificationBody, []byte(`class="auth-shell"`)) ||
		!bytes.Contains(verificationBody, []byte(`name="user_code"`)) || !bytes.Contains(verificationBody, []byte(device.UserCode)) ||
		!bytes.Contains(verificationBody, []byte(`name="username"`)) || !bytes.Contains(verificationBody, []byte(`name="password"`)) {
		t.Fatalf("device verification status=%d content-type=%q body=%s", verification.StatusCode, verification.Header.Get("Content-Type"), verificationBody)
	}
	pending := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{"grant_type": {deviceGrantType}, "client_id": {"graphit-cli"}, "device_code": {device.DeviceCode}})
	pendingBody, _ := io.ReadAll(pending.Body)
	_ = pending.Body.Close()
	if pending.StatusCode != http.StatusBadRequest || !strings.Contains(string(pendingBody), "authorization_pending") {
		t.Fatalf("pending device status=%d body=%s", pending.StatusCode, pendingBody)
	}
	slowDown := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{"grant_type": {deviceGrantType}, "client_id": {"graphit-cli"}, "device_code": {device.DeviceCode}})
	slowDownBody, _ := io.ReadAll(slowDown.Body)
	_ = slowDown.Body.Close()
	if slowDown.StatusCode != http.StatusBadRequest || !strings.Contains(string(slowDownBody), "slow_down") {
		t.Fatalf("fast device poll status=%d body=%s", slowDown.StatusCode, slowDownBody)
	}
	approved := oauthForm(t, httpServer.URL+"/oauth/device", url.Values{"user_code": {device.UserCode}, "username": {"consumer"}, "password": {"consumer-secret"}})
	if approved.StatusCode != http.StatusOK {
		t.Fatalf("device approval status=%d", approved.StatusCode)
	}
	_ = approved.Body.Close()
	_, _ = service.control.db.Exec(`UPDATE oauth_device_codes SET last_poll_at=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	issued := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{"grant_type": {deviceGrantType}, "client_id": {"graphit-cli"}, "device_code": {device.DeviceCode}})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if issued.StatusCode != http.StatusOK || json.NewDecoder(issued.Body).Decode(&token) != nil || token.AccessToken == "" {
		t.Fatalf("approved device token status=%d", issued.StatusCode)
	}
	_ = issued.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", token.AccessToken, http.StatusOK)
	replay := oauthForm(t, httpServer.URL+"/oauth/token", url.Values{"grant_type": {deviceGrantType}, "client_id": {"graphit-cli"}, "device_code": {device.DeviceCode}})
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("device code replay status=%d", replay.StatusCode)
	}
	_ = replay.Body.Close()
}

func TestOAuthAndDeviceDoNotCompleteBeforeRequiredMFA(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	required := true
	service.runtime().localAuth.config.Required = &required

	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	redirectURI := "http://127.0.0.1:49152/oauth/callback"
	query := url.Values{"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {redirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"mfa-state"}, "nonce": {"mfa-nonce"}, "scope": {"openid profile " + localAPIScope}}
	client := noRedirectClient()
	loginURL := startOIDCLogin(t, client, httpServer.URL, query)
	started := oauthFormWithClient(t, client, loginURL, url.Values{"username": {"consumer"}, "password": {"consumer-secret"}})
	startedBody, _ := io.ReadAll(started.Body)
	_ = started.Body.Close()
	if started.StatusCode != http.StatusOK {
		t.Fatalf("MFA enrollment start status=%d body=%s", started.StatusCode, startedBody)
	}
	var codeCount int
	if err := service.control.db.QueryRow(`SELECT COUNT(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL`).Scan(&codeCount); err != nil || codeCount != 0 {
		t.Fatalf("authorization code existed before MFA count=%d err=%v", codeCount, err)
	}
	tokenMatch := regexp.MustCompile(`name="challenge_token" value="([^"]+)"`).FindSubmatch(startedBody)
	secretMatch := regexp.MustCompile(`Manual key: <code>([^<]+)</code>`).FindSubmatch(startedBody)
	if len(tokenMatch) != 2 || len(secretMatch) != 2 {
		t.Fatalf("enrollment fields missing from page: %s", startedBody)
	}
	totpCode, err := totp.GenerateCode(string(secretMatch[1]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirmed := oauthFormWithClient(t, client, loginURL, url.Values{"challenge_token": {string(tokenMatch[1])}, "code": {totpCode}})
	confirmedBody, _ := io.ReadAll(confirmed.Body)
	_ = confirmed.Body.Close()
	if confirmed.StatusCode != http.StatusOK {
		t.Fatalf("MFA authorization completion status=%d body=%s", confirmed.StatusCode, confirmedBody)
	}
	if err := service.control.db.QueryRow(`SELECT COUNT(*) FROM oidc_auth_requests WHERE request_json LIKE '%"done":true%'`).Scan(&codeCount); err != nil || codeCount != 1 {
		t.Fatalf("completed authorization after MFA count=%d err=%v", codeCount, err)
	}
	recoveryMatch := regexp.MustCompile(`<li><code>([^<]+)</code></li>`).FindSubmatch(confirmedBody)
	if len(recoveryMatch) != 2 {
		t.Fatalf("recovery code missing after enrollment: %s", confirmedBody)
	}

	deviceResponse := oauthForm(t, httpServer.URL+"/oauth/device/authorize", url.Values{"client_id": {"graphit-cli"}, "scope": {localAPIScope}})
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if deviceResponse.StatusCode != http.StatusOK || json.NewDecoder(deviceResponse.Body).Decode(&device) != nil {
		t.Fatalf("device authorization status=%d", deviceResponse.StatusCode)
	}
	_ = deviceResponse.Body.Close()
	deviceStarted := oauthForm(t, httpServer.URL+"/oauth/device", url.Values{"user_code": {device.UserCode}, "username": {"consumer"}, "password": {"consumer-secret"}})
	deviceStartedBody, _ := io.ReadAll(deviceStarted.Body)
	_ = deviceStarted.Body.Close()
	deviceChallenge := regexp.MustCompile(`name="challenge_token" value="([^"]+)"`).FindSubmatch(deviceStartedBody)
	var deviceStatus string
	if err := service.control.db.QueryRow(`SELECT status FROM oauth_device_codes`).Scan(&deviceStatus); err != nil || deviceStatus != deviceStatusPending || len(deviceChallenge) != 2 {
		t.Fatalf("device before MFA status=%q challenge=%q err=%v", deviceStatus, deviceChallenge, err)
	}
	deviceComplete := oauthForm(t, httpServer.URL+"/oauth/device", url.Values{"user_code": {device.UserCode}, "challenge_token": {string(deviceChallenge[1])}, "code": {string(recoveryMatch[1])}})
	_ = deviceComplete.Body.Close()
	if deviceComplete.StatusCode != http.StatusOK {
		t.Fatalf("device MFA completion status=%d", deviceComplete.StatusCode)
	}
	if err := service.control.db.QueryRow(`SELECT status FROM oauth_device_codes`).Scan(&deviceStatus); err != nil || deviceStatus != deviceStatusApproved {
		t.Fatalf("device after MFA status=%q err=%v", deviceStatus, err)
	}
}

func TestOAuthLocalLoginRendersAndAcceptsBothAdaptiveCaptchaProviders(t *testing.T) {
	for _, provider := range []string{localCaptchaProviderTurnstile, localCaptchaProviderRecaptcha} {
		t.Run(provider, func(t *testing.T) {
			service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
			defer service.Close()
			defer httpServer.Close()
			state := service.runtime()
			state.config.Authentication.Local.Captcha = LocalCaptchaConfig{Enabled: true, Provider: provider, SiteKey: "site-key", SecretKey: "secret-key", TriggerMultiplier: 1.5, VerificationTimeout: time.Second}
			state.localPasswords.captcha = &stubLocalCaptchaVerifier{provider: provider, valid: "valid-proof"}
			state.localPasswords.captchaThreshold = 1

			verifier := strings.Repeat("v", 64)
			digest := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(digest[:])
			redirectURI := "http://127.0.0.1:49152/oauth/callback"
			query := url.Values{"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {redirectURI},
				"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"captcha-state"}, "nonce": {"captcha-nonce"}, "scope": {"openid " + localAPIScope}}
			client := noRedirectClient()
			loginURL := startOIDCLogin(t, client, httpServer.URL, query)

			page, err := client.Get(loginURL)
			if err != nil {
				t.Fatal(err)
			}
			pageBody, _ := io.ReadAll(page.Body)
			_ = page.Body.Close()
			expectedClass, expectedCSP := "cf-turnstile", "https://challenges.cloudflare.com"
			if provider == localCaptchaProviderRecaptcha {
				expectedClass, expectedCSP = "g-recaptcha", "https://www.google.com/recaptcha/"
			}
			if page.StatusCode != http.StatusOK || !bytes.Contains(pageBody, []byte(expectedClass)) || !bytes.Contains(pageBody, []byte("site-key")) || !strings.Contains(page.Header.Get("Content-Security-Policy"), expectedCSP) {
				t.Fatalf("%s CAPTCHA page status=%d CSP=%q body=%s", provider, page.StatusCode, page.Header.Get("Content-Security-Policy"), pageBody)
			}

			missing := oauthFormWithClient(t, client, loginURL, url.Values{"username": {"consumer"}, "password": {"consumer-secret"}})
			missingBody, _ := io.ReadAll(missing.Body)
			_ = missing.Body.Close()
			if missing.StatusCode != http.StatusForbidden || !bytes.Contains(missingBody, []byte(expectedClass)) || bytes.Contains(missingBody, []byte("consumer-secret")) {
				t.Fatalf("%s missing CAPTCHA status=%d body=%s", provider, missing.StatusCode, missingBody)
			}

			field := "cf-turnstile-response"
			if provider == localCaptchaProviderRecaptcha {
				field = "g-recaptcha-response"
			}
			valid := oauthFormWithClient(t, client, loginURL, url.Values{
				"username": {"consumer"}, "password": {"consumer-secret"}, field: {"valid-proof"},
			})
			_ = valid.Body.Close()
			if valid.StatusCode != http.StatusFound {
				t.Fatalf("%s valid CAPTCHA authorization status=%d", provider, valid.StatusCode)
			}
		})
	}
}

func TestDeviceLocalLoginUsesDeviceCaptchaAction(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	state := service.runtime()
	state.config.Authentication.Local.Captcha = LocalCaptchaConfig{Enabled: true, Provider: localCaptchaProviderTurnstile, SiteKey: "site-key", SecretKey: "secret-key", TriggerMultiplier: 1.5, VerificationTimeout: time.Second}
	state.localPasswords.captcha = &stubLocalCaptchaVerifier{provider: localCaptchaProviderTurnstile, valid: "valid-proof"}
	state.localPasswords.captchaThreshold = 1

	deviceResponse := oauthForm(t, httpServer.URL+"/oauth/device/authorize", url.Values{"client_id": {"graphit-cli"}, "scope": {localAPIScope}})
	var device struct {
		UserCode string `json:"user_code"`
	}
	if deviceResponse.StatusCode != http.StatusOK || json.NewDecoder(deviceResponse.Body).Decode(&device) != nil {
		t.Fatalf("device authorization status=%d", deviceResponse.StatusCode)
	}
	_ = deviceResponse.Body.Close()

	missing := oauthForm(t, httpServer.URL+"/oauth/device", url.Values{"user_code": {device.UserCode}, "username": {"consumer"}, "password": {"consumer-secret"}})
	body, _ := io.ReadAll(missing.Body)
	_ = missing.Body.Close()
	if missing.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte(`data-action="device-login"`)) {
		t.Fatalf("device CAPTCHA status=%d body=%s", missing.StatusCode, body)
	}
	valid := oauthForm(t, httpServer.URL+"/oauth/device", url.Values{"user_code": {device.UserCode}, "username": {"consumer"}, "password": {"consumer-secret"}, "cf-turnstile-response": {"valid-proof"}})
	defer valid.Body.Close()
	if valid.StatusCode != http.StatusOK {
		t.Fatalf("valid device CAPTCHA status=%d", valid.StatusCode)
	}
}

func TestServiceCredentialIsShownOnceRevocableAndRevisionBound(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

	created := bearerRequest(t, http.MethodPost, httpServer.URL+"/admin/api/v1/local-users", "root-token", `{"username":"buildbot","subject":"service-buildbot","kind":"service","name":"Build Bot","roles":[],"enabled":true}`)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("service identity create status=%d", created.StatusCode)
	}
	_ = created.Body.Close()
	credential := bearerRequest(t, http.MethodPost, httpServer.URL+"/admin/api/v1/local-users/buildbot/credentials", "root-token", `{}`)
	var issued struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if credential.StatusCode != http.StatusCreated || json.NewDecoder(credential.Body).Decode(&issued) != nil {
		t.Fatalf("service credential create status=%d", credential.StatusCode)
	}
	_ = credential.Body.Close()
	if !strings.HasPrefix(issued.Token, serviceCredentialPrefix) || issued.ID == "" {
		t.Fatalf("service credential response=%#v", issued)
	}
	listed := bearerRequest(t, http.MethodGet, httpServer.URL+"/admin/api/v1/local-users/buildbot/credentials", "root-token", "")
	listedBody, _ := io.ReadAll(listed.Body)
	_ = listed.Body.Close()
	if listed.StatusCode != http.StatusOK || strings.Contains(string(listedBody), issued.Token) {
		t.Fatalf("service credential list status=%d body=%s", listed.StatusCode, listedBody)
	}
	var rawPersisted int
	if err := service.control.db.QueryRow(`SELECT COUNT(*) FROM local_tokens WHERE token_hash=? OR token_id=?`, issued.Token, issued.Token).Scan(&rawPersisted); err != nil || rawPersisted != 0 {
		t.Fatalf("raw service credential persisted count=%d err=%v", rawPersisted, err)
	}
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", issued.Token, http.StatusOK)

	revoked := bearerRequest(t, http.MethodDelete, httpServer.URL+"/admin/api/v1/local-users/buildbot/credentials/"+url.PathEscape(issued.ID), "root-token", "")
	if revoked.StatusCode != http.StatusNoContent {
		t.Fatalf("service credential revoke status=%d", revoked.StatusCode)
	}
	_ = revoked.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", issued.Token, http.StatusUnauthorized)

	secondResponse := bearerRequest(t, http.MethodPost, httpServer.URL+"/admin/api/v1/local-users/buildbot/credentials", "root-token", `{}`)
	var second struct {
		Token string `json:"token"`
	}
	if secondResponse.StatusCode != http.StatusCreated || json.NewDecoder(secondResponse.Body).Decode(&second) != nil {
		t.Fatalf("second service credential status=%d", secondResponse.StatusCode)
	}
	_ = secondResponse.Body.Close()
	updated := bearerRequest(t, http.MethodPut, httpServer.URL+"/admin/api/v1/local-users/buildbot", "root-token", `{"username":"buildbot","subject":"service-buildbot","kind":"service","name":"Updated Build Bot","roles":[],"enabled":true}`)
	if updated.StatusCode != http.StatusNoContent {
		t.Fatalf("service identity update status=%d", updated.StatusCode)
	}
	_ = updated.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", second.Token, http.StatusUnauthorized)

	expiringResponse := bearerRequest(t, http.MethodPost, httpServer.URL+"/admin/api/v1/local-users/buildbot/credentials", "root-token", `{}`)
	var expiring struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if expiringResponse.StatusCode != http.StatusCreated || json.NewDecoder(expiringResponse.Body).Decode(&expiring) != nil {
		t.Fatalf("expiring service credential status=%d", expiringResponse.StatusCode)
	}
	_ = expiringResponse.Body.Close()
	if _, err := service.control.db.Exec(`UPDATE local_tokens SET expires_at=? WHERE token_id=?`, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), expiring.ID); err != nil {
		t.Fatal(err)
	}
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", expiring.Token, http.StatusUnauthorized)
}

func TestLocalAuthorizationRejectsNonLoopbackOrInvalidPort(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	for _, redirectURI := range []string{"http://127.0.0.1:0/oauth/callback", "http://127.0.0.1:49152/other", "https://example.com/oauth/callback"} {
		query := url.Values{"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {redirectURI},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"client-state"}, "nonce": {"client-nonce"}, "scope": {"openid " + localAPIScope}}
		response, err := noRedirectClient().Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("redirect %q status=%d", redirectURI, response.StatusCode)
		}
	}
}

func startOIDCLogin(t *testing.T, client *http.Client, baseURL string, query url.Values) string {
	t.Helper()
	response, err := client.Get(baseURL + "/oauth/authorize?" + query.Encode())
	if err != nil || response.StatusCode != http.StatusFound {
		t.Fatalf("OpenID authorization start status=%s err=%v", statusText(response), err)
	}
	target := absoluteTestURL(baseURL, html.UnescapeString(response.Header.Get("Location")))
	_ = response.Body.Close()
	return target
}

func TestLocalAccessTokenEnforcesAudienceScopeExpiryAndUserRevision(t *testing.T) {
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateLocalUser(context.Background(), LocalUser{Username: "alice", Subject: "alice-subject", Kind: humanIdentityKind, PasswordHash: mustPasswordHash(t, "alice-password!"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	user, _ := store.LocalUserByUsername(context.Background(), "alice")
	grant := LocalTokenGrant{Subject: user.Subject, LocalUserRevision: user.Revision, ClientID: "graphit-cli", Audience: "graphit-broker",
		Scopes: []string{localAPIScope}, FamilyID: "family-a", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.SaveTokenPair(context.Background(), localAccessTokenPrefix+"valid", "token-a", "", "", grant); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateLocalToken(context.Background(), localAccessTokenPrefix+"valid", "wrong-audience", []string{localAPIScope}); err == nil {
		t.Fatal("local access token accepted for the wrong audience")
	}
	if _, err := store.AuthenticateLocalToken(context.Background(), localAccessTokenPrefix+"valid", "graphit-broker", []string{"missing.scope"}); err == nil {
		t.Fatal("local access token accepted without a required scope")
	}
	if _, err := store.AuthenticateLocalToken(context.Background(), localAccessTokenPrefix+"valid", "graphit-broker", []string{localAPIScope}); err != nil {
		t.Fatalf("valid local access token failed: %v", err)
	}
	user.Name = "Updated"
	if err := store.UpdateLocalUser(context.Background(), "alice", user); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateLocalToken(context.Background(), localAccessTokenPrefix+"valid", "graphit-broker", []string{localAPIScope}); err == nil {
		t.Fatal("local access token survived an identity revision change")
	}
	expired := grant
	expired.LocalUserRevision++
	expired.ExpiresAt = time.Now().Add(-time.Second)
	if err := store.SaveTokenPair(context.Background(), localAccessTokenPrefix+"expired", "token-expired", "", "", expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateLocalToken(context.Background(), localAccessTokenPrefix+"expired", "graphit-broker", []string{localAPIScope}); err == nil {
		t.Fatal("expired local access token authenticated")
	}
}

func authorizeLocalCLI(t *testing.T, baseURL, redirectURI, challenge, scope string) string {
	t.Helper()
	if !strings.Contains(scope, "openid") {
		scope = "openid profile email " + scope
	}
	query := url.Values{"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {redirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"client-state"}, "nonce": {"client-nonce"}, "scope": {scope}}
	client := noRedirectClient()
	start, err := client.Get(baseURL + "/oauth/authorize?" + query.Encode())
	if err != nil || start.StatusCode != http.StatusFound {
		t.Fatalf("authorization start status=%s err=%v", statusText(start), err)
	}
	loginURL := start.Header.Get("Location")
	_ = start.Body.Close()
	if strings.HasPrefix(loginURL, "/") {
		loginURL = baseURL + loginURL
	}
	request, _ := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(url.Values{"username": {"consumer"}, "password": {"consumer-secret"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusFound {
		t.Fatalf("authorization status=%s err=%v", statusText(response), err)
	}
	callbackURL := response.Header.Get("Location")
	_ = response.Body.Close()
	if strings.HasPrefix(callbackURL, "/") {
		callbackURL = baseURL + callbackURL
	}
	response, err = client.Get(callbackURL)
	if err != nil || response.StatusCode != http.StatusFound {
		t.Fatalf("authorization callback status=%s err=%v", statusText(response), err)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	_ = response.Body.Close()
	if err != nil || location.Query().Get("state") != "client-state" || location.Query().Get("code") == "" {
		t.Fatalf("authorization redirect=%q err=%v", location, err)
	}
	return location.Query().Get("code")
}

func oauthForm(t *testing.T, endpoint string, values url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func oauthFormWithClient(t *testing.T, client *http.Client, endpoint string, values url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertBearerStatus(t *testing.T, endpoint, token string, expected int) {
	t.Helper()
	response := bearerRequest(t, http.MethodGet, endpoint, token, "")
	defer response.Body.Close()
	if response.StatusCode != expected {
		t.Fatalf("bearer status=%d expected=%d", response.StatusCode, expected)
	}
}
