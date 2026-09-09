package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestLocalAuthorizationCodeRequiresPKCEAndRotatesRefreshTokens(t *testing.T) {
	service, httpServer, _ := newAdminTestServer(t, "http://127.0.0.1:1")
	defer service.Close()
	defer httpServer.Close()

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
	}
	if tokenResponse.StatusCode != http.StatusOK || json.NewDecoder(tokenResponse.Body).Decode(&tokens) != nil {
		t.Fatalf("token exchange status=%d", tokenResponse.StatusCode)
	}
	_ = tokenResponse.Body.Close()
	if !strings.HasPrefix(tokens.AccessToken, localAccessTokenPrefix) || !strings.HasPrefix(tokens.RefreshToken, localRefreshTokenPrefix) {
		t.Fatalf("issued tokens=%#v", tokens)
	}
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
	revoked := oauthForm(t, httpServer.URL+"/oauth/revoke", url.Values{"token": {revocable.AccessToken}})
	if revoked.StatusCode != http.StatusOK {
		t.Fatalf("revocation status=%d", revoked.StatusCode)
	}
	_ = revoked.Body.Close()
	assertBearerStatus(t, httpServer.URL+"/admin/api/v1/session", revocable.AccessToken, http.StatusUnauthorized)

	var rawPersisted int
	if err := service.control.db.QueryRow(`SELECT COUNT(*) FROM local_tokens WHERE token_hash=? OR token_id=?`, tokens.AccessToken, tokens.AccessToken).Scan(&rawPersisted); err != nil || rawPersisted != 0 {
		t.Fatalf("raw token persisted count=%d err=%v", rawPersisted, err)
	}
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
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"mfa-state"}, "scope": {localAPIScope}}
	authorizeURL := httpServer.URL + "/oauth/authorize?" + query.Encode()
	started := oauthForm(t, authorizeURL, url.Values{"username": {"consumer"}, "password": {"consumer-secret"}})
	startedBody, _ := io.ReadAll(started.Body)
	_ = started.Body.Close()
	if started.StatusCode != http.StatusOK {
		t.Fatalf("MFA enrollment start status=%d body=%s", started.StatusCode, startedBody)
	}
	var codeCount int
	if err := service.control.db.QueryRow(`SELECT COUNT(*) FROM oauth_authorization_codes`).Scan(&codeCount); err != nil || codeCount != 0 {
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
	confirmed := oauthForm(t, authorizeURL, url.Values{"challenge_token": {string(tokenMatch[1])}, "code": {totpCode}})
	confirmedBody, _ := io.ReadAll(confirmed.Body)
	_ = confirmed.Body.Close()
	if confirmed.StatusCode != http.StatusOK {
		t.Fatalf("MFA authorization completion status=%d body=%s", confirmed.StatusCode, confirmedBody)
	}
	if err := service.control.db.QueryRow(`SELECT COUNT(*) FROM oauth_authorization_codes`).Scan(&codeCount); err != nil || codeCount != 1 {
		t.Fatalf("authorization code after MFA count=%d err=%v", codeCount, err)
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
	for _, redirectURI := range []string{"https://127.0.0.1:49152/oauth/callback", "http://localhost:49152/oauth/callback", "http://127.0.0.1:0/oauth/callback", "http://127.0.0.1:49152/other"} {
		query := url.Values{"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {redirectURI},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"client-state"}, "scope": {localAPIScope}}
		response, err := http.Get(httpServer.URL + "/oauth/authorize?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("redirect %q status=%d", redirectURI, response.StatusCode)
		}
	}
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
	query := url.Values{"response_type": {"code"}, "client_id": {"graphit-cli"}, "redirect_uri": {redirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"client-state"}, "scope": {scope}}
	request, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/authorize?"+query.Encode(), strings.NewReader(url.Values{"username": {"consumer"}, "password": {"consumer-secret"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := noRedirectClient().Do(request)
	if err != nil || response.StatusCode != http.StatusFound {
		t.Fatalf("authorization status=%s err=%v", statusText(response), err)
	}
	_ = response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || location.Query().Get("state") != "client-state" || location.Query().Get("code") == "" {
		t.Fatalf("authorization redirect=%q err=%v", response.Header.Get("Location"), err)
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

func assertBearerStatus(t *testing.T, endpoint, token string, expected int) {
	t.Helper()
	response := bearerRequest(t, http.MethodGet, endpoint, token, "")
	defer response.Body.Close()
	if response.StatusCode != expected {
		t.Fatalf("bearer status=%d expected=%d", response.StatusCode, expected)
	}
}
