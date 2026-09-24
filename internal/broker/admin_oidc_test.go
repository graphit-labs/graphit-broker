package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestAdminIdentityProviderUsesConfidentialCodeFlowAndVerifiesIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nonce := "expected-nonce"
	secretObserved := false
	includeNonce := true
	accessOpaque := false
	omitAccessToken := false
	accessSubject := "provider-subject"
	userinfoSubject := "provider-subject"
	userinfoStatus := http.StatusOK
	includeUserinfoEndpoint := true
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			metadata := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"}
			if includeUserinfoEndpoint {
				metadata["userinfo_endpoint"] = issuer + "/userinfo"
			}
			_ = json.NewEncoder(w).Encode(metadata)
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&key.PublicKey, "test")}})
		case "/token":
			_ = r.ParseForm()
			clientID, clientSecret, basic := r.BasicAuth()
			if !basic {
				clientID, clientSecret = r.Form.Get("client_id"), r.Form.Get("client_secret")
			}
			secretObserved = clientID == "admin-client" && clientSecret == "client-secret"
			if r.Form.Get("code") != "valid-code" || r.Form.Get("code_verifier") != "pkce-verifier" || !secretObserved {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusUnauthorized)
				return
			}
			claims := map[string]any{"iss": issuer, "sub": "provider-subject", "identity": map[string]any{"id": "admin-subject"}, "aud": "admin-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
				"profile": map[string]any{"display_name": "Admin", "email": "admin@example.test"}, "realm_access": map[string]any{"roles": []string{"admin", "auditor"}}}
			if includeNonce {
				claims["nonce"] = nonce
			}
			accessClaims := map[string]any{"iss": issuer, "sub": accessSubject, "aud": "resource-api", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
				"identity": map[string]any{"id": "access-subject"}, "profile": map[string]any{"display_name": "Access Admin", "email": "access@example.test"}, "realm_access": map[string]any{"roles": []string{"admin"}}}
			accessToken := signJWT(t, key, accessClaims)
			if accessOpaque {
				accessToken = "opaque-access"
			}
			if omitAccessToken {
				accessToken = ""
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600, "id_token": signJWT(t, key, claims)})
		case "/userinfo":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(userinfoStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": userinfoSubject, "identity": map[string]any{"id": "userinfo-subject"},
				"profile": map[string]any{"display_name": "Userinfo Admin", "email": "userinfo@example.test"}, "realm_access": map[string]any{"roles": []string{"auditor"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	providerConfig := OIDCIssuerConfig{Issuer: issuer, ClientID: "admin-client", ClientSecret: "client-secret", RedirectURL: "http://localhost/oauth/oidc/callback",
		SubjectClaim: "$.identity.id", NameClaim: "$.profile.display_name", EmailClaim: "$.profile.email", UsernameClaim: "$.profile.email", RoleClaim: "$.realm_access.roles[*]"}
	provider, err := NewAdminIdentityProvider(ctx, providerConfig)
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, _ := url.Parse(provider.AuthorizationURL("state", nonce, "pkce-verifier"))
	if authorizationURL.Query().Get("state") != "state" || authorizationURL.Query().Get("nonce") != nonce || authorizationURL.Query().Get("code_challenge") == "" || authorizationURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL=%s", authorizationURL)
	}
	identity, err := provider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !secretObserved || identity.Subject != "admin-subject" || identity.Name != "Admin" || identity.Email != "admin@example.test" || !identity.RolesFromClaim || len(identity.Roles) != 3 || identity.Roles[0] != "admin" || identity.Roles[2] != userRole {
		t.Fatalf("secretObserved=%v identity=%#v", secretObserved, identity)
	}
	if _, err := provider.Exchange(context.Background(), "valid-code", "pkce-verifier", "wrong-nonce"); err == nil {
		t.Fatal("ID token with the wrong nonce was accepted")
	}
	includeNonce = false
	if _, err := provider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err == nil {
		t.Fatal("ID token without the required nonce was accepted")
	}
	requireNonce := false
	providerConfig.RequireNonce = &requireNonce
	providerWithoutNonce, err := NewAdminIdentityProvider(ctx, providerConfig)
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, _ = url.Parse(providerWithoutNonce.AuthorizationURL("state", nonce, "pkce-verifier"))
	if authorizationURL.Query().Has("nonce") || authorizationURL.Query().Get("state") != "state" || authorizationURL.Query().Get("code_challenge") == "" || authorizationURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL without nonce=%s", authorizationURL)
	}
	if _, err := providerWithoutNonce.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err != nil {
		t.Fatalf("ID token without optional nonce was rejected: %v", err)
	}
	includeNonce = true
	if _, err := providerWithoutNonce.Exchange(context.Background(), "valid-code", "pkce-verifier", "different-nonce"); err != nil {
		t.Fatalf("optional nonce was compared: %v", err)
	}
	providerConfig.RequireNonce = nil
	providerConfig.ClaimsSource = "access_token"
	accessProvider, err := NewAdminIdentityProvider(ctx, providerConfig)
	if err != nil {
		t.Fatal(err)
	}
	identity, err = accessProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce)
	if err != nil || identity.Subject != "access-subject" || identity.Name != "Access Admin" || !slices.Contains(identity.Roles, "admin") {
		t.Fatalf("access token identity=%#v err=%v", identity, err)
	}
	if _, err := accessProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", "wrong-nonce"); err == nil {
		t.Fatal("access token claim mode bypassed the ID token nonce")
	}
	accessSubject = "different-subject"
	if _, err := accessProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err == nil {
		t.Fatal("access token with mismatched subject was accepted")
	}
	accessSubject = "provider-subject"
	accessOpaque = true
	if _, err := accessProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err == nil {
		t.Fatal("opaque access token was accepted for access_token claims")
	}
	accessOpaque = false
	providerConfig.ClaimsSource = "userinfo"
	userinfoProvider, err := NewAdminIdentityProvider(ctx, providerConfig)
	if err != nil {
		t.Fatal(err)
	}
	identity, err = userinfoProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce)
	if err != nil || identity.Subject != "userinfo-subject" || identity.Name != "Userinfo Admin" || !slices.Contains(identity.Roles, "auditor") {
		t.Fatalf("userinfo identity=%#v err=%v", identity, err)
	}
	if _, err := userinfoProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", "wrong-nonce"); err == nil {
		t.Fatal("userinfo claim mode bypassed the ID token nonce")
	}
	omitAccessToken = true
	if _, err := userinfoProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err == nil {
		t.Fatal("userinfo without access token was accepted")
	}
	omitAccessToken = false
	userinfoSubject = "different-subject"
	if _, err := userinfoProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err == nil {
		t.Fatal("userinfo with mismatched subject was accepted")
	}
	userinfoSubject = "provider-subject"
	userinfoStatus = http.StatusBadGateway
	if _, err := userinfoProvider.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err == nil {
		t.Fatal("failed userinfo request was accepted")
	}
	userinfoStatus = http.StatusOK
	includeUserinfoEndpoint = false
	providerWithoutUserinfo, err := NewAdminIdentityProvider(ctx, providerConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := providerWithoutUserinfo.Exchange(context.Background(), "valid-code", "pkce-verifier", nonce); err == nil {
		t.Fatal("missing userinfo endpoint was accepted")
	}
}
