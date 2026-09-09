package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
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
			claims := map[string]any{"iss": issuer, "sub": "provider-subject", "identity": map[string]any{"id": "admin-subject"}, "aud": "admin-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "nonce": nonce,
				"profile": map[string]any{"display_name": "Admin", "email": "admin@example.test"}, "realm_access": map[string]any{"roles": []string{"admin", "auditor"}}}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": signJWT(t, key, claims)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	provider, err := NewAdminIdentityProvider(ctx, OIDCIssuerConfig{Issuer: issuer, ClientID: "admin-client", ClientSecret: "client-secret", RedirectURL: "http://localhost/oauth/oidc/callback",
		SubjectClaim: "$.identity.id", NameClaim: "$.profile.display_name", EmailClaim: "$.profile.email", UsernameClaim: "$.profile.email", RoleClaim: "$.realm_access.roles[*]"})
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
}
