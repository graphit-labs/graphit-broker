package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthenticatorValidatesOIDCSignatureAudienceExpiryScopesAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(&key.PublicKey, "test")}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	cfg := AuthenticationConfig{OIDC: []OIDCIssuerConfig{{Issuer: issuer, Audiences: []string{"graphit-broker"}, RequiredScopes: []string{"graphit.use"}, UsernameClaim: "$.profile.username", OrganizationClaim: "$.organization.id", TeamsClaim: "$.groups[*]"}}}
	authenticator, err := newAuthenticator(context.Background(), cfg, true, server.Client())
	if err != nil {
		t.Fatalf("newAuthenticator: %v", err)
	}
	base := map[string]any{"iss": issuer, "sub": "subject-1", "aud": []string{"other", "graphit-broker"}, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "scope": "openid graphit.use", "profile": map[string]any{"username": "alice"}, "organization": map[string]any{"id": "acme"}, "groups": []string{"platform", "security"}}
	token := signJWT(t, key, base)
	principal, err := authenticator.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Username != "alice" || principal.Organization != "acme" || len(principal.Teams) != 2 {
		t.Fatalf("principal = %#v", principal)
	}

	invalidCases := map[string]func(map[string]any){
		"issuer":   func(c map[string]any) { c["iss"] = "https://wrong.example" },
		"audience": func(c map[string]any) { c["aud"] = "wrong" },
		"expired":  func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"scope":    func(c map[string]any) { c["scope"] = "openid" },
		"username": func(c map[string]any) { delete(c, "profile") },
	}
	for name, mutate := range invalidCases {
		t.Run(name, func(t *testing.T) {
			claims := cloneClaims(base)
			mutate(claims)
			if _, err := authenticator.Authenticate(context.Background(), signJWT(t, key, claims)); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := authenticator.Authenticate(context.Background(), signJWT(t, otherKey, base)); err == nil {
		t.Fatal("invalid signature accepted")
	}
}

func TestTokenScopesAndClaimSelectorsSupportCommonIdPShapes(t *testing.T) {
	claims := map[string]any{
		"scp":                              "graphit.use profile",
		"organization":                     map[string]any{"id": "acme"},
		"https://claims.example.com/teams": []any{"platform"},
		"realm_access":                     map[string]any{"roles": []any{"user", "auditor"}},
		"accounts":                         []any{map[string]any{"primary": true, "name": "alice"}, map[string]any{"primary": false, "name": "bob"}},
	}
	if scopes := tokenScopes(claims); !containsString(scopes, "graphit.use") {
		t.Fatalf("scopes=%v", scopes)
	}
	if value, ok := claimValue(claims, "organization.id"); !ok || value != "acme" {
		t.Fatalf("nested claim=%v ok=%v", value, ok)
	}
	if value, ok := claimValue(claims, "https://claims.example.com/teams"); !ok || value == nil {
		t.Fatalf("namespaced claim=%v ok=%v", value, ok)
	}
	roles, err := claimStrings(claims, "$.realm_access.roles[*]")
	if err != nil || len(roles) != 2 || roles[0] != "auditor" || roles[1] != "user" {
		t.Fatalf("JSONPath roles=%v err=%v", roles, err)
	}
	username, err := claimString(claims, "$.accounts[?@.primary == true].name", true)
	if err != nil || username != "alice" {
		t.Fatalf("filtered JSONPath username=%q err=%v", username, err)
	}
	claims["organization.id"] = "literal-acme"
	organization, err := claimString(claims, "organization.id", true)
	if err != nil || organization != "literal-acme" {
		t.Fatalf("exact dotted claim did not take precedence: %q err=%v", organization, err)
	}
	if _, err := claimStrings(claims, "$.realm_access["); err == nil {
		t.Fatal("invalid JSONPath was accepted")
	}
}

func TestAuthenticatorAcceptsConfiguredAPIKeyInConstantDigestForm(t *testing.T) {
	digest := sha256.Sum256([]byte("secret-key"))
	a, err := newAuthenticator(context.Background(), AuthenticationConfig{APIKeys: []APIKeyConfig{{Name: "ci", TokenSHA256: fmtHex(digest[:]), Subject: "ci", Username: "automation", Organization: "acme"}}}, false, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := a.Authenticate(context.Background(), "secret-key")
	if err != nil || principal.AuthMethod != "api_key" {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
	if _, err := a.Authenticate(context.Background(), "wrong"); err == nil {
		t.Fatal("wrong API key accepted")
	}
}

func rsaJWK(key *rsa.PublicKey, kid string) map[string]any {
	e := big.NewInt(int64(key.E)).Bytes()
	return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func cloneClaims(input map[string]any) map[string]any {
	encoded, _ := json.Marshal(input)
	var output map[string]any
	_ = json.Unmarshal(encoded, &output)
	return output
}
func fmtHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = alphabet[b>>4]
		out[i*2+1] = alphabet[b&15]
	}
	return string(out)
}
