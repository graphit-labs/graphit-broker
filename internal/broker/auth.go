package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

var ErrUnauthenticated = errors.New("authentication failed")

type Principal struct {
	Issuer       string
	Subject      string
	Username     string
	Organization string
	Teams        []string
	Scopes       []string
	AuthMethod   string
}

func (p Principal) CanonicalSubject() string { return p.Issuer + "|" + p.Subject }

type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

type tokenVerifier interface {
	Verify(context.Context, string) (*oidc.IDToken, error)
}

type oidcVerifier struct {
	config   OIDCIssuerConfig
	verifier tokenVerifier
}

type apiKeyIdentity struct {
	digest    [sha256.Size]byte
	principal Principal
}

type authenticator struct {
	oidc    []oidcVerifier
	apiKeys []apiKeyIdentity
}

func NewAuthenticator(ctx context.Context, cfg AuthenticationConfig) (Authenticator, error) {
	return newAuthenticator(ctx, cfg, false, http.DefaultClient)
}

func newAuthenticator(ctx context.Context, cfg AuthenticationConfig, allowInsecureIssuer bool, client *http.Client) (*authenticator, error) {
	a := &authenticator{}
	providerContext := oidc.ClientContext(ctx, client)
	for _, issuerCfg := range cfg.OIDC {
		issuerURL := strings.TrimRight(issuerCfg.Issuer, "/")
		issuerContext := providerContext
		if allowInsecureIssuer {
			issuerContext = oidc.InsecureIssuerURLContext(providerContext, issuerURL)
		}
		provider, err := oidc.NewProvider(issuerContext, issuerURL)
		if err != nil {
			return nil, fmt.Errorf("discover OIDC issuer %s: %w", issuerURL, err)
		}
		// Verification of multiple accepted audiences is completed after signature,
		// issuer and temporal validation by checking the token's complete aud claim.
		verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
		a.oidc = append(a.oidc, oidcVerifier{config: issuerCfg, verifier: verifier})
	}
	for _, key := range cfg.APIKeys {
		var digest [sha256.Size]byte
		if key.TokenSHA256 != "" {
			decoded, _ := hex.DecodeString(key.TokenSHA256)
			copy(digest[:], decoded)
		} else {
			digest = sha256.Sum256([]byte(key.Token))
		}
		a.apiKeys = append(a.apiKeys, apiKeyIdentity{digest: digest, principal: Principal{
			Issuer: "apikey:" + key.Name, Subject: key.Subject, Username: key.Username,
			Organization: key.Organization, Teams: cleanStrings(key.Teams), AuthMethod: "api_key",
		}})
	}
	return a, nil
}

func (a *authenticator) Authenticate(ctx context.Context, raw string) (Principal, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Principal{}, ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(raw))
	for _, key := range a.apiKeys {
		if subtle.ConstantTimeCompare(digest[:], key.digest[:]) == 1 {
			return key.principal, nil
		}
	}
	for _, candidate := range a.oidc {
		token, err := candidate.verifier.Verify(ctx, raw)
		if err != nil {
			continue
		}
		principal, err := principalFromIDToken(token, candidate.config)
		if err == nil {
			return principal, nil
		}
	}
	return Principal{}, ErrUnauthenticated
}

func principalFromIDToken(token *oidc.IDToken, cfg OIDCIssuerConfig) (Principal, error) {
	if token == nil || token.Subject == "" {
		return Principal{}, errors.New("verified token has no subject")
	}
	if !intersects(token.Audience, cfg.Audiences) {
		return Principal{}, errors.New("token audience is not accepted")
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("decode verified claims: %w", err)
	}
	username, err := claimString(claims, cfg.UsernameClaim, true)
	if err != nil {
		return Principal{}, err
	}
	organization, err := claimString(claims, cfg.OrganizationClaim, false)
	if err != nil {
		return Principal{}, err
	}
	teams, err := claimStrings(claims, cfg.TeamsClaim)
	if err != nil {
		return Principal{}, err
	}
	scopes := tokenScopes(claims)
	for _, required := range cfg.RequiredScopes {
		if !containsString(scopes, required) {
			return Principal{}, fmt.Errorf("required scope %q is missing", required)
		}
	}
	return Principal{Issuer: token.Issuer, Subject: token.Subject, Username: username,
		Organization: organization, Teams: teams, Scopes: scopes, AuthMethod: "oidc"}, nil
}

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func claimValue(claims map[string]any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	if value, ok := claims[path]; ok {
		return value, true
	}
	current := any(claims)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func claimString(claims map[string]any, path string, required bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		if required {
			return "", errors.New("required claim path is empty")
		}
		return "", nil
	}
	value, ok := claimValue(claims, path)
	if !ok {
		if required {
			return "", fmt.Errorf("required claim %q is missing", path)
		}
		return "", nil
	}
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("claim %q must be a non-empty string", path)
	}
	return strings.TrimSpace(text), nil
}

func claimStrings(claims map[string]any, path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	value, ok := claimValue(claims, path)
	if !ok {
		return nil, nil
	}
	switch typed := value.(type) {
	case string:
		return cleanStrings([]string{typed}), nil
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("claim %q must contain only strings", path)
			}
			values = append(values, text)
		}
		return cleanStrings(values), nil
	default:
		return nil, fmt.Errorf("claim %q must be a string or string array", path)
	}
}

func tokenScopes(claims map[string]any) []string {
	var scopes []string
	if raw, ok := claims["scope"].(string); ok {
		scopes = append(scopes, strings.Fields(raw)...)
	}
	if raw, ok := claims["scp"].([]any); ok {
		for _, value := range raw {
			if text, ok := value.(string); ok {
				scopes = append(scopes, text)
			}
		}
	}
	if raw, ok := claims["scp"].(string); ok {
		scopes = append(scopes, strings.Fields(raw)...)
	}
	return cleanStrings(scopes)
}

func cleanStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func intersects(left, right []string) bool {
	for _, a := range left {
		if containsString(right, a) {
			return true
		}
	}
	return false
}
