package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/theory/jsonpath"
)

var ErrUnauthenticated = errors.New("authentication failed")

type Principal struct {
	Issuer       string
	Subject      string
	Username     string
	Organization string
	Teams        []string
	Scopes       []string
	Roles        []string
	AuthMethod   string
}

func (p Principal) CanonicalSubject() string { return p.Issuer + "|" + p.Subject }

func AnonymousPrincipal() Principal {
	return Principal{Issuer: "anonymous", Subject: "anonymous", Username: "anonymous", AuthMethod: "anonymous"}
}

func (p Principal) IsAnonymous() bool { return p.AuthMethod == "anonymous" }

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
	verifier  passwordVerifier
	pepper    []byte
	principal Principal
}

type authenticator struct {
	oidc         []oidcVerifier
	apiKeys      map[string]apiKeyIdentity
	dummy        *apiKeyIdentity
	passwordWork chan struct{}
}

func NewAuthenticator(ctx context.Context, cfg AuthenticationConfig) (Authenticator, error) {
	return newAuthenticator(ctx, cfg, false, http.DefaultClient)
}

func newAuthenticator(ctx context.Context, cfg AuthenticationConfig, allowInsecureIssuer bool, client *http.Client) (*authenticator, error) {
	a := &authenticator{apiKeys: make(map[string]apiKeyIdentity, len(cfg.APIKeys)), passwordWork: make(chan struct{}, 1)}
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
		verifier, err := parsePasswordVerifier(key.PasswordHash)
		if err != nil {
			return nil, fmt.Errorf("authentication API key %q password hash: %w", key.Username, err)
		}
		if len(key.Pepper) < passwordPepperMinimumBytes {
			return nil, fmt.Errorf("authentication API key %q password pepper must contain at least %d bytes", key.Username, passwordPepperMinimumBytes)
		}
		if _, duplicate := a.apiKeys[key.Username]; duplicate {
			return nil, fmt.Errorf("duplicate authentication API key username %q", key.Username)
		}
		identity := apiKeyIdentity{verifier: verifier, pepper: []byte(key.Pepper), principal: Principal{
			Issuer: "apikey:" + key.Username, Subject: key.Subject, Username: key.Username,
			Organization: key.Organization, Teams: cleanStrings(key.Teams), Roles: cleanStrings(key.Roles), AuthMethod: "api_key",
		}}
		a.apiKeys[key.Username] = identity
		if a.dummy == nil {
			a.dummy = &identity
		}
	}
	return a, nil
}

func (a *authenticator) Authenticate(ctx context.Context, raw string) (Principal, error) {
	if strings.TrimSpace(raw) == "" {
		return Principal{}, ErrUnauthenticated
	}
	if username, password, ok := localPasswordCredential(raw); ok {
		if key, exists := a.apiKeys[username]; exists {
			if a.verifyPassword(ctx, key.verifier, key.pepper, password) {
				return key.principal, nil
			}
		} else if a.dummy != nil {
			// Unknown local names still pay one Argon2id verification to reduce account-name
			// enumeration through response timing without multiplying work by configured identities.
			a.verifyPassword(ctx, a.dummy.verifier, a.dummy.pepper, password)
		}
		return Principal{}, ErrUnauthenticated
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

func (a *authenticator) verifyPassword(ctx context.Context, verifier passwordVerifier, pepper []byte, password string) bool {
	plaintext := []byte(password)
	defer clear(plaintext)
	select {
	case a.passwordWork <- struct{}{}:
		defer func() { <-a.passwordWork }()
	case <-ctx.Done():
		return false
	}
	return verifier.verify(plaintext, pepper)
}

func localPasswordCredential(raw string) (string, string, bool) {
	separator := strings.IndexByte(raw, ':')
	if separator <= 0 || separator == len(raw)-1 {
		return "", "", false
	}
	return raw[:separator], raw[separator+1:], true
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

// claimValues resolves a configured claim selector. An exact top-level key always wins, which
// keeps namespaced and dotted claim names unambiguous. Selectors beginning with $ are evaluated as
// RFC 9535 JSONPath; other values retain the legacy dotted-object traversal as a fallback.
func claimValues(claims map[string]any, selector string) ([]any, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, nil
	}
	if value, ok := claims[selector]; ok {
		return []any{value}, nil
	}
	if strings.HasPrefix(selector, "$") {
		path, err := jsonpath.Parse(selector)
		if err != nil {
			return nil, fmt.Errorf("invalid claim JSONPath %q: %w", selector, err)
		}
		var values []any
		for value := range path.Select(claims).All() {
			values = append(values, value)
		}
		return values, nil
	}
	if value, ok := claimValue(claims, selector); ok {
		return []any{value}, nil
	}
	return nil, nil
}

func validateClaimSelector(selector string) error {
	selector = strings.TrimSpace(selector)
	if selector == "" || !strings.HasPrefix(selector, "$") {
		return nil
	}
	if _, err := jsonpath.Parse(selector); err != nil {
		return fmt.Errorf("invalid JSONPath %q: %w", selector, err)
	}
	return nil
}

func claimString(claims map[string]any, path string, required bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		if required {
			return "", errors.New("required claim path is empty")
		}
		return "", nil
	}
	values, err := claimValues(claims, path)
	if err != nil {
		return "", err
	}
	if len(values) == 0 {
		if required {
			return "", fmt.Errorf("required claim %q is missing", path)
		}
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("claim %q must select exactly one value", path)
	}
	text, ok := values[0].(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("claim %q must be a non-empty string", path)
	}
	return strings.TrimSpace(text), nil
}

func claimStrings(claims map[string]any, path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	selected, err := claimValues(claims, path)
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		return nil, nil
	}
	var values []string
	for _, value := range selected {
		switch typed := value.(type) {
		case string:
			values = append(values, typed)
		case []any:
			for _, item := range typed {
				text, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("claim %q must contain only strings", path)
				}
				values = append(values, text)
			}
		case []string:
			values = append(values, typed...)
		default:
			return nil, fmt.Errorf("claim %q must select only strings or string arrays", path)
		}
	}
	return cleanStrings(values), nil
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
