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
	Issuer            string   `json:"issuer"`
	Subject           string   `json:"subject"`
	Name              string   `json:"name,omitempty"`
	Email             string   `json:"email,omitempty"`
	Username          string   `json:"username"`
	Organization      string   `json:"organization,omitempty"`
	Teams             []string `json:"teams,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	RolesFromClaim    bool     `json:"roles_from_claim,omitempty"`
	RoleClaimSelector string   `json:"role_claim_selector,omitempty"`
	LocalUserRevision int64    `json:"local_user_revision,omitempty"`
	AuthMethod        string   `json:"auth_method"`
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

type localUserReader interface {
	LocalUserByUsername(context.Context, string) (LocalUser, error)
}

type localTokenReader interface {
	AuthenticateLocalToken(context.Context, string, string, []string) (Principal, error)
}

type authenticator struct {
	oidc          []oidcVerifier
	oidcIssuers   map[string]struct{}
	localTokens   localTokenReader
	localAudience string
}

func NewAuthenticator(ctx context.Context, cfg AuthenticationConfig, localTokens localTokenReader) (Authenticator, error) {
	return newAuthenticator(ctx, cfg, localTokens, false, http.DefaultClient)
}

func newAuthenticator(ctx context.Context, cfg AuthenticationConfig, localTokens localTokenReader, allowInsecureIssuer bool, client *http.Client) (*authenticator, error) {
	cfg.Local.Tokens.setDefaults()
	a := &authenticator{localTokens: localTokens, localAudience: cfg.Local.Tokens.Audience, oidcIssuers: make(map[string]struct{})}
	providerContext := oidc.ClientContext(ctx, client)
	for _, issuerCfg := range cfg.OIDC {
		if !issuerCfg.isEnabled() {
			continue
		}
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
		a.oidcIssuers[issuerURL] = struct{}{}
	}
	return a, nil
}

func (a *authenticator) Authenticate(ctx context.Context, raw string) (Principal, error) {
	if strings.TrimSpace(raw) == "" {
		return Principal{}, ErrUnauthenticated
	}
	if strings.HasPrefix(raw, localAccessTokenPrefix) || strings.HasPrefix(raw, serviceCredentialPrefix) {
		if a.localTokens == nil {
			return Principal{}, ErrUnauthenticated
		}
		// No scope is demanded: an opaque credential is authorized by its domain-separated
		// hash, stored audience, empty revocation stamp, the local user's revision, and RBAC.
		principal, err := a.localTokens.AuthenticateLocalToken(ctx, raw, a.localAudience, nil)
		if err != nil {
			return Principal{}, err
		}
		if principal.AuthMethod == "oidc" {
			if _, ok := a.oidcIssuers[strings.TrimRight(principal.Issuer, "/")]; !ok {
				return Principal{}, ErrUnauthenticated
			}
		}
		return principal, nil
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
	if token == nil {
		return Principal{}, errors.New("verified token is missing")
	}
	if !intersects(token.Audience, cfg.Audiences) {
		return Principal{}, errors.New("token audience is not accepted")
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("decode verified claims: %w", err)
	}
	subjectClaim := strings.TrimSpace(cfg.SubjectClaim)
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	subject, err := claimString(claims, subjectClaim, true)
	if err != nil {
		return Principal{}, err
	}
	username, err := claimString(claims, cfg.UsernameClaim, true)
	if err != nil {
		return Principal{}, err
	}
	name, err := claimString(claims, cfg.NameClaim, false)
	if err != nil {
		return Principal{}, err
	}
	email, err := claimString(claims, cfg.EmailClaim, false)
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
	roles, err := claimStrings(claims, cfg.RoleClaim)
	if err != nil {
		return Principal{}, err
	}
	for _, role := range roles {
		if !safeSegment(role) {
			return Principal{}, fmt.Errorf("role claim %q contains invalid role %q", cfg.RoleClaim, role)
		}
	}
	scopes := tokenScopes(claims)
	for _, required := range cfg.RequiredScopes {
		if !containsString(scopes, required) {
			return Principal{}, fmt.Errorf("required scope %q is missing", required)
		}
	}
	return Principal{Issuer: token.Issuer, Subject: subject, Name: name, Email: email, Username: username,
		Organization: organization, Teams: teams, Scopes: scopes, Roles: cleanStrings(append(roles, userRole)),
		RolesFromClaim: strings.TrimSpace(cfg.RoleClaim) != "", RoleClaimSelector: strings.TrimSpace(cfg.RoleClaim), AuthMethod: "oidc"}, nil
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
