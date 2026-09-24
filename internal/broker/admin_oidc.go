package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type AdminIdentity struct {
	Issuer            string   `json:"issuer,omitempty"`
	Subject           string   `json:"subject"`
	Name              string   `json:"name,omitempty"`
	Email             string   `json:"email,omitempty"`
	Username          string   `json:"username,omitempty"`
	Organization      string   `json:"organization,omitempty"`
	Teams             []string `json:"teams,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	RolesFromClaim    bool     `json:"-"`
	RoleClaimSelector string   `json:"-"`
}

type AdminIdentityProvider interface {
	AuthorizationURL(state, nonce, verifier string) string
	Exchange(context.Context, string, string, string) (AdminIdentity, error)
}

type browserOIDCProvider struct {
	ID       string
	Name     string
	Identity AdminIdentityProvider
}

type browserOIDCOption struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	StartURL string `json:"-"`
}

func browserOIDCProviderID(cfg OIDCIssuerConfig) string {
	value := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/") + "\x00" + strings.TrimSpace(cfg.ClientID)
	digest := sha256.Sum256([]byte(value))
	return "oidc_" + base64.RawURLEncoding.EncodeToString(digest[:12])
}

func browserOIDCProviderName(cfg OIDCIssuerConfig) string {
	return strings.TrimSpace(cfg.DisplayName)
}

type oidcAdminProvider struct {
	oauth          oauth2.Config
	verifier       *oidc.IDTokenVerifier
	accessVerifier *oidc.IDTokenVerifier
	provider       *oidc.Provider
	httpClient     *http.Client
	config         OIDCIssuerConfig
}

func NewAdminIdentityProvider(ctx context.Context, cfg OIDCIssuerConfig) (AdminIdentityProvider, error) {
	provider, err := oidc.NewProvider(ctx, strings.TrimRight(cfg.Issuer, "/"))
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer for browser login: %w", err)
	}
	scopes := cleanStrings(append([]string{oidc.ScopeOpenID}, cfg.Scopes...))
	var httpClient *http.Client
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		httpClient = configured
	}
	return &oidcAdminProvider{
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
			Endpoint: provider.Endpoint(), Scopes: scopes,
		},
		verifier:       provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		accessVerifier: provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
		provider:       provider, httpClient: httpClient, config: cfg,
	}, nil
}

func (p *oidcAdminProvider) AuthorizationURL(state, nonce, verifier string) string {
	challenge := sha256.Sum256([]byte(verifier))
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if p.config.requiresNonce() {
		options = append(options, oidc.Nonce(nonce))
	}
	return p.oauth.AuthCodeURL(state, options...)
}

func (p *oidcAdminProvider) Exchange(ctx context.Context, code, verifier, nonce string) (AdminIdentity, error) {
	ctx = p.withHTTPClient(ctx)
	token, err := p.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return AdminIdentity{}, fmt.Errorf("exchange OIDC code: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return AdminIdentity{}, errors.New("OIDC response omitted id_token")
	}
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return AdminIdentity{}, fmt.Errorf("verify OIDC ID token: %w", err)
	}
	if p.config.requiresNonce() && idToken.Nonce != nonce {
		return AdminIdentity{}, errors.New("OIDC ID token nonce mismatch")
	}
	var claims map[string]any
	switch p.config.claimsSource() {
	case "id_token":
		if err := idToken.Claims(&claims); err != nil {
			return AdminIdentity{}, fmt.Errorf("decode OIDC ID token claims: %w", err)
		}
	case "access_token":
		accessToken, err := p.accessVerifier.Verify(ctx, token.AccessToken)
		if err != nil {
			return AdminIdentity{}, fmt.Errorf("verify OIDC access token: %w", err)
		}
		if accessToken.Subject == "" || accessToken.Subject != idToken.Subject {
			return AdminIdentity{}, errors.New("OIDC access token subject does not match ID token")
		}
		if err := accessToken.Claims(&claims); err != nil {
			return AdminIdentity{}, fmt.Errorf("decode OIDC access token claims: %w", err)
		}
	case "userinfo":
		claims, err = p.userinfoClaims(ctx, token.AccessToken)
		if err != nil {
			return AdminIdentity{}, err
		}
		if subject, ok := claims["sub"].(string); !ok || subject == "" || subject != idToken.Subject {
			return AdminIdentity{}, errors.New("OIDC userinfo subject does not match ID token")
		}
	default:
		return AdminIdentity{}, errors.New("invalid OIDC claims source")
	}
	return adminIdentityFromClaims(idToken.Issuer, claims, p.config)
}

func (p *oidcAdminProvider) userinfoClaims(ctx context.Context, accessToken string) (map[string]any, error) {
	if accessToken == "" {
		return nil, errors.New("OIDC response omitted access_token for userinfo")
	}
	endpoint := p.provider.UserInfoEndpoint()
	if endpoint == "" {
		return nil, errors.New("OIDC issuer has no userinfo endpoint")
	}
	if err := validateHTTPSOrLoopbackURL(endpoint, "OIDC userinfo endpoint"); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("prepare OIDC userinfo request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	client := http.DefaultClient
	if p.httpClient != nil {
		client = p.httpClient
	}
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := noRedirectClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch OIDC userinfo: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch OIDC userinfo: status %d", response.StatusCode)
	}
	const maxUserinfoBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxUserinfoBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OIDC userinfo: %w", err)
	}
	if len(body) > maxUserinfoBytes {
		return nil, errors.New("OIDC userinfo response is too large")
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil || claims == nil {
		return nil, errors.New("decode OIDC userinfo claims")
	}
	return claims, nil
}

func (p *oidcAdminProvider) withHTTPClient(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
}

func adminIdentityFromClaims(issuer string, claims map[string]any, cfg OIDCIssuerConfig) (AdminIdentity, error) {
	subjectClaim := strings.TrimSpace(cfg.SubjectClaim)
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	subject, err := claimString(claims, subjectClaim, true)
	if err != nil {
		return AdminIdentity{}, err
	}
	nameClaim := cfg.NameClaim
	if strings.TrimSpace(nameClaim) == "" {
		nameClaim = "name"
	}
	emailClaim := cfg.EmailClaim
	if strings.TrimSpace(emailClaim) == "" {
		emailClaim = "email"
	}
	name, err := claimString(claims, nameClaim, false)
	if err != nil {
		return AdminIdentity{}, err
	}
	email, err := claimString(claims, emailClaim, false)
	if err != nil {
		return AdminIdentity{}, err
	}
	username, err := claimString(claims, cfg.UsernameClaim, true)
	if err != nil {
		return AdminIdentity{}, err
	}
	organization, err := claimString(claims, cfg.OrganizationClaim, false)
	if err != nil {
		return AdminIdentity{}, err
	}
	teams, err := claimStrings(claims, cfg.TeamsClaim)
	if err != nil {
		return AdminIdentity{}, err
	}
	roles, err := claimStrings(claims, cfg.RoleClaim)
	if err != nil {
		return AdminIdentity{}, err
	}
	rolesFromClaim := strings.TrimSpace(cfg.RoleClaim) != ""
	for _, role := range roles {
		if !safeSegment(role) {
			return AdminIdentity{}, fmt.Errorf("role claim %q contains invalid role %q", cfg.RoleClaim, role)
		}
	}
	return AdminIdentity{Issuer: issuer, Subject: subject, Name: name, Email: email,
		Username: username, Organization: organization, Teams: teams, Roles: cleanStrings(append(roles, userRole)),
		RolesFromClaim: rolesFromClaim, RoleClaimSelector: strings.TrimSpace(cfg.RoleClaim)}, nil
}

func randomURLToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
