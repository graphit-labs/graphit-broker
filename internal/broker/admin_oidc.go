package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type AdminIdentity struct {
	Issuer       string   `json:"issuer,omitempty"`
	Subject      string   `json:"subject"`
	Name         string   `json:"name,omitempty"`
	Email        string   `json:"email,omitempty"`
	Username     string   `json:"username,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Teams        []string `json:"teams,omitempty"`
}

type AdminIdentityProvider interface {
	AuthorizationURL(state, nonce, verifier string) string
	Exchange(context.Context, string, string, string) (AdminIdentity, error)
	Verify(context.Context, string) (AdminIdentity, error)
}

type oidcAdminProvider struct {
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	httpClient *http.Client
	config     AdminOIDCConfig
}

func NewAdminIdentityProvider(ctx context.Context, cfg AdminOIDCConfig) (AdminIdentityProvider, error) {
	provider, err := oidc.NewProvider(ctx, strings.TrimRight(cfg.Issuer, "/"))
	if err != nil {
		return nil, fmt.Errorf("discover administration OIDC issuer: %w", err)
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
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}), httpClient: httpClient, config: cfg,
	}, nil
}

func (p *oidcAdminProvider) AuthorizationURL(state, nonce, verifier string) string {
	challenge := sha256.Sum256([]byte(verifier))
	return p.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *oidcAdminProvider) Exchange(ctx context.Context, code, verifier, nonce string) (AdminIdentity, error) {
	ctx = p.withHTTPClient(ctx)
	token, err := p.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return AdminIdentity{}, fmt.Errorf("exchange administration OIDC code: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return AdminIdentity{}, errors.New("administration OIDC response omitted id_token")
	}
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return AdminIdentity{}, fmt.Errorf("verify administration ID token: %w", err)
	}
	if idToken.Nonce != nonce {
		return AdminIdentity{}, errors.New("administration ID token nonce mismatch")
	}
	return adminIdentityFromToken(idToken, p.config)
}

func (p *oidcAdminProvider) Verify(ctx context.Context, raw string) (AdminIdentity, error) {
	ctx = p.withHTTPClient(ctx)
	token, err := p.verifier.Verify(ctx, strings.TrimSpace(raw))
	if err != nil {
		return AdminIdentity{}, err
	}
	return adminIdentityFromToken(token, p.config)
}

func (p *oidcAdminProvider) withHTTPClient(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
}

func adminIdentityFromToken(token *oidc.IDToken, cfg AdminOIDCConfig) (AdminIdentity, error) {
	if token == nil || strings.TrimSpace(token.Subject) == "" {
		return AdminIdentity{}, errors.New("administration ID token has no subject")
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return AdminIdentity{}, fmt.Errorf("decode administration ID token claims: %w", err)
	}
	name, err := claimString(claims, "name", false)
	if err != nil {
		return AdminIdentity{}, err
	}
	email, err := claimString(claims, "email", false)
	if err != nil {
		return AdminIdentity{}, err
	}
	username, err := claimString(claims, cfg.UsernameClaim, false)
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
	return AdminIdentity{Issuer: token.Issuer, Subject: token.Subject, Name: name, Email: email,
		Username: username, Organization: organization, Teams: teams}, nil
}

func randomURLToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
