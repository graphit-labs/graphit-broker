package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	zitoidc "github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	oidcSubjectDomain       = "graphit-broker/oidc-subject/v1"
	oidcSigningKeyDomain    = "graphit-broker/oidc-signing-key/v1"
	oidcEncryptionKeyDomain = "graphit-broker/oidc-encryption-key/v1"
	oidcAuthRequestDomain   = "graphit-broker/oidc-auth-request/v1"
	oidcAuthCodeDomain      = "graphit-broker/oidc-auth-code/v1"
	oidcStoredAccessDomain  = "graphit-broker/oidc-stored-access/v1"
	oidcLoginPath           = "/oauth/login"
	oidcAuthorizationPath   = "oauth/authorize"
	oidcTokenPath           = "oauth/token"
	oidcUserinfoPath        = "oauth/userinfo"
	oidcRevocationPath      = "oauth/revoke"
	oidcIntrospectionPath   = "oauth/introspect"
	oidcEndSessionPath      = "oauth/end-session"
	oidcKeysPath            = "oauth/keys"
)

// brokerOIDCScopes is what this OpenID Provider offers, all of them standard OIDC scopes. The
// broker requires no scope of its own anywhere: naming one would narrow which identity providers
// can mint a token this deployment accepts, and a credential's reach comes from its audience.
var brokerOIDCScopes = []string{zitoidc.ScopeOpenID, zitoidc.ScopeProfile, zitoidc.ScopeEmail, offlineAccessScope}

type brokerOIDCProvider struct {
	handler http.Handler
	op      op.OpenIDProvider
	storage *brokerOIDCStorage
}

func (p *brokerOIDCProvider) AuthenticateAccessToken(ctx context.Context, raw string) (Principal, error) {
	issuerContext := op.ContextWithIssuer(ctx, strings.TrimRight(strings.TrimSpace(p.storage.cfg.Server.PublicURL), "/"))
	return p.storage.AuthenticateAccessToken(issuerContext, raw, p.op.AccessTokenVerifier(issuerContext))
}

func newBrokerOIDCProvider(cfg Config, control *ControlStore) (*brokerOIDCProvider, error) {
	if control == nil {
		return nil, errors.New("OIDC provider requires the control store")
	}
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Server.PublicURL), "/")
	if issuer == "" {
		return nil, errors.New("server.public_url is required for the OpenID Provider")
	}
	storage := newBrokerOIDCStorage(control, cfg)
	cryptoKey := deriveOIDCKey(cfg.Authentication.TokenPepper, oidcEncryptionKeyDomain)
	opConfig := &op.Config{
		CryptoKey:              cryptoKey,
		CryptoKeyId:            storage.signingKey.id + "-enc",
		CodeMethodS256:         true,
		GrantTypeRefreshToken:  true,
		RequestObjectSupported: false,
		SupportedClaims: append(append([]string(nil), op.DefaultSupportedClaims...),
			"organization", "groups", "roles"),
		SupportedScopes: append([]string(nil), brokerOIDCScopes...),
	}
	options := []op.Option{
		op.WithCORSOptions(brokerCORSOptions(cfg.Server.CORS)),
		op.WithAccessTokenVerifierOpts(op.WithSupportedAccessTokenSigningAlgorithms(string(jose.EdDSA))),
		op.WithCustomAuthEndpoint(op.NewEndpoint(oidcAuthorizationPath)),
		op.WithCustomTokenEndpoint(op.NewEndpoint(oidcTokenPath)),
		op.WithCustomUserinfoEndpoint(op.NewEndpoint(oidcUserinfoPath)),
		op.WithCustomRevocationEndpoint(op.NewEndpoint(oidcRevocationPath)),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint(oidcIntrospectionPath)),
		op.WithCustomEndSessionEndpoint(op.NewEndpoint(oidcEndSessionPath)),
		op.WithCustomKeysEndpoint(op.NewEndpoint(oidcKeysPath)),
	}
	parsed, _ := url.Parse(issuer)
	if parsed != nil && parsed.Scheme == "http" {
		options = append(options, op.WithAllowInsecure())
	}
	provider, err := op.NewProvider(opConfig, storage, op.StaticIssuer(issuer), options...)
	if err != nil {
		return nil, fmt.Errorf("initialize OpenID Provider: %w", err)
	}
	return &brokerOIDCProvider{handler: provider, op: provider, storage: storage}, nil
}

func deriveOIDCKey(pepper, domain string) [32]byte {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(domain))
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	return key
}

type brokerOIDCSigningKey struct {
	id  string
	key ed25519.PrivateKey
}

func (k *brokerOIDCSigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.EdDSA }
func (k *brokerOIDCSigningKey) Key() any                                    { return k.key }
func (k *brokerOIDCSigningKey) ID() string                                  { return k.id }

type brokerOIDCPublicKey struct{ *brokerOIDCSigningKey }

func (k *brokerOIDCPublicKey) Algorithm() jose.SignatureAlgorithm { return jose.EdDSA }
func (k *brokerOIDCPublicKey) Use() string                        { return "sig" }
func (k *brokerOIDCPublicKey) Key() any                           { return k.key.Public() }

type brokerOIDCClient struct{ cfg LocalTokenConfig }

func (c *brokerOIDCClient) GetID() string { return c.cfg.CLIClientID }
func (c *brokerOIDCClient) RedirectURIs() []string {
	return []string{"http://127.0.0.1" + c.cfg.CLIRedirectPath}
}
func (c *brokerOIDCClient) PostLogoutRedirectURIs() []string    { return nil }
func (c *brokerOIDCClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeNative }
func (c *brokerOIDCClient) AuthMethod() zitoidc.AuthMethod      { return zitoidc.AuthMethodNone }
func (c *brokerOIDCClient) ResponseTypes() []zitoidc.ResponseType {
	return []zitoidc.ResponseType{zitoidc.ResponseTypeCode}
}
func (c *brokerOIDCClient) GrantTypes() []zitoidc.GrantType {
	return []zitoidc.GrantType{zitoidc.GrantTypeCode, zitoidc.GrantTypeRefreshToken}
}
func (c *brokerOIDCClient) LoginURL(id string) string {
	return oidcLoginPath + "?id=" + url.QueryEscape(id)
}
func (c *brokerOIDCClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *brokerOIDCClient) IDTokenLifetime() time.Duration      { return c.cfg.AccessTTL }
func (c *brokerOIDCClient) DevMode() bool                       { return false }
func (c *brokerOIDCClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *brokerOIDCClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *brokerOIDCClient) IsScopeAllowed(scope string) bool {
	return slices.Contains(brokerOIDCScopes, scope)
}
func (c *brokerOIDCClient) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *brokerOIDCClient) ClockSkew() time.Duration             { return 0 }

type brokerOIDCAuthRequest struct {
	ID                  string               `json:"-"`
	ClientID            string               `json:"client_id"`
	Audience            string               `json:"audience"`
	Resource            string               `json:"resource,omitempty"`
	RedirectURI         string               `json:"redirect_uri"`
	State               string               `json:"state"`
	Scopes              []string             `json:"scopes"`
	ResponseType        zitoidc.ResponseType `json:"response_type"`
	ResponseMode        zitoidc.ResponseMode `json:"response_mode"`
	Nonce               string               `json:"nonce"`
	CodeChallenge       string               `json:"code_challenge"`
	CodeChallengeMethod string               `json:"code_challenge_method"`
	OIDCSubject         string               `json:"oidc_subject,omitempty"`
	Principal           Principal            `json:"principal,omitempty"`
	AMR                 []string             `json:"amr,omitempty"`
	AuthTime            time.Time            `json:"auth_time,omitempty"`
	DoneValue           bool                 `json:"done"`
}

func (r *brokerOIDCAuthRequest) GetID() string    { return r.ID }
func (r *brokerOIDCAuthRequest) GetACR() string   { return "" }
func (r *brokerOIDCAuthRequest) GetAMR() []string { return append([]string(nil), r.AMR...) }
func (r *brokerOIDCAuthRequest) GetAudience() []string {
	return audienceFor(r.Audience, r.Resource)
}
func (r *brokerOIDCAuthRequest) GetAuthTime() time.Time                { return r.AuthTime }
func (r *brokerOIDCAuthRequest) GetClientID() string                   { return r.ClientID }
func (r *brokerOIDCAuthRequest) GetNonce() string                      { return r.Nonce }
func (r *brokerOIDCAuthRequest) GetRedirectURI() string                { return r.RedirectURI }
func (r *brokerOIDCAuthRequest) GetResponseType() zitoidc.ResponseType { return r.ResponseType }
func (r *brokerOIDCAuthRequest) GetResponseMode() zitoidc.ResponseMode { return r.ResponseMode }
func (r *brokerOIDCAuthRequest) GetScopes() []string                   { return append([]string(nil), r.Scopes...) }
func (r *brokerOIDCAuthRequest) GetState() string                      { return r.State }
func (r *brokerOIDCAuthRequest) GetSubject() string                    { return r.OIDCSubject }
func (r *brokerOIDCAuthRequest) Done() bool                            { return r.DoneValue }
func (r *brokerOIDCAuthRequest) GetCodeChallenge() *zitoidc.CodeChallenge {
	if r.CodeChallenge == "" {
		return nil
	}
	return &zitoidc.CodeChallenge{Challenge: r.CodeChallenge, Method: zitoidc.CodeChallengeMethod(r.CodeChallengeMethod)}
}

type brokerOIDCRefreshRequest struct{ grant LocalTokenGrant }

func (r *brokerOIDCRefreshRequest) GetAMR() []string { return []string{r.grant.Principal.AuthMethod} }
func (r *brokerOIDCRefreshRequest) GetAudience() []string {
	return audienceFor(r.grant.Audience, r.grant.Resource)
}
func (r *brokerOIDCRefreshRequest) GetAuthTime() time.Time { return r.grant.AuthTime }
func (r *brokerOIDCRefreshRequest) GetClientID() string    { return r.grant.ClientID }
func (r *brokerOIDCRefreshRequest) GetScopes() []string {
	return append([]string(nil), r.grant.Scopes...)
}
func (r *brokerOIDCRefreshRequest) GetSubject() string          { return r.grant.OIDCSubject }
func (r *brokerOIDCRefreshRequest) SetCurrentScopes(v []string) { r.grant.Scopes = cleanStrings(v) }

type brokerOIDCStorage struct {
	control    *ControlStore
	cfg        Config
	client     *brokerOIDCClient
	signingKey *brokerOIDCSigningKey
}

func newBrokerOIDCStorage(control *ControlStore, cfg Config) *brokerOIDCStorage {
	seed := deriveOIDCKey(cfg.Authentication.TokenPepper, oidcSigningKeyDomain)
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicDigest := sha256.Sum256(privateKey.Public().(ed25519.PublicKey))
	keyID := hex.EncodeToString(publicDigest[:8])
	return &brokerOIDCStorage{control: control, cfg: cfg, client: &brokerOIDCClient{cfg: cfg.Authentication.Local.Tokens},
		signingKey: &brokerOIDCSigningKey{id: keyID, key: privateKey}}
}

func (s *brokerOIDCStorage) Health(ctx context.Context) error { return s.control.db.PingContext(ctx) }

func (s *brokerOIDCStorage) CreateAuthRequest(ctx context.Context, input *zitoidc.AuthRequest, _ string) (op.AuthRequest, error) {
	if len(input.Prompt) == 1 && input.Prompt[0] == zitoidc.PromptNone {
		return nil, zitoidc.ErrLoginRequired()
	}
	// openid is the only scope this provider insists on, because OIDC Core requires it of
	// any authentication request. A token's reach is decided by its audience rather than by
	// a product-specific scope, so none is demanded here.
	if !slices.Contains(input.Scopes, zitoidc.ScopeOpenID) {
		return nil, zitoidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	if strings.TrimSpace(input.Nonce) == "" || strings.TrimSpace(input.State) == "" || len(input.State) > 512 {
		return nil, zitoidc.ErrInvalidRequest().WithDescription("nonce and state are required and state must not exceed 512 bytes")
	}
	id, err := randomURLToken(32)
	if err != nil {
		return nil, err
	}
	request := &brokerOIDCAuthRequest{ID: id, ClientID: input.ClientID, Audience: s.cfg.Authentication.Local.Tokens.Audience,
		Resource: requestedResource(ctx), RedirectURI: input.RedirectURI, State: input.State,
		Scopes: cleanStrings(input.Scopes), ResponseType: input.ResponseType, ResponseMode: input.ResponseMode, Nonce: input.Nonce,
		CodeChallenge: input.CodeChallenge, CodeChallengeMethod: string(input.CodeChallengeMethod)}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	_, err = s.control.db.ExecContext(ctx, s.control.bind(`INSERT INTO oidc_auth_requests(request_hash, identity_subject, request_json, code_hash, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?)`),
		s.control.tokenHash(oidcAuthRequestDomain, id), "", string(payload), nil, now.Add(s.cfg.Authentication.Local.Tokens.AuthorizationTTL).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	return request, nil
}

func (s *brokerOIDCStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.authRequest(ctx, "request_hash", s.control.tokenHash(oidcAuthRequestDomain, id), id)
}

func (s *brokerOIDCStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	return s.authRequest(ctx, "code_hash", s.control.tokenHash(oidcAuthCodeDomain, code), "")
}

func (s *brokerOIDCStorage) authRequest(ctx context.Context, column, value, rawID string) (*brokerOIDCAuthRequest, error) {
	if column != "request_hash" && column != "code_hash" {
		return nil, errors.New("invalid OIDC request lookup")
	}
	var requestHash, payload, expires string
	query := `SELECT request_hash, request_json, expires_at FROM oidc_auth_requests WHERE ` + column + `=?`
	if err := s.control.db.QueryRowContext(ctx, s.control.bind(query), value).Scan(&requestHash, &payload, &expires); err != nil {
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !expiresAt.After(time.Now()) {
		return nil, errors.New("OIDC authorization request expired")
	}
	var request brokerOIDCAuthRequest
	if err := json.Unmarshal([]byte(payload), &request); err != nil {
		return nil, err
	}
	if rawID != "" {
		request.ID = rawID
	} else {
		request.ID = "hash:" + requestHash
	}
	return &request, nil
}

func (s *brokerOIDCStorage) SaveAuthCode(ctx context.Context, id, code string) error {
	requestHash := s.requestHash(id)
	result, err := s.control.db.ExecContext(ctx, s.control.bind(`UPDATE oidc_auth_requests SET code_hash=? WHERE request_hash=? AND code_hash IS NULL AND expires_at>?`),
		s.control.tokenHash(oidcAuthCodeDomain, code), requestHash, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("OIDC authorization request is invalid or already used")
	}
	return nil
}

func (s *brokerOIDCStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.control.db.ExecContext(ctx, s.control.bind(`DELETE FROM oidc_auth_requests WHERE request_hash=?`), s.requestHash(id))
	return err
}

func (s *brokerOIDCStorage) requestHash(id string) string {
	if strings.HasPrefix(id, "hash:") {
		return strings.TrimPrefix(id, "hash:")
	}
	return s.control.tokenHash(oidcAuthRequestDomain, id)
}

func (s *brokerOIDCStorage) AuthorizeRequest(ctx context.Context, id string, principal Principal, amr []string) error {
	request, err := s.AuthRequestByID(ctx, id)
	if err != nil {
		return err
	}
	value := request.(*brokerOIDCAuthRequest)
	if value.DoneValue {
		return errors.New("OIDC authorization request is already completed")
	}
	principal, err = s.control.grantPrincipal(ctx, LocalTokenGrant{Principal: principal, Subject: principal.Subject, LocalUserRevision: principal.LocalUserRevision})
	if err != nil {
		return err
	}
	value.Principal = principal
	value.OIDCSubject = s.subject(principal)
	value.AMR = cleanStrings(amr)
	value.AuthTime = time.Now().UTC()
	value.DoneValue = true
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	result, err := s.control.db.ExecContext(ctx, s.control.bind(`UPDATE oidc_auth_requests SET identity_subject=?, request_json=? WHERE request_hash=? AND code_hash IS NULL AND expires_at>?`),
		principal.Subject, string(payload), s.requestHash(id), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("OIDC authorization request is invalid or already used")
	}
	return nil
}

func (s *brokerOIDCStorage) subject(principal Principal) string {
	mac := hmac.New(sha256.New, s.control.tokenPepper)
	_, _ = mac.Write([]byte(oidcSubjectDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(principal.CanonicalSubject()))
	return "gb_sub_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *brokerOIDCStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	grant, err := s.grantFromRequest(ctx, request)
	if err != nil {
		return "", time.Time{}, err
	}
	accessID, _, expiry, err := s.saveTokenPair(ctx, grant, "", false)
	return accessID, expiry, err
}

func (s *brokerOIDCStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	grant, err := s.grantFromRequest(ctx, request)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if currentRefreshToken != "" {
		consumed, err := s.control.ConsumeRefreshToken(ctx, currentRefreshToken, grant.ClientID)
		if err != nil || consumed.OIDCSubject != grant.OIDCSubject {
			return "", "", time.Time{}, ErrUnauthenticated
		}
		grant = consumed
		grant.Scopes = cleanStrings(request.GetScopes())
	}
	accessID, refresh, expiry, err := s.saveTokenPair(ctx, grant, currentRefreshToken, true)
	return accessID, refresh, expiry, err
}

func (s *brokerOIDCStorage) saveTokenPair(ctx context.Context, grant LocalTokenGrant, _ string, withRefresh bool) (string, string, time.Time, error) {
	principal, err := s.validPrincipal(ctx, grant)
	if err != nil {
		return "", "", time.Time{}, err
	}
	grant.Principal, grant.Subject, grant.LocalUserRevision = principal, principal.Subject, principal.LocalUserRevision
	if grant.OIDCSubject == "" {
		grant.OIDCSubject = s.subject(principal)
	}
	grant.Audience = s.cfg.Authentication.Local.Tokens.Audience
	// grant.Resource is whatever the authorization request validated; it is carried, never
	// re-derived, so a refresh cannot widen the audience beyond what was originally granted.
	accessID, err := randomURLToken(18)
	if err != nil {
		return "", "", time.Time{}, err
	}
	accessExpiry := time.Now().Add(s.cfg.Authentication.Local.Tokens.AccessTTL)
	grant.ExpiresAt = accessExpiry
	if grant.AuthTime.IsZero() {
		grant.AuthTime = time.Now().UTC()
	}
	refreshRaw, refreshID := "", ""
	if withRefresh {
		refreshSecret, err := randomURLToken(32)
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshRaw = localRefreshTokenPrefix + refreshSecret
		refreshID, err = randomURLToken(18)
		if err != nil {
			return "", "", time.Time{}, err
		}
		if grant.RefreshExpiresAt.IsZero() {
			grant.RefreshExpiresAt = time.Now().Add(s.cfg.Authentication.Local.Tokens.RefreshTTL)
		}
		if grant.FamilyID == "" {
			grant.FamilyID, err = randomURLToken(16)
			if err != nil {
				return "", "", time.Time{}, err
			}
		}
	}
	if err := s.control.SaveOIDCTokenPair(ctx, accessID, refreshRaw, refreshID, grant); err != nil {
		return "", "", time.Time{}, err
	}
	return accessID, refreshRaw, accessExpiry, nil
}

func (s *brokerOIDCStorage) grantFromRequest(ctx context.Context, request op.TokenRequest) (LocalTokenGrant, error) {
	switch value := request.(type) {
	case *brokerOIDCAuthRequest:
		if !value.DoneValue || value.Principal.Subject == "" {
			return LocalTokenGrant{}, ErrUnauthenticated
		}
		return LocalTokenGrant{Principal: value.Principal, Subject: value.Principal.Subject, LocalUserRevision: value.Principal.LocalUserRevision,
			OIDCSubject: value.OIDCSubject, ClientID: value.ClientID, Scopes: cleanStrings(value.Scopes), AuthTime: value.AuthTime,
			Resource: value.Resource}, nil
	case *brokerOIDCRefreshRequest:
		return value.grant, nil
	default:
		return LocalTokenGrant{}, fmt.Errorf("unsupported OpenID token request %T", request)
	}
}

func (s *brokerOIDCStorage) validPrincipal(ctx context.Context, grant LocalTokenGrant) (Principal, error) {
	principal, err := s.control.grantPrincipal(ctx, grant)
	if err != nil {
		return Principal{}, err
	}
	if principal.Issuer != localIdentityIssuer {
		issuer, found := findOIDCConfig(s.cfg.Authentication.OIDC, principal.Issuer)
		if !found || !issuer.loginConfigured() || strings.TrimSpace(issuer.RoleClaim) != strings.TrimSpace(principal.RoleClaimSelector) {
			return Principal{}, errors.New("OIDC identity configuration changed; sign in again")
		}
	}
	return principal, nil
}

func findOIDCConfig(configs []OIDCIssuerConfig, issuer string) (OIDCIssuerConfig, bool) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	for _, candidate := range configs {
		if candidate.isEnabled() && strings.TrimRight(strings.TrimSpace(candidate.Issuer), "/") == issuer {
			return candidate, true
		}
	}
	return OIDCIssuerConfig{}, false
}

func (s *brokerOIDCStorage) TokenRequestByRefreshToken(ctx context.Context, raw string) (op.RefreshTokenRequest, error) {
	grant, err := s.control.OIDCRefreshTokenGrant(ctx, raw)
	if err != nil || grant.OIDCSubject == "" {
		return nil, op.ErrInvalidRefreshToken
	}
	return &brokerOIDCRefreshRequest{grant: grant}, nil
}

func (s *brokerOIDCStorage) TerminateSession(ctx context.Context, oidcSubject, clientID string) error {
	return s.control.RevokeOIDCSession(ctx, oidcSubject, clientID, s.subject)
}

// RevokeToken ends what the revocation request named.
//
// The identifier arrives in one of three shapes, and they must be tried in this order. A raw
// refresh token means the framework could not resolve it, so the store matches it by hash. A
// family id is what GetRefreshTokenInfo hands back for a refresh token the framework did
// resolve, and revoking it ends the whole grant. Anything left is an access token id.
//
// Family ids and access token ids are separate identifier spaces with no marker distinguishing
// them, so the order of attempts is what tells them apart: only a family lookup can confirm a
// family. Reversing these two would silently revoke nothing for every refresh token, because an
// access-token lookup keyed by a family id never matches a row.
func (s *brokerOIDCStorage) RevokeToken(ctx context.Context, tokenOrID, _ string, clientID string) *zitoidc.Error {
	if strings.HasPrefix(tokenOrID, localRefreshTokenPrefix) {
		if err := s.control.RevokeRawToken(ctx, tokenOrID); err != nil {
			return zitoidc.ErrServerError().WithParent(err)
		}
		return nil
	}
	switch revoked, err := s.control.RevokeOIDCTokenFamily(ctx, tokenOrID); {
	case err != nil:
		return zitoidc.ErrServerError().WithParent(err)
	case revoked:
		return nil
	}
	// An access token is revoked on its own. Ending its grant as well is only a MAY in
	// RFC 7009 section 2.1, and the refresh token remains the caller's to revoke.
	if err := s.control.RevokeOIDCAccessToken(ctx, tokenOrID, clientID); err != nil {
		return zitoidc.ErrServerError().WithParent(err)
	}
	return nil
}

func (s *brokerOIDCStorage) GetRefreshTokenInfo(ctx context.Context, clientID, raw string) (string, string, error) {
	grant, err := s.control.RefreshTokenGrant(ctx, raw, clientID)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return grant.OIDCSubject, grant.FamilyID, nil
}

func (s *brokerOIDCStorage) SigningKey(context.Context) (op.SigningKey, error) {
	return s.signingKey, nil
}
func (s *brokerOIDCStorage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.EdDSA}, nil
}
func (s *brokerOIDCStorage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{&brokerOIDCPublicKey{s.signingKey}}, nil
}

func (s *brokerOIDCStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	if subtle.ConstantTimeCompare([]byte(clientID), []byte(s.client.GetID())) == 1 {
		return s.client, nil
	}
	if !s.cfg.Authentication.Local.Tokens.DynamicRegistration {
		return nil, sql.ErrNoRows
	}
	record, found, err := s.control.DynamicClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, sql.ErrNoRows
	}
	return &dynamicOIDCClient{brokerOIDCClient: *s.client, record: record}, nil
}

func (s *brokerOIDCStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, secret string) error {
	// Registration never issues a secret, and the static client has none either, so a
	// supplied secret is always wrong regardless of which client is being authenticated.
	if secret != "" {
		return ErrUnauthenticated
	}
	if subtle.ConstantTimeCompare([]byte(clientID), []byte(s.client.GetID())) == 1 {
		return nil
	}
	if !s.cfg.Authentication.Local.Tokens.DynamicRegistration {
		return ErrUnauthenticated
	}
	_, found, err := s.control.DynamicClient(ctx, clientID)
	if err != nil || !found {
		return ErrUnauthenticated
	}
	return nil
}

func (s *brokerOIDCStorage) SetUserinfoFromScopes(context.Context, *zitoidc.UserInfo, string, string, []string) error {
	return nil
}

func (s *brokerOIDCStorage) SetUserinfoFromRequest(ctx context.Context, userinfo *zitoidc.UserInfo, request op.IDTokenRequest, _ []string) error {
	var principal Principal
	switch value := request.(type) {
	case *brokerOIDCAuthRequest:
		principal = value.Principal
	case *brokerOIDCRefreshRequest:
		principal = value.grant.Principal
	default:
		return fmt.Errorf("unsupported OpenID identity request %T", request)
	}
	principal, err := s.validPrincipal(ctx, LocalTokenGrant{Principal: principal, Subject: principal.Subject, LocalUserRevision: principal.LocalUserRevision})
	if err != nil {
		return err
	}
	s.setUserinfo(userinfo, request.GetSubject(), principal)
	return nil
}

func (s *brokerOIDCStorage) SetUserinfoFromToken(ctx context.Context, userinfo *zitoidc.UserInfo, tokenID, oidcSubject, _ string) error {
	grant, err := s.control.OIDCAccessTokenGrant(ctx, tokenID)
	if err != nil {
		return err
	}
	principal, err := s.validPrincipal(ctx, grant)
	if err != nil || subtle.ConstantTimeCompare([]byte(oidcSubject), []byte(s.subject(principal))) != 1 {
		return ErrUnauthenticated
	}
	s.setUserinfo(userinfo, oidcSubject, principal)
	return nil
}

func (s *brokerOIDCStorage) setUserinfo(userinfo *zitoidc.UserInfo, subject string, principal Principal) {
	userinfo.Subject = subject
	userinfo.Name = principal.Name
	userinfo.Email = principal.Email
	userinfo.PreferredUsername = principal.Username
	if organization := strings.TrimSpace(principal.Organization); organization != "" {
		userinfo.AppendClaims("organization", organization)
	}
	if groups := cleanStrings(principal.Teams); len(groups) > 0 {
		userinfo.AppendClaims("groups", groups)
	}
	if roles := cleanStrings(principal.Roles); len(roles) > 0 {
		userinfo.AppendClaims("roles", roles)
	}
}

func (s *brokerOIDCStorage) SetIntrospectionFromToken(ctx context.Context, response *zitoidc.IntrospectionResponse, tokenID, oidcSubject, clientID string) error {
	grant, err := s.control.OIDCAccessTokenGrant(ctx, tokenID)
	if err != nil || grant.ClientID != clientID || grant.OIDCSubject != oidcSubject {
		return ErrUnauthenticated
	}
	response.ClientID = clientID
	response.Scope = grant.Scopes
	response.Expiration = zitoidc.FromTime(grant.ExpiresAt)
	return nil
}

func (s *brokerOIDCStorage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

func (s *brokerOIDCStorage) GetPrivateClaimsFromRequest(ctx context.Context, request op.TokenRequest, _ []string) (map[string]any, error) {
	grant, err := s.grantFromRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	principal, err := s.validPrincipal(ctx, grant)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{
		"preferred_username": principal.Username,
		"scope":              strings.Join(cleanStrings(request.GetScopes()), " "),
		// Distinguish an access JWT from the ID token signed by the same OP key.
		"token_use": "access",
	}
	if name := strings.TrimSpace(principal.Name); name != "" {
		claims["name"] = name
	}
	if email := strings.TrimSpace(principal.Email); email != "" {
		claims["email"] = email
	}
	if organization := strings.TrimSpace(principal.Organization); organization != "" {
		claims["organization"] = organization
	}
	if groups := cleanStrings(principal.Teams); len(groups) > 0 {
		claims["groups"] = groups
	}
	if roles := cleanStrings(principal.Roles); len(roles) > 0 {
		claims["roles"] = roles
	}
	return claims, nil
}
func (s *brokerOIDCStorage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("JWT client authentication is not supported")
}
func (s *brokerOIDCStorage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("JWT bearer grants are not supported")
}

func (s *brokerOIDCStorage) AuthenticateAccessToken(ctx context.Context, raw string, verifier *op.AccessTokenVerifier) (Principal, error) {
	// The audience admits a token to this API, so a client that reaches the Graphit MCP endpoint
	// can also reach the calls Graphit relays here on its behalf. The grant lookup below refuses
	// a revoked token, and RBAC decides what the principal may do.
	claims, err := op.VerifyAccessToken[*zitoidc.AccessTokenClaims](ctx, raw, verifier)
	if err != nil || claims.JWTID == "" || claims.Subject == "" ||
		claims.Claims["token_use"] != "access" ||
		!slices.Contains(claims.Audience, s.cfg.Authentication.Local.Tokens.Audience) {
		return Principal{}, ErrUnauthenticated
	}
	// The client must be one this broker issued to. Pinning it to the configured CLI client
	// would lock every dynamically registered agent out of the broker's own API, even though
	// the broker itself minted its token.
	if _, err := s.GetClientByClientID(ctx, claims.ClientID); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	grant, err := s.control.OIDCAccessTokenGrant(ctx, claims.JWTID)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	principal, err := s.validPrincipal(ctx, grant)
	if err != nil || grant.ClientID != claims.ClientID || !slices.Contains(claims.Audience, grant.Audience) ||
		subtle.ConstantTimeCompare([]byte(claims.Subject), []byte(s.subject(principal))) != 1 {
		return Principal{}, ErrUnauthenticated
	}
	principal.Scopes = cleanStrings([]string(claims.Scopes))
	return principal, nil
}
