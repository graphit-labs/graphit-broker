package broker

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

var localAuthorizationPage = template.Must(template.New("authorize").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize Graphit CLI</title></head><body><main><h1>Authorize Graphit CLI</h1><p>Sign in with a local human account. Your password is used only for this login and is never issued as an API credential.</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post"><label>Username <input name="username" autocomplete="username" required></label><label>Password <input name="password" type="password" minlength="15" autocomplete="current-password" required></label><button type="submit">Authorize</button></form></main></body></html>`))

var deviceVerificationPage = template.Must(template.New("device").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize device</title></head><body><main><h1>Authorize device</h1>{{if .Approved}}<p>Device authorized. You may close this page.</p>{{else}}<p>Enter the code shown by the CLI and sign in with a local human account.</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}<form method="post"><label>Device code <input name="user_code" value="{{.UserCode}}" autocomplete="one-time-code" required></label><label>Username <input name="username" autocomplete="username" required></label><label>Password <input name="password" type="password" minlength="15" autocomplete="current-password" required></label><button type="submit">Authorize</button></form>{{end}}</main></body></html>`))

func (s *Server) oauthMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := s.publicURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"device_authorization_endpoint":         issuer + "/oauth/device/authorize",
		"revocation_endpoint":                   issuer + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", deviceGrantType},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{localAPIScope, offlineAccessScope},
	})
}

func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.control == nil || s.runtime().localPasswords == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "local authorization is unavailable")
		return
	}
	params, err := s.localAuthorizationRequest(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if r.Method == http.MethodGet {
		s.writeOAuthHTML(w, localAuthorizationPage, map[string]any{})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid authorization form")
		return
	}
	username, password := strings.TrimSpace(r.PostForm.Get("username")), r.PostForm.Get("password")
	principal, authErr := s.runtime().localPasswords.Authenticate(r.Context(), username, password)
	password = ""
	if retryAfter, limited := authenticationRetryAfter(authErr); limited {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter/time.Second))))
		s.writeOAuthHTMLStatus(w, http.StatusTooManyRequests, localAuthorizationPage, map[string]any{"Error": "Too many authentication attempts. Try again later."})
		return
	}
	if authErr != nil || principal.AuthMethod != "local-password" {
		s.writeOAuthHTMLStatus(w, http.StatusUnauthorized, localAuthorizationPage, map[string]any{"Error": "Invalid local credentials."})
		return
	}
	code, err := randomURLToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not create authorization code")
		return
	}
	expires := time.Now().Add(s.runtime().config.Authentication.LocalTokens.AuthorizationTTL)
	grant := AuthorizationCodeGrant{LocalTokenGrant: LocalTokenGrant{Subject: principal.Subject, LocalUserRevision: principal.LocalUserRevision,
		ClientID: params.clientID, Audience: s.runtime().config.Authentication.LocalTokens.Audience, Scopes: params.scopes},
		RedirectURI: params.redirectURI, CodeChallenge: params.codeChallenge}
	grant.ExpiresAt = expires
	if err := s.control.SaveAuthorizationCode(r.Context(), code, grant); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist authorization code")
		return
	}
	redirect, _ := url.Parse(params.redirectURI)
	query := redirect.Query()
	query.Set("code", code)
	query.Set("state", params.state)
	redirect.RawQuery = query.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

type localAuthorizationParams struct {
	clientID, redirectURI, codeChallenge, state string
	scopes                                      []string
}

func (s *Server) localAuthorizationRequest(r *http.Request) (localAuthorizationParams, error) {
	query := r.URL.Query()
	params := localAuthorizationParams{clientID: strings.TrimSpace(query.Get("client_id")), redirectURI: strings.TrimSpace(query.Get("redirect_uri")),
		codeChallenge: strings.TrimSpace(query.Get("code_challenge")), state: query.Get("state")}
	if query.Get("response_type") != "code" {
		return params, errors.New("response_type must be code")
	}
	cfg := s.runtime().config.Authentication.LocalTokens
	if params.clientID != cfg.CLIClientID {
		return params, errors.New("unknown client_id")
	}
	if err := validateLoopbackRedirect(params.redirectURI, cfg.CLIRedirectPath); err != nil {
		return params, err
	}
	if query.Get("code_challenge_method") != "S256" || !validPKCEChallenge(params.codeChallenge) {
		return params, errors.New("PKCE S256 code_challenge is required")
	}
	if params.state == "" || len(params.state) > 512 {
		return params, errors.New("state is required and must not exceed 512 bytes")
	}
	var err error
	params.scopes, err = requestedLocalScopes(query.Get("scope"))
	return params, err
}

func validateLoopbackRedirect(raw, expectedPath string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != expectedPath {
		return errors.New("redirect_uri must be the configured HTTP loopback callback path")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "::1" {
		return errors.New("redirect_uri must use a loopback IP literal")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("redirect_uri must include the CLI loopback port")
	}
	if net.ParseIP(host) == nil {
		return errors.New("redirect_uri loopback host is invalid")
	}
	return nil
}

func validPKCEChallenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func requestedLocalScopes(raw string) ([]string, error) {
	values := cleanStrings(strings.Fields(raw))
	if len(values) == 0 {
		values = []string{localAPIScope}
	}
	if !containsString(values, localAPIScope) {
		return nil, errors.New("scope graphit.use is required")
	}
	for _, value := range values {
		if value != localAPIScope && value != offlineAccessScope {
			return nil, errors.New("unsupported scope " + value)
		}
	}
	return values, nil
}

func (s *Server) oauthDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if !requireForm(w, r) {
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	cfg := s.runtime().config.Authentication.LocalTokens
	if clientID != cfg.CLIClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	scopes, err := requestedLocalScopes(r.PostForm.Get("scope"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	deviceCode, err := randomURLToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not create device code")
		return
	}
	deviceCode = deviceCodePrefix + deviceCode
	userCode, err := randomDeviceUserCode()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not create user code")
		return
	}
	expires := time.Now().Add(cfg.DeviceTTL)
	if err := s.control.SaveDeviceAuthorization(r.Context(), deviceCode, userCode, DeviceAuthorization{ClientID: clientID, Scopes: scopes, Interval: cfg.DevicePollInterval, ExpiresAt: expires}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist device authorization")
		return
	}
	verificationURI := s.publicURL(r) + "/oauth/device"
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"device_code": deviceCode, "user_code": userCode,
		"verification_uri": verificationURI, "verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(userCode),
		"expires_in": int64(cfg.DeviceTTL / time.Second), "interval": int64(cfg.DevicePollInterval / time.Second)})
}

func (s *Server) oauthDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if s.control == nil || s.runtime().localPasswords == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "local authorization is unavailable")
		return
	}
	if r.Method == http.MethodGet {
		s.writeOAuthHTML(w, deviceVerificationPage, map[string]any{"UserCode": r.URL.Query().Get("user_code")})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.writeOAuthHTMLStatus(w, http.StatusBadRequest, deviceVerificationPage, map[string]any{"Error": "Invalid verification form."})
		return
	}
	userCode := r.PostForm.Get("user_code")
	username, password := strings.TrimSpace(r.PostForm.Get("username")), r.PostForm.Get("password")
	principal, authErr := s.runtime().localPasswords.Authenticate(r.Context(), username, password)
	password = ""
	if retryAfter, limited := authenticationRetryAfter(authErr); limited {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter/time.Second))))
		s.writeOAuthHTMLStatus(w, http.StatusTooManyRequests, deviceVerificationPage, map[string]any{"UserCode": userCode, "Error": "Too many authentication attempts. Try again later."})
		return
	}
	if authErr != nil || principal.AuthMethod != "local-password" {
		s.writeOAuthHTMLStatus(w, http.StatusUnauthorized, deviceVerificationPage, map[string]any{"UserCode": userCode, "Error": "Invalid local credentials."})
		return
	}
	user, err := s.control.LocalUserBySubject(r.Context(), principal.Subject)
	if err != nil || s.control.ApproveDeviceAuthorization(r.Context(), userCode, user) != nil {
		s.writeOAuthHTMLStatus(w, http.StatusBadRequest, deviceVerificationPage, map[string]any{"UserCode": userCode, "Error": "The device code is invalid or expired."})
		return
	}
	s.writeOAuthHTML(w, deviceVerificationPage, map[string]any{"Approved": true})
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	if !requireForm(w, r) {
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if clientID != s.runtime().config.Authentication.LocalTokens.CLIClientID {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}
	var grant LocalTokenGrant
	var err error
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		if !validPKCEVerifier(r.PostForm.Get("code_verifier")) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization grant is invalid")
			return
		}
		grant, err = s.control.ConsumeAuthorizationCode(r.Context(), r.PostForm.Get("code"), clientID, r.PostForm.Get("redirect_uri"), r.PostForm.Get("code_verifier"))
	case deviceGrantType:
		grant, err = s.control.PollDeviceAuthorization(r.Context(), r.PostForm.Get("device_code"), clientID)
	case "refresh_token":
		grant, err = s.control.ConsumeRefreshToken(r.Context(), r.PostForm.Get("refresh_token"), clientID)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrAuthorizationPending):
			writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "device authorization is pending")
		case errors.Is(err, ErrSlowDown):
			writeOAuthError(w, http.StatusBadRequest, "slow_down", "device polling interval was exceeded")
		case errors.Is(err, ErrExpiredToken):
			writeOAuthError(w, http.StatusBadRequest, "expired_token", "device code expired")
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization grant is invalid")
		}
		return
	}
	s.oauthIssueTokenPair(w, r, grant)
}

func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-._~", r) {
			continue
		}
		return false
	}
	return true
}

func (s *Server) oauthIssueTokenPair(w http.ResponseWriter, r *http.Request, grant LocalTokenGrant) {
	user, err := s.control.LocalUserBySubject(r.Context(), grant.Subject)
	if err != nil || !user.Enabled || user.Kind != humanIdentityKind || user.Revision != grant.LocalUserRevision {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "local identity is no longer valid")
		return
	}
	cfg := s.runtime().config.Authentication.LocalTokens
	accessSecret, err := randomURLToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	accessID, err := randomURLToken(12)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	accessRaw := localAccessTokenPrefix + accessSecret
	grant.Audience, grant.ClientID = cfg.Audience, cfg.CLIClientID
	grant.ExpiresAt = time.Now().Add(cfg.AccessTTL)
	if grant.RefreshExpiresAt.IsZero() {
		grant.RefreshExpiresAt = time.Now().Add(cfg.RefreshTTL)
	}
	if grant.FamilyID == "" {
		grant.FamilyID, err = randomURLToken(16)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue token family")
			return
		}
	}
	refreshRaw, refreshID := "", ""
	if containsString(grant.Scopes, offlineAccessScope) {
		refreshSecret, refreshErr := randomURLToken(32)
		if refreshErr != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue refresh token")
			return
		}
		refreshRaw = localRefreshTokenPrefix + refreshSecret
		refreshID, err = randomURLToken(12)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue refresh token")
			return
		}
	}
	if err := s.control.SaveTokenPair(r.Context(), accessRaw, accessID, refreshRaw, refreshID, grant); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist access token")
		return
	}
	response := map[string]any{"access_token": accessRaw, "token_type": "Bearer", "expires_in": int64(cfg.AccessTTL / time.Second), "scope": strings.Join(cleanStrings(grant.Scopes), " ")}
	if refreshRaw != "" {
		response["refresh_token"] = refreshRaw
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if !requireForm(w, r) {
		return
	}
	if err := s.control.RevokeRawToken(r.Context(), r.PostForm.Get("token")); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not revoke token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func requireForm(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "application/x-www-form-urlencoded") {
		writeOAuthError(w, http.StatusUnsupportedMediaType, "invalid_request", "application/x-www-form-urlencoded is required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return false
	}
	return true
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func (s *Server) writeOAuthHTML(w http.ResponseWriter, page *template.Template, data any) {
	s.writeOAuthHTMLStatus(w, http.StatusOK, page, data)
}

func (s *Server) writeOAuthHTMLStatus(w http.ResponseWriter, status int, page *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = page.Execute(w, data)
}

func (s *Server) publicURL(r *http.Request) string {
	if configured := strings.TrimRight(strings.TrimSpace(s.runtime().config.Server.PublicURL), "/"); configured != "" {
		return configured
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func randomDeviceUserCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(raw[:4]) + "-" + string(raw[4:]), nil
}
