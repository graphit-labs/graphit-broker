package broker

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

//go:embed oauthui/index.html
var oauthHTML string

var oauthAuthorizationPage = template.Must(template.New("oauth-browser").Parse(oauthHTML))
var localAuthorizationPage = oauthAuthorizationPage
var deviceVerificationPage = oauthAuthorizationPage

type localLoginPageData struct {
	Error, Status, ChallengeToken, Secret, UserCode, Redirect string
	QRCodeDataURL                                             template.URL
	RecoveryCodes                                             []string
	Device, Approved, Fatal                                   bool
	Local, OIDC                                               bool
	Captcha                                                   *localCaptchaChallenge
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		s.writeOAuthLoginError(w, http.StatusServiceUnavailable, "Authorization is temporarily unavailable.")
		return
	}
	requestID := strings.TrimSpace(r.URL.Query().Get("id"))
	authRequest, err := s.oidcProvider.storage.AuthRequestByID(r.Context(), requestID)
	if err != nil || authRequest.Done() {
		s.writeOAuthLoginError(w, http.StatusBadRequest, "This OpenID authorization request is invalid or has expired.")
		return
	}
	methods := s.oauthLoginMethods()
	localEnabled, oidcEnabled := containsString(methods, "local"), containsString(methods, "oidc")
	if !localEnabled && !oidcEnabled {
		s.writeOAuthLoginError(w, http.StatusServiceUnavailable, "No authentication method is currently available.")
		return
	}
	if r.Method == http.MethodGet {
		if oidcEnabled && !localEnabled {
			s.startOAuthOIDC(w, r, requestID)
			return
		}
		data := localLoginPageData{Local: localEnabled, OIDC: oidcEnabled}
		data.Captcha = s.runtime().localPasswords.CaptchaChallenge(localCaptchaActionOAuth)
		s.writeOAuthHTML(w, localAuthorizationPage, data)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.writeOAuthLoginError(w, http.StatusBadRequest, "The authorization form is invalid. Please try again.")
		return
	}
	if r.PostForm.Get("login_method") == "oidc" {
		if !oidcEnabled {
			s.writeOAuthLoginError(w, http.StatusBadRequest, "Organization sign-in is unavailable.")
			return
		}
		s.startOAuthOIDC(w, r, requestID)
		return
	}
	if !localEnabled {
		s.writeOAuthLoginError(w, http.StatusBadRequest, "Local sign-in is unavailable.")
		return
	}
	binding := requestID
	step, authErr := s.continueBrowserLocalLogin(r, localAuthPurposeOAuth, binding)
	if challenge, required := captchaChallengeFromError(authErr); required {
		data := loginPageData(step, "Complete human verification before signing in.")
		data.Local, data.OIDC, data.Captcha = localEnabled, oidcEnabled, &challenge
		s.writeOAuthHTMLStatus(w, http.StatusForbidden, localAuthorizationPage, data)
		return
	}
	if retryAfter, limited := authenticationRetryAfter(authErr); limited {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter/time.Second))))
		data := loginPageData(step, "Too many authentication attempts. Try again later.")
		data.Local, data.OIDC = localEnabled, oidcEnabled
		s.writeOAuthHTMLStatus(w, http.StatusTooManyRequests, localAuthorizationPage, data)
		return
	}
	if authErr != nil {
		var inputError *localAuthInputError
		switch {
		case errors.Is(authErr, ErrUnauthenticated):
			data := loginPageData(step, "Invalid local credentials.")
			data.Local, data.OIDC = localEnabled, oidcEnabled
			data.Captcha = s.runtime().localPasswords.CaptchaChallenge(localCaptchaActionOAuth)
			s.writeOAuthHTMLStatus(w, http.StatusUnauthorized, localAuthorizationPage, data)
		case errors.Is(authErr, ErrLocalChallengeInvalid), errors.Is(authErr, ErrLocalMFACodeInvalid):
			data := loginPageData(step, authErr.Error())
			data.Local, data.OIDC = localEnabled, oidcEnabled
			s.writeOAuthHTMLStatus(w, http.StatusUnauthorized, localAuthorizationPage, data)
		case errors.As(authErr, &inputError):
			data := loginPageData(step, inputError.Error())
			data.Local, data.OIDC = localEnabled, oidcEnabled
			s.writeOAuthHTMLStatus(w, http.StatusBadRequest, localAuthorizationPage, data)
		default:
			s.writeOAuthLoginError(w, http.StatusInternalServerError, "Local authorization could not be completed.")
		}
		return
	}
	if step.Status != "complete" {
		data := loginPageData(step, "")
		data.Local, data.OIDC = localEnabled, oidcEnabled
		s.writeOAuthHTML(w, localAuthorizationPage, data)
		return
	}
	if err := s.oidcProvider.storage.AuthorizeRequest(r.Context(), requestID, step.Principal, s.localAuthenticationMethods(r.Context(), step.Principal)); err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "OpenID authorization could not be completed.")
		return
	}
	redirect := s.oidcProvider.op.AuthorizationEndpoint().Absolute(s.publicURL(r)) + "/callback?id=" + url.QueryEscape(requestID)
	w.Header().Set("Cache-Control", "no-store")
	if len(step.RecoveryCodes) > 0 {
		data := loginPageData(step, "")
		data.Redirect = redirect
		data.Local, data.OIDC = localEnabled, oidcEnabled
		s.writeOAuthHTML(w, localAuthorizationPage, data)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *Server) localAuthenticationMethods(ctx context.Context, principal Principal) []string {
	methods := []string{"pwd"}
	if s.control != nil {
		if user, err := s.control.LocalUserBySubject(ctx, principal.Subject); err == nil && user.MFAEnabled {
			methods = append(methods, "otp")
		}
	}
	return methods
}

type oauthOIDCContinuation struct {
	RequestID string `json:"request_id"`
}

func (s *Server) localLoginAvailable() bool {
	state := s.runtime()
	return s.control != nil && state.config.Authentication.Local.Login.isEnabled() &&
		state.localPasswords != nil && state.localAuth != nil
}

func (s *Server) oauthLoginMethods() []string {
	methods := []string{}
	state := s.runtime()
	if s.localLoginAvailable() {
		methods = append(methods, "local")
	}
	if state.adminOIDC != nil {
		methods = append(methods, "oidc")
	}
	return methods
}

func (s *Server) startOAuthOIDC(w http.ResponseWriter, r *http.Request, requestID string) {
	rawState, err := randomURLToken(32)
	if err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "Organization sign-in could not be started.")
		return
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "Organization sign-in could not be started.")
		return
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "Organization sign-in could not be started.")
		return
	}
	browserBinding, err := randomURLToken(32)
	if err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "Organization sign-in could not be started.")
		return
	}
	continuation, err := json.Marshal(oauthOIDCContinuation{RequestID: requestID})
	if err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "Organization sign-in could not be started.")
		return
	}
	expires := time.Now().Add(oidcFlowTTL)
	flow := OIDCFlow{Nonce: nonce, PKCEVerifier: verifier, Purpose: oidcPurposeOAuth, Continuation: string(continuation), ExpiresAt: expires}
	if err := s.control.SaveFlow(r.Context(), rawState, browserBinding, flow); err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "Organization sign-in could not be started.")
		return
	}
	http.SetCookie(w, s.oidcFlowCookie(rawState, browserBinding, expires))
	http.Redirect(w, r, s.runtime().adminOIDC.AuthorizationURL(rawState, nonce, verifier), http.StatusFound)
}

func (s *Server) finishOIDCAuthorization(w http.ResponseWriter, r *http.Request, flow OIDCFlow, identity AdminIdentity) {
	requestID, err := s.requestIDFromOIDCFlow(r.Context(), flow)
	if err != nil {
		s.writeOAuthLoginError(w, http.StatusUnauthorized, "The organization sign-in continuation is invalid or has expired.")
		return
	}
	principal := Principal{Issuer: identity.Issuer, Subject: identity.Subject, Name: identity.Name, Email: identity.Email,
		Username: identity.Username, Organization: identity.Organization, Teams: identity.Teams, Roles: identity.Roles,
		RolesFromClaim: identity.RolesFromClaim, RoleClaimSelector: identity.RoleClaimSelector, AuthMethod: "oidc"}
	if err := s.oidcProvider.storage.AuthorizeRequest(r.Context(), requestID, principal, []string{"federated"}); err != nil {
		s.writeOAuthLoginError(w, http.StatusInternalServerError, "OpenID authorization could not be completed.")
		return
	}
	redirect := s.oidcProvider.op.AuthorizationEndpoint().Absolute(s.publicURL(r)) + "/callback?id=" + url.QueryEscape(requestID)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *Server) requestIDFromOIDCFlow(ctx context.Context, flow OIDCFlow) (string, error) {
	var saved oauthOIDCContinuation
	if flow.Purpose != oidcPurposeOAuth || json.Unmarshal([]byte(flow.Continuation), &saved) != nil {
		return "", errors.New("invalid OIDC continuation")
	}
	if saved.RequestID == "" {
		return "", errors.New("invalid OIDC continuation")
	}
	if _, err := s.oidcProvider.storage.AuthRequestByID(ctx, saved.RequestID); err != nil {
		return "", err
	}
	return saved.RequestID, nil
}

func (s *Server) redirectOAuthFailure(w http.ResponseWriter, r *http.Request, flow OIDCFlow, code string) bool {
	requestID, err := s.requestIDFromOIDCFlow(r.Context(), flow)
	if err != nil {
		return false
	}
	request, err := s.oidcProvider.storage.AuthRequestByID(r.Context(), requestID)
	if err != nil {
		return false
	}
	redirect, err := url.Parse(request.GetRedirectURI())
	if err != nil {
		return false
	}
	query := redirect.Query()
	query.Set("error", code)
	query.Set("state", request.GetState())
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
	return true
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
		if value != localAPIScope {
			return nil, errors.New("unsupported scope " + value)
		}
	}
	return values, nil
}

func (s *Server) oauthDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.runtime().config.Authentication.Local.Login.isEnabled() || s.runtime().localAuth == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "local device authorization is unavailable")
		return
	}
	if !requireForm(w, r) {
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	cfg := s.runtime().config.Authentication.Local.Tokens
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
	if s.control == nil || !s.runtime().config.Authentication.Local.Login.isEnabled() || s.runtime().localPasswords == nil {
		s.writeOAuthHTMLStatus(w, http.StatusServiceUnavailable, deviceVerificationPage, localLoginPageData{Device: true, Fatal: true, Error: "Local device authorization is temporarily unavailable."})
		return
	}
	if r.Method == http.MethodGet {
		data := localLoginPageData{Device: true, Local: true, UserCode: r.URL.Query().Get("user_code")}
		data.Captcha = s.runtime().localPasswords.CaptchaChallenge(localCaptchaActionDevice)
		s.writeOAuthHTML(w, deviceVerificationPage, data)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.writeOAuthHTMLStatus(w, http.StatusBadRequest, deviceVerificationPage, localLoginPageData{Device: true, Error: "Invalid verification form."})
		return
	}
	userCode := r.PostForm.Get("user_code")
	step, authErr := s.continueBrowserLocalLogin(r, localAuthPurposeDevice, normalizeUserCode(userCode))
	if challenge, required := captchaChallengeFromError(authErr); required {
		data := loginPageData(step, "Complete human verification before signing in.")
		data.Device, data.Local, data.UserCode, data.Captcha = true, true, userCode, &challenge
		s.writeOAuthHTMLStatus(w, http.StatusForbidden, deviceVerificationPage, data)
		return
	}
	if retryAfter, limited := authenticationRetryAfter(authErr); limited {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter/time.Second))))
		data := loginPageData(step, "Too many authentication attempts. Try again later.")
		data.Device, data.Local, data.UserCode = true, true, userCode
		s.writeOAuthHTMLStatus(w, http.StatusTooManyRequests, deviceVerificationPage, data)
		return
	}
	if authErr != nil {
		var inputError *localAuthInputError
		message := "Could not complete local authorization."
		status := http.StatusInternalServerError
		switch {
		case errors.Is(authErr, ErrUnauthenticated):
			message, status = "Invalid local credentials.", http.StatusUnauthorized
		case errors.Is(authErr, ErrLocalChallengeInvalid), errors.Is(authErr, ErrLocalMFACodeInvalid):
			message, status = authErr.Error(), http.StatusUnauthorized
		case errors.As(authErr, &inputError):
			message, status = inputError.Error(), http.StatusBadRequest
		}
		data := loginPageData(step, message)
		data.Device, data.Local, data.UserCode = true, true, userCode
		if errors.Is(authErr, ErrUnauthenticated) {
			data.Captcha = s.runtime().localPasswords.CaptchaChallenge(localCaptchaActionDevice)
		}
		s.writeOAuthHTMLStatus(w, status, deviceVerificationPage, data)
		return
	}
	if step.Status != "complete" {
		data := loginPageData(step, "")
		data.Device, data.Local, data.UserCode = true, true, userCode
		s.writeOAuthHTML(w, deviceVerificationPage, data)
		return
	}
	principal := step.Principal
	user, err := s.control.LocalUserBySubject(r.Context(), principal.Subject)
	if err != nil || s.control.ApproveDeviceAuthorization(r.Context(), userCode, user) != nil {
		s.writeOAuthHTMLStatus(w, http.StatusBadRequest, deviceVerificationPage, localLoginPageData{Device: true, UserCode: userCode, Error: "The device code is invalid or expired."})
		return
	}
	if len(step.RecoveryCodes) > 0 {
		data := loginPageData(step, "")
		data.Device, data.Local, data.UserCode = true, true, userCode
		s.writeOAuthHTML(w, deviceVerificationPage, data)
		return
	}
	s.writeOAuthHTML(w, deviceVerificationPage, localLoginPageData{Device: true, Approved: true})
}

func (s *Server) continueBrowserLocalLogin(r *http.Request, purpose, binding string) (LocalAuthStep, error) {
	challenge := r.PostForm.Get("challenge_token")
	if challenge != "" {
		if password := r.PostForm.Get("new_password"); password != "" {
			if password != r.PostForm.Get("confirm_password") {
				return LocalAuthStep{Status: localAuthStagePassword, ChallengeToken: challenge}, &localAuthInputError{message: "password confirmation does not match"}
			}
			return s.runtime().localAuth.CompletePasswordChange(r.Context(), challenge, purpose, binding, password)
		}
		return s.runtime().localAuth.CompleteMFA(r.Context(), challenge, purpose, binding, r.PostForm.Get("code"))
	}
	password := r.PostForm.Get("password")
	action := localCaptchaActionOAuth
	if purpose == localAuthPurposeDevice {
		action = localCaptchaActionDevice
	}
	captchaToken := r.PostForm.Get("cf-turnstile-response")
	if s.runtime().config.Authentication.Local.Captcha.Provider == localCaptchaProviderRecaptcha {
		captchaToken = r.PostForm.Get("g-recaptcha-response")
	}
	principal, err := s.runtime().localPasswords.Authenticate(r.Context(), strings.TrimSpace(r.PostForm.Get("username")), password, localCaptchaAttempt{Token: captchaToken, Action: action})
	password = ""
	captchaToken = ""
	if err != nil {
		return LocalAuthStep{}, err
	}
	return s.runtime().localAuth.Begin(r.Context(), principal, purpose, binding)
}

func loginPageData(step LocalAuthStep, message string) localLoginPageData {
	return localLoginPageData{Error: message, Status: step.Status, ChallengeToken: step.ChallengeToken,
		Secret: step.Secret, QRCodeDataURL: template.URL(step.QRCodeDataURL), RecoveryCodes: step.RecoveryCodes} // #nosec G203 -- generated PNG data URL only.
}

func (s *Server) oauthTokenGateway(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if r.PostForm.Get("grant_type") == deviceGrantType {
		s.oauthDeviceToken(w, r)
		return
	}
	s.oidcProvider.handler.ServeHTTP(w, r)
}

func (s *Server) oidcAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			redirectURI = r.PostForm.Get("redirect_uri")
		}
	}
	if parsed, err := url.Parse(redirectURI); err == nil && parsed.Port() == "0" {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	s.oidcProvider.handler.ServeHTTP(w, r)
}

func (s *Server) oauthDeviceToken(w http.ResponseWriter, r *http.Request) {
	if !requireForm(w, r) {
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if clientID != s.runtime().config.Authentication.Local.Tokens.CLIClientID {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}
	if r.PostForm.Get("grant_type") != deviceGrantType {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
		return
	}
	grant, err := s.control.PollDeviceAuthorization(r.Context(), r.PostForm.Get("device_code"), clientID)
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

func (s *Server) oauthIssueTokenPair(w http.ResponseWriter, r *http.Request, grant LocalTokenGrant) {
	principal, err := s.control.grantPrincipal(r.Context(), grant)
	if err != nil || (principal.Issuer == localIdentityIssuer && principal.AuthMethod == "service-credential") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "identity is no longer valid")
		return
	}
	if principal.Issuer != localIdentityIssuer {
		issuer, found := s.oidcConfigForIssuer(principal.Issuer)
		if !found || !issuer.loginConfigured() || strings.TrimSpace(issuer.RoleClaim) != strings.TrimSpace(principal.RoleClaimSelector) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "OIDC identity configuration changed; sign in again")
			return
		}
	}
	grant.Principal, grant.Subject, grant.LocalUserRevision = principal, principal.Subject, principal.LocalUserRevision
	cfg := s.runtime().config.Authentication.Local.Tokens
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
	if err := s.control.SaveTokenPair(r.Context(), accessRaw, accessID, "", "", grant); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist access token")
		return
	}
	response := map[string]any{"access_token": accessRaw, "token_type": "Bearer", "expires_in": int64(cfg.AccessTTL / time.Second), "scope": strings.Join(cleanStrings(grant.Scopes), " ")}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, response)
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

func (s *Server) writeOAuthLoginError(w http.ResponseWriter, status int, message string) {
	s.writeOAuthHTMLStatus(w, status, localAuthorizationPage, localLoginPageData{Error: message, Fatal: true})
}

func (s *Server) writeOAuthHTML(w http.ResponseWriter, page *template.Template, data any) {
	s.writeOAuthHTMLStatus(w, http.StatusOK, page, data)
}

func (s *Server) writeOAuthHTMLStatus(w http.ResponseWriter, status int, page *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	captcha := s.runtime().config.Authentication.Local.Captcha
	scriptSources := localCaptchaScriptSources(captcha)
	if scriptSources == "" {
		scriptSources = " 'none'"
	}
	connectSources := localCaptchaConnectSources(captcha)
	if connectSources == "" {
		connectSources = " 'none'"
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src"+scriptSources+"; style-src 'unsafe-inline'; connect-src"+connectSources+"; frame-src "+localCaptchaFrameSources(captcha)+"; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
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
