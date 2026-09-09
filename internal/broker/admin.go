package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed adminui/index.html
var adminHTML []byte

const (
	adminCookieName  = "graphit_admin_session"
	configuredSecret = "[configured-secret]"
	oidcFlowTTL      = 10 * time.Minute
)

type adminContextKey string

const adminSessionKey adminContextKey = "admin_session"

func (s *Server) adminPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(adminHTML)
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	if s.control == nil || state.adminOIDC == nil {
		writeError(w, http.StatusServiceUnavailable, "administration_unavailable", "OIDC browser login is unavailable", requestID(r.Context()))
		return
	}
	rawState, err := randomURLToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not start OIDC login", requestID(r.Context()))
		return
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not start OIDC login", requestID(r.Context()))
		return
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not start OIDC login", requestID(r.Context()))
		return
	}
	browserBinding, err := randomURLToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not start OIDC login", requestID(r.Context()))
		return
	}
	expires := time.Now().Add(oidcFlowTTL)
	if err := s.control.SaveFlow(r.Context(), rawState, browserBinding, OIDCFlow{Nonce: nonce, PKCEVerifier: verifier, ExpiresAt: expires}); err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not persist OIDC login", requestID(r.Context()))
		return
	}
	http.SetCookie(w, s.oidcFlowCookie(rawState, browserBinding, expires))
	http.Redirect(w, r, state.adminOIDC.AuthorizationURL(rawState, nonce, verifier), http.StatusFound)
}

func (s *Server) adminCallback(w http.ResponseWriter, r *http.Request) {
	if s.control == nil || s.runtime().adminOIDC == nil {
		writeError(w, http.StatusServiceUnavailable, "administration_unavailable", "OIDC browser login is unavailable", requestID(r.Context()))
		return
	}
	rawState := r.URL.Query().Get("state")
	flowCookie, err := r.Cookie(s.oidcFlowCookieName(rawState))
	if err != nil || flowCookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "invalid_state", "OIDC login state is invalid or expired", requestID(r.Context()))
		return
	}
	http.SetCookie(w, s.oidcFlowCookie(rawState, "", time.Unix(1, 0)))
	if oidcError := strings.TrimSpace(r.URL.Query().Get("error")); oidcError != "" {
		writeError(w, http.StatusUnauthorized, "oidc_error", "identity provider rejected administration login", requestID(r.Context()))
		return
	}
	flow, err := s.control.ConsumeFlow(r.Context(), rawState, flowCookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_state", "OIDC login state is invalid or expired", requestID(r.Context()))
		return
	}
	state := s.runtime()
	identity, err := state.adminOIDC.Exchange(r.Context(), r.URL.Query().Get("code"), flow.PKCEVerifier, flow.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_identity", "OIDC identity is invalid", requestID(r.Context()))
		return
	}
	session := AdminSession{Issuer: identity.Issuer, Subject: identity.Subject,
		Name: identity.Name, Email: identity.Email, Username: identity.Username, Organization: identity.Organization,
		Teams: identity.Teams, Roles: identity.Roles, RolesFromClaim: identity.RolesFromClaim, RoleClaimSelector: identity.RoleClaimSelector}
	allowed, err := s.authorizeAdmin(r.Context(), session, "session.read")
	if err != nil || !allowed {
		writeError(w, http.StatusForbidden, "admin_forbidden", "administration access denied", requestID(r.Context()))
		return
	}
	if !s.createAdminSession(w, r, session) {
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (s *Server) adminLocalLogin(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		writeError(w, http.StatusServiceUnavailable, "administration_unavailable", "administration is unavailable", requestID(r.Context()))
		return
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "content_type_required", "local login requires application/json", requestID(r.Context()))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || request.Password == "" {
		request.Password = ""
		writeError(w, http.StatusUnauthorized, "local_login_failed", "the local broker credentials are invalid", requestID(r.Context()))
		return
	}
	credential := request.Username + ":" + request.Password
	request.Password = ""
	state := s.runtime()
	principal, err := state.authenticator.Authenticate(r.Context(), credential)
	credential = ""
	if retryAfter, limited := authenticationRetryAfter(err); limited {
		writeAuthenticationRateLimit(w, r, retryAfter)
		return
	}
	if err != nil || principal.AuthMethod != "local" {
		writeError(w, http.StatusUnauthorized, "local_login_failed", "the local broker credentials are invalid", requestID(r.Context()))
		return
	}
	user, err := s.control.LocalUserByUsername(r.Context(), principal.Username)
	if err != nil || !user.Enabled || user.Subject != principal.Subject {
		writeError(w, http.StatusUnauthorized, "local_login_failed", "the local broker credentials are invalid", requestID(r.Context()))
		return
	}
	session := AdminSession{Issuer: principal.Issuer, Subject: principal.Subject, Username: principal.Username,
		Organization: principal.Organization, Teams: principal.Teams, Name: principal.Name, Email: principal.Email,
		LocalUserRevision: user.Revision}
	allowed, err := s.authorizeAdmin(r.Context(), session, "session.read")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authorization_failed", "could not authorize local login", requestID(r.Context()))
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "admin_forbidden", "UI access is not assigned to this local identity", requestID(r.Context()))
		return
	}
	if !s.createAdminSession(w, r, session) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createAdminSession(w http.ResponseWriter, r *http.Request, session AdminSession) bool {
	token, err := randomURLToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not create UI session", requestID(r.Context()))
		return false
	}
	csrf, err := randomURLToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not create UI session", requestID(r.Context()))
		return false
	}
	expires := time.Now().Add(s.runtime().config.Administration.SessionTTL)
	session.CSRFToken = csrf
	session.ExpiresAt = expires
	if err := s.control.CreateSession(r.Context(), token, session); err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not persist UI session", requestID(r.Context()))
		return false
	}
	http.SetCookie(w, s.adminCookie(token, expires))
	return true
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(adminCookieName)
	if err == nil && s.control != nil {
		if session, sessionErr := s.control.Session(r.Context(), cookie.Value); sessionErr == nil && !constantEqual(session.CSRFToken, r.Header.Get("X-CSRF-Token")) {
			writeError(w, http.StatusForbidden, "csrf_failed", "CSRF token is invalid", requestID(r.Context()))
			return
		}
		_ = s.control.DeleteSession(r.Context(), cookie.Value)
	}
	http.SetCookie(w, s.adminCookie("", time.Unix(1, 0)))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: adminCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: s.secureAdminCookies(), SameSite: http.SameSiteLaxMode,
		Expires: expires.UTC(), MaxAge: cookieMaxAge(expires)}
}

func (s *Server) oidcFlowCookie(rawState, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: s.oidcFlowCookieName(rawState), Value: value, Path: "/", HttpOnly: true,
		Secure: s.secureAdminCookies(), SameSite: http.SameSiteLaxMode,
		Expires: expires.UTC(), MaxAge: cookieMaxAge(expires)}
}

func (s *Server) oidcFlowCookieName(rawState string) string {
	digest := sha256.Sum256([]byte(rawState))
	prefix := "graphit_oidc_flow_"
	if s.secureAdminCookies() {
		prefix = "__Host-" + prefix
	}
	return prefix + hex.EncodeToString(digest[:])
}

func (s *Server) secureAdminCookies() bool {
	login, _ := browserLoginOIDC(s.runtime().config.Authentication.OIDC)
	redirect, _ := url.Parse(login.RedirectURL)
	publicURL, _ := url.Parse(s.runtime().config.Server.PublicURL)
	return (redirect != nil && redirect.Scheme == "https") || (publicURL != nil && publicURL.Scheme == "https")
}

func cookieMaxAge(expires time.Time) int {
	if !expires.After(time.Now()) {
		return -1
	}
	return int(time.Until(expires).Seconds())
}

func (s *Server) adminLoginOptions(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	localCount := 0
	if s.control != nil {
		localCount, _ = s.control.LocalUserCount(r.Context())
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]bool{
		"oidc":  state.adminOIDC != nil,
		"local": localCount > 0,
	})
}

func (s *Server) adminSession(w http.ResponseWriter, r *http.Request) {
	session := adminSessionFromContext(r.Context())
	roles, permissions, err := s.adminRolesAndPermissions(r.Context(), session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authorization_failed", "could not read roles", requestID(r.Context()))
		return
	}
	roleSource := "database"
	if s.sessionRolesAuthoritative(session) {
		roleSource = "claim"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": session.Subject, "name": session.Name, "email": session.Email,
		"username": session.Username, "organization": session.Organization, "teams": session.Teams,
		"roles": roles, "role_source": roleSource,
		"permissions": permissions,
		"csrf_token":  session.CSRFToken,
	})
}

type userProject struct {
	ID           string   `json:"id"`
	Capabilities []string `json:"capabilities"`
}

func (s *Server) adminProjects(w http.ResponseWriter, r *http.Request) {
	session := adminSessionFromContext(r.Context())
	authMethod := "oidc"
	if session.Issuer == localIdentityIssuer {
		authMethod = "local"
	}
	principal := Principal{Issuer: session.Issuer, Subject: session.Subject, Username: session.Username,
		Organization: session.Organization, Teams: session.Teams, AuthMethod: authMethod}
	document, err := s.runtime().acl.ResolveHubAccess(r.Context(), principal)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "projects_read_failed", "could not resolve accessible projects", requestID(r.Context()))
		return
	}
	capabilities := map[string]map[string]struct{}{}
	allProjects := false
	for _, rule := range document.Rules {
		projects := rule.Projects
		if len(projects) == 0 {
			projects = []string{"*"}
		}
		for _, project := range projects {
			project = strings.TrimSpace(project)
			if project == "*" {
				allProjects = true
				continue
			}
			if capabilities[project] == nil {
				capabilities[project] = map[string]struct{}{}
			}
			for _, capability := range rule.Capabilities {
				capabilities[project][capability] = struct{}{}
			}
		}
	}
	ids := make([]string, 0, len(capabilities))
	for id := range capabilities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	projects := make([]userProject, 0, len(ids))
	for _, id := range ids {
		values := make([]string, 0, len(capabilities[id]))
		for capability := range capabilities[id] {
			values = append(values, capability)
		}
		sort.Strings(values)
		projects = append(projects, userProject{ID: id, Capabilities: values})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"projects": projects, "all_projects": allProjects, "authorization_revision": document.Revision,
		"provider_command": s.graphitProviderCommand(session),
	})
}

func (s *Server) graphitProviderCommand(session AdminSession) string {
	cfg := s.runtime().config
	localToken := session.Issuer == localIdentityIssuer
	username := session.Username
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Server.PublicURL), "/")
	if endpoint == "" {
		endpoint = "<BROKER_URL>"
	}
	providerName := cfg.Administration.CLI.ProviderName
	profileName := cfg.Administration.CLI.ProfileName
	if providerName == "" {
		providerName = "organization-broker"
	}
	if profileName == "" {
		profileName = providerName
	}
	base := "graphit --non-interactive provider add " + shellArgument(providerName)
	if localToken {
		if username == "" {
			username = "<USERNAME>"
		}
		command := base + " --type local --broker-endpoint " + shellArgument(endpoint) +
			" --embedding-mode broker --rerank-mode broker\n\n" +
			"graphit --non-interactive login --provider " + shellArgument(providerName) + " --profile " + shellArgument(profileName) + " --username " +
			shellArgument(username) + " --broker-key \"$GRAPHIT_BROKER_KEY\""
		if session.Organization != "" {
			command += " --organization " + shellArgument(session.Organization)
		}
		for _, team := range session.Teams {
			command += " --team " + shellArgument(team)
		}
		return command
	}
	if len(cfg.Authentication.OIDC) == 0 {
		return base + " --type local \\\n  --broker-endpoint " + shellArgument(endpoint) + " \\\n  --embedding-mode broker --rerank-mode broker"
	}
	issuer := cfg.Authentication.OIDC[0]
	for _, candidate := range cfg.Authentication.OIDC {
		if strings.TrimRight(candidate.Issuer, "/") == strings.TrimRight(session.Issuer, "/") {
			issuer = candidate
			break
		}
	}
	scopes := cleanStrings(append([]string{"openid", "profile", "offline_access"}, issuer.RequiredScopes...))
	clientID := strings.TrimSpace(cfg.Administration.CLI.OIDCClientID)
	if clientID == "" {
		clientID = "<GRAPHIT_OIDC_CLIENT_ID>"
	}
	parts := []string{
		base + " --type oidc",
		"  --issuer " + shellArgument(strings.TrimRight(issuer.Issuer, "/")),
		"  --client-id " + shellArgument(clientID),
		"  --token-auth-method none",
		"  --scopes " + shellArgument(strings.Join(scopes, ",")),
	}
	if cfg.Administration.CLI.OIDCRedirectURI != "" {
		parts = append(parts, "  --redirect-uri "+shellArgument(cfg.Administration.CLI.OIDCRedirectURI))
	}
	if issuer.UsernameClaim != "" {
		parts = append(parts, "  --username-claim "+shellArgument(issuer.UsernameClaim))
	}
	if issuer.OrganizationClaim != "" {
		parts = append(parts, "  --organization-claim "+shellArgument(issuer.OrganizationClaim))
	}
	if issuer.TeamsClaim != "" {
		parts = append(parts, "  --teams-claim "+shellArgument(issuer.TeamsClaim))
	}
	parts = append(parts,
		"  --broker-endpoint "+shellArgument(endpoint),
		"  --broker-token-strategy relay",
	)
	if len(issuer.Audiences) > 0 {
		parts = append(parts, "  --broker-audience "+shellArgument(issuer.Audiences[0]))
	}
	parts = append(parts, "  --embedding-mode broker --rerank-mode broker\n\ngraphit login --provider "+shellArgument(providerName)+" --profile "+shellArgument(profileName))
	return strings.Join(parts, " \\\n")
}

func shellArgument(value string) string {
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (s *Server) adminConfig(w http.ResponseWriter, r *http.Request) {
	redacted := redactConfig(s.runtime().config)
	encoded, err := yaml.Marshal(redacted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "configuration_encode_failed", "could not encode broker configuration", requestID(r.Context()))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"source": "deployment", "restart_required": true, "yaml": string(encoded)})
}

func (s *Server) adminGrants(w http.ResponseWriter, r *http.Request) {
	document, err := s.control.ResourceGrants(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "grants_read_failed", "could not read resource grants", requestID(r.Context()))
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("ETag", configETag(document.Revision))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, document)
		return
	}
	expected, err := parseConfigETag(r.Header.Get("If-Match"))
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "precondition_required", "If-Match with the current configuration revision is required", requestID(r.Context()))
		return
	}
	var grant ACLRuleConfig
	if err := s.decodeRequest(w, r, &grant); err != nil {
		return
	}
	updated, err := s.control.CreateResourceGrant(r.Context(), expected, grant, s.runtime().config.Services.S3)
	if errors.Is(err, ErrRevisionConflict) {
		writeError(w, http.StatusConflict, "revision_conflict", "resource grants changed; reload before saving", requestID(r.Context()))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error(), requestID(r.Context()))
		return
	}
	w.Header().Set("ETag", configETag(updated.Revision))
	writeJSON(w, http.StatusCreated, updated)
}

func (s *Server) adminGrant(w http.ResponseWriter, r *http.Request) {
	expected, err := parseConfigETag(r.Header.Get("If-Match"))
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "precondition_required", "If-Match with the current grants revision is required", requestID(r.Context()))
		return
	}
	var updated PolicyDocument
	if r.Method == http.MethodDelete {
		updated, err = s.control.DeleteResourceGrant(r.Context(), expected, r.PathValue("grant"), s.runtime().config.Services.S3)
	} else {
		var grant ACLRuleConfig
		if decodeErr := s.decodeRequest(w, r, &grant); decodeErr != nil {
			return
		}
		updated, err = s.control.UpdateResourceGrant(r.Context(), expected, r.PathValue("grant"), grant, s.runtime().config.Services.S3)
	}
	if errors.Is(err, ErrRevisionConflict) {
		writeError(w, http.StatusConflict, "revision_conflict", "resource grants changed; reload before saving", requestID(r.Context()))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "grant_write_failed", err.Error(), requestID(r.Context()))
		return
	}
	w.Header().Set("ETag", configETag(updated.Revision))
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) adminPrincipals(w http.ResponseWriter, r *http.Request) {
	type principalSummary struct {
		Type         string   `json:"type"`
		ID           string   `json:"id"`
		Username     string   `json:"username,omitempty"`
		Organization string   `json:"organization,omitempty"`
		Teams        []string `json:"teams,omitempty"`
	}
	principals := []principalSummary{{Type: "anonymous", ID: "anonymous"}, {Type: "authenticated", ID: "authenticated"}}
	users, err := s.control.LocalUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "principals_read_failed", "could not list local principals", requestID(r.Context()))
		return
	}
	for _, user := range users {
		principals = append(principals, principalSummary{Type: "local", ID: user.Subject, Username: user.Username, Organization: user.Organization, Teams: append([]string(nil), user.Teams...)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"principals": principals})
}

func (s *Server) adminRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.control.Roles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "roles_read_failed", "could not list roles", requestID(r.Context()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles, "actions": systemActions})
}

func (s *Server) adminRole(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		if err := s.control.DeleteRole(r.Context(), r.PathValue("role")); err != nil {
			writeError(w, http.StatusBadRequest, "role_delete_failed", err.Error(), requestID(r.Context()))
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var request struct {
		Permissions []string `json:"permissions"`
	}
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	if err := s.control.SetRole(r.Context(), Role{Name: r.PathValue("role"), Permissions: request.Permissions}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_role", err.Error(), requestID(r.Context()))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminAssignments(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		assignments, err := s.control.Assignments(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "assignments_read_failed", "could not list role assignments", requestID(r.Context()))
			return
		}
		count, _ := s.control.AssignmentCount(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"assignments": assignments, "bootstrap_only": count == 0})
		return
	}
	var request struct {
		Subject string `json:"subject"`
		Role    string `json:"role"`
	}
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	var err error
	if r.Method == http.MethodPost {
		err = s.control.AssignRole(r.Context(), request.Subject, request.Role)
	} else {
		err = s.control.RevokeRole(r.Context(), request.Subject, request.Role)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "assignment_failed", err.Error(), requestID(r.Context()))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type localUserRequest struct {
	Username     string   `json:"username"`
	Subject      string   `json:"subject"`
	Password     string   `json:"password"`
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	Organization string   `json:"organization"`
	Teams        []string `json:"teams"`
	Roles        []string `json:"roles"`
	Enabled      *bool    `json:"enabled"`
}

func (s *Server) adminLocalUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		users, err := s.control.LocalUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "users_read_failed", "could not list local users", requestID(r.Context()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
		return
	}
	var request localUserRequest
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	user, err := s.localUserFromRequest(request, true)
	if err == nil {
		err = s.control.CreateLocalUser(r.Context(), user)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "user_create_failed", err.Error(), requestID(r.Context()))
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) adminLocalUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	if r.Method == http.MethodDelete {
		if err := s.control.DeleteLocalUser(r.Context(), username); err != nil {
			writeError(w, http.StatusBadRequest, "user_delete_failed", err.Error(), requestID(r.Context()))
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var request localUserRequest
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	user, err := s.localUserFromRequest(request, false)
	if err == nil {
		err = s.control.UpdateLocalUser(r.Context(), username, user)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "user_update_failed", err.Error(), requestID(r.Context()))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) localUserFromRequest(request localUserRequest, passwordRequired bool) (LocalUser, error) {
	password := []byte(request.Password)
	request.Password = ""
	defer clear(password)
	var passwordHash string
	var err error
	if len(password) > 0 {
		passwordHash, err = HashPassword(password, []byte(s.runtime().config.Authentication.TokenPepper))
		if err != nil {
			return LocalUser{}, err
		}
	} else if passwordRequired {
		return LocalUser{}, errors.New("local user password is required")
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	return LocalUser{Username: strings.TrimSpace(request.Username), Subject: strings.TrimSpace(request.Subject),
		PasswordHash: passwordHash, Name: strings.TrimSpace(request.Name), Email: strings.TrimSpace(request.Email),
		Organization: strings.TrimSpace(request.Organization), Teams: cleanStrings(request.Teams),
		Roles: cleanStrings(request.Roles), Enabled: enabled}, nil
}

func (s *Server) requireAdministration(action string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.control == nil {
			writeError(w, http.StatusServiceUnavailable, "administration_unavailable", "administration is unavailable", requestID(r.Context()))
			return
		}
		var session AdminSession
		cookie, cookieErr := r.Cookie(adminCookieName)
		if cookieErr == nil && cookie.Value != "" {
			var err error
			session, err = s.control.Session(r.Context(), cookie.Value)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "admin_unauthorized", "valid broker login is required", requestID(r.Context()))
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !constantEqual(session.CSRFToken, r.Header.Get("X-CSRF-Token")) {
				writeError(w, http.StatusForbidden, "csrf_failed", "CSRF token is invalid", requestID(r.Context()))
				return
			}
		} else if raw := bearerToken(r); raw != "" {
			principal, err := s.runtime().authenticator.Authenticate(r.Context(), raw)
			if err != nil {
				if retryAfter, limited := authenticationRetryAfter(err); limited {
					writeAuthenticationRateLimit(w, r, retryAfter)
					return
				}
				writeError(w, http.StatusUnauthorized, "admin_unauthorized", "valid broker credentials are required", requestID(r.Context()))
				return
			}
			session = AdminSession{Issuer: principal.Issuer, Subject: principal.Subject, Name: principal.Name, Email: principal.Email,
				Username: principal.Username, Organization: principal.Organization, Teams: principal.Teams,
				Roles: principal.Roles, RolesFromClaim: principal.RolesFromClaim, RoleClaimSelector: principal.RoleClaimSelector,
				LocalUserRevision: principal.LocalUserRevision}
		} else {
			writeError(w, http.StatusUnauthorized, "admin_unauthorized", "valid broker credentials are required", requestID(r.Context()))
			return
		}
		if s.sessionNeedsRoleRefresh(r.Context(), session) {
			writeError(w, http.StatusUnauthorized, "admin_unauthorized", "administration login must be refreshed to load current roles", requestID(r.Context()))
			return
		}
		allowed, err := s.authorizeAdmin(r.Context(), session, action)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "authorization_failed", "could not authorize administration request", requestID(r.Context()))
			return
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "admin_forbidden", "administration action is not permitted", requestID(r.Context()))
			return
		}
		ctx := context.WithValue(r.Context(), adminSessionKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authorizeAdmin(ctx context.Context, session AdminSession, action string) (bool, error) {
	if s.sessionRolesAuthoritative(session) {
		return s.control.AuthorizeRoles(ctx, session.Roles, action)
	}
	return s.control.Authorize(ctx, canonicalSubject(session.Issuer, session.Subject), action)
}

func (s *Server) adminRolesAndPermissions(ctx context.Context, session AdminSession) ([]string, []string, error) {
	if s.sessionRolesAuthoritative(session) {
		roles := cleanStrings(session.Roles)
		permissions, err := s.control.RolePermissions(ctx, roles)
		return roles, permissions, err
	}
	canonical := canonicalSubject(session.Issuer, session.Subject)
	roles, err := s.control.SubjectRoles(ctx, canonical)
	if err != nil {
		return nil, nil, err
	}
	permissions, err := s.control.SubjectPermissions(ctx, canonical)
	return roles, permissions, err
}

func (s *Server) sessionNeedsRoleRefresh(ctx context.Context, session AdminSession) bool {
	if session.Issuer == localIdentityIssuer {
		user, err := s.control.LocalUserByUsername(ctx, session.Username)
		return err != nil || !user.Enabled || user.Subject != session.Subject || user.Revision != session.LocalUserRevision
	}
	cfg, found := s.oidcConfigForIssuer(session.Issuer)
	if !found {
		return true
	}
	selector := strings.TrimSpace(cfg.RoleClaim)
	return selector != "" &&
		(!session.RolesFromClaim || selector != strings.TrimSpace(session.RoleClaimSelector))
}

func (s *Server) sessionRolesAuthoritative(session AdminSession) bool {
	if session.Issuer == localIdentityIssuer {
		return false
	}
	cfg, found := s.oidcConfigForIssuer(session.Issuer)
	if !found {
		return false
	}
	selector := strings.TrimSpace(cfg.RoleClaim)
	return selector != "" && session.RolesFromClaim &&
		selector == strings.TrimSpace(session.RoleClaimSelector)
}

func canonicalSubject(issuer, subject string) string {
	return strings.TrimRight(strings.TrimSpace(issuer), "/") + "|" + strings.TrimSpace(subject)
}

func (s *Server) oidcConfigForIssuer(issuer string) (OIDCIssuerConfig, bool) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	for _, cfg := range s.runtime().config.Authentication.OIDC {
		if strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/") == issuer {
			return cfg, true
		}
	}
	return OIDCIssuerConfig{}, false
}

func adminSessionFromContext(ctx context.Context) AdminSession {
	session, _ := ctx.Value(adminSessionKey).(AdminSession)
	return session
}

func constantEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func configETag(revision uint64) string { return `"` + strconv.FormatUint(revision, 10) + `"` }

func parseConfigETag(value string) (uint64, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "W/"))
	value = strings.Trim(value, `"`)
	if value == "" {
		return 0, errors.New("empty ETag")
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil || revision == 0 {
		return 0, fmt.Errorf("invalid configuration ETag")
	}
	return revision, nil
}

func redactConfig(cfg Config) Config {
	cfg.Authentication.OIDC = append([]OIDCIssuerConfig(nil), cfg.Authentication.OIDC...)
	if cfg.Services.S3.Routes != nil {
		routes := make(map[string]S3RouteConfig, len(cfg.Services.S3.Routes))
		for name, route := range cfg.Services.S3.Routes {
			routes[name] = route
		}
		cfg.Services.S3.Routes = routes
	}
	if cfg.Database.DSN != "" {
		cfg.Database.DSN = configuredSecret
	}
	if cfg.Authentication.TokenPepper != "" {
		cfg.Authentication.TokenPepper = configuredSecret
	}
	for i := range cfg.Authentication.OIDC {
		if cfg.Authentication.OIDC[i].ClientSecret != "" {
			cfg.Authentication.OIDC[i].ClientSecret = configuredSecret
		}
	}
	if cfg.Services.Embeddings.Upstream.APIKey != "" {
		cfg.Services.Embeddings.Upstream.APIKey = configuredSecret
	}
	if cfg.Services.Rerank.Upstream.APIKey != "" {
		cfg.Services.Rerank.Upstream.APIKey = configuredSecret
	}
	for name, route := range cfg.Services.S3.Routes {
		if route.SecretAccessKey != "" {
			route.SecretAccessKey = configuredSecret
			cfg.Services.S3.Routes[name] = route
		}
	}
	return cfg
}
