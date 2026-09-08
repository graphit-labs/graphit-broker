package broker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed adminui/index.html
var adminHTML []byte

const (
	adminCookieName                  = "graphit_admin_session"
	configuredSecret                 = "[configured-secret]"
	localAPIKeyRoleSource            = "authentication.api_keys.roles"
	localCredentialFingerprintDomain = "graphit-broker/local-admin-credential/v1"
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
		writeError(w, http.StatusServiceUnavailable, "administration_unavailable", "OIDC administration is unavailable", requestID(r.Context()))
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
	if err := s.control.SaveFlow(r.Context(), rawState, OIDCFlow{Nonce: nonce, PKCEVerifier: verifier, ExpiresAt: time.Now().Add(10 * time.Minute)}); err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "could not persist OIDC login", requestID(r.Context()))
		return
	}
	http.Redirect(w, r, state.adminOIDC.AuthorizationURL(rawState, nonce, verifier), http.StatusFound)
}

func (s *Server) adminCallback(w http.ResponseWriter, r *http.Request) {
	if s.control == nil || s.runtime().adminOIDC == nil {
		writeError(w, http.StatusServiceUnavailable, "administration_unavailable", "OIDC administration is unavailable", requestID(r.Context()))
		return
	}
	if oidcError := strings.TrimSpace(r.URL.Query().Get("error")); oidcError != "" {
		writeError(w, http.StatusUnauthorized, "oidc_error", "identity provider rejected administration login", requestID(r.Context()))
		return
	}
	flow, err := s.control.ConsumeFlow(r.Context(), r.URL.Query().Get("state"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_state", "OIDC login state is invalid or expired", requestID(r.Context()))
		return
	}
	state := s.runtime()
	identity, err := state.adminOIDC.Exchange(r.Context(), r.URL.Query().Get("code"), flow.PKCEVerifier, flow.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_identity", "OIDC administration identity is invalid", requestID(r.Context()))
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
	if err != nil || principal.AuthMethod != "api_key" {
		writeError(w, http.StatusUnauthorized, "local_login_failed", "the local broker credentials are invalid", requestID(r.Context()))
		return
	}
	key, found := localAPIKeyByUsername(state.config.Authentication.APIKeys, principal.Username, principal.Subject)
	if !found {
		writeError(w, http.StatusUnauthorized, "local_login_failed", "the local broker credentials are invalid", requestID(r.Context()))
		return
	}
	session := AdminSession{Issuer: principal.Issuer, Subject: principal.Subject, Username: principal.Username,
		Organization: principal.Organization, Teams: principal.Teams, Name: principal.Username,
		Roles: principal.Roles, RolesFromClaim: len(principal.Roles) > 0, RoleClaimSelector: localAPIKeyRoleSource,
		CredentialFingerprint: localCredentialFingerprint(key, state.config.Administration.TokenPepper)}
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
	redirect, _ := url.Parse(s.runtime().config.Administration.OIDC.RedirectURL)
	publicURL, _ := url.Parse(s.runtime().config.Server.PublicURL)
	return &http.Cookie{Name: adminCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: (redirect != nil && redirect.Scheme == "https") || (publicURL != nil && publicURL.Scheme == "https"), SameSite: http.SameSiteLaxMode,
		Expires: expires.UTC(), MaxAge: int(time.Until(expires).Seconds())}
}

func (s *Server) adminLoginOptions(w http.ResponseWriter, _ *http.Request) {
	state := s.runtime()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]bool{
		"oidc":  state.adminOIDC != nil,
		"local": len(state.config.Authentication.APIKeys) > 0,
	})
}

func (s *Server) adminSession(w http.ResponseWriter, r *http.Request) {
	session := adminSessionFromContext(r.Context())
	roles, permissions, err := s.adminRolesAndPermissions(r.Context(), session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authorization_failed", "could not read administration roles", requestID(r.Context()))
		return
	}
	roleSource := "database"
	if s.sessionRolesAuthoritative(session) {
		roleSource = "claim"
		if strings.HasPrefix(session.Issuer, "apikey:") {
			roleSource = "configuration"
		}
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
	if strings.HasPrefix(session.Issuer, "apikey:") {
		authMethod = "api_key"
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
	localToken := strings.HasPrefix(session.Issuer, "apikey:")
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
	for _, key := range s.runtime().config.Authentication.APIKeys {
		principals = append(principals, principalSummary{Type: "api_key", ID: key.Subject, Username: key.Username, Organization: key.Organization, Teams: append([]string(nil), key.Teams...)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"principals": principals})
}

func (s *Server) adminRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.control.Roles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "roles_read_failed", "could not list roles", requestID(r.Context()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles, "actions": adminActions})
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
	if err := s.control.SetRole(r.Context(), AdminRole{Name: r.PathValue("role"), Permissions: request.Permissions}); err != nil {
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
				writeError(w, http.StatusUnauthorized, "admin_unauthorized", "OIDC administration login is required", requestID(r.Context()))
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !constantEqual(session.CSRFToken, r.Header.Get("X-CSRF-Token")) {
				writeError(w, http.StatusForbidden, "csrf_failed", "CSRF token is invalid", requestID(r.Context()))
				return
			}
		} else if raw := bearerToken(r); raw != "" {
			provider := s.runtime().adminOIDC
			if provider == nil {
				writeError(w, http.StatusUnauthorized, "admin_unauthorized", "valid UI credentials are required", requestID(r.Context()))
				return
			}
			identity, err := provider.Verify(r.Context(), raw)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "admin_unauthorized", "valid administration OIDC credentials are required", requestID(r.Context()))
				return
			}
			session = AdminSession{Issuer: identity.Issuer, Subject: identity.Subject, Name: identity.Name,
				Email: identity.Email, Username: identity.Username, Organization: identity.Organization, Teams: identity.Teams,
				Roles: identity.Roles, RolesFromClaim: identity.RolesFromClaim, RoleClaimSelector: identity.RoleClaimSelector}
		} else {
			writeError(w, http.StatusUnauthorized, "admin_unauthorized", "OIDC administration login is required", requestID(r.Context()))
			return
		}
		if s.sessionNeedsRoleRefresh(session) {
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
	return s.control.Authorize(ctx, session.Subject, action)
}

func (s *Server) adminRolesAndPermissions(ctx context.Context, session AdminSession) ([]string, []string, error) {
	if s.sessionRolesAuthoritative(session) {
		roles := cleanStrings(session.Roles)
		permissions, err := s.control.RolePermissions(ctx, roles)
		return roles, permissions, err
	}
	roles, err := s.control.SubjectRoles(ctx, session.Subject)
	if err != nil {
		return nil, nil, err
	}
	permissions, err := s.control.SubjectPermissions(ctx, session.Subject)
	return roles, permissions, err
}

func (s *Server) sessionNeedsRoleRefresh(session AdminSession) bool {
	if strings.HasPrefix(session.Issuer, "apikey:") {
		username := strings.TrimPrefix(session.Issuer, "apikey:")
		key, found := localAPIKeyByUsername(s.runtime().config.Authentication.APIKeys, username, session.Subject)
		if !found || !constantEqual(session.CredentialFingerprint, localCredentialFingerprint(key, s.runtime().config.Administration.TokenPepper)) {
			return true
		}
		roles := cleanStrings(key.Roles)
		if len(roles) == 0 {
			return session.RolesFromClaim
		}
		return !session.RolesFromClaim || strings.TrimSpace(session.RoleClaimSelector) != localAPIKeyRoleSource ||
			!slices.Equal(roles, cleanStrings(session.Roles))
	}
	selector := strings.TrimSpace(s.runtime().config.Administration.OIDC.RoleClaim)
	return selector != "" &&
		(!session.RolesFromClaim || selector != strings.TrimSpace(session.RoleClaimSelector))
}

func (s *Server) sessionRolesAuthoritative(session AdminSession) bool {
	if strings.HasPrefix(session.Issuer, "apikey:") {
		return session.RolesFromClaim && strings.TrimSpace(session.RoleClaimSelector) == localAPIKeyRoleSource
	}
	selector := strings.TrimSpace(s.runtime().config.Administration.OIDC.RoleClaim)
	return selector != "" && session.RolesFromClaim &&
		selector == strings.TrimSpace(session.RoleClaimSelector)
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
	cfg.Authentication.APIKeys = append([]APIKeyConfig(nil), cfg.Authentication.APIKeys...)
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
	if cfg.Administration.TokenPepper != "" {
		cfg.Administration.TokenPepper = configuredSecret
	}
	if cfg.Administration.OIDC.ClientSecret != "" {
		cfg.Administration.OIDC.ClientSecret = configuredSecret
	}
	for i := range cfg.Authentication.APIKeys {
		if cfg.Authentication.APIKeys[i].PasswordHash != "" {
			cfg.Authentication.APIKeys[i].PasswordHash = configuredSecret
		}
		if cfg.Authentication.APIKeys[i].Pepper != "" {
			cfg.Authentication.APIKeys[i].Pepper = configuredSecret
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

func localAPIKeyByUsername(keys []APIKeyConfig, username, subject string) (APIKeyConfig, bool) {
	for _, key := range keys {
		if key.Username == username && key.Subject == subject {
			return key, true
		}
	}
	return APIKeyConfig{}, false
}

func localCredentialFingerprint(key APIKeyConfig, tokenPepper string) string {
	mac := hmac.New(sha256.New, []byte(tokenPepper))
	_, _ = mac.Write([]byte(localCredentialFingerprintDomain))
	writeField := func(label, value string) {
		_, _ = fmt.Fprintf(mac, "\x00%d:%s\x00%d:", len(label), label, len(value))
		_, _ = mac.Write([]byte(value))
	}
	writeField("username", key.Username)
	writeField("subject", key.Subject)
	writeField("password_hash", key.PasswordHash)
	writeField("pepper", key.Pepper)
	writeField("organization", key.Organization)
	for _, team := range key.Teams {
		writeField("team", team)
	}
	for _, role := range key.Roles {
		writeField("role", role)
	}
	return hex.EncodeToString(mac.Sum(nil))
}
