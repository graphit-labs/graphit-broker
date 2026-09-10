package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type runtimeState struct {
	config         Config
	authenticator  Authenticator
	localPasswords *localPasswordAuthenticator
	localAuth      *localAuthenticationService
	acl            *ACL
	ai             *AIService
	s3Credentials  S3CredentialService
	adminOIDC      AdminIdentityProvider
}

type Server struct {
	state        atomic.Pointer[runtimeState]
	control      *ControlStore
	oidcProvider *brokerOIDCProvider
	handler      http.Handler
	ready        atomic.Bool
}

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	principalKey contextKey = "principal"
)

func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	return newServerWithFactory(ctx, cfg, NewAdminIdentityProvider)
}

func newServerWithFactory(ctx context.Context, cfg Config, factory func(context.Context, OIDCIssuerConfig) (AdminIdentityProvider, error)) (*Server, error) {
	control, err := OpenControlStore(cfg.Database, cfg.Authentication.TokenPepper)
	if err != nil {
		return nil, err
	}
	runtime, err := buildRuntime(ctx, cfg, factory, control)
	if err != nil {
		if control != nil {
			_ = control.Close()
		}
		return nil, err
	}
	s, err := newServerFromRuntime(runtime, control)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	return s, nil
}

func buildRuntime(ctx context.Context, cfg Config, factory func(context.Context, OIDCIssuerConfig) (AdminIdentityProvider, error), grants ResourceGrantReader) (*runtimeState, error) {
	if cfg.Authentication.Local.Login.Enabled == nil {
		enabled := cfg.Administration.Enabled
		cfg.Authentication.Local.Login.Enabled = &enabled
	}
	cfg.Authentication.Local.RateLimit.setDefaults()
	cfg.Authentication.Local.Captcha.setDefaults()
	cfg.Authentication.Local.MFA.setDefaults()
	cfg.Authentication.Local.Tokens.setDefaults()
	if cfg.Administration.CookieSecure == nil {
		secure := true
		cfg.Administration.CookieSecure = &secure
	}
	localUsers, _ := grants.(localUserReader)
	localTokens, _ := grants.(localTokenReader)
	authenticator, err := NewAuthenticator(ctx, cfg.Authentication, localTokens)
	if err != nil {
		return nil, err
	}
	control, _ := grants.(*ControlStore)
	var localPasswords *localPasswordAuthenticator
	var localAuth *localAuthenticationService
	if cfg.Authentication.Local.Login.isEnabled() {
		localPasswords, err = newLocalPasswordAuthenticator(ctx, cfg.Authentication, localUsers, cfg.Server.PublicURL)
		if err != nil {
			return nil, err
		}
		localAuth, err = newLocalAuthenticationService(cfg.Authentication, control, localPasswords)
		if err != nil {
			return nil, err
		}
	}
	var s3Credentials S3CredentialService
	if cfg.Services.S3.Enabled {
		s3Credentials = NewAWSSTSCredentialService()
	}
	var adminOIDC AdminIdentityProvider
	if loginConfig, ok := browserLoginOIDC(cfg.Authentication.OIDC); ok {
		adminOIDC, err = factory(ctx, loginConfig)
		if err != nil {
			return nil, err
		}
	}
	ai := NewAIService(cfg.Services)
	if err := ai.InitializeLocal(ctx); err != nil {
		_ = ai.Close()
		return nil, err
	}
	cfg.Services = ai.EffectiveServices()
	return &runtimeState{config: cfg, authenticator: authenticator, localPasswords: localPasswords, localAuth: localAuth,
		acl: NewACL(grants), ai: ai, s3Credentials: s3Credentials, adminOIDC: adminOIDC}, nil
}

func browserLoginOIDC(configs []OIDCIssuerConfig) (OIDCIssuerConfig, bool) {
	for _, cfg := range configs {
		if cfg.loginConfigured() {
			return cfg, true
		}
	}
	return OIDCIssuerConfig{}, false
}

func newServerFromRuntime(runtime *runtimeState, control *ControlStore) (*Server, error) {
	s := &Server{control: control}
	s.state.Store(runtime)
	s.ready.Store(true)
	if control != nil && strings.TrimSpace(runtime.config.Server.PublicURL) != "" && (runtime.config.Authentication.Local.Login.isEnabled() || runtime.adminOIDC != nil) {
		provider, err := newBrokerOIDCProvider(runtime.config, control)
		if err != nil {
			return nil, err
		}
		s.oidcProvider = provider
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.readyHandler)
	mux.HandleFunc("GET /.well-known/graphit-broker", s.discovery)
	if s.oidcProvider != nil {
		mux.Handle("GET /.well-known/openid-configuration", s.oidcProvider.handler)
		mux.HandleFunc("GET /oauth/authorize", s.oidcAuthorize)
		mux.HandleFunc("POST /oauth/authorize", s.oidcAuthorize)
		mux.Handle("GET /oauth/authorize/callback", s.oidcProvider.handler)
		mux.HandleFunc("GET "+oidcLoginPath, s.oidcLogin)
		mux.HandleFunc("POST "+oidcLoginPath, s.oidcLogin)
		mux.HandleFunc("POST /oauth/device/authorize", s.oauthDeviceAuthorize)
		mux.HandleFunc("GET /oauth/device", s.oauthDeviceVerification)
		mux.HandleFunc("POST /oauth/device", s.oauthDeviceVerification)
		mux.HandleFunc("POST /oauth/token", s.oauthTokenGateway)
		mux.Handle("POST /oauth/revoke", s.oidcProvider.handler)
		mux.Handle("GET /oauth/userinfo", s.oidcProvider.handler)
		mux.Handle("POST /oauth/userinfo", s.oidcProvider.handler)
		mux.Handle("POST /oauth/introspect", s.oidcProvider.handler)
		mux.Handle("GET /oauth/end-session", s.oidcProvider.handler)
		mux.Handle("POST /oauth/end-session", s.oidcProvider.handler)
		mux.Handle("GET /oauth/keys", s.oidcProvider.handler)
	}
	if runtime.adminOIDC != nil {
		mux.HandleFunc("GET /oauth/oidc/callback", s.adminCallback)
	}
	mux.Handle("POST /v1/embeddings", s.resolvePrincipal(http.HandlerFunc(s.embeddings)))
	mux.Handle("POST /v1/rerank", s.resolvePrincipal(http.HandlerFunc(s.rerank)))
	mux.Handle("POST /v1/s3/credentials", s.resolvePrincipal(http.HandlerFunc(s.s3CredentialGrant)))
	mux.Handle("POST /v1/hub/access/resolve", s.resolvePrincipal(http.HandlerFunc(s.hubAccessResolve)))
	if runtime.config.Administration.Enabled {
		mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/", http.StatusPermanentRedirect)
		})
		mux.HandleFunc("GET /admin/{$}", s.adminPage)
		mux.HandleFunc("GET /admin/auth/login", s.adminLogin)
		mux.HandleFunc("POST /admin/auth/local", s.adminLocalLogin)
		mux.HandleFunc("POST /admin/auth/local/continue", s.adminLocalLoginContinue)
		mux.HandleFunc("POST /admin/auth/logout", s.adminLogout)
		mux.HandleFunc("GET /admin/api/v1/login-options", s.adminLoginOptions)
		mux.Handle("GET /admin/api/v1/session", s.requireAdministration("session.read", http.HandlerFunc(s.adminSession)))
		mux.Handle("GET /admin/api/v1/projects", s.requireAdministration("projects.read", http.HandlerFunc(s.adminProjects)))
		mux.Handle("GET /admin/api/v1/config", s.requireAdministration("configuration.read", http.HandlerFunc(s.adminConfig)))
		mux.Handle("GET /admin/api/v1/grants", s.requireAdministration("grants.read", http.HandlerFunc(s.adminGrants)))
		mux.Handle("POST /admin/api/v1/grants", s.requireAdministration("grants.write", http.HandlerFunc(s.adminGrants)))
		mux.Handle("PUT /admin/api/v1/grants/{grant}", s.requireAdministration("grants.write", http.HandlerFunc(s.adminGrant)))
		mux.Handle("DELETE /admin/api/v1/grants/{grant}", s.requireAdministration("grants.write", http.HandlerFunc(s.adminGrant)))
		mux.Handle("GET /admin/api/v1/principals", s.requireAdministration("grants.read", http.HandlerFunc(s.adminPrincipals)))
		mux.Handle("GET /admin/api/v1/roles", s.requireAdministration("roles.read", http.HandlerFunc(s.adminRoles)))
		mux.Handle("PUT /admin/api/v1/roles/{role}", s.requireAdministration("roles.write", http.HandlerFunc(s.adminRole)))
		mux.Handle("DELETE /admin/api/v1/roles/{role}", s.requireAdministration("roles.write", http.HandlerFunc(s.adminRole)))
		mux.Handle("GET /admin/api/v1/role-assignments", s.requireAdministration("roles.read", http.HandlerFunc(s.adminAssignments)))
		mux.Handle("POST /admin/api/v1/role-assignments", s.requireAdministration("roles.write", http.HandlerFunc(s.adminAssignments)))
		mux.Handle("DELETE /admin/api/v1/role-assignments", s.requireAdministration("roles.write", http.HandlerFunc(s.adminAssignments)))
		mux.Handle("GET /admin/api/v1/local-users", s.requireAdministration("users.read", http.HandlerFunc(s.adminLocalUsers)))
		mux.Handle("POST /admin/api/v1/local-users", s.requireAdministration("users.write", http.HandlerFunc(s.adminLocalUsers)))
		mux.Handle("PUT /admin/api/v1/local-users/{username}", s.requireAdministration("users.write", http.HandlerFunc(s.adminLocalUser)))
		mux.Handle("DELETE /admin/api/v1/local-users/{username}", s.requireAdministration("users.write", http.HandlerFunc(s.adminLocalUser)))
		mux.Handle("POST /admin/api/v1/local-users/{username}/mfa/reset", s.requireAdministration("users.write", http.HandlerFunc(s.adminLocalUserMFAReset)))
		mux.Handle("GET /admin/api/v1/local-users/{username}/credentials", s.requireAdministration("users.read", http.HandlerFunc(s.adminServiceCredentials)))
		mux.Handle("POST /admin/api/v1/local-users/{username}/credentials", s.requireAdministration("users.write", http.HandlerFunc(s.adminServiceCredentials)))
		mux.Handle("DELETE /admin/api/v1/local-users/{username}/credentials/{credential}", s.requireAdministration("users.write", http.HandlerFunc(s.adminServiceCredential)))
	}
	s.handler = s.observability(mux)
	return s, nil
}

func (s *Server) runtime() *runtimeState { return s.state.Load() }

func (s *Server) Close() error {
	var firstErr error
	if state := s.runtime(); state != nil && state.ai != nil {
		firstErr = state.ai.Close()
	}
	if s.control != nil {
		if err := s.control.Close(); firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) HTTPServer() *http.Server {
	cfg := s.runtime().config.Server
	return &http.Server{Addr: cfg.Address, Handler: s, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) readyHandler(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "broker is not ready", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	services := map[string]any{}
	authorizationRevision, err := state.acl.Revision(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "resource authorization is unavailable", requestID(r.Context()))
		return
	}
	services["hub_access"] = map[string]any{"protocol": "graphit-hub-access-v1", "path": "/v1/hub/access/resolve",
		"authorization_revision": authorizationRevision}
	if cfg := state.config.Services.Embeddings; cfg.Enabled {
		services["embeddings"] = map[string]any{"protocol": "openai-embeddings-v1", "path": "/v1/embeddings", "route": cfg.Route,
			"revision": cfg.Revision, "dimensions": cfg.Dimensions, "max_batch": cfg.MaxBatch}
	}
	if cfg := state.config.Services.Rerank; cfg.Enabled {
		services["rerank"] = map[string]any{"protocol": "graphit-rerank-v1", "path": "/v1/rerank", "route": cfg.Route,
			"revision": cfg.Revision, "max_documents": cfg.MaxDocuments}
	}
	if cfg := state.config.Services.S3; cfg.Enabled {
		services["s3_credentials"] = map[string]any{"protocol": "graphit-s3-credentials-v1", "path": "/v1/s3/credentials",
			"authorization_revision": authorizationRevision}
	}
	audiences := []string{state.config.Authentication.Local.Tokens.Audience}
	for _, issuer := range state.config.Authentication.OIDC {
		if !issuer.isEnabled() {
			continue
		}
		audiences = append(audiences, issuer.Audiences...)
	}
	authentication := map[string]any{"schemes": []string{"anonymous", "bearer"}, "audiences": cleanStrings(audiences)}
	methods, methodsErr := s.oauthLoginMethods(r)
	if methodsErr != nil {
		writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", "authentication discovery is unavailable", requestID(r.Context()))
		return
	}
	if len(methods) > 0 {
		authentication["type"] = "openid_connect"
		authentication["issuer"] = s.publicURL(r)
		authentication["client_id"] = state.config.Authentication.Local.Tokens.CLIClientID
		authentication["scopes"] = append([]string(nil), brokerOIDCScopes...)
		authentication["redirect_uri_path"] = state.config.Authentication.Local.Tokens.CLIRedirectPath
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": "1", "issuer": s.publicURL(r),
		"authentication": authentication, "services": services})
}

type hubProjectSelector struct {
	ID         string `json:"id,omitempty"`
	NamePrefix string `json:"name_prefix,omitempty"`
	All        bool   `json:"all,omitempty"`
}

func (s *Server) hubAccessResolve(w http.ResponseWriter, r *http.Request) {
	principal := principalFromContext(r.Context())
	document, err := s.runtime().acl.ResolveHubAccess(r.Context(), principal)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "resource authorization is unavailable", requestID(r.Context()))
		return
	}
	selectors := make([]hubProjectSelector, 0)
	seen := map[hubProjectSelector]struct{}{}
	for _, rule := range document.Rules {
		projects := rule.Projects
		if len(projects) == 0 {
			projects = []string{"*"}
		}
		for _, project := range projects {
			project = strings.TrimSpace(project)
			selector := hubProjectSelector{ID: project}
			switch {
			case project == "*":
				selector = hubProjectSelector{All: true}
			}
			if _, ok := seen[selector]; !ok {
				seen[selector] = struct{}{}
				selectors = append(selectors, selector)
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"v": 1, "authorization_revision": fmt.Sprint(document.Revision),
		"subject": principal.CanonicalSubject(), "selectors": selectors,
	})
}

func (s *Server) embeddings(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	if !state.config.Services.Embeddings.Enabled {
		writeError(w, http.StatusNotFound, "capability_disabled", "embeddings are disabled", requestID(r.Context()))
		return
	}
	principal := principalFromContext(r.Context())
	if err := state.acl.AuthorizeCapability(r.Context(), principal, "embeddings"); err != nil {
		s.authorizationFailure(w, r, err)
		return
	}
	var request struct {
		Model     string          `json:"model,omitempty"`
		Input     json.RawMessage `json:"input"`
		InputType string          `json:"input_type,omitempty"`
	}
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	inputs, err := decodeEmbeddingInput(request.Input)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), requestID(r.Context()))
		return
	}
	cfg := state.config.Services.Embeddings
	request.InputType = strings.ToLower(strings.TrimSpace(request.InputType))
	if request.InputType == "" {
		request.InputType = "document"
	}
	if request.InputType != "document" && request.InputType != "query" {
		writeError(w, http.StatusBadRequest, "invalid_request", "input_type must be query or document", requestID(r.Context()))
		return
	}
	if len(inputs) == 0 || len(inputs) > cfg.MaxBatch {
		writeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("input must contain between 1 and %d items", cfg.MaxBatch), requestID(r.Context()))
		return
	}
	total := 0
	for _, input := range inputs {
		total += len(input)
		if strings.TrimSpace(input) == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "embedding input must not be empty", requestID(r.Context()))
			return
		}
	}
	if total > cfg.MaxInputBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "embedding input exceeds configured limit", requestID(r.Context()))
		return
	}
	response, cached, err := state.ai.Embed(r.Context(), principal, inputs, request.InputType)
	if err != nil {
		s.upstreamFailure(w, r, err)
		return
	}
	w.Header().Set("X-Graphit-Embedding-Revision", response.Graphit.Revision)
	w.Header().Set("X-Graphit-Embedding-Dimensions", fmt.Sprint(response.Graphit.Dimensions))
	if cached {
		w.Header().Set("X-Graphit-Cache", "HIT")
	} else {
		w.Header().Set("X-Graphit-Cache", "MISS")
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) rerank(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	if !state.config.Services.Rerank.Enabled {
		writeError(w, http.StatusNotFound, "capability_disabled", "rerank is disabled", requestID(r.Context()))
		return
	}
	principal := principalFromContext(r.Context())
	if err := state.acl.AuthorizeCapability(r.Context(), principal, "rerank"); err != nil {
		s.authorizationFailure(w, r, err)
		return
	}
	var request struct {
		Model     string   `json:"model,omitempty"`
		Query     string   `json:"query"`
		Documents []string `json:"documents"`
		TopN      int      `json:"top_n,omitempty"`
	}
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	cfg := state.config.Services.Rerank
	if strings.TrimSpace(request.Query) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "query is required", requestID(r.Context()))
		return
	}
	if len(request.Documents) == 0 || len(request.Documents) > cfg.MaxDocuments {
		writeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("documents must contain between 1 and %d items", cfg.MaxDocuments), requestID(r.Context()))
		return
	}
	for _, document := range request.Documents {
		if strings.TrimSpace(document) == "" || len(document) > cfg.MaxDocumentBytes {
			writeError(w, http.StatusBadRequest, "invalid_request", "each document must be non-empty and within the configured size limit", requestID(r.Context()))
			return
		}
	}
	if request.TopN == 0 {
		request.TopN = len(request.Documents)
	}
	if request.TopN < 1 || request.TopN > len(request.Documents) {
		writeError(w, http.StatusBadRequest, "invalid_request", "top_n must be between 1 and the number of documents", requestID(r.Context()))
		return
	}
	response, cached, err := state.ai.Rerank(r.Context(), principal, request.Query, request.Documents, request.TopN)
	if err != nil {
		s.upstreamFailure(w, r, err)
		return
	}
	w.Header().Set("X-Graphit-Rerank-Revision", response.Graphit.Revision)
	if cached {
		w.Header().Set("X-Graphit-Cache", "HIT")
	} else {
		w.Header().Set("X-Graphit-Cache", "MISS")
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) s3CredentialGrant(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	if !state.config.Services.S3.Enabled || state.s3Credentials == nil {
		writeError(w, http.StatusNotFound, "capability_disabled", "S3 credentials are disabled", requestID(r.Context()))
		return
	}
	principal := principalFromContext(r.Context())
	if principal.IsAnonymous() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-broker"`)
		writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer credentials are required", requestID(r.Context()))
		return
	}
	var request struct{}
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	grant, err := state.acl.ResolveS3Session(r.Context(), principal, state.config.Services.S3.DefaultRoute)
	if err != nil {
		s.authorizationFailure(w, r, err)
		return
	}
	route, ok := state.config.Services.S3.Routes[grant.Route]
	if !ok {
		slog.Error("S3 credential route is unavailable", "request_id", requestID(r.Context()), "route", grant.Route)
		writeError(w, http.StatusServiceUnavailable, "storage_unavailable", "S3 storage route is unavailable", requestID(r.Context()))
		return
	}
	response, err := state.s3Credentials.Issue(r.Context(), route, grant, principal)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", requestID(r.Context()))
		} else {
			slog.Error("S3 credential issuance failed", "request_id", requestID(r.Context()), "error", err)
			writeError(w, http.StatusBadGateway, "sts_failed", "temporary S3 credential issuance failed", requestID(r.Context()))
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) authorizationFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrForbidden) {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", requestID(r.Context()))
		return
	}
	slog.Error("resource authorization failed", "request_id", requestID(r.Context()), "error", err)
	writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "resource authorization is unavailable", requestID(r.Context()))
}

func (s *Server) resolvePrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if authorization == "" {
			ctx := context.WithValue(r.Context(), principalKey, AnonymousPrincipal())
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		raw := bearerToken(r)
		if raw == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-broker"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "authorization must use one bearer credential", requestID(r.Context()))
			return
		}
		principal, err := s.authenticateCredential(r.Context(), raw)
		if err != nil {
			if retryAfter, limited := authenticationRetryAfter(err); limited {
				writeAuthenticationRateLimit(w, r, retryAfter)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-broker"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer credentials are required", requestID(r.Context()))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authenticateCredential(ctx context.Context, raw string) (Principal, error) {
	if s.oidcProvider != nil {
		if principal, err := s.oidcProvider.storage.AuthenticateAccessToken(ctx, raw, s.oidcProvider.op.Crypto()); err == nil {
			return principal, nil
		}
	}
	return s.runtime().authenticator.Authenticate(ctx, raw)
}

func writeAuthenticationRateLimit(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	seconds := int64(retryAfter / time.Second)
	if retryAfter%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeError(w, http.StatusTooManyRequests, "authentication_rate_limited", "too many failed authentication attempts", requestID(r.Context()))
}

func (s *Server) observability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" || len(id) > 128 {
			id = newRequestID()
		}
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("request panic", "request_id", id, "panic", recovered, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error", id)
			}
			slog.Info("request", "request_id", id, "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) decodeRequest(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.runtime().config.Server.MaxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be one valid JSON object", requestID(r.Context()))
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain one JSON object", requestID(r.Context()))
		return errors.New("trailing JSON data")
	}
	return nil
}

func (s *Server) upstreamFailure(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("AI upstream failed", "request_id", requestID(r.Context()), "error", err)
	writeError(w, http.StatusBadGateway, "upstream_failed", "AI upstream request failed", requestID(r.Context()))
}

func decodeEmbeddingInput(raw json.RawMessage) ([]string, error) {
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list, nil
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}, nil
	}
	return nil, errors.New("input must be a string or an array of strings")
}

func principalFromContext(ctx context.Context) Principal {
	principal, _ := ctx.Value(principalKey).(Principal)
	return principal
}
func requestID(ctx context.Context) string { id, _ := ctx.Value(requestIDKey).(string); return id }

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message, id string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}, "request_id": id})
}
