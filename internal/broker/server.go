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
	"strings"
	"sync/atomic"
	"time"
)

type runtimeState struct {
	config                Config
	configurationRevision uint64
	authenticator         Authenticator
	acl                   *ACL
	ai                    *AIService
	presigner             PresignService
	adminOIDC             AdminIdentityProvider
}

type Server struct {
	bootstrap            Config
	state                atomic.Pointer[runtimeState]
	control              *ControlStore
	adminProviderFactory func(context.Context, AdminOIDCConfig) (AdminIdentityProvider, error)
	handler              http.Handler
	ready                atomic.Bool
}

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	principalKey contextKey = "principal"
)

func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	return newServerWithFactory(ctx, cfg, NewAdminIdentityProvider)
}

func newServerWithFactory(ctx context.Context, cfg Config, factory func(context.Context, AdminOIDCConfig) (AdminIdentityProvider, error)) (*Server, error) {
	control, stored, err := OpenControlStore(cfg.Database, cfg)
	if err != nil {
		return nil, err
	}
	effective := stored.Config
	// Database selection and the administration bootstrap are deployment-owned, not mutable UI state.
	effective.Database = cfg.Database
	effective.Administration.Enabled = cfg.Administration.Enabled
	effective.Administration.SuperadminSubject = cfg.Administration.SuperadminSubject
	runtime, err := buildRuntime(ctx, effective, stored.Revision, factory, control)
	if err != nil {
		if control != nil {
			_ = control.Close()
		}
		return nil, err
	}
	s := newServerFromRuntime(cfg, runtime, control, factory)
	return s, nil
}

func buildRuntime(ctx context.Context, cfg Config, revision uint64, factory func(context.Context, AdminOIDCConfig) (AdminIdentityProvider, error), grants ResourceGrantReader) (*runtimeState, error) {
	authenticator, err := NewAuthenticator(ctx, cfg.Authentication)
	if err != nil {
		return nil, err
	}
	var presigner PresignService
	if cfg.Services.S3.Enabled {
		presigner = NewAWSPresignService(cfg.Services.S3)
	}
	var adminOIDC AdminIdentityProvider
	if cfg.Administration.Enabled {
		adminOIDC, err = factory(ctx, cfg.Administration.OIDC)
		if err != nil {
			return nil, err
		}
	}
	ai := NewAIService(cfg.Services)
	if err := ai.InitializeLocal(ctx); err != nil {
		_ = ai.Close()
		return nil, err
	}
	return &runtimeState{config: cfg, configurationRevision: revision, authenticator: authenticator,
		acl: NewACL(grants), ai: ai, presigner: presigner, adminOIDC: adminOIDC}, nil
}

func newServerWithDependencies(cfg Config, authenticator Authenticator, ai *AIService, presigner PresignService, grants ResourceGrantReader, control *ControlStore, adminOIDC AdminIdentityProvider) *Server {
	runtime := &runtimeState{config: cfg, authenticator: authenticator, acl: NewACL(grants), ai: ai, presigner: presigner, adminOIDC: adminOIDC}
	return newServerFromRuntime(cfg, runtime, control, nil)
}

func newServerFromRuntime(bootstrap Config, runtime *runtimeState, control *ControlStore, factory func(context.Context, AdminOIDCConfig) (AdminIdentityProvider, error)) *Server {
	s := &Server{bootstrap: bootstrap, control: control, adminProviderFactory: factory}
	s.state.Store(runtime)
	s.ready.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.readyHandler)
	mux.HandleFunc("GET /.well-known/graphit-broker", s.discovery)
	mux.Handle("POST /v1/embeddings", s.resolvePrincipal(http.HandlerFunc(s.embeddings)))
	mux.Handle("POST /v1/rerank", s.resolvePrincipal(http.HandlerFunc(s.rerank)))
	mux.Handle("POST /v1/s3/presign", s.resolvePrincipal(http.HandlerFunc(s.s3Presign)))
	mux.Handle("POST /v1/hub/access/resolve", s.resolvePrincipal(http.HandlerFunc(s.hubAccessResolve)))
	if bootstrap.Administration.Enabled {
		mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/", http.StatusPermanentRedirect)
		})
		mux.HandleFunc("GET /admin/{$}", s.adminPage)
		mux.HandleFunc("GET /admin/auth/login", s.adminLogin)
		mux.HandleFunc("GET /admin/auth/callback", s.adminCallback)
		mux.HandleFunc("POST /admin/auth/logout", s.adminLogout)
		mux.Handle("GET /admin/api/v1/session", s.requireAdministration("session.read", http.HandlerFunc(s.adminSession)))
		mux.Handle("GET /admin/api/v1/config", s.requireAdministration("configuration.read", http.HandlerFunc(s.adminConfig)))
		mux.Handle("PUT /admin/api/v1/config", s.requireAdministration("configuration.write", http.HandlerFunc(s.adminConfig)))
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
	}
	s.handler = s.observability(mux)
	return s
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
		services["s3_presign"] = map[string]any{"protocol": "graphit-s3-presign-v1", "path": "/v1/s3/presign",
			"authorization_revision": authorizationRevision, "default_expires_in": int64(cfg.PresignExpiry / time.Second), "max_expires_in": int64(cfg.MaxPresignExpiry / time.Second)}
	}
	audiences := []string{}
	for _, issuer := range state.config.Authentication.OIDC {
		audiences = append(audiences, issuer.Audiences...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": "1", "issuer": state.config.Server.PublicURL,
		"authentication": map[string]any{"schemes": []string{"anonymous", "bearer"}, "audiences": cleanStrings(audiences)}, "services": services})
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

func validateRequestProjectKey(project, key string) error {
	project = strings.TrimSpace(project)
	parts := strings.Split(strings.Trim(strings.TrimSpace(key), "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "v2" && parts[i+1] == "projects" {
			if parts[i+2] != project {
				return errors.New("project does not match the logical object key")
			}
			return nil
		}
	}
	if project != "global" {
		return errors.New("non-project logical keys must use project global")
	}
	return nil
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

func (s *Server) s3Presign(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	if !state.config.Services.S3.Enabled || state.presigner == nil {
		writeError(w, http.StatusNotFound, "capability_disabled", "S3 presigned operations are disabled", requestID(r.Context()))
		return
	}
	var request PresignRequest
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	if err := validateRequestProjectKey(request.Project, request.Key); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), requestID(r.Context()))
		return
	}
	principal := principalFromContext(r.Context())
	grant, err := state.acl.AuthorizeS3Request(r.Context(), principal, request.Project, request.Operation, state.config.Services.S3.DefaultRoute)
	if err != nil {
		s.authorizationFailure(w, r, err)
		return
	}
	response, err := state.presigner.Presign(r.Context(), grant, request)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", requestID(r.Context()))
		} else {
			slog.Error("S3 presign failed", "request_id", requestID(r.Context()), "error", err)
			writeError(w, http.StatusBadGateway, "presign_failed", "S3 request signing failed", requestID(r.Context()))
		}
		return
	}
	response.AuthorizationRevision, err = state.acl.Revision(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "resource authorization is unavailable", requestID(r.Context()))
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
		principal, err := s.runtime().authenticator.Authenticate(r.Context(), raw)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-broker"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer credentials are required", requestID(r.Context()))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
