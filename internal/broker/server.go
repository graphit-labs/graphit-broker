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
	config                Config
	configurationRevision uint64
	authenticator         Authenticator
	policy                *PolicyStore
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
	effective, revision := cfg, uint64(0)
	var control *ControlStore
	var err error
	if cfg.Administration.Enabled {
		var stored StoredConfig
		control, stored, err = OpenControlStore(cfg.Administration.DatabasePath, cfg)
		if err != nil {
			return nil, err
		}
		effective, revision = stored.Config, stored.Revision
		// These bootstrap values are controlled by the deployment and never overridden by SQLite.
		effective.Administration.Enabled = true
		effective.Administration.DatabasePath = cfg.Administration.DatabasePath
		effective.Administration.SuperadminSubject = cfg.Administration.SuperadminSubject
	}
	runtime, err := buildRuntime(ctx, effective, revision, factory)
	if err != nil {
		if control != nil {
			_ = control.Close()
		}
		return nil, err
	}
	s := newServerFromRuntime(cfg, runtime, control, factory)
	return s, nil
}

func buildRuntime(ctx context.Context, cfg Config, revision uint64, factory func(context.Context, AdminOIDCConfig) (AdminIdentityProvider, error)) (*runtimeState, error) {
	authenticator, err := NewAuthenticator(ctx, cfg.Authentication)
	if err != nil {
		return nil, err
	}
	authorizationRevision := cfg.Services.S3.AuthorizationRevision
	if revision > 0 {
		authorizationRevision += ".c" + strconv.FormatUint(revision, 10)
	}
	policy, err := NewPolicyStore(cfg.Authorization, authorizationRevision, cfg.Services.S3)
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
	return &runtimeState{config: cfg, configurationRevision: revision, authenticator: authenticator,
		policy: policy, acl: NewACLWithPolicy(policy), ai: NewAIService(cfg.Services), presigner: presigner, adminOIDC: adminOIDC}, nil
}

func newServer(cfg Config, authenticator Authenticator, ai *AIService) *Server {
	policy, _ := NewPolicyStore(cfg.Authorization, cfg.Services.S3.AuthorizationRevision, cfg.Services.S3)
	var presigner PresignService
	if cfg.Services.S3.Enabled {
		presigner = NewAWSPresignService(cfg.Services.S3)
	}
	runtime := &runtimeState{config: cfg, authenticator: authenticator, policy: policy, acl: NewACLWithPolicy(policy), ai: ai, presigner: presigner}
	return newServerFromRuntime(cfg, runtime, nil, nil)
}

func newServerWithDependencies(cfg Config, authenticator Authenticator, ai *AIService, presigner PresignService, policy *PolicyStore, control *ControlStore, adminOIDC AdminIdentityProvider) *Server {
	runtime := &runtimeState{config: cfg, authenticator: authenticator, policy: policy, acl: NewACLWithPolicy(policy), ai: ai, presigner: presigner, adminOIDC: adminOIDC}
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
		mux.Handle("GET /admin/api/v1/access", s.requireAdministration("access.read", http.HandlerFunc(s.adminAccess)))
		mux.Handle("PUT /admin/api/v1/access", s.requireAdministration("access.write", http.HandlerFunc(s.adminAccess)))
		mux.Handle("GET /admin/api/v1/principals", s.requireAdministration("access.read", http.HandlerFunc(s.adminPrincipals)))
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
	if s.control != nil {
		return s.control.Close()
	}
	return nil
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

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	state := s.runtime()
	services := map[string]any{}
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
			"authorization_revision": state.acl.Revision(), "default_expires_in": int64(cfg.PresignExpiry / time.Second), "max_expires_in": int64(cfg.MaxPresignExpiry / time.Second)}
	}
	audiences := []string{}
	for _, issuer := range state.config.Authentication.OIDC {
		audiences = append(audiences, issuer.Audiences...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": "1", "issuer": state.config.Server.PublicURL,
		"authentication": map[string]any{"schemes": []string{"anonymous", "bearer"}, "audiences": cleanStrings(audiences)}, "services": services})
}

func (s *Server) embeddings(w http.ResponseWriter, r *http.Request) {
	state := s.runtime()
	if !state.config.Services.Embeddings.Enabled {
		writeError(w, http.StatusNotFound, "capability_disabled", "embeddings are disabled", requestID(r.Context()))
		return
	}
	principal := principalFromContext(r.Context())
	if err := state.acl.AuthorizeCapability(principal, "embeddings"); err != nil {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", requestID(r.Context()))
		return
	}
	var request struct {
		Model string          `json:"model,omitempty"`
		Input json.RawMessage `json:"input"`
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
	response, cached, err := state.ai.Embed(r.Context(), principal, inputs)
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
	if err := state.acl.AuthorizeCapability(principal, "rerank"); err != nil {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", requestID(r.Context()))
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
	grant, err := state.acl.AuthorizeS3Request(principal, request.Project, request.Operation, state.config.Services.S3.DefaultRoute)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", requestID(r.Context()))
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), requestID(r.Context()))
		}
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
	response.AuthorizationRevision = state.acl.Revision()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
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
			w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-auth-broker"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "authorization must use one bearer credential", requestID(r.Context()))
			return
		}
		principal, err := s.runtime().authenticator.Authenticate(r.Context(), raw)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-auth-broker"`)
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
