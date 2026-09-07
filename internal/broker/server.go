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
	"time"
)

type Server struct {
	config        Config
	authenticator Authenticator
	acl           *ACL
	ai            *AIService
	credentials   CredentialIssuer
	handler       http.Handler
	ready         bool
}

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	principalKey contextKey = "principal"
	tokenKey     contextKey = "raw_token"
)

func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	authenticator, err := NewAuthenticator(ctx, cfg.Authentication)
	if err != nil {
		return nil, err
	}
	var credentials CredentialIssuer
	if cfg.Services.S3.Enabled {
		credentials, err = NewAWSCredentialIssuer(ctx, cfg.Services.S3)
		if err != nil {
			return nil, err
		}
	}
	return newServer(cfg, authenticator, NewAIService(cfg.Services), credentials), nil
}

func newServer(cfg Config, authenticator Authenticator, ai *AIService, credentials CredentialIssuer) *Server {
	s := &Server{config: cfg, authenticator: authenticator, acl: NewACL(cfg.Authorization, cfg.Services.S3.AuthorizationRevision), ai: ai, credentials: credentials, ready: true}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.readyHandler)
	mux.HandleFunc("GET /.well-known/graphit-broker", s.discovery)
	mux.Handle("POST /v1/embeddings", s.requireAuthentication(http.HandlerFunc(s.embeddings)))
	mux.Handle("POST /v1/rerank", s.requireAuthentication(http.HandlerFunc(s.rerank)))
	mux.Handle("POST /v1/s3/credentials", s.requireAuthentication(http.HandlerFunc(s.s3Credentials)))
	s.handler = s.observability(mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{Addr: s.config.Server.Address, Handler: s, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: s.config.Server.ReadTimeout, WriteTimeout: s.config.Server.WriteTimeout, IdleTimeout: s.config.Server.IdleTimeout}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) readyHandler(w http.ResponseWriter, _ *http.Request) {
	if !s.ready {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "broker is not ready", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	services := map[string]any{}
	if cfg := s.config.Services.Embeddings; cfg.Enabled {
		services["embeddings"] = map[string]any{"protocol": "openai-embeddings-v1", "path": "/v1/embeddings", "route": cfg.Route,
			"revision": cfg.Revision, "dimensions": cfg.Dimensions, "max_batch": cfg.MaxBatch}
	}
	if cfg := s.config.Services.Rerank; cfg.Enabled {
		services["rerank"] = map[string]any{"protocol": "graphit-rerank-v1", "path": "/v1/rerank", "route": cfg.Route,
			"revision": cfg.Revision, "max_documents": cfg.MaxDocuments}
	}
	if cfg := s.config.Services.S3; cfg.Enabled {
		services["s3_credentials"] = map[string]any{"protocol": "graphit-s3-credentials-v1", "path": "/v1/s3/credentials",
			"authorization_revision": cfg.AuthorizationRevision}
	}
	audiences := []string{}
	for _, issuer := range s.config.Authentication.OIDC {
		audiences = append(audiences, issuer.Audiences...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": "1", "issuer": s.config.Server.PublicURL,
		"authentication": map[string]any{"schemes": []string{"bearer"}, "audiences": cleanStrings(audiences)}, "services": services})
}

func (s *Server) embeddings(w http.ResponseWriter, r *http.Request) {
	if !s.config.Services.Embeddings.Enabled {
		writeError(w, http.StatusNotFound, "capability_disabled", "embeddings are disabled", requestID(r.Context()))
		return
	}
	principal := principalFromContext(r.Context())
	if err := s.acl.AuthorizeCapability(principal, "embeddings"); err != nil {
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
	cfg := s.config.Services.Embeddings
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
	response, cached, err := s.ai.Embed(r.Context(), principal, inputs)
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
	if !s.config.Services.Rerank.Enabled {
		writeError(w, http.StatusNotFound, "capability_disabled", "rerank is disabled", requestID(r.Context()))
		return
	}
	principal := principalFromContext(r.Context())
	if err := s.acl.AuthorizeCapability(principal, "rerank"); err != nil {
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
	cfg := s.config.Services.Rerank
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
	response, cached, err := s.ai.Rerank(r.Context(), principal, request.Query, request.Documents, request.TopN)
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

func (s *Server) s3Credentials(w http.ResponseWriter, r *http.Request) {
	if !s.config.Services.S3.Enabled || s.credentials == nil {
		writeError(w, http.StatusNotFound, "capability_disabled", "S3 credentials are disabled", requestID(r.Context()))
		return
	}
	var request CredentialRequest
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	principal := principalFromContext(r.Context())
	grant, err := s.acl.AuthorizeS3(principal, request.Project, request.Operation, s.config.Services.S3.BasePrefix)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", requestID(r.Context()))
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), requestID(r.Context()))
		}
		return
	}
	credentials, err := s.credentials.Issue(r.Context(), principal, rawTokenFromContext(r.Context()), grant)
	if err != nil {
		slog.Error("S3 credential issue failed", "request_id", requestID(r.Context()), "error", err)
		writeError(w, http.StatusBadGateway, "credential_exchange_failed", "credential exchange failed", requestID(r.Context()))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, credentials)
}

func (s *Server) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		principal, err := s.authenticator.Authenticate(r.Context(), raw)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-auth-broker"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer credentials are required", requestID(r.Context()))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		ctx = context.WithValue(ctx, tokenKey, raw)
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
	r.Body = http.MaxBytesReader(w, r.Body, s.config.Server.MaxRequestBytes)
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
func rawTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(tokenKey).(string)
	return token
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
