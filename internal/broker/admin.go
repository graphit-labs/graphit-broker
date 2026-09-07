package broker

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

//go:embed adminui/index.html
var adminHTML []byte

type adminIdentity struct {
	name   string
	digest [sha256.Size]byte
}

type AdminAuthenticator struct{ identities []adminIdentity }

func NewAdminAuthenticator(cfg AdministrationConfig) *AdminAuthenticator {
	authenticator := &AdminAuthenticator{}
	for _, key := range cfg.APIKeys {
		var digest [sha256.Size]byte
		if key.TokenSHA256 != "" {
			decoded, _ := hex.DecodeString(key.TokenSHA256)
			copy(digest[:], decoded)
		} else {
			digest = sha256.Sum256([]byte(key.Token))
		}
		authenticator.identities = append(authenticator.identities, adminIdentity{name: key.Name, digest: digest})
	}
	return authenticator
}

func (a *AdminAuthenticator) Authenticate(raw string) (string, bool) {
	if a == nil || strings.TrimSpace(raw) == "" {
		return "", false
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	for _, identity := range a.identities {
		if subtle.ConstantTimeCompare(digest[:], identity.digest[:]) == 1 {
			return identity.name, true
		}
	}
	return "", false
}

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

func (s *Server) adminAccess(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		document := s.policy.Snapshot()
		w.Header().Set("ETag", policyETag(document.Revision))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, document)
	case http.MethodPut:
		expected, err := parsePolicyETag(r.Header.Get("If-Match"))
		if err != nil {
			writeError(w, http.StatusPreconditionRequired, "precondition_required", "If-Match with the current policy revision is required", requestID(r.Context()))
			return
		}
		var request struct {
			Version int             `json:"v"`
			Rules   []ACLRuleConfig `json:"rules"`
		}
		if err := s.decodeRequest(w, r, &request); err != nil {
			return
		}
		if request.Version != 1 {
			writeError(w, http.StatusBadRequest, "invalid_policy", "policy version must be 1", requestID(r.Context()))
			return
		}
		document, err := s.policy.Replace(expected, request.Rules)
		if errors.Is(err, ErrPolicyConflict) {
			writeError(w, http.StatusConflict, "revision_conflict", "access policy changed; reload before saving", requestID(r.Context()))
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_policy", err.Error(), requestID(r.Context()))
			return
		}
		w.Header().Set("ETag", policyETag(document.Revision))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, document)
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestID(r.Context()))
	}
}

func (s *Server) adminPrincipals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestID(r.Context()))
		return
	}
	type principalSummary struct {
		Type         string   `json:"type"`
		ID           string   `json:"id"`
		Username     string   `json:"username,omitempty"`
		Organization string   `json:"organization,omitempty"`
		Teams        []string `json:"teams,omitempty"`
	}
	principals := []principalSummary{{Type: "anonymous", ID: "anonymous"}, {Type: "authenticated", ID: "authenticated"}}
	for _, key := range s.config.Authentication.APIKeys {
		principals = append(principals, principalSummary{Type: "api_key", ID: key.Subject, Username: key.Username, Organization: key.Organization, Teams: append([]string(nil), key.Teams...)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"principals": principals})
}

func (s *Server) requireAdministration(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := s.adminAuth.Authenticate(bearerToken(r))
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="graphit-auth-broker-admin"`)
			writeError(w, http.StatusUnauthorized, "admin_unauthorized", "valid administrator credentials are required", requestID(r.Context()))
			return
		}
		r.Header.Set("X-Graphit-Admin-Identity", name)
		next.ServeHTTP(w, r)
	})
}

func policyETag(revision uint64) string { return `"` + strconv.FormatUint(revision, 10) + `"` }

func parsePolicyETag(value string) (uint64, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "W/"))
	value = strings.Trim(value, `"`)
	if value == "" {
		return 0, errors.New("empty ETag")
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil || revision == 0 {
		return 0, fmt.Errorf("invalid policy ETag")
	}
	return revision, nil
}
