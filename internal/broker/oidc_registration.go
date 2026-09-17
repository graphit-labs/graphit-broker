package broker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	zitoidc "github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	oidcRegistrationPath = "/oauth/register"
	// maxRegistrationBody bounds an unauthenticated request body, like the token gateway does.
	maxRegistrationBody = 32 << 10

	// RFC 7591 application_type values. The library's op.ApplicationType is an integer, so
	// the persisted and advertised form is spelled out here.
	applicationTypeNative = "native"
	applicationTypeWeb    = "web"
)

// dynamicClientRecord is a client created through RFC 7591 registration. It deliberately
// carries no secret: registration only ever produces public clients.
type dynamicClientRecord struct {
	ClientID        string
	ClientName      string
	RedirectURIs    []string
	Scopes          []string
	ApplicationType string
	CreatedAt       time.Time
}

// registrationError is the RFC 7591 failure shape, reusing the SDK's type so client and
// server agree on the wire contract rather than each inventing one.
func writeRegistrationError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(&oauthex.ClientRegistrationError{ErrorCode: code, ErrorDescription: description})
}

// validateRegistrationMetadata enforces that only a public Authorization Code client can be
// created. Everything it rejects is something that would either hand out a confidential
// client or widen the redirect surface, so each check fails the whole registration rather
// than silently normalizing the request into something the caller did not ask for.
func validateRegistrationMetadata(metadata *oauthex.ClientRegistrationMetadata) (dynamicClientRecord, string) {
	// RFC 7591 defaults this to client_secret_basic when omitted, which would be a
	// confidential client; the broker requires the public method to be explicit or absent.
	switch strings.TrimSpace(metadata.TokenEndpointAuthMethod) {
	case "", "none":
	default:
		return dynamicClientRecord{}, "this broker registers public clients only; token_endpoint_auth_method must be none"
	}

	grantTypes := metadata.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{string(zitoidc.GrantTypeCode)}
	}
	for _, grant := range grantTypes {
		if grant != string(zitoidc.GrantTypeCode) && grant != string(zitoidc.GrantTypeRefreshToken) {
			return dynamicClientRecord{}, fmt.Sprintf("grant_type %q is not available to registered clients", grant)
		}
	}

	responseTypes := metadata.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{string(zitoidc.ResponseTypeCode)}
	}
	for _, responseType := range responseTypes {
		if responseType != string(zitoidc.ResponseTypeCode) {
			return dynamicClientRecord{}, fmt.Sprintf("response_type %q is not available to registered clients", responseType)
		}
	}

	if len(metadata.RedirectURIs) == 0 {
		return dynamicClientRecord{}, "redirect_uris is required"
	}
	redirectURIs := make([]string, 0, len(metadata.RedirectURIs))
	sawHTTPS := false
	for _, raw := range metadata.RedirectURIs {
		trimmed := strings.TrimSpace(raw)
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
			return dynamicClientRecord{}, fmt.Sprintf("redirect_uri %q must be an absolute URL without fragment or embedded credentials", raw)
		}
		switch parsed.Scheme {
		case "https":
			if isLoopbackHost(parsed.Hostname()) {
				return dynamicClientRecord{}, fmt.Sprintf("redirect_uri %q must not use https on a loopback host", raw)
			}
			sawHTTPS = true
		case "http":
			// Plain HTTP is confined to loopback, where it cannot leave the user's machine.
			if !isLoopbackHost(parsed.Hostname()) {
				return dynamicClientRecord{}, fmt.Sprintf("redirect_uri %q may use http only on a loopback host", raw)
			}
		default:
			return dynamicClientRecord{}, fmt.Sprintf("redirect_uri %q must use https, or http on a loopback host", raw)
		}
		redirectURIs = append(redirectURIs, trimmed)
	}

	scopes := strings.Fields(metadata.Scope)
	if len(scopes) == 0 {
		scopes = append([]string(nil), brokerOIDCScopes...)
	}
	for _, scope := range scopes {
		if !slices.Contains(brokerOIDCScopes, scope) {
			return dynamicClientRecord{}, fmt.Sprintf("scope %q is not supported by this broker", scope)
		}
	}

	// A hosted agent redirects to its own HTTPS callback and is a web client; a desktop
	// client on loopback is native. The distinction decides how the provider validates the
	// redirect later, so it is derived from what was registered rather than trusted input.
	applicationType := applicationTypeNative
	if sawHTTPS {
		applicationType = applicationTypeWeb
	}

	return dynamicClientRecord{
		ClientName:      strings.TrimSpace(metadata.ClientName),
		RedirectURIs:    redirectURIs,
		Scopes:          scopes,
		ApplicationType: applicationType,
	}, ""
}

// isLoopbackHost follows RFC 8252 section 7.3: the whole loopback range counts, not a fixed
// list of three spellings, so 127.0.0.2 or any other loopback address is treated the same.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// SaveDynamicClient persists a registered public client.
func (s *ControlStore) SaveDynamicClient(ctx context.Context, record dynamicClientRecord) error {
	redirects, err := json.Marshal(record.RedirectURIs)
	if err != nil {
		return err
	}
	scopes, err := json.Marshal(record.Scopes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(
		`INSERT INTO oauth_dynamic_clients(client_id, client_name, redirect_uris_json, scopes_json, application_type, created_at) VALUES(?, ?, ?, ?, ?, ?)`),
		record.ClientID, record.ClientName, string(redirects), string(scopes), record.ApplicationType,
		record.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// DynamicClient loads a registered client, reporting whether it exists.
func (s *ControlStore) DynamicClient(ctx context.Context, clientID string) (dynamicClientRecord, bool, error) {
	var record dynamicClientRecord
	var redirects, scopes, createdAt string
	err := s.db.QueryRowContext(ctx, s.bind(
		`SELECT client_id, client_name, redirect_uris_json, scopes_json, application_type, created_at FROM oauth_dynamic_clients WHERE client_id=?`), clientID).
		Scan(&record.ClientID, &record.ClientName, &redirects, &scopes, &record.ApplicationType, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return dynamicClientRecord{}, false, nil
	}
	if err != nil {
		return dynamicClientRecord{}, false, err
	}
	if err := json.Unmarshal([]byte(redirects), &record.RedirectURIs); err != nil {
		return dynamicClientRecord{}, false, err
	}
	if err := json.Unmarshal([]byte(scopes), &record.Scopes); err != nil {
		return dynamicClientRecord{}, false, err
	}
	record.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return record, true, nil
}

// oidcRegister implements RFC 7591 registration.
func (s *Server) oidcRegister(w http.ResponseWriter, r *http.Request) {
	runtime := s.runtime()
	if !runtime.config.Authentication.Local.Tokens.DynamicRegistration {
		writeRegistrationError(w, http.StatusNotFound, "invalid_client_metadata", "dynamic client registration is disabled on this broker")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRegistrationBody)
	var metadata oauthex.ClientRegistrationMetadata
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid client metadata")
		return
	}

	record, problem := validateRegistrationMetadata(&metadata)
	if problem != "" {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", problem)
		return
	}

	clientID, err := randomURLToken(24)
	if err != nil {
		writeRegistrationError(w, http.StatusInternalServerError, "invalid_client_metadata", "could not allocate a client identifier")
		return
	}
	// A generated identifier must never shadow the statically configured CLI client.
	if clientID == runtime.config.Authentication.Local.Tokens.CLIClientID {
		writeRegistrationError(w, http.StatusInternalServerError, "invalid_client_metadata", "could not allocate a client identifier")
		return
	}
	record.ClientID = clientID
	record.CreatedAt = time.Now().UTC()

	if err := s.control.SaveDynamicClient(r.Context(), record); err != nil {
		writeRegistrationError(w, http.StatusInternalServerError, "invalid_client_metadata", "could not persist the registration")
		return
	}

	response := &oauthex.ClientRegistrationResponse{
		ClientRegistrationMetadata: oauthex.ClientRegistrationMetadata{
			RedirectURIs:            record.RedirectURIs,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{string(zitoidc.GrantTypeCode), string(zitoidc.GrantTypeRefreshToken)},
			ResponseTypes:           []string{string(zitoidc.ResponseTypeCode)},
			ClientName:              record.ClientName,
			Scope:                   strings.Join(record.Scopes, " "),
			ApplicationType:         record.ApplicationType,
		},
		ClientID:         record.ClientID,
		ClientIDIssuedAt: record.CreatedAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// oidcDiscovery serves the provider's OpenID configuration, adding registration_endpoint.
//
// The library builds the document and does not populate that field (op.CreateDiscoveryConfig
// leaves oidc.DiscoveryConfiguration.RegistrationEndpoint empty), so the response is decoded,
// the one field is added, and everything else the library produced is passed through
// untouched rather than rebuilt here.
func (s *Server) oidcDiscovery(w http.ResponseWriter, r *http.Request) {
	if !s.runtime().config.Authentication.Local.Tokens.DynamicRegistration {
		s.oidcProvider.handler.ServeHTTP(w, r)
		return
	}

	recorder := &bufferedResponse{header: http.Header{}}
	s.oidcProvider.handler.ServeHTTP(recorder, r)

	var document map[string]any
	if recorder.status != http.StatusOK || json.Unmarshal(recorder.body, &document) != nil {
		recorder.copyTo(w)
		return
	}
	document["registration_endpoint"] = strings.TrimRight(s.publicURL(r), "/") + oidcRegistrationPath

	body, err := json.Marshal(document)
	if err != nil {
		recorder.copyTo(w)
		return
	}
	for key, values := range recorder.header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		w.Header()[key] = values
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// bufferedResponse captures a handler's response so one field can be added to it.
type bufferedResponse struct {
	header http.Header
	body   []byte
	status int
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	b.body = append(b.body, data...)
	return len(data), nil
}

func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedResponse) copyTo(w http.ResponseWriter) {
	for key, values := range b.header {
		w.Header()[key] = values
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body)
}

// dynamicOIDCClient adapts a registered client to the provider's client contract. It differs
// from the static CLI client only in identity, redirects and application type; everything
// else -- public authentication, Authorization Code with refresh, JWT access tokens, the
// broker's scope set -- is deliberately identical, so a registered client can never obtain
// capabilities the configured one does not have.
type dynamicOIDCClient struct {
	brokerOIDCClient
	record dynamicClientRecord
}

func (c *dynamicOIDCClient) GetID() string { return c.record.ClientID }
func (c *dynamicOIDCClient) RedirectURIs() []string {
	return append([]string(nil), c.record.RedirectURIs...)
}
func (c *dynamicOIDCClient) ApplicationType() op.ApplicationType {
	if c.record.ApplicationType == applicationTypeWeb {
		return op.ApplicationTypeWeb
	}
	return op.ApplicationTypeNative
}
