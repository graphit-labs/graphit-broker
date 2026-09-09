package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	localAPIScope           = "graphit.use"
	offlineAccessScope      = "offline_access"
	localAccessTokenPrefix  = "gb_at_"
	localRefreshTokenPrefix = "gb_rt_"
	serviceCredentialPrefix = "gb_sc_"
	authorizationCodePrefix = "gb_ac_"
	deviceCodePrefix        = "gb_dc_"
	localAccessTokenDomain  = "graphit-broker/local-access-token/v1"
	localRefreshTokenDomain = "graphit-broker/local-refresh-token/v1"
	serviceCredentialDomain = "graphit-broker/service-credential/v1"
	authorizationCodeDomain = "graphit-broker/authorization-code/v1"
	deviceCodeDomain        = "graphit-broker/device-code/v1"
	deviceUserCodeDomain    = "graphit-broker/device-user-code/v1"
	localTokenKindAccess    = "access"
	localTokenKindRefresh   = "refresh"
	localTokenKindService   = "service"
	deviceStatusPending     = "pending"
	deviceStatusApproved    = "approved"
)

var (
	ErrAuthorizationPending = errors.New("authorization pending")
	ErrSlowDown             = errors.New("device polling too quickly")
	ErrExpiredToken         = errors.New("token expired")
)

type LocalTokenGrant struct {
	Subject           string
	LocalUserRevision int64
	ClientID          string
	Audience          string
	Scopes            []string
	FamilyID          string
	ExpiresAt         time.Time
	RefreshExpiresAt  time.Time
}

type AuthorizationCodeGrant struct {
	LocalTokenGrant
	RedirectURI   string
	CodeChallenge string
}

type DeviceAuthorization struct {
	ClientID     string
	Scopes       []string
	Interval     time.Duration
	ExpiresAt    time.Time
	Subject      string
	UserRevision int64
}

type ServiceCredential struct {
	ID         string     `json:"id"`
	Subject    string     `json:"subject"`
	ClientID   string     `json:"client_id"`
	Audience   string     `json:"audience"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func tokenDomain(raw string) (string, string, bool) {
	switch {
	case strings.HasPrefix(raw, localAccessTokenPrefix):
		return localAccessTokenDomain, localTokenKindAccess, true
	case strings.HasPrefix(raw, localRefreshTokenPrefix):
		return localRefreshTokenDomain, localTokenKindRefresh, true
	case strings.HasPrefix(raw, serviceCredentialPrefix):
		return serviceCredentialDomain, localTokenKindService, true
	default:
		return "", "", false
	}
}

func (s *ControlStore) SaveAuthorizationCode(ctx context.Context, raw string, grant AuthorizationCodeGrant) error {
	scopes, err := json.Marshal(cleanStrings(grant.Scopes))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO oauth_authorization_codes(code_hash, subject, local_user_revision, client_id, redirect_uri, code_challenge, scopes_json, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.tokenHash(authorizationCodeDomain, raw), strings.TrimSpace(grant.Subject), grant.LocalUserRevision,
		strings.TrimSpace(grant.ClientID), grant.RedirectURI, grant.CodeChallenge, string(scopes),
		grant.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *ControlStore) ConsumeAuthorizationCode(ctx context.Context, raw, clientID, redirectURI, verifier string) (LocalTokenGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LocalTokenGrant{}, err
	}
	defer tx.Rollback()
	var grant LocalTokenGrant
	var storedRedirect, challenge, scopesJSON, expires string
	hash := s.tokenHash(authorizationCodeDomain, raw)
	err = tx.QueryRowContext(ctx, s.bind(`SELECT subject, local_user_revision, client_id, redirect_uri, code_challenge, scopes_json, expires_at FROM oauth_authorization_codes WHERE code_hash=?`), hash).
		Scan(&grant.Subject, &grant.LocalUserRevision, &grant.ClientID, &storedRedirect, &challenge, &scopesJSON, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	if err != nil {
		return LocalTokenGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM oauth_authorization_codes WHERE code_hash=?`), hash); err != nil {
		return LocalTokenGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return LocalTokenGrant{}, err
	}
	grant.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil || !grant.ExpiresAt.After(time.Now()) || grant.ClientID != strings.TrimSpace(clientID) || storedRedirect != redirectURI {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	if err := json.Unmarshal([]byte(scopesJSON), &grant.Scopes); err != nil {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(verifier))
	if !constantEqual(challenge, base64.RawURLEncoding.EncodeToString(digest[:])) {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	return grant, nil
}

func (s *ControlStore) SaveDeviceAuthorization(ctx context.Context, rawDeviceCode, rawUserCode string, authorization DeviceAuthorization) error {
	scopes, err := json.Marshal(cleanStrings(authorization.Scopes))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO oauth_device_codes(device_hash, user_hash, client_id, scopes_json, subject, local_user_revision, status, interval_seconds, last_poll_at, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.tokenHash(deviceCodeDomain, rawDeviceCode), s.tokenHash(deviceUserCodeDomain, normalizeUserCode(rawUserCode)),
		authorization.ClientID, string(scopes), "", 0, deviceStatusPending, int64(authorization.Interval/time.Second), "",
		authorization.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *ControlStore) ApproveDeviceAuthorization(ctx context.Context, rawUserCode string, user LocalUser) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, s.bind(`UPDATE oauth_device_codes SET subject=?, local_user_revision=?, status=? WHERE user_hash=? AND status=? AND expires_at>?`),
		user.Subject, user.Revision, deviceStatusApproved, s.tokenHash(deviceUserCodeDomain, normalizeUserCode(rawUserCode)), deviceStatusPending, now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrUnauthenticated
	}
	return nil
}

func (s *ControlStore) PollDeviceAuthorization(ctx context.Context, rawDeviceCode, clientID string) (LocalTokenGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LocalTokenGrant{}, err
	}
	defer tx.Rollback()
	var grant LocalTokenGrant
	var status, scopesJSON, lastPoll, expires string
	var intervalSeconds int64
	hash := s.tokenHash(deviceCodeDomain, rawDeviceCode)
	err = tx.QueryRowContext(ctx, s.bind(`SELECT subject, local_user_revision, client_id, scopes_json, status, interval_seconds, last_poll_at, expires_at FROM oauth_device_codes WHERE device_hash=?`), hash).
		Scan(&grant.Subject, &grant.LocalUserRevision, &grant.ClientID, &scopesJSON, &status, &intervalSeconds, &lastPoll, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	if err != nil {
		return LocalTokenGrant{}, err
	}
	now := time.Now().UTC()
	grant.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil || !grant.ExpiresAt.After(now) {
		_, _ = tx.ExecContext(ctx, s.bind(`DELETE FROM oauth_device_codes WHERE device_hash=?`), hash)
		_ = tx.Commit()
		return LocalTokenGrant{}, ErrExpiredToken
	}
	if grant.ClientID != strings.TrimSpace(clientID) {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	if lastPoll != "" {
		previous, parseErr := time.Parse(time.RFC3339Nano, lastPoll)
		if parseErr == nil && now.Sub(previous) < time.Duration(intervalSeconds)*time.Second {
			return LocalTokenGrant{}, ErrSlowDown
		}
	}
	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE oauth_device_codes SET last_poll_at=? WHERE device_hash=?`), now.Format(time.RFC3339Nano), hash); err != nil {
		return LocalTokenGrant{}, err
	}
	if status == deviceStatusPending {
		if err := tx.Commit(); err != nil {
			return LocalTokenGrant{}, err
		}
		return LocalTokenGrant{}, ErrAuthorizationPending
	}
	if status != deviceStatusApproved || grant.Subject == "" {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM oauth_device_codes WHERE device_hash=?`), hash); err != nil {
		return LocalTokenGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return LocalTokenGrant{}, err
	}
	if err := json.Unmarshal([]byte(scopesJSON), &grant.Scopes); err != nil {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	return grant, nil
}

func (s *ControlStore) SaveTokenPair(ctx context.Context, accessRaw, accessID, refreshRaw, refreshID string, grant LocalTokenGrant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := s.insertLocalToken(ctx, tx, accessRaw, accessID, localTokenKindAccess, grant, grant.ExpiresAt, now); err != nil {
		return err
	}
	if refreshRaw != "" {
		refreshExpiry := grant.RefreshExpiresAt
		if !refreshExpiry.After(now) {
			return errors.New("refresh token expiry must be in the future")
		}
		if err := s.insertLocalToken(ctx, tx, refreshRaw, refreshID, localTokenKindRefresh, grant, refreshExpiry, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ControlStore) SaveServiceCredential(ctx context.Context, raw, id string, grant LocalTokenGrant) error {
	user, err := s.LocalUserBySubject(ctx, grant.Subject)
	if err != nil || user.Kind != serviceIdentityKind || !user.Enabled || user.Revision != grant.LocalUserRevision {
		return errors.New("service credential requires an enabled service identity")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.insertLocalToken(ctx, tx, raw, id, localTokenKindService, grant, grant.ExpiresAt, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *ControlStore) insertLocalToken(ctx context.Context, tx *sql.Tx, raw, id, kind string, grant LocalTokenGrant, expires, now time.Time) error {
	domain, detected, ok := tokenDomain(raw)
	if !ok || detected != kind {
		return errors.New("local token type does not match its prefix")
	}
	scopes, err := json.Marshal(cleanStrings(grant.Scopes))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO local_tokens(token_hash, token_id, token_kind, subject, client_id, audience, scopes_json, local_user_revision, family_id, expires_at, revoked_at, consumed_at, last_used_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.tokenHash(domain, raw), id, kind, grant.Subject, grant.ClientID, grant.Audience, string(scopes), grant.LocalUserRevision,
		grant.FamilyID, expires.UTC().Format(time.RFC3339Nano), "", "", "", now.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *ControlStore) AuthenticateLocalToken(ctx context.Context, raw, audience string, requiredScopes []string) (Principal, error) {
	domain, expectedKind, ok := tokenDomain(raw)
	if !ok || expectedKind == localTokenKindRefresh {
		return Principal{}, ErrUnauthenticated
	}
	var kind, subject, storedAudience, scopesJSON, expires, revoked string
	var revision int64
	hash := s.tokenHash(domain, raw)
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT token_kind, subject, audience, scopes_json, local_user_revision, expires_at, revoked_at FROM local_tokens WHERE token_hash=?`), hash).
		Scan(&kind, &subject, &storedAudience, &scopesJSON, &revision, &expires, &revoked)
	if err != nil || kind != expectedKind || revoked != "" || storedAudience != strings.TrimSpace(audience) {
		return Principal{}, ErrUnauthenticated
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !expiresAt.After(time.Now()) {
		return Principal{}, ErrUnauthenticated
	}
	var scopes []string
	if json.Unmarshal([]byte(scopesJSON), &scopes) != nil {
		return Principal{}, ErrUnauthenticated
	}
	for _, required := range cleanStrings(requiredScopes) {
		if !containsString(scopes, required) {
			return Principal{}, ErrUnauthenticated
		}
	}
	user, err := s.LocalUserBySubject(ctx, subject)
	if err != nil || !user.Enabled || user.Revision != revision {
		return Principal{}, ErrUnauthenticated
	}
	if kind == localTokenKindService && user.Kind != serviceIdentityKind {
		return Principal{}, ErrUnauthenticated
	}
	if kind == localTokenKindAccess && user.Kind != humanIdentityKind {
		return Principal{}, ErrUnauthenticated
	}
	_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE local_tokens SET last_used_at=? WHERE token_hash=?`), time.Now().UTC().Format(time.RFC3339Nano), hash)
	principal := principalFromLocalUser(user, "local-token")
	if kind == localTokenKindService {
		principal.AuthMethod = "service-credential"
	}
	principal.Scopes = cleanStrings(scopes)
	return principal, nil
}

func (s *ControlStore) ConsumeRefreshToken(ctx context.Context, raw, clientID string) (LocalTokenGrant, error) {
	if !strings.HasPrefix(raw, localRefreshTokenPrefix) {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LocalTokenGrant{}, err
	}
	defer tx.Rollback()
	hash := s.tokenHash(localRefreshTokenDomain, raw)
	var grant LocalTokenGrant
	var scopesJSON, expires, revoked, consumed string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT subject, local_user_revision, client_id, audience, scopes_json, family_id, expires_at, revoked_at, consumed_at FROM local_tokens WHERE token_hash=? AND token_kind=?`), hash, localTokenKindRefresh).
		Scan(&grant.Subject, &grant.LocalUserRevision, &grant.ClientID, &grant.Audience, &scopesJSON, &grant.FamilyID, &expires, &revoked, &consumed)
	if err != nil || grant.ClientID != strings.TrimSpace(clientID) || revoked != "" {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	if consumed != "" {
		_, _ = tx.ExecContext(ctx, s.bind(`UPDATE local_tokens SET revoked_at=? WHERE family_id=? AND revoked_at=?`), time.Now().UTC().Format(time.RFC3339Nano), grant.FamilyID, "")
		_ = tx.Commit()
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	parsedExpiry, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !parsedExpiry.After(time.Now()) {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	grant.RefreshExpiresAt = parsedExpiry
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE local_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at=?`), time.Now().UTC().Format(time.RFC3339Nano), hash, "")
	if err != nil {
		return LocalTokenGrant{}, err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		_, _ = tx.ExecContext(ctx, s.bind(`UPDATE local_tokens SET revoked_at=? WHERE family_id=? AND revoked_at=?`), time.Now().UTC().Format(time.RFC3339Nano), grant.FamilyID, "")
		_ = tx.Commit()
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	if err := tx.Commit(); err != nil {
		return LocalTokenGrant{}, err
	}
	if json.Unmarshal([]byte(scopesJSON), &grant.Scopes) != nil {
		return LocalTokenGrant{}, ErrUnauthenticated
	}
	return grant, nil
}

func (s *ControlStore) RevokeRawToken(ctx context.Context, raw string) error {
	domain, _, ok := tokenDomain(raw)
	if !ok {
		return nil
	}
	hash := s.tokenHash(domain, raw)
	var family string
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT family_id FROM local_tokens WHERE token_hash=?`), hash).Scan(&family); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if family != "" {
		_, err := s.db.ExecContext(ctx, s.bind(`UPDATE local_tokens SET revoked_at=? WHERE family_id=? AND revoked_at=?`), now, family, "")
		return err
	}
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE local_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at=?`), now, hash, "")
	return err
}

func (s *ControlStore) ServiceCredentials(ctx context.Context, subject string) ([]ServiceCredential, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT token_id, subject, client_id, audience, scopes_json, expires_at, revoked_at, last_used_at, created_at FROM local_tokens WHERE subject=? AND token_kind=? ORDER BY created_at DESC`), strings.TrimSpace(subject), localTokenKindService)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ServiceCredential
	for rows.Next() {
		var credential ServiceCredential
		var scopesJSON, expires, revoked, lastUsed, created string
		if err := rows.Scan(&credential.ID, &credential.Subject, &credential.ClientID, &credential.Audience, &scopesJSON, &expires, &revoked, &lastUsed, &created); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(scopesJSON), &credential.Scopes) != nil {
			return nil, errors.New("stored service credential scopes are invalid")
		}
		credential.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		credential.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if revoked != "" {
			value, _ := time.Parse(time.RFC3339Nano, revoked)
			credential.RevokedAt = &value
		}
		if lastUsed != "" {
			value, _ := time.Parse(time.RFC3339Nano, lastUsed)
			credential.LastUsedAt = &value
		}
		result = append(result, credential)
	}
	return result, rows.Err()
}

func (s *ControlStore) RevokeServiceCredential(ctx context.Context, subject, id string) error {
	result, err := s.db.ExecContext(ctx, s.bind(`UPDATE local_tokens SET revoked_at=? WHERE subject=? AND token_id=? AND token_kind=? AND revoked_at=?`),
		time.Now().UTC().Format(time.RFC3339Nano), strings.TrimSpace(subject), strings.TrimSpace(id), localTokenKindService, "")
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return fmt.Errorf("service credential does not exist or is already revoked")
	}
	return nil
}

func normalizeUserCode(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}
