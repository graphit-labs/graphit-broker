package broker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrRevisionConflict  = errors.New("revision conflict")
	ErrLocalUserNotFound = errors.New("local user not found")
	ErrLocalUsersExist   = errors.New("local users already exist")
)

const (
	adminRole               = "admin"
	userRole                = "user"
	humanIdentityKind       = "human"
	serviceIdentityKind     = "service"
	localIdentityIssuer     = "local"
	schemaVersion           = 11
	tokenPepperMinimumBytes = 32
	adminSessionTokenDomain = "graphit-broker/admin-session/v1"
	oidcFlowTokenDomain     = "graphit-broker/oidc-flow/v1"
	oidcFlowBindingDomain   = "graphit-broker/oidc-flow-binding/v1"
)

var systemActions = []string{
	"session.read", "configuration.read",
	"grants.read", "grants.write", "roles.read", "roles.write", "users.read", "users.write", "projects.read",
}

var userActions = []string{"session.read", "projects.read"}

// ControlStore owns all durable broker state. Domain persistence is portable across the SQL
// backends supported by DatabaseDialect.
type ControlStore struct {
	db          *sql.DB
	dialect     DatabaseDialect
	tokenPepper []byte
}

type Role struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type LocalUser struct {
	Username               string    `json:"username"`
	Subject                string    `json:"subject"`
	Kind                   string    `json:"kind"`
	Name                   string    `json:"name,omitempty"`
	Email                  string    `json:"email,omitempty"`
	Organization           string    `json:"organization,omitempty"`
	Teams                  []string  `json:"teams,omitempty"`
	Roles                  []string  `json:"roles"`
	Enabled                bool      `json:"enabled"`
	PasswordChangeRequired bool      `json:"password_change_required"`
	MFAEnabled             bool      `json:"mfa_enabled"`
	Revision               int64     `json:"revision"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
	PasswordHash           string    `json:"-"`
	PasswordChanged        bool      `json:"-"`
}

type RoleAssignment struct {
	Subject   string    `json:"subject"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type AdminSession struct {
	Issuer            string
	Subject           string
	Name              string
	Email             string
	Username          string
	Organization      string
	Teams             []string
	Roles             []string
	RolesFromClaim    bool
	RoleClaimSelector string
	LocalUserRevision int64
	CSRFToken         string
	ExpiresAt         time.Time
}

type OIDCFlow struct {
	Nonce        string
	PKCEVerifier string
	Purpose      string
	Continuation string
	ExpiresAt    time.Time
}

func OpenControlStore(cfg DatabaseConfig, tokenPepper string) (*ControlStore, error) {
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), cfg.connectTimeout())
	db, dialect, err := openDatabase(connectCtx, cfg)
	cancelConnect()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store := &ControlStore{db: db, dialect: dialect, tokenPepper: []byte(tokenPepper)}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if dialect.Name() == "sqlite" {
		if err := secureSQLiteFile(cfg.DSN); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return store, nil
}

func (s *ControlStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	clear(s.tokenPepper)
	return s.db.Close()
}

func (s *ControlStore) bind(query string) string { return s.dialect.Bind(query) }

func (s *ControlStore) initialize(ctx context.Context) error {
	if s.dialect.Name() == "sqlite" {
		for _, statement := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`} {
			if _, err := s.db.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("configure SQLite: %w", err)
			}
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database initialization: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_meta (id SMALLINT PRIMARY KEY, version BIGINT NOT NULL)`); err != nil {
		return fmt.Errorf("initialize %s schema version table: %w", s.dialect.Name(), err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO schema_meta(id, version) VALUES(?, ?)`)), 1, schemaVersion); err != nil {
		return fmt.Errorf("seed schema version: %w", err)
	}
	var storedSchemaVersion int
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT version FROM schema_meta WHERE id=?`), 1).Scan(&storedSchemaVersion); err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	if storedSchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported database schema version %d: recreate the database", storedSchemaVersion)
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS roles (name VARCHAR(128) PRIMARY KEY, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS role_permissions (role VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL, PRIMARY KEY(role, action), FOREIGN KEY(role) REFERENCES roles(name) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS role_assignments (subject VARCHAR(512) NOT NULL, role VARCHAR(128) NOT NULL, created_at VARCHAR(40) NOT NULL, PRIMARY KEY(subject, role), FOREIGN KEY(role) REFERENCES roles(name) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS admin_sessions (token_hash VARCHAR(64) PRIMARY KEY, subject VARCHAR(512) NOT NULL, name VARCHAR(512) NOT NULL, email VARCHAR(512) NOT NULL, csrf_token VARCHAR(128) NOT NULL, expires_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS admin_session_principals (token_hash VARCHAR(64) PRIMARY KEY, issuer VARCHAR(1024) NOT NULL, username VARCHAR(512) NOT NULL, organization VARCHAR(512) NOT NULL, teams_json TEXT NOT NULL, local_user_revision BIGINT NOT NULL, FOREIGN KEY(token_hash) REFERENCES admin_sessions(token_hash) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS admin_session_claim_roles (token_hash VARCHAR(64) PRIMARY KEY, claim_selector VARCHAR(4096) NOT NULL, roles_json TEXT NOT NULL, FOREIGN KEY(token_hash) REFERENCES admin_sessions(token_hash) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS oidc_flows (state_hash VARCHAR(64) PRIMARY KEY, browser_binding_hash VARCHAR(64) NOT NULL, nonce VARCHAR(128) NOT NULL, pkce_verifier VARCHAR(256) NOT NULL, purpose VARCHAR(32) NOT NULL, continuation_json TEXT NOT NULL, expires_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS local_users (username VARCHAR(128) PRIMARY KEY, subject VARCHAR(512) NOT NULL UNIQUE, identity_kind VARCHAR(16) NOT NULL, password_hash VARCHAR(512) NOT NULL, name VARCHAR(512) NOT NULL, email VARCHAR(512) NOT NULL, organization VARCHAR(512) NOT NULL, teams_json TEXT NOT NULL, enabled SMALLINT NOT NULL, password_change_required SMALLINT NOT NULL, revision BIGINT NOT NULL, created_at VARCHAR(40) NOT NULL, updated_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS local_mfa (subject VARCHAR(512) PRIMARY KEY, secret_ciphertext TEXT NOT NULL, last_totp_step BIGINT NOT NULL, confirmed_at VARCHAR(40) NOT NULL, FOREIGN KEY(subject) REFERENCES local_users(subject) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS local_mfa_recovery_codes (subject VARCHAR(512) NOT NULL, code_hash VARCHAR(64) NOT NULL, created_at VARCHAR(40) NOT NULL, PRIMARY KEY(subject, code_hash), FOREIGN KEY(subject) REFERENCES local_users(subject) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS local_auth_challenges (challenge_hash VARCHAR(64) PRIMARY KEY, subject VARCHAR(512) NOT NULL, local_user_revision BIGINT NOT NULL, purpose VARCHAR(32) NOT NULL, binding_hash VARCHAR(64) NOT NULL, stage VARCHAR(32) NOT NULL, secret_ciphertext TEXT NOT NULL, expires_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL, FOREIGN KEY(subject) REFERENCES local_users(subject) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS local_tokens (token_hash VARCHAR(64) PRIMARY KEY, token_id VARCHAR(128) NOT NULL UNIQUE, token_kind VARCHAR(16) NOT NULL, subject VARCHAR(512) NOT NULL, oidc_subject VARCHAR(128) NOT NULL, principal_json TEXT NOT NULL, client_id VARCHAR(128) NOT NULL, audience VARCHAR(128) NOT NULL, resource VARCHAR(512) NOT NULL DEFAULT '', scopes_json TEXT NOT NULL, local_user_revision BIGINT NOT NULL, family_id VARCHAR(128) NOT NULL, auth_time VARCHAR(40) NOT NULL, expires_at VARCHAR(40) NOT NULL, revoked_at VARCHAR(40) NOT NULL, consumed_at VARCHAR(40) NOT NULL, last_used_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS oidc_auth_requests (request_hash VARCHAR(64) PRIMARY KEY, identity_subject VARCHAR(512) NOT NULL, request_json TEXT NOT NULL, code_hash VARCHAR(64) UNIQUE, expires_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS oauth_device_codes (device_hash VARCHAR(64) PRIMARY KEY, user_hash VARCHAR(64) NOT NULL UNIQUE, client_id VARCHAR(128) NOT NULL, scopes_json TEXT NOT NULL, subject VARCHAR(512) NOT NULL, local_user_revision BIGINT NOT NULL, status VARCHAR(16) NOT NULL, interval_seconds BIGINT NOT NULL, last_poll_at VARCHAR(40) NOT NULL, expires_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
		// Clients registered through RFC 7591. Only public clients are ever stored, so there
		// is no secret column to leak: the absence of one is the schema asserting that a
		// confidential client cannot be created by registration.
		`CREATE TABLE IF NOT EXISTS oauth_dynamic_clients (client_id VARCHAR(128) PRIMARY KEY, client_name VARCHAR(256) NOT NULL, redirect_uris_json TEXT NOT NULL, scopes_json TEXT NOT NULL, application_type VARCHAR(16) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS resource_acl_state (id SMALLINT PRIMARY KEY, revision BIGINT NOT NULL, updated_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS resource_grants (id VARCHAR(128) PRIMARY KEY, name VARCHAR(256) NOT NULL, access_kind VARCHAR(32) NOT NULL, principal VARCHAR(512) NOT NULL, s3_route VARCHAR(128) NOT NULL, created_at VARCHAR(40) NOT NULL, updated_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS grant_capabilities (grant_id VARCHAR(128) NOT NULL, value VARCHAR(128) NOT NULL, PRIMARY KEY(grant_id, value), FOREIGN KEY(grant_id) REFERENCES resource_grants(id) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS grant_projects (grant_id VARCHAR(128) NOT NULL, value VARCHAR(256) NOT NULL, PRIMARY KEY(grant_id, value), FOREIGN KEY(grant_id) REFERENCES resource_grants(id) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS grant_s3_operations (grant_id VARCHAR(128) NOT NULL, value VARCHAR(32) NOT NULL, PRIMARY KEY(grant_id, value), FOREIGN KEY(grant_id) REFERENCES resource_grants(id) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS grant_s3_prefixes (grant_id VARCHAR(128) NOT NULL, value VARCHAR(512) NOT NULL, PRIMARY KEY(grant_id, value), FOREIGN KEY(grant_id) REFERENCES resource_grants(id) ON DELETE CASCADE)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize %s schema: %w", s.dialect.Name(), err)
		}
	}
	vectorType := "TEXT"
	if s.dialect.Name() == "mysql" {
		vectorType = "LONGTEXT"
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS embedding_cache (`+
		`compatibility_hash VARCHAR(64) NOT NULL, input_hash VARCHAR(64) NOT NULL, `+
		`provider TEXT NOT NULL, revision TEXT NOT NULL, model TEXT NOT NULL, `+
		`input_type VARCHAR(16) NOT NULL, embedding_json `+vectorType+` NOT NULL, `+
		`PRIMARY KEY(compatibility_hash, input_hash))`); err != nil {
		return fmt.Errorf("initialize embedding cache: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO roles(name, created_at) VALUES(?, ?)`)), adminRole, now); err != nil {
		return fmt.Errorf("seed admin role: %w", err)
	}
	for _, action := range systemActions {
		if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO role_permissions(role, action) VALUES(?, ?)`)), adminRole, action); err != nil {
			return fmt.Errorf("seed admin permissions: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO roles(name, created_at) VALUES(?, ?)`)), userRole, now); err != nil {
		return fmt.Errorf("seed user role: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM role_permissions WHERE role=?`), userRole); err != nil {
		return fmt.Errorf("reset user permissions: %w", err)
	}
	for _, action := range userActions {
		if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO role_permissions(role, action) VALUES(?, ?)`)), userRole, action); err != nil {
			return fmt.Errorf("seed user permissions: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO resource_acl_state(id, revision, updated_at) VALUES(?, ?, ?)`)), 1, 1, now); err != nil {
		return fmt.Errorf("seed resource ACL revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database initialization: %w", err)
	}
	return nil
}

func (s *ControlStore) Authorize(ctx context.Context, subject, action string) (bool, error) {
	permissions, err := s.SubjectPermissions(ctx, subject)
	if err != nil {
		return false, fmt.Errorf("authorize principal: %w", err)
	}
	return containsString(permissions, action) || containsString(permissions, "*"), nil
}

func (s *ControlStore) AssignmentCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_assignments`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count role assignments: %w", err)
	}
	return count, nil
}

func (s *ControlStore) SubjectRoles(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT role FROM role_assignments WHERE subject=? ORDER BY role`), strings.TrimSpace(subject))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []string{userRole}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		if value != userRole {
			values = append(values, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cleanStrings(values), nil
}

func (s *ControlStore) SubjectPermissions(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT DISTINCT p.action FROM role_permissions p WHERE p.role=? OR p.role IN (SELECT a.role FROM role_assignments a WHERE a.subject=?) ORDER BY p.action`), userRole, strings.TrimSpace(subject))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *ControlStore) RolePermissions(ctx context.Context, roles []string) ([]string, error) {
	roles = cleanStrings(append(roles, userRole))
	placeholders := make([]string, len(roles))
	arguments := make([]any, len(roles))
	for i, role := range roles {
		placeholders[i], arguments[i] = "?", role
	}
	query := `SELECT DISTINCT action FROM role_permissions WHERE role IN (` + strings.Join(placeholders, ",") + `) ORDER BY action`
	rows, err := s.db.QueryContext(ctx, s.bind(query), arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *ControlStore) AuthorizeRoles(ctx context.Context, roles []string, action string) (bool, error) {
	permissions, err := s.RolePermissions(ctx, roles)
	if err != nil {
		return false, fmt.Errorf("authorize claimed roles: %w", err)
	}
	return containsString(permissions, action) || containsString(permissions, "*"), nil
}

func (s *ControlStore) Roles(ctx context.Context) ([]Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.name, COALESCE(p.action, '') FROM roles r LEFT JOIN role_permissions p ON p.role=r.name ORDER BY r.name, p.action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byName := map[string]*Role{}
	var order []string
	for rows.Next() {
		var name, action string
		if err := rows.Scan(&name, &action); err != nil {
			return nil, err
		}
		role := byName[name]
		if role == nil {
			role = &Role{Name: name}
			byName[name] = role
			order = append(order, name)
		}
		if action != "" {
			role.Permissions = append(role.Permissions, action)
		}
	}
	result := make([]Role, 0, len(order))
	for _, name := range order {
		result = append(result, *byName[name])
	}
	return result, rows.Err()
}

func (s *ControlStore) SetRole(ctx context.Context, role Role) error {
	role.Name = strings.TrimSpace(role.Name)
	role.Permissions = cleanStrings(role.Permissions)
	switch role.Name {
	case adminRole:
		role.Permissions = append([]string(nil), systemActions...)
	case userRole:
		role.Permissions = append([]string(nil), userActions...)
	}
	if !safeSegment(role.Name) || len(role.Permissions) == 0 {
		return errors.New("role needs a safe name and at least one permission")
	}
	for _, action := range role.Permissions {
		if !validSystemAction(action) {
			return fmt.Errorf("unsupported system action %q", action)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO roles(name, created_at) VALUES(?, ?)`)), role.Name, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM role_permissions WHERE role=?`), role.Name); err != nil {
		return err
	}
	for _, action := range role.Permissions {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO role_permissions(role, action) VALUES(?, ?)`), role.Name, action); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ControlStore) DeleteRole(ctx context.Context, role string) error {
	role = strings.TrimSpace(role)
	if role == adminRole || role == userRole {
		return errors.New("built-in roles cannot be deleted")
	}
	if !safeSegment(role) {
		return errors.New("a safe role name is required")
	}
	result, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM roles WHERE name=?`), role)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return errors.New("role does not exist")
	}
	return nil
}

func validSystemAction(action string) bool {
	if action == "*" {
		return true
	}
	for _, allowed := range systemActions {
		if action == allowed {
			return true
		}
	}
	return false
}

func (s *ControlStore) Assignments(ctx context.Context) ([]RoleAssignment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject, role, created_at FROM role_assignments ORDER BY subject, role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []RoleAssignment
	for rows.Next() {
		var item RoleAssignment
		var created string
		if err := rows.Scan(&item.Subject, &item.Role, &created); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *ControlStore) AssignRole(ctx context.Context, subject, role string) error {
	subject, role = strings.TrimSpace(subject), strings.TrimSpace(role)
	if subject == "" || !safeSegment(role) {
		return errors.New("subject and a safe role are required")
	}
	_, err := s.db.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO role_assignments(subject, role, created_at) VALUES(?, ?, ?)`)), subject, role, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *ControlStore) RevokeRole(ctx context.Context, subject, role string) error {
	subject, role = strings.TrimSpace(subject), strings.TrimSpace(role)
	if role == adminRole {
		last, err := s.isLastAssignedAdmin(ctx, subject)
		if err != nil {
			return err
		}
		if last {
			return errors.New("cannot revoke the last assigned admin role")
		}
	}
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM role_assignments WHERE subject=? AND role=?`), subject, role)
	return err
}

func (s *ControlStore) isLastAssignedAdmin(ctx context.Context, subject string) (bool, error) {
	assignments, err := s.Assignments(ctx)
	if err != nil {
		return false, err
	}
	currentIsAdmin := false
	var others []string
	for _, assignment := range assignments {
		if assignment.Role != adminRole {
			continue
		}
		if assignment.Subject == subject {
			currentIsAdmin = true
		} else {
			others = append(others, assignment.Subject)
		}
	}
	if !currentIsAdmin {
		return false, nil
	}
	users, err := s.LocalUsers(ctx)
	if err != nil {
		return false, err
	}
	enabledLocalAdmins := map[string]bool{}
	for _, user := range users {
		enabledLocalAdmins[localUserCanonicalSubject(user.Subject)] = user.Enabled
	}
	for _, candidate := range others {
		if !strings.HasPrefix(candidate, localIdentityIssuer+"|") || enabledLocalAdmins[candidate] {
			return false, nil
		}
	}
	return true, nil
}

func localUserCanonicalSubject(subject string) string {
	return localIdentityIssuer + "|" + strings.TrimSpace(subject)
}

func validateLocalUser(user LocalUser, passwordRequired bool) error {
	if user.Kind == "" {
		user.Kind = humanIdentityKind
	}
	if user.Kind != humanIdentityKind && user.Kind != serviceIdentityKind {
		return errors.New("local user kind must be human or service")
	}
	if !safeSegment(user.Username) {
		return errors.New("local user username must be a safe non-empty identifier")
	}
	if strings.TrimSpace(user.Subject) == "" || len(user.Subject) > 512 {
		return errors.New("local user subject is required and must not exceed 512 bytes")
	}
	if user.Kind == serviceIdentityKind && user.PasswordHash != "" {
		return errors.New("service identities must not have a password")
	}
	if user.Kind == humanIdentityKind && (passwordRequired || user.PasswordHash != "") {
		if _, err := parsePasswordVerifier(user.PasswordHash); err != nil {
			return fmt.Errorf("local user password hash: %w", err)
		}
	}
	for _, role := range cleanStrings(user.Roles) {
		if !safeSegment(role) {
			return fmt.Errorf("local user role %q is invalid", role)
		}
	}
	return nil
}

func assignedRoles(roles []string) []string {
	values := cleanStrings(roles)
	result := values[:0]
	for _, role := range values {
		if role != userRole {
			result = append(result, role)
		}
	}
	return result
}

func (s *ControlStore) LocalUserCount(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_users`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count local users: %w", err)
	}
	return count, nil
}

func (s *ControlStore) EnabledLocalHumanCount(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM local_users WHERE identity_kind=? AND enabled=?`), humanIdentityKind, 1).Scan(&count); err != nil {
		return 0, fmt.Errorf("count enabled local human users: %w", err)
	}
	return count, nil
}

func (s *ControlStore) LocalUsers(ctx context.Context) ([]LocalUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, subject, identity_kind, name, email, organization, teams_json, enabled, password_change_required, revision, created_at, updated_at, (SELECT COUNT(*) FROM local_mfa WHERE local_mfa.subject=local_users.subject) FROM local_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	var users []LocalUser
	for rows.Next() {
		user, err := scanLocalUser(rows, false)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range users {
		var err error
		users[i].Roles, err = s.SubjectRoles(ctx, localUserCanonicalSubject(users[i].Subject))
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

type rowScanner interface{ Scan(...any) error }

func scanLocalUser(row rowScanner, withPassword bool) (LocalUser, error) {
	var user LocalUser
	var teams, created, updated string
	var enabled, passwordChangeRequired, mfaEnabled int
	values := []any{&user.Username, &user.Subject, &user.Kind}
	if withPassword {
		values = append(values, &user.PasswordHash)
	}
	values = append(values, &user.Name, &user.Email, &user.Organization, &teams, &enabled, &passwordChangeRequired, &user.Revision, &created, &updated, &mfaEnabled)
	if err := row.Scan(values...); err != nil {
		return LocalUser{}, err
	}
	if err := json.Unmarshal([]byte(teams), &user.Teams); err != nil {
		return LocalUser{}, fmt.Errorf("decode local user teams: %w", err)
	}
	user.Teams = cleanStrings(user.Teams)
	user.Enabled = enabled != 0
	user.PasswordChangeRequired = passwordChangeRequired != 0
	user.MFAEnabled = mfaEnabled != 0
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return user, nil
}

func (s *ControlStore) LocalUserByUsername(ctx context.Context, username string) (LocalUser, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT username, subject, identity_kind, password_hash, name, email, organization, teams_json, enabled, password_change_required, revision, created_at, updated_at, (SELECT COUNT(*) FROM local_mfa WHERE local_mfa.subject=local_users.subject) FROM local_users WHERE username=?`), strings.TrimSpace(username))
	user, err := scanLocalUser(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalUser{}, ErrLocalUserNotFound
	}
	if err != nil {
		return LocalUser{}, err
	}
	user.Roles, err = s.SubjectRoles(ctx, localUserCanonicalSubject(user.Subject))
	if err != nil {
		return LocalUser{}, err
	}
	return user, nil
}

func (s *ControlStore) LocalUserBySubject(ctx context.Context, subject string) (LocalUser, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT username, subject, identity_kind, password_hash, name, email, organization, teams_json, enabled, password_change_required, revision, created_at, updated_at, (SELECT COUNT(*) FROM local_mfa WHERE local_mfa.subject=local_users.subject) FROM local_users WHERE subject=?`), strings.TrimSpace(subject))
	user, err := scanLocalUser(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalUser{}, ErrLocalUserNotFound
	}
	if err != nil {
		return LocalUser{}, err
	}
	user.Roles, err = s.SubjectRoles(ctx, localUserCanonicalSubject(user.Subject))
	if err != nil {
		return LocalUser{}, err
	}
	return user, nil
}

func (s *ControlStore) BootstrapLocalAdmin(ctx context.Context, passwordHash string) error {
	user := LocalUser{Username: "admin", Subject: "admin", Kind: humanIdentityKind, Name: "Local Administrator", PasswordHash: passwordHash, PasswordChangeRequired: true, Enabled: true, Roles: []string{adminRole}}
	if err := validateLocalUser(user, true); err != nil {
		return err
	}
	teams, _ := json.Marshal([]string{})
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_users`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrLocalUsersExist
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO local_users(username, subject, identity_kind, password_hash, name, email, organization, teams_json, enabled, password_change_required, revision, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`), user.Username, user.Subject, user.Kind, user.PasswordHash, user.Name, "", "", string(teams), 1, 1, 1, now, now); err != nil {
		return fmt.Errorf("create local administrator: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO role_assignments(subject, role, created_at) VALUES(?, ?, ?)`), localUserCanonicalSubject(user.Subject), adminRole, now); err != nil {
		return fmt.Errorf("assign local administrator role: %w", err)
	}
	return tx.Commit()
}

func (s *ControlStore) CreateLocalUser(ctx context.Context, user LocalUser) error {
	if user.Kind == "" {
		user.Kind = humanIdentityKind
	}
	user.PasswordChangeRequired = user.Kind == humanIdentityKind
	if err := validateLocalUser(user, true); err != nil {
		return err
	}
	roles := assignedRoles(user.Roles)
	teams, err := json.Marshal(cleanStrings(user.Teams))
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO local_users(username, subject, identity_kind, password_hash, name, email, organization, teams_json, enabled, password_change_required, revision, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`), user.Username, strings.TrimSpace(user.Subject), user.Kind, user.PasswordHash, user.Name, user.Email, user.Organization, string(teams), boolInt(user.Enabled), boolInt(user.PasswordChangeRequired), 1, now, now); err != nil {
		return fmt.Errorf("create local user: %w", err)
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO role_assignments(subject, role, created_at) VALUES(?, ?, ?)`), localUserCanonicalSubject(user.Subject), role, now); err != nil {
			return fmt.Errorf("assign local user role %q: %w", role, err)
		}
	}
	return tx.Commit()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *ControlStore) UpdateLocalUser(ctx context.Context, currentUsername string, user LocalUser) error {
	existing, err := s.LocalUserByUsername(ctx, currentUsername)
	if err != nil {
		return err
	}
	if strings.TrimSpace(user.Subject) != existing.Subject {
		return errors.New("local user subject is immutable")
	}
	if user.Kind == "" {
		user.Kind = existing.Kind
	}
	if user.Kind != existing.Kind {
		return errors.New("local user kind is immutable")
	}
	if err := validateLocalUser(user, false); err != nil {
		return err
	}
	if user.PasswordHash == "" {
		user.PasswordHash = existing.PasswordHash
	}
	passwordChangeRequired := existing.PasswordChangeRequired || user.PasswordChangeRequired || user.PasswordChanged
	if user.Kind == serviceIdentityKind {
		passwordChangeRequired = false
	}
	roles := assignedRoles(user.Roles)
	canonical := localUserCanonicalSubject(user.Subject)
	if (!user.Enabled || !containsString(roles, adminRole)) && containsString(existing.Roles, adminRole) {
		last, err := s.isLastAssignedAdmin(ctx, canonical)
		if err != nil {
			return err
		}
		if last {
			return errors.New("cannot disable or demote the last assigned administrator")
		}
	}
	teams, _ := json.Marshal(cleanStrings(user.Teams))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE local_users SET username=?, password_hash=?, name=?, email=?, organization=?, teams_json=?, enabled=?, password_change_required=?, revision=revision+1, updated_at=? WHERE username=? AND subject=?`), user.Username, user.PasswordHash, user.Name, user.Email, user.Organization, string(teams), boolInt(user.Enabled), boolInt(passwordChangeRequired), now, strings.TrimSpace(currentUsername), existing.Subject)
	if err != nil {
		return fmt.Errorf("update local user: %w", err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrLocalUserNotFound
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM role_assignments WHERE subject=?`), canonical); err != nil {
		return err
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO role_assignments(subject, role, created_at) VALUES(?, ?, ?)`), canonical, role, now); err != nil {
			return fmt.Errorf("assign local user role %q: %w", role, err)
		}
	}
	// Any identity mutation increments the revision and immediately revokes all
	// credentials and unfinished login flows issued for the prior identity state.
	if err := s.invalidateLocalArtifactsTx(ctx, tx, existing.Subject, now, false); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *ControlStore) DeleteLocalUser(ctx context.Context, username string) error {
	user, err := s.LocalUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	canonical := localUserCanonicalSubject(user.Subject)
	last, err := s.isLastAssignedAdmin(ctx, canonical)
	if err != nil {
		return err
	}
	if last {
		return errors.New("cannot delete the last assigned administrator")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM role_assignments WHERE subject=?`), canonical); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM oauth_device_codes WHERE subject=?`), user.Subject); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM local_users WHERE username=?`), strings.TrimSpace(username))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrLocalUserNotFound
	}
	return tx.Commit()
}

func (s *ControlStore) ResourceGrants(ctx context.Context) (PolicyDocument, error) {
	// The normalized document spans several queries. A monotonic revision check prevents a
	// caller from observing parent rows from one committed grant set and child rows from another
	// on databases whose default read isolation is statement-scoped.
	for attempt := 0; attempt < 3; attempt++ {
		document, err := s.resourceGrantsOnce(ctx)
		if err != nil {
			return PolicyDocument{}, err
		}
		var current uint64
		if err := s.db.QueryRowContext(ctx, s.bind(`SELECT revision FROM resource_acl_state WHERE id=?`), 1).Scan(&current); err != nil {
			return PolicyDocument{}, err
		}
		if current == document.Revision {
			return document, nil
		}
	}
	return PolicyDocument{}, errors.New("resource grants changed concurrently; retry the request")
}

func (s *ControlStore) resourceGrantsOnce(ctx context.Context) (PolicyDocument, error) {
	var document PolicyDocument
	var updated string
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT revision, updated_at FROM resource_acl_state WHERE id=?`), 1).Scan(&document.Revision, &updated); err != nil {
		return PolicyDocument{}, err
	}
	document.Version = 1
	document.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, access_kind, principal, s3_route FROM resource_grants ORDER BY id`)
	if err != nil {
		return PolicyDocument{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var rule ACLRuleConfig
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Access, &rule.Principal, &rule.S3Route); err != nil {
			return PolicyDocument{}, err
		}
		document.Rules = append(document.Rules, rule)
	}
	if err := rows.Err(); err != nil {
		return PolicyDocument{}, err
	}
	for i := range document.Rules {
		rule := &document.Rules[i]
		if rule.Capabilities, err = s.grantValues(ctx, "grant_capabilities", rule.ID); err != nil {
			return PolicyDocument{}, err
		}
		if rule.Projects, err = s.grantValues(ctx, "grant_projects", rule.ID); err != nil {
			return PolicyDocument{}, err
		}
		if rule.S3Operations, err = s.grantValues(ctx, "grant_s3_operations", rule.ID); err != nil {
			return PolicyDocument{}, err
		}
		if rule.S3Prefixes, err = s.grantValues(ctx, "grant_s3_prefixes", rule.ID); err != nil {
			return PolicyDocument{}, err
		}
	}
	return document, nil
}

func (s *ControlStore) grantValues(ctx context.Context, table, grantID string) ([]string, error) {
	allowed := map[string]bool{"grant_capabilities": true, "grant_projects": true, "grant_s3_operations": true, "grant_s3_prefixes": true}
	if !allowed[table] {
		return nil, errors.New("unsupported grant value table")
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT value FROM `+table+` WHERE grant_id=? ORDER BY value`), grantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *ControlStore) ReplaceResourceGrants(ctx context.Context, expected uint64, rules []ACLRuleConfig, storage S3ServiceConfig) (PolicyDocument, error) {
	seen := map[string]bool{}
	for i := range rules {
		normalizeGrant(&rules[i])
		if err := validateACLRule(rules[i]); err != nil {
			return PolicyDocument{}, fmt.Errorf("grant %d: %w", i, err)
		}
		if seen[rules[i].ID] {
			return PolicyDocument{}, fmt.Errorf("duplicate grant id %q", rules[i].ID)
		}
		seen[rules[i].ID] = true
		if err := validateGrantRoute(rules[i], storage); err != nil {
			return PolicyDocument{}, fmt.Errorf("grant %q: %w", rules[i].ID, err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PolicyDocument{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE resource_acl_state SET revision=revision+1, updated_at=? WHERE id=? AND revision=?`), now, 1, expected)
	if err != nil {
		return PolicyDocument{}, err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return PolicyDocument{}, ErrRevisionConflict
	}
	// SQLite connections may not enforce cascading foreign keys. Remove child
	// values explicitly before replacing grants so reused IDs remain insertable.
	for _, table := range []string{"grant_capabilities", "grant_projects", "grant_s3_operations", "grant_s3_prefixes"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			return PolicyDocument{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resource_grants`); err != nil {
		return PolicyDocument{}, err
	}
	for _, rule := range rules {
		if err := s.insertGrant(ctx, tx, rule, now); err != nil {
			return PolicyDocument{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return PolicyDocument{}, err
	}
	return s.ResourceGrants(ctx)
}

func (s *ControlStore) CreateResourceGrant(ctx context.Context, expected uint64, rule ACLRuleConfig, storage S3ServiceConfig) (PolicyDocument, error) {
	document, err := s.ResourceGrants(ctx)
	if err != nil {
		return PolicyDocument{}, err
	}
	if document.Revision != expected {
		return PolicyDocument{}, ErrRevisionConflict
	}
	for _, existing := range document.Rules {
		if existing.ID == strings.TrimSpace(rule.ID) {
			return PolicyDocument{}, errors.New("grant already exists")
		}
	}
	document.Rules = append(document.Rules, rule)
	return s.ReplaceResourceGrants(ctx, expected, document.Rules, storage)
}

func (s *ControlStore) UpdateResourceGrant(ctx context.Context, expected uint64, id string, rule ACLRuleConfig, storage S3ServiceConfig) (PolicyDocument, error) {
	document, err := s.ResourceGrants(ctx)
	if err != nil {
		return PolicyDocument{}, err
	}
	if document.Revision != expected {
		return PolicyDocument{}, ErrRevisionConflict
	}
	found := false
	for i := range document.Rules {
		if document.Rules[i].ID == id {
			rule.ID = id
			document.Rules[i] = rule
			found = true
		}
	}
	if !found {
		return PolicyDocument{}, errors.New("grant does not exist")
	}
	return s.ReplaceResourceGrants(ctx, expected, document.Rules, storage)
}

func (s *ControlStore) DeleteResourceGrant(ctx context.Context, expected uint64, id string, storage S3ServiceConfig) (PolicyDocument, error) {
	document, err := s.ResourceGrants(ctx)
	if err != nil {
		return PolicyDocument{}, err
	}
	if document.Revision != expected {
		return PolicyDocument{}, ErrRevisionConflict
	}
	filtered := document.Rules[:0]
	for _, rule := range document.Rules {
		if rule.ID != id {
			filtered = append(filtered, rule)
		}
	}
	if len(filtered) == len(document.Rules) {
		return PolicyDocument{}, errors.New("grant does not exist")
	}
	return s.ReplaceResourceGrants(ctx, expected, filtered, storage)
}

func normalizeGrant(rule *ACLRuleConfig) {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Access = strings.ToLower(strings.TrimSpace(rule.Access))
	rule.Principal = strings.TrimSpace(rule.Principal)
	rule.S3Route = strings.TrimSpace(rule.S3Route)
	rule.Capabilities = cleanStrings(rule.Capabilities)
	rule.Projects = cleanStrings(rule.Projects)
	rule.S3Operations = cleanStrings(rule.S3Operations)
	rule.S3Prefixes = cleanStrings(rule.S3Prefixes)
}

func validateGrantRoute(rule ACLRuleConfig, storage S3ServiceConfig) error {
	if !ruleUsesS3(rule) {
		return nil
	}
	route := rule.S3Route
	if route == "" {
		route = storage.DefaultRoute
	}
	if _, ok := storage.Routes[route]; !ok {
		return fmt.Errorf("storage route %q is not configured", route)
	}
	return nil
}

func (s *ControlStore) insertGrant(ctx context.Context, tx *sql.Tx, rule ACLRuleConfig, now string) error {
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO resource_grants(id, name, access_kind, principal, s3_route, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)`), rule.ID, rule.Name, rule.Access, rule.Principal, rule.S3Route, now, now); err != nil {
		return err
	}
	sets := []struct {
		table  string
		values []string
	}{{"grant_capabilities", rule.Capabilities}, {"grant_projects", rule.Projects}, {"grant_s3_operations", rule.S3Operations}, {"grant_s3_prefixes", rule.S3Prefixes}}
	for _, set := range sets {
		for _, value := range set.values {
			if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO `+set.table+`(grant_id, value) VALUES(?, ?)`), rule.ID, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ControlStore) ResolveHubAccess(ctx context.Context, principal Principal) (PolicyDocument, error) {
	document, err := s.ResourceGrants(ctx)
	if err != nil {
		return PolicyDocument{}, err
	}
	filtered := document.Rules[:0]
	for _, rule := range document.Rules {
		if matchesPrincipal(rule, principal) && matchesValue(rule.Capabilities, "hub") {
			filtered = append(filtered, rule)
		}
	}
	document.Rules = filtered
	return document, nil
}

func (s *ControlStore) tokenHash(domain, raw string) string {
	mac := hmac.New(sha256.New, s.tokenPepper)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *ControlStore) SaveFlow(ctx context.Context, rawState, rawBrowserBinding string, flow OIDCFlow) error {
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO oidc_flows(state_hash, browser_binding_hash, nonce, pkce_verifier, purpose, continuation_json, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`), s.tokenHash(oidcFlowTokenDomain, rawState), s.tokenHash(oidcFlowBindingDomain, rawBrowserBinding), flow.Nonce, flow.PKCEVerifier, flow.Purpose, flow.Continuation, flow.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *ControlStore) ConsumeFlow(ctx context.Context, rawState, rawBrowserBinding string) (OIDCFlow, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OIDCFlow{}, err
	}
	defer tx.Rollback()
	var flow OIDCFlow
	var expires string
	key := s.tokenHash(oidcFlowTokenDomain, rawState)
	binding := s.tokenHash(oidcFlowBindingDomain, rawBrowserBinding)
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT nonce, pkce_verifier, purpose, continuation_json, expires_at FROM oidc_flows WHERE state_hash=? AND browser_binding_hash=?`), key, binding).Scan(&flow.Nonce, &flow.PKCEVerifier, &flow.Purpose, &flow.Continuation, &expires); err != nil {
		return OIDCFlow{}, err
	}
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM oidc_flows WHERE state_hash=? AND browser_binding_hash=?`), key, binding)
	if err != nil {
		return OIDCFlow{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return OIDCFlow{}, errors.New("OIDC login state was already consumed")
	}
	if err := tx.Commit(); err != nil {
		return OIDCFlow{}, err
	}
	flow.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil || !flow.ExpiresAt.After(time.Now()) {
		return OIDCFlow{}, errors.New("OIDC login state expired")
	}
	return flow, nil
}

func (s *ControlStore) CreateSession(ctx context.Context, rawToken string, session AdminSession) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hash := s.tokenHash(adminSessionTokenDomain, rawToken)
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO admin_sessions(token_hash, subject, name, email, csrf_token, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`), hash, session.Subject, session.Name, session.Email, session.CSRFToken, session.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	teams, err := json.Marshal(cleanStrings(session.Teams))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO admin_session_principals(token_hash, issuer, username, organization, teams_json, local_user_revision) VALUES(?, ?, ?, ?, ?, ?)`), hash, session.Issuer, session.Username, session.Organization, string(teams), session.LocalUserRevision); err != nil {
		return err
	}
	if session.RolesFromClaim {
		if strings.TrimSpace(session.RoleClaimSelector) == "" {
			return errors.New("administration session role claim selector is required")
		}
		claimedRoles := cleanStrings(session.Roles)
		roles, err := json.Marshal(claimedRoles)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO admin_session_claim_roles(token_hash, claim_selector, roles_json) VALUES(?, ?, ?)`), hash, strings.TrimSpace(session.RoleClaimSelector), string(roles)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ControlStore) Session(ctx context.Context, rawToken string) (AdminSession, error) {
	var session AdminSession
	var expires string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT subject, name, email, csrf_token, expires_at FROM admin_sessions WHERE token_hash=?`), s.tokenHash(adminSessionTokenDomain, rawToken)).Scan(&session.Subject, &session.Name, &session.Email, &session.CSRFToken, &expires)
	if err != nil {
		return AdminSession{}, err
	}
	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil || !session.ExpiresAt.After(time.Now()) {
		_ = s.DeleteSession(ctx, rawToken)
		return AdminSession{}, errors.New("administration session expired")
	}
	var teams string
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT issuer, username, organization, teams_json, local_user_revision FROM admin_session_principals WHERE token_hash=?`), s.tokenHash(adminSessionTokenDomain, rawToken)).Scan(&session.Issuer, &session.Username, &session.Organization, &teams, &session.LocalUserRevision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AdminSession{}, err
	}
	if err == nil && json.Unmarshal([]byte(teams), &session.Teams) != nil {
		return AdminSession{}, errors.New("administration session identity is invalid")
	}
	var roles string
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT claim_selector, roles_json FROM admin_session_claim_roles WHERE token_hash=?`), s.tokenHash(adminSessionTokenDomain, rawToken)).Scan(&session.RoleClaimSelector, &roles)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AdminSession{}, err
	}
	if err == nil {
		if json.Unmarshal([]byte(roles), &session.Roles) != nil || len(cleanStrings(session.Roles)) == 0 {
			return AdminSession{}, errors.New("administration session claimed roles are invalid")
		}
		session.Roles = cleanStrings(session.Roles)
		session.RolesFromClaim = true
	}
	return session, nil
}

func (s *ControlStore) DeleteSession(ctx context.Context, rawToken string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM admin_sessions WHERE token_hash=?`), s.tokenHash(adminSessionTokenDomain, rawToken))
	return err
}

func (s *ControlStore) Cleanup(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM oidc_flows WHERE expires_at <= ?`), now); err != nil {
		return err
	}
	for _, statement := range []string{
		`DELETE FROM admin_sessions WHERE expires_at <= ?`,
		`DELETE FROM local_auth_challenges WHERE expires_at <= ?`,
		`DELETE FROM oidc_auth_requests WHERE expires_at <= ?`,
		`DELETE FROM oauth_device_codes WHERE expires_at <= ?`,
		`DELETE FROM local_tokens WHERE expires_at <= ?`,
	} {
		if _, err := s.db.ExecContext(ctx, s.bind(statement), now); err != nil {
			return err
		}
	}
	return nil
}
