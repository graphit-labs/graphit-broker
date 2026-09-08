package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var ErrRevisionConflict = errors.New("revision conflict")

const (
	adminRole = "admin"
	userRole  = "user"
)

var adminActions = []string{
	"session.read", "configuration.read", "configuration.write",
	"grants.read", "grants.write", "roles.read", "roles.write", "projects.read",
}

var userActions = []string{"session.read", "projects.read"}

// ControlStore owns all durable broker state. Domain persistence is portable across the SQL
// backends supported by DatabaseDialect.
type ControlStore struct {
	db      *sql.DB
	dialect DatabaseDialect
}

type StoredConfig struct {
	Revision  uint64    `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
	Config    Config    `json:"config"`
}

type AdminRole struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
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
	CSRFToken         string
	ExpiresAt         time.Time
}

type OIDCFlow struct {
	StateHash    string
	Nonce        string
	PKCEVerifier string
	ExpiresAt    time.Time
}

func OpenControlStore(cfg DatabaseConfig, seed Config) (*ControlStore, StoredConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, dialect, err := openDatabase(ctx, cfg)
	if err != nil {
		return nil, StoredConfig{}, err
	}
	store := &ControlStore{db: db, dialect: dialect}
	if err := store.initialize(ctx, seed); err != nil {
		_ = db.Close()
		return nil, StoredConfig{}, err
	}
	if dialect.Name() == "sqlite" {
		if err := secureSQLiteFile(cfg.DSN); err != nil {
			_ = db.Close()
			return nil, StoredConfig{}, err
		}
	}
	stored, err := store.Config(ctx)
	if err != nil {
		_ = db.Close()
		return nil, StoredConfig{}, err
	}
	return store, stored, nil
}

func (s *ControlStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *ControlStore) bind(query string) string { return s.dialect.Bind(query) }

func (s *ControlStore) initialize(ctx context.Context, seed Config) error {
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
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS schema_meta (id SMALLINT PRIMARY KEY, version BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS broker_config (id SMALLINT PRIMARY KEY, revision BIGINT NOT NULL, config_yaml TEXT NOT NULL, updated_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS roles (name VARCHAR(128) PRIMARY KEY, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS role_permissions (role VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL, PRIMARY KEY(role, action), FOREIGN KEY(role) REFERENCES roles(name) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS role_assignments (subject VARCHAR(512) NOT NULL, role VARCHAR(128) NOT NULL, created_at VARCHAR(40) NOT NULL, PRIMARY KEY(subject, role), FOREIGN KEY(role) REFERENCES roles(name) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS admin_sessions (token_hash VARCHAR(64) PRIMARY KEY, subject VARCHAR(512) NOT NULL, name VARCHAR(512) NOT NULL, email VARCHAR(512) NOT NULL, csrf_token VARCHAR(128) NOT NULL, expires_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS admin_session_principals (token_hash VARCHAR(64) PRIMARY KEY, issuer VARCHAR(1024) NOT NULL, username VARCHAR(512) NOT NULL, organization VARCHAR(512) NOT NULL, teams_json TEXT NOT NULL, FOREIGN KEY(token_hash) REFERENCES admin_sessions(token_hash) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS admin_session_claim_roles (token_hash VARCHAR(64) PRIMARY KEY, claim_selector VARCHAR(4096) NOT NULL, roles_json TEXT NOT NULL, FOREIGN KEY(token_hash) REFERENCES admin_sessions(token_hash) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS oidc_flows (state_hash VARCHAR(64) PRIMARY KEY, nonce VARCHAR(128) NOT NULL, pkce_verifier VARCHAR(256) NOT NULL, expires_at VARCHAR(40) NOT NULL, created_at VARCHAR(40) NOT NULL)`,
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO schema_meta(id, version) VALUES(?, ?)`)), 1, 1); err != nil {
		return fmt.Errorf("seed schema version: %w", err)
	}
	var schemaVersion int
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT version FROM schema_meta WHERE id=?`), 1).Scan(&schemaVersion); err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	if schemaVersion != 1 {
		return fmt.Errorf("unsupported database schema version %d: recreate the database", schemaVersion)
	}
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO roles(name, created_at) VALUES(?, ?)`)), adminRole, now); err != nil {
		return fmt.Errorf("seed admin role: %w", err)
	}
	for _, action := range adminActions {
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
	encoded, err := yaml.Marshal(seed)
	if err != nil {
		return fmt.Errorf("encode initial broker configuration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO broker_config(id, revision, config_yaml, updated_at) VALUES(?, ?, ?, ?)`)), 1, 1, string(encoded), now); err != nil {
		return fmt.Errorf("seed broker configuration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(s.dialect.InsertIgnore(`INSERT INTO resource_acl_state(id, revision, updated_at) VALUES(?, ?, ?)`)), 1, 1, now); err != nil {
		return fmt.Errorf("seed resource ACL revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database initialization: %w", err)
	}
	return nil
}

func (s *ControlStore) Config(ctx context.Context) (StoredConfig, error) {
	var revision uint64
	var raw, updated string
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT revision, config_yaml, updated_at FROM broker_config WHERE id=?`), 1).Scan(&revision, &raw, &updated); err != nil {
		return StoredConfig{}, fmt.Errorf("read broker configuration: %w", err)
	}
	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return StoredConfig{}, fmt.Errorf("decode broker configuration: %w", err)
	}
	cfg.defaults()
	when, err := time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return StoredConfig{}, fmt.Errorf("decode broker configuration timestamp: %w", err)
	}
	return StoredConfig{Revision: revision, UpdatedAt: when, Config: cfg}, nil
}

func (s *ControlStore) ReplaceConfig(ctx context.Context, expected uint64, cfg Config) (StoredConfig, error) {
	if err := cfg.Validate(); err != nil {
		return StoredConfig{}, err
	}
	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		return StoredConfig{}, fmt.Errorf("encode broker configuration: %w", err)
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, s.bind(`UPDATE broker_config SET revision=revision+1, config_yaml=?, updated_at=? WHERE id=? AND revision=?`), string(encoded), now.Format(time.RFC3339Nano), 1, expected)
	if err != nil {
		return StoredConfig{}, fmt.Errorf("replace broker configuration: %w", err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return StoredConfig{}, ErrRevisionConflict
	}
	return s.Config(ctx)
}

func (s *ControlStore) Authorize(ctx context.Context, subject, action, superadmin string) (bool, error) {
	if strings.TrimSpace(subject) != "" && subject == strings.TrimSpace(superadmin) {
		return true, nil
	}
	var one int
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role=a.role WHERE a.subject=? AND (p.action=? OR p.action='*')`), subject, action).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("authorize administrator: %w", err)
	}
	return true, nil
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

func (s *ControlStore) SubjectPermissions(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT DISTINCT p.action FROM role_assignments a JOIN role_permissions p ON p.role=a.role WHERE a.subject=? ORDER BY p.action`), strings.TrimSpace(subject))
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
	roles = cleanStrings(roles)
	if len(roles) == 0 {
		return nil, nil
	}
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
		return false, fmt.Errorf("authorize claimed administration roles: %w", err)
	}
	return containsString(permissions, action) || containsString(permissions, "*"), nil
}

func (s *ControlStore) Roles(ctx context.Context) ([]AdminRole, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.name, COALESCE(p.action, '') FROM roles r LEFT JOIN role_permissions p ON p.role=r.name ORDER BY r.name, p.action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byName := map[string]*AdminRole{}
	var order []string
	for rows.Next() {
		var name, action string
		if err := rows.Scan(&name, &action); err != nil {
			return nil, err
		}
		role := byName[name]
		if role == nil {
			role = &AdminRole{Name: name}
			byName[name] = role
			order = append(order, name)
		}
		if action != "" {
			role.Permissions = append(role.Permissions, action)
		}
	}
	result := make([]AdminRole, 0, len(order))
	for _, name := range order {
		result = append(result, *byName[name])
	}
	return result, rows.Err()
}

func (s *ControlStore) SetRole(ctx context.Context, role AdminRole) error {
	role.Name = strings.TrimSpace(role.Name)
	role.Permissions = cleanStrings(role.Permissions)
	if role.Name == adminRole {
		role.Permissions = append([]string(nil), adminActions...)
	} else if role.Name == userRole {
		role.Permissions = append([]string(nil), userActions...)
	}
	if !safeSegment(role.Name) || len(role.Permissions) == 0 {
		return errors.New("role needs a safe name and at least one permission")
	}
	for _, action := range role.Permissions {
		if !validAdminAction(action) {
			return fmt.Errorf("unsupported administration action %q", action)
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

func validAdminAction(action string) bool {
	if action == "*" {
		return true
	}
	for _, allowed := range adminActions {
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
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM role_assignments WHERE subject=? AND role=?`), strings.TrimSpace(subject), strings.TrimSpace(role))
	return err
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

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *ControlStore) SaveFlow(ctx context.Context, rawState string, flow OIDCFlow) error {
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO oidc_flows(state_hash, nonce, pkce_verifier, expires_at, created_at) VALUES(?, ?, ?, ?, ?)`), tokenHash(rawState), flow.Nonce, flow.PKCEVerifier, flow.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *ControlStore) ConsumeFlow(ctx context.Context, rawState string) (OIDCFlow, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OIDCFlow{}, err
	}
	defer tx.Rollback()
	var flow OIDCFlow
	var expires string
	key := tokenHash(rawState)
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT nonce, pkce_verifier, expires_at FROM oidc_flows WHERE state_hash=?`), key).Scan(&flow.Nonce, &flow.PKCEVerifier, &expires); err != nil {
		return OIDCFlow{}, err
	}
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM oidc_flows WHERE state_hash=?`), key)
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
	hash := tokenHash(rawToken)
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO admin_sessions(token_hash, subject, name, email, csrf_token, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`), hash, session.Subject, session.Name, session.Email, session.CSRFToken, session.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	teams, err := json.Marshal(cleanStrings(session.Teams))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO admin_session_principals(token_hash, issuer, username, organization, teams_json) VALUES(?, ?, ?, ?, ?)`), hash, session.Issuer, session.Username, session.Organization, string(teams)); err != nil {
		return err
	}
	if session.RolesFromClaim {
		if strings.TrimSpace(session.RoleClaimSelector) == "" {
			return errors.New("administration session role claim selector is required")
		}
		claimedRoles := cleanStrings(session.Roles)
		if len(claimedRoles) == 0 {
			return errors.New("administration session claimed roles are required")
		}
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
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT subject, name, email, csrf_token, expires_at FROM admin_sessions WHERE token_hash=?`), tokenHash(rawToken)).Scan(&session.Subject, &session.Name, &session.Email, &session.CSRFToken, &expires)
	if err != nil {
		return AdminSession{}, err
	}
	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil || !session.ExpiresAt.After(time.Now()) {
		_ = s.DeleteSession(ctx, rawToken)
		return AdminSession{}, errors.New("administration session expired")
	}
	var teams string
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT issuer, username, organization, teams_json FROM admin_session_principals WHERE token_hash=?`), tokenHash(rawToken)).Scan(&session.Issuer, &session.Username, &session.Organization, &teams)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AdminSession{}, err
	}
	if err == nil && json.Unmarshal([]byte(teams), &session.Teams) != nil {
		return AdminSession{}, errors.New("administration session identity is invalid")
	}
	var roles string
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT claim_selector, roles_json FROM admin_session_claim_roles WHERE token_hash=?`), tokenHash(rawToken)).Scan(&session.RoleClaimSelector, &roles)
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
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM admin_sessions WHERE token_hash=?`), tokenHash(rawToken))
	return err
}

func (s *ControlStore) Cleanup(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM oidc_flows WHERE expires_at <= ?`), now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM admin_sessions WHERE expires_at <= ?`), now)
	return err
}
