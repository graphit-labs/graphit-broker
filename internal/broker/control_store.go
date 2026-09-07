package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

var ErrRevisionConflict = errors.New("configuration revision conflict")

const adminRole = "admin"

var adminActions = []string{
	"session.read",
	"configuration.read",
	"configuration.write",
	"access.read",
	"access.write",
	"roles.read",
	"roles.write",
}

type ControlStore struct {
	db *sql.DB
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
	Subject   string
	Name      string
	Email     string
	CSRFToken string
	ExpiresAt time.Time
}

type OIDCFlow struct {
	StateHash    string
	Nonce        string
	PKCEVerifier string
	ExpiresAt    time.Time
}

func OpenControlStore(path string, seed Config) (*ControlStore, StoredConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, StoredConfig{}, errors.New("SQLite database path is required")
	}
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, StoredConfig{}, fmt.Errorf("create SQLite directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, StoredConfig{}, fmt.Errorf("secure SQLite directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, StoredConfig{}, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &ControlStore{db: db}
	if err := store.initialize(context.Background(), seed); err != nil {
		_ = db.Close()
		return nil, StoredConfig{}, err
	}
	if path != ":memory:" {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = db.Close()
			return nil, StoredConfig{}, fmt.Errorf("secure SQLite database: %w", err)
		}
	}
	stored, err := store.Config(context.Background())
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

func (s *ControlStore) initialize(ctx context.Context, seed Config) error {
	for _, statement := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure SQLite: %w", err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SQLite initialization: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS broker_config (
			id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL,
			config_yaml TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS roles (
			name TEXT PRIMARY KEY, created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS role_permissions (
			role TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
			action TEXT NOT NULL, PRIMARY KEY(role, action))`,
		`CREATE TABLE IF NOT EXISTS role_assignments (
			subject TEXT NOT NULL, role TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
			created_at TEXT NOT NULL, PRIMARY KEY(subject, role))`,
		`CREATE TABLE IF NOT EXISTS admin_sessions (
			token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, name TEXT NOT NULL,
			email TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS oidc_flows (
			state_hash TEXT PRIMARY KEY, nonce TEXT NOT NULL, pkce_verifier TEXT NOT NULL,
			expires_at TEXT NOT NULL, created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS role_assignments_subject_idx ON role_assignments(subject)`,
		`CREATE INDEX IF NOT EXISTS admin_sessions_expires_idx ON admin_sessions(expires_at)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize SQLite schema: %w", err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO roles(name, created_at) VALUES(?, ?)`, adminRole, now); err != nil {
		return fmt.Errorf("seed admin role: %w", err)
	}
	for _, action := range adminActions {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO role_permissions(role, action) VALUES(?, ?)`, adminRole, action); err != nil {
			return fmt.Errorf("seed admin permissions: %w", err)
		}
	}
	encoded, err := yaml.Marshal(seed)
	if err != nil {
		return fmt.Errorf("encode initial broker configuration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO broker_config(id, revision, config_yaml, updated_at) VALUES(1, 1, ?, ?)`, string(encoded), now); err != nil {
		return fmt.Errorf("seed broker configuration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SQLite initialization: %w", err)
	}
	return nil
}

func (s *ControlStore) Config(ctx context.Context) (StoredConfig, error) {
	var revision uint64
	var raw, updated string
	if err := s.db.QueryRowContext(ctx, `SELECT revision, config_yaml, updated_at FROM broker_config WHERE id=1`).Scan(&revision, &raw, &updated); err != nil {
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
	result, err := s.db.ExecContext(ctx, `UPDATE broker_config SET revision=revision+1, config_yaml=?, updated_at=? WHERE id=1 AND revision=?`, string(encoded), now.Format(time.RFC3339Nano), expected)
	if err != nil {
		return StoredConfig{}, fmt.Errorf("replace broker configuration: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return StoredConfig{}, fmt.Errorf("inspect broker configuration update: %w", err)
	}
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
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM role_assignments a
		JOIN role_permissions p ON p.role=a.role
		WHERE a.subject=? AND (p.action=? OR p.action='*') LIMIT 1`, subject, action).Scan(&one)
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
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_assignments`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count role assignments: %w", err)
	}
	return count, nil
}

func (s *ControlStore) SubjectRoles(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role FROM role_assignments WHERE subject = ? ORDER BY role`, strings.TrimSpace(subject))
	if err != nil {
		return nil, fmt.Errorf("list subject roles: %w", err)
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scan subject role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list subject roles: %w", err)
	}
	return roles, nil
}

func (s *ControlStore) SubjectPermissions(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT p.action FROM role_assignments a JOIN role_permissions p ON p.role=a.role WHERE a.subject=? ORDER BY p.action`, strings.TrimSpace(subject))
	if err != nil {
		return nil, fmt.Errorf("list subject permissions: %w", err)
	}
	defer rows.Close()
	var permissions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			return nil, fmt.Errorf("scan subject permission: %w", err)
		}
		permissions = append(permissions, action)
	}
	return permissions, rows.Err()
}

func (s *ControlStore) Roles(ctx context.Context) ([]AdminRole, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.name, COALESCE(p.action, '') FROM roles r LEFT JOIN role_permissions p ON p.role=r.name ORDER BY r.name, p.action`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
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
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO roles(name, created_at) VALUES(?, ?)`, role.Name, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role=?`, role.Name); err != nil {
		return err
	}
	for _, action := range role.Permissions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO role_permissions(role, action) VALUES(?, ?)`, role.Name, action); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ControlStore) DeleteRole(ctx context.Context, role string) error {
	role = strings.TrimSpace(role)
	if role == adminRole {
		return errors.New("the built-in admin role cannot be deleted")
	}
	if !safeSegment(role) {
		return errors.New("a safe role name is required")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE name=?`, role)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect role deletion: %w", err)
	}
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
		return nil, fmt.Errorf("list role assignments: %w", err)
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO role_assignments(subject, role, created_at) VALUES(?, ?, ?)
		ON CONFLICT(subject, role) DO NOTHING`, subject, role, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}

func (s *ControlStore) RevokeRole(ctx context.Context, subject, role string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM role_assignments WHERE subject=? AND role=?`, strings.TrimSpace(subject), strings.TrimSpace(role))
	if err != nil {
		return fmt.Errorf("revoke role: %w", err)
	}
	return nil
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *ControlStore) SaveFlow(ctx context.Context, rawState string, flow OIDCFlow) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_flows(state_hash, nonce, pkce_verifier, expires_at, created_at) VALUES(?, ?, ?, ?, ?)`,
		tokenHash(rawState), flow.Nonce, flow.PKCEVerifier, flow.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
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
	if err := tx.QueryRowContext(ctx, `SELECT nonce, pkce_verifier, expires_at FROM oidc_flows WHERE state_hash=?`, key).Scan(&flow.Nonce, &flow.PKCEVerifier, &expires); err != nil {
		return OIDCFlow{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_flows WHERE state_hash=?`, key); err != nil {
		return OIDCFlow{}, err
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_sessions(token_hash, subject, name, email, csrf_token, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		tokenHash(rawToken), session.Subject, session.Name, session.Email, session.CSRFToken,
		session.ExpiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *ControlStore) Session(ctx context.Context, rawToken string) (AdminSession, error) {
	var session AdminSession
	var expires string
	err := s.db.QueryRowContext(ctx, `SELECT subject, name, email, csrf_token, expires_at FROM admin_sessions WHERE token_hash=?`, tokenHash(rawToken)).Scan(
		&session.Subject, &session.Name, &session.Email, &session.CSRFToken, &expires)
	if err != nil {
		return AdminSession{}, err
	}
	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil || !session.ExpiresAt.After(time.Now()) {
		_ = s.DeleteSession(ctx, rawToken)
		return AdminSession{}, errors.New("administration session expired")
	}
	return session, nil
}

func (s *ControlStore) DeleteSession(ctx context.Context, rawToken string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash=?`, tokenHash(rawToken))
	return err
}

func (s *ControlStore) Cleanup(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oidc_flows WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at <= ?`, now)
	return err
}
