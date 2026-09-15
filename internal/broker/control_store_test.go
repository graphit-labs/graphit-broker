package broker

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testTokenPepper = "0123456789abcdef0123456789abcdef"

func testDatabase(path string) DatabaseConfig {
	return DatabaseConfig{Driver: "sqlite", DSN: path, MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute}
}

func TestControlStorePersistsOnlyDurableStateAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "broker.db")
	store, err := OpenControlStore(testDatabase(path), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, Role{Name: "auditor", Permissions: []string{"configuration.read", "grants.read"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignRole(ctx, "subject-auditor", "auditor"); err != nil {
		t.Fatal(err)
	}
	var configTables int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='broker_`+`config'`).Scan(&configTables); err != nil {
		t.Fatal(err)
	}
	if configTables != 0 {
		t.Fatal("deployment configuration was persisted in a config table")
	}
	var schema string
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(group_concat(sql, ''), '') FROM sqlite_master WHERE type='table'`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(schema), "pepper") || !strings.Contains(schema, "password_hash") || !strings.Contains(schema, "local_users") {
		t.Fatalf("local-user schema did not persist password verifiers without a pepper: %s", schema)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenControlStore(testDatabase(path), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	roles, err := reopened.SubjectRoles(ctx, "subject-auditor")
	if err != nil || !reflect.DeepEqual(roles, []string{"auditor", userRole}) {
		t.Fatalf("roles=%v err=%v", roles, err)
	}
	if allowed, err := reopened.Authorize(ctx, "subject-auditor", "grants.read"); err != nil || !allowed {
		t.Fatalf("assigned authorization=%v err=%v", allowed, err)
	}
	if err := reopened.AssignRole(ctx, "subject-user", userRole); err != nil {
		t.Fatal(err)
	}
	if allowed, err := reopened.Authorize(ctx, "subject-user", "projects.read"); err != nil || !allowed {
		t.Fatalf("user project authorization=%v err=%v", allowed, err)
	}
	if allowed, err := reopened.Authorize(ctx, "subject-user", "configuration.read"); err != nil || allowed {
		t.Fatalf("user configuration authorization=%v err=%v", allowed, err)
	}
	if mode := fileMode(t, filepath.Dir(path)); mode != 0o700 {
		t.Fatalf("SQLite directory mode=%o", mode)
	}
	if mode := fileMode(t, path); mode != 0o600 {
		t.Fatalf("SQLite file mode=%o", mode)
	}
}

func TestControlStorePreservesExistingSQLiteParentPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	store, err := OpenControlStore(testDatabase(filepath.Join(dir, "broker.db")), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if mode := fileMode(t, dir); mode != 0o770 {
		t.Fatalf("existing SQLite directory mode=%o, want 770", mode)
	}
}

func TestControlStoreFailsClosedAndPreservesStateAfterRejectedUpdates(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if allowed, err := store.Authorize(ctx, "unassigned", "configuration.read"); err != nil || allowed {
		t.Fatalf("unassigned subject allowed=%v err=%v", allowed, err)
	}
	if err := store.SetRole(ctx, Role{Name: "reader", Permissions: []string{"configuration.read"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, Role{Name: "writer", Permissions: []string{"configuration.write"}}); err == nil {
		t.Fatal("removed configuration.write permission was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_reader_write BEFORE INSERT ON role_permissions WHEN NEW.role='reader' AND NEW.action='grants.write' BEGIN SELECT RAISE(ABORT, 'synthetic rejection'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, Role{Name: "reader", Permissions: []string{"grants.write"}}); err == nil {
		t.Fatal("transactional role update unexpectedly succeeded")
	}
	roles, err := store.Roles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, role := range roles {
		if role.Name == "reader" {
			found = reflect.DeepEqual(role.Permissions, []string{"configuration.read"})
		}
	}
	if !found {
		t.Fatalf("role transaction did not roll back after an insert failure: %#v", roles)
	}
	if err := store.AssignRole(ctx, "reader-subject", "reader"); err != nil {
		t.Fatal(err)
	}
	rawSession := "claimed-session"
	wantSession := AdminSession{Issuer: "https://identity.example", Subject: "reader-subject", Roles: []string{"reader"}, RolesFromClaim: true, RoleClaimSelector: "$.roles[*]", LocalUserRevision: 7, CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.CreateSession(ctx, rawSession, wantSession); err != nil {
		t.Fatal(err)
	}
	gotSession, err := store.Session(ctx, rawSession)
	if err != nil || !gotSession.RolesFromClaim || !reflect.DeepEqual(gotSession.Roles, wantSession.Roles) || gotSession.LocalUserRevision != wantSession.LocalUserRevision {
		t.Fatalf("claimed session=%#v err=%v", gotSession, err)
	}
	if err := store.DeleteRole(ctx, adminRole); err == nil {
		t.Fatal("built-in admin role was deleted")
	}
	flow := OIDCFlow{Nonce: "nonce", PKCEVerifier: "verifier", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.SaveFlow(ctx, "one-time-state", "browser-binding", flow); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeFlow(ctx, "one-time-state", "wrong-binding"); err == nil {
		t.Fatal("OIDC flow accepted the wrong browser binding")
	}
	if consumed, err := store.ConsumeFlow(ctx, "one-time-state", "browser-binding"); err != nil || consumed.Nonce != flow.Nonce {
		t.Fatalf("consumed flow=%#v err=%v", consumed, err)
	}
	if _, err := store.ConsumeFlow(ctx, "one-time-state", "browser-binding"); err == nil {
		t.Fatal("OIDC flow state was consumed twice")
	}
}

func TestControlStoreTokenHashesUsePepperAndDomainSeparation(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw := "same-random-token"
	if store.tokenHash(adminSessionTokenDomain, raw) == store.tokenHash(oidcFlowTokenDomain, raw) {
		t.Fatal("token hash domains are not separated")
	}
	if err := store.CreateSession(ctx, raw, AdminSession{Subject: "subject", CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var persisted string
	if err := store.db.QueryRowContext(ctx, `SELECT token_hash FROM admin_sessions`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted == raw || persisted != store.tokenHash(adminSessionTokenDomain, raw) {
		t.Fatalf("persisted token hash=%q", persisted)
	}
	browserBinding := "browser-binding"
	if err := store.SaveFlow(ctx, raw, browserBinding, OIDCFlow{Nonce: "nonce", PKCEVerifier: "verifier", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var persistedFlow, persistedBinding string
	if err := store.db.QueryRowContext(ctx, `SELECT state_hash, browser_binding_hash FROM oidc_flows`).Scan(&persistedFlow, &persistedBinding); err != nil {
		t.Fatal(err)
	}
	if persistedFlow == raw || persistedFlow != store.tokenHash(oidcFlowTokenDomain, raw) || persistedFlow == persisted {
		t.Fatalf("persisted flow hash=%q session hash=%q", persistedFlow, persisted)
	}
	if persistedBinding == browserBinding || persistedBinding != store.tokenHash(oidcFlowBindingDomain, browserBinding) {
		t.Fatalf("persisted browser binding hash=%q", persistedBinding)
	}
	other := &ControlStore{tokenPepper: []byte("abcdef0123456789abcdef0123456789")}
	if persisted == other.tokenHash(adminSessionTokenDomain, raw) {
		t.Fatal("token hash did not depend on the external pepper")
	}
}

func TestControlStoreRejectsPreviousSchemaWithoutMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_meta (id SMALLINT PRIMARY KEY, version BIGINT NOT NULL); INSERT INTO schema_meta(id, version) VALUES(1, 6)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if store, err := OpenControlStore(testDatabase(path), testTokenPepper); err == nil {
		_ = store.Close()
		t.Fatal("previous schema version was accepted")
	}
}

func TestControlStorePersistsAndManagesLocalUsersWithDefaultRole(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	user := LocalUser{Username: "alice", Subject: "identity-1", Name: "Alice", Email: "alice@example.test",
		Organization: "acme", Teams: []string{"platform"}, Roles: []string{"admin"}, Enabled: true,
		PasswordHash: mustPasswordHash(t, "initial-password")}
	if err := store.CreateLocalUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LocalUserByUsername(ctx, "alice")
	if err != nil || loaded.PasswordHash == "" || loaded.Revision != 1 || !reflect.DeepEqual(loaded.Roles, []string{"admin", "user"}) {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	users, err := store.LocalUsers(ctx)
	if err != nil || len(users) != 1 || users[0].PasswordHash != "" {
		t.Fatalf("redacted users=%#v err=%v", users, err)
	}
	loaded.Username = "alice-renamed"
	loaded.Name = "Alice Updated"
	loaded.PasswordHash = mustPasswordHash(t, "updated-password")
	loaded.Roles = []string{"admin"}
	if err := store.UpdateLocalUser(ctx, "alice", loaded); err != nil {
		t.Fatal(err)
	}
	updated, err := store.LocalUserByUsername(ctx, "alice-renamed")
	if err != nil || updated.Subject != "identity-1" || updated.Revision != 2 || updated.Name != "Alice Updated" {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	if err := store.DeleteLocalUser(ctx, "alice-renamed"); err == nil {
		t.Fatal("last assigned administrator was deleted")
	}
	if err := store.CreateLocalUser(ctx, LocalUser{Username: "bob", Subject: "identity-2", PasswordHash: mustPasswordHash(t, "bob-local-password"), Roles: []string{"admin"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLocalUser(ctx, "alice-renamed"); err != nil {
		t.Fatal(err)
	}
}

func TestControlStorePersistsNormalizedResourceGrantsAndRejectsStaleWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "broker.db")
	seed := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	store, err := OpenControlStore(testDatabase(path), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	grant := ACLRuleConfig{ID: "team-platform", Name: "Platform projects", Access: "team", Principal: "platform", Capabilities: []string{"hub", "s3"}, Projects: []string{"project-a"}, S3Operations: []string{"read"}, S3Route: "primary"}
	document, err := store.CreateResourceGrant(ctx, 1, grant, seed.Services.S3)
	if err != nil || document.Revision != 2 {
		t.Fatalf("create document=%#v err=%v", document, err)
	}
	if _, err := store.CreateResourceGrant(ctx, 1, grant, seed.Services.S3); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale create error=%v", err)
	}
	second := ACLRuleConfig{ID: "team-secondary", Name: "Secondary project", Access: "team", Principal: "platform", Capabilities: []string{"hub", "s3"}, Projects: []string{"project-b"}, S3Operations: []string{"read"}, S3Route: "primary"}
	document, err = store.CreateResourceGrant(ctx, 2, second, seed.Services.S3)
	if err != nil || document.Revision != 3 || len(document.Rules) != 2 {
		t.Fatalf("second create document=%#v err=%v", document, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenControlStore(testDatabase(path), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.ResourceGrants(ctx)
	if err != nil || persisted.Revision != 3 || len(persisted.Rules) != 2 || !reflect.DeepEqual(persisted.Rules[0].Projects, []string{"project-a"}) {
		t.Fatalf("persisted=%#v err=%v", persisted, err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
