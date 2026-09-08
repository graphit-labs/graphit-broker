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
	if err := store.SetRole(ctx, AdminRole{Name: "auditor", Permissions: []string{"configuration.read", "grants.read"}}); err != nil {
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
	if strings.Contains(strings.ToLower(schema), "pepper") || strings.Contains(schema, "password_hash") {
		t.Fatalf("password verifier or pepper appeared in durable schema: %s", schema)
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
	if err != nil || !reflect.DeepEqual(roles, []string{"auditor"}) {
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
	if err := store.SetRole(ctx, AdminRole{Name: "reader", Permissions: []string{"configuration.read"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, AdminRole{Name: "writer", Permissions: []string{"configuration.write"}}); err == nil {
		t.Fatal("removed configuration.write permission was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_reader_write BEFORE INSERT ON role_permissions WHEN NEW.role='reader' AND NEW.action='grants.write' BEGIN SELECT RAISE(ABORT, 'synthetic rejection'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, AdminRole{Name: "reader", Permissions: []string{"grants.write"}}); err == nil {
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
	wantSession := AdminSession{Issuer: "https://identity.example", Subject: "reader-subject", Roles: []string{"reader"}, RolesFromClaim: true, RoleClaimSelector: "$.roles[*]", CredentialFingerprint: "fingerprint", CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.CreateSession(ctx, rawSession, wantSession); err != nil {
		t.Fatal(err)
	}
	gotSession, err := store.Session(ctx, rawSession)
	if err != nil || !gotSession.RolesFromClaim || !reflect.DeepEqual(gotSession.Roles, wantSession.Roles) || gotSession.CredentialFingerprint != wantSession.CredentialFingerprint {
		t.Fatalf("claimed session=%#v err=%v", gotSession, err)
	}
	if err := store.DeleteRole(ctx, adminRole); err == nil {
		t.Fatal("built-in admin role was deleted")
	}
	flow := OIDCFlow{Nonce: "nonce", PKCEVerifier: "verifier", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.SaveFlow(ctx, "one-time-state", flow); err != nil {
		t.Fatal(err)
	}
	if consumed, err := store.ConsumeFlow(ctx, "one-time-state"); err != nil || consumed.Nonce != flow.Nonce {
		t.Fatalf("consumed flow=%#v err=%v", consumed, err)
	}
	if _, err := store.ConsumeFlow(ctx, "one-time-state"); err == nil {
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
	if err := store.SaveFlow(ctx, raw, OIDCFlow{Nonce: "nonce", PKCEVerifier: "verifier", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var persistedFlow string
	if err := store.db.QueryRowContext(ctx, `SELECT state_hash FROM oidc_flows`).Scan(&persistedFlow); err != nil {
		t.Fatal(err)
	}
	if persistedFlow == raw || persistedFlow != store.tokenHash(oidcFlowTokenDomain, raw) || persistedFlow == persisted {
		t.Fatalf("persisted flow hash=%q session hash=%q", persistedFlow, persisted)
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
	if _, err := db.Exec(`CREATE TABLE schema_meta (id SMALLINT PRIMARY KEY, version BIGINT NOT NULL); INSERT INTO schema_meta(id, version) VALUES(1, 2)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if store, err := OpenControlStore(testDatabase(path), testTokenPepper); err == nil {
		_ = store.Close()
		t.Fatal("previous schema version was accepted")
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
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenControlStore(testDatabase(path), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.ResourceGrants(ctx)
	if err != nil || persisted.Revision != 2 || !reflect.DeepEqual(persisted.Rules[0].Projects, []string{"project-a"}) {
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
