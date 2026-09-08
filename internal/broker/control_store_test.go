package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestControlStorePersistsConfigurationRolesAndAssignmentsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "broker.db")
	seed := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	store, initial, err := OpenControlStore(DatabaseConfig{Driver: "sqlite", DSN: path, MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute}, seed)
	if err != nil {
		t.Fatal(err)
	}
	updated := initial.Config
	updated.Authentication.APIKeys = []APIKeyConfig{{Name: "automation", Token: "consumer-secret", Subject: "subject-api", Username: "automation"}}
	stored, err := store.ReplaceConfig(ctx, initial.Revision, updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, AdminRole{Name: "auditor", Permissions: []string{"configuration.read", "grants.read"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignRole(ctx, "subject-auditor", "auditor"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	replacementSeed := seed
	replacementSeed.Authentication.APIKeys = nil
	reopened, persisted, err := OpenControlStore(DatabaseConfig{Driver: "sqlite", DSN: path, MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute}, replacementSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if persisted.Revision != stored.Revision || len(persisted.Config.Authentication.APIKeys) != 1 || persisted.Config.Authentication.APIKeys[0].Token != "consumer-secret" {
		t.Fatalf("persisted configuration=%#v", persisted)
	}
	roles, err := reopened.SubjectRoles(ctx, "subject-auditor")
	if err != nil || !reflect.DeepEqual(roles, []string{"auditor"}) {
		t.Fatalf("roles=%v err=%v", roles, err)
	}
	if allowed, err := reopened.Authorize(ctx, "subject-auditor", "grants.read", "root"); err != nil || !allowed {
		t.Fatalf("assigned authorization=%v err=%v", allowed, err)
	}
	if err := reopened.AssignRole(ctx, "subject-user", userRole); err != nil {
		t.Fatal(err)
	}
	if allowed, err := reopened.Authorize(ctx, "subject-user", "projects.read", "root"); err != nil || !allowed {
		t.Fatalf("user project authorization=%v err=%v", allowed, err)
	}
	if allowed, err := reopened.Authorize(ctx, "subject-user", "configuration.read", "root"); err != nil || allowed {
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
	seed := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	store, initial, err := OpenControlStore(DatabaseConfig{Driver: "sqlite", DSN: ":memory:", MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute}, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if allowed, err := store.Authorize(ctx, "unassigned", "configuration.read", "super"); err != nil || allowed {
		t.Fatalf("unassigned subject allowed=%v err=%v", allowed, err)
	}
	if allowed, err := store.Authorize(ctx, "super", "roles.write", "super"); err != nil || !allowed {
		t.Fatalf("superadmin allowed=%v err=%v", allowed, err)
	}
	if _, err := store.ReplaceConfig(ctx, initial.Revision+1, initial.Config); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale configuration error=%v", err)
	}
	afterConflict, _ := store.Config(ctx)
	if afterConflict.Revision != initial.Revision {
		t.Fatalf("revision changed after conflict: %d", afterConflict.Revision)
	}
	if err := store.SetRole(ctx, AdminRole{Name: "reader", Permissions: []string{"configuration.read"}}); err != nil {
		t.Fatal(err)
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
	if allowed, _ := store.Authorize(ctx, "reader-subject", "configuration.read", "super"); !allowed {
		t.Fatal("assigned permission denied")
	}
	if allowed, _ := store.Authorize(ctx, "reader-subject", "configuration.write", "super"); allowed {
		t.Fatal("unassigned permission allowed")
	}
	if err := store.RevokeRole(ctx, "reader-subject", "reader"); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := store.Authorize(ctx, "reader-subject", "configuration.read", "super"); allowed {
		t.Fatal("revoked permission remained active")
	}
	if err := store.DeleteRole(ctx, adminRole); err == nil {
		t.Fatal("built-in admin role was deleted")
	}
	if err := store.DeleteRole(ctx, "reader"); err != nil {
		t.Fatal(err)
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

func TestControlStorePersistsNormalizedResourceGrantsAndRejectsStaleWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "broker.db")
	seed := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	store, _, err := OpenControlStore(DatabaseConfig{Driver: "sqlite", DSN: path, MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute}, seed)
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
	resolved, err := store.ResolveHubAccess(ctx, Principal{Issuer: "issuer", Subject: "subject", Teams: []string{"platform"}, AuthMethod: "oidc"})
	if err != nil || len(resolved.Rules) != 1 || resolved.Rules[0].ID != grant.ID {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, _, err := OpenControlStore(DatabaseConfig{Driver: "sqlite", DSN: path, MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute}, seed)
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
