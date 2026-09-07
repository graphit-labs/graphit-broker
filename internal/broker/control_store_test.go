package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestControlStorePersistsConfigurationRolesAndAssignmentsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "broker.db")
	seed := testServerConfig("http://127.0.0.1:1", "http://127.0.0.1:1")
	store, initial, err := OpenControlStore(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	updated := initial.Config
	updated.Authentication.APIKeys = []APIKeyConfig{{Name: "automation", Token: "consumer-secret", Subject: "subject-api", Username: "automation"}}
	stored, err := store.ReplaceConfig(ctx, initial.Revision, updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, AdminRole{Name: "auditor", Permissions: []string{"configuration.read", "access.read"}}); err != nil {
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
	reopened, persisted, err := OpenControlStore(path, replacementSeed)
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
	if allowed, err := reopened.Authorize(ctx, "subject-auditor", "access.read", "root"); err != nil || !allowed {
		t.Fatalf("assigned authorization=%v err=%v", allowed, err)
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
	store, initial, err := OpenControlStore(":memory:", seed)
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
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_reader_write BEFORE INSERT ON role_permissions WHEN NEW.role='reader' AND NEW.action='access.write' BEGIN SELECT RAISE(ABORT, 'synthetic rejection'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole(ctx, AdminRole{Name: "reader", Permissions: []string{"access.write"}}); err == nil {
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
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
