package broker

import (
	"errors"
	"testing"
)

func TestPolicyStoreReplacesAtomicallyAndRejectsStaleRevision(t *testing.T) {
	store, err := NewPolicyStore(AuthorizationConfig{Rules: []ACLRuleConfig{{Name: "public", Access: "global", Capabilities: []string{"embeddings"}}}}, "acl-test")
	if err != nil {
		t.Fatal(err)
	}
	initial := store.Snapshot()
	if initial.Revision != 1 || len(initial.Rules) != 1 {
		t.Fatalf("initial=%#v", initial)
	}
	updated, err := store.Replace(initial.Revision, []ACLRuleConfig{{Name: "signed-in", Access: "authenticated", Capabilities: []string{"rerank"}}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || store.Revision() != "acl-test.2" {
		t.Fatalf("updated=%#v revision=%q", updated, store.Revision())
	}
	if _, err := store.Replace(initial.Revision, nil); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("stale replace error=%v", err)
	}
}

func TestPolicyStoreRejectsInvalidManagedRule(t *testing.T) {
	store, err := NewPolicyStore(AuthorizationConfig{}, "acl")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Replace(1, []ACLRuleConfig{{Name: "bad", Access: "user", Capabilities: []string{"s3"}}})
	if err == nil {
		t.Fatal("user rule without principal was accepted")
	}
}

func TestPolicyStoreRejectsUnavailableRoutesAndAllowsAnonymousNamedRoutes(t *testing.T) {
	storage := S3ServiceConfig{Enabled: true, DefaultRoute: "primary", Routes: map[string]S3RouteConfig{
		"primary": {AccessKeyID: "primary", SecretAccessKey: "secret"},
		"public":  {AccessKeyID: "public", SecretAccessKey: "secret"},
	}}
	store, err := NewPolicyStore(AuthorizationConfig{}, "acl", storage)
	if err != nil {
		t.Fatal(err)
	}
	missing := ACLRuleConfig{Name: "missing", Access: "authenticated", Capabilities: []string{"s3"}, S3Route: "missing"}
	if _, err := store.Replace(1, []ACLRuleConfig{missing}); err == nil {
		t.Fatalf("accepted unavailable storage route %#v", missing)
	}
	public := ACLRuleConfig{Name: "public", Access: "anonymous", Capabilities: []string{"s3"}, S3Route: "public"}
	if _, err := store.Replace(1, []ACLRuleConfig{public}); err != nil {
		t.Fatalf("rejected anonymous named route: %v", err)
	}
}
