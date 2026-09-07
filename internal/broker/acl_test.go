package broker

import (
	"errors"
	"reflect"
	"testing"
)

func TestACLIsDenyByDefaultAndRequiresAllConfiguredSelectors(t *testing.T) {
	acl := NewACL(AuthorizationConfig{Rules: []ACLRuleConfig{{
		Name: "platform", Organizations: []string{"acme"}, Teams: []string{"platform"}, Capabilities: []string{"embeddings"},
	}}}, "rev")
	allowed := Principal{Issuer: "https://id", Subject: "1", Username: "alice", Organization: "acme", Teams: []string{"platform"}}
	if err := acl.AuthorizeCapability(allowed, "embeddings"); err != nil {
		t.Fatalf("AuthorizeCapability: %v", err)
	}
	denied := allowed
	denied.Teams = []string{"other"}
	if err := acl.AuthorizeCapability(denied, "embeddings"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied error = %v", err)
	}
}

func TestACLBuildsTemplatedS3Grant(t *testing.T) {
	acl := NewACL(AuthorizationConfig{Rules: []ACLRuleConfig{{Name: "publish", Organizations: []string{"acme"}, Teams: []string{"platform"},
		Capabilities: []string{"s3"}, Projects: []string{"platform-*"}, S3Operations: []string{"publish"},
		S3Prefixes: []string{"v2/organizations/{organization}/projects/{project}"}, S3Route: "tenant-a",
	}}}, "rev")
	grant, err := acl.AuthorizeS3(Principal{Issuer: "i", Subject: "s", Username: "alice", Organization: "acme", Teams: []string{"platform"}}, "platform-api", "publish", "default")
	if err != nil {
		t.Fatalf("AuthorizeS3: %v", err)
	}
	want := []string{"v2/organizations/acme/projects/platform-api"}
	if !reflect.DeepEqual(grant.Prefixes, want) {
		t.Fatalf("prefixes = %#v, want %#v", grant.Prefixes, want)
	}
	if grant.Route != "tenant-a" {
		t.Fatalf("route = %q, want tenant-a", grant.Route)
	}
	if _, err := acl.AuthorizeS3(Principal{Username: "alice", Organization: "acme", Teams: []string{"platform"}}, "../escape", "publish", "graphit"); err == nil {
		t.Fatal("unsafe project accepted")
	}
}

func TestACLAccessLevelsMatchFrameworkSemantics(t *testing.T) {
	rules := []ACLRuleConfig{
		{Name: "global", Access: "global", Capabilities: []string{"global-capability"}},
		{Name: "anonymous", Access: "anonymous", Capabilities: []string{"anonymous-capability"}},
		{Name: "authenticated", Access: "authenticated", Capabilities: []string{"authenticated-capability"}},
		{Name: "user", Access: "user", Principal: "alice", Capabilities: []string{"user-capability"}},
		{Name: "team", Access: "team", Principal: "platform", Capabilities: []string{"team-capability"}},
		{Name: "organization", Access: "organization", Principal: "acme", Capabilities: []string{"organization-capability"}},
		{Name: "subject", Access: "subject", Principal: "https://id|subject-1", Capabilities: []string{"subject-capability"}},
	}
	acl := NewACL(AuthorizationConfig{Rules: rules}, "rev")
	anonymous := AnonymousPrincipal()
	authenticated := Principal{Issuer: "https://id", Subject: "subject-1", Username: "alice", Organization: "acme", Teams: []string{"platform"}, AuthMethod: "oidc"}
	for _, capability := range []string{"global-capability", "anonymous-capability"} {
		if err := acl.AuthorizeCapability(anonymous, capability); err != nil {
			t.Fatalf("anonymous %s: %v", capability, err)
		}
	}
	if err := acl.AuthorizeCapability(anonymous, "authenticated-capability"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("anonymous received authenticated grant: %v", err)
	}
	for _, capability := range []string{"global-capability", "authenticated-capability", "user-capability", "team-capability", "organization-capability", "subject-capability"} {
		if err := acl.AuthorizeCapability(authenticated, capability); err != nil {
			t.Fatalf("authenticated %s: %v", capability, err)
		}
	}
	if err := acl.AuthorizeCapability(authenticated, "anonymous-capability"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("authenticated principal received anonymous-only grant: %v", err)
	}
}

func TestACLMapsPresignVerbsToPermissionLevels(t *testing.T) {
	acl := NewACL(AuthorizationConfig{Rules: []ACLRuleConfig{{Name: "publisher", Access: "user", Principal: "alice", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"publish"}, S3Prefixes: []string{"v2/projects/{project}"}}}}, "rev")
	principal := Principal{Username: "alice", AuthMethod: "oidc"}
	for _, operation := range []string{"get", "head", "list", "put", "delete"} {
		grant, err := acl.AuthorizeS3Request(principal, "project-a", operation, "primary")
		if err != nil || len(grant.Prefixes) != 1 {
			t.Fatalf("operation %s grant=%#v err=%v", operation, grant, err)
		}
	}
}

func TestACLRejectsAmbiguousStorageRoutes(t *testing.T) {
	acl := NewACL(AuthorizationConfig{Rules: []ACLRuleConfig{
		{Name: "one", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Route: "primary"},
		{Name: "two", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Route: "archive"},
	}}, "rev")
	if _, err := acl.AuthorizeS3Request(Principal{Username: "alice"}, "project-a", "get", "primary"); err == nil {
		t.Fatal("ambiguous routes were accepted")
	}
}
