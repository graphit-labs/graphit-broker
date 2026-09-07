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
		S3Prefixes: []string{"organizations/{organization}/projects/{project}"},
	}}}, "rev")
	grant, err := acl.AuthorizeS3(Principal{Issuer: "i", Subject: "s", Username: "alice", Organization: "acme", Teams: []string{"platform"}}, "platform-api", "publish", "graphit")
	if err != nil {
		t.Fatalf("AuthorizeS3: %v", err)
	}
	want := []string{"organizations/acme/projects/platform-api"}
	if !reflect.DeepEqual(grant.Prefixes, want) {
		t.Fatalf("prefixes = %#v, want %#v", grant.Prefixes, want)
	}
	if _, err := acl.AuthorizeS3(Principal{Username: "alice", Organization: "acme", Teams: []string{"platform"}}, "../escape", "publish", "graphit"); err == nil {
		t.Fatal("unsafe project accepted")
	}
}
