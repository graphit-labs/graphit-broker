package broker

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type resourceGrantStub struct{ document PolicyDocument }

func (s *resourceGrantStub) ResourceGrants(context.Context) (PolicyDocument, error) {
	return clonePolicy(s.document), nil
}

func clonePolicy(document PolicyDocument) PolicyDocument {
	rules := document.Rules
	document.Rules = make([]ACLRuleConfig, len(rules))
	for i, rule := range rules {
		document.Rules[i] = rule
		document.Rules[i].Capabilities = append([]string(nil), rule.Capabilities...)
		document.Rules[i].Projects = append([]string(nil), rule.Projects...)
		document.Rules[i].S3Operations = append([]string(nil), rule.S3Operations...)
		document.Rules[i].S3Prefixes = append([]string(nil), rule.S3Prefixes...)
	}
	return document
}

func testACL(rules ...ACLRuleConfig) *ACL {
	return NewACL(&resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: rules}})
}

func TestACLIsDenyByDefaultAndReadsCurrentGrants(t *testing.T) {
	reader := &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 1, Rules: []ACLRuleConfig{{
		ID: "platform", Name: "platform", Access: "team", Principal: "platform", Capabilities: []string{"embeddings"},
	}}}}
	acl := NewACL(reader)
	allowed := Principal{Issuer: "https://id", Subject: "1", Username: "alice", Teams: []string{"platform"}, AuthMethod: "oidc"}
	if err := acl.AuthorizeCapability(context.Background(), allowed, "embeddings"); err != nil {
		t.Fatalf("AuthorizeCapability: %v", err)
	}
	reader.document.Rules = nil
	reader.document.Revision++
	if err := acl.AuthorizeCapability(context.Background(), allowed, "embeddings"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("removed grant remained active: %v", err)
	}
	if revision, _ := acl.Revision(context.Background()); revision != "2" {
		t.Fatalf("revision=%q", revision)
	}
}

func TestACLAccessLevelsAndTemplatedS3Grant(t *testing.T) {
	acl := testACL(
		ACLRuleConfig{ID: "global", Name: "global", Access: "global", Capabilities: []string{"global"}},
		ACLRuleConfig{ID: "anonymous", Name: "anonymous", Access: "anonymous", Capabilities: []string{"anonymous"}},
		ACLRuleConfig{ID: "authenticated", Name: "authenticated", Access: "authenticated", Capabilities: []string{"authenticated"}},
		ACLRuleConfig{ID: "user", Name: "user", Access: "user", Principal: "alice", Capabilities: []string{"user"}},
		ACLRuleConfig{ID: "team", Name: "team", Access: "team", Principal: "platform", Capabilities: []string{"team"}},
		ACLRuleConfig{ID: "organization", Name: "organization", Access: "organization", Principal: "acme", Capabilities: []string{"organization", "s3"}, Projects: []string{"platform-*"}, S3Operations: []string{"publish"}, S3Prefixes: []string{"v2/organizations/{organization}/projects/{project}"}, S3Route: "tenant-a"},
		ACLRuleConfig{ID: "subject", Name: "subject", Access: "subject", Principal: "https://id|subject-1", Capabilities: []string{"subject"}},
	)
	ctx := context.Background()
	anonymous := AnonymousPrincipal()
	for _, capability := range []string{"global", "anonymous"} {
		if err := acl.AuthorizeCapability(ctx, anonymous, capability); err != nil {
			t.Fatalf("anonymous %s: %v", capability, err)
		}
	}
	principal := Principal{Issuer: "https://id", Subject: "subject-1", Username: "alice", Organization: "acme", Teams: []string{"platform"}, AuthMethod: "oidc"}
	for _, capability := range []string{"global", "authenticated", "user", "team", "organization", "subject"} {
		if err := acl.AuthorizeCapability(ctx, principal, capability); err != nil {
			t.Fatalf("authenticated %s: %v", capability, err)
		}
	}
	grant, err := acl.AuthorizeS3(ctx, principal, "platform-api", "publish", "default")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grant.Prefixes, []string{"v2/organizations/acme/projects/platform-api"}) || grant.Route != "tenant-a" {
		t.Fatalf("grant=%#v", grant)
	}
	if _, err := acl.AuthorizeS3(ctx, principal, "../escape", "publish", "default"); err == nil {
		t.Fatal("unsafe project accepted")
	}
}

func TestACLMapsPublishAndRejectsAmbiguousRoutes(t *testing.T) {
	principal := Principal{Username: "alice", AuthMethod: "oidc"}
	acl := testACL(ACLRuleConfig{ID: "publisher", Name: "publisher", Access: "user", Principal: "alice", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Operations: []string{"publish"}, S3Prefixes: []string{"v2/projects/{project}"}})
	for _, operation := range []string{"get", "head", "list", "put", "delete"} {
		if _, err := acl.AuthorizeS3Request(context.Background(), principal, "project-a", operation, "primary"); err != nil {
			t.Fatalf("operation %s: %v", operation, err)
		}
	}
	ambiguous := testACL(
		ACLRuleConfig{ID: "one", Name: "one", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Route: "primary"},
		ACLRuleConfig{ID: "two", Name: "two", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"project-a"}, S3Route: "archive"},
	)
	if _, err := ambiguous.AuthorizeS3Request(context.Background(), principal, "project-a", "get", "primary"); err == nil {
		t.Fatal("ambiguous routes were accepted")
	}
}
