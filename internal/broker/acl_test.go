package broker

import (
	"context"
	"errors"
	"strings"
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

func TestResolveS3SessionDerivesAllEffectiveOperationsAndCurrentRevision(t *testing.T) {
	reader := &resourceGrantStub{document: PolicyDocument{Version: 1, Revision: 9, Rules: []ACLRuleConfig{
		{ID: "read", Name: "read", Access: "team", Principal: "dev", Capabilities: []string{"s3:read"}, Projects: []string{"a", "b"}},
		{ID: "write", Name: "write", Access: "user", Principal: "alice", Capabilities: []string{"s3"}, Projects: []string{"a"}, S3Operations: []string{"write"}, S3Prefixes: []string{"v2/projects/{project}/working"}},
	}}}
	acl := NewACL(reader)
	grant, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Teams: []string{"dev"}, Subject: "subject"}, S3SessionScope{Kind: "project", ProjectID: "a"}, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if grant.Revision != "9" || grant.Route != "primary" || len(grant.Access["read"]) != 1 || grant.Access["read"][0] != "v2/projects/a" || len(grant.Access["write"]) != 1 {
		t.Fatalf("grant=%#v", grant)
	}
	reader.document.Revision = 10
	reader.document.Rules = reader.document.Rules[1:]
	grant, err = acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Teams: []string{"dev"}, Subject: "subject"}, S3SessionScope{Kind: "project", ProjectID: "a"}, "primary")
	if err != nil || grant.Revision != "10" || len(grant.Access["read"]) != 0 {
		t.Fatalf("renewed grant=%#v err=%v", grant, err)
	}
}

func TestResolveS3SessionRejectsAnonymousNoGrantAndMultipleRoutes(t *testing.T) {
	acl := testACL(ACLRuleConfig{ID: "all", Name: "all", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"*"}})
	if _, err := acl.ResolveS3Session(context.Background(), AnonymousPrincipal(), S3SessionScope{Kind: "project", ProjectID: "a"}, "primary"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("anonymous error=%v", err)
	}
	if _, err := acl.ResolveS3Session(context.Background(), Principal{Username: "nobody", Subject: "s"}, S3SessionScope{Kind: "project", ProjectID: "a"}, "primary"); err != nil {
		t.Fatalf("authenticated wildcard grant error=%v", err)
	}
	acl = testACL(
		ACLRuleConfig{ID: "one", Name: "one", Access: "authenticated", Capabilities: []string{"s3:read"}, Projects: []string{"a"}, S3Route: "one"},
		ACLRuleConfig{ID: "two", Name: "two", Access: "authenticated", Capabilities: []string{"s3:write"}, Projects: []string{"a"}, S3Route: "two"},
	)
	if _, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Subject: "s"}, S3SessionScope{Kind: "project", ProjectID: "a"}, "primary"); err == nil || !strings.Contains(err.Error(), "multiple storage routes") {
		t.Fatalf("multiple route error=%v", err)
	}
}

func TestResolveS3SessionIsolatesProjectUserAndHubScopes(t *testing.T) {
	acl := testACL(ACLRuleConfig{ID: "all", Name: "all", Access: "authenticated", Capabilities: []string{"s3", "hub"}, Projects: []string{"*"}, S3Operations: []string{"read", "write"}, S3Prefixes: []string{"v2"}})
	principal := Principal{Username: "alice", Subject: "s"}
	tests := []struct {
		scope S3SessionScope
		root  string
	}{
		{S3SessionScope{Kind: "project", ProjectID: "project-a"}, "v2/projects/project-a"},
		{S3SessionScope{Kind: "user"}, "v2/users/alice/memory"},
		{S3SessionScope{Kind: "hub"}, "v2/registry"},
	}
	for _, test := range tests {
		grant, err := acl.ResolveS3Session(context.Background(), principal, test.scope, "primary")
		found := false
		for _, prefix := range grant.Access["read"] {
			found = found || prefix == test.root
		}
		if err != nil || !found {
			t.Fatalf("scope=%#v grant=%#v err=%v", test.scope, grant, err)
		}
	}
	if _, err := acl.ResolveS3Session(context.Background(), principal, S3SessionScope{Kind: "project", ProjectID: "project-b"}, "primary"); err != nil {
		t.Fatalf("wildcard project scope: %v", err)
	}
	limited := testACL(ACLRuleConfig{ID: "a", Name: "a", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"project-a"}})
	if _, err := limited.ResolveS3Session(context.Background(), principal, S3SessionScope{Kind: "project", ProjectID: "project-b"}, "primary"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other project error=%v", err)
	}
	if _, err := limited.ResolveS3Session(context.Background(), principal, S3SessionScope{Kind: "user"}, "primary"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("project grant opened user scope: %v", err)
	}
}

func TestResolveS3SessionComposesIndependentHubAndS3Rules(t *testing.T) {
	acl := testACL(
		ACLRuleConfig{ID: "hub", Name: "hub", Access: "authenticated", Capabilities: []string{"hub"}, Projects: []string{"global"}},
		ACLRuleConfig{ID: "s3", Name: "s3", Access: "authenticated", Capabilities: []string{"s3:read"}, Projects: []string{"*"}},
	)
	grant, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Subject: "s"}, S3SessionScope{Kind: "hub"}, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if got := grant.Access["read"]; len(got) != 2 || got[0] != "v2/global/rules" || got[1] != "v2/registry" {
		t.Fatalf("hub prefixes=%#v", got)
	}
}
