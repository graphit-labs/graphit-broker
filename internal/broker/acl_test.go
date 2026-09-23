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
		{ID: "write", Name: "write", Access: "user", Principal: "alice", Capabilities: []string{"s3"}, Projects: []string{"a"}, S3Operations: []string{"write"}, S3Prefixes: []string{"v2/projects/{project}/tasks/working"}},
	}}}
	acl := NewACL(reader)
	grant, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Teams: []string{"dev"}, Subject: "subject"}, S3SessionScope{Kind: "project", ProjectID: "a", Module: "task"}, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if grant.Revision != "9" || grant.Route != "primary" || len(grant.Access["read"]) != 1 || grant.Access["read"][0] != "v2/projects/a/tasks" || len(grant.Access["write"]) != 1 || grant.Access["write"][0] != "v2/projects/a/tasks/working" {
		t.Fatalf("grant=%#v", grant)
	}
	reader.document.Revision = 10
	reader.document.Rules = reader.document.Rules[1:]
	grant, err = acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Teams: []string{"dev"}, Subject: "subject"}, S3SessionScope{Kind: "project", ProjectID: "a", Module: "task"}, "primary")
	if err != nil || grant.Revision != "10" || len(grant.Access["read"]) != 0 {
		t.Fatalf("renewed grant=%#v err=%v", grant, err)
	}
}

func TestResolveS3SessionRejectsAnonymousNoGrantAndMultipleRoutes(t *testing.T) {
	acl := testACL(ACLRuleConfig{ID: "all", Name: "all", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"*"}})
	if _, err := acl.ResolveS3Session(context.Background(), AnonymousPrincipal(), S3SessionScope{Kind: "project", ProjectID: "a", Module: "task"}, "primary"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("anonymous error=%v", err)
	}
	if _, err := acl.ResolveS3Session(context.Background(), Principal{Username: "nobody", Subject: "s"}, S3SessionScope{Kind: "project", ProjectID: "a", Module: "task"}, "primary"); err != nil {
		t.Fatalf("authenticated wildcard grant error=%v", err)
	}
	acl = testACL(
		ACLRuleConfig{ID: "one", Name: "one", Access: "authenticated", Capabilities: []string{"s3:read"}, Projects: []string{"a"}, S3Route: "one"},
		ACLRuleConfig{ID: "two", Name: "two", Access: "authenticated", Capabilities: []string{"s3:write"}, Projects: []string{"a"}, S3Route: "two"},
	)
	if _, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Subject: "s"}, S3SessionScope{Kind: "project", ProjectID: "a", Module: "task"}, "primary"); err == nil || !strings.Contains(err.Error(), "multiple storage routes") {
		t.Fatalf("multiple route error=%v", err)
	}
}

func TestResolveS3SessionIsolatesProjectUserAndHubScopes(t *testing.T) {
	acl := testACL(ACLRuleConfig{ID: "all", Name: "all", Access: "authenticated", Capabilities: []string{"s3", "hub"}, Projects: []string{"*"}, S3Operations: []string{"read", "write"}, S3Prefixes: []string{"v2"}})
	principal := Principal{Username: "alice", Subject: "s"}
	tests := []struct {
		scope S3SessionScope
		roots []string
	}{
		{S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "task"}, []string{"v2/projects/project-a/tasks"}},
		{S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "memory"}, []string{"v2/projects/project-a/memory"}},
		{S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "dream"}, []string{"v2/projects/project-a/dream"}},
		{S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "knowledge"}, []string{"v2/projects/project-a/knowledge"}},
		{S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "ast"}, []string{"v2/projects/project-a/ast"}},
		{S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "hub"}, []string{"v2/projects/project-a/artifacts", "v2/projects/project-a/events", "v2/projects/project-a/project.json", "v2/projects/project-a/registry"}},
		{S3SessionScope{Kind: "user", Module: "memory"}, []string{"v2/users/alice/memory"}},
		{S3SessionScope{Kind: "hub", Module: "hub"}, []string{"v2/global/rules", "v2/registry"}},
	}
	for _, test := range tests {
		grant, err := acl.ResolveS3Session(context.Background(), principal, test.scope, "primary")
		if err != nil || strings.Join(grant.Access["read"], ",") != strings.Join(test.roots, ",") {
			t.Fatalf("scope=%#v grant=%#v err=%v", test.scope, grant, err)
		}
	}
	if _, err := acl.ResolveS3Session(context.Background(), principal, S3SessionScope{Kind: "project", ProjectID: "project-b", Module: "task"}, "primary"); err != nil {
		t.Fatalf("wildcard project scope: %v", err)
	}
	limited := testACL(ACLRuleConfig{ID: "a", Name: "a", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"project-a"}})
	if _, err := limited.ResolveS3Session(context.Background(), principal, S3SessionScope{Kind: "project", ProjectID: "project-b", Module: "task"}, "primary"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other project error=%v", err)
	}
	if _, err := limited.ResolveS3Session(context.Background(), principal, S3SessionScope{Kind: "user", Module: "memory"}, "primary"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("project grant opened user scope: %v", err)
	}
}

func TestResolveS3SessionComposesIndependentHubAndS3Rules(t *testing.T) {
	acl := testACL(
		ACLRuleConfig{ID: "hub", Name: "hub", Access: "authenticated", Capabilities: []string{"hub"}, Projects: []string{"global"}},
		ACLRuleConfig{ID: "s3", Name: "s3", Access: "authenticated", Capabilities: []string{"s3:read"}, Projects: []string{"*"}},
	)
	grant, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Subject: "s"}, S3SessionScope{Kind: "hub", Module: "hub"}, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if got := grant.Access["read"]; len(got) != 2 || got[0] != "v2/global/rules" || got[1] != "v2/registry" {
		t.Fatalf("hub prefixes=%#v", got)
	}
}

func TestValidateS3SessionScopeRequiresKnownCompatibleModule(t *testing.T) {
	tests := []struct {
		name  string
		scope S3SessionScope
	}{
		{"missing", S3SessionScope{Kind: "project", ProjectID: "project-a"}},
		{"unknown", S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "other"}},
		{"user task", S3SessionScope{Kind: "user", Module: "task"}},
		{"hub ast", S3SessionScope{Kind: "hub", Module: "ast"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateS3SessionScope(test.scope); err == nil {
				t.Fatalf("scope %#v was accepted", test.scope)
			}
		})
	}
}

func TestDreamS3SessionUsesItsOwnProjectPrefix(t *testing.T) {
	acl := testACL(ACLRuleConfig{ID: "dream", Name: "dream", Access: "authenticated", Capabilities: []string{"s3:read", "s3:write"}, Projects: []string{"project-a"}})
	grant, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Subject: "s"}, S3SessionScope{Kind: "project", ProjectID: "project-a", Module: "dream"}, "primary")
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"read", "write"} {
		if got := grant.Access[operation]; len(got) != 1 || got[0] != "v2/projects/project-a/dream" {
			t.Fatalf("%s prefixes = %#v", operation, got)
		}
	}
}
