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
	grant, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Teams: []string{"dev"}, Subject: "subject"}, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if grant.Revision != "9" || grant.Route != "primary" || len(grant.Access["read"]) != 2 || len(grant.Access["write"]) != 1 {
		t.Fatalf("grant=%#v", grant)
	}
	reader.document.Revision = 10
	reader.document.Rules = reader.document.Rules[1:]
	grant, err = acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Teams: []string{"dev"}, Subject: "subject"}, "primary")
	if err != nil || grant.Revision != "10" || len(grant.Access["read"]) != 0 {
		t.Fatalf("renewed grant=%#v err=%v", grant, err)
	}
}

func TestResolveS3SessionRejectsAnonymousNoGrantAndMultipleRoutes(t *testing.T) {
	acl := testACL(ACLRuleConfig{ID: "all", Name: "all", Access: "authenticated", Capabilities: []string{"s3"}, Projects: []string{"*"}})
	if _, err := acl.ResolveS3Session(context.Background(), AnonymousPrincipal(), "primary"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("anonymous error=%v", err)
	}
	if _, err := acl.ResolveS3Session(context.Background(), Principal{Username: "nobody", Subject: "s"}, "primary"); err != nil {
		t.Fatalf("authenticated wildcard grant error=%v", err)
	}
	acl = testACL(
		ACLRuleConfig{ID: "one", Name: "one", Access: "authenticated", Capabilities: []string{"s3:read"}, Projects: []string{"a"}, S3Route: "one"},
		ACLRuleConfig{ID: "two", Name: "two", Access: "authenticated", Capabilities: []string{"s3:write"}, Projects: []string{"a"}, S3Route: "two"},
	)
	if _, err := acl.ResolveS3Session(context.Background(), Principal{Username: "alice", Subject: "s"}, "primary"); err == nil || !strings.Contains(err.Error(), "multiple storage routes") {
		t.Fatalf("multiple route error=%v", err)
	}
}
