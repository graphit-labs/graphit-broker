package broker

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

var ErrForbidden = errors.New("access denied")

type ACL struct {
	rules    []ACLRuleConfig
	revision string
}

type S3Grant struct {
	Project   string
	Operation string
	Prefixes  []string
}

func NewACL(cfg AuthorizationConfig, revision string) *ACL {
	return &ACL{rules: append([]ACLRuleConfig(nil), cfg.Rules...), revision: revision}
}

func (a *ACL) Revision() string { return a.revision }

func (a *ACL) AuthorizeCapability(principal Principal, capability string) error {
	for _, rule := range a.rules {
		if matchesPrincipal(rule, principal) && matchesValue(rule.Capabilities, capability) {
			return nil
		}
	}
	return ErrForbidden
}

func (a *ACL) AuthorizeS3(principal Principal, project, operation, basePrefix string) (S3Grant, error) {
	project = strings.TrimSpace(project)
	operation = strings.ToLower(strings.TrimSpace(operation))
	if !safeSegment(project) {
		return S3Grant{}, errors.New("project must be a non-empty safe path segment")
	}
	if operation != "read" && operation != "write" && operation != "publish" && operation != "delete" {
		return S3Grant{}, errors.New("operation must be read, write, publish, or delete")
	}
	set := map[string]struct{}{}
	for _, rule := range a.rules {
		if !matchesPrincipal(rule, principal) {
			continue
		}
		if !matchesValue(rule.Capabilities, "s3") && !matchesValue(rule.Capabilities, "s3:"+operation) {
			continue
		}
		if len(rule.Projects) > 0 && !matchesValue(rule.Projects, project) {
			continue
		}
		if len(rule.S3Operations) > 0 && !matchesValue(rule.S3Operations, operation) {
			continue
		}
		prefixes := rule.S3Prefixes
		if len(prefixes) == 0 {
			prefixes = []string{joinPrefix(basePrefix, project)}
		}
		for _, prefix := range prefixes {
			rendered, err := renderPrefix(prefix, principal, project)
			if err != nil {
				return S3Grant{}, fmt.Errorf("ACL rule %q: %w", rule.Name, err)
			}
			if rendered != "" {
				set[rendered] = struct{}{}
			}
		}
	}
	if len(set) == 0 {
		return S3Grant{}, ErrForbidden
	}
	prefixes := make([]string, 0, len(set))
	for prefix := range set {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	return S3Grant{Project: project, Operation: operation, Prefixes: prefixes}, nil
}

func matchesPrincipal(rule ACLRuleConfig, principal Principal) bool {
	matchedSelector := false
	if len(rule.Subjects) > 0 {
		matchedSelector = true
		if !matchesValue(rule.Subjects, principal.CanonicalSubject()) && !matchesValue(rule.Subjects, principal.Subject) {
			return false
		}
	}
	if len(rule.Users) > 0 {
		matchedSelector = true
		if !matchesValue(rule.Users, principal.Username) {
			return false
		}
	}
	if len(rule.Organizations) > 0 {
		matchedSelector = true
		if !matchesValue(rule.Organizations, principal.Organization) {
			return false
		}
	}
	if len(rule.Teams) > 0 {
		matchedSelector = true
		matched := false
		for _, team := range principal.Teams {
			if matchesValue(rule.Teams, team) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return matchedSelector
}

func matchesValue(patterns []string, value string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "*" || pattern == value {
			return true
		}
		if strings.ContainsAny(pattern, "*?[") {
			if matched, err := path.Match(pattern, value); err == nil && matched {
				return true
			}
		}
	}
	return false
}

var safeSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func safeSegment(value string) bool {
	return safeSegmentPattern.MatchString(value) && value != "." && value != ".."
}

func renderPrefix(template string, principal Principal, project string) (string, error) {
	values := map[string]string{
		"{project}": project, "{username}": principal.Username,
		"{organization}": principal.Organization, "{subject}": principal.Subject,
	}
	rendered := strings.Trim(strings.TrimSpace(template), "/")
	for placeholder, value := range values {
		if strings.Contains(rendered, placeholder) {
			if !safeSegment(value) {
				return "", fmt.Errorf("value for %s is not a safe S3 path segment", placeholder)
			}
			rendered = strings.ReplaceAll(rendered, placeholder, value)
		}
	}
	if rendered == "" || strings.Contains(rendered, "{") {
		return "", errors.New("S3 prefix is empty or has an unknown placeholder")
	}
	for _, segment := range strings.Split(rendered, "/") {
		if !safeSegment(segment) {
			return "", fmt.Errorf("S3 prefix contains unsafe segment %q", segment)
		}
	}
	return rendered, nil
}

func joinPrefix(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.Trim(strings.TrimSpace(part), "/"); value != "" {
			clean = append(clean, value)
		}
	}
	return strings.Join(clean, "/")
}
