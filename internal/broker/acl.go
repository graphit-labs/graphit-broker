package broker

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ErrForbidden = errors.New("access denied")

type ResourceGrantReader interface {
	ResourceGrants(context.Context) (PolicyDocument, error)
}

// ACL reads the current database snapshot for every operation, so a committed grant change is
// effective on the next request without a process-local policy cache.
type ACL struct{ grants ResourceGrantReader }

// S3SessionGrant is the complete, current S3 authorization snapshot for one
// principal. A single credential response has one storage topology, so all
// matching rules must resolve to the same route.
type S3SessionGrant struct {
	Revision string
	Route    string
	Access   map[string][]string
}

func NewACL(grants ResourceGrantReader) *ACL { return &ACL{grants: grants} }

func (a *ACL) Revision(ctx context.Context) (string, error) {
	document, err := a.grants.ResourceGrants(ctx)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(document.Revision, 10), nil
}

func (a *ACL) rules(ctx context.Context) ([]ACLRuleConfig, error) {
	document, err := a.grants.ResourceGrants(ctx)
	if err != nil {
		return nil, err
	}
	return document.Rules, nil
}

func (a *ACL) AuthorizeCapability(ctx context.Context, principal Principal, capability string) error {
	rules, err := a.rules(ctx)
	if err != nil {
		return fmt.Errorf("load resource grants: %w", err)
	}
	for _, rule := range rules {
		if matchesPrincipal(rule, principal) && matchesValue(rule.Capabilities, capability) {
			return nil
		}
	}
	return ErrForbidden
}

func (a *ACL) ResolveHubAccess(ctx context.Context, principal Principal) (PolicyDocument, error) {
	document, err := a.grants.ResourceGrants(ctx)
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("load resource grants: %w", err)
	}
	filtered := make([]ACLRuleConfig, 0, len(document.Rules))
	for _, rule := range document.Rules {
		if matchesPrincipal(rule, principal) && matchesValue(rule.Capabilities, "hub") {
			filtered = append(filtered, rule)
		}
	}
	document.Rules = filtered
	return document, nil
}

func (a *ACL) ResolveS3Session(ctx context.Context, principal Principal, defaultRoute string) (S3SessionGrant, error) {
	if principal.IsAnonymous() {
		return S3SessionGrant{}, ErrForbidden
	}
	document, err := a.grants.ResourceGrants(ctx)
	if err != nil {
		return S3SessionGrant{}, fmt.Errorf("load resource grants: %w", err)
	}
	sets := map[string]map[string]struct{}{}
	for _, operation := range []string{"read", "write", "publish", "delete"} {
		sets[operation] = map[string]struct{}{}
	}
	route := ""
	for _, rule := range document.Rules {
		if !matchesPrincipal(rule, principal) {
			continue
		}
		operations := matchingS3Operations(rule)
		if len(operations) == 0 {
			continue
		}
		candidateRoute := strings.TrimSpace(rule.S3Route)
		if candidateRoute == "" {
			candidateRoute = defaultRoute
		}
		if route != "" && route != candidateRoute {
			return S3SessionGrant{}, errors.New("matching S3 ACL rules select multiple storage routes")
		}
		route = candidateRoute
		prefixes, renderErr := renderSessionPrefixes(rule, principal)
		if renderErr != nil {
			return S3SessionGrant{}, fmt.Errorf("ACL rule %q: %w", rule.Name, renderErr)
		}
		for _, operation := range operations {
			for _, prefix := range prefixes {
				sets[operation][prefix] = struct{}{}
			}
		}
	}
	access := map[string][]string{}
	for operation, set := range sets {
		for prefix := range set {
			access[operation] = append(access[operation], prefix)
		}
		sort.Strings(access[operation])
	}
	if route == "" {
		return S3SessionGrant{}, ErrForbidden
	}
	return S3SessionGrant{Revision: strconv.FormatUint(document.Revision, 10), Route: route, Access: access}, nil
}

func matchingS3Operations(rule ACLRuleConfig) []string {
	operations := make([]string, 0, 4)
	for _, operation := range []string{"read", "write", "publish", "delete"} {
		if (!matchesValue(rule.Capabilities, "s3") && !matchesValue(rule.Capabilities, "s3:"+operation)) ||
			(len(rule.S3Operations) > 0 && !matchesValue(rule.S3Operations, operation)) {
			continue
		}
		operations = append(operations, operation)
	}
	return operations
}

func renderSessionPrefixes(rule ACLRuleConfig, principal Principal) ([]string, error) {
	projects := rule.Projects
	if len(projects) == 0 {
		projects = []string{"*"}
	}
	prefixes := rule.S3Prefixes
	if len(prefixes) == 0 {
		for _, project := range projects {
			if project == "*" || project == "global" {
				return []string{"v2"}, nil
			}
		}
		result := make([]string, 0, len(projects))
		for _, project := range projects {
			result = append(result, "v2/projects/"+project)
		}
		return result, nil
	}
	set := map[string]struct{}{}
	for _, template := range prefixes {
		for _, project := range projects {
			if project == "*" {
				project = "GRAPHIT_PROJECT_WILDCARD"
			}
			rendered, err := renderPrefix(template, principal, project)
			if err != nil {
				return nil, err
			}
			rendered = strings.ReplaceAll(rendered, "GRAPHIT_PROJECT_WILDCARD", "*")
			set[rendered] = struct{}{}
			if !strings.Contains(template, "{project}") {
				break
			}
		}
	}
	result := make([]string, 0, len(set))
	for prefix := range set {
		result = append(result, prefix)
	}
	sort.Strings(result)
	return result, nil
}

func matchesPrincipal(rule ACLRuleConfig, principal Principal) bool {
	switch strings.ToLower(strings.TrimSpace(rule.Access)) {
	case "global":
		return true
	case "anonymous":
		return principal.IsAnonymous()
	case "authenticated":
		return !principal.IsAnonymous()
	case "user":
		return !principal.IsAnonymous() && principal.Username == strings.TrimSpace(rule.Principal)
	case "team":
		return !principal.IsAnonymous() && containsString(principal.Teams, strings.TrimSpace(rule.Principal))
	case "organization":
		return !principal.IsAnonymous() && principal.Organization == strings.TrimSpace(rule.Principal)
	case "subject":
		value := strings.TrimSpace(rule.Principal)
		return !principal.IsAnonymous() && (principal.Subject == value || principal.CanonicalSubject() == value)
	}
	return false
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
