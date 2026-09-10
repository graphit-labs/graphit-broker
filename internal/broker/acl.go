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
// principal and requested storage scope. A single credential response has one
// storage topology, so all contributing rules must resolve to the same route.
type S3SessionGrant struct {
	Revision string
	Route    string
	Access   map[string][]string
	Scope    S3SessionScope
}

type S3SessionScope struct {
	Kind      string
	ProjectID string
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

func (a *ACL) ResolveS3Session(ctx context.Context, principal Principal, scope S3SessionScope, defaultRoute string) (S3SessionGrant, error) {
	if principal.IsAnonymous() {
		return S3SessionGrant{}, ErrForbidden
	}
	roots, err := s3SessionScopeRoots(principal, scope)
	if err != nil {
		return S3SessionGrant{}, err
	}
	document, err := a.grants.ResourceGrants(ctx)
	if err != nil {
		return S3SessionGrant{}, fmt.Errorf("load resource grants: %w", err)
	}
	sets := map[string]map[string]struct{}{}
	for _, operation := range []string{"read", "write", "publish", "delete"} {
		sets[operation] = map[string]struct{}{}
	}
	if scope.Kind == "hub" {
		hubAllowed := false
		for _, rule := range document.Rules {
			if matchesPrincipal(rule, principal) && matchesS3Scope(rule, scope) && matchesValue(rule.Capabilities, "hub") {
				hubAllowed = true
				break
			}
		}
		if !hubAllowed {
			return S3SessionGrant{}, ErrForbidden
		}
	}
	route := ""
	for _, rule := range document.Rules {
		if !matchesPrincipal(rule, principal) || !matchesS3Scope(rule, scope) {
			continue
		}
		operations := matchingS3Operations(rule)
		if len(operations) == 0 {
			continue
		}
		prefixes, renderErr := renderSessionPrefixesForScope(rule, principal, scope, roots)
		if renderErr != nil {
			return S3SessionGrant{}, fmt.Errorf("ACL rule %q: %w", rule.Name, renderErr)
		}
		if len(prefixes) == 0 {
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
	return S3SessionGrant{Revision: strconv.FormatUint(document.Revision, 10), Route: route, Access: access, Scope: scope}, nil
}

func s3SessionScopeRoots(principal Principal, scope S3SessionScope) ([]string, error) {
	if err := validateS3SessionScope(scope); err != nil {
		return nil, err
	}
	switch scope.Kind {
	case "project":
		return []string{"v2/projects/" + scope.ProjectID}, nil
	case "user":
		if !safeSegment(principal.Username) {
			return nil, errors.New("invalid user storage scope")
		}
		return []string{"v2/users/" + principal.Username + "/memory"}, nil
	case "hub":
		return []string{"v2/registry", "v2/global/rules"}, nil
	}
	panic("validated S3 scope has no roots")
}

func validateS3SessionScope(scope S3SessionScope) error {
	switch scope.Kind {
	case "project":
		if !safeSegment(scope.ProjectID) {
			return errors.New("invalid project storage scope")
		}
	case "user", "hub":
		if scope.ProjectID != "" {
			return fmt.Errorf("%s storage scope cannot select a project", scope.Kind)
		}
	default:
		return errors.New("invalid S3 storage scope")
	}
	return nil
}

func matchesS3Scope(rule ACLRuleConfig, scope S3SessionScope) bool {
	projects := rule.Projects
	if len(projects) == 0 {
		projects = []string{"*"}
	}
	if scope.Kind == "project" {
		return matchesValue(projects, scope.ProjectID) || matchesValue(projects, "global")
	}
	return matchesValue(projects, "*") || matchesValue(projects, "global")
}

func renderSessionPrefixesForScope(rule ACLRuleConfig, principal Principal, scope S3SessionScope, roots []string) ([]string, error) {
	if len(rule.S3Prefixes) == 0 {
		return append([]string(nil), roots...), nil
	}
	project := scope.ProjectID
	if project == "" {
		project = "global"
	}
	set := map[string]struct{}{}
	for _, template := range rule.S3Prefixes {
		rendered, err := renderPrefix(template, principal, project)
		if err != nil {
			return nil, err
		}
		for _, root := range roots {
			if narrowed := intersectS3Prefix(rendered, root); narrowed != "" {
				set[narrowed] = struct{}{}
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

func intersectS3Prefix(candidate, root string) string {
	candidate = strings.Trim(candidate, "/")
	root = strings.Trim(root, "/")
	switch {
	case candidate == root, strings.HasPrefix(candidate, root+"/"):
		return candidate
	case strings.HasPrefix(root, candidate+"/"):
		return root
	default:
		return ""
	}
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
