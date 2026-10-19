//! S3 operation/prefix policy over the existing literal Hub principal matcher.
use crate::{
    ResourceGrantSnapshot, StorageAdmissionError, StorageOperation, StorageScope,
    resource_policy::{HubResourcePolicy, check_deadline, pattern},
    storage_admission::StorageIdentity,
};
use regex::bytes::Regex;
use std::{collections::BTreeSet, time::Instant};

struct StorageRule {
    route: String,
    operations: Vec<Regex>,
    templates: Vec<String>,
}
pub(crate) struct StoragePolicy<'a> {
    hub: HubResourcePolicy<'a>,
    rules: Vec<StorageRule>,
}
pub(crate) struct StorageDecision {
    pub(crate) route: String,
    pub(crate) access: [Vec<String>; 4],
}
impl<'a> StoragePolicy<'a> {
    pub(crate) fn compile(
        snapshot: &'a ResourceGrantSnapshot,
        end: Instant,
    ) -> Result<Self, StorageAdmissionError> {
        let hub = HubResourcePolicy::compile(snapshot, end)?;
        let mut rules = Vec::with_capacity(snapshot.rules().len());
        for r in snapshot.rules() {
            check_deadline(end)?;
            let operations = r
                .s3_operations()
                .iter()
                .map(|s| pattern(s, end))
                .collect::<Result<Vec<_>, _>>()?;
            let mut templates = Vec::with_capacity(r.s3_prefixes().len());
            for raw in r.s3_prefixes() {
                check_deadline(end)?;
                let template = raw.trim().trim_matches('/').to_owned();
                // Lexical DATA probe only. These values are never stored or admitted.
                let mut probe = template.clone();
                for name in ["{project}", "{username}", "{organization}", "{subject}"] {
                    probe = probe.replace(name, "validation");
                }
                if !safe_path(&probe) {
                    return Err(StorageAdmissionError::InvalidPolicy);
                }
                templates.push(template);
            }
            rules.push(StorageRule {
                route: r.s3_route().trim().into(),
                operations,
                templates,
            });
        }
        check_deadline(end)?;
        Ok(Self { hub, rules })
    }
    pub(crate) fn evaluate(
        &self,
        identity: &StorageIdentity<'_>,
        scope: &StorageScope,
        default_route: &str,
        end: Instant,
    ) -> Result<Option<StorageDecision>, StorageAdmissionError> {
        let matches = self.hub.storage_rules(identity, scope.project_id(), end)?;
        if scope.is_global_hub() && !matches.iter().any(|(_, _, hub)| *hub) {
            check_deadline(end)?;
            return Ok(None);
        }
        let roots = scope.roots(identity);
        let mut route = None::<String>;
        let mut access: [BTreeSet<String>; 4] = std::array::from_fn(|_| BTreeSet::new());
        for (index, caps, _) in matches {
            check_deadline(end)?;
            let rule = &self.rules[index];
            let allowed = StorageOperation::ALL.map(|op| {
                caps[op.index()]
                    && (rule.operations.is_empty()
                        || rule
                            .operations
                            .iter()
                            .any(|p| p.is_match(op.name().as_bytes())))
            });
            if !allowed.iter().any(|x| *x) {
                continue;
            }
            let mut prefixes = BTreeSet::new();
            if rule.templates.is_empty() {
                prefixes.extend(roots.iter().cloned());
            }
            for template in &rule.templates {
                check_deadline(end)?;
                let Some(candidate) = render(template, identity, scope.project_id())? else {
                    continue;
                };
                for root in &roots {
                    if let Some(p) = intersect(&candidate, root) {
                        prefixes.insert(p.into());
                    }
                }
            }
            if prefixes.is_empty() {
                continue;
            }
            let selected = if rule.route.is_empty() {
                default_route
            } else {
                &rule.route
            };
            if route.as_deref().is_some_and(|prior| prior != selected) {
                return Err(StorageAdmissionError::ConflictingRoutes);
            }
            route = Some(selected.into());
            for op in StorageOperation::ALL {
                if allowed[op.index()] {
                    access[op.index()].extend(prefixes.iter().cloned());
                }
            }
        }
        check_deadline(end)?;
        Ok(route.map(|route| StorageDecision {
            route,
            access: access.map(|s| s.into_iter().collect()),
        }))
    }
}
fn safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && s != "."
        && s != ".."
}
fn safe_path(s: &str) -> bool {
    !s.is_empty() && s.split('/').all(safe_segment)
}
fn render(
    template: &str,
    identity: &StorageIdentity<'_>,
    project: Option<&str>,
) -> Result<Option<String>, StorageAdmissionError> {
    if project.is_none() && template.contains("{project}") {
        return Ok(None);
    }
    let (username, organization, subject) = match identity {
        StorageIdentity::Native(p) => (p.username(), p.organization(), p.subject()),
        StorageIdentity::Local(p) => {
            let u = p.current_local_user();
            (Some(u.username()), Some(u.organization()), u.subject())
        }
    };
    let mut rendered = template.to_owned();
    for (name, value) in [
        ("{project}", project),
        ("{username}", username),
        ("{organization}", organization),
        ("{subject}", Some(subject)),
    ] {
        if rendered.contains(name) {
            let value = value
                .filter(|v| safe_segment(v))
                .ok_or(StorageAdmissionError::InvalidPolicy)?;
            rendered = rendered.replace(name, value);
        }
    }
    if !safe_path(&rendered) {
        return Err(StorageAdmissionError::InvalidPolicy);
    }
    Ok(Some(rendered))
}
fn intersect<'a>(candidate: &'a str, root: &'a str) -> Option<&'a str> {
    if candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|s| s.starts_with('/'))
    {
        Some(candidate)
    } else if root
        .strip_prefix(candidate)
        .is_some_and(|s| s.starts_with('/'))
    {
        Some(root)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_path_intersections_and_template_grammar() {
        let root = "v1/projects/01D39ZY06FGSCTVN4T2V9PKHFZ/artifacts";
        for ancestor in [
            "v1",
            "v1/projects",
            "v1/projects/01D39ZY06FGSCTVN4T2V9PKHFZ",
        ] {
            assert_eq!(intersect(ancestor, root), Some(root));
        }
        assert_eq!(intersect(root, root), Some(root));
        let child = format!("{root}/task/encoded-id/exact-version/digest");
        assert_eq!(intersect(&child, root), Some(child.as_str()));
        for other in [
            format!("{root}2"),
            format!("{root}-sibling"),
            root.replace("PKHFZ", "PKHG0"),
            "v1/projects/01D39ZY06FGSCTVN4T2V9PKHFZ/registry".into(),
        ] {
            assert_eq!(intersect(&other, root), None);
        }
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "-prefix",
            "../escape",
            "a*b",
            "a?b",
            "a[b]",
            "a{unknown}",
            "é",
            "a\0",
        ] {
            assert!(!safe_segment(bad));
        }
        assert!(safe_segment(&"a".repeat(128)));
        assert!(!safe_segment(&"a".repeat(129)));
        assert!(safe_path("v1/projects/valid-name_1.2/artifacts"));
        for bad in [
            "v1//artifacts",
            "v1/../artifacts",
            "/v1/artifacts",
            "v1/artifacts/",
        ] {
            assert!(!safe_path(bad));
        }
    }
}
