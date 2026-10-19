//! Private PROJECT/Presence glob policy and separate literal Hub principal policy.
use crate::{
    LocalBearerUser, ResourceGrantSnapshot, VerifiedBrokerAccess,
    instance_registry::canonical_project_id,
};
use globset::GlobBuilder;
use regex::bytes::Regex;
use std::{collections::HashSet, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourcePolicyError {
    InvalidPolicy,
    Deadline,
}
// Private views are created only from the actual authenticated caller types.
struct Principal<'a> {
    issuer: &'a str,
    subject: &'a str,
    username: Option<&'a str>,
    organization: Option<&'a str>,
    teams: &'a [String],
}
impl<'a> Principal<'a> {
    fn inference(identity: &'a crate::embedding_admission::EmbeddingIdentity<'_>) -> Option<Self> {
        use crate::embedding_admission::EmbeddingIdentity;
        match identity {
            EmbeddingIdentity::Anonymous => None,
            EmbeddingIdentity::Broker(proof) => Some(Self::broker(proof)),
            EmbeddingIdentity::Local(proof) => Some(Self::local(proof.current_local_user())),
            EmbeddingIdentity::Upstream(proof) => Some(Principal {
                issuer: proof.issuer(),
                subject: &proof.profile().subject,
                username: Some(proof.username()),
                organization: Some(proof.organization()),
                teams: proof.teams(),
            }),
        }
    }
    fn local(user: &'a LocalBearerUser) -> Self {
        Self {
            issuer: user.issuer(),
            subject: user.subject(),
            username: Some(user.username()),
            organization: Some(user.organization()),
            teams: user.teams(),
        }
    }
    fn broker(user: &'a VerifiedBrokerAccess<'_>) -> Self {
        Self {
            issuer: user.issuer(),
            subject: user.subject(),
            username: user.username(),
            organization: user.organization(),
            teams: user.teams(),
        }
    }
}

enum Selector {
    Global,
    Anonymous,
    Authenticated,
    User(Regex),
    Team(Regex),
    Organization(Regex),
    Subject(Regex),
}
impl Selector {
    fn matches(&self, user: &Principal<'_>) -> bool {
        match self {
            Self::Global | Self::Authenticated => true,
            Self::Anonymous => false,
            Self::User(pattern) => user
                .username
                .is_some_and(|value| pattern.is_match(value.as_bytes())),
            Self::Team(pattern) => user
                .teams
                .iter()
                .any(|team| pattern.is_match(team.as_bytes())),
            Self::Organization(pattern) => user
                .organization
                .is_some_and(|value| pattern.is_match(value.as_bytes())),
            Self::Subject(pattern) => {
                pattern.is_match(user.subject.as_bytes())
                    || pattern.is_match(format!("{}|{}", user.issuer, user.subject).as_bytes())
            }
        }
    }
}
struct CompiledRule<'a> {
    selector: Selector,
    capabilities: Vec<Regex>,
    projects: &'a [String],
}
pub(crate) struct ResourcePolicy<'a> {
    rules: Vec<CompiledRule<'a>>,
}

enum HubSelector<'a> {
    Global,
    Anonymous,
    Authenticated,
    User(&'a str),
    Team(&'a str),
    Organization(&'a str),
    Subject(&'a str),
}
impl HubSelector<'_> {
    fn matches(&self, user: Option<&Principal<'_>>) -> bool {
        match self {
            Self::Global => true,
            Self::Anonymous => user.is_none(),
            Self::Authenticated => user.is_some(),
            Self::User(value) => user.and_then(|u| u.username) == Some(*value),
            Self::Team(value) => user.is_some_and(|u| u.teams.iter().any(|t| t == value)),
            Self::Organization(value) => user.and_then(|u| u.organization) == Some(*value),
            Self::Subject(value) => user.is_some_and(|u| {
                u.subject == *value
                    || value
                        .strip_prefix(u.issuer)
                        .and_then(|v| v.strip_prefix('|'))
                        == Some(u.subject)
            }),
        }
    }
}
struct HubRule<'a> {
    selector: HubSelector<'a>,
    capabilities: Vec<Regex>,
    projects: &'a [String],
}
pub(crate) struct HubResourcePolicy<'a> {
    rules: Vec<HubRule<'a>>,
}
impl<'a> HubResourcePolicy<'a> {
    pub(crate) fn compile(
        snapshot: &'a ResourceGrantSnapshot,
        end: Instant,
    ) -> Result<Self, ResourcePolicyError> {
        let mut rules = Vec::with_capacity(snapshot.rules().len());
        for rule in snapshot.rules() {
            check_deadline(end)?;
            let principal = rule.principal().trim();
            let selector = match rule.access_kind().trim().to_ascii_lowercase().as_str() {
                "global" => HubSelector::Global,
                "anonymous" => HubSelector::Anonymous,
                "authenticated" => HubSelector::Authenticated,
                "user" => HubSelector::User(principal),
                "team" => HubSelector::Team(principal),
                "organization" => HubSelector::Organization(principal),
                "subject" => HubSelector::Subject(principal),
                _ => return Err(ResourcePolicyError::InvalidPolicy),
            };
            if rule.capabilities().is_empty()
                || rule.projects().iter().any(|p| {
                    let p = p.trim();
                    p != "*" && !canonical_project_id(p)
                })
            {
                return Err(ResourcePolicyError::InvalidPolicy);
            }
            let capabilities = rule
                .capabilities()
                .iter()
                .map(|p| pattern(p, end))
                .collect::<Result<Vec<_>, _>>()?;
            rules.push(HubRule {
                selector,
                capabilities,
                projects: rule.projects(),
            });
        }
        check_deadline(end)?;
        Ok(Self { rules })
    }
    pub(crate) fn allows_inference(
        &self,
        identity: &crate::embedding_admission::EmbeddingIdentity<'_>,
        capability: &[u8],
        end: Instant,
    ) -> Result<bool, ResourcePolicyError> {
        let user = Principal::inference(identity);
        for rule in &self.rules {
            check_deadline(end)?;
            if rule.selector.matches(user.as_ref())
                && rule.capabilities.iter().any(|p| p.is_match(capability))
            {
                return Ok(true);
            }
        }
        check_deadline(end)?;
        Ok(false)
    }
    pub(crate) fn selectors(
        &self,
        identity: &crate::hub_access::HubIdentity<'_>,
        end: Instant,
    ) -> Result<Vec<crate::HubProjectSelector>, ResourcePolicyError> {
        use crate::hub_access::HubIdentity;
        let user = match identity {
            HubIdentity::Anonymous => None,
            HubIdentity::Broker(proof) => Some(Principal::broker(proof)),
            HubIdentity::Local(proof) => Some(Principal::local(proof.current_local_user())),
        };
        let mut seen = HashSet::new();
        let mut selectors = Vec::new();
        for rule in &self.rules {
            check_deadline(end)?;
            if !rule.selector.matches(user.as_ref())
                || !rule.capabilities.iter().any(|p| p.is_match(b"hub"))
            {
                continue;
            }
            if rule.projects.is_empty() && seen.insert(None) {
                selectors.push(crate::HubProjectSelector::all());
            }
            for project in rule.projects {
                check_deadline(end)?;
                let project = project.trim();
                let key = (project != "*").then_some(project);
                if seen.insert(key) {
                    selectors.push(match key {
                        None => crate::HubProjectSelector::all(),
                        Some(id) => crate::HubProjectSelector::project(id),
                    });
                }
            }
        }
        check_deadline(end)?;
        Ok(selectors)
    }
    pub(crate) fn catalog_routes(
        &self,
        identity: &crate::hub_access::HubIdentity<'_>,
        snapshot: &ResourceGrantSnapshot,
        end: Instant,
    ) -> Result<Vec<crate::hub_access::HubCatalogRoute>, ResourcePolicyError> {
        use crate::hub_access::HubIdentity;
        let user = match identity {
            HubIdentity::Anonymous => None,
            HubIdentity::Broker(proof) => Some(Principal::broker(proof)),
            HubIdentity::Local(proof) => Some(Principal::local(proof.current_local_user())),
        };
        let mut routes = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            check_deadline(end)?;
            if rule.selector.matches(user.as_ref())
                && rule.capabilities.iter().any(|p| p.is_match(b"hub"))
            {
                routes.push(crate::hub_access::HubCatalogRoute {
                    route: snapshot.rules()[index].s3_route().trim().into(),
                    projects: rule.projects.iter().map(|p| p.trim().to_owned()).collect(),
                });
            }
        }
        Ok(routes)
    }
    /// The caller has already authenticated and observed the current action in
    /// its SQL operation. This private projection does not authenticate a DTO.
    pub(crate) fn admin_catalog_rules(
        &self,
        profile: &crate::SessionProfile,
        principal: &crate::SessionPrincipal,
        end: Instant,
    ) -> Result<Vec<usize>, ResourcePolicyError> {
        let user = Principal {
            issuer: &principal.issuer,
            subject: &profile.subject,
            username: Some(&principal.username),
            organization: Some(&principal.organization),
            teams: &principal.teams,
        };
        let mut indices = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            check_deadline(end)?;
            if rule.selector.matches(Some(&user))
                && rule.capabilities.iter().any(|p| p.is_match(b"hub"))
            {
                indices.push(index);
            }
        }
        check_deadline(end)?;
        Ok(indices)
    }
    /// Reuse the actual literal principal and compiled capability policy for
    /// storage domains, without turning discovery selectors into grants.
    pub(crate) fn storage_rules(
        &self,
        identity: &crate::storage_admission::StorageIdentity<'_>,
        project: Option<&str>,
        end: Instant,
    ) -> Result<Vec<(usize, [bool; 4], bool)>, ResourcePolicyError> {
        use crate::{StorageOperation, storage_admission::StorageIdentity};
        let user = match identity {
            StorageIdentity::Native(p) => Principal::broker(p),
            StorageIdentity::Local(p) => Principal::local(p.current_local_user()),
        };
        let mut matching = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            check_deadline(end)?;
            if !rule.selector.matches(Some(&user))
                || !(rule.projects.is_empty()
                    || rule.projects.iter().any(|p| {
                        let p = p.trim();
                        p == "*" || project.is_some_and(|project| p == project)
                    }))
            {
                continue;
            }
            let masks = StorageOperation::ALL.map(|op| {
                let capability = format!("s3:{}", op.name());
                rule.capabilities
                    .iter()
                    .any(|p| p.is_match(b"s3") || p.is_match(capability.as_bytes()))
            });
            let hub = rule.capabilities.iter().any(|p| p.is_match(b"hub"));
            matching.push((index, masks, hub));
        }
        check_deadline(end)?;
        Ok(matching)
    }
}
pub(crate) fn check_deadline(end: Instant) -> Result<(), ResourcePolicyError> {
    if Instant::now() >= end {
        Err(ResourcePolicyError::Deadline)
    } else {
        Ok(())
    }
}
pub(crate) fn pattern(value: &str, end: Instant) -> Result<Regex, ResourcePolicyError> {
    check_deadline(end)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(ResourcePolicyError::InvalidPolicy);
    }
    let glob = GlobBuilder::new(value)
        .case_insensitive(false)
        .literal_separator(true)
        .backslash_escape(true)
        .allow_unclosed_class(false)
        .empty_alternates(false)
        .build()
        .map_err(|_| ResourcePolicyError::InvalidPolicy)?;
    // The SDK's anchored byte regex preserves identifier bytes on every OS.
    // Candidate is a path API and would normalize Windows backslashes.
    let compiled = Regex::new(glob.regex()).map_err(|_| ResourcePolicyError::InvalidPolicy)?;
    check_deadline(end)?;
    Ok(compiled)
}
impl<'a> ResourcePolicy<'a> {
    pub(crate) fn compile(
        snapshot: &'a ResourceGrantSnapshot,
        end: Instant,
    ) -> Result<Self, ResourcePolicyError> {
        let mut rules = Vec::with_capacity(snapshot.rules().len());
        for rule in snapshot.rules() {
            check_deadline(end)?;
            let selector = match rule.access_kind().trim().to_ascii_lowercase().as_str() {
                "global" => Selector::Global,
                "anonymous" => Selector::Anonymous,
                "authenticated" => Selector::Authenticated,
                "user" => Selector::User(pattern(rule.principal(), end)?),
                "team" => Selector::Team(pattern(rule.principal(), end)?),
                "organization" => Selector::Organization(pattern(rule.principal(), end)?),
                "subject" => Selector::Subject(pattern(rule.principal(), end)?),
                _ => return Err(ResourcePolicyError::InvalidPolicy),
            };
            if rule.capabilities().is_empty()
                || rule
                    .projects()
                    .iter()
                    .any(|p| p != "*" && !canonical_project_id(p))
            {
                return Err(ResourcePolicyError::InvalidPolicy);
            }
            let capabilities = rule
                .capabilities()
                .iter()
                .map(|p| pattern(p, end))
                .collect::<Result<Vec<_>, _>>()?;
            rules.push(CompiledRule {
                selector,
                capabilities,
                projects: rule.projects(),
            });
        }
        check_deadline(end)?;
        Ok(Self { rules })
    }
    pub(crate) fn allows_any_project(
        &self,
        user: &LocalBearerUser,
        capability: &str,
        end: Instant,
    ) -> Result<bool, ResourcePolicyError> {
        self.allows_any_principal(&Principal::local(user), capability, end)
    }
    pub(crate) fn allows_any_broker(
        &self,
        user: &VerifiedBrokerAccess<'_>,
        capability: &str,
        end: Instant,
    ) -> Result<bool, ResourcePolicyError> {
        self.allows_any_principal(&Principal::broker(user), capability, end)
    }
    fn allows_any_principal(
        &self,
        user: &Principal<'_>,
        capability: &str,
        end: Instant,
    ) -> Result<bool, ResourcePolicyError> {
        for rule in &self.rules {
            check_deadline(end)?;
            if rule.selector.matches(user)
                && rule
                    .capabilities
                    .iter()
                    .any(|p| p.is_match(capability.as_bytes()))
                && (rule.projects.is_empty() || rule.projects.iter().any(|p| p == "*"))
            {
                return Ok(true);
            }
        }
        check_deadline(end)?;
        Ok(false)
    }
    pub(crate) fn allows(
        &self,
        user: &LocalBearerUser,
        capability: &str,
        project: &str,
        end: Instant,
    ) -> Result<bool, ResourcePolicyError> {
        self.allows_principal(&Principal::local(user), capability, project, end)
    }
    pub(crate) fn allows_broker(
        &self,
        user: &VerifiedBrokerAccess<'_>,
        capability: &str,
        project: &str,
        end: Instant,
    ) -> Result<bool, ResourcePolicyError> {
        self.allows_principal(&Principal::broker(user), capability, project, end)
    }

    fn allows_principal(
        &self,
        user: &Principal<'_>,
        capability: &str,
        project: &str,
        end: Instant,
    ) -> Result<bool, ResourcePolicyError> {
        for rule in &self.rules {
            check_deadline(end)?;
            if rule.selector.matches(user)
                && rule
                    .capabilities
                    .iter()
                    .any(|p| p.is_match(capability.as_bytes()))
                && (rule.projects.is_empty()
                    || rule.projects.iter().any(|p| p == "*" || p == project))
            {
                return Ok(true);
            }
        }
        check_deadline(end)?;
        Ok(false)
    }
}

pub(crate) fn inference_cache_scope(
    identity: &crate::embedding_admission::EmbeddingIdentity<'_>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"graphit-rerank-principal-v1");
    match Principal::inference(identity) {
        None => hash.update([0]),
        Some(principal) => {
            hash.update([1]);
            for field in [
                principal.issuer,
                principal.subject,
                principal.organization.unwrap_or(""),
            ] {
                hash.update((field.len() as u64).to_le_bytes());
                hash.update(field.as_bytes());
            }
        }
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalIdentityKind, resource_grants::decode_snapshot};
    fn end() -> Instant {
        Instant::now() + std::time::Duration::from_secs(30)
    }
    fn user() -> LocalBearerUser {
        LocalBearerUser {
            username: "alice".into(),
            subject: "alice-subject".into(),
            kind: LocalIdentityKind::Human,
            name: "".into(),
            email: "".into(),
            organization: "org/team".into(),
            teams: vec!["a,b".into(), "dev".into()],
            revision: 1,
        }
    }
    fn rule(
        id: &str,
        access: &str,
        principal: &str,
        caps: &[&str],
        projects: &[&str],
    ) -> serde_json::Value {
        serde_json::json!({"id":id,"name":"synthetic","access_kind":access,"principal":principal,"s3_route":"","capabilities":caps,"projects":projects,"s3_operations":[],"s3_prefixes":[],"created_at":0,"updated_at":0})
    }
    fn snapshot(rules: Vec<serde_json::Value>) -> ResourceGrantSnapshot {
        decode_snapshot(1, 0, &serde_json::to_string(&rules).unwrap()).unwrap()
    }
    #[test]
    fn empty_inventory_requires_explicit_any_project_publish_on_the_same_rule() {
        let project = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        for projects in [&[][..], &["*"][..]] {
            let s = snapshot(vec![rule(
                "a",
                "user",
                "alice",
                &["presence:publish"],
                projects,
            )]);
            assert!(
                ResourcePolicy::compile(&s, end())
                    .unwrap()
                    .allows_any_project(&user(), "presence:publish", end())
                    .unwrap()
            );
        }
        for rules in [
            vec![rule(
                "a",
                "user",
                "alice",
                &["presence:publish"],
                &[project],
            )],
            vec![
                rule("a", "user", "alice", &["presence:read"], &[]),
                rule("b", "user", "alice", &["presence:publish"], &[project]),
            ],
            vec![rule("a", "user", "bob", &["presence:publish"], &[])],
            vec![rule("a", "user", "alice", &["hub:admin"], &[])],
            vec![rule("a", "anonymous", "", &["presence:publish"], &[])],
        ] {
            let s = snapshot(rules);
            assert!(
                !ResourcePolicy::compile(&s, end())
                    .unwrap()
                    .allows_any_project(&user(), "presence:publish", end())
                    .unwrap()
            );
        }
        let s = snapshot(vec![
            rule("a", "user", "alice", &["presence:publish"], &[]),
            rule("b", "team", "[", &["presence:read"], &[project]),
        ]);
        assert!(matches!(
            ResourcePolicy::compile(&s, end()),
            Err(ResourcePolicyError::InvalidPolicy)
        ));
    }
    #[test]
    fn same_rule_explicit_capability_and_project_never_combine_cross_grants() {
        let a = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let b = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
        let s = snapshot(vec![
            rule("a", "user", "alice", &["presence:read"], &[a]),
            rule("b", "user", "alice", &["presence:publish"], &[b]),
        ]);
        let p = ResourcePolicy::compile(&s, end()).unwrap();
        assert!(p.allows(&user(), "presence:read", a, end()).unwrap());
        assert!(!p.allows(&user(), "presence:publish", a, end()).unwrap());
        assert!(!p.allows(&user(), "presence:read", b, end()).unwrap());
        for projects in [vec![], vec!["*"]] {
            let s = snapshot(vec![rule(
                "a",
                "authenticated",
                "",
                &["presence:*"],
                &projects,
            )]);
            let p = ResourcePolicy::compile(&s, end()).unwrap();
            assert!(p.allows(&user(), "presence:publish", b, end()).unwrap());
        }
        let s = snapshot(vec![rule("a", "global", "", &["hub"], &[])]);
        assert!(
            !ResourcePolicy::compile(&s, end())
                .unwrap()
                .allows(&user(), "presence:read", a, end())
                .unwrap()
        );
        let s = snapshot(vec![]);
        assert!(
            !ResourcePolicy::compile(&s, end())
                .unwrap()
                .allows(&user(), "presence:read", a, end())
                .unwrap()
        );
    }
    #[test]
    fn current_principal_selectors_are_case_exact_native_patterns() {
        let a = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        for (access, principal, expected) in [
            ("global", "", true),
            ("anonymous", "", false),
            (" authenticated ", "", true),
            (" USER ", " ali?e ", true),
            ("user", "Alice", false),
            ("team", "d[ae]v", true),
            ("team", "a,b", true),
            ("organization", "org/*", true),
            ("organization", "org*", false),
            ("subject", "alice-subject", true),
            ("subject", "local|alice-*", true),
            ("subject", "other|alice-*", false),
        ] {
            let s = snapshot(vec![rule("a", access, principal, &["presence:read"], &[a])]);
            assert_eq!(
                ResourcePolicy::compile(&s, end())
                    .unwrap()
                    .allows(&user(), "presence:read", a, end())
                    .unwrap(),
                expected,
                "{access}/{principal}"
            );
        }
    }
    #[test]
    fn native_glob_regex_preserves_literal_bytes_and_documents_recursion() {
        for (pat, value, expected) in [
            ("*", "a/b", false),
            ("?", "é", false),
            ("??", "é", true),
            ("é", "é", true),
            ("a?", "ab", true),
            ("a[0-9]", "a7", true),
            ("[!a]", "b", true),
            ("[^a]", "b", true),
            (r"a\*", "a*", true),
            (r"a\?", "a?", true),
            (r"a\\b", r"a\b", true),
            (r"a\\b", "a/b", false),
            ("{a,b}", "a", true),
            ("{a,{b,c}}", "a", true),
            ("{a,{b,c}}", "b", true),
            ("{a,{b,c}}", "c", true),
            ("**", "a/b", true),
            ("a/**/b", "a/b", true),
            ("a/**/b", "a/x/y/b", true),
            ("a/**", "a", false),
            ("[ab]", "z", false),
            ("a,b", "a", false),
            ("abc", "ABC", false),
        ] {
            assert_eq!(
                pattern(pat, end()).unwrap().is_match(value.as_bytes()),
                expected,
                "{pat}/{value}"
            );
        }
        for pat in ["", " ", "[", "[z-a]", "{a,b", r"a\"] {
            assert!(pattern(pat, end()).is_err(), "{pat}");
        }
    }
    #[test]
    fn whole_policy_validation_precedes_any_allow_and_errors_are_finite() {
        let good = rule("a", "global", "", &["presence:*"], &[]);
        for bad in [
            rule("b", "admin", "", &["presence:read"], &[]),
            rule("b", "user", "", &["presence:read"], &[]),
            rule("b", "user", "[", &["presence:read"], &[]),
            rule("b", "user", "alice", &[], &[]),
            rule("b", "user", "alice", &[" "], &[]),
            rule("b", "user", "alice", &["["], &[]),
            rule("b", "user", "alice", &["presence:read"], &["global"]),
            rule(
                "b",
                "user",
                "alice",
                &["presence:read"],
                &["00000000000000000000000000"],
            ),
            rule(
                "b",
                "user",
                "alice",
                &["presence:read"],
                &["01arz3ndektsv4rrffq69g5fav"],
            ),
        ] {
            let s = snapshot(vec![good.clone(), bad]);
            assert!(matches!(
                ResourcePolicy::compile(&s, end()),
                Err(ResourcePolicyError::InvalidPolicy)
            ));
        }
        let s = snapshot(vec![good]);
        assert!(matches!(
            ResourcePolicy::compile(&s, Instant::now()),
            Err(ResourcePolicyError::Deadline)
        ));
    }
    fn broker_fixture() -> (
        crate::BrokerAccessVerifier,
        serde_json::Value,
        jsonwebtoken::EncodingKey,
    ) {
        use base64::Engine;
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let key = jsonwebtoken::EncodingKey::from_ed_der(&pair.serialize_der());
        let jwks = serde_json::from_value(serde_json::json!({"keys":[{
            "kty":"OKP","crv":"Ed25519","kid":"policy-key",
            "x":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key_raw())
        }]}))
        .unwrap();
        let verifier = crate::BrokerAccessVerifier::new(
            "https://issuer.test",
            "api",
            Some("https://issuer.test/v1"),
            &jwks,
            std::num::NonZeroUsize::new(8192).unwrap(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({"iss":"https://issuer.test","sub":"broker-sub","aud":["api","https://issuer.test/v1"],
            "iat":now-1,"exp":now+600,"token_use":"access","client_id":"client","jti":"policy-token",
            "scope":"task:read","preferred_username":"alice","groups":["dev"],"organization":"org",
            "roles":["admin"]});
        (verifier, claims, key)
    }
    fn signed(claims: &serde_json::Value, key: &jsonwebtoken::EncodingKey) -> String {
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        h.kid = Some("policy-key".into());
        jsonwebtoken::encode(&h, claims, key).unwrap()
    }
    #[test]
    fn broker_signed_attributes_and_canonical_subject_are_policy_inputs() {
        let (verifier, claims, key) = broker_fixture();
        let proof = verifier.verify(&signed(&claims, &key), &[], end()).unwrap();
        let project = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        for (kind, principal, allowed) in [
            ("subject", "broker-sub", true),
            ("subject", "https://issuer.test|broker-*", true),
            ("subject", "upstream|original-sub", false),
            ("user", "alice", true),
            ("user", "Alice", false),
            ("team", "de?", true),
            ("organization", "org", true),
            ("anonymous", "", false),
            ("authenticated", "", true),
            ("global", "", true),
        ] {
            let s = snapshot(vec![rule("a", kind, principal, &["task:read"], &[project])]);
            assert_eq!(
                ResourcePolicy::compile(&s, end())
                    .unwrap()
                    .allows_broker(&proof, "task:read", project, end())
                    .unwrap(),
                allowed
            );
        }
    }
    #[test]
    fn broker_absent_profile_does_not_match_wildcards_or_roles_scopes() {
        let (verifier, mut claims, key) = broker_fixture();
        for field in ["preferred_username", "organization", "groups"] {
            claims.as_object_mut().unwrap().remove(field);
        }
        let project = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let proof = verifier.verify(&signed(&claims, &key), &[], end()).unwrap();
        for kind in ["user", "organization", "team"] {
            let s = snapshot(vec![rule("a", kind, "*", &["task:read"], &[project])]);
            assert!(
                !ResourcePolicy::compile(&s, end())
                    .unwrap()
                    .allows_broker(&proof, "task:read", project, end())
                    .unwrap()
            );
        }
        let s = snapshot(vec![]);
        assert!(
            !ResourcePolicy::compile(&s, end())
                .unwrap()
                .allows_broker(&proof, "task:read", project, end())
                .unwrap()
        );
        let s = snapshot(vec![rule(
            "a",
            "authenticated",
            "",
            &["hub", "presence:*", "s3:read"],
            &[project],
        )]);
        assert!(
            !ResourcePolicy::compile(&s, end())
                .unwrap()
                .allows_broker(&proof, "task:read", project, end())
                .unwrap()
        );
        claims["organization"] = serde_json::json!("");
        let proof = verifier.verify(&signed(&claims, &key), &[], end()).unwrap();
        let s = snapshot(vec![rule(
            "a",
            "organization",
            "*",
            &["task:read"],
            &[project],
        )]);
        assert!(
            ResourcePolicy::compile(&s, end())
                .unwrap()
                .allows_broker(&proof, "task:read", project, end())
                .unwrap()
        );
    }
    #[test]
    fn broker_requires_whole_valid_policy_and_one_rule_for_the_exact_pair() {
        use crate::{ProjectResourceAction as Action, ProjectResourceModule as Module};
        let (verifier, claims, key) = broker_fixture();
        let proof = verifier.verify(&signed(&claims, &key), &[], end()).unwrap();
        let a = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let b = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
        for module in [Module::Task, Module::Memory, Module::Knowledge, Module::Ast] {
            for action in [Action::Read, Action::Write] {
                let cap = module.capability(action).unwrap();
                let s = snapshot(vec![rule("a", "subject", "broker-sub", &[cap], &[a])]);
                let policy = ResourcePolicy::compile(&s, end()).unwrap();
                assert!(policy.allows_broker(&proof, cap, a, end()).unwrap());
                let opposite = if action == Action::Read {
                    Action::Write
                } else {
                    Action::Read
                };
                assert!(
                    !policy
                        .allows_broker(&proof, module.capability(opposite).unwrap(), a, end())
                        .unwrap()
                );
                assert!(!policy.allows_broker(&proof, cap, b, end()).unwrap());
                for projects in [&[][..], &["*"][..]] {
                    let s = snapshot(vec![rule("a", "authenticated", "", &[cap], projects)]);
                    assert!(
                        ResourcePolicy::compile(&s, end())
                            .unwrap()
                            .allows_broker(&proof, cap, b, end())
                            .unwrap()
                    );
                }
            }
        }
        let s = snapshot(vec![
            rule("a", "subject", "broker-sub", &["task:read"], &[b]),
            rule("b", "subject", "other", &["task:read"], &[a]),
            rule("c", "subject", "broker-sub", &["memory:read"], &[a]),
        ]);
        assert!(
            !ResourcePolicy::compile(&s, end())
                .unwrap()
                .allows_broker(&proof, "task:read", a, end())
                .unwrap()
        );
        let s = snapshot(vec![
            rule("a", "subject", "broker-sub", &["task:read"], &[a]),
            rule("z", "team", "[", &["memory:read"], &[b]),
        ]);
        assert!(matches!(
            ResourcePolicy::compile(&s, end()),
            Err(ResourcePolicyError::InvalidPolicy)
        ));
    }
}
