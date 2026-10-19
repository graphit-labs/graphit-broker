//! Bounded administrative document codecs. These values carry no authorization.
use crate::{
    AdminReadError as Error, AdminReadKind, ControlError, SessionPrincipal, SessionProfile,
    identity::{safe_identity_segment, valid_identity_subject},
    resource_policy::HubResourcePolicy,
};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    time::Instant,
};

pub(crate) struct Payload {
    pub(crate) body: Vec<u8>,
    pub(crate) revision: Option<i64>,
}
pub(crate) fn check(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok(())
}
struct CappedJson {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for CappedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode(
    value: &impl Serialize,
    maximum: usize,
    kind: AdminReadKind,
) -> Result<Vec<u8>, Error> {
    let mut out = CappedJson {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut out, value).map_err(|_| Error::Projection(kind))?;
    Ok(out.bytes)
}
pub(crate) fn timestamp(value: i64, kind: AdminReadKind) -> Result<String, Error> {
    DateTime::<Utc>::from_timestamp_micros(value)
        .filter(|v| value >= 0 && v.year() <= 9999)
        .map(|v| v.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .ok_or(Error::Projection(kind))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Role {
    name: String,
    permissions: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    subject: String,
    role: String,
    created_at: i64,
}
#[derive(Serialize)]
struct AssignmentWire {
    subject: String,
    role: String,
    created_at: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUser {
    username: String,
    subject: String,
    kind: String,
    name: String,
    email: String,
    organization: String,
    teams: Vec<String>,
    roles: Vec<String>,
    enabled: i64,
    password_change_required: i64,
    mfa_enabled: bool,
    revision: i64,
    created_at: i64,
    updated_at: i64,
}
#[derive(Serialize)]
struct UserWire {
    username: String,
    subject: String,
    kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    email: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    organization: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    teams: Vec<String>,
    roles: Vec<String>,
    enabled: bool,
    password_change_required: bool,
    mfa_enabled: bool,
    revision: i64,
    created_at: String,
    updated_at: String,
}
#[derive(Serialize)]
struct Hint {
    #[serde(rename = "type")]
    kind: &'static str,
    id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    organization: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    teams: Vec<String>,
}
fn ordered(values: &[String]) -> bool {
    values.windows(2).all(|v| v[0] < v[1])
}
fn users(json: &str, kind: AdminReadKind, end: Instant) -> Result<Vec<UserWire>, Error> {
    let rows: Vec<StoredUser> = serde_json::from_str(json).map_err(|_| Error::Projection(kind))?;
    if rows.windows(2).any(|p| p[0].username >= p[1].username) {
        return Err(Error::Projection(kind));
    }
    rows.into_iter()
        .map(|u| {
            check(end)?;
            if !safe_identity_segment(&u.username, 128)
                || !valid_identity_subject(&u.subject, 512)
                || !matches!(u.kind.as_str(), "human" | "service")
                || !matches!(u.enabled, 0 | 1)
                || !matches!(u.password_change_required, 0 | 1)
                || u.revision < 1
                || [&u.name, &u.email, &u.organization]
                    .iter()
                    .any(|s| s.chars().count() > 512)
                || !ordered(&u.roles)
                || !u.roles.iter().any(|r| r == "user")
                || u.roles.iter().any(|r| !safe_identity_segment(r, 128))
                || !ordered(&u.teams)
                || u.teams.iter().any(|t| t.is_empty() || t.trim() != t)
            {
                return Err(Error::Projection(kind));
            }
            Ok(UserWire {
                username: u.username,
                subject: u.subject,
                kind: u.kind,
                name: u.name,
                email: u.email,
                organization: u.organization,
                teams: u.teams,
                roles: u.roles,
                enabled: u.enabled == 1,
                password_change_required: u.password_change_required == 1,
                mfa_enabled: u.mfa_enabled,
                revision: u.revision,
                created_at: timestamp(u.created_at, kind)?,
                updated_at: timestamp(u.updated_at, kind)?,
            })
        })
        .collect()
}
#[derive(Serialize)]
struct GrantWire<'a> {
    id: &'a str,
    name: &'a str,
    access: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    principal: &'a str,
    capabilities: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    projects: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    s3_operations: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    s3_prefixes: &'a [String],
    #[serde(skip_serializing_if = "str::is_empty")]
    s3_route: &'a str,
}
pub(crate) fn grants_payload(
    snapshot: &crate::ResourceGrantSnapshot,
    bytes: usize,
    end: Instant,
) -> Result<Payload, Error> {
    let kind = AdminReadKind::Grants;
    check(end)?;
    let rules: Vec<_> = snapshot
        .rules()
        .iter()
        .map(|r| GrantWire {
            id: r.id(),
            name: r.name(),
            access: r.access_kind(),
            principal: r.principal(),
            capabilities: r.capabilities(),
            projects: r.projects(),
            s3_operations: r.s3_operations(),
            s3_prefixes: r.s3_prefixes(),
            s3_route: r.s3_route(),
        })
        .collect();
    let value = serde_json::json!({"v":1,"revision":snapshot.revision(),"updated_at":timestamp(snapshot.updated_at().as_i64(),kind)?,"rules":rules});
    let body = encode(&value, bytes, kind)?;
    check(end)?;
    Ok(Payload {
        body,
        revision: Some(snapshot.revision()),
    })
}
fn payload(
    value: serde_json::Value,
    bytes: usize,
    kind: AdminReadKind,
    end: Instant,
) -> Result<Payload, Error> {
    check(end)?;
    let body = encode(&value, bytes, kind)?;
    check(end)?;
    Ok(Payload {
        body,
        revision: None,
    })
}

pub(crate) fn projects_payload(
    snapshot: &crate::ResourceGrantSnapshot,
    provider_command: &str,
    profile: &SessionProfile,
    principal: &SessionPrincipal,
    bytes: usize,
    end: Instant,
) -> Result<Payload, Error> {
    let kind = AdminReadKind::Projects;
    check(end)?;
    let value = {
        let policy =
            HubResourcePolicy::compile(snapshot, end).map_err(|_| Error::Projection(kind))?;
        let indices = policy
            .admin_catalog_rules(profile, principal, end)
            .map_err(|_| Error::Projection(kind))?;
        let mut all = false;
        for index in &indices {
            check(end)?;
            let projects = snapshot.rules()[*index].projects();
            all |= projects.is_empty();
            for project in projects {
                check(end)?;
                all |= project.trim() == "*";
            }
        }
        let mut budget = JsonBudget {
            used: 0,
            limit: bytes,
        };
        budget.add(&serde_json::json!({"projects":[],"all_projects":all,"authorization_revision":snapshot.revision(),"provider_command":provider_command}), kind)?;
        // Borrow the bounded snapshot and charge each distinct output
        // item BEFORE allocating its map/set node. A compact rule can
        // otherwise expand projects × capabilities before encoding.
        let mut projects = BTreeMap::<&str, BTreeSet<&str>>::new();
        for index in indices {
            check(end)?;
            let rule = &snapshot.rules()[index];
            for project in rule.projects() {
                check(end)?;
                let project = project.trim();
                if project != "*" {
                    let separator = usize::from(!projects.is_empty());
                    let capabilities = match projects.entry(project) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            budget.bytes(separator, kind)?;
                            budget
                                .add(&serde_json::json!({"id":project,"capabilities":[]}), kind)?;
                            entry.insert(BTreeSet::new())
                        }
                        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    };
                    for capability in rule.capabilities() {
                        check(end)?;
                        if !capabilities.contains(capability.as_str()) {
                            budget.bytes(usize::from(!capabilities.is_empty()), kind)?;
                            budget.add(capability, kind)?;
                            capabilities.insert(capability);
                        }
                    }
                }
            }
        }
        let projects: Vec<_> = projects
            .into_iter()
            .map(|(id, capabilities)| serde_json::json!({"id":id,"capabilities":capabilities}))
            .collect();
        serde_json::json!({"projects":projects,"all_projects":all,"authorization_revision":snapshot.revision(),"provider_command":provider_command})
    };
    payload(value, bytes, kind, end)
}
pub(crate) fn rows_payload(
    json: &str,
    kind: AdminReadKind,
    bytes: usize,
    end: Instant,
) -> Result<Payload, Error> {
    check(end)?;
    let value = match kind {
        AdminReadKind::Roles => {
            let rows: Vec<Role> =
                serde_json::from_str(json).map_err(|_| Error::Projection(kind))?;
            if rows.windows(2).any(|r| r[0].name >= r[1].name)
                || rows.iter().any(|r| {
                    !safe_identity_segment(&r.name, 128)
                        || !ordered(&r.permissions)
                        || r.permissions
                            .iter()
                            .any(|p| crate::SystemPermission::stored(p).is_none())
                })
            {
                return Err(Error::Projection(kind));
            }
            serde_json::json!({"roles":rows,"actions":broker_store::seeds::ADMIN_ACTIONS.iter().map(|a|a.as_str()).collect::<Vec<_>>()})
        }
        AdminReadKind::Assignments => {
            let rows: Vec<Assignment> =
                serde_json::from_str(json).map_err(|_| Error::Projection(kind))?;
            if rows
                .windows(2)
                .any(|r| (&r[0].subject, &r[0].role) >= (&r[1].subject, &r[1].role))
            {
                return Err(Error::Projection(kind));
            }
            let rows: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    check(end)?;
                    if r.subject.is_empty()
                        || r.subject.chars().count() > 512
                        || !safe_identity_segment(&r.role, 128)
                    {
                        return Err(Error::Projection(kind));
                    }
                    Ok(AssignmentWire {
                        subject: r.subject,
                        role: r.role,
                        created_at: timestamp(r.created_at, kind)?,
                    })
                })
                .collect::<Result<_, Error>>()?;
            serde_json::json!({"bootstrap_only":rows.is_empty(),"assignments":rows})
        }
        AdminReadKind::Users | AdminReadKind::Principals => {
            let rows = users(json, kind, end)?;
            if matches!(kind, AdminReadKind::Users) {
                serde_json::json!({"users":rows})
            } else {
                let mut hints = vec![
                    Hint {
                        kind: "anonymous",
                        id: "anonymous".into(),
                        username: String::new(),
                        organization: String::new(),
                        teams: Vec::new(),
                    },
                    Hint {
                        kind: "authenticated",
                        id: "authenticated".into(),
                        username: String::new(),
                        organization: String::new(),
                        teams: Vec::new(),
                    },
                ];
                hints.extend(rows.into_iter().map(|u| Hint {
                    kind: "local",
                    id: u.subject,
                    username: u.username,
                    organization: u.organization,
                    teams: u.teams,
                }));
                serde_json::json!({"principals":hints})
            }
        }
        _ => return Err(Error::Projection(kind)),
    };
    payload(value, bytes, kind, end)
}
pub(crate) fn configuration_payload(
    yaml: &str,
    bytes: usize,
    end: Instant,
) -> Result<Payload, Error> {
    let kind = AdminReadKind::Configuration;
    check(end)?;
    payload(
        serde_json::json!({"source":"deployment","restart_required":true,"yaml":yaml}),
        bytes,
        kind,
        end,
    )
}
struct JsonBudget {
    used: usize,
    limit: usize,
}
impl JsonBudget {
    fn bytes(&mut self, bytes: usize, kind: AdminReadKind) -> Result<(), Error> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|n| *n <= self.limit)
            .ok_or(Error::Projection(kind))?;
        Ok(())
    }
    fn add<T: Serialize + ?Sized>(&mut self, value: &T, kind: AdminReadKind) -> Result<(), Error> {
        struct Count<'a>(&'a mut JsonBudget);
        impl Write for Count<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let used = self
                    .0
                    .used
                    .checked_add(bytes.len())
                    .filter(|n| *n <= self.0.limit)
                    .ok_or_else(|| std::io::Error::other("administrative response bound"))?;
                self.0.used = used;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Count(self), value).map_err(|_| Error::Projection(kind))
    }
}
