use crate::{
    AdminUserInput, AdminUsersError as Error,
    identity::{safe_identity_segment, valid_identity_subject},
};
use broker_security::LOCAL_PASSWORD_MAX_BYTES;
use std::collections::BTreeSet;

pub(crate) struct UserValues<'a> {
    pub(crate) username: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) name: &'a str,
    pub(crate) email: &'a str,
    pub(crate) organization: &'a str,
    pub(crate) teams: BTreeSet<&'a str>,
    pub(crate) roles: BTreeSet<&'a str>,
    pub(crate) enabled: bool,
}
pub(crate) fn values<'a>(
    input: &'a AdminUserInput,
    kind: &'a str,
    creating: bool,
    error: Error,
) -> Result<UserValues<'a>, Error> {
    let username = input.username.trim();
    let subject = input.subject.trim();
    let roles = input
        .roles
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "user")
        .collect::<BTreeSet<_>>();
    if !safe_identity_segment(username, 128)
        || !valid_identity_subject(subject, 512)
        || subject.chars().any(char::is_control)
        || !matches!(kind, "human" | "service")
        || roles.iter().any(|s| !safe_identity_segment(s, 128))
        || [&input.name, &input.email, &input.organization]
            .iter()
            .any(|s| s.trim().chars().count() > 512 || s.contains('\0'))
    {
        return Err(error);
    }
    if kind == "service" && !input.password.is_empty()
        || kind == "human"
            && (creating || !input.password.is_empty())
            && !valid_new_password(&input.password)
    {
        return Err(error);
    }
    Ok(UserValues {
        username,
        subject,
        kind,
        name: input.name.trim(),
        email: input.email.trim(),
        organization: input.organization.trim(),
        teams: input
            .teams
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect(),
        roles,
        enabled: input.enabled.unwrap_or(true),
    })
}

pub(crate) fn valid_new_password(password: &str) -> bool {
    password.len() <= LOCAL_PASSWORD_MAX_BYTES && password.chars().count() >= 15
}

pub(crate) fn valid_credential_id(value: &str) -> bool {
    safe_identity_segment(value, 128)
        || (value.len() == 16
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
}
