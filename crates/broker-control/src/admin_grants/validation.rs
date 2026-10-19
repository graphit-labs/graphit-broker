//! Shared grant normalization and policy validation; no SQL or authority construction.
use crate::{AdminGrantError as Error, AdminGrantRoutes, ControlError, ResourceGrantSnapshot};
use std::time::Instant;

pub(crate) fn check(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok(())
}

fn text(value: &str, max: usize, required: bool) -> Result<(), Error> {
    if (required && value.is_empty())
        || value.chars().count() > max
        || value.chars().any(char::is_control)
    {
        return Err(Error::InvalidGrant);
    }
    Ok(())
}
fn set(values: &[String], max: usize) -> Result<Vec<String>, Error> {
    let mut values = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            text(value, max, true)?;
            Ok(value.to_owned())
        })
        .collect::<Result<Vec<_>, Error>>()?;
    values.sort_unstable();
    values.dedup();
    Ok(values)
}
pub(crate) fn normalized(
    input: &crate::AdminGrantInput,
    id: &str,
) -> Result<crate::AdminGrantInput, Error> {
    let grant = crate::AdminGrantInput {
        id: id.trim().to_owned(),
        name: input.name.trim().to_owned(),
        access: input.access.trim().to_ascii_lowercase(),
        principal: input.principal.trim().to_owned(),
        capabilities: set(&input.capabilities, 128)?,
        projects: set(&input.projects, 256)?,
        s3_operations: set(&input.s3_operations, 32)?,
        s3_prefixes: set(&input.s3_prefixes, 512)?,
        s3_route: input.s3_route.trim().to_owned(),
    };
    if !crate::identity::safe_identity_segment(&grant.id, 128) || grant.capabilities.is_empty() {
        return Err(Error::InvalidGrant);
    }
    text(&grant.name, 256, true)?;
    text(&grant.principal, 512, false)?;
    text(&grant.s3_route, 128, false)?;
    match grant.access.as_str() {
        "global" | "anonymous" | "authenticated" if grant.principal.is_empty() => {}
        "user" | "team" | "organization" | "subject" if !grant.principal.is_empty() => {}
        _ => return Err(Error::InvalidGrant),
    }
    Ok(grant)
}

pub(crate) fn validate_snapshot(
    snapshot: &ResourceGrantSnapshot,
    routes: &AdminGrantRoutes,
    end: Instant,
) -> Result<(), Error> {
    crate::resource_policy::ResourcePolicy::compile(snapshot, end)
        .map_err(|_| Error::InvalidGrant)?;
    crate::storage_policy::StoragePolicy::compile(snapshot, end)
        .map_err(|_| Error::InvalidGrant)?;
    for rule in snapshot.rules() {
        check(end)?;
        if !crate::identity::safe_identity_segment(rule.id(), 128) || rule.capabilities().is_empty()
        {
            return Err(Error::InvalidGrant);
        }
        text(rule.name(), 256, true)?;
        text(rule.principal(), 512, false)?;
        match rule.access_kind() {
            "global" | "anonymous" | "authenticated" if rule.principal().is_empty() => {}
            "user" | "team" | "organization" | "subject" if !rule.principal().is_empty() => {}
            _ => return Err(Error::InvalidGrant),
        }
        if !rule.s3_route().is_empty() && !routes.names.contains(rule.s3_route()) {
            return Err(Error::InvalidGrant);
        }
        for capability in rule.capabilities() {
            let pattern = crate::resource_policy::pattern(capability, end)
                .map_err(|_| Error::InvalidGrant)?;
            let s3 = pattern.is_match(b"s3")
                || crate::StorageOperation::ALL
                    .iter()
                    .any(|op| pattern.is_match(format!("s3:{}", op.name()).as_bytes()));
            if s3 && rule.s3_route().is_empty() && !routes.names.contains(&routes.default) {
                return Err(Error::InvalidGrant);
            }
        }
    }
    check(end)?;
    Ok(())
}
