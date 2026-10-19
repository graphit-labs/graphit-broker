use crate::{AdminReadError as Error, AdminReadKind, ControlError, sqlite::executor::Work};
use rusqlite::Transaction;

// Dynamic SQLite types become null in the closed shared codecs. The complete
// aggregate is measured inside SQLite before any payload is copied by the driver.
const ROLES: &str = r#"WITH data AS MATERIALIZED (
 SELECT json_group_array(json_object(
  'name',CASE WHEN typeof(r.name)='text' THEN r.name END,
  'permissions',json((SELECT json_group_array(
   CASE WHEN typeof(p.action)='text' THEN p.action END ORDER BY p.action COLLATE BINARY)
   FROM role_permissions p WHERE p.role=r.name))
 ) ORDER BY r.name COLLATE BINARY) payload FROM roles r
) SELECT length(CAST(payload AS BLOB)),
 CASE WHEN length(CAST(payload AS BLOB))<=?1 THEN payload END FROM data"#;

const ASSIGNMENTS: &str = r#"WITH data AS MATERIALIZED (
 SELECT json_group_array(json_object(
  'subject',CASE WHEN typeof(subject)='text' THEN subject END,
  'role',CASE WHEN typeof(role)='text' THEN role END,
  'created_at',CASE WHEN typeof(created_at)='integer' THEN created_at END
 ) ORDER BY subject COLLATE BINARY,role COLLATE BINARY) payload FROM role_assignments
) SELECT length(CAST(payload AS BLOB)),
 CASE WHEN length(CAST(payload AS BLOB))<=?1 THEN payload END FROM data"#;

const USERS: &str = r#"WITH data AS MATERIALIZED (
 SELECT json_group_array(json_object(
  'username',CASE WHEN typeof(u.username)='text' THEN u.username END,
  'subject',CASE WHEN typeof(u.subject)='text' THEN u.subject END,
  'kind',CASE WHEN typeof(u.identity_kind)='text' THEN u.identity_kind END,
  'name',CASE WHEN typeof(u.name)='text' THEN u.name END,
  'email',CASE WHEN typeof(u.email)='text' THEN u.email END,
  'organization',CASE WHEN typeof(u.organization)='text' THEN u.organization END,
  'teams',json(CASE WHEN typeof(u.teams_json)='text' AND json_valid(u.teams_json)
   THEN u.teams_json ELSE 'null' END),
  'enabled',CASE WHEN typeof(u.enabled)='integer' THEN u.enabled END,
  'password_change_required',CASE WHEN typeof(u.password_change_required)='integer'
   THEN u.password_change_required END,
  'mfa_enabled',json(CASE WHEN EXISTS(SELECT 1 FROM local_mfa m WHERE m.subject=u.subject)
   THEN 'true' ELSE 'false' END),
  'revision',CASE WHEN typeof(u.revision)='integer' THEN u.revision END,
  'created_at',CASE WHEN typeof(u.created_at)='integer' THEN u.created_at END,
  'updated_at',CASE WHEN typeof(u.updated_at)='integer' THEN u.updated_at END,
  'roles',json((SELECT json_group_array(
   CASE WHEN typeof(a.role)='text' THEN a.role END ORDER BY a.role COLLATE BINARY)
   FROM (SELECT role FROM role_assignments WHERE subject='local|'||u.subject
    UNION SELECT 'user') a))
 ) ORDER BY u.username COLLATE BINARY) payload FROM local_users u
) SELECT length(CAST(payload AS BLOB)),
 CASE WHEN length(CAST(payload AS BLOB))<=?1 THEN payload END FROM data"#;

pub(super) fn read(
    tx: &Transaction<'_>,
    work: &Work,
    kind: AdminReadKind,
    maximum: usize,
) -> Result<String, Error> {
    work.check().map_err(ControlError::from)?;
    let select = match kind {
        AdminReadKind::Roles => ROLES,
        AdminReadKind::Assignments => ASSIGNMENTS,
        AdminReadKind::Users | AdminReadKind::Principals => USERS,
        _ => return Err(Error::Projection(kind)),
    };
    let mut statement = tx
        .prepare(select)
        .map_err(|e| super::projection_error(kind, work.sql(e).into()))?;
    let result = statement
        .query_row([maximum as i64], |row| {
            Ok((|| {
                let size: i64 = row.get(0).map_err(|_| Error::Projection(kind))?;
                if size < 0 || size as u64 > maximum as u64 {
                    return Err(Error::Projection(kind));
                }
                let json = row
                    .get_ref(1)
                    .map_err(|_| Error::Projection(kind))?
                    .as_str()
                    .map_err(|_| Error::Projection(kind))?;
                Ok(json.to_owned())
            })())
        })
        .map_err(|e| super::projection_error(kind, work.sql(e).into()))?;
    work.check().map_err(ControlError::from)?;
    result
}
