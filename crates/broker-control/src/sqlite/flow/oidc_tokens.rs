use crate::{
    ControlError, OidcTokenExchangeError as Error, service::oidc_tokens::TokenData,
    sqlite::executor::Work,
};
use rusqlite::{Transaction, params};

pub(super) fn insert(
    tx: &Transaction<'_>,
    work: &Work,
    d: &TokenData<'_>,
    hash: &str,
    id: &str,
    kind: &str,
    expiry: i64,
) -> Result<(), Error> {
    let count = tx.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",params![hash,id,kind,d.principal.subject(),d.oidc_subject,d.principal_json,d.client_id,d.audience,d.resource.unwrap_or(""),d.scopes_json,d.principal.revision(),d.family,d.auth_time,expiry,d.created_at]).map_err(|e| ControlError::from(work.sql(e)))?;
    if count != 1 {
        return Err(ControlError::Storage.into());
    }
    Ok(())
}
