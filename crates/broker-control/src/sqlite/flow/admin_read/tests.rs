use super::*;
use crate::{FlowLimits, IdentityReadLimits, SqliteControlConfig};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use rusqlite::{Connection, params};
use std::time::Duration;
use zeroize::Zeroizing;

fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

#[tokio::test]
async fn verified_factor_expiry_bounds_a_later_physical_admin_read_lock() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private/db");
    let digester = CredentialDigester::new(
        Zeroizing::new(vec![53; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap();
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).unwrap();
    let raw = Zeroizing::new(format!("gb_at_{}", URL_SAFE_NO_PAD.encode(secret)));
    let hash = digester
        .token(TokenKind::LocalAccess, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    let end = || Instant::now() + Duration::from_secs(5);
    let store = SqliteControlStore::open(
        SqliteControlConfig::new(
            path.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: n(128),
                request_bytes: n(256),
                continuation_bytes: n(1024),
            },
        )
        .unwrap(),
        digester,
        end(),
    )
    .await
    .unwrap();
    let db = Connection::open(path).unwrap();
    db.execute_batch("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at)VALUES('alice','alice-subject','human','','','','','[]',1,1,1,0,0);DELETE FROM role_permissions WHERE role='user';INSERT INTO role_permissions(role,action)VALUES('user','roles.read');").unwrap();
    let principal=serde_json::json!({"issuer":"local","subject":"alice-subject","username":"alice","auth_method":"local-token","roles":[],"teams":[],"local_user_revision":1}).to_string();
    db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at)VALUES(?1,'admin-read-expiry','access','alice-subject','pseudo',?2,'client','aud','','[]',1,'',0,?3,0)",params![hash,principal,crate::flow::now_micros().unwrap()+300_000]).unwrap();
    let proof = store
        .local_bearer_verifier("aud", n(8192))
        .unwrap()
        .verify(&raw, &[], end())
        .await
        .unwrap();
    let expected = proof.authentication_expiry().1;
    // The genuine factor exists before the second physical owner acquires its
    // write lock. No row is mutated during the expiry observation window.
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let limits = AdminReadLimits {
        authorization: crate::AdminBrokerSessionLimits {
            identity: IdentityReadLimits {
                username_bytes: n(128),
                subject_bytes: n(512),
                role_bytes: n(128),
                roles: n(16),
                rows: n(128),
            },
            profile_json_bytes: n(8192),
        },
        grants_json_bytes: n(8192),
        response_json_bytes: n(8192),
    };
    let result = store
        .local_admin_reads(limits)
        .unwrap()
        .read_current(proof, OwnedRequest::Roles, end())
        .await;
    assert_eq!(
        result.unwrap_err(),
        Error::Authorization(AdminBrokerSessionError::Authentication(
            BrokerAccessError::Expired
        ))
    );
    assert!(Instant::now() >= expected);
    assert!(Instant::now().duration_since(expected) < Duration::from_secs(2));
    db.execute_batch("ROLLBACK").unwrap();
    store.shutdown(end()).await.unwrap();
}
