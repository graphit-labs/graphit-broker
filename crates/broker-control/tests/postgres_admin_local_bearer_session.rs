#[allow(
    dead_code,
    reason = "shared real TLS PostgreSQL fixture serves other suites"
)]
mod support;
use broker_control::{
    AdminBrokerSessionError as Error, AdminBrokerSessionLimits, AdminLocalBearerSession,
    BrokerAccessError, ConnectionLimits, ControlError, IdentityReadLimits, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_security::TokenKind;
use serde_json::json;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, digester, n};
use zeroize::Zeroizing;
const ACCESS: &str = "gb_at_admin-fixture-access";
const SERVICE: &str = "gb_sc_admin-fixture-service";
const AUDIENCE: &str = "explicit-admin-api";
fn micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap()
}
fn limits() -> AdminBrokerSessionLimits {
    AdminBrokerSessionLimits {
        identity: IdentityReadLimits {
            username_bytes: n(128),
            subject_bytes: n(512),
            role_bytes: n(128),
            roles: n(16),
            rows: n(128),
        },
        profile_json_bytes: n(8192),
    }
}
async fn open(f: &Fixture, port: u16) -> Arc<PostgresControlStore> {
    Arc::new(
        PostgresControlStore::open(
            PostgresConfig::new(
                PostgresEndpoint {
                    host: "127.0.0.1".into(),
                    port: NonZeroU16::new(port).unwrap(),
                    database: "postgres".into(),
                },
                PostgresCredentials::new(
                    "admin_opaque_owner".into(),
                    Zeroizing::new("ephemeral-owner".into()),
                ),
                f.ca.clone(),
                ConnectionLimits {
                    text_bytes: n(256),
                    ca_bytes: n(8192),
                },
                support::pool(2),
                support::limits(),
            )
            .unwrap(),
            digester(),
            deadline(),
        )
        .await
        .unwrap(),
    )
}
async fn read(
    store: &PostgresControlStore,
    raw: &str,
    original: Instant,
) -> Result<AdminLocalBearerSession, Error> {
    store
        .admin_local_bearer_sessions(AUDIENCE, n(8192), limits())
        .unwrap()
        .read(raw, &["admin:session".into()], original)
        .await
}
async fn seed(c: &mut sqlx_postgres::PgConnection) {
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Current','current@example.invalid','org','[\" z \",\"a\",\"z\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    for (raw, id, kind, domain, subject) in [
        (
            ACCESS,
            "access-test",
            "access",
            TokenKind::LocalAccess,
            "alice-subject",
        ),
        (
            SERVICE,
            "service-test",
            "service",
            TokenKind::ServiceCredential,
            "bot-subject",
        ),
    ] {
        let hash = digester().token(domain, raw.as_bytes()).unwrap();
        let principal = json!({"issuer":"local","subject":subject,"username":"stale","name":"stale","auth_method":"stale","roles":["admin"],"local_user_revision":1});
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'different-pseudonym',$5,'explicit-client',$6,'','[\"admin:session\"]',1,'',0,$7,0)")
            .bind(hash.to_sql_hex()).bind(id).bind(kind).bind(subject).bind(principal.to_string()).bind(AUDIENCE).bind(micros()+60_000_000).execute(&mut *c).await.unwrap();
    }
}
async fn wait_select(c: &mut sqlx_postgres::PgConnection, state: &str) {
    let end = deadline();
    loop {
        let ready: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename='admin_opaque_owner' AND query LIKE '%FROM public.local_users u%' AND (CASE WHEN $1='Lock' THEN wait_event_type='Lock' ELSE state=$1 END))")
            .bind(state).fetch_one(&mut *c).await.unwrap();
        if ready {
            return;
        }
        assert!(
            Instant::now() < end,
            "actual opaque Admin SELECT did not reach the expected state"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
// End-to-end TLS remains between SQLx and PostgreSQL. This owned TCP relay
// withholds server replies when armed for the actual reader transaction.
// The observer releases SELECT/close replies and withholds only actual COMMIT ACK.
struct CommitRelay {
    port: u16,
    armed: Arc<AtomicBool>,
    replies: tokio::sync::mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<bool>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl CommitRelay {
    async fn new(port: u16) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = listener.local_addr().unwrap().port();
        let armed = Arc::new(AtomicBool::new(false));
        let (replies_tx, replies) =
            tokio::sync::mpsc::unbounded_channel::<tokio::sync::oneshot::Sender<bool>>();
        let (stop, mut stopping) = tokio::sync::oneshot::channel();
        let gate = armed.clone();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopping => break,
                    accepted=listener.accept()=>{
                        let (client,_)=accepted.unwrap(); client.set_nodelay(true).unwrap();
                        let gate=gate.clone(); let replies_tx=replies_tx.clone();
                        children.spawn(async move {
                            let peer=tokio::net::TcpStream::connect(("127.0.0.1",port)).await.unwrap(); peer.set_nodelay(true).unwrap();
                            let (mut client_read,mut client_write)=client.into_split();
                            let (mut peer_read,mut peer_write)=peer.into_split();
                            let upstream=async {
                                let mut bytes=[0u8;8192];
                                loop {
                                    let count=client_read.read(&mut bytes).await?;
                                    if count==0 { return Ok::<_,std::io::Error>(()); }
                                    peer_write.write_all(&bytes[..count]).await?;
                                }
                            };
                            let downstream=async {
                                let mut bytes=[0u8;8192];
                                loop {
                                    let count=peer_read.read(&mut bytes).await?;
                                    if count==0{return Ok::<_,std::io::Error>(());}
                                    if gate.load(Ordering::SeqCst) {
                                        let (decision,chosen)=tokio::sync::oneshot::channel();
                                        if replies_tx.send(decision).is_err(){return Ok(());}
                                        if !chosen.await.unwrap_or(false){std::future::pending::<()>().await;}
                                    }
                                    client_write.write_all(&bytes[..count]).await?;
                                }
                            };
                            tokio::select! {_=upstream=>{},_=downstream=>{}}
                        });
                    },
                    _=children.join_next(),if !children.is_empty()=>{},
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Self {
            port: local_port,
            armed,
            replies,
            stop: Some(stop),
            task: Some(task),
        }
    }
    async fn close(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap();
    }
}
impl Drop for CommitRelay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
#[tokio::test]
#[ignore = "actual opaque verifier, current Admin SQL, TLS NOSUPERUSER, expiry and readonly COMMIT uncertainty"]
async fn postgres_admin_local_bearer_session_contract() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE admin_opaque_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION admin_opaque_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO admin_opaque_owner").await.unwrap();
    let mut relay = CommitRelay::new(fixture.port).await;
    let store = open(&fixture, relay.port).await;
    let ordinary: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT NOT rolsuper FROM pg_roles WHERE rolname='admin_opaque_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(ordinary);
    seed(&mut c).await;
    for (raw, username, subject) in [
        (ACCESS, "alice", "alice-subject"),
        (SERVICE, "bot", "bot-subject"),
    ] {
        let session = read(&store, raw, deadline()).await.unwrap();
        assert_eq!(session.profile().subject, subject);
        assert_eq!(session.principal().username, username);
        assert_eq!(session.principal().issuer, "local");
        assert_eq!(session.roles(), ["user"]);
        assert!(
            session
                .permissions()
                .iter()
                .any(|p| p.as_str() == "session.read")
        );
        assert_eq!(
            format!("{session:?}"),
            "AdminLocalBearerSession([REDACTED])"
        );
        session.check().unwrap();
    }
    assert_eq!(
        read(&store, ACCESS, deadline())
            .await
            .unwrap()
            .principal()
            .teams,
        ["a", "z"]
    );
    let denied = Error::Authentication(BrokerAccessError::InvalidToken);
    for invalid in [
        "",
        "gb_rt_no",
        "GB_AT_admin-fixture-access",
        "gb_at_missing",
        "gb_at_admin-fixture-access ",
        "eyJ.fake.jwt",
    ] {
        assert_eq!(read(&store, invalid, deadline()).await.unwrap_err(), denied);
    }
    assert_eq!(
        store
            .admin_local_bearer_sessions("different-api", n(8192), limits())
            .unwrap()
            .read(ACCESS, &[], deadline())
            .await
            .unwrap_err(),
        denied
    );
    assert_eq!(
        store
            .admin_local_bearer_sessions(AUDIENCE, n(8192), limits())
            .unwrap()
            .read(ACCESS, &["different-scope".into()], deadline())
            .await
            .unwrap_err(),
        denied
    );
    for (change, restore) in [
        (
            "UPDATE local_tokens SET revoked_at=0 WHERE token_id='access-test'",
            "UPDATE local_tokens SET revoked_at=NULL WHERE token_id='access-test'",
        ),
        (
            "UPDATE local_tokens SET audience='wrong' WHERE token_id='access-test'",
            "UPDATE local_tokens SET audience='explicit-admin-api' WHERE token_id='access-test'",
        ),
        (
            "UPDATE local_tokens SET scopes_json='[\" admin:session \"]' WHERE token_id='access-test'",
            "UPDATE local_tokens SET scopes_json='[\"admin:session\"]' WHERE token_id='access-test'",
        ),
        (
            "UPDATE local_users SET enabled=0 WHERE username='alice'",
            "UPDATE local_users SET enabled=1 WHERE username='alice'",
        ),
        (
            "UPDATE local_users SET revision=2 WHERE username='alice'",
            "UPDATE local_users SET revision=1 WHERE username='alice'",
        ),
        (
            "UPDATE local_users SET subject='other' WHERE username='alice'",
            "UPDATE local_users SET subject='alice-subject' WHERE username='alice'",
        ),
        (
            "UPDATE local_users SET identity_kind='service' WHERE username='alice'",
            "UPDATE local_users SET identity_kind='human' WHERE username='alice'",
        ),
    ] {
        c.execute(change).await.unwrap();
        assert_eq!(read(&store, ACCESS, deadline()).await.unwrap_err(), denied);
        c.execute(restore).await.unwrap();
    }
    c.execute("DELETE FROM role_permissions WHERE role='user' AND action='session.read'; INSERT INTO role_assignments(subject,role,created_at) VALUES('alice-subject','admin',0)").await.unwrap();
    assert_eq!(
        read(&store, ACCESS, deadline()).await.unwrap_err(),
        Error::Forbidden
    );
    c.execute("INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','admin',0)").await.unwrap();
    assert_eq!(
        read(&store, ACCESS, deadline()).await.unwrap().roles(),
        ["admin", "user"]
    );
    c.execute("DELETE FROM role_assignments; INSERT INTO role_permissions(role,action) VALUES('user','session.read')").await.unwrap();
    // Retain the genuine verifier read-COMMIT ACK after it observed revision 1.
    // A later Admin SELECT must reject that proof once SQL binds the token to revision 2.
    let mut binding_lock = fixture.connection().await;
    let mut updating = binding_lock.begin().await.unwrap();
    updating
        .execute("LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let owner = store.clone();
    let mut stale_binding = tokio::spawn(async move { read(&owner, ACCESS, deadline()).await });
    let end = deadline();
    let pid: i32 = loop {
        let pid: Option<i32> = sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_opaque_owner' AND wait_event_type='Lock' AND query LIKE '%FROM public.local_tokens t%'")
            .fetch_optional(&mut c).await.unwrap();
        if let Some(pid) = pid {
            break pid;
        }
        assert!(
            Instant::now() < end,
            "genuine verifier did not reach its state SELECT"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    relay.armed.store(true, Ordering::SeqCst);
    updating.commit().await.unwrap();
    let acknowledgement = loop {
        let decision = tokio::select! {
            decision=relay.replies.recv()=>decision.unwrap(),
            result=&mut stale_binding=>panic!("verifier read-COMMIT ACK was not withheld: {:?}",result.unwrap().err()),
            _=tokio::time::sleep_until(end.into())=>panic!("verifier did not reach read-COMMIT"),
        };
        let query: String = sqlx_core::query_scalar::query_scalar(
            "SELECT query FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut c)
        .await
        .unwrap();
        if query == "COMMIT" {
            break decision;
        }
        // Forward statement/close replies until this actual backend commits its read.
        decision.send(true).unwrap();
    };
    c.execute("UPDATE local_users SET revision=2 WHERE username='alice'; UPDATE local_tokens SET local_user_revision=2,principal_json=jsonb_set(principal_json::jsonb,'{local_user_revision}','2'::jsonb)::text WHERE token_id='access-test'").await.unwrap();
    relay.armed.store(false, Ordering::SeqCst);
    acknowledgement.send(true).unwrap();
    assert_eq!(stale_binding.await.unwrap().unwrap_err(), denied);
    assert_eq!(
        read(&store, ACCESS, deadline())
            .await
            .unwrap()
            .principal()
            .local_user_revision,
        2
    );
    c.execute("UPDATE local_users SET revision=1 WHERE username='alice'; UPDATE local_tokens SET local_user_revision=1,principal_json=jsonb_set(principal_json::jsonb,'{local_user_revision}','1'::jsonb)::text WHERE token_id='access-test'").await.unwrap();
    binding_lock.close().await.unwrap();
    let mut tiny = limits();
    tiny.profile_json_bytes = n(64);
    assert_eq!(
        store
            .admin_local_bearer_sessions(AUDIENCE, n(8192), tiny)
            .unwrap()
            .read(ACCESS, &[], deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::IdentityLimitExceeded)
    );
    let mut limited = limits();
    limited.identity.rows = n(1);
    assert_eq!(
        store
            .admin_local_bearer_sessions(AUDIENCE, n(8192), limited)
            .unwrap()
            .read(ACCESS, &[], deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::IdentityLimitExceeded)
    );
    c.execute("INSERT INTO role_permissions(role,action) VALUES('user','unknown.action')")
        .await
        .unwrap();
    assert_eq!(
        read(&store, ACCESS, deadline()).await.unwrap_err(),
        Error::Control(ControlError::CorruptRbac)
    );
    c.execute("DELETE FROM role_permissions WHERE action='unknown.action'; REVOKE SELECT ON role_permissions FROM admin_opaque_owner").await.unwrap();
    assert_eq!(
        read(&store, ACCESS, deadline()).await.unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT ON role_permissions TO admin_opaque_owner")
        .await
        .unwrap();
    // Only the role statement is blocked: raw authentication has completed.
    let mut locker = fixture.connection().await;
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let owner = store.clone();
    let timed =
        tokio::spawn(
            async move { read(&owner, ACCESS, Instant::now() + Duration::from_secs(1)).await },
        );
    wait_select(&mut c, "Lock").await;
    assert_eq!(
        timed.await.unwrap().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    let owner = store.clone();
    let cancelled = tokio::spawn(async move { read(&owner, ACCESS, deadline()).await });
    wait_select(&mut c, "Lock").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    read(&store, ACCESS, deadline()).await.unwrap();
    // Original raw-token expiry crosses an actual role-read wait, not a forged proof.
    sqlx_core::query::query("UPDATE local_tokens SET expires_at=$1 WHERE token_id='access-test'")
        .bind(micros() + 1_000_000)
        .execute(&mut c)
        .await
        .unwrap();
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let owner = store.clone();
    let expiring = tokio::spawn(async move { read(&owner, ACCESS, deadline()).await });
    wait_select(&mut c, "Lock").await;
    assert_eq!(
        expiring.await.unwrap().unwrap_err(),
        Error::Authentication(BrokerAccessError::Expired)
    );
    tx.rollback().await.unwrap();
    let commit_expiry = micros() + 10_000_000;
    sqlx_core::query::query("UPDATE local_tokens SET expires_at=$1 WHERE token_id='access-test'")
        .bind(commit_expiry)
        .execute(&mut c)
        .await
        .unwrap();
    // Withhold server replies after SELECT, then inspect this actual backend
    // to distinguish SQLx prepared-statement cleanup from real COMMIT ACK.
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let reader = store
        .admin_local_bearer_sessions(AUDIENCE, n(8192), limits())
        .unwrap();
    let pending = reader.read(ACCESS, &[], deadline());
    tokio::pin!(pending);
    tokio::select! { _=wait_select(&mut c,"Lock")=>{}, _=&mut pending=>panic!("actual SELECT must wait") }
    tx.rollback().await.unwrap();
    wait_select(&mut c, "idle in transaction").await;
    let pid: i32=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_opaque_owner' AND query LIKE '%FROM public.local_users u%' AND state='idle in transaction'").fetch_one(&mut c).await.unwrap();
    relay.armed.store(true, Ordering::SeqCst);
    loop {
        let decision = tokio::select! {
            decision=relay.replies.recv()=>decision.unwrap(),
            result=&mut pending=>panic!("actual COMMIT ACK was not withheld: {:?}",result.err()),
        };
        let query: String = sqlx_core::query_scalar::query_scalar(
            "SELECT query FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut c)
        .await
        .unwrap();
        if query == "COMMIT" {
            decision.send(false).unwrap();
            break;
        }
        // SQLx may close its uncached prepared SELECT before issuing COMMIT.
        // Forward those real protocol replies; they are not COMMIT uncertainty.
        decision.send(true).unwrap();
    }
    assert!(
        micros() < commit_expiry,
        "COMMIT attempt must precede authentication expiry"
    );
    // Stop polling until both cutoffs pass while the actual COMMIT ACK is absent.
    let remaining = u64::try_from((commit_expiry - micros()).max(0)).unwrap();
    tokio::time::sleep(Duration::from_micros(remaining) + Duration::from_millis(30)).await;
    assert_eq!(
        pending.await.unwrap_err(),
        Error::Control(ControlError::OutcomeUncertain)
    );
    locker.close().await.unwrap();
    relay.close().await;
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        read(&store, SERVICE, deadline()).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
}

#[derive(Clone, Copy, Debug)]
enum ReadonlyMetadata {
    Bearer,
    Grants,
    Inventory,
}
impl ReadonlyMetadata {
    fn sql(self) -> (&'static str, &'static str) {
        match self {
            Self::Bearer => (
                "LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE",
                "FROM public.local_tokens t",
            ),
            Self::Grants => (
                "LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE",
                "WITH policy AS MATERIALIZED",
            ),
            Self::Inventory => (
                "LOCK TABLE public.broker_instances IN ACCESS EXCLUSIVE MODE",
                "FROM public.broker_instances i",
            ),
        }
    }
    async fn read(self, store: &PostgresControlStore, end: Instant) -> Result<(), ControlError> {
        match self {
            Self::Bearer => {
                let digest = digester()
                    .token(TokenKind::LocalAccess, ACCESS.as_bytes())
                    .unwrap();
                store
                    .local_bearer_states(n(8192))
                    .unwrap()
                    .read(&digest, broker_control::LocalBearerKind::Access, end)
                    .await
                    .map(|state| assert!(state.is_some()))
                    .map_err(|error| match error {
                        broker_control::LocalBearerStateError::Control(error) => error,
                        other => panic!("unexpected bearer metadata failure: {other:?}"),
                    })
            }
            Self::Grants => store
                .resource_grants(n(8192))
                .unwrap()
                .read(end)
                .await
                .map(|_| ())
                .map_err(|error| match error {
                    broker_control::ResourceGrantReadError::Control(error) => error,
                    other => panic!("unexpected grants metadata failure: {other:?}"),
                }),
            Self::Inventory => store
                .instance_inventories(n(8192))
                .unwrap()
                .read("readonly-fixture", end)
                .await
                .map(|state| assert!(state.is_none()))
                .map_err(|error| match error {
                    broker_control::InstanceReadError::Control(error) => error,
                    other => panic!("unexpected inventory metadata failure: {other:?}"),
                }),
        }
    }
}
async fn readonly_metadata_state(c: &mut sqlx_postgres::PgConnection) -> Vec<String> {
    let mut result = Vec::new();
    macro_rules! snapshot {
        ($table:literal) => {
            concat!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM public.", $table, " t")
        };
    }
    for sql in [
        snapshot!("local_users"),
        snapshot!("local_tokens"),
        snapshot!("resource_acl_state"),
        snapshot!("resource_grants"),
        snapshot!("grant_capabilities"),
        snapshot!("grant_projects"),
        snapshot!("grant_s3_operations"),
        snapshot!("grant_s3_prefixes"),
        snapshot!("broker_instances"),
        snapshot!("broker_instance_project_versions"),
    ] {
        result.push(
            sqlx_core::query_scalar::query_scalar(sql)
                .fetch_one(&mut *c)
                .await
                .unwrap(),
        );
    }
    result
}
#[tokio::test]
#[ignore = "real TLS readonly COMMIT ACK timeout/disconnect, no result or effect, and recovery"]
async fn postgres_readonly_commit_failures_preserve_state() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE admin_opaque_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION admin_opaque_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO admin_opaque_owner").await.unwrap();
    let initial = open(&fixture, fixture.port).await;
    seed(&mut c).await;
    initial.shutdown(deadline()).await.unwrap();
    let before = readonly_metadata_state(&mut c).await;
    let mut blocker = fixture.connection().await;
    for kind in [
        ReadonlyMetadata::Bearer,
        ReadonlyMetadata::Grants,
        ReadonlyMetadata::Inventory,
    ] {
        for disconnect in [false, true] {
            let mut relay = CommitRelay::new(fixture.port).await;
            let store = open(&fixture, relay.port).await;
            let (lock_sql, marker) = kind.sql();
            let mut lock = blocker.begin().await.unwrap();
            lock.execute(lock_sql).await.unwrap();
            let end = if disconnect {
                deadline()
            } else {
                Instant::now() + Duration::from_secs(2)
            };
            let owner = store.clone();
            let mut pending = tokio::spawn(async move { kind.read(&owner, end).await });
            let pid: i32 = loop {
                c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
                let pid = sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_opaque_owner' AND wait_event_type='Lock' AND query LIKE $1")
                    .bind(format!("%{marker}%")).fetch_optional(&mut c).await.unwrap();
                if let Some(pid) = pid {
                    break pid;
                }
                assert!(Instant::now() < end, "{kind:?} did not reach its SELECT");
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            relay.armed.store(true, Ordering::SeqCst);
            lock.commit().await.unwrap();
            let acknowledgement = loop {
                let decision = tokio::select! {
                    decision=relay.replies.recv()=>decision.unwrap(),
                    result=&mut pending=>panic!("{kind:?} returned before its COMMIT ACK was retained: {result:?}"),
                    _=tokio::time::sleep_until(end.into())=>panic!("{kind:?} did not reach COMMIT before Original"),
                };
                let query: String = sqlx_core::query_scalar::query_scalar(
                    "SELECT query FROM pg_stat_activity WHERE pid=$1",
                )
                .bind(pid)
                .fetch_one(&mut c)
                .await
                .unwrap();
                if query == "COMMIT" {
                    break decision;
                }
                decision.send(true).unwrap();
            };
            assert!(
                Instant::now() < end,
                "{kind:?} reached COMMIT before its cutoff"
            );
            relay.armed.store(false, Ordering::SeqCst);
            if disconnect {
                // Close the real TLS relay while this backend's COMMIT reply is retained.
                relay.close().await;
                drop(acknowledgement);
                assert_eq!(
                    pending.await.unwrap(),
                    Err(ControlError::Storage),
                    "{kind:?}"
                );
                store.shutdown(deadline()).await.unwrap();
                let recovered = open(&fixture, fixture.port).await;
                kind.read(&recovered, deadline()).await.unwrap();
                recovered.shutdown(deadline()).await.unwrap();
            } else {
                // COMMIT already ran, but without its ACK the read must return no result.
                assert_eq!(
                    pending.await.unwrap(),
                    Err(ControlError::Deadline),
                    "{kind:?}"
                );
                drop(acknowledgement);
                // Recovery proves pool availability, not reaping of this specific backend.
                kind.read(&store, deadline()).await.unwrap();
                relay.close().await;
                store.shutdown(deadline()).await.unwrap();
            }
            assert_eq!(
                readonly_metadata_state(&mut c).await,
                before,
                "{kind:?} disconnect={disconnect}"
            );
        }
    }
    blocker.close().await.unwrap();
    c.close().await.unwrap();
}
