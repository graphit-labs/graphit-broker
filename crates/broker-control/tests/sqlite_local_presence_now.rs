#[allow(
    dead_code,
    reason = "shared SQLite identity fixture also serves administrative targets"
)]
#[path = "support/sqlite_admin_fixture.rs"]
mod fixture;
use broker_control::{
    ControlError, InstanceInventory, InstanceInventoryReadError, InstanceListQuery,
    InstanceProjectVersions, InstanceReadError, InstanceRegistrationError,
    NowChannelAuthorizationError, PresenceAuthorizationError, PresenceChannel, RegistrationChange,
};
use fixture::{Fixture, end, n};
use rusqlite::{Connection, params};
use std::time::Instant;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
fn scopes() -> Vec<String> {
    vec!["presence-sdk".into()]
}
fn prepare(f: &Fixture) {
    f.db().execute_batch("UPDATE local_tokens SET audience='presence-api',scopes_json='[\"presence-sdk\"]'; DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1").unwrap();
}
fn grant(db: &Connection, id: &str, user: &str, caps: &[&str], projects: &[&str]) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,'fixture','user',?2,'',0,0)",params![id,user]).unwrap();
    for cap in caps {
        db.execute(
            "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,?2)",
            params![id, cap],
        )
        .unwrap();
    }
    for p in projects {
        db.execute(
            "INSERT INTO grant_projects(grant_id,value) VALUES(?1,?2)",
            params![id, p],
        )
        .unwrap();
    }
}
fn inventory(id: &str, projects: &[&str]) -> InstanceInventory {
    InstanceInventory::new(
        id.into(),
        projects
            .iter()
            .map(|p| {
                InstanceProjectVersions::new((*p).into(), vec!["main".into(), "release.1".into()])
                    .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
fn query(limit: usize, after: Option<&str>) -> InstanceListQuery {
    InstanceListQuery::new(n(limit), after.map(str::to_owned), None, None, None).unwrap()
}
#[tokio::test]
#[ignore = "real SQLite LOCAL registration, All/Any and projected inventory"]
async fn sqlite_local_inventory_owner_all_any_projection_and_pagination() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    grant(
        &db,
        "alice-a",
        "alice",
        &["presence:publish", "presence:read"],
        &[A],
    );
    let registrar = f
        .store
        .local_instance_registrar("presence-api", n(8192), n(65536))
        .unwrap();
    assert!(matches!(
        registrar
            .register(&f.access, &scopes(), &inventory("a", &[A, B]), end())
            .await,
        Err(InstanceRegistrationError::Authorization(
            PresenceAuthorizationError::Forbidden
        ))
    ));
    assert_eq!(
        db.query_row("SELECT count(*) FROM broker_instances", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    grant(
        &db,
        "alice-b",
        "alice",
        &["presence:publish", "presence:read"],
        &[B],
    );
    assert_eq!(
        registrar
            .register(&f.access, &scopes(), &inventory("a", &[A, B]), end())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Created
    );
    assert_eq!(
        registrar
            .register(&f.access, &scopes(), &inventory("a", &[A, B]), end())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Unchanged
    );
    assert_eq!(
        registrar
            .register(&f.access, &scopes(), &inventory("c", &[A]), end())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Created
    );
    grant(&db, "bot-a", "bot", &["presence:read", "task:read"], &[A]);
    let reader = f
        .store
        .local_instance_inventory_reader("presence-api", n(8192), n(65536), n(65536))
        .unwrap();
    assert!(matches!(
        reader.read(&f.service, &scopes(), "a", end()).await,
        Err(InstanceInventoryReadError::OwnerConflict)
    ));
    assert!(
        reader
            .read(&f.access, &scopes(), "missing", end())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reader
            .read(&f.access, &scopes(), "a", end())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .projects()
            .len(),
        2
    );
    let lister = f
        .store
        .local_instance_inventory_lister("presence-api", n(8192), n(65536), n(65536))
        .unwrap();
    let page = lister
        .list(&f.service, &scopes(), &query(1, None), end())
        .await
        .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].inventory().instance_id(), "a");
    assert_eq!(page.items()[0].inventory().projects().len(), 1);
    assert_eq!(page.items()[0].inventory().projects()[0].project_id(), A);
    assert_eq!(page.next_after(), Some("a"));
    let next = lister
        .list(&f.service, &scopes(), &query(1, page.next_after()), end())
        .await
        .unwrap();
    assert_eq!(next.items()[0].inventory().instance_id(), "c");
    assert!(next.next_after().is_none());
    db.execute("DELETE FROM resource_grants WHERE id='alice-b'", [])
        .unwrap();
    db.execute("UPDATE resource_acl_state SET revision=revision+1", [])
        .unwrap();
    assert!(matches!(
        reader.read(&f.access, &scopes(), "a", end()).await,
        Err(InstanceInventoryReadError::Authorization(
            PresenceAuthorizationError::Forbidden
        ))
    ));
    assert!(
        registrar
            .register(&f.access, &scopes(), &inventory("empty", &[]), end())
            .await
            .is_err()
    );
    grant(
        &db,
        "alice-any",
        "alice",
        &["presence:publish", "presence:read"],
        &[],
    );
    registrar
        .register(&f.access, &scopes(), &inventory("empty", &[]), end())
        .await
        .unwrap();
    assert!(
        reader
            .read(&f.access, &scopes(), "empty", end())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .projects()
            .is_empty()
    );
    assert!(
        lister
            .list(
                &f.service,
                &scopes(),
                &InstanceListQuery::new(n(10), None, Some("empty".into()), None, None).unwrap(),
                end()
            )
            .await
            .unwrap()
            .items()
            .is_empty()
    );
    let auth = f
        .store
        .local_now_channel_authorizer("presence-api", n(8192), n(65536), n(65536))
        .unwrap();
    let channel = PresenceChannel::new("c", A, "main").unwrap();
    let read = auth
        .authorize_read(&f.service, &scopes(), &channel, end())
        .await
        .unwrap();
    assert!(read.read_mask().task_read());
    assert!(!read.read_mask().memory_read());
    assert!(!read.read_mask().knowledge_read());
    assert!(matches!(
        auth.authorize_publish(&f.service, &scopes(), &channel, end())
            .await,
        Err(NowChannelAuthorizationError::Local(
            PresenceAuthorizationError::Forbidden
        ))
    ));
    grant(&db, "bot-pub", "bot", &["presence:publish"], &[A]);
    assert!(matches!(
        auth.authorize_publish(&f.service, &scopes(), &channel, end())
            .await,
        Err(NowChannelAuthorizationError::OwnerConflict)
    ));
    assert!(matches!(
        auth.authorize_read(
            &f.service,
            &scopes(),
            &PresenceChannel::new("c", A, "not-registered").unwrap(),
            end()
        )
        .await,
        Err(NowChannelAuthorizationError::NotRegistered)
    ));
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test]
#[ignore = "real SQLite keyset, cap, corruption, Original and closed outcomes"]
async fn sqlite_local_inventory_candidates_are_bounded_and_eof_is_observed() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    grant(
        &db,
        "all",
        "alice",
        &["presence:publish", "presence:read"],
        &[],
    );
    let registrar = f
        .store
        .local_instance_registrar("presence-api", n(8192), n(65536))
        .unwrap();
    for id in ["a", "c", "z"] {
        registrar
            .register(&f.access, &scopes(), &inventory(id, &[A]), end())
            .await
            .unwrap();
    }
    let candidates = f.store.instance_inventory_candidates(n(65536)).unwrap();
    assert_eq!(
        candidates
            .read_next(None, end())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .instance_id(),
        "a"
    );
    assert_eq!(
        candidates
            .read_next(Some("b"), end())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .instance_id(),
        "c"
    );
    assert!(
        candidates
            .read_next(Some("z"), end())
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        candidates.read_next(Some(" invalid "), end()).await,
        Err(InstanceReadError::InvalidInstanceId)
    ));
    assert!(matches!(
        f.store
            .instance_inventory_candidates(n(1))
            .unwrap()
            .read_next(None, end())
            .await,
        Err(InstanceReadError::ReadLimitExceeded)
    ));
    assert_eq!(db.execute("UPDATE broker_instance_project_versions SET position=8 WHERE instance_id='a' AND position=1",[]).unwrap(), 1);
    assert!(matches!(
        candidates.read_next(None, end()).await,
        Err(InstanceReadError::MalformedStored)
    ));
    assert!(matches!(
        candidates.read_next(None, Instant::now()).await,
        Err(InstanceReadError::Control(ControlError::Deadline))
    ));
    f.store.shutdown(end()).await.unwrap();
    assert!(matches!(
        candidates.read_next(Some("z"), end()).await,
        Err(InstanceReadError::Control(ControlError::Closed))
    ));
}
#[tokio::test]
#[ignore = "real current opaque bearer state, no metadata or ingress substitution"]
async fn sqlite_local_presence_reauthenticates_current_human_service_state() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    grant(
        &db,
        "alice",
        "alice",
        &["presence:publish", "presence:read"],
        &[],
    );
    grant(
        &db,
        "bot",
        "bot",
        &["presence:publish", "presence:read"],
        &[],
    );
    let registrar = f
        .store
        .local_instance_registrar("presence-api", n(8192), n(65536))
        .unwrap();
    registrar
        .register(&f.access, &scopes(), &inventory("human", &[A]), end())
        .await
        .unwrap();
    registrar
        .register(&f.service, &scopes(), &inventory("service", &[B]), end())
        .await
        .unwrap();
    assert!(
        registrar
            .register("invalid", &scopes(), &inventory("bad", &[A]), end())
            .await
            .is_err()
    );
    assert!(
        registrar
            .register(
                &f.access,
                &["missing-scope".into()],
                &inventory("bad", &[A]),
                end()
            )
            .await
            .is_err()
    );
    assert!(
        f.store
            .local_instance_registrar("wrong-audience", n(8192), n(65536))
            .unwrap()
            .register(&f.access, &scopes(), &inventory("bad", &[A]), end())
            .await
            .is_err()
    );
    db.execute(
        "UPDATE local_users SET revision=revision+1 WHERE username='alice'",
        [],
    )
    .unwrap();
    assert!(
        registrar
            .register(&f.access, &scopes(), &inventory("bad", &[A]), end())
            .await
            .is_err()
    );
    db.execute(
        "UPDATE local_tokens SET revoked_at=1 WHERE token_kind='service'",
        [],
    )
    .unwrap();
    assert!(
        registrar
            .register(&f.service, &scopes(), &inventory("bad", &[A]), end())
            .await
            .is_err()
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM broker_instances", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test]
#[ignore = "real SQLite candidate snapshot while another connection owns the write lock"]
async fn sqlite_local_candidates_read_without_a_write_lock() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(
        f.store
            .instance_inventory_candidates(n(65536))
            .unwrap()
            .read_next(None, end())
            .await
            .unwrap()
            .is_none()
    );
    db.execute_batch("ROLLBACK").unwrap();
    f.store.shutdown(end()).await.unwrap();
}
