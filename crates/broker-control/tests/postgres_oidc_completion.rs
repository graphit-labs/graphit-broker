#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture also serves other suites"
)]
mod support;
use broker_control::{
    AuthorizedOidcAuthorization, CompletedLocalLogin, ConnectionLimits, ControlError,
    LocalAuthPolicy, LocalAuthStep, LocalMfaAttemptLimiter, LocalMfaAttemptPolicy,
    LocalPasswordEngine, OidcAuthorizationConfiguration, OidcAuthorizationError as Error,
    OidcAuthorizationInput, OidcAuthorizationLimits, OidcAuthorizationPolicy,
    OidcLoginPreparationError, PendingOidcAuthorization, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, PreparedOidcLogin,
};
use broker_security::{
    CredentialDigester, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher, TokenKind,
};
use sqlx_core::{connection::Connection, executor::Executor, row::Row};
use sqlx_postgres::PgConnection;
use std::{
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use zeroize::Zeroizing;
const PASSWORD: &str = "fixture-only native OIDC password";
const RESOURCE: &str = "https://broker.example/v1";
fn utc() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn policy(dynamic: bool) -> OidcAuthorizationPolicy {
    OidcAuthorizationPolicy::new(
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: "graphit-broker".into(),
            accepted_resources: vec![RESOURCE.into()],
            dynamic_registration: dynamic,
            authorization_ttl: Duration::from_secs(600),
        },
        OidcAuthorizationLimits::new(n(4096), n(8192)).unwrap(),
    )
    .unwrap()
}
fn input(dynamic: bool) -> OidcAuthorizationInput<'static> {
    OidcAuthorizationInput {
        client_id: if dynamic { "web-client" } else { "graphit-cli" },
        redirect_uri: if dynamic {
            "https://client.example/cb"
        } else {
            "http://localhost:49152/oauth/callback"
        },
        response_type: "code",
        scope: "openid profile email phone address offline_access",
        state: " state\0 ",
        nonce: " nonce\0 ",
        code_challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        code_challenge_method: "S256",
        response_mode: Some("form_post"),
        resources: if dynamic { &[RESOURCE] } else { &[] },
        prompts: &[],
    }
}
fn completed(step: LocalAuthStep) -> CompletedLocalLogin {
    match step {
        LocalAuthStep::Complete(login) => login,
        _ => panic!("expected completed real LOCAL login"),
    }
}
struct F {
    fixture: Fixture,
    store: Arc<PostgresControlStore>,
    engine: Arc<LocalPasswordEngine>,
    d: Arc<CredentialDigester>,
    m: LocalMfaProtector,
    p: Arc<OidcAuthorizationPolicy>,
    exempt: LocalAuthPolicy,
    required: LocalAuthPolicy,
    limiter: LocalMfaAttemptLimiter,
    admin: PgConnection,
    phc: Zeroizing<String>,
}
impl F {
    async fn new() -> Self {
        let fixture = Fixture::new(true).await;
        let mut admin = fixture.connection().await;
        admin.execute("CREATE ROLE completion_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION completion_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO completion_owner").await.unwrap();
        let config = PostgresConfig::new(
            PostgresEndpoint {
                host: "127.0.0.1".into(),
                port: NonZeroU16::new(fixture.port).unwrap(),
                database: "postgres".into(),
            },
            PostgresCredentials::new(
                "completion_owner".into(),
                Zeroizing::new("ephemeral-owner".into()),
            ),
            fixture.ca.clone(),
            ConnectionLimits {
                text_bytes: n(256),
                ca_bytes: n(8192),
            },
            support::pool(2),
            support::limits(),
        )
        .unwrap();
        let store = Arc::new(
            PostgresControlStore::open(config, support::digester(), deadline())
                .await
                .unwrap(),
        );
        let engine = Arc::new(
            LocalPasswordEngine::new(
                LocalPasswordHasher::new(Zeroizing::new(vec![29; 32].into_boxed_slice())).unwrap(),
                n(1),
                deadline(),
            )
            .await
            .unwrap(),
        );
        let phc = engine.hash(PASSWORD, deadline()).await.unwrap();
        let mut f = Self {
            fixture,
            store,
            engine,
            d: Arc::new(support::digester()),
            m: LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap(),
            p: Arc::new(policy(true)),
            exempt: LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600))
                .unwrap(),
            required: LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(600))
                .unwrap(),
            limiter: LocalMfaAttemptLimiter::new(
                LocalMfaAttemptPolicy::new(
                    NonZeroU32::new(10).unwrap(),
                    Duration::from_secs(60),
                    Duration::from_secs(60),
                    n(4),
                )
                .unwrap(),
            ),
            admin,
            phc,
        };
        f.restore_user().await;
        f.restore_client().await;
        let ordinary: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT NOT rolsuper FROM pg_roles WHERE rolname='completion_owner'",
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        assert!(ordinary);
        f
    }
    async fn restore_user(&mut self) {
        sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',$1,'','','','[]',1,0,1,0,0) ON CONFLICT(subject) DO UPDATE SET username='alice',identity_kind='human',password_hash=excluded.password_hash,name='',email='',organization='',teams_json='[]',enabled=1,password_change_required=0,revision=1")
            .bind(self.phc.as_str()).execute(&mut self.admin).await.unwrap();
    }
    async fn restore_client(&mut self) {
        sqlx_core::query::query("INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('web-client','Client','[\"https://client.example/cb\"]','[\"openid\"]','web',$1) ON CONFLICT(client_id) DO UPDATE SET redirect_uris_json=excluded.redirect_uris_json,application_type='web'").bind(utc()).execute(&mut self.admin).await.unwrap();
    }
    async fn request(&self, dynamic: bool) -> PendingOidcAuthorization {
        self.store
            .oidc_authorization_service(&self.d, &self.p)
            .create(input(dynamic), deadline())
            .await
            .unwrap()
    }
    async fn plain(&self, context: LocalAuthBinding<'_>) -> CompletedLocalLogin {
        let proof = self
            .store
            .local_password_verifier(&self.engine)
            .verify("alice", PASSWORD, deadline())
            .await
            .unwrap();
        completed(
            self.store
                .local_auth_service(&self.d, &self.m, &self.exempt)
                .begin(proof, context, deadline())
                .await
                .unwrap(),
        )
    }
    async fn ready(&self, raw: &str) -> PreparedOidcLogin {
        PreparedOidcLogin::try_from(
            self.plain(LocalAuthBinding::OauthAuthorize(raw.as_bytes()))
                .await,
        )
        .unwrap()
    }
    fn hash(&self, raw: &str) -> String {
        self.d
            .token(TokenKind::OidcAuthRequest, raw.as_bytes())
            .unwrap()
            .to_sql_hex()
    }
    async fn snapshot(&mut self) -> Zeroizing<String> {
        Zeroizing::new(sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('requests',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.oidc_auth_requests ORDER BY request_hash) r),'users',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.local_users ORDER BY subject) r),'roles',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.role_assignments ORDER BY subject,role) r),'clients',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.oauth_dynamic_clients ORDER BY client_id) r),'mfa',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.local_mfa ORDER BY subject) r),'recovery',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.local_mfa_recovery_codes ORDER BY subject,code_hash) r),'challenges',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.local_auth_challenges ORDER BY challenge_hash) r),'tokens',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.local_tokens ORDER BY token_hash) r))::text").fetch_one(&mut self.admin).await.unwrap())
    }
    async fn unchanged(&mut self, before: &str) {
        assert!(
            self.snapshot().await.as_str() == before,
            "denial/cancellation must preserve SQL snapshot"
        );
    }
    fn spawn(
        &self,
        raw: Zeroizing<String>,
        ready: PreparedOidcLogin,
        end: Instant,
    ) -> tokio::task::JoinHandle<Result<AuthorizedOidcAuthorization, Error>> {
        let (s, d, p) = (self.store.clone(), self.d.clone(), self.p.clone());
        tokio::spawn(async move {
            s.oidc_authorization_service(&d, &p)
                .complete(&raw, ready, end)
                .await
        })
    }
    async fn wait(&mut self, needle: &str, count: i64) {
        let end = deadline();
        loop {
            self.admin
                .execute("SELECT pg_stat_clear_snapshot()")
                .await
                .unwrap();
            let n: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='completion_owner' AND wait_event_type='Lock' AND query LIKE $1").bind(format!("%{needle}%")).fetch_one(&mut self.admin).await.unwrap();
            if n >= count {
                return;
            }
            assert!(
                Instant::now() < end,
                "actual completion SQL lock not observed"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    async fn healthy(&self, raw: &str) {
        assert!(
            self.store
                .oidc_authorization_service(&self.d, &self.p)
                .load(raw, deadline())
                .await
                .unwrap()
                .is_some()
        );
    }
    async fn finish(self) {
        self.admin.close().await.unwrap();
        self.store.shutdown(deadline()).await.unwrap();
        self.fixture.shutdown().unwrap();
    }
}
async fn positive_and_preparation(f: &mut F) {
    let admin_login = f.plain(LocalAuthBinding::AdminLogin).await;
    let e = PreparedOidcLogin::try_from(admin_login).unwrap_err();
    assert!(matches!(e, OidcLoginPreparationError::InvalidPurpose(_)));
    assert!(!format!("{e:?}").contains("alice"));
    let admin_login = e.into_login();
    admin_login
        .verify_binding(&f.d, LocalAuthBinding::AdminLogin)
        .unwrap();
    let p = f.request(false).await;
    let raw = Zeroizing::new(p.request().to_owned());
    let hash = f.hash(&raw);
    let ready = f.ready(&raw).await;
    sqlx_core::query::query("UPDATE public.local_users SET name=$1,email='fixture@example.invalid',organization='Example',teams_json='[\" team \",\"\",\"team\",\"other\"]'").bind("😀".repeat(512)).execute(&mut f.admin).await.unwrap();
    f.admin
        .execute("INSERT INTO public.roles(name,created_at) VALUES('publisher',1),('raw-must-not-be-promoted',1)")
        .await
        .unwrap();
    f.admin
        .execute(
            "INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','publisher',1),('alice-subject','raw-must-not-be-promoted',1)",
        )
        .await
        .unwrap();
    let old =
        sqlx_core::query::query("SELECT * FROM public.oidc_auth_requests WHERE request_hash=$1")
            .bind(&hash)
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
    let original: serde_json::Value =
        serde_json::from_str(&old.get::<String, _>("request_json")).unwrap();
    let started = utc();
    let a = f
        .store
        .oidc_authorization_service(&f.d, &f.p)
        .complete(&raw, ready, deadline())
        .await
        .unwrap();
    assert_eq!(a.code().len(), 43);
    assert_eq!(a.oidc_subject().len(), 43);
    assert_eq!(a.amr(), &["pwd"]);
    assert!(a.auth_time().as_i64() >= started && a.auth_time().as_i64() <= utc());
    assert_eq!(format!("{a:?}"), "AuthorizedOidcAuthorization([REDACTED])");
    assert_eq!(a.info().created_at(), p.info().created_at());
    assert_eq!(a.info().expires_at(), p.info().expires_at());
    let row =
        sqlx_core::query::query("SELECT * FROM public.oidc_auth_requests WHERE request_hash=$1")
            .bind(&hash)
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
    assert_eq!(row.get::<String, _>("identity_subject"), "alice-subject");
    let code_hash = row.get::<String, _>("code_hash");
    assert!(
        code_hash
            == f.d
                .token(TokenKind::OidcAuthorizationCode, a.code().as_bytes())
                .unwrap()
                .to_sql_hex()
    );
    assert!(
        code_hash
            != f.d
                .token(TokenKind::LocalAuthChallenge, a.code().as_bytes())
                .unwrap()
                .to_sql_hex()
    );
    for key in ["created_at", "expires_at"] {
        assert_eq!(old.get::<i64, _>(key), row.get::<i64, _>(key));
    }
    let json = Zeroizing::new(row.get::<String, _>("request_json"));
    assert!(!json.contains(raw.as_str()) && !json.contains(a.code()));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    for (key, val) in original.as_object().unwrap() {
        if key != "phase" {
            assert!(&v[key] == val, "original pending fields remain unchanged");
        }
    }
    assert_eq!(v["phase"], "authorized");
    assert_eq!(v["principal"]["name"], "😀".repeat(512));
    assert_eq!(v["principal"]["email"], "fixture@example.invalid");
    assert_eq!(v["principal"]["organization"], "Example");
    assert_eq!(
        v["principal"]["teams"],
        serde_json::json!(["team", "other"])
    );
    assert_eq!(
        v["principal"]["roles"],
        serde_json::json!(["publisher", "user"])
    );
    assert_eq!(v["principal"]["auth_method"], "local-token");
    assert!(
        v["oidc_subject"].as_str()
            == Some(
                f.d.oidc_subject(b"local", b"alice-subject")
                    .unwrap()
                    .as_str()
            )
    );
    assert_eq!(v["auth_time"].as_i64(), Some(a.auth_time().as_i64()));
    assert!(
        f.store
            .oidc_authorization_service(&f.d, &f.p)
            .load(&raw, deadline())
            .await
            .unwrap()
            .is_none()
    );
    let ready = f.ready(&raw).await;
    let before = f.snapshot().await;
    assert_eq!(
        f.store
            .oidc_authorization_service(&f.d, &f.p)
            .complete(&raw, ready, deadline())
            .await
            .unwrap_err(),
        Error::InvalidRequest
    );
    f.unchanged(&before).await;
    f.restore_user().await;
}
async fn rollback(f: &mut F) {
    for (setup, cleanup, expected) in [
        (
            "REVOKE UPDATE ON public.oidc_auth_requests FROM completion_owner",
            "GRANT UPDATE ON public.oidc_auth_requests TO completion_owner",
            Error::Control(ControlError::Storage),
        ),
        (
            "ALTER TABLE public.oidc_auth_requests ADD CONSTRAINT deny_code CHECK(code_hash IS NULL) NOT VALID",
            "ALTER TABLE public.oidc_auth_requests DROP CONSTRAINT deny_code",
            Error::Control(ControlError::Storage),
        ),
        (
            "CREATE FUNCTION public.reject_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture commit rejection'; END $$; CREATE CONSTRAINT TRIGGER reject_completion AFTER UPDATE ON public.oidc_auth_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_completion()",
            "DROP TRIGGER reject_completion ON public.oidc_auth_requests; DROP FUNCTION public.reject_completion()",
            Error::Control(ControlError::OutcomeUncertain),
        ),
    ] {
        let p = f.request(false).await;
        let ready = f.ready(p.request()).await;
        f.admin.execute(setup).await.unwrap();
        let before = f.snapshot().await;
        assert_eq!(
            f.store
                .oidc_authorization_service(&f.d, &f.p)
                .complete(p.request(), ready, deadline())
                .await
                .unwrap_err(),
            expected
        );
        f.admin.execute(cleanup).await.unwrap();
        f.unchanged(&before).await;
        f.healthy(p.request()).await;
    }
}
async fn locks_and_concurrency(f: &mut F) {
    for table in ["local_users", "oauth_dynamic_clients", "oidc_auth_requests"] {
        let p = f.request(table == "oauth_dynamic_clients").await;
        let raw = Zeroizing::new(p.request().to_owned());
        let ready = f.ready(&raw).await;
        let before = f.snapshot().await;
        let mut holder = f.fixture.connection().await;
        holder.execute("BEGIN").await.unwrap();
        let sql = match table {
            "local_users" => "SELECT subject FROM public.local_users FOR UPDATE",
            "oauth_dynamic_clients" => {
                "SELECT client_id FROM public.oauth_dynamic_clients FOR UPDATE"
            }
            _ => {
                "SELECT request_hash FROM public.oidc_auth_requests WHERE request_hash=$1 FOR UPDATE"
            }
        };
        let mut query = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql.to_owned()));
        if table == "oidc_auth_requests" {
            query = query.bind(f.hash(&raw));
        }
        query.fetch_all(&mut holder).await.unwrap();
        let job = f.spawn(
            Zeroizing::new(raw.to_string()),
            ready,
            Instant::now() + Duration::from_millis(500),
        );
        f.wait(table, 1).await;
        assert_eq!(
            job.await.unwrap().unwrap_err(),
            Error::Control(ControlError::Deadline)
        );
        holder.execute("ROLLBACK").await.unwrap();
        holder.close().await.unwrap();
        f.unchanged(&before).await;
        f.healthy(&raw).await;
    }
    let p = f.request(false).await;
    let raw = Zeroizing::new(p.request().to_owned());
    let ready = f.ready(&raw).await;
    let before = f.snapshot().await;
    let mut holder = f.fixture.connection().await;
    holder.execute("BEGIN").await.unwrap();
    sqlx_core::query::query(
        "SELECT request_hash FROM public.oidc_auth_requests WHERE request_hash=$1 FOR UPDATE",
    )
    .bind(f.hash(&raw))
    .fetch_one(&mut holder)
    .await
    .unwrap();
    let job = f.spawn(Zeroizing::new(raw.to_string()), ready, deadline());
    f.wait("oidc_auth_requests", 1).await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    holder.execute("ROLLBACK").await.unwrap();
    holder.close().await.unwrap();
    f.unchanged(&before).await;
    f.healthy(&raw).await;
    let p = f.request(false).await;
    let raw = Zeroizing::new(p.request().to_owned());
    let one = f.ready(&raw).await;
    let two = f.ready(&raw).await;
    let mut holder = f.fixture.connection().await;
    holder.execute("BEGIN").await.unwrap();
    sqlx_core::query::query(
        "SELECT request_hash FROM public.oidc_auth_requests WHERE request_hash=$1 FOR UPDATE",
    )
    .bind(f.hash(&raw))
    .fetch_one(&mut holder)
    .await
    .unwrap();
    let a = f.spawn(Zeroizing::new(raw.to_string()), one, deadline());
    let b = f.spawn(Zeroizing::new(raw.to_string()), two, deadline());
    f.wait("oidc_auth_requests", 2).await;
    holder.execute("COMMIT").await.unwrap();
    holder.close().await.unwrap();
    let winner = match (a.await.unwrap(), b.await.unwrap()) {
        (Ok(winner), Err(Error::InvalidRequest)) | (Err(Error::InvalidRequest), Ok(winner)) => {
            winner
        }
        _ => panic!("concurrent completion must return one code and one invalid request"),
    };
    let stored: String = sqlx_core::query_scalar::query_scalar(
        "SELECT code_hash FROM public.oidc_auth_requests WHERE request_hash=$1",
    )
    .bind(f.hash(&raw))
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert!(
        stored
            == f.d
                .token(TokenKind::OidcAuthorizationCode, winner.code().as_bytes())
                .unwrap()
                .to_sql_hex()
    );
    let p = f.request(false).await;
    let raw = Zeroizing::new(p.request().to_owned());
    let ready = f.ready(&raw).await;
    let expiry = utc() + 900_000;
    sqlx_core::query::query("UPDATE public.oidc_auth_requests SET created_at=$2-600000000,expires_at=$2 WHERE request_hash=$1").bind(f.hash(&raw)).bind(expiry).execute(&mut f.admin).await.unwrap();
    let before = f.snapshot().await;
    let mut holder = f.fixture.connection().await;
    holder.execute("BEGIN").await.unwrap();
    sqlx_core::query::query(
        "SELECT request_hash FROM public.oidc_auth_requests WHERE request_hash=$1 FOR UPDATE",
    )
    .bind(f.hash(&raw))
    .fetch_one(&mut holder)
    .await
    .unwrap();
    let job = f.spawn(Zeroizing::new(raw.to_string()), ready, deadline());
    f.wait("oidc_auth_requests", 1).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    holder.execute("COMMIT").await.unwrap();
    holder.close().await.unwrap();
    assert_eq!(job.await.unwrap().unwrap_err(), Error::InvalidRequest);
    f.unchanged(&before).await;
    let p = f.request(true).await;
    let raw = Zeroizing::new(p.request().to_owned());
    let ready = f.ready(&raw).await;
    let mut holder = f.fixture.connection().await;
    holder.execute("BEGIN").await.unwrap();
    holder
        .execute("SELECT client_id FROM public.oauth_dynamic_clients FOR UPDATE")
        .await
        .unwrap();
    let job = f.spawn(Zeroizing::new(raw.to_string()), ready, deadline());
    f.wait("oauth_dynamic_clients", 1).await;
    let json: String = sqlx_core::query_scalar::query_scalar(
        "SELECT request_json FROM public.oidc_auth_requests WHERE request_hash=$1",
    )
    .bind(f.hash(&raw))
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value["state"] = serde_json::json!("changed");
    sqlx_core::query::query(
        "UPDATE public.oidc_auth_requests SET request_json=$2 WHERE request_hash=$1",
    )
    .bind(f.hash(&raw))
    .bind(serde_json::to_string(&value).unwrap())
    .execute(&mut f.admin)
    .await
    .unwrap();
    let before = f.snapshot().await;
    holder.execute("COMMIT").await.unwrap();
    holder.close().await.unwrap();
    assert_eq!(job.await.unwrap().unwrap_err(), Error::MalformedStored);
    f.unchanged(&before).await;
    f.healthy(&raw).await;
}
async fn real_mfa_and_code_handoff(f: &mut F) {
    let p = f.request(false).await;
    let raw = Zeroizing::new(p.request().to_owned());
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, deadline())
        .await
        .unwrap();
    let LocalAuthStep::Pending(enrollment) = f
        .store
        .local_auth_service(&f.d, &f.m, &f.required)
        .begin(
            proof,
            LocalAuthBinding::OauthAuthorize(raw.as_bytes()),
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("real enrollment required")
    };
    let sdk = totp_rs::Totp::from_url(enrollment.enrollment().unwrap().otpauth_uri()).unwrap();
    let code = Zeroizing::new(sdk.generate(utc() as u64 / 1_000_000).to_string());
    let login = completed(
        f.store
            .local_auth_service(&f.d, &f.m, &f.required)
            .complete_mfa(
                &f.limiter,
                enrollment.challenge(),
                LocalAuthBinding::OauthAuthorize(raw.as_bytes()),
                &code,
                deadline(),
            )
            .await
            .unwrap(),
    );
    let observed = login.observed_at();
    let error = PreparedOidcLogin::try_from(login).unwrap_err();
    assert!(matches!(
        error,
        OidcLoginPreparationError::RecoveryCodesPending(_)
    ));
    assert!(!format!("{error:?}").contains("alice"));
    let mut login = error.into_login();
    assert_eq!(login.observed_at(), observed);
    let retained = login.take_recovery_codes().unwrap();
    assert_eq!(retained.iter().count(), 10);
    assert!(login.take_recovery_codes().is_none());
    let a = f
        .store
        .oidc_authorization_service(&f.d, &f.p)
        .complete(
            &raw,
            PreparedOidcLogin::try_from(login).unwrap(),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(a.amr(), &["pwd", "otp"]);
    assert!(a.auth_time() >= observed);
    assert_eq!(a.info().created_at(), p.info().created_at());
    assert_eq!(a.info().expires_at(), p.info().expires_at());
    for totp in [true, false] {
        let p = f.request(false).await;
        let raw = Zeroizing::new(p.request().to_owned());
        let proof = f
            .store
            .local_password_verifier(&f.engine)
            .verify("alice", PASSWORD, deadline())
            .await
            .unwrap();
        let LocalAuthStep::Pending(mfa) = f
            .store
            .local_auth_service(&f.d, &f.m, &f.required)
            .begin(
                proof,
                LocalAuthBinding::OauthAuthorize(raw.as_bytes()),
                deadline(),
            )
            .await
            .unwrap()
        else {
            panic!("enrolled MFA must require a real factor")
        };
        let code = Zeroizing::new(if totp {
            sdk.generate(utc() as u64 / 1_000_000 + 30).to_string()
        } else {
            retained.iter().next().unwrap().to_owned()
        });
        let mut login = completed(
            f.store
                .local_auth_service(&f.d, &f.m, &f.required)
                .complete_mfa(
                    &f.limiter,
                    mfa.challenge(),
                    LocalAuthBinding::OauthAuthorize(raw.as_bytes()),
                    &code,
                    deadline(),
                )
                .await
                .unwrap(),
        );
        assert!(login.take_recovery_codes().is_none());
        let a = f
            .store
            .oidc_authorization_service(&f.d, &f.p)
            .complete(
                &raw,
                PreparedOidcLogin::try_from(login).unwrap(),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(a.amr(), &["pwd", "otp"]);
        let json: String = sqlx_core::query_scalar::query_scalar(
            "SELECT request_json FROM public.oidc_auth_requests WHERE request_hash=$1",
        )
        .bind(f.hash(&raw))
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["principal"]["auth_method"], "local-token");
        assert_eq!(v["principal"]["local_user_revision"], 2);
        assert_eq!(v["amr"], serde_json::json!(["pwd", "otp"]));
    }
    let exempt_request = f.request(false).await;
    let exempt_login = f.ready(exempt_request.request()).await;
    let exempt_result = f
        .store
        .oidc_authorization_service(&f.d, &f.p)
        .complete(exempt_request.request(), exempt_login, deadline())
        .await
        .unwrap();
    assert_eq!(exempt_result.amr(), &["pwd"]);
    let left: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.local_mfa_recovery_codes",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(left, 9);
    assert_eq!(retained.iter().count(), 10);
    assert!(!format!("{retained:?}").contains(retained.iter().next().unwrap()));
    // Taking codes does not prove UI presentation: this owner deliberately retains them.
    let p = f.request(false).await;
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, deadline())
        .await
        .unwrap();
    let LocalAuthStep::Pending(mfa) = f
        .store
        .local_auth_service(&f.d, &f.m, &f.required)
        .begin(
            proof,
            LocalAuthBinding::OauthAuthorize(p.request().as_bytes()),
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("real MFA required")
    };
    let code = Zeroizing::new(retained.iter().nth(1).unwrap().to_owned());
    let login = completed(
        f.store
            .local_auth_service(&f.d, &f.m, &f.required)
            .complete_mfa(
                &f.limiter,
                mfa.challenge(),
                LocalAuthBinding::OauthAuthorize(p.request().as_bytes()),
                &code,
                deadline(),
            )
            .await
            .unwrap(),
    );
    let ready = PreparedOidcLogin::try_from(login).unwrap();
    let before = f.snapshot().await;
    assert_eq!(
        f.store
            .oidc_authorization_service(&f.d, &f.p)
            .complete(p.request(), ready, Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    f.unchanged(&before).await;
    assert_eq!(retained.iter().count(), 10);
}
#[tokio::test]
#[ignore = "real ordinary PostgreSQL TLS, password/MFA completion, current SQL, rollback and concurrency"]
async fn postgres_oidc_completion_contract() {
    let mut f = F::new().await;
    positive_and_preparation(&mut f).await;
    denials(&mut f).await;
    rollback(&mut f).await;
    locks_and_concurrency(&mut f).await;
    real_mfa_and_code_handoff(&mut f).await;
    f.finish().await;
}
async fn denials(f: &mut F) {
    for sql in [
        "UPDATE public.local_users SET enabled=0",
        "UPDATE public.local_users SET identity_kind='service'",
        "UPDATE public.local_users SET revision=2",
        "UPDATE public.local_users SET password_change_required=1",
        "UPDATE public.local_users SET username='changed'",
        "DELETE FROM public.local_users",
    ] {
        let p = f.request(false).await;
        let raw = Zeroizing::new(p.request().to_owned());
        let ready = f.ready(&raw).await;
        f.admin.execute(sql).await.unwrap();
        let before = f.snapshot().await;
        assert_eq!(
            f.store
                .oidc_authorization_service(&f.d, &f.p)
                .complete(&raw, ready, deadline())
                .await
                .unwrap_err(),
            Error::InvalidLogin
        );
        f.unchanged(&before).await;
        f.restore_user().await;
    }
    let p = f.request(false).await;
    let q = f.request(false).await;
    let ready = f.ready(p.request()).await;
    let before = f.snapshot().await;
    assert_eq!(
        f.store
            .oidc_authorization_service(&f.d, &f.p)
            .complete(q.request(), ready, deadline())
            .await
            .unwrap_err(),
        Error::InvalidLogin
    );
    f.unchanged(&before).await;
    let ready = f.ready(p.request()).await;
    let wrong = CredentialDigester::new(
        Zeroizing::new(vec![0x92; 32].into_boxed_slice()),
        broker_security::DigestLimits::new(n(64), n(256), n(256), n(256), n(256)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        f.store
            .oidc_authorization_service(&wrong, &f.p)
            .complete(p.request(), ready, deadline())
            .await
            .unwrap_err(),
        Error::InvalidLogin
    );
    f.unchanged(&before).await;
    for (sql, expected) in [
        (
            "DELETE FROM public.oauth_dynamic_clients",
            Error::InvalidClient,
        ),
        (
            "UPDATE public.oauth_dynamic_clients SET redirect_uris_json='[\"https://client.example/other\"]'",
            Error::MalformedStored,
        ),
    ] {
        let p = f.request(true).await;
        let ready = f.ready(p.request()).await;
        f.admin.execute(sql).await.unwrap();
        let before = f.snapshot().await;
        assert_eq!(
            f.store
                .oidc_authorization_service(&f.d, &f.p)
                .complete(p.request(), ready, deadline())
                .await
                .unwrap_err(),
            expected
        );
        f.unchanged(&before).await;
        f.restore_client().await;
    }
    let p = f.request(true).await;
    let ready = f.ready(p.request()).await;
    let before = f.snapshot().await;
    assert_eq!(
        f.store
            .oidc_authorization_service(&f.d, &policy(false))
            .complete(p.request(), ready, deadline())
            .await
            .unwrap_err(),
        Error::InvalidClient
    );
    f.unchanged(&before).await;
    for (case, expected) in [
        ("empty", Error::MalformedStored),
        ("array", Error::MalformedStored),
        ("extra", Error::MalformedStored),
        ("phase", Error::MalformedStored),
        ("api_audience", Error::MalformedStored),
        ("code_challenge_method", Error::MalformedStored),
        ("oversized", Error::ReadLimitExceeded),
    ] {
        let p = f.request(false).await;
        let ready = f.ready(p.request()).await;
        let stored: String = sqlx_core::query_scalar::query_scalar(
            "SELECT request_json FROM public.oidc_auth_requests WHERE request_hash=$1",
        )
        .bind(f.hash(p.request()))
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&stored).unwrap();
        let json = match case {
            "empty" => "{}".to_owned(),
            "array" => "[]".to_owned(),
            "oversized" => "x".repeat(4097),
            "extra" => {
                value["extra"] = serde_json::json!(1);
                serde_json::to_string(&value).unwrap()
            }
            "phase" => {
                value["phase"] = serde_json::json!("authorized");
                serde_json::to_string(&value).unwrap()
            }
            "api_audience" => {
                value["api_audience"] = serde_json::json!("other");
                serde_json::to_string(&value).unwrap()
            }
            "code_challenge_method" => {
                value["code_challenge_method"] = serde_json::json!("plain");
                serde_json::to_string(&value).unwrap()
            }
            _ => panic!("unknown test corruption"),
        };
        sqlx_core::query::query(
            "UPDATE public.oidc_auth_requests SET request_json=$2 WHERE request_hash=$1",
        )
        .bind(f.hash(p.request()))
        .bind(json)
        .execute(&mut f.admin)
        .await
        .unwrap();
        let before = f.snapshot().await;
        assert_eq!(
            f.store
                .oidc_authorization_service(&f.d, &f.p)
                .complete(p.request(), ready, deadline())
                .await
                .unwrap_err(),
            expected
        );
        f.unchanged(&before).await;
    }
    for (sql, expected) in [
        (
            "UPDATE public.local_users SET teams_json='[1]'",
            Error::MalformedStored,
        ),
        (
            "UPDATE public.local_users SET teams_json=repeat('x',4097)",
            Error::ReadLimitExceeded,
        ),
        (
            "UPDATE public.local_users SET name=repeat('😀',512),email=repeat('😀',512)",
            Error::ReadLimitExceeded,
        ),
    ] {
        let p = f.request(false).await;
        let ready = f.ready(p.request()).await;
        f.admin.execute(sql).await.unwrap();
        let before = f.snapshot().await;
        assert_eq!(
            f.store
                .oidc_authorization_service(&f.d, &f.p)
                .complete(p.request(), ready, deadline())
                .await
                .unwrap_err(),
            expected
        );
        f.unchanged(&before).await;
        f.restore_user().await;
    }
    for (state, expected) in [
        ("missing", Error::InvalidRequest),
        ("expired", Error::InvalidRequest),
        ("identity", Error::InvalidRequest),
        ("code", Error::InvalidRequest),
        ("ttl", Error::MalformedStored),
        ("future", Error::MalformedStored),
    ] {
        let p = f.request(false).await;
        let ready = f.ready(p.request()).await;
        let hash = f.hash(p.request());
        let sql = match state {
            "missing" => "DELETE FROM public.oidc_auth_requests WHERE request_hash=$1",
            "expired" => {
                "UPDATE public.oidc_auth_requests SET created_at=$2-600000000,expires_at=$2 WHERE request_hash=$1"
            }
            "identity" => {
                "UPDATE public.oidc_auth_requests SET identity_subject='alice-subject' WHERE request_hash=$1"
            }
            "code" => {
                "UPDATE public.oidc_auth_requests SET code_hash=repeat('0',64) WHERE request_hash=$1"
            }
            "ttl" => {
                "UPDATE public.oidc_auth_requests SET expires_at=expires_at+1 WHERE request_hash=$1"
            }
            _ => {
                "UPDATE public.oidc_auth_requests SET created_at=$2+10000000,expires_at=$2+610000000 WHERE request_hash=$1"
            }
        };
        let mut query =
            sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql.to_owned())).bind(hash);
        if matches!(state, "expired" | "future") {
            query = query.bind(utc());
        }
        query.execute(&mut f.admin).await.unwrap();
        let before = f.snapshot().await;
        assert_eq!(
            f.store
                .oidc_authorization_service(&f.d, &f.p)
                .complete(p.request(), ready, deadline())
                .await
                .unwrap_err(),
            expected
        );
        f.unchanged(&before).await;
    }
}
