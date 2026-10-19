//! Real owned PostgreSQL + genuine LOCAL login/cookie, never a seeded cookie proof.
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "shared genuine password/MFA fixture also serves other cookie contracts"
)]
mod cookie;
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixture includes helpers for other contracts"
)]
mod support;
use broker_control::{
    AdminBrokerSessionError, AdminReadAuthentication, AdminReadError, AdminReadKind,
    AdminReadLimits, AdminReadRequest, AdminReadResult, SystemAction,
};
use cookie::CookieFixture;
use serde_json::Value;
use sqlx_core::connection::Connection;
use sqlx_core::executor::Executor;
use std::time::{Duration, Instant};
use support::{deadline, n};

fn limits() -> AdminReadLimits {
    AdminReadLimits {
        authorization: cookie::limits().authorization,
        grants_json_bytes: n(65536),
        response_json_bytes: n(65536),
    }
}
async fn read<'a>(
    fixture: &CookieFixture,
    raw: &str,
    command: AdminReadRequest<'_>,
) -> Result<AdminReadResult<'a>, AdminReadError> {
    fixture
        .store
        .admin_reads(limits())
        .unwrap()
        .read(
            AdminReadAuthentication::Cookie {
                raw,
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            command,
            deadline(),
        )
        .await
}
async fn json(fixture: &CookieFixture, raw: &str, command: AdminReadRequest<'_>) -> Value {
    let response = read(fixture, raw, command).await.unwrap();
    response.check().unwrap();
    let value = serde_json::from_slice(response.body()).unwrap();
    response.check().unwrap();
    value
}
async fn action(fixture: &mut CookieFixture, action: SystemAction) {
    fixture
        .admin
        .execute("DELETE FROM public.role_permissions WHERE role='user'")
        .await
        .unwrap();
    sqlx_core::query::query("INSERT INTO public.role_permissions(role,action) VALUES('user',$1)")
        .bind(action.as_str())
        .execute(&mut fixture.admin)
        .await
        .unwrap();
}
async fn grant(
    fixture: &mut CookieFixture,
    id: &str,
    access: &str,
    principal: &str,
    capabilities: &[&str],
    projects: &[&str],
) {
    let now = cookie::micros();
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,$1,$2,$3,'',$4,$4)")
        .bind(id).bind(access).bind(principal).bind(now).execute(&mut fixture.admin).await.unwrap();
    for capability in capabilities {
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(capability)
        .execute(&mut fixture.admin)
        .await
        .unwrap();
    }
    for project in projects {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(project)
            .execute(&mut fixture.admin)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Docker owned PostgreSQL TLS fixture"]
async fn postgres_admin_projects_contract() {
    let mut fixture = CookieFixture::new().await;
    let issued = fixture.cookie().await;
    action(&mut fixture, SystemAction::ProjectsRead).await;
    let command = "graphit --non-interactive provider add 'organization-broker' --type broker --broker-endpoint 'https://broker.example.invalid'\n\ngraphit login --provider 'organization-broker' --profile 'organization-broker'";
    let initial = json(
        &fixture,
        issued.secret(),
        AdminReadRequest::Projects {
            provider_command: command,
        },
    )
    .await;
    assert_eq!(initial["projects"], serde_json::json!([]));
    assert_eq!(initial["all_projects"], false);
    assert!(initial["authorization_revision"].as_i64().unwrap() > 0);
    assert_eq!(initial["provider_command"], command);
    assert!(matches!(
        fixture
            .store
            .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
            .unwrap()
            .read(issued.secret(), deadline())
            .await,
        Err(broker_control::AdminCookieSessionError::Forbidden)
    ));
    let p = "01M1YEAE1WYMWG9KJKV1XQC4T4";
    let denied = "01KSH1CRFFG8Z74B5ZS78WW808";
    grant(
        &mut fixture,
        "one",
        "user",
        "alice",
        &["h*", "presence:read"],
        &[p],
    )
    .await;
    grant(
        &mut fixture,
        "two",
        "subject",
        "local|alice-subject",
        &["hub", "s3:read"],
        &[p],
    )
    .await;
    grant(&mut fixture, "all", "authenticated", "", &["hub"], &[]).await;
    grant(
        &mut fixture,
        "literal",
        "team",
        "engineer*",
        &["hub"],
        &[denied],
    )
    .await;
    grant(
        &mut fixture,
        "wrong-principal",
        "user",
        "someone-else",
        &["hub"],
        &[denied],
    )
    .await;
    grant(
        &mut fixture,
        "wrong-capability",
        "user",
        "alice",
        &["presence:read"],
        &[denied],
    )
    .await;
    let projected = json(
        &fixture,
        issued.secret(),
        AdminReadRequest::Projects {
            provider_command: command,
        },
    )
    .await;
    assert_eq!(projected["all_projects"], true);
    assert_eq!(
        projected["projects"],
        serde_json::json!([{"id":p,"capabilities":["h*","hub","presence:read","s3:read"]}])
    );
    // The LOCAL cookie holds an older profile; current SQL attributes must govern.
    fixture
        .admin
        .execute("UPDATE public.local_users SET organization='current-org' WHERE username='alice'")
        .await
        .unwrap();
    grant(
        &mut fixture,
        "old-profile",
        "organization",
        "org",
        &["hub"],
        &[denied],
    )
    .await;
    assert_eq!(
        json(
            &fixture,
            issued.secret(),
            AdminReadRequest::Projects {
                provider_command: command
            }
        )
        .await["projects"],
        projected["projects"]
    );
    fixture
        .admin
        .execute("REVOKE SELECT ON public.resource_grants FROM admin_cookie_owner")
        .await
        .unwrap();
    assert!(matches!(
        read(
            &fixture,
            issued.secret(),
            AdminReadRequest::Projects {
                provider_command: command
            }
        )
        .await,
        Err(AdminReadError::Projection(AdminReadKind::Projects))
    ));
    fixture
        .admin
        .execute("GRANT SELECT ON public.resource_grants TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        json(
            &fixture,
            issued.secret(),
            AdminReadRequest::Projects {
                provider_command: command
            }
        )
        .await["projects"],
        projected["projects"]
    );
    fixture
        .admin
        .execute("UPDATE public.resource_grants SET access_kind='unknown' WHERE id='literal'")
        .await
        .unwrap();
    assert!(matches!(
        read(
            &fixture,
            issued.secret(),
            AdminReadRequest::Projects {
                provider_command: command
            }
        )
        .await,
        Err(AdminReadError::Projection(AdminReadKind::Projects))
    ));
    // Grant metadata is deliberately not compiled into policy to authorize GET.
    action(&mut fixture, SystemAction::GrantsRead).await;
    let metadata = read(&fixture, issued.secret(), AdminReadRequest::Grants)
        .await
        .unwrap();
    assert!(metadata.revision().unwrap() > 0);
    assert!(
        serde_json::from_slice::<Value>(metadata.body()).unwrap()["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["access"] == "unknown")
    );
    action(&mut fixture, SystemAction::UsersRead).await;
    assert!(matches!(
        read(
            &fixture,
            issued.secret(),
            AdminReadRequest::Projects {
                provider_command: command
            }
        )
        .await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    action(&mut fixture, SystemAction::ProjectsRead).await;
    fixture
        .admin
        .execute("UPDATE public.resource_grants SET access_kind='team' WHERE id='literal'")
        .await
        .unwrap();
    let escaped_command = "literal 'quoted' \"command\"\n\\end";
    let exact = read(
        &fixture,
        issued.secret(),
        AdminReadRequest::Projects {
            provider_command: escaped_command,
        },
    )
    .await
    .unwrap()
    .body()
    .len();
    for (bytes, allowed) in [(exact, true), (exact - 1, false)] {
        let mut bounded = limits();
        bounded.response_json_bytes = n(bytes);
        let result = fixture
            .store
            .admin_reads(bounded)
            .unwrap()
            .read(
                AdminReadAuthentication::Cookie {
                    raw: issued.secret(),
                    limits: cookie::limits(),
                    policy: cookie::policy(),
                    upstream: None,
                },
                AdminReadRequest::Projects {
                    provider_command: escaped_command,
                },
                deadline(),
            )
            .await;
        assert_eq!(
            result.is_ok(),
            allowed,
            "exact JSON bound includes escapes and all_projects=true"
        );
    }
    let projects: Vec<String> = (0..128).map(|i| format!("{}{:04}", &p[..22], i)).collect();
    let mut capabilities: Vec<String> = (0..128).map(|i| format!("cap-{i:03}")).collect();
    capabilities.push("hub".into());
    let project_refs: Vec<&str> = projects.iter().map(String::as_str).collect();
    let capability_refs: Vec<&str> = capabilities.iter().map(String::as_str).collect();
    grant(
        &mut fixture,
        "expanded",
        "authenticated",
        "",
        &capability_refs,
        &project_refs,
    )
    .await;
    // Snapshot remains below its independent 64KiB cap. Its P×C output is
    // rejected by the response budget during accumulation, before expansion.
    let mut bounded = limits();
    bounded.response_json_bytes = n(8192);
    assert!(matches!(
        fixture
            .store
            .admin_reads(bounded)
            .unwrap()
            .read(
                AdminReadAuthentication::Cookie {
                    raw: issued.secret(),
                    limits: cookie::limits(),
                    policy: cookie::policy(),
                    upstream: None
                },
                AdminReadRequest::Projects {
                    provider_command: command
                },
                deadline()
            )
            .await,
        Err(AdminReadError::Projection(AdminReadKind::Projects))
    ));
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires Docker owned PostgreSQL TLS fixture"]
async fn postgres_admin_rbac_read_contract() {
    let mut fixture = CookieFixture::new().await;
    let issued = fixture.cookie().await;
    action(&mut fixture, SystemAction::RolesRead).await;
    let initial = json(&fixture, issued.secret(), AdminReadRequest::Assignments).await;
    assert_eq!(
        initial,
        serde_json::json!({"assignments":[],"bootstrap_only":true})
    );
    fixture.admin.execute("INSERT INTO public.roles(name,created_at) VALUES('custom',0); INSERT INTO public.role_permissions(role,action) VALUES('custom','*'); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('https://identity.example.invalid|external','custom',0)").await.unwrap();
    let assignments = json(&fixture, issued.secret(), AdminReadRequest::Assignments).await;
    assert_eq!(
        assignments,
        serde_json::json!({"assignments":[{"subject":"https://identity.example.invalid|external","role":"custom","created_at":"1970-01-01T00:00:00Z"}],"bootstrap_only":false})
    );
    // Assignment subjects are literal VARCHAR(512) DATA, not raw LOCAL IDs.
    // Preserve all 512 Unicode characters even when their UTF-8 exceeds 512 bytes.
    let unicode = "é".repeat(512);
    let ascii = "x".repeat(512);
    for subject in [
        unicode.as_str(),
        ascii.as_str(),
        "without-separator",
        "  literal whitespace  ",
    ] {
        sqlx_core::query::query(
            "INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,'custom',0)",
        )
        .bind(subject)
        .execute(&mut fixture.admin)
        .await
        .unwrap();
    }
    let literal = json(&fixture, issued.secret(), AdminReadRequest::Assignments).await;
    for subject in [
        unicode.as_str(),
        ascii.as_str(),
        "without-separator",
        "  literal whitespace  ",
    ] {
        assert!(
            literal["assignments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["subject"] == subject)
        );
    }
    let roles = json(&fixture, issued.secret(), AdminReadRequest::Roles).await;
    assert_eq!(roles["actions"].as_array().unwrap().len(), 9);
    assert!(
        !roles["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "*")
    );
    assert_eq!(
        roles["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "custom")
            .unwrap()["permissions"],
        serde_json::json!(["*"])
    );
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Users).await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    fixture
        .admin
        .execute(
            "INSERT INTO public.role_permissions(role,action) VALUES('custom','unknown.action')",
        )
        .await
        .unwrap();
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Roles).await,
        Err(AdminReadError::Projection(AdminReadKind::Roles))
    ));
    fixture.admin.execute("DELETE FROM public.role_permissions WHERE action='unknown.action'; REVOKE SELECT ON public.role_assignments FROM admin_cookie_owner").await.unwrap();
    // The authorization observer also needs assignments: a failure there keeps
    // the authorization error distinct from an endpoint projection failure.
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Assignments).await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Control(_)
        ))
    ));
    fixture
        .admin
        .execute("GRANT SELECT ON public.role_assignments TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        json(&fixture, issued.secret(), AdminReadRequest::Assignments).await["bootstrap_only"],
        false
    );
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires Docker owned PostgreSQL TLS fixture"]
async fn postgres_admin_user_read_contract() {
    let mut fixture = CookieFixture::new().await;
    let issued = fixture.cookie().await;
    action(&mut fixture, SystemAction::UsersRead).await;
    let now = cookie::micros();
    sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('automation','service-subject','service','','','','','[]',0,0,2,$1,$1),('bob','bob-subject','human','fixture-phc-must-not-be-selected','','','','[]',0,1,3,$1,$1)")
        .bind(now).execute(&mut fixture.admin).await.unwrap();
    // Deliberately opaque target DATA: this read reports factor presence and
    // never authenticates/decrypts a factor or manufactures a cookie proof.
    sqlx_core::query::query("INSERT INTO public.local_mfa(subject,secret_ciphertext,last_totp_step,confirmed_at) VALUES('bob-subject','fixture-ciphertext-must-not-be-selected',0,$1)")
        .bind(now).execute(&mut fixture.admin).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|bob-subject','admin',$1)").bind(now).execute(&mut fixture.admin).await.unwrap();
    fixture.admin.execute("REVOKE SELECT ON public.local_users FROM admin_cookie_owner; GRANT SELECT(username,subject,identity_kind,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) ON public.local_users TO admin_cookie_owner; REVOKE SELECT ON public.local_mfa FROM admin_cookie_owner; GRANT SELECT(subject) ON public.local_mfa TO admin_cookie_owner; REVOKE SELECT ON public.local_mfa_recovery_codes FROM admin_cookie_owner").await.unwrap();
    let users = json(&fixture, issued.secret(), AdminReadRequest::Users).await;
    let rows = users["users"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|u| u["username"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["alice", "automation", "bob"]
    );
    assert_eq!(rows[0]["teams"], serde_json::json!(["engineering"]));
    assert_eq!(rows[1]["kind"], "service");
    assert_eq!(rows[1]["enabled"], false);
    assert_eq!(rows[1]["roles"], serde_json::json!(["user"]));
    assert!(rows[1].get("teams").is_none());
    assert!(rows[1].get("name").is_none());
    assert_eq!(rows[2]["roles"], serde_json::json!(["admin", "user"]));
    assert_eq!(rows[2]["mfa_enabled"], true);
    assert_eq!(rows[2]["password_change_required"], true);
    for row in rows {
        assert!(row["revision"].as_i64().unwrap() > 0);
        chrono::DateTime::parse_from_rfc3339(row["created_at"].as_str().unwrap()).unwrap();
        chrono::DateTime::parse_from_rfc3339(row["updated_at"].as_str().unwrap()).unwrap();
    }
    let text = users.to_string();
    for forbidden in [
        "password_hash",
        "secret_ciphertext",
        "code_hash",
        "$argon2id$",
        "must-not-be-selected",
    ] {
        assert!(!text.contains(forbidden));
    }
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Principals).await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    action(&mut fixture, SystemAction::GrantsRead).await;
    let principals = json(&fixture, issued.secret(), AdminReadRequest::Principals).await;
    assert_eq!(
        principals["principals"][0],
        serde_json::json!({"type":"anonymous","id":"anonymous"})
    );
    assert_eq!(
        principals["principals"][1],
        serde_json::json!({"type":"authenticated","id":"authenticated"})
    );
    assert_eq!(
        principals["principals"][3],
        serde_json::json!({"type":"local","id":"service-subject","username":"automation"})
    );
    assert_eq!(
        principals["principals"][4],
        serde_json::json!({"type":"local","id":"bob-subject","username":"bob"})
    );
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Users).await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    fixture
        .admin
        .execute("UPDATE public.local_users SET teams_json='invalid-json' WHERE username='bob'")
        .await
        .unwrap();
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Principals).await,
        Err(AdminReadError::Projection(AdminReadKind::Principals))
    ));
    fixture
        .admin
        .execute("UPDATE public.local_users SET teams_json='[]' WHERE username='bob'")
        .await
        .unwrap();
    assert_eq!(
        json(&fixture, issued.secret(), AdminReadRequest::Principals).await["principals"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires Docker owned PostgreSQL TLS fixture"]
async fn postgres_admin_grant_read_contract() {
    let mut fixture = CookieFixture::new().await;
    let issued = fixture.cookie().await;
    action(&mut fixture, SystemAction::GrantsRead).await;
    let initial = read(&fixture, issued.secret(), AdminReadRequest::Grants)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(initial.body()).unwrap()["rules"],
        serde_json::json!([])
    );
    assert!(initial.revision().unwrap() > 0);
    grant(
        &mut fixture,
        "raw",
        " unknown ",
        " literal* ",
        &[" h* ", "hub"],
        &[],
    )
    .await;
    fixture
        .admin
        .execute("UPDATE public.resource_acl_state SET revision=9223372036854775807 WHERE id=1")
        .await
        .unwrap();
    let result = read(&fixture, issued.secret(), AdminReadRequest::Grants)
        .await
        .unwrap();
    assert_eq!(result.revision(), Some(i64::MAX));
    let document: Value = serde_json::from_slice(result.body()).unwrap();
    assert_eq!(document["v"], 1);
    assert_eq!(document["revision"].as_i64(), Some(i64::MAX));
    assert_eq!(document["rules"][0]["access"], " unknown ");
    assert_eq!(document["rules"][0]["principal"], " literal* ");
    assert_eq!(
        document["rules"][0]["capabilities"],
        serde_json::json!([" h* ", "hub"])
    );
    assert!(document["rules"][0].get("projects").is_none());
    assert!(document["rules"][0].get("access_kind").is_none());
    chrono::DateTime::parse_from_rfc3339(document["updated_at"].as_str().unwrap()).unwrap();
    fixture
        .admin
        .execute("REVOKE SELECT ON public.grant_capabilities FROM admin_cookie_owner")
        .await
        .unwrap();
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Grants).await,
        Err(AdminReadError::Projection(AdminReadKind::Grants))
    ));
    fixture
        .admin
        .execute("GRANT SELECT ON public.grant_capabilities TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        json(&fixture, issued.secret(), AdminReadRequest::Grants).await["revision"].as_i64(),
        Some(i64::MAX)
    );
    fixture
        .admin
        .execute("UPDATE public.resource_acl_state SET updated_at=9223372036854775807 WHERE id=1")
        .await
        .unwrap();
    assert!(matches!(
        read(&fixture, issued.secret(), AdminReadRequest::Grants).await,
        Err(AdminReadError::Projection(AdminReadKind::Grants))
    ));
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires Docker owned PostgreSQL TLS fixture"]
async fn postgres_admin_config_authorization_contract() {
    let mut fixture = CookieFixture::new().await;
    let issued = fixture.cookie().await;
    action(&mut fixture, SystemAction::ConfigurationRead).await;
    // Public DATA supplied to the SQL authorization consumer. The server suite
    // separately qualifies the actual typed deployment projection and canaries.
    let yaml = "fixture_public_data: 'literal'\n";
    assert_eq!(
        json(
            &fixture,
            issued.secret(),
            AdminReadRequest::Configuration { yaml }
        )
        .await,
        serde_json::json!({"source":"deployment","restart_required":true,"yaml":yaml})
    );
    assert!(matches!(
        read(
            &fixture,
            issued.secret(),
            AdminReadRequest::Projects {
                provider_command: ""
            }
        )
        .await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    let mut cap = limits();
    cap.response_json_bytes = n(1);
    assert!(matches!(
        fixture
            .store
            .admin_reads(cap)
            .unwrap()
            .read(
                AdminReadAuthentication::Cookie {
                    raw: issued.secret(),
                    limits: cookie::limits(),
                    policy: cookie::policy(),
                    upstream: None
                },
                AdminReadRequest::Configuration { yaml },
                deadline()
            )
            .await,
        Err(AdminReadError::Projection(AdminReadKind::Configuration))
    ));
    fixture
        .admin
        .execute("REVOKE SELECT ON public.role_permissions FROM admin_cookie_owner")
        .await
        .unwrap();
    assert!(matches!(
        read(
            &fixture,
            issued.secret(),
            AdminReadRequest::Configuration { yaml }
        )
        .await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Control(_)
        ))
    ));
    fixture
        .admin
        .execute("GRANT SELECT ON public.role_permissions TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        json(
            &fixture,
            issued.secret(),
            AdminReadRequest::Configuration { yaml }
        )
        .await["source"],
        "deployment"
    );
    action(&mut fixture, SystemAction::UsersRead).await;
    assert!(matches!(
        read(
            &fixture,
            issued.secret(),
            AdminReadRequest::Configuration { yaml }
        )
        .await,
        Err(AdminReadError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    fixture.close().await;
}

async fn locked_pid(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock' AND query LIKE '%octet_length(u.username)%'")
            .fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "protected read must reach observed SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn closed_pid(admin: &mut sqlx_postgres::PgConnection, pid: i32) {
    let end = deadline();
    loop {
        let exists: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
        if !exists {
            return;
        }
        assert!(
            Instant::now() < end,
            "unconfirmed read connection must close physically"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual administrative read COMMIT ACK withholding, expiry priority, exact PostgreSQL PID and cancellation"]
async fn postgres_admin_projects_uncertainty_contract() {
    let mut fixture = CookieFixture::new().await;
    let cookie = fixture.cookie().await;
    fixture.admin.execute("INSERT INTO public.roles(name,created_at) VALUES('all-reads',0); INSERT INTO public.role_permissions(role,action) VALUES('all-reads','*'); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','all-reads',0)").await.unwrap();
    for request in [
        AdminReadRequest::Projects {
            provider_command: "literal",
        },
        AdminReadRequest::Roles,
        AdminReadRequest::Assignments,
        AdminReadRequest::Users,
        AdminReadRequest::Principals,
        AdminReadRequest::Grants,
        AdminReadRequest::Configuration {
            yaml: "public: true\n",
        },
    ] {
        let mut relay = commit::CommitRelay::new(fixture.fixture.port).await;
        let owner = broker_control::PostgresControlStore::open(
            cookie::config(&fixture.fixture, relay.port),
            cookie::digester(),
            deadline(),
        )
        .await
        .unwrap();
        let short = fixture.cookie().await;
        let hash = fixture
            .digester
            .token(
                broker_security::TokenKind::AdminSession,
                short.secret().as_bytes(),
            )
            .unwrap();
        let expires_at = cookie::micros() + 2_000_000;
        sqlx_core::query::query(
            "UPDATE public.admin_sessions SET expires_at=$1 WHERE token_hash=$2",
        )
        .bind(expires_at)
        .bind(hash.to_sql_hex())
        .execute(&mut fixture.admin)
        .await
        .unwrap();
        let expected_count = fixture.count().await;
        let reader = owner.admin_reads(limits()).unwrap();
        let mut locker = fixture.fixture.connection().await;
        locker
            .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let pid;
        {
            let pending = reader.read(
                AdminReadAuthentication::Cookie {
                    raw: short.secret(),
                    limits: cookie::limits(),
                    policy: cookie::policy(),
                    upstream: None,
                },
                request,
                Instant::now() + Duration::from_secs(3),
            );
            tokio::pin!(pending);
            pid = tokio::select! {pid=locked_pid(&mut fixture.admin)=>pid,result=&mut pending=>panic!("actual protected read must reach SQL lock: {:?}",result.err())};
            relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            locker.execute("ROLLBACK").await.unwrap();
            loop {
                let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("actual COMMIT reply must be withheld: {:?}",result.err())};
                let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                    "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
                )
                .bind(pid)
                .fetch_one(&mut fixture.admin)
                .await
                .unwrap();
                if query == "COMMIT" && idle && fixture.count().await == expected_count {
                    decision.send(false).unwrap();
                    break;
                }
                decision.send(true).unwrap();
            }
            assert!(matches!(
                pending.await,
                Err(AdminReadError::Authorization(
                    AdminBrokerSessionError::Control(
                        broker_control::ControlError::OutcomeUncertain
                    )
                ))
            ));
            assert!(
                cookie::micros() >= expires_at,
                "uncertain COMMIT retains priority after actual cookie expiry"
            );
        }
        closed_pid(&mut fixture.admin, pid).await;
        assert_eq!(
            fixture.count().await,
            expected_count,
            "unknown read never renews/replays a cookie"
        );
        locker.close().await.unwrap();
        relay.close().await;
        owner.shutdown(deadline()).await.unwrap();
        assert!(
            read(
                &fixture,
                cookie.secret(),
                AdminReadRequest::Projects {
                    provider_command: "recovery"
                }
            )
            .await
            .is_ok()
        );
    }
    // Cancellation while an observed statement is blocked must also close its
    // exact physical connection, preserving the original cookie and healthy pool.
    let mut locker = fixture.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let reader = fixture.store.admin_reads(limits()).unwrap();
    let pid;
    {
        let pending = reader.read(
            AdminReadAuthentication::Cookie {
                raw: cookie.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminReadRequest::Roles,
            deadline(),
        );
        tokio::pin!(pending);
        pid = tokio::select! {pid=locked_pid(&mut fixture.admin)=>pid,result=&mut pending=>panic!("cancel target must reach real SQL lock: {:?}",result.err())};
    }
    closed_pid(&mut fixture.admin, pid).await;
    locker.execute("ROLLBACK").await.unwrap();
    locker.close().await.unwrap();
    assert!(
        read(&fixture, cookie.secret(), AdminReadRequest::Roles)
            .await
            .is_ok()
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual observed SQL locks, Original deadline and a ready negative after genuine cookie expiry"]
async fn postgres_admin_read_temporal_contract() {
    let mut fixture = CookieFixture::new().await;
    let cookie = fixture.cookie().await;
    action(&mut fixture, SystemAction::RolesRead).await;
    let owner = fixture.store.clone();
    let reader = owner.admin_reads(limits()).unwrap();
    let mut locker = fixture.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let pid;
    {
        let pending = reader.read(
            AdminReadAuthentication::Cookie {
                raw: cookie.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminReadRequest::Roles,
            Instant::now() + Duration::from_millis(300),
        );
        tokio::pin!(pending);
        pid = tokio::select! {pid=locked_pid(&mut fixture.admin)=>pid,result=&mut pending=>panic!("Original case must reach real SQL lock: {:?}",result.err())};
        assert!(matches!(
            pending.await,
            Err(AdminReadError::Authorization(
                AdminBrokerSessionError::Control(broker_control::ControlError::Deadline)
            ))
        ));
    }
    closed_pid(&mut fixture.admin, pid).await;
    locker.execute("ROLLBACK").await.unwrap();
    assert!(
        read(&fixture, cookie.secret(), AdminReadRequest::Roles)
            .await
            .is_ok()
    );

    action(&mut fixture, SystemAction::SessionRead).await;
    let expiring = fixture.cookie().await;
    let hash = fixture
        .digester
        .token(
            broker_security::TokenKind::AdminSession,
            expiring.secret().as_bytes(),
        )
        .unwrap();
    sqlx_core::query::query("UPDATE public.admin_sessions SET expires_at=$1 WHERE token_hash=$2")
        .bind(cookie::micros() + 2_000_000)
        .bind(hash.to_sql_hex())
        .execute(&mut fixture.admin)
        .await
        .unwrap();
    // SessionRead alone deliberately cannot grant RolesRead. The SQL negative
    // becomes ready only after the genuine cookie's captured expiry.
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        let pending = reader.read(
            AdminReadAuthentication::Cookie {
                raw: expiring.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminReadRequest::Roles,
            Instant::now() + Duration::from_secs(8),
        );
        tokio::pin!(pending);
        let pid = tokio::select! {pid=locked_pid(&mut fixture.admin)=>pid,result=&mut pending=>panic!("expiry case must reach real SQL lock: {:?}",result.err())};
        // Deliberately do not poll the protected future while Exp passes.
        tokio::time::sleep(Duration::from_millis(2200)).await;
        locker.execute("ROLLBACK").await.unwrap();
        let end = deadline();
        loop {
            let ready: bool = sqlx_core::query_scalar::query_scalar(
                "SELECT state='idle in transaction' FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(pid)
            .fetch_one(&mut fixture.admin)
            .await
            .unwrap();
            if ready {
                break;
            }
            assert!(
                Instant::now() < end,
                "negative SQL reply must be ready before final poll"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(matches!(
            pending.await,
            Err(AdminReadError::Authorization(
                AdminBrokerSessionError::Authentication(
                    broker_control::BrokerAccessError::InvalidToken
                )
            ))
        ));
    }
    locker.close().await.unwrap();
    action(&mut fixture, SystemAction::RolesRead).await;
    assert!(
        read(&fixture, cookie.secret(), AdminReadRequest::Roles)
            .await
            .is_ok()
    );
    fixture.close().await;
}
