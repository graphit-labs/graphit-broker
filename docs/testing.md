# Testing boundaries

The ordinary Broker suite is self-contained after locked dependency preparation.
It does not require Docker, PostgreSQL/MySQL services, a model download, a vendor
account, an installed Broker, or a Graphit Code application checkout or executable.
Cargo still builds the shared Rust libraries pinned in `Cargo.lock`.

```sh
cargo fetch --locked
cargo test --locked --offline --workspace --all-targets --no-fail-fast
node scripts/check-admin-ui.cjs
```

Keep the default test runner parallel. SQLite databases, signing material, model
HTTP peers, filesystem payloads, installation roots and subprocess environments
belong to each fixture. A deliberately short request budget belongs only to the
blocked/deadline scenario; successful recovery uses the ordinary request budget.
Drive submitted operations with their first poll before cancelling them or
closing the store. Continue polling pending work together with shutdown so the
native owner can be released. Sleeps are not admission barriers.

Readiness probes may poll, but each HTTP attempt is bounded by the fixture's
original startup deadline. SQL infrastructure qualifications also bound their
Docker command processes and reap them on timeout. Their standard IO uses
private temporary files, so large SQL input and simultaneous stdout/stderr do
not deadlock full pipes. Container cleanup ownership is captured before create,
including a client timeout or lost startup acknowledgement.

## Reviewed suite boundaries

| Area | Ordinary coverage | Explicit additional qualification |
| --- | --- | --- |
| `broker-control` | Private SQLite, identity/ACL, local password/MFA, flows, caches, authorization and cancellation | PostgreSQL/MySQL TLS, live SQL admission and extended protocol journeys |
| `broker-presence` | Loopback HTTP/WebSocket peers, private SQLite, service contracts and instruction draft/publish/CAS/reopen/authentication | Live SQL, S3/STS credentials and model-backed journeys |
| `broker-server` | Real workspace executable, configuration, disabled/HTTP model services, assets and device login | Installed/relocated binaries, extended LOCAL MFA/browser and SQL/container journeys |
| `broker-storage` | Native filesystem/configuration and isolated SDK endpoint model tests | Authenticated SQL plus real S3/STS and filesystem gateway journeys |
| `broker-security` | Actual local HMAC, AEAD, Argon2, credential framing and TOTP/recovery checks | No external account required |
| `broker-store` | Schema constraints and bounded child-process lifecycle | PostgreSQL/MySQL images with native schema and mutation assertions |
| `broker-now-wire` | Closed serialization and identity/protocol contracts | Covered by explicit composed realtime journeys |
| `xtask` | Check selection, failure propagation and small local Cargo fixture workspaces | Native build/package/install and infrastructure orchestration |
| Administration UI | Syntax plus actual instruction-controller draft/activation, deferred response, conflict, read-only and session-change tests | Interactive visual/keyboard checks against an authenticated Broker |
| Workflows/installers | Local workflow lint; Unix installer fixtures with checksums and private destinations | Native Windows/macOS installation and distribution tests |

The device authorization tests start the actual Broker on loopback against a
private SQLite database and use the pinned `NativeOAuth` Rust SDK. They exercise
server-issued codes/tokens, consent, MFA and rejection paths without invoking the
Graphit Code CLI or building that application's workspace. A separate Code login
consumer qualification is not substituted for this Broker server boundary.

## Administration instructions

`node scripts/check-admin-ui.cjs` checks the entire shipped inline JavaScript and
runs the Node-native instruction-controller tests. The controller tests use local
DOM objects and deferred promises; they prove editor state and response ordering,
not cookie or SQL authorization. The real HTTP tests in
`crates/broker-presence/tests/sqlite_admin_session_http.rs` cover authentication
before JSON consumption, CSRF, current role removal, activation validation,
concurrent revision conflicts, persisted reopen and corrupt-file rejection.

The `Native CI` administration job and the staged-path UI hook use that same
entry point. `scripts/test-admin-instructions.cjs` changes also select the UI
hook. Visual inspection remains a separate check: a passing Node or HTTP test
is not a screenshot, keyboard or accessibility qualification.

## Explicit external and distribution checks

Keep tests marked with a documented `#[ignore]` reason available through
`make qualify` and `.github/workflows/qualification.yml`. They retain real SQL,
S3/STS, HTTP, packaging, model and GPU coverage. Their prerequisites must be
prepared deliberately; absence is not a passing result. The ordinary CI uses
`cargo fetch --locked` followed by offline checks on Linux, macOS and Windows;
release packaging is handled separately by `release.yml`.

For local installer fixtures, run `python3 scripts/test-install.py`. The
PowerShell/native relocated-installation tests must run on their corresponding
platforms. Reuse passing native CI evidence only for unchanged code and record
the exact source revision for any new run. A local dirty checkout is not covered
by an earlier remote result.
