---
references:
  - target: {type: task, id: tsk-6414, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-e52a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5df1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Public PROJECT JWT integration fixture

Audience: native Auth/Core integration test maintainers. This Rust example serves
the [actual PROJECT JWT endpoint](rust-broker-project-authorization-http.md)
over an ordinary NOSUPERUSER PostgreSQL TLS store. It supplies a real
SDK-signed access JWT and matching public JWKS through private JSON-lines IPC.
It provides no OAuth provider, discovery metadata or authenticated-proof DTO.
The [Broker access issuer](rust-broker-access-issuer.md) now validates the dev
fixture PKCS#8 key, derives public JWKS and signs typed access claims; rcgen
remains test-only. Start, the exact 13-field Ready and HTTP/SQL behavior stay
the same. The issuer input is cryptographic data, not grant admission.

## Run and capture the fixture

Requirements: Rust/Cargo and the Docker daemon used by the existing PostgreSQL
TLS native fixture. From the Broker workspace:

~~~text
cargo run --locked -j1 -p broker-presence --example project_authorization_fixture
~~~

Keep stdin open; send exactly one Start object and wait for Ready before HTTP.
All fields below are required and captured as supplied, with no inferred issuer,
resource, client, scope or project. The following values are synthetic examples:

~~~json
{"command":"start","issuer":"https://broker.example.test","api_audience":"native-api","resource":"https://broker.example.test/v1","client_id":"web-client","subject":"native-subject","scope":"","project_ids":["01D39ZY06FGSCTVN4T2V9PKHFZ"],"access_ttl_seconds":600}
~~~

Start and subsequent commands must be JSON objects; missing, duplicate or unknown
fields, wrong types, positional arrays and trailing JSON are rejected through
the Serde SDK. project_ids must be nonempty and unique, and each project must
pass the actual authorizer's canonical nonzero ULID validation. The explicit
test-only access TTL must be positive and fit the actual signed time checks.
This does not change the production OP TTL of 10 minutes by default, configurable
from 1 minute to 1 hour. scope may be empty; it is still a typed, signed and
validated claim.

Ready contains exactly event, authorize_endpoint, issuer, api_audience, resource,
client_id, subject, scope, project_ids, required_scopes, access_bearer,
trusted_jwks and expires_at. event is ready; required_scopes is explicitly [].
authorize_endpoint is the full real loopback POST URL:
http://127.0.0.1:<actual-port>/v1/project/access/authorize. The remaining metadata
matches the supplied setup and actual signer. expires_at is signed UTC seconds.
access_bearer is the raw JWT, without the Bearer prefix; trusted_jwks contains
only the matching public Ed25519 key. Keep Ready and credentials in transient
private IPC memory; never log or persist the credential or private signer.

Configure the PROJECT backend with the exact endpoint from Ready, independently
of issuer/API audience/resource. Do not append a path to issuer or invent a
discovery extension. The existing Graphit HTTP transport needs explicit
allow_loopback_http=true and a captured origin for this IP-loopback endpoint;
redirects remain disabled. localhost is not interchangeable with IP loopback.
OAuth issuer transport can retain its own captured origin. The Auth consumer
must verify the signed JWT through its actual SDK/trusted key path and retain
the registered Web client/resource binding; Ready is data, never authority.

## Exercise current PROJECT authorization

Send the [strict three-field body](rust-broker-project-authorization-http.md)
to authorize_endpoint with Authorization: Bearer <access_bearer>.
The fixture seeds one SQL subject rule matching the captured canonical Broker
issuer/sub pair and the supplied project IDs, with eight independent task,
memory, knowledge and ast read/write capabilities. Glob metacharacters in the
identity are escaped as literals; the actual policy SDK still compiles and
matches the selector. Actual authorizer calls validate all eight pairs before
Ready. Client integrations must compare the returned canonical pair and exact
requested operation, and bind local project version separately where required.

The server authenticates the JWT locally until exp and reads ACL from SQL on
each call. It configures required_scopes=[] for the current Graphit consumer;
there is no invented project authorization OAuth scope. The JWT scope string,
signature, issuer, audiences, time, use and client claims are still validated.
An explicit scope requirement in another deployment does not create an ACL
grant. No token/user SQL row or UserInfo call supplies this JWT's validity.

Send a command and await its acknowledgement before the next HTTP observation:

| JSON command | Committed effect |
| --- | --- |
| {"command":"deny_access"} | Remove the entire fixture grant, including its projects and capabilities; next valid request returns 403 forbidden. |
| {"command":"allow_access"} | Recreate the captured principal, projects and all eight capabilities in one grant; next valid request returns 200. |
| {"command":"corrupt_policy"} | Insert an unrelated malformed project selector; whole policy returns 503 invalid_policy. |
| {"command":"restore_policy"} | Remove that malformed rule; valid requests return 200 when allowed. |
| {"command":"shutdown"} | Close listener, shared store, control connection and owned PostgreSQL container before Ack. |

Every normal Ack is exactly {"event":"ack","command":"<command>","ok":true}.
ACL controls commit whole changes and increment the current policy revision
before Ack. They affect subsequent decisions, not responses already in progress.
There is no fake immediate token revocation command: access expires according
to its signed time. Shutdown Ack follows cleanup; await process exit as well.
The consumed PostgreSQL fixture shutdown requires the actual Docker removal
command to succeed. A removal failure cannot produce a successful shutdown Ack;
RAII remains available for cleanup on failure.
EOF also cleans up but produces no shutdown Ack; initial EOF creates nothing.
A repeated Start or invalid command exits with failure after normal cleanup.
Failures report only static redacted diagnostics on stderr.

## Qualification

~~~text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-presence --example project_authorization_fixture project_authorization_fixture_postgres_contract -- --ignored --test-threads=1
~~~

The native example contract checks real TCP/JWT/ordinary SQL TLS, all eight
operations, deny/allow plus fresh revision, whole invalid policy/recovery and
closed listener. Public binary IPC qualification exercises Start/Ready,
control Ack ordering, shutdown, EOF and invalid input, checking actual process
exit/listener/container cleanup without logging credentials.
Historical e52a qualification on Linux, before the issuer change, passed
17 Presence fast tests and 76 Control
fast tests for the shared helper, four Presence rustdocs, formatting and strict
Clippy. The native contract passed in 69.413 seconds. Public IPC passed shutdown
(20 real HTTP calls, six output events), EOF (no shutdown Ack), invalid command
(exit 1, no Ack) and initial EOF (no setup or output). Sanitized receipts are in
.build/rust-broker-project-authorization-fixture-2026-10-11/.

Current tsk-6414 qualification on Linux passed 85 Control fast tests (including
nine issuer SDK tests), 57 Control rustdocs, 17 Presence fast tests and four
Presence rustdocs. After a test-only assertion helper changed, the affected
nine issuer tests were rerun successfully; product code and the fixture were
unchanged. Final formatting and strict Clippy passed. The actual native
PostgreSQL TLS/TCP contract passed in 37.782 seconds. Public IPC passed all
four cases: shutdown with 20 HTTP calls and six events (24.404 seconds), EOF
without shutdown Ack (4.078 seconds), invalid input with exit 1 and no Ack
(5.654 seconds), and initial EOF with no setup/output (0.148 seconds). All
listeners closed; successful shutdown Ack followed confirmed cleanup.
Sanitized receipts and preserved compile/lint failures are in
.build/rust-broker-access-issuer-2026-10-11/. No raw bearer is retained there.

These checks qualify the fixture; the Auth PROJECT consumer, OAuth provider,
full application startup and Windows/macOS need their own integration evidence.

Source: crates/broker-presence/examples/project_authorization_fixture.rs.
See the [HTTP wire/error/deadline contract](rust-broker-project-authorization-http.md)
and [local JWT authentication/expiry window](rust-broker-access-jwt.md).
