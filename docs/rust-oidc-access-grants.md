---
type: document
title: PostgreSQL OIDC stored access grant data in Rust
description: Read one native OIDC grant, optional dynamic registration and current local user without conferring authority.
references:
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5ff3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-463c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-7442, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# PostgreSQL OIDC stored access grant data in Rust

Server maintainers can read one native stored OIDC access grant on the existing
[PostgreSQL control pool](rust-postgres-control.md). The result contains SQL
metadata, a stored principal, optional dynamic registration and optional
current local user attributes. Receiving these data does not authenticate a
bearer, recognize a client or grant permission.

The Rust access JWT authentication contract is local until expiry, using trusted signature keys,
issuer, audience, time, type, client and resource checks. Discovery/JWKS caching
and rotation belong to that verifier. This DATA reader is not a mandatory SQL,
UserInfo or revocation check on every HTTP request. Revocation, disabled accounts
and changed claims may be observed only after access expiry. Current PROJECT
authorization remains separate; a JWT does not itself confer PROJECT permission.
The JWT verifier is a separate delivery; this reader does not implement it.
OIDC login, PKCE, state, nonce, ID token and refresh flows remain separate producers.

## API and input

~~~text
PostgresControlStore::oidc_access_grants(json_bytes: NonZeroUsize)
  -> Result<PostgresOidcAccessGrants<'_>, OidcAccessGrantReadError>

PostgresOidcAccessGrants::read(
  &self,
  digest: &CredentialDigest,
  deadline: std::time::Instant,
) -> Result<Option<OidcAccessGrantSnapshot>, OidcAccessGrantReadError>
~~~

The reader borrows its store. A caller needing this lookup computes the actual
digest with TokenKind::OidcStoredAccess and the access ID/JTI bytes. The digest
has no inspectable domain or possession proof. A digest parsed from SQL hex is
also metadata and cannot establish authentication.

Lookup binds the canonical hash and selects native kind oidc_access.
Missing rows and incompatible access/service/refresh rows return Ok(None).
The native writer must produce oidc_access; there is no alias, importer or format
conversion. This fits the existing epoch2 schema.

## Snapshot and principal

OidcAccessGrantSnapshot exposes immutable data through getters:

| Getter | Meaning |
| --- | --- |
| token_id() | Stored access ID/JTI, distinct from input digest. |
| subject() | Original underlying identity subject. |
| oidc_subject() | Stored stable Broker subject; no derivation from original identity. |
| client_id(), audience(), resource() | Literal stored metadata, without recognition. |
| scopes() | Raw SQL strings, preserving spaces, order, duplicates and empties. |
| local_user_revision(), family_id() | Stored revision and possibly empty family identifier. |
| auth_time(), expires_at(), created_at() | Nonnegative UTC microseconds. |
| revoked_at() | None for SQL NULL; Some(0) is present revocation metadata. |
| stored_principal() | StoredOidcPrincipal with literal attributes. |
| current_local_user() | Option<&OidcCurrentLocalUser>, only for a local principal. |
| dynamic_registration() | Option<&OidcDynamicClientRegistration>. |

Zero timestamps, expired grants and revoked grants can return successfully.
No password, MFA secret, raw token, token hash, consumed timestamp or usage
timestamp is returned. The read never updates usage or consumes/revokes a grant.
Snapshot, stored principal, current user, registration and reader Debug are redacted.

Native principal JSON requires an object with issuer/subject/username/auth_method
strings and integer local_user_revision. Optional name/email/organization/
role_claim_selector are strings; teams/scopes/roles are arrays of strings;
roles_from_claim is a boolean. Optional absence and explicit null yield None.
Present empty strings/arrays and false remain present. Required null/absence,
wrong types, duplicates, unknown fields, root arrays and trailing JSON fail.

Issuer is nonempty, already trimmed and free of NUL. LOCAL username is canonical;
LOCAL subject is nonempty, already trimmed, free of NUL and at most 512 UTF8 bytes.
Federated mapped subject/username retain H1 literal bytes, including Unicode and
external spaces, while remaining nonempty after trim, NUL-free and within the
configured document/SQL read limits. They are not subjected to LOCAL 512-byte or
ASCII rules. JSON subject and revision must equal token columns. The separate
`oidc_subject` holds the native HMAC pseudonym; reading it does not authenticate it.
See [federated grants](rust-oidc-federated-grants.md).
Local issuer local requires positive revision and local-token or service-credential
method. A nonlocal issuer requires oidc method and explicit revision zero.
This checks stored coherence; it does not verify issuer URL/current configuration,
claims, signature, roles or role selectors.

Token ID, stable OIDC subject, client ID and audience are nonempty canonical
strings up to 128 UTF8 bytes. Family ID allows empty, otherwise the same 128-byte
contract. Resource retains its natural SQL 512-character limit including empty.
All timestamps use the existing nonnegative TimestampMicros contract.

## Current local user and dynamic registration

One SELECT LEFT JOINs local_users by subject and oauth_dynamic_clients by client ID
inside READ COMMITTED READ ONLY. Grant and joined data share one statement snapshot.

For local principals, current user exposes username, subject, identity kind,
enabled, name, email, organization, raw teams and revision. Mutable current
attributes do not come from stale JSON. Missing/changed subject yields None;
disabled users and changed revisions remain Some with actual values. Kind is
human or service, enabled exactly 0/1, revision positive; username/subject use
existing canonical helpers. Name/email/organization retain natural SQL character
limits, Unicode and empty values. Raw teams preserve values. A kind differing
from the stored authentication method remains data.

Federated principals return no current local user, even when a local row shares
their original subject. Stored attributes do not establish trusted current
federation configuration.

Dynamic registration contains exactly client ID, client name, redirect URI array,
scope array, Native/Web application type and creation timestamp. Client name
allows empty and natural SQL 256-character limit. Arrays retain literal strings,
order, duplicates and empties; no URL/scope recognition. Missing registration is
None even with a present grant. No static fallback or invented enabled/revision/
issuer/resource/secret fields. Consumers needing recognition use their operation's
actual client catalog/configuration.

## Limits, errors and lifecycle

Explicit nonzero JSON cap must fit isize and i64; no default. It applies per field
to principal, grant scopes, applicable local teams, dynamic redirects and dynamic
scopes. SQL OCTET_LENGTH/CASE withholds oversize text before transfer. Equality is
accepted; excess fails without truncated success. Arrays must contain strings;
null/CSV are invalid. No aggregate/count quota or array cleanup.

| Error | Meaning |
| --- | --- |
| InvalidLimits | Explicit cap cannot be represented. |
| ReadLimitExceeded | Applicable JSON exceeds physical byte cap. |
| MalformedStored | Selected JSON/scalars/timestamps/client type/coherence invalid. |
| Control(Storage) | Real SQL failure including denied SELECT, not empty result. |
| Control(Deadline) | Original caller deadline or existing operation budget exhausted. |
| Control(Closed) | Store admission closed. |
| Control(OutcomeUncertain) | COMMIT began but outcome unknown; no automatic replay. |

Original Instant is bounded by operation budget without reset. Existing connection
guard/transaction ownership handles errors and cancellation; connection confirmed
only after COMMIT. No cache, repair, retry or duplicate authentication query.

## Qualification

Native command uses existing pinned PostgreSQL Docker TLS fixture and ordinary
NOSUPERUSER application account:

~~~text
cargo test --locked -j1 -p broker-control --test oidc_access_grant postgres_oidc_access_grant_contract -- --ignored --test-threads=1
~~~

Affected commands:

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
~~~

Native test covers actual digests, local/federated data, registration/current
changes, corruption, each JSON cap, denied SELECT, observed SQL locks with
original deadline, task cancellation/pool recovery, closed admission and read-only
SQL oracle. Current execution evidence is Task tsk-5ff3 and private
.build/rust-oidc-access-grants-2026-10-11/ artifacts. Definition alone is not a pass.
Broader OP/HTTP/PROJECTWeb/product/platform integration remains with Main; no
formal SQL-cancellation or COMMIT-disconnect fault proof is claimed.

On Linux, the affected qualification passed 61 fast tests and 45 rustdocs, fmt
and strict Clippy. The real PostgreSQL test passed (162.508 seconds command wall,
161.46 seconds test runtime), including the observed lock/deadline/cancellation
and recovery cases. Historical compile and lock-oracle failures remain in the
qualification artifacts; they were corrected and rerun, not treated as passes.
The eight protected files remained unchanged; shared existing code received
module/exports only and PostgreSQL navigation retained its original prefix.
