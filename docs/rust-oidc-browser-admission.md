---
type: document
title: Native initial browser authorization admission
description: Confirmed PostgreSQL admission and protected protocol rejections before the public browser journey.
doc_type: reference
references:
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7db9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7568, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native initial browser authorization admission

A server browser adapter can distinguish a genuine pending request from a known
protocol rejection whose destination has been validated against the current
client. The Rust Control producer uses the existing [P2 authorization policy](rust-oidc-authorization.md)
and PostgreSQL transaction boundaries. This Control producer itself mounts no HTTP route. The
[public browser transport](rust-oidc-browser-authorization.md) consumes its sealed API.

## Call and consume

```text
store.browser_oidc_authorizations(&policy)
    .admit_browser(OidcAuthorizationInput<'a>, original: Instant)
    -> Result<BrowserOidcAuthorization<'a>, OidcAuthorizationError>

BrowserOidcAuthorization::Pending(Box<PendingOidcAuthorization>)
BrowserOidcAuthorization::Rejected(RejectedOidcAuthorization<'a>)

rejected.code() -> OidcAuthorizationRejectionCode
rejected.into_target() -> OidcAuthorizationResponseTarget<'a>
```

Pending is the same genuine P2 result, produced by the shared private INSERT and
COMMIT implementation. It carries the zeroizing request secret, persisted pending
DATA and existing expiry. It is not a login or an authorization code.

Rejected has no public constructor, Clone or Serialize implementation. Debug is
redacted. The code is closed, and the destination is borrowed from the admitted
request. The target exposes the literal redirect, state, canonical mode and parsed
origin. These are transport DATA, never identity or grant authority. Call its
`check()` before and after constructing a response; the renderer must not replace
the literal redirect with the parsed origin.

| Existing semantic error | Rejection code |
|---|---|
| InvalidRequest | invalid_request |
| InvalidScope | invalid_scope |
| LoginRequired | login_required |
| InvalidTarget | invalid_target |

Other errors remain Err. In particular, an invalid or missing client, invalid or
changed redirect, malformed stored client, read cap, credential/RNG failure, SQL
failure, expired deadline or uncertain COMMIT cannot release a protected rejection.
An error from the direct P2 `create` API is not evidence of a safe redirect.

## Admission order

1. Derive one effective Original from the caller deadline and existing operation
   budget. Apply existing scalar/aggregate bounds and the existing 512-byte state cap.
2. For canonical form_post only, reject NUL, CR and LF in state before acquiring a
   SQL connection. Query/Fragment keep the literal bytes; direct P2 is unchanged.
3. Read the current client using the bounded existing reader and READ COMMITTED
   transaction. Its dynamic-client query retains FOR SHARE. Admit the literal
   redirect using the established Web exact match or NativeLoopback rules.
4. Apply the full P2 policy. Success uses the shared pending insertion path. A
   closed semantic rejection confirms the read transaction's COMMIT before
   constructing its sealed result. All final gates retain that same Original.

The active response-mode rule is preserved: explicit fragment and form_post select
those modes; absent, empty and unknown values select Query. The existing SDK still
maps unsupported response types to InvalidRequest. This producer does not loosen
P2's nonempty state/nonce, S256 PKCE, resource, scope or prompt policy.

## State and lifetime

A rejection preserves every admitted nonempty state literally, including whitespace.
An empty state represents an omitted parameter for the future HTTP response, as
specified by [RFC 6749 section 3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1).
The future renderer must echo a present state exactly and must not redirect on an
invalid client or redirect, following [section 4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1).
The producer itself does not render a response.

An initial rejection has only its effective Original. It has no invented pending
row, UTC expiry, new TTL or retained server holder. It cannot extend the caller's
request. A target obtained from a genuine pending observation retains both its
existing UTC expiry and monotonic cutoff, as in the [shared upstream callback](rust-oidc-browser-callback.md).

COMMIT ACK uncertainty is local even for a read-only effect: the transaction uses
READ COMMITTED, and a rejected response is not released when PostgreSQL has become
idle after COMMIT but the TLS reply is withheld. No retry is disguised as a
conclusive OAuth denial.

## Validation

The recurring portable invocation is:

```text
cargo test --locked --offline -j4 -p broker-control --test postgres_oidc_authorization -- --ignored --test-threads=1
```

It runs the existing P2 contract plus Browser admission and read COMMIT-ACK
uncertainty contracts against owned PostgreSQL TLS with a NOSUPERUSER role. The
Browser test compares full request/client snapshots after semantic rejection,
checks both protocol destinations and local failures, holds real client locks to
prove pre-SQL rejection, and changes registration while admission waits. A valid
request returns a genuine loadable pending result. The TLS relay observes actual
COMMIT-idle state before withholding the reply; no fabricated storage success is
used. Unit tests independently preserve Original, UTC and monotonic gates, and
rustdoc rejects construction, serialization and cloning of sealed outputs.

The versioned xtask pre-push phase runs this invocation before audit. Its isolated
Cargo failure oracle makes each selected real Rust test fail and proves later
phases stop. Linux execution qualifies Linux only; the command is portable but
Windows/macOS execution remains part of final integration.
