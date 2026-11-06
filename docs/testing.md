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

Native CI restores locked Cargo sources separately from compiled artifacts.
Compiled cache keys bind the OS, architecture, Rust host/toolchain, runner image,
compiler/SDK and installed native library versions, build options, manifests,
lockfile and workflow. Only the final source revision component is dropped for a
compatible restore. Cargo still fetches the locked inputs, checks fingerprints,
and rebuilds changed sources. The cache includes Rust libraries, build-script
outputs (including native C/C++ outputs) and the actual Broker/xtask executables;
it excludes incremental state and test executables. No separate vcpkg or native
SDK cache is used by the ordinary workflow because it does not produce them.
Cargo may rebuild executable wrappers after restore; a cache hit does not
guarantee that every target is fresh.
Windows selects the x64 Visual Studio 2022 environment before probing `cl /Bv`;
the MSVC toolset, Windows SDK and UCRT versions must be nonempty to form a key.

The workflow prepares Clippy and test builds offline, then explicitly saves
compiled outputs before running the unchanged `xtask hook pre-push` gate. A
later test failure therefore does not discard reusable preparation. Cache hits
never skip formatting, Clippy, doctests or the parallel ordinary suite. SQL,
S3/STS, CUDA and installed-package qualifications remain separate. Cache misses
follow the same locked preparation and offline validation path. Measure source
preparation, compilation, cache transfer and test execution separately; a warm
local probe does not establish an end-to-end hosted-runner speedup.

When the `xtask` check executor launches Cargo, it removes its inherited `CARGO_PKG_*`,
`CARGO_MANIFEST_DIR` and `CARGO_MANIFEST_PATH` package identity from that child
command. Cargo supplies the identity of each package it builds. Forwarding the
launcher's identity can invalidate native dependencies that track those values
with `rerun-if-env-changed`, even when sources and compiler flags are unchanged.
Caller configuration, including target/cache paths and encoded Rust flags,
remains inherited. Direct CI preparation and checks launched by `cargo run`
therefore use the same package-identity inputs.

The Ubuntu 24.04 ordinary job reuses available C/C++/Make tools and CMake
3.28.3 or newer, preserving the former Ubuntu package floor. It checks the
native `libclang1-18` runtime, Clang 18 resource headers, OpenSSL development
package and `pkg-config` installation before asking APT for missing requirements.
Bindgen's retained `clang-sys` runtime supports the version-suffixed Clang C ABI
without Clang C API headers or a linker symlink. APT update/install runs only for a
nonempty missing-package list; tool/version/package checks still fail the step
when preparation does not supply a requirement. ABI keys retain the actual
CMake version even when CMake comes from the runner tool installation.

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
