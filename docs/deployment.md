---
title: Deployment
references:
  - target: {type: knowledge, id: Rust_Copilot_one-shot_Knowledge_Ask, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6413, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# Deployment

Configure the Rust Broker with [native PostgreSQL or explicit private SQLite](rust-broker-server.md). The image runs the same executable and preserves its key, authentication and storage contracts. GGUF CPU inference requires explicitly provisioned GGUF model files. Native process tests do not establish container, GPU, other-platform or hosted-publication support.

## Build and configure the native image

```text
cargo run --locked -p xtask -- build --debug
cargo run --release --locked -p xtask -- package --binary ./graphit-broker --output installer-package
docker build -t graphit-broker:local .
```

Omit `--debug` for a release-profile build. Packaging uses the existing executable;
choose a new output directory or remove only a previous generated package first.
The Dockerfile extracts `installer-package/graphit-broker-linux-amd64.tar.gz` and
copies its complete layout, including native notices and runtime libraries.
Ubuntu24.04 supplies its base runtime libraries; the maintained
`buildpack-deps:noble-curl` stage supplies the OS CA bundle required by the HTTP
client. Model weights are provisioned separately; the image contains the native GGUF runtime.
The shell remains available for operator startup hooks.

A CUDA-enabled package includes its Cargo-built engine and CUDA user-space runtime beside the executable;
see [Cargo CUDA backend](binary.md#cargo-cuda-backend). Supply the
host NVIDIA driver and NVIDIA Container Toolkit separately and start the container
with `--gpus all`. Model execution still follows the configured CPU/CUDA/auto choice;
enabling this build feature does not enable rerank or force GPU inference. A CPU-only
package needs no CUDA installation. This layout contract is separate from actual
GPU container execution, which must be validated on the deployment hardware.

The runtime user is `graphit:graphit` (UID/GID10001), with working directory
`/home/graphit/.graphit/broker`. That protected directory and
`/var/lib/graphit/hub` are declared volumes with matching ownership.
Supply a regular native config readable by UID10001 at
`/home/graphit/.graphit/broker/config.yaml`, plus its real key and CA files.
There is no embedded operational YAML, old-schema importer or no-SQL smoke mode.

After provisioning `/srv/graphit-broker` and its files for UID/GID10001, for example:

```text
docker run --rm --name graphit-broker -p 127.0.0.1:8080:8080 --mount type=bind,src=/srv/graphit-broker,dst=/home/graphit/.graphit/broker --mount type=volume,src=graphit-hub,dst=/var/lib/graphit/hub graphit-broker:local
```

Set `server.address: 0.0.0.0:8080` in that namespace and configure the public
HTTPS origin separately. Database DNS must resolve inside the container and
match its TLS trust. PostgreSQL remains an external configured service, with no
implicit SQLite file. Select explicit native storage directories when using the
Hub volume. Protect private configuration/key/pepper files and grant UID10001
only the volume access it needs. Supply any referenced secrets through the
container environment or protected configuration; startup does not create login credentials.

Bind the host port to loopback when a reverse proxy owns public TLS. Preserve
the original host/scheme and exact configured upstream browser callback.
Use the native [OIDC](oidc.md), [authorization](authorization.md) and server
contracts for policy; container startup does not grant administrators.

## Probe, recover and shut down

The image sets `GRAPHIT_GLOBAL_DIR=/home/graphit/.graphit`,
`GRAPHIT_BROKER_CONFIG=/home/graphit/.graphit/broker/config.yaml` and
`GRAPHIT_BROKER_HEALTHCHECK_URL=http://127.0.0.1:8080/readyz`.
Change the probe URL when changing the listener. The probe removes only the
config variable from its subprocess to preserve the CLI conflict contract;
normal service startup keeps it.

`/healthz` reports liveness. `/readyz` becomes ready after productive startup
and is cleared during shutdown; it is not a new continuous SQL-health policy.
The native HTTP(S) probe has a five-second timeout and follows no redirects.

```text
docker exec graphit-broker env -u GRAPHIT_BROKER_CONFIG /usr/local/bin/graphit-broker --healthcheck http://127.0.0.1:8080/readyz
docker stop graphit-broker
```

Missing/unreadable config, inaccessible bootstrap directories or failed hooks
produce nonzero startup. Valid configuration still needs reachable TLS SQL and
usable storage. Fix the dependency and restart; do not weaken TLS or add fallback.
The entrypoint execs the native process as PID1, so SIGTERM and SIGINT reach its
normal admission/drain/SQL-close lifecycle and configured shutdown budget.

## Local Linux user service

The Broker is an independently operated server. A local installation can use the
existing systemd user manager with the same native executable and configuration.
Keep its executable at a stable installation path; the native builder documented
in [Running the native binary](binary.md) publishes `--output` through a staged
copy, fsync and rename. Preserve a private backup when replacing a qualified
installed executable. Building is separate from starting the service.

For the private `.graphit-rust` installation, prepare
`graphit-broker-rust.service` with the following contents:

```ini
[Unit]
Description=Graphit Broker Rust

[Service]
Type=simple
ExecStart=%h/.graphit-rust/bin/graphit-broker --config %h/.graphit-rust/broker/config.json
Restart=on-failure

[Install]
WantedBy=default.target
```

The configuration filename is an operator choice; its contents still follow the
[native configuration contract](rust-broker-server.md#supply-configuration-and-key-files).
Retain the existing SQLite database, keys, issuer, accounts, grants and listener.
The service manager runs the server directly and delivers its normal shutdown
signals. The Code `daemon install` command manages Code's daemon and has no
Broker service installation mode.

Validate a staged unit and the stable executable before the coordinated cutover.
The relative staging path below is resolved from the operator's workspace:

```sh
systemd-analyze --user verify .build/activation-broker-service/graphit-broker-rust.service
"$HOME/.graphit-rust/bin/graphit-broker" --config "$HOME/.graphit-rust/broker/config.json" --check-config
```

Run verification from the user's manager session with its real
`XDG_RUNTIME_DIR`. `--check-config` opens no SQL pool or listening socket.
These checks do not install or start the unit, or qualify startup at login or
after reboot.

The operator coordinates the consumer stop and the old Broker's SIGTERM/join
before installing and starting the unit. After that handoff, the existing OS
commands are:

```sh
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$unit_dir"
install -m 600 .build/activation-broker-service/graphit-broker-rust.service "$unit_dir/graphit-broker-rust.service"
systemctl --user daemon-reload
systemctl --user enable --now graphit-broker-rust.service
env -u GRAPHIT_BROKER_CONFIG "$HOME/.graphit-rust/bin/graphit-broker" --healthcheck http://127.0.0.1:34461/readyz
```

The probe uses the existing readiness route and avoids the CLI conflict with an
inherited configuration environment variable. A successful configuration or unit
check does not substitute for this real startup/readiness observation. Qualify
login and reboot behavior separately. Any ordering dependency for a Code daemon
using this local Broker belongs to that installation's OS configuration; a Code
installation may instead use a remote Broker.

## Operator hooks

Mount hooks read-only at `/docker-entrypoint.d`, outside the data volume.
`init.d` runs before directory/config checks; `pre-start.d` runs after checks,
immediately before the executable. Files run in filename order as UID/GID10001.
Readable regular `.sh` files use `/bin/sh`; other regular files need execute
permission and an available interpreter. Missing/empty directories do nothing.
Invalid types/permissions or a nonzero exit stop startup and preserve failure status.

Hooks run on every entrypoint invocation, including version/config-check commands;
make them repeatable. Child exports cannot change the parent environment.
Use mounted files or container environment for persistent values. Keeping hooks
outside the data volume preserves them when data is replaced.

## Verify the actual container

```text
cargo test --locked --offline -j4 -p broker-server --test container -- --ignored --exact broker_native_container_contract --test-threads=1
```

This existing xtask pre-push phase builds the real Dockerfile in an owned temporary
context and runs its actual executable with the maintained PostgreSQL TLS
NOSUPERUSER fixture, native config and keys. It checks UID/volumes, missing config,
health/readiness/actual image probe, hooks/order/failures, blocked directories,
PID1, SIGTERM/SIGINT, restart and cleanup of owned resources. There is no synthetic
health service or weakened SQL trust. The test is not compiled away on other
platforms: missing Linux-image/host-network support fails the actual fixture
rather than reporting an empty successful qualification. Only Linux execution
is recorded here.

Set `GRAPHIT_BROKER_CONTAINER_IMAGE` to validate an already built image with the
same command. The Linux publisher does that before registry login/push; local tests
never publish. The same xtask gate retains every SQL/HTTP/STS/revocation phase.
CI also runs formatting, strict Clippy, checksum-verified actionlint and the maintained frontend check.
Workflow syntax is also checked by the active pre-commit hook.

## CI source and release provenance

Configure `GRAPHIT_CODE_REPOSITORY` and `GRAPHIT_CODE_REF` with an accessible source containing
the current `graphit-ai`, `graphit-http` and `graphit-core` crates and their locked Cargo dependencies. Reusable/manual CI also accepts
`code_repository` and `code_ref`. Missing values stop the job before checkout/build; no repository
or branch is silently selected. Values must be nonempty and have no surrounding whitespace. A private source may use `GRAPHIT_CODE_READ_TOKEN` with read access.
Checkout credentials are not persisted.

Each Cargo job uses sibling `graphit-broker`/`graphit-code` checkouts. Before Cargo, the source guard requires the manifests of `graphit-ai`, `graphit-http` and `graphit-core`, plus `crates/graphit-ai/licenses/NVIDIA-CUDA-LICENSE`. Use the complete Code checkout at the configured revision.
Linux builds its CUDA backend through the same locked Cargo dependency and the `broker-server/cuda` feature.
Its CI job provisions the CUDA compiler and development libraries, then the native
Cargo builder compiles the same engine with CUDA enabled. It does not install a host NVIDIA driver or claim GPU
execution on a runner without GPU hardware. The real GGUF consumer gate requires
explicit provisioned model bundles. Configuration/model files remain explicit at
service runtime.

The Linux artifact `graphit-broker-linux-amd64-ci` carries the executable,
`code-source.txt` and installer pair under `installer-package/`. Linux CI resolves
the actual Code/Broker commits; the container and native Darwin/Windows package jobs
reuse those exact commits. Records include platform and the actual executable
version. The container verifies its record/checksum and tag/version before the
existing image/lifecycle check; Docker's context remains the Broker root.

The tag workflow also prepares the [automatic installer asset producer](binary.md#release-assets-and-partial-recovery).
An existing stable tag must match the native versions and qualified Broker
commit. Linux amd64, Darwin arm64 and Windows amd64 pairs are required and independently
verified before any Release mutation. The archive validator requires the executable
and six native notices as regular nonempty files, Linux library provenance or the
native macOS/Windows runtime manifest and its exact library digests. Unknown paths, duplicate entries, links, unexpected modes
and platform prefixes are rejected. The Darwin producer runs on the documented
native `macos-15` ARM64 host; its manifest records the actual Mach-O minimum OS version.
The Windows producer uses `windows-2022`, MSVC's release CRT redistributable directory,
the Cargo native engine and the same qualified Code/Broker commits. Both jobs exercise the
installed package and SQLite/configuration consumers. Their source is prepared but
native execution remains unqualified until those jobs actually run.
Release absence is classified only from a complete HTTP404 response. Creation
uses the existing tag, tag title and generated notes. Existing Releases retain
their title/body/draft/prerelease state; uploads never overwrite or delete assets.
Conflicts fail. Partial upload recovery preserves verified existing files and
manually sends only absent names, as described in that runbook.

Code CI's reverse dependency separately requires an explicit compatible
`GRAPHIT_BROKER_REF`. Neither direction can use an invented remote ref for
unpublished local changes. A real accessible Rust Code revision remains necessary for hosted composition;
its Cargo lock selects the maintained forks from the published Libs revision. No hosted build, native Darwin
execution, asset upload/download, registry push or release publication was
executed in this workflow preparation. Linux process/container results do not
establish other-platform runtime or full Broker parity.


Native release executables use Cargo Release with Thin LTO, one codegen unit and
`strip = "symbols"`; static symbol/name tables and debug information are omitted
from the distributed executable. Dynamic exports and native library linkage are
preserved. `xtask build` uses Release unless `--debug` is explicitly selected;
release CI uses the default optimized path.

The native container gate consumes the same real installer archive as Docker.
`GRAPHIT_BROKER_CONTAINER_PACKAGE` selects an explicit existing Linux package;
`GRAPHIT_BROKER_CONTAINER_IMAGE` selects an already-built image. Without either,
`xtask` packages the `graphit-broker` binary produced by the preceding build into
an owned temporary directory, passes that archive to the container test, and
removes the temporary package after the check. It does not rebuild the executable
for packaging. A direct container-test invocation defaults to
`installer-package/graphit-broker-linux-amd64.tar.gz` and reports a missing package
before attempting the image build.
