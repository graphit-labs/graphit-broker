---
title: Running the native binary
references:
  - target: {type: knowledge, id: Rust_Copilot_one-shot_Knowledge_Ask, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6413, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# Running the native binary

Build the native Rust Broker executable through the maintained runner:

```text
cargo run --locked -p xtask -- build --debug
cargo run --locked -p xtask -- build --debug --output .build/native/graphit-broker
```

The default output is `graphit-broker` (`graphit-broker.exe` on Windows).
Omit `--debug` for Cargo's release profile. The builder honors
`CARGO_TARGET_DIR`, propagates Cargo/copy errors and never substitutes Go.
The output is staged beside its destination and renamed after a complete copy,
so absolute, symlink or hardlink aliases cannot truncate the source artifact.
Publishing replaces the destination directory entry; an output symlink becomes
a regular executable.
It requires Rust and the native compiler prerequisites; offline builds require
fetched locked dependencies. It does not publish an artifact automatically.
`make build` wraps the release-profile native builder; the existing Unix
`make install` packages it once, then uses the validated Unix installer to install
the complete selected payload into `PREFIX`, requesting privilege if needed.
Its temporary package is removed afterward; native assets and notices are retained.

## Produce an installer package locally

Use the maintained Rust runner on Linux amd64, macOS arm64 or Windows amd64:

~~~text
cargo run --release --locked -p xtask -- package --debug --output .build/installer-package
~~~

The output directory is explicit and must not exist. Choose a new destination for another build;
the command preserves an earlier package. Omit `--debug` for the existing release profile.
The package builder selects Cargo's native `host-tuple` explicitly, even when a cross target was
inherited, and takes the executable from [Cargo's artifact message](https://doc.rust-lang.org/cargo/reference/external-tools.html#artifact-messages)
after successful completion. It checks the executable's `--version` against the workspace version.
It does not change that version from a release tag or relabel another architecture's executable.
The normal `build` command still honors its configured target.

To package an executable already qualified on the current native host without invoking Cargo
for the server, select it explicitly:

~~~text
cargo run --release --locked -p xtask -- package --binary /path/to/qualified/graphit-broker --output /path/to/new/package
~~~

`--binary` and `--debug` are mutually exclusive. The input must be a regular executable file;
its `--version` must match the workspace version, exit successfully and write no stderr.
The caller supplies the prior host, architecture, source and runtime qualification: a version
check alone does not establish those facts. The packager modifies only staged copies: Linux adds a
relative RUNPATH; macOS rewrites external dylib references and applies an ad-hoc signature;
Windows retains the PE executable and stages its required DLLs. Manifests record input and
packaged SHA-256 without inventing source/build provenance. Keep the input stable during packaging; compare its SHA-256 with the manifest input digest
and verify the extracted executable digest and runtime behavior before distributing it. Keep source/build
provenance alongside the installer pair. The archive retains the repository's actual `LICENSE`
and the engine/binding, jsonhpp and NVIDIA redistribution notices.

The new directory contains exactly two files, with the actual native platform substituted:

- `graphit-broker-linux-amd64.tar.gz` and `graphit-broker-linux-amd64.sha256`; or
- `graphit-broker-darwin-arm64.tar.gz` and `graphit-broker-darwin-arm64.sha256`; or
- `graphit-broker-windows-amd64.tar.gz` and `graphit-broker-windows-amd64.sha256`.

Each archive contains `graphit-broker-<platform>/graphit-broker` (`graphit-broker.exe` on Windows)
with mode `0755`, plus regular
`0644` notices under `graphit-runtime/licenses/broker`.
The packager resolves the exact `llama-cpp-sys-2` source through locked offline
Cargo metadata before collecting its notices. Tar ownership/time and gzip time are
fixed so the same executable produces identical bytes. SHA-256 covers the complete compressed
archive; its sidecar line is `<64hex>  <archive-basename>\n`. Compression and hashing stream the
artifact. The complete pair is staged and closed before its directory is renamed into place;
build/version/write failures clean only the command's own staging directory.

This is the archive/path/checksum contract consumed by `install.sh`. On Linux, verify and extract
from the produced directory using `sha256sum -c graphit-broker-linux-amd64.sha256` and
`tar -xzf graphit-broker-linux-amd64.tar.gz`; on macOS use `shasum -a 256 -c` with its sidecar.
Run the extracted executable with `--version` before installing it. Configuration remains separate.
The installer downloads the pair from the selected GitHub tag, verifies it and replaces its
installed executable by staging/rename. To install an already-produced local pair without
network access, keep the adjacent checksum with the archive and run:

~~~sh
sh install.sh --archive .build/installer-package/graphit-broker-linux-amd64.tar.gz --dir "$HOME/.local/bin"
~~~

The `.sha256` path is derived by replacing `.tar.gz`; `--archive` and `--version`
(including `VERSION` from the environment) are mutually exclusive. Both local files
are copied to private staging before the same checksum, layout, native-component
and install checks used for a downloaded release. The archive still has to match
the current supported host platform. Generating this pair locally does not upload a release,
validate a hosted download, or deliver an independent native self-update command.

### Linux libraries and host requirements

Linux packages include the actual non-glibc ELF dependency closure under
`graphit-runtime/broker/lib`; the executable uses `$ORIGIN/graphit-runtime/broker/lib`
and bundled libraries use `$ORIGIN`. This includes `libstdc++` and `libgcc_s` for the
current executable. `graphit-runtime/broker/linux-libraries.json` records each input
and packaged digest, Debian binary/source package version, notice digests and required
GLIBC symbol versions. Notices include the GCC Runtime Library Exception and full GPL-3
text under `graphit-runtime/licenses/broker/linux`.

The maintained Linux package builder runs on Debian/Ubuntu with `patchelf`, `readelf`,
`dpkg-query` and the distribution's runtime copyright files. It resolves the closure
with the native ELF loader (allowing only the GPU driver to be absent on CUDA builders)
and rejects libraries without package/license provenance or resolving outside the bundle.
No client-side C++/GCC runtime installation or `LD_LIBRARY_PATH` is needed. Keep the
executable and its complete `graphit-runtime` directory together when relocating.
The OS still supplies glibc, libm, the ELF loader and optional NVIDIA driver. Required
GLIBC symbol versions come from the built artifacts, not a promise of compatibility
with older distributions. Packaging does not make this a fully static executable.

### macOS and Windows native runtimes

These producers use `scripts/package-platform-runtime.mjs` from the Code source
selected by Cargo
with the `graphit-runtime/broker` namespace. Node 22 and native inspection tools are
build prerequisites, not client runtime prerequisites. Neither changes the current
MSVC CRT selection or silently drops a dependency.

On macOS, `otool` and `lipo` verify arm64 Mach-O files. `/usr/lib` libraries (including
libc++) and `/System/Library` frameworks (including Accelerate) belong to macOS.
Required external OpenSSL 3 dylibs, if any, come from the explicit `OPENSSL_DIR`
distribution with its license, are copied to `graphit-runtime/broker/lib`, and use
`@loader_path` references rewritten with `install_name_tool`. Other external dylibs
fail packaging. The producer signs the modified files ad hoc and verifies them
with `codesign`. Native CI preserves linker flags and adds
`-Wl,-headerpad_max_install_names`, allowing relocatable load-command edits.
`graphit-runtime/broker/macos-libraries.json` records hashes, OS libraries and the
minimum macOS versions read from the actual Mach-O load commands. The `macos-15`
runner does not establish support for an earlier macOS release, notarization or a
hosted download's Gatekeeper behavior. Install with `install.sh`; preserve the
complete runtime beside the executable when moving it.

On Windows 10/11 amd64, `dumpbin` recursively checks the executable and every
redistributed DLL. Windows API/UCRT components remain OS-provided. Required release
VC143 CRT DLLs come from the explicit `VCToolsRedistDir/x64/Microsoft.VC143.CRT`
Visual Studio redistributable directory; optional OpenSSL 3 DLLs come from
`OPENSSL_DIR/bin`. Required DLLs are app-local next to `graphit-broker.exe`, with
hashes/origin in `graphit-runtime/broker/windows-libraries.json` and distribution
notices under `graphit-runtime/broker/licenses/windows-amd64`. Missing or unsupported
non-system DLLs fail packaging. No separate VC Redistributable installer is run.
The native build keeps `/MD` compatible with the C++ dependencies. OpenBLAS is no longer used.

Use `install.ps1 -Version vX.Y.Z`, or an offline checksum-verified package:

~~~powershell
./install.ps1 -Archive ./installer-package/graphit-broker-windows-amd64.tar.gz
~~~

The default is `%LOCALAPPDATA%/Programs/graphit-broker`, separate from Code's directory
to avoid app-local DLL collisions. `-Dir` overrides it. The installer checks the
complete regular-file layout, checksum and native manifest before installing all
sidecars and replacing the executable last. It preserves unrelated files and Code's
build receipt. If Windows refuses replacement of a file held by a running process,
close that process and repeat; the installer does not truncate loaded DLLs.
`make install` selects this installer on Windows and the Unix installer elsewhere.
The Make recipes require the existing POSIX shell/tools on the build host; the
PowerShell installer itself does not require them on the client.

CI prepares actual package/install/relocation and installed SQLite/configuration
journeys on Windows and macOS. `scripts/test-install.ps1` exercises the real Windows
package without downloads. Linux contract/syntax checks do not qualify either native
platform; their hosted jobs still have to run successfully.

### Cargo CUDA backend

CPU remains the default configuration. To include CUDA, use the normal Cargo
feature and preserve its successful artifact stream for packaging:

~~~sh
cargo build --release --locked -p broker-server --features cuda --bin graphit-broker --message-format=json-render-diagnostics > .build/broker-release-artifacts.jsonl
cargo run --release --locked --offline -p xtask -- package --binary target/release/graphit-broker --cargo-artifacts .build/broker-release-artifacts.jsonl --output .build/cuda-package
~~~

Use a supported NVIDIA toolkit/host compiler (Linux CI uses CUDA 12.9.1,
Ubuntu 24.04 and GCC13). The binding's `cuda-no-vmm` and `dynamic-link` features
build one shared engine through Cargo. The package includes that engine and
CUDA runtime/cuBLAS from the explicit `CUDA_PATH` toolkit under
`graphit-runtime/broker/lib`; relative loader paths make it relocatable.
The artifact stream must select the supplied binary and the resolved engine build.
VMM is disabled, allowing CPU startup without an NVIDIA driver. Actual GPU
inference requires a compatible host driver. CPU-only builds link the engine
statically and do not require `--cargo-artifacts` or a toolkit.
The former separately compiled GGML plugin/SDK and archive receipts are gone.
Engine/binding licenses come from Cargo's selected source; the package retains
both NVIDIA runtime and cuBLAS notices under `graphit-runtime/licenses/broker`.
This namespace and `graphit-runtime/broker` are independent of Code's runtime
and are preserved by Code self-update. No CUDA compiler or model weights are
distributed. Users need neither llama.cpp nor toolkit installation.

Code and Broker use `llama-cpp-sys-2`0.1.161 at binding revision
`424d1ffe6c1c4212d5da8e6075f473e33e35fb7f`, an unmerged utilityai update.
It includes unmodified official engine`620d2225cc436ab0b001e3200e590e3b286ef9ab`.
See [the exact Cargo build contract](https://github.com/graphit-labs/graphit-code/blob/main/docs/development/llama-cargo.md).
`cargo fetch --locked` prepares the binding and upstream engine submodule;
no Graphit engine downloader or SDK is used. libclang, CMake and a C++ compiler
are build prerequisites, not installed-client dependencies.

Embedding/rerank services still use the existing configuration, authorization,
discovery and endpoints. `search.rerank=false` remains default on consumers;
configuring a reranker does not execute it. CPU, explicit accelerator and auto
remain independent per model. Load/idle-unload, deadlines and cancellation are
unchanged. Windows/macOS and other GPUs require their own execution evidence.

Installer tests retain checksum, regular-file/confinement, required notices,
platform runtime closure and unrelated-file preservation. Native package tests
exercise the actual Cargo producer and supplied-binary path separately.

## Configure, run and probe

Supply the [native YAML, Ed25519 PKCS8 DER key and pepper](rust-broker-server.md).
Select PostgreSQL with its TLS CA, or [explicit private SQLite](rust-broker-server.md#select-private-sqlite)
with its path and three mandatory time budgets.
The earlier Go configuration is not accepted or imported. There is no
server mode that skips SQL and no generated production signing key.

```text
graphit-broker --config config.yaml --check-config
graphit-broker --config config.yaml
graphit-broker --version
graphit-broker --healthcheck http://127.0.0.1:8080/readyz
```

Run the executable from its actual output path or install it on PATH.
`--check-config` validates files/settings without SQL/listener startup.
Normal readiness requires the configured SQL store, runtime, volumes and listener.
Fix unavailable SQL, invalid key/CA, incompatible schema, unwritable storage or
occupied listener before restarting; config validation alone cannot prove readiness.

`--config` overrides `GRAPHIT_BROKER_CONFIG`; otherwise the home location is
`.graphit/broker/config.yaml`, relocated by `GRAPHIT_GLOBAL_DIR`.
Relative CA/key/storage and SQLite paths use the YAML parent. The runbook defines secret
expansion, bounds and all currently composed endpoints.

The standalone health client uses HTTP(S), its existing five-second timeout,
no redirects and a nonzero result for an unsuccessful probe. Do not combine
it with config/check-config. Remove an inherited `GRAPHIT_BROKER_CONFIG`
from that probe subprocess; the [container](deployment.md) already does so.
The main service keeps its configuration environment. SIGTERM/SIGINT request
the normal bounded, ordered shutdown described in the runbook.

## Artifact sources and qualification

The Broker lockfile pins the shared Graphit Code crates to an immutable Git
revision. Cargo fetches them along with the other dependencies. Packaging resolves
the runtime producer and license notices from the same locked sources via
`cargo metadata --locked --offline`.

The manual and stable-tag `Native qualification` workflow records the locked
Code revision and the Broker commit. The Linux, macOS and Windows native producers
build at those revisions. The release container uses the qualified Linux artifact.

Each platform's `code-source.txt` records the source repository/ref, both commits,
platform and the version read from its native executable. The artifacts are:

| Native runner | CI artifact | Contents |
|---|---|---|
| Ubuntu24.04 amd64 | `graphit-broker-linux-amd64-ci` | Executable, record and Linux pair under `installer-package/`. |
| macOS15 ARM64 | `graphit-broker-darwin-arm64-ci` | Record and Darwin pair under `installer-package/`. |
| Windows2022 AMD64 | `graphit-broker-windows-amd64-ci` | Record and Windows pair under `installer-package/`. |

The Darwin job uses the documented [`macos-15` ARM64 runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
asserts Darwin/arm64 and prepares native dependency inspection, package/installer,
relocation and installed configuration/SQLite checks. Windows prepares corresponding
native checks on `windows-2022` with app-local release CRT DLLs. Neither substitutes
a Linux executable, and neither native run has been executed or qualified here.

## Release assets and partial recovery

The tag workflow accepts an existing stable `vMAJOR.MINOR.PATCH` tag, matching
the active installer format (no prerelease or build metadata). Each native executable's actual version
must match the tag; the workflow never rewrites a manifest to match it.
Before any Release API mutation, the asset job checks the tag's resolved commit
against the qualified Broker commit, downloads all three platform artifacts into
separate directories, and verifies every record, checksum sidecar and archive.
Each tar must contain exactly its one nonempty regular `0755` executable entry.
All three complete pairs are mandatory. The publisher uses those CI bytes without
rebuilding or relabeling another host's output.

The maintained [GitHub CLI](https://cli.github.com/manual/gh_release_create)
queries the Release for that tag. Only a complete HTTP404 response takes the
creation path: `--verify-tag`, title equal to the tag, generated notes and all six
assets. Tag creation is never implicit. An existing Release receives
[`gh release upload`](https://cli.github.com/manual/gh_release_upload) with the six
qualified files; title, body, draft and prerelease state are preserved. There is
no `--clobber`, deletion or metadata edit. Existing asset names cause a clear
failure, including on a repeated workflow run. Authentication, transport,
malformed responses and other HTTP errors stop instead of creating a Release.
Only the asset job receives `contents: write`; the container retains its separate
image validation and package permissions.

GitHub asset upload is not atomic. After a failure, inspect the Release's state,
tag commit, asset names, downloaded bytes/checksums and the CI source records.
Preserve existing assets and metadata. With a complete verified local set from
that same qualified CI run, upload only the names that are absent, using
`gh release upload TAG MISSING_FILE... --repo OWNER/REPO` without `--clobber`.
Do not rerun the full four-file upload as a repair, change a tag, or delete and
replace a conflicting asset automatically. A different existing payload requires
an explicit operational decision. Preserve a draft left by a partial creation
until the operator decides its publication state.

Workflow definitions and local guards do not prove hosted builds, release uploads, native Darwin runtime or installer downloads. Hosted composition requires accessible published revisions of its dependencies.

[Native embeddings](rust-embeddings.md) compose four HTTP provider families or verified GGUF inference with current SQL authorization and persistent PostgreSQL/SQLite cache. GGUF uses an explicitly provisioned bundle, common typed manifest and GGUF weights; the executable does not download or extract them. Linux CPU execution does not establish GPU or native Windows/macOS execution.

| Remaining obligation | Required producer |
|---|---|
| macOS arm64 package/runtime qualification | Execute the prepared native CI producer on its real host, then qualify configuration/SQL operation. |
| Windows amd64 archive/runtime | Actual native Broker build, configuration/SQL execution and qualification. |
| Hosted release and installer download | Publish the expected pairs with matching tag/binary versions and coordinated Code provenance, then qualify the real download/install journey. |

First-administrator creation uses the [native stdin bootstrap](administration.md#first-local-administrator).
Backend and API/CLI work must follow its current functional contract; an old command
or a qualified library alone does not establish a missing product delivery.
Linux build/container qualification does not complete the Broker migration.
