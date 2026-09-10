# Running the native binary

GitHub releases publish the same native platform matrix as Graphit Code:

| Archive | Host | Embedded inference runtime |
|---|---|---|
| `graphit-broker-linux-amd64.tar.gz` | Linux x86-64 | ONNX Runtime CPU + CUDA provider |
| `graphit-broker-darwin-arm64.tar.gz` | macOS Apple Silicon | ONNX Runtime CPU + integrated CoreML |
| `graphit-broker-windows-amd64.tar.gz` | Windows x86-64 | ONNX Runtime CPU + CUDA provider |

Each archive contains one self-contained broker executable and the example configuration. There is
no adjacent native-library directory:

```text
graphit-broker-linux-amd64/
├── graphit-broker
└── config.example.yaml
```

Model weights are deliberately absent. Startup downloads CodeRankEmbed only when embeddings are
enabled with `upstream.protocol: onnx`, and downloads BGE only when rerank is enabled with `upstream.protocol: onnx`.
Custom models are selected through each service’s `upstream.model` and loaded from manifest bundles in the
persistent model directory. See the [model catalog](models.md) for `on_demand`, `setup`, and `never`
installation modes.

## Download and verify

Choose a release tag instead of `latest` for reproducible installation:

```bash
VERSION=v1.0.0
curl -fLO "https://github.com/graphit-labs/graphit-broker/releases/download/${VERSION}/graphit-broker-linux-amd64.tar.gz"
curl -fLO "https://github.com/graphit-labs/graphit-broker/releases/download/${VERSION}/graphit-broker-linux-amd64.sha256"
sha256sum -c graphit-broker-linux-amd64.sha256
tar -xzf graphit-broker-linux-amd64.tar.gz
./graphit-broker-linux-amd64/graphit-broker --version
```

Use `shasum -a 256 -c` on macOS. Windows users can verify the archive with
`Get-FileHash -Algorithm SHA256` and compare it with the published `.sha256` file.

## Embedded runtime extraction

The matching ONNX Runtime files are compressed inside the executable. Every invocation performs
a cheap completion-marker read plus a `stat` of each required file. On first execution, or when the
embedded build changes, the broker verifies the embedded payload and installs it atomically at:

```text
~/.graphit/broker/runtime/onnxruntime/<ort-version>/<os>-<arch>/<bundle-sha256>/
```

It extracts into a private sibling directory and renames only a complete, fsynced installation;
concurrent broker processes converge on the same immutable directory. Later starts do not hash the
native library and do not read or decompress the embedded payload. The `broker` namespace keeps
these files outside Graphit Code's independently managed `~/.graphit/runtime` directory.

Set `GRAPHIT_GLOBAL_DIR` to move the entire Graphit global directory. An absolute value is used as
given; a relative value is resolved from the broker's startup directory:

```bash
GRAPHIT_GLOBAL_DIR=/var/lib/graphit ./graphit-broker --version
```

`ONNXRUNTIME_SHARED_LIBRARY_PATH` remains an expert override. When set, it selects that exact
operator-managed library and suppresses extraction of the embedded runtime.

## Install and configure

Configure `authentication.token_pepper` with at least 32 secret-manager bytes. On an empty SQL
database, create the first local administrator interactively. The command requires a TTY, disables
terminal echo, asks for confirmation, and accepts no username or password argument:

```bash
graphit-broker --config /etc/graphit-broker/config.yaml --bootstrap-admin
```

Unattended provisioning must use the explicit stdin mode. Feed it from a secret manager or a
permission-restricted mounted file; never put the plaintext password in argv or an environment
variable:

```bash
cat /run/secrets/broker-password | \
  graphit-broker --config /etc/graphit-broker/config.yaml --bootstrap-admin-stdin
```

The command hashes with the configured pepper, persists only the Argon2id verifier, creates fixed
username/subject `admin`, assigns `admin`, and refuses passwords shorter than 15 Unicode
characters or a database that already contains a local user. Further users and role changes belong
to the administration UI/API.

This example creates a dedicated service identity and persistent directories:

```bash
sudo useradd --system --home /var/lib/graphit-broker --shell /usr/sbin/nologin graphit-broker
sudo install -d -o graphit-broker -g graphit-broker -m 0700 \
  /etc/graphit-broker /var/lib/graphit-broker /var/lib/graphit-broker/.graphit \
  /var/cache/graphit-broker/models
sudo install -d -o root -g root -m 0755 /opt/graphit-broker
sudo cp -a graphit-broker-linux-amd64/. /opt/graphit-broker/
sudo install -o graphit-broker -g graphit-broker -m 0600 \
  graphit-broker-linux-amd64/config.example.yaml /etc/graphit-broker/config.yaml
```

Edit `/etc/graphit-broker/config.yaml`. Keep the SQLite DSN under
`/var/lib/graphit-broker`, the model catalog under `/var/cache/graphit-broker/models`, and
provider secrets in a root-readable environment file rather than command-line arguments.

Validate without starting or downloading local models:

```bash
sudo -u graphit-broker /opt/graphit-broker/graphit-broker \
  --config /etc/graphit-broker/config.yaml --check-config
```

Optionally acquire all selected `setup` and `on_demand` bundles without listening:

```bash
sudo -u graphit-broker /opt/graphit-broker/graphit-broker \
  --config /etc/graphit-broker/config.yaml --setup-models
```

Run in the foreground:

```bash
sudo -u graphit-broker /opt/graphit-broker/graphit-broker \
  --config /etc/graphit-broker/config.yaml
```

The broker does not listen until every enabled local backend has resolved, validated, inspected,
and initialized its selected model. A `never` bundle must already exist in the persistent catalog;
a `setup` bundle must be installed with `--setup-models`; and an `on_demand` bundle may download at
startup. Stop the process with `SIGTERM` or `SIGINT` for graceful shutdown.

## systemd example

Create `/etc/systemd/system/graphit-broker.service`:

```ini
[Unit]
Description=Graphit Broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=graphit-broker
Group=graphit-broker
EnvironmentFile=/etc/graphit-broker/broker.env
Environment=GRAPHIT_GLOBAL_DIR=/var/lib/graphit-broker/.graphit
ExecStart=/opt/graphit-broker/graphit-broker --config /etc/graphit-broker/config.yaml
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/graphit-broker /var/cache/graphit-broker/models

[Install]
WantedBy=multi-user.target
```

Then enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now graphit-broker
sudo systemctl status graphit-broker
```

## CPU and accelerated providers

`local.device` controls both embedding and rerank independently:

- `auto` (default) tries CoreML then CPU on macOS; on Linux and Windows it tries CUDA when an
  NVIDIA device is visible and then CPU.
- `cpu` always uses CPU, even on a GPU host.
- `cuda` requires the configured `local.device_id`; startup fails instead of silently falling back.
- `coreml` requires macOS and CoreML; it uses `device_id: 0` and fails instead of silently falling
  back.

Linux and Windows release binaries embed the ONNX Runtime main library,
`onnxruntime_providers_shared`, and `onnxruntime_providers_cuda`. These are ONNX components, not the
NVIDIA runtime. CPU operation needs no NVIDIA installation; selecting CUDA additionally requires a
compatible NVIDIA driver, CUDA, cuBLAS, and cuDNN in the host environment. The macOS release embeds
only the main ONNX dylib because CoreML is compiled into it and the remaining frameworks come from
macOS; there is no separate `onnxruntime_providers_coreml` library.

Use the broker container for GPU inference. Its broker executable embeds the ONNX CUDA provider,
while the image supplies CUDA 12.8 and cuDNN 9; the host only needs a compatible NVIDIA driver and
NVIDIA Container Toolkit. The same image supports `auto`, `cpu`, and strict `cuda` policies.

Example strict GPU configuration:

```yaml
services:
  embeddings:
    enabled: true
    dimensions: 768
    revision: coderankembed-v1
    upstream:
      protocol: onnx
      model: coderankembed
      device: cuda
      device_id: 0
```

Use `device: auto` when the same deployment must remain portable: CoreML falls back to CPU on
macOS, and CUDA falls back to CPU on Linux and Windows.

## Building the self-contained binaries

The Makefile owns dependency preparation, as in Graphit Code. Each target downloads the official
platform archive into the build cache, verifies its pinned SHA-256, selects the required runtime
library, embeds it, and removes the temporary source payload:

```bash
make build VERSION=dev                  # current supported host
make install VERSION=dev                # build and install to /usr/local/bin
make install PREFIX="$HOME/.local/bin"   # install without a global destination
make release-linux VERSION=v1.0.0       # Linux amd64 runner
make release-darwin VERSION=v1.0.0      # macOS arm64 runner
make release-windows VERSION=v1.0.0     # Windows amd64/MSYS2 runner
```

Like Graphit Code, `make install` accepts `PREFIX` as the destination directory and warns when
that directory is not on `PATH`. The installed executable is named `graphit-broker` (or
`graphit-broker.exe` on Windows).

[`native-deps.env`](../native-deps.env) is only the build-time lockfile: it pins the ONNX Runtime
version, official archive names, and SHA-256 values used by the Makefile, Docker build, and release
workflow. The published broker does not read that file and it contains no runtime configuration.

Tagged releases run those targets independently on native Ubuntu, macOS ARM64, and Windows
GitHub-hosted runners. There is intentionally no single-host `release-all` cross-build: the broker
uses CGO, so the macOS artifact must be linked against the Apple SDK on macOS.

`GRAPHIT_BROKER_NATIVE_CACHE` may move the build-time download cache. This cache is not consulted
by the resulting executable. Model weights are never embedded; their manifest policy still governs
`on_demand`, `setup`, or pre-installed acquisition.
