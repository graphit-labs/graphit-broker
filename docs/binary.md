# Running the native binary

GitHub releases publish `graphit-broker-linux-amd64.tar.gz`, following the gated build, checksum,
and release pattern used by Graphit Code. The archive contains:

```text
graphit-broker-linux-amd64/
├── graphit-broker
├── config.example.yaml
└── lib/
    ├── libonnxruntime.so.1.29.0
    ├── libonnxruntime.so -> libonnxruntime.so.1.29.0
    ├── libonnxruntime_providers_shared.so
    └── libonnxruntime_providers_cuda.so
```

Model weights are deliberately absent. Startup downloads CodeRankEmbed only when embeddings are
enabled with `backend: local`, and downloads BGE only when rerank is enabled with `backend: local`.
When paired custom `model_path` and `tokenizer_path` values are set, the binary performs no model
download and requires those compatible artifacts (plus any ONNX external data) to exist already.

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

Keep the `lib` directory beside the executable. The broker discovers that ONNX Runtime location
automatically. `ONNXRUNTIME_SHARED_LIBRARY_PATH` may override it when an operator manages the
runtime elsewhere.

## Install and configure

This example creates a dedicated service identity and persistent directories:

```bash
sudo useradd --system --home /var/lib/graphit-broker --shell /usr/sbin/nologin graphit-broker
sudo install -d -o graphit-broker -g graphit-broker -m 0700 \
  /etc/graphit-broker /var/lib/graphit-broker /var/cache/graphit-broker/models
sudo install -d -o root -g root -m 0755 /opt/graphit-broker
sudo cp -a graphit-broker-linux-amd64/. /opt/graphit-broker/
sudo install -o graphit-broker -g graphit-broker -m 0600 \
  graphit-broker-linux-amd64/config.example.yaml /etc/graphit-broker/config.yaml
```

Edit `/etc/graphit-broker/config.yaml`. Keep the SQLite DSN under
`/var/lib/graphit-broker`, local model cache paths under `/var/cache/graphit-broker/models`, and
provider secrets in a root-readable environment file rather than command-line arguments.

Validate without starting or downloading local models:

```bash
sudo -u graphit-broker /opt/graphit-broker/graphit-broker \
  --config /etc/graphit-broker/config.yaml --check-config
```

Run in the foreground:

```bash
sudo -u graphit-broker /opt/graphit-broker/graphit-broker \
  --config /etc/graphit-broker/config.yaml
```

The broker does not listen until every enabled local backend has acquired or validated and then
initialized its respective model. Custom model paths are never acquired: place them in a persistent
directory readable by `graphit-broker` before startup. Stop the process with `SIGTERM` or `SIGINT`
for graceful shutdown.

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

## CPU and GPU

`local.device` controls both embedding and rerank independently:

- `auto` (default) selects CUDA when an NVIDIA device is visible and initialization succeeds;
  otherwise it logs the CUDA failure and uses CPU.
- `cpu` always uses CPU, even on a GPU host.
- `cuda` requires the configured `local.device_id`; startup fails instead of silently falling back.

CPU needs no additional model runtime because the release bundle includes ONNX Runtime. For GPU,
the release contains the ONNX CUDA provider but not the NVIDIA driver, CUDA, or cuDNN. Install a
driver compatible with CUDA 12 plus CUDA 12 and cuDNN 9, ensure their shared libraries are visible
to the service loader, and verify the selected device with `nvidia-smi`. The container image is the
recommended GPU deployment because it already carries the CUDA 12.8 and cuDNN 9 user-space runtime.

Example strict GPU configuration:

```yaml
services:
  embeddings:
    enabled: true
    backend: local
    dimensions: 768
    revision: coderankembed-v1
    local:
      device: cuda
      device_id: 0
      cache_dir: /var/cache/graphit-broker/models/coderankembed
```

Use `device: auto` when the same installation must remain portable between GPU and CPU hosts.
