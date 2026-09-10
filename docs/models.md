# Local ONNX model catalog

Local embedding and rerank models run inside the broker process. They use the same broker image and
the same public HTTP contracts as upstream providers; clients do not know whether a route is local.
Model weights are never included in the image or release archive.

## Select models in `config.yml`

Each service selects its local model and execution settings in `upstream`:

```yaml
services:
  embeddings:
    enabled: true
    revision: local-embedding # optional readable prefix for a local model
    dimensions: 768           # optional assertion; omit or use 0 to infer from ONNX/manifest
    upstream:
      protocol: onnx
      model: coderankembed
      directory: /var/cache/graphit-broker/models
      device: auto
      device_id: 0
  rerank:
    enabled: true
    revision: local-rerank    # optional readable prefix
    upstream:
      protocol: onnx
      model: bge-reranker-base
      device: auto
      device_id: 0
```

`upstream.directory` defaults to `/var/cache/graphit-broker/models` independently for each service.
With `protocol: onnx`, `upstream.model` defaults to `coderankembed` for embeddings and
`bge-reranker-base` for rerank. `device` defaults to `auto` and `device_id` to `0`.
The broker does not expose local generation or a generation model selector.

ONNX selects an in-process runtime adapter. Omit HTTP-only options (`url`, API-key fields,
`send_dimensions`, and `timeout`); incompatible nonzero/nonempty values are rejected.
Different services may select different catalog directories. Model semantics remain in manifests.

A complete CPU/GPU-portable preset configuration is available at
[`examples/local-models.yaml`](../examples/local-models.yaml).

Model selection has no effect while the corresponding service is disabled or uses
an HTTP `upstream.protocol`. Therefore an HTTP-only broker neither loads nor downloads local model
artifacts.

Each selected ID maps to one bundle:

```text
<upstream.directory>/<model-id>/
├── manifest.json
├── model.onnx
├── tokenizer.json
└── optional ONNX external-data and tokenizer files
```

The Compose `broker-models` volume is mounted at the default directory. Native installations should
make the configured directory persistent and writable by the broker service user.

## Built-in presets

The presets use exactly the same manifest format as custom models:

| ID | Task | Runtime behavior |
|---|---|---|
| `coderankembed` | embedding | CodeRankEmbed INT8, 768 dimensions, query prefix, L2 normalization |
| `bge-reranker-base` | rerank | BGE cross-encoder, raw relevance logit |

When selected for an enabled local service, a missing preset `manifest.json` is materialized in its
bundle directory. Its pinned model and tokenizer are then downloaded, SHA-256 verified, fsynced,
and atomically renamed. Existing valid files are reused.

## Manifest reference

This complete example shows every currently supported field:

```json
{
  "schema_version": 1,
  "id": "bge-custom",
  "task": "rerank",
  "runtime": {
    "engine": "onnx",
    "entrypoints": {
      "model": "model.onnx"
    }
  },
  "fetch_policy": "on_demand",
  "artifacts": [
    {
      "role": "model",
      "path": "model.onnx",
      "sources": [
        {
          "url": "https://models.example.com/bge/model.onnx",
          "auth_ref": "private-models"
        }
      ],
      "sha256": "<64 hexadecimal characters>",
      "size": 123456789,
      "required": true
    },
    {
      "role": "tokenizer",
      "format": "huggingface-json",
      "path": "tokenizer.json",
      "sources": [
        {
          "url": "https://models.example.com/bge/tokenizer.json",
          "auth_ref": "private-models"
        }
      ],
      "sha256": "<64 hexadecimal characters>",
      "required": true
    }
  ],
  "text": {
    "max_tokens": 512,
    "query_prefix": "",
    "document_prefix": "",
    "truncation": "longest-first",
    "padding": "longest"
  },
  "inference": {
    "inputs": "auto",
    "output": "auto",
    "pooling": "none",
    "normalize": false,
    "dimensions": null,
    "score_transform": "sigmoid",
    "score_column": 0
  }
}
```

Fields and accepted values:

| Field | Values and meaning |
|---|---|
| `schema_version` | Must be `1` |
| `id` | Must exactly equal the bundle directory and selected model ID |
| `task` | `embedding`, `rerank`, or the reserved `generate` task |
| `runtime.engine` | Currently `onnx` |
| `runtime.entrypoints.model` | Relative path of the artifact whose role is `model` |
| `fetch_policy` | `on_demand`, `setup`, or `never` |
| `artifacts[].role` | Unique semantic role; `model` and `tokenizer` are required |
| `artifacts[].format` | Tokenizer supports empty or `huggingface-json` |
| `artifacts[].path` | Relative path confined to this bundle, including through symlinks |
| `artifacts[].sources` | Ordered download alternatives; omit for pre-installed files |
| `artifacts[].sha256` | Required whenever `sources` is non-empty; optional for installed-only files |
| `artifacts[].size` | Optional exact byte count |
| `artifacts[].required` | Missing required artifacts fail with an actionable error |
| `text.max_tokens` | `1` through `8192`; default `512` |
| `text.query_prefix` | Prepended to embedding queries or the rerank query |
| `text.document_prefix` | Prepended to embedding documents or rerank documents |
| `text.truncation` | Currently `longest-first` |
| `text.padding` | Currently `longest` |
| `inference.inputs` | `auto` or an explicit semantic tensor-name map |
| `inference.output` | `auto` or an exact output tensor name |
| `inference.pooling` | `none`, `cls`, or attention-mask-aware `mean` |
| `inference.normalize` | L2-normalize embedding vectors when `true` |
| `inference.dimensions` | Positive fixed width, or `null` to infer a static ONNX width |
| `inference.score_transform` | Rerank `identity`, `sigmoid`, or row-wise `softmax` |
| `inference.score_column` | Optional zero-based rerank output column; defaults to column 1 for width 2, otherwise 0 |

Unknown manifest and YAML fields are errors. Paths must be relative, remain under the bundle even
after resolving symlinks, and reference regular files. Missing, corrupt, incompatible, or ambiguous
models cause startup to fail; there is no silent model or device-semantic fallback.

## Artifact acquisition policies

### `on_demand`

An enabled local service is initialized before the HTTP listener starts, so `on_demand` downloads
missing selected artifacts during broker startup. Disabled and upstream services do nothing.

```json
{
  "fetch_policy": "on_demand",
  "artifacts": [
    {
      "role": "model",
      "path": "model.onnx",
      "sources": [{"url": "https://models.example.com/model.onnx"}],
      "sha256": "<required digest>",
      "required": true
    }
  ]
}
```

Concurrent attempts for the same destination share a per-path lock. Downloads use a temporary file
and only become visible after their size and digest pass validation.

### `setup`

`setup` permits download only through the dedicated setup command. Normal startup uses an already
installed artifact and otherwise reports that setup is required:

```bash
graphit-broker --config /etc/graphit-broker/config.yml --setup-models
graphit-broker --config /etc/graphit-broker/config.yml
```

The command processes only enabled embedding/rerank services with `upstream.protocol: onnx`,
then exits without creating the database server or HTTP listener. It also pre-installs
selected `on_demand` bundles, which is useful for image deployment with controlled startup egress.

With the existing Compose file, no override is needed:

```bash
docker compose run --rm broker --config /etc/graphit-broker/config.yaml --setup-models
docker compose up -d
```

### `never`

`never` never performs network access, including under `--setup-models`. Put every required file in
the bundle before startup:

```json
{
  "fetch_policy": "never",
  "artifacts": [
    {"role": "model", "path": "model.onnx", "sha256": "<optional digest>", "required": true},
    {"role": "tokenizer", "format": "huggingface-json", "path": "tokenizer.json", "required": true}
  ]
}
```

For the named Compose volume:

```bash
docker compose create broker
docker compose cp ./models/my-embedding broker:/var/cache/graphit-broker/models/my-embedding
docker compose up -d
```

## Private artifact sources

Credentials never appear in a manifest. A source may name `auth_ref`; the broker converts it to an
environment variable by uppercasing it and replacing punctuation with underscores:

```json
{"url": "https://models.example.com/model.onnx", "auth_ref": "private-hf"}
```

```text
GRAPHIT_BROKER_MODEL_AUTH_PRIVATE_HF=<token>
```

The download sends `Authorization: Bearer <token>`. Keep this variable in the normal broker secret
environment (`.env`, systemd `EnvironmentFile`, Kubernetes Secret, or an equivalent secret store).

## Custom embedding examples

Rank-2 sentence embeddings need no pooling:

```json
{
  "inference": {
    "inputs": "auto",
    "output": "sentence_embedding",
    "pooling": "none",
    "normalize": true,
    "dimensions": 768
  }
}
```

Rank-3 token embeddings require `cls` or `mean`. Explicit input mapping supports exports that use
nonstandard tensor names:

```json
{
  "text": {
    "max_tokens": 1024,
    "query_prefix": "query: ",
    "document_prefix": "passage: ",
    "truncation": "longest-first",
    "padding": "longest"
  },
  "inference": {
    "inputs": {
      "input_ids": "ids",
      "attention_mask": "mask",
      "token_type_ids": "segments"
    },
    "output": "last_hidden_state",
    "pooling": "mean",
    "normalize": true,
    "dimensions": null
  }
}
```

`auto` recognizes BERT-style `input_ids`, `attention_mask`, and optional `token_type_ids`. Inputs
must be rank-2 `int64`. Embedding output must be `float32`, rank 2 for `none`, or rank 3 for
`cls`/`mean`. A dynamic output width requires explicit `dimensions`.

## Custom rerank examples

A single-logit cross encoder with sigmoid conversion:

```json
{
  "task": "rerank",
  "inference": {
    "inputs": "auto",
    "output": "logits",
    "pooling": "none",
    "normalize": false,
    "dimensions": null,
    "score_transform": "sigmoid",
    "score_column": 0
  }
}
```

A two-class classifier can return the probability for its relevant class:

```json
{
  "inference": {
    "inputs": "auto",
    "output": "logits",
    "pooling": "none",
    "normalize": false,
    "dimensions": null,
    "score_transform": "softmax",
    "score_column": 1
  }
}
```

Rerank output must be a rank-1 or rank-2 `float32` tensor.

## ONNX inspection and validation

The runtime inspects tensor names, element types, ranks, shapes, opset imports, model metadata, and
external-data declarations. Resolution is deterministic:

```text
ONNX inspection -> known task profile -> manifest overrides -> validation or startup error
```

Tensor structure can be inferred; semantic behavior cannot. Tokenizer files, prefixes, truncation,
padding, pooling, normalization, score transforms, and ambiguous tensor meanings therefore remain
explicit manifest data. Every ONNX external-data location is confined to the bundle, must exist,
and contributes its content hash to model identity.

## Effective identity and embedding reindexing

The broker hashes the resolved manifest, every artifact digest (including ONNX external data), the
inspected signature and metadata, semantic input/output mapping, pooling/normalization, and final
dimension. A local service revision is exposed as:

```text
<configured revision or model ID>@sha256:<effective identity>
```

That revision is used by response caches and broker discovery. Any material model or preprocessing
change therefore creates a new cache namespace automatically. For embeddings, an identity change
means a different vector space and requires reindexing existing content before queries use it.

## Execution providers

Device policy is configured in each service’s `upstream`, alongside its model selection:

```yaml
services:
  embeddings:
    upstream: {protocol: onnx, device: auto, device_id: 0}
  rerank:
    upstream: {protocol: onnx, device: cpu, device_id: 0}
```

Strict NVIDIA and Apple configurations use the same field:

```yaml
# Linux or Windows with NVIDIA driver, CUDA and cuDNN available.
services:
  embeddings:
    upstream: {protocol: onnx, device: cuda, device_id: 0}

# macOS; CoreML chooses the available Apple compute units.
services:
  rerank:
    upstream: {protocol: onnx, device: coreml, device_id: 0}
```

- `auto` prefers CoreML on macOS, or a visible NVIDIA GPU on Linux/Windows, and falls back to CPU.
- `cpu` always uses CPU.
- `cuda` requires the selected GPU and fails startup if it cannot initialize.
- `coreml` requires macOS CoreML and fails startup if it cannot initialize.

If an accelerator runs out of memory during an `auto` inference, the same inference is retried on
CPU immediately. CPU use remains temporary: the broker probes the accelerator after 1 minute and
backs off subsequent failed probes to 2, 4, 8, and at most 10 minutes. A probe switches normal
traffic back only after its complete inference succeeds. Explicit `cpu`, `cuda`, and `coreml`
policies never use this fallback or switch providers at runtime.

Native Linux and Windows binaries embed the ONNX core, shared-provider, and CUDA-provider
libraries. CPU therefore works without NVIDIA dependencies, while CUDA additionally requires a
compatible driver plus CUDA/cuDNN on the host. The macOS dylib has CoreML compiled into the main
ONNX library and needs no separate `libonnxruntime_providers_coreml` file. The container image
provides CUDA/cuDNN. To expose NVIDIA GPUs using the repository's single Compose file:

```bash
GRAPHIT_BROKER_CONTAINER_RUNTIME=nvidia docker compose up -d
```

See [deployment](deployment.md) and [native binary operation](binary.md) for host prerequisites.
