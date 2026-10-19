---
references:
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# Local GGUF models

The native Broker uses the shared Code llama.cpp/cxx implementation for local inference. Embeddings use EmbeddingGemma2; rerank uses the paired classification head of BAAI/bge-reranker-v2-m3 in F16. Rerank remains disabled unless its service is explicitly enabled. Remote provider protocols and HTTP consumers remain independent.

Use [examples/local-models.yaml](../examples/local-models.yaml) with provisioned bundles. Broker releases contain the runtime; model weights and their manifests are provisioned separately. No runtime-library path, tokenizer sidecar or automatic model substitution is configured.

| Field | Contract |
|---|---|
| `protocol` | `gguf-embeddinggemma2` or `gguf-bge-reranker-v2-m3` |
| `model` | Exact ID in the typed manifest |
| `directory`, `manifest_file` | Explicit bundle and manifest; relative paths resolve against the configuration file |
| `max_artifact_bytes` | Positive maximum for the declared GGUF artifact |
| `manifest_limits` | Positive bounds for manifest bytes, artifacts, relative paths, IDs, revisions, dimensions and tokens |
| `device`, `device_id` | CPU by default, or explicit CUDA/Metal/auto selection; Metal requires macOS, CPU/Metal device ID zero |
| `threads` | Optional positive inference thread count; defaults to half the available logical CPUs, rounded up |
| `recipe` | Optional explicit versioned semantic recipe name; otherwise derived from the manifest, independently of device and threads |
| `queue_capacity` | Optional positive worker queue capacity, default 8 |
| `idle_timeout_seconds` | Positive time since the last completed native inference; default 300 seconds |

The closed manifest declares task, model revision, artifact digest and exact recipe. Only declared artifacts are read, with containment, EOF and integrity checks. Embedded GGUF tokenizers supply tokenization. EmbeddingGemma2 uses its query/document prefixes and normalized embedding recipe; BGE uses query/document pairs, rank pooling and the manifest's raw-logit or sigmoid transform. BGE does not fall back to vector cosine. EmbeddingGemma2 documents exceeding the context are processed as token windows and produce one final normalized vector; overlong queries are rejected. Only complete vectors are eligible for the cache. A later non-temporal item failure can preserve earlier complete vectors under the same request authority and deadline.

Startup validates each enabled service's configuration and bounded manifest, retaining only declarations. Both local models read, verify, stage and load weights on the first valid uncached request, using its original cancellation and deadline. Missing or corrupt weights and an unavailable requested device fail first use. The administrative configuration describes requested execution; after each load, the existing diagnostic output reports the registered provider/device and any automatic CPU fallback.

When a local GGUF service is selected, startup captures the installation root from `GRAPHIT_GLOBAL_DIR` or the native home `.graphit` directory and privately prepares `<global>/tmp`. A relative global override resolves against the captured startup working directory. The YAML location and configured model bundle do not select this staging parent. Embedding and rerank workers receive its captured directory explicitly; invalid privacy, replacement or missing-parent observations fail without a system-temporary fallback. Remote-only configurations do not prepare this local infrastructure. The worker retains each verified snapshot until native cleanup joins.

The default local recipe identity `gguf-manifest-v1:<digest>` covers the declared manifest (including artifact digests, precision, dimensions and query/document or pair-scoring recipe). Device, device ID and thread count are execution settings and do not change this semantic identity, the local service revision or its cache namespace. A deployment can declare `upstream.recipe` explicitly, for example `retrieval-v1`; this label must be versioned when weights, precision or the actual recipe change. It never bypasses manifest, artifact or model validation. Keeping the same label for unchanged weights/recipes permits moving execution between CPU and GPU without re-embedding documents. Authorization is checked on cache hits and before publishing results.

Omitting `threads` adapts to the machine: 4 available logical CPUs use 2 inference threads, 8 use 4, and 20 use 10. An explicit value overrides this default. The setting applies to each model; it is not a machine-wide reservation. `device: cpu` remains the product default. `device: auto` uses an available supported accelerator, otherwise CPU, with the effective provider and fallback reason reported when loading. Large BGE F16 documents can exceed a request deadline on a small CPU allocation; select execution deliberately rather than assuming the default provides a latency guarantee. Embedding and rerank device/thread settings are independent.

After `idle_timeout_seconds` without completed native inference, the owner joins its worker and releases the model/context, GPU allocations and verified staging files. Cache hits do not keep a model resident. In-flight inference is never interrupted for idleness: completion starts the next idle period. The next uncached request loads on demand again. Shutdown cancels admission and drains retained startup/inference before releasing the SDK bootstrap. An unused model is never loaded just to shut it down.


Run `graphit-broker --config config.yaml --check-config` after provisioning. The real SQLite consumer tests use explicit `GRAPHIT_TEST_RERANK_BUNDLE` and `GRAPHIT_TEST_GEMMA_BUNDLE` paths. Linux CPU results do not establish CUDA, Metal, Windows or macOS execution.
