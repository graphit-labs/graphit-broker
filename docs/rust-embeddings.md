---
references:
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Native embeddings

The Rust embeddings service combines current capability authorization, the existing Code inference clients and a durable SQL cache. Operators configure one HTTP or GGUF model; callers submit text and its query/document purpose. This page covers the PostgreSQL and private SQLite Server compositions.

## Configure and start

Use the native [Server configuration](rust-broker-server.md#native-embeddings),
including its explicit service, transport and manifest bounds. That page contains
complete HTTP and GGUF examples. The earlier release configuration is not imported.
`--check-config` validates the captured configuration and selected constructors;
normal startup additionally establishes SQL ownership and the listener.

The defaults are 256 inputs when `max_batch` is absent/zero, 1 MiB of literal UTF-8
when `max_input_bytes` is absent/zero, and 45 seconds when the service
`request_timeout` is absent. Required byte/transport bounds have no hidden defaults.
There is one request timeout covering admission, body parsing, cache, every provider
batch and response publication. Genuine authentication expiry can shorten it.
There is no per-batch timeout setting or SQL cache TTL.

HTTP needs an explicit supported protocol, endpoint, model, nonempty service revision,
positive dimensions, and exact `upstream.model_revision` / `upstream.recipe` declarations
for the deployed model and query/document preprocessing. Neither declaration is
invented or independently attested by a provider protocol that does not report it. Supported aliases are:

| Family | Selected protocol aliases |
|---|---|
| OpenAI | `openai`, `openai-compatible`, `openai-embeddings-v1` |
| Cohere | `cohere`, `cohere-embed-v2` |
| Voyage | `voyage`, `voyage-embeddings-v1` |
| Google | `google`, `google-embed-content-v1beta`, `gemini`, `gemini-embed-content-v1beta` |

The endpoint and model are captured once at preparation. Google accepts the API
base or its complete batch endpoint and prepares both single and batch routes.
Its model selects the existing embedding family: Gemini Embedding 2 uses retrieval
prefixes; earlier models use query/document task types. `send_dimensions` controls
the actual optional dimensions field for OpenAI and Google. Google sends it inside
`embedContentConfig.outputDimensionality`, on both single and batch requests.

An API key is optional. With a configured key the defaults are `Authorization:
Bearer` for OpenAI/Cohere/Voyage and `x-goog-api-key` without a scheme for Google.
Custom header/scheme settings use parsed HTTP names and sensitive values; unsafe
framing headers fail preparation. The four mature clients borrow a `HeaderMap`,
including an empty map for a provider needing no key. The bounded transport retains
captured trust, response/request limits, cancellation and finite errors, with no
ambient proxy, redirects or automatic retries. The administrative configuration
projection redacts the key.

SDK input budgets account for protocol/manifest prefixes using checked arithmetic.
The public `max_input_bytes` still counts only the submitted text, before prefixes.

## Request and result

Send `POST /v1/embeddings` with JSON. For example:

```json
{"input":["first text","second text","first text"],"input_type":"document"}
```

Only `input` and `input_type` are accepted. A client-supplied `model`, `route` or
other field is rejected. Duplicate fields, malformed/truncated JSON and trailing
JSON values are rejected. `input` is a string or a nonempty array of strings;
missing/null/wrong types, whitespace-only items and too many items are invalid.
The UTF-8 byte cap applies to the sum of the literal decoded strings, including
duplicates. No trimming changes the text sent to the provider or hashed for cache.

An absent/null/trimmed-empty `input_type` means `document`. Trimmed, case-insensitive
`query` and `document` select the corresponding provider/manifest behavior; any
other value is invalid.

A successful response has this shape; the two-dimensional vectors below are
illustrative, and actual width/revision come from the prepared service:

```json
{
  "object":"list",
  "data":[
    {"object":"embedding","embedding":[0.1,0.2],"index":0},
    {"object":"embedding","embedding":[0.3,0.4],"index":1},
    {"object":"embedding","embedding":[0.1,0.2],"index":2}
  ],
  "graphit":{"revision":"example-space-v1","model":"example-model","model_revision":"deployment-r1","recipe":"retrieval-v1","dimensions":2}
}
```

Discovery names this wire protocol `graphit-embeddings-v1`: its request is not the OpenAI request envelope. The response `graphit` model, model revision, recipe, service revision and dimensions exactly match the discovery descriptor. For local GGUF, model/revision come from the manifest and recipe is `gguf-config-v1:<declared-execution-identity>`; caller configuration cannot override this provenance.

Order and duplicate positions match the original request. Response headers are
`X-Graphit-Embedding-Revision`, `X-Graphit-Embedding-Dimensions` and
`X-Graphit-Cache: HIT|MISS`. `HIT` means there were no missing unique inputs;
any provider work makes the request `MISS`.

`usage` is present only when actually observed from provider responses. One
observed object remains an object; multiple observed objects form an array in
response order. The service does not invent totals across batches, and complete
cache hits omit usage. The response has no client-selected model or route alias.

## Authorization precedes cache and decoding

Every request, including a hit, obtains current SQL capability grants before body
decoding, cache reads or inference. The genuine dispatcher supports native Broker
access JWTs, LOCAL opaque human access/service credentials and configured F1
upstream verification. Absence of a bearer is genuine anonymous admission;
an invalid bearer never becomes anonymous. Administrative cookies do not grant
this capability.

The required capability is the literal `embeddings`. Principal user/team/org
selectors match literal trimmed values, and subjects match raw subject or
`issuer|subject`; only capability selectors support glob matching. Project
selectors do not restrict this endpoint, which has no project identifier.
PROJECT/Any authorization retains its separate contract. The request retains the
actual proof and checks it across asynchronous boundaries, without treating a
caller-provided boolean as authority. Revocation affects the next hit as well as
the next miss.

## Durable cache and incomplete inference

The existing `embedding_cache` table stores SHA-256 input hashes, a versioned
compatibility hash, provider/revision/model/input-type provenance and exact-width
finite float32 vector JSON. It stores neither original text nor credentials or
subjects. Entries have no SQL expiry, eviction or overwrite behavior.

The compatibility identity includes the selected protocol alias after trim/lower
normalization, captured endpoint or verified local semantic identity, model,
service revision, model revision, recipe, dimensions, dimensions-field mode and query/document purpose. Google
also includes its family and batch endpoint. Credential rotation alone does not
change vector compatibility. Another principal can reuse a row only after its
own independent current authorization.

Each request deduplicates inputs and sends only unique misses through the mature
SDK batching logic. PostgreSQL uses one bulk `UNNEST` read and one bulk insert for
the relevant batch. SQLite uses one executor job/transaction with reused prepared
statements. Existing keys are never overwritten, including concurrent inserts.
Reads bound metadata and vector bytes before decoding. Malformed, oversized,
wrong-width or nonfinite stored data is an error, not a cache miss.

Only a **complete, valid JSON response** can supply partial vectors. A vector must
have an unambiguous input position and the exact finite dimension. Duplicate
indices invalidate every candidate for that index, including duplicate index
fields in one object. Positional cardinality mismatch invalidates that response;
an individually invalid row can leave its unambiguous siblings usable. A truncated
JSON prefix supplies no vectors. Previously completed native/provider batches can
also survive a later inference error.

While the genuine proof and Original remain valid, these known valid results may
be committed before returning an error for the whole HTTP request. The endpoint
never returns partial success. It does not retry a failed batch or reinfer siblings
individually. A subsequent caller request reads the confirmed rows and infers only
the remaining misses. Expired proof, cancellation or backend closure prevents later
cache publication. An already observed non-temporal failure retains its cause.

An insert reports a known COMMIT or `OutcomeUncertain`; a lost acknowledgement
does not trigger automatic replay. A later independently authorized request may
read the durable result. The actual connection and transaction lifecycle belongs
to the existing SQL owner, including physical cleanup after cancelled waits.

## Local GGUF model ownership

Select `protocol: gguf-embeddinggemma2` with an explicit model ID, bundle `directory`, `manifest_file` and positive `max_artifact_bytes`. Paths resolve relative to the configuration file. The shared closed manifest uses runtime `gguf-embeddinggemma2`, task `embedding`, declared GGUF artifacts with SHA-256 byte-array digests, and the EmbeddingGemma2 recipe. Tokenization is embedded in the GGUF file.

Provision the bundle first. Startup bounds manifest decoding; the first valid uncached request verifies only declared artifacts and loads the native worker. Omitted/zero dimensions derive from the recipe; positive dimensions assert equality. The model revision comes from the manifest. Recipe identity covers the declared manifest, requested device and thread count; local overrides are rejected. Moving the same bundle preserves that identity.

CPU is the default. Explicit CUDA or Metal requires successful device registration; Metal is macOS-only. Auto allows an available accelerator or a reported CPU fallback. Optional `threads` controls native inference threads and defaults to half the logical CPUs, rounded up; the dedicated worker queue defaults to eight requests. These are local execution settings, separate from public request limits.

The original request cancellation and deadline follow work into the worker. SQL authorization is checked before publishing response/cache results. Server shutdown stops admission and joins native workers before releasing the SDK bootstrap. See the [local model configuration](models.md) and [complete service schema](rust-broker-server.md#native-embeddings).

## Errors and operations

Errors use a finite JSON envelope with `error.code`, a static `error.message` and
`request_id`, without echoing input, provider payload, credentials or private paths.

| Status | Code | Action |
|---|---|---|
| 400 | `invalid_json` | Send one complete JSON object with only the accepted fields. |
| 400 | `invalid_request` | Correct input count/types/content or input type. |
| 401 | `unauthorized` | Supply a currently valid credential; the response has the bearer challenge. |
| 403 | `forbidden` | Obtain a current resource grant for `embeddings`. |
| 404 | `capability_disabled` | Enable the service in the native configuration. |
| 413 | `request_too_large` | Reduce literal UTF-8 input/body size. |
| 502 | `upstream_failed` | Investigate bounded provider/model/cache failure using safe correlation data. |
| 503 | `authorization_unavailable` | Restore the actual SQL authorization dependency. |

Disabled services initialize no model/provider/cache and advertise no service.
Enabled discovery publishes path, effective revision/dimensions, input limits and
the public protocol `graphit-embeddings-v1` independently of the selected upstream.

Native GGUF consumer qualification requires explicit provisioned bundles; Linux CPU results do not establish GPU execution or another operating system.

Implementation boundaries: `broker-presence/src/embeddings.rs` and its provider/
request modules compose the endpoint; `broker-control` owns the borrowed SQL cache
and genuine admission views; `broker-server/src/embeddings_config.rs` prepares the
native service. The Code `graphit-ai` SDK supplies all four HTTP families and the
shared local GGUF workers. The maintained [API](api.md), [Server](rust-broker-server.md),
[SQLite](rust-sqlite-control.md) and [model catalog](models.md) pages describe their
respective consumers.

Local GGUF models load on the first valid uncached request. `upstream.idle_timeout_seconds` defaults to 300 seconds and must be positive. Completed native inference resets that deadline; a cache hit does not. Idle unloading joins the native owner and removes verified staging before a later request reloads the same model identity.
