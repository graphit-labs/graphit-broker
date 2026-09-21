---
name: graphit-memory
description: 'Memory: retrieve facts, decisions and lessons whenever questions arise; preserve durable guidance, corrections and confirmed discoveries across tasks.'
---

# Graphit Memory

`project_dir` is a runtime MCP argument, not persisted project identity. In docs, Task, Memory and handoffs save project identity plus repository-relative paths; never copy a machine-specific checkout root. Resolve the local root again on each host.

Preserve preferences, corrections, standing guidance, project facts and confirmed non-obvious knowledge that affect future work. Use Graphit, not native/model memory. Task holds investigation/progress; Knowledge holds maintained docs.

When a task, session, memory or knowledge page relies on another record, explicitly send `references` with each target's `type` and `id`, plus `relation` (for example supports, implements, derived_from or relates_to). Resolve real IDs through the corresponding read tools; never invent them. Mentioning an ID in prose or making a Markdown link does not create a database relation. Send the complete intended explicit list on reference changes; omit it to preserve existing relations, and send [] to clear explicit relations. Structural task/session links remain managed by their existing fields. Qualify cross-project/user targets with `scope` and `scope_id`, and imported knowledge with `context`; use logical identities, never checkout paths.
Example write input: `references: [{"target": {"type": "memory", "id": "<verified memory ID>"}, "relation": "supports"}]`. The source is the record being written; do not repeat a source ID. Read its existing references before replacing the list so unrelated links survive.
Use `graphit_references_query` with source_type/source_id for outgoing relations or target_type/target_id for backlinks. Scope filters retain identity; include_user explicitly adds personal memory. If the result reports incomplete projections, `graphit_references_reconcile` repairs writable local module projections from existing structured data; it never invents relations from prose.

## Recall whenever a question needs context

Hooks load mandatory project/user memories. Reuse them; call `graphit_memory_mandatory` only if the hook reports fallback, mandatory context is absent, or project/scope changes. In fallback, call once per missing scope (`scope: project` and `scope: user` for a project session); the default fetch covers only project scope. Use only user scope on an artifact-only server, without inventing `project_dir`. After compaction recover only missing context.

At any stage—questions, exploration, implementation, debugging or review—when retained context cannot explain the system, a decision or a surprising result, use `graphit_memory_search` with a focused query, `exclude_mandatory: true`, `top_k: 5` and `ai_optimized: true`. Do not wait for a new session, plan or blocker. Known ID: read directly. Search returns titles/IDs; read selected entries with `graphit_memory_source`. Use `preview: true` to disambiguate; expand only for remaining gaps. Reuse sufficient context; a new question can need a new search in the same scope. Read a superseded entry's `current` version before relying on it.

Use the questioned project's known/cluster-returned `dir` as `project_dir` with project scope, including neighbors; user scope is for cross-project preferences. If unresolved, read Hub and resolve with `graphit_cluster_projects` before its catalog; never guess paths or read stores as files. Installed AST/Knowledge contexts provide no project memories. For missing context, refine once; use `graphit_memory_list` for an intended inventory or suspected empty store, not routine recall or post-write verification.

## Capture at the first durable finding

For the first unfamiliar mid-work recall, correction, duplicate merge or durable discovery, read [recall and capture cases](references/durable-context.md); reuse thereafter. If the local resource is unavailable, call `graphit_module_skill` with `module: memory`, `reference: references/durable-context.md` and the known `project_dir` when available.

Capture user facts about lifecycle/environment, policies, conventions or standing instructions even without “remember this”. Preserve its rationale and conditions when they affect future planning, compatibility, migration, review or risk. Also capture confirmed structural, reusable or costly discoveries: implicit contracts, sources of truth/generation flows, coupling, recurring failure modes, trade-offs and learned procedures. Capture now, not at repetition or task end.

Before writing, reuse an existing matching entry already recalled; otherwise make one focused subject search. If the same fact is present and current, do not write it again. Use `graphit_memory_update` for an existing subject so its ID/history survives; use `graphit_memory_insert` when genuinely new. Include the concrete conclusion, scope/conditions, rationale and a compact source reference. Classify lifecycle/environment state as `fact`, standing choices as `decision`/`convention`, and corrections as `correction`. Task-local instructions, transient progress, speculation, obvious code facts and one-off results without future value stay out of Memory.

Mark standing context needed in every session `mandatory`; use `important` for consequential but conditional knowledge. Use `graphit_memory_mark_mandatory`/`graphit_memory_unmark_mandatory` or `graphit_memory_promote`/`graphit_memory_demote` only when recall needs change. Never demote, shorten away conditions, or delete critical constraints merely to reduce tokens. `graphit_memory_important` is for intentional review of promoted entries, not a second mandatory-memory fetch.

## Reconcile without losing knowledge

On contradiction, preserve provenance and conditions, then update the current entry using confirmed newer evidence; do not silently replace a user constraint with an inference. For duplicates, merge every distinct fact and constraint into the survivor, read that entry once to verify preservation, then `graphit_memory_delete` the redundant entry. Preserve unique knowledge; leave unrelated memories alone.

A successful write is durable and refreshes its own search indexes: trust the acknowledgement; do not list/search/sync after each write. Read back only if the response is ambiguous or verification is needed before removing a duplicate. Use `graphit_memory_index` to repair indexes, `graphit_memory_schema` for graph diagnostics, and `graphit_memory_sync` to refresh an imported authoritative context. `graphit_memory_remove` is destructive context maintenance, never a recall repair.

Keep investigation/next action in Task and the reusable conclusion in Memory. If Memory MCP is unavailable, state that persistence was unavailable and retain the conclusion in the available task handoff; do not claim it was saved or substitute the Graphit CLI.
