---
name: graphit-memory
description: 'Durable memory: project and user preferences, corrections, decisions, constraints, and non-obvious knowledge; mandatory recall is performed by adapter hooks.'
---

# Graphit Memory

Graphit memory is the durable source for preferences, corrections, decisions, constraints, and non-obvious project knowledge. Agent-native/model memory is not a substitute.

The adapter hook loads mandatory project and user memories at session start and reinjects the Graphit invariant at the strongest lifecycle points the host exposes. Do not repeat `graphit_memory_mandatory` unless the hook explicitly reports fallback or the user changes project/scope.

## Recall

For a relevant request, call `graphit_memory_search` with a focused query and `exclude_mandatory: true`. Results are titles and ids; choose one or two and read them with `graphit_memory_source`. Use `preview: true` only to disambiguate titles. A superseded hit is historical: read its `current` memory before treating anything as present truth. Use `graphit_memory_list` to distinguish an empty store from a missed search.

Use project scope by default. Use user scope only for preferences that genuinely apply across projects. For another project, pass that project's resolved `project_dir`; do not infer it or read the global store as files.

## Write and maintain

Write with `graphit_memory_insert` when information should survive the session: a correction, durable preference, design choice with rationale, constraint, or non-obvious behavior. Skip transient task state already captured by Graphit Task and facts obvious from code.

Prefer `graphit_memory_update` when the subject already exists. On contradiction, update the current memory so its id/history survives. On duplication, first merge every distinct fact into the survivor, verify it, then call `graphit_memory_delete` on the redundant entry. Never delete unique knowledge. Perform this sanitation when discovered, not as a vague future task.

Mark only standing context required in every session with `graphit_memory_mark_mandatory`; unmark it with `graphit_memory_unmark_mandatory` when that stops being true. Use `promote`/`demote` for important but conditional memories. `important` lists promoted entries; `schema` describes the memory graph.

Writes are durable immediately and refresh the authoritative table's own search indexes. Confirm a fresh write with `list`; call `graphit_memory_index` only to repair or explicitly refresh those indexes. `graphit_memory_sync` validates and refreshes an imported authoritative context; no local memory projection is created.

Tool index: `graphit_memory_mandatory`, `graphit_memory_search`, `graphit_memory_source`, `graphit_memory_insert`, `graphit_memory_update`, `graphit_memory_list`, `graphit_memory_important`, `graphit_memory_promote`, `graphit_memory_demote`, `graphit_memory_mark_mandatory`, `graphit_memory_unmark_mandatory`, `graphit_memory_delete`, `graphit_memory_index`, `graphit_memory_schema`, `graphit_memory_sync`, `graphit_memory_remove`.
