---
name: graphit-memory
description: 'Durable memory: preferences, corrections, decisions, constraints, user-provided project facts, standing guidance, and agent-discovered structural or non-obvious system knowledge; mandatory recall is performed by adapter hooks.'
---

# Graphit Memory

Graphit memory is the durable source for preferences, corrections, decisions, constraints, and non-obvious project knowledge. Agent-native/model memory is not a substitute.

The adapter hook loads mandatory project and user memories at session start and reinjects the Graphit invariant at the strongest lifecycle points the host exposes. Do not repeat `graphit_memory_mandatory` unless the hook explicitly reports fallback or the user changes project/scope.

## Recall

For a relevant request, call `graphit_memory_search` with a focused query and `exclude_mandatory: true`. Results are titles and ids; choose one or two and read them with `graphit_memory_source`. Use `preview: true` only to disambiguate titles. A superseded hit is historical: read its `current` memory before treating anything as present truth. Use `graphit_memory_list` to distinguish an empty store from a missed search.

Use project scope by default. Use user scope only for preferences that genuinely apply across projects. For another project, pass that project's resolved `project_dir`; do not infer it or read the global store as files.

## Write and maintain

Treat a user statement as a memory-capture event when it provides project information the agent did not already know or standing guidance for how the agent should act. Do not require the user to ask for memory or repeat the statement. Presume it is durable when it describes the project, its lifecycle or environment, policies, or conventions, or when knowing it would change planning, implementation, review, compatibility, migration, safety, or risk decisions in later work. Preserve the user's rationale when it connects a project fact to an operating policy.

Also treat an agent discovery as a memory-capture event when analysis, implementation, debugging, or review establishes relevant non-obvious knowledge that is structural, reusable across tasks, or costly to rediscover. Create or update Memory automatically; do not wait for a user request. Capture implicit invariants or contracts, sources of truth and generation flows, non-obvious dependencies or coupling, recurring root causes or failure modes, confirmed trade-offs, surprising tool/infrastructure/lifecycle behavior, and learned procedures. Ask whether another agent would plan or act better, or avoid material investigation, by knowing it.

Write with `graphit_memory_insert` on that first occurrence. Use project scope for project facts and instructions; use user scope only for genuinely cross-project preferences. Classify lifecycle or environment state as a `fact` and standing project guidance as a `decision` or `convention`. Mark standing context needed in every session as mandatory and important but conditional context as important. If the statement is explicitly limited to the current task, keep it in Graphit Task instead. Also skip transient task state, questions or speculation, and facts obvious from authoritative code or documentation.

The complete investigation remains in Graphit Task; Memory stores its durable reusable conclusion and never substitutes for Task. Do not capture trivial or obvious observations, transient progress, one-off results without future value, or unconfirmed hypotheses.

Prefer `graphit_memory_update` when the subject already exists. On contradiction, update the current memory so its id/history survives. On duplication, first merge every distinct fact into the survivor, verify it, then call `graphit_memory_delete` on the redundant entry. Never delete unique knowledge. Perform this sanitation when discovered, not as a vague future task.

Mark only standing context required in every session with `graphit_memory_mark_mandatory`; unmark it with `graphit_memory_unmark_mandatory` when that stops being true. Use `promote`/`demote` for important but conditional memories. `important` lists promoted entries; `schema` describes the memory graph.

Writes are durable immediately and refresh the authoritative table's own search indexes. Confirm a fresh write with `list`; call `graphit_memory_index` only to repair or explicitly refresh those indexes. `graphit_memory_sync` validates and refreshes an imported authoritative context; no local memory projection is created.

Tool index: `graphit_memory_mandatory`, `graphit_memory_search`, `graphit_memory_source`, `graphit_memory_insert`, `graphit_memory_update`, `graphit_memory_list`, `graphit_memory_important`, `graphit_memory_promote`, `graphit_memory_demote`, `graphit_memory_mark_mandatory`, `graphit_memory_unmark_mandatory`, `graphit_memory_delete`, `graphit_memory_index`, `graphit_memory_schema`, `graphit_memory_sync`, `graphit_memory_remove`.
