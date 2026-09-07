---
name: graphit-task
description: 'Deterministic tasks: shared LanceDB work, dependencies, claims, progress, handoff, completion, and prior-task search.'
---

# Graphit Task

Graphit Task is the only task-control source of truth. Always use it instead of the host agent's native task/TODO/planning mechanism, even when that mechanism is available. The shared LanceDB tables own task state; do not create Markdown task logs or TODO/backlog files.

## Enter work

Before material work, search prior tasks with `graphit_task_search` and follow `next_cursor` until the relevant history is covered; use `graphit_task_list` with `ready: true` to find unblocked work and `graphit_task_get` to read dependencies, progress, next step, and audit history. Resume an existing task instead of duplicating it.

Create missing work with `graphit_task_create`, a stable `idempotency_key`, a complete specification, explicit acceptance criteria, and concrete tests/validations. Use `parent_id` for subtasks and dependency IDs for ordering; an unclaimed `open` task is the backlog. Add/remove dependencies with `graphit_task_dependency_add`/`graphit_task_dependency_remove`; never encode relations only in prose.
Cleanup, validation, review, documentation, commit preparation, release checks, and similar delivery-support or finalization work are subtasks of the relevant delivery task, not unrelated top-level tasks. Use a check for a pass/fail condition; use a subtask when the validation or finalization itself is a work unit that must be owned, resumed, or audited.
When discovery changes a claimed task's scope, use `graphit_task_revise` with the current task revision and a reason. Supersede an obsolete check through `graphit_task_check_supersede`, optionally creating its replacement; never falsify evidence or delete history to force completion.
For two or more independent mutations, prefer `graphit_task_batch`; it runs in input order and reports every item. Inspect all results and never use batching to bypass claims, checks, flags, dependencies, or removal confirmation.

## Specify work

Keep titles as concise, action-oriented plain text that identifies one outcome. Write the description as proportional Markdown with the sections needed to make the specification self-contained: objective and value; context; in-scope and out-of-scope boundaries; requirements or externally observable behavior; constraints and assumptions; interfaces or dependencies; material risks and edge cases; and intended result. Requirements must be necessary, singular, feasible, consistent, unambiguous, and implementation-independent unless an implementation choice is itself a constraint.

Write each acceptance criterion as a singular imperative statement of what the system **must** do or **must not** allow, including the applicable condition and a measurable or observable expected result. State required behavior, not the implementation procedure. Write each behavioral test check in Given-When-Then form: known preconditions, one action or event, and observable outcomes. For non-behavioral validation, state the method or command, target and conditions, and expected evidence or result instead of forcing Gherkin. Include meaningful failure paths without duplicating equivalent scenarios.

Markdown is supported for descriptions, check text and evidence, progress and next steps, comments, reasons, and completion/release summaries. Use structure only when it improves comprehension. Evidence names the command, observation, or artifact and its result; progress records completed facts; next steps identify the exact action, target, and completion condition; comments preserve durable context and rationale; reasons identify cause, impact, and the condition or replacement that resolves the change. IDs, titles, types, statuses, priorities, actors, and timestamps remain compact plain text.

Claim with `graphit_task_claim` before changing project state. A claim returns a fencing token; keep it private and pass it to progress, heartbeat, release, and complete. A rejected claim means another agent owns the task—choose other ready work. Never bypass a claim or edit task tables directly.

## Advance and hand off

After each independently reportable unit, call `graphit_task_progress` with what landed and the exact next step. Add relevant typed comments with `graphit_task_comment_add` for decisions, problems, lessons, and system knowledge. Record every active acceptance/test result through `graphit_task_check` with concrete evidence; a parent cannot complete before all subtasks, and no task can complete with an unchecked/failed active check.

When a risk or unresolved condition must gate completion, call `graphit_task_flag` with its reason; flagged work may be released and claimed by another agent, but cannot complete until `graphit_task_unflag` records resolution. Call `graphit_task_complete` only after every active check passes, all subtasks complete, and no flag remains. If stopping, blocked by external input, or handing off, call `graphit_task_release` with current evidence and next step; supported stop hooks release host-identifiable claims, leases recover crashes, and hooks reconcile invalid completion state.

On a direction change, clean obsolete work immediately: use `graphit_task_cancel` when its history remains useful, or `graphit_task_remove` only when deletion is certainly correct. Removal requires the exact task ID and a reason and refuses referenced tasks. Never leave superseded work open or flagged as garbage.

Every mutation is revision-checked and audited. Dependencies gate readiness; expired or stopped claims become open for takeover. Search is discovery; `get` and filtered `list` read authoritative state.

Use `graphit_task_export` only when a machine-readable complete archive is required. Pass an exact task ID for that task and its subtasks, or omit it for every project task; the JSON includes all public Task entities in deterministic order and never exposes fencing tokens.

Tool index: `graphit_task_search`, `graphit_task_list`, `graphit_task_get`, `graphit_task_export`, `graphit_task_batch`, `graphit_task_create`, `graphit_task_claim`, `graphit_task_revise`, `graphit_task_progress`, `graphit_task_heartbeat`, `graphit_task_comment_add`, `graphit_task_check`, `graphit_task_check_supersede`, `graphit_task_flag`, `graphit_task_unflag`, `graphit_task_release`, `graphit_task_complete`, `graphit_task_cancel`, `graphit_task_remove`, `graphit_task_dependency_add`, `graphit_task_dependency_remove`.
