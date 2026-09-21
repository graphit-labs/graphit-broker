# Durable sessions: demand, coordination and continuation

Read before creating/resuming a session, revising its direction, handing off or closing it. A session is the durable envelope of an evolving user demand; Tasks are its executable units. This reference defines the session packet and a worked lifecycle. [Planning](planning.md) and [execution](execution.md) retain Task specification, check and claim rules; read them at their stated boundaries, not every checkpoint.

## Find the right record before creating one

Use graphit_task_session_get for a known ID. Otherwise list open/in_progress sessions with graphit_task_session_list (active: true, page_size: 5) or search the demand/decision with graphit_task_session_search (query, top_k: 5); pass project_dir and ai_optimized: true. Get selected matches before choosing. Search can find historical checkpoints as well as current intent. A title match alone does not prove scope or readiness. Read current description/strategy, recent meaningful checkpoints, relevant decisions/problems and associated Task summaries; task_get supplies selected Tasks' full specifications, checks and evidence. Use task_list with session_id when the graph needs inventory. Follow next_cursor when needed for complete recovery or closure, not for an unrelated question.

On resume, the decision is explicit and comes before anything else: continue the previous session, or open a new one. Finding an open session does not settle it — read its current demand and judge whether this request is that demand still evolving. It usually is, and then you continue it. Reuse a matching nonterminal session across turns, interruptions, compaction and agent replacement. Do not make one session per tool call, Task, subagent or context window. A host's chat/session ID is not the Graphit session ID. A genuinely different demand gets its own session; related changed scope revises the current one. A completed/cancelled session is historical evidence: new authorized work needs a new session referencing the closed one, not an invented reopen operation.

Retrieve sessions and Tasks throughout analysis, coding, debugging and review whenever a new question exceeds retained context. For example, to learn why report work was deferred, read the session's decision checkpoint/revision and the cancelled Task's reason; do not infer the reason from its status. Then verify current applicability through the relevant AST/Knowledge sources. Keep completed records read-only when using them as evidence.

## Initial session packet

Before material project work, graphit_task_session_create saves title, description, strategy and a stable idempotency_key; then graphit_task_session_claim takes coordination. Write in the user's language. The description must preserve:

- Requested result and purpose, users/consumers, each distinct requirement and supplied example.
- Scope boundaries, constraints, accepted decisions and what the user has actually authorized.
- Verified starting context and named evidence; distinguish facts, assumptions and unresolved questions.
- The intended observable finish, including known validation/documentation obligations.

Strategy explains the present approach, investigation needed, ordering/dependencies, delegation boundaries and next decision. Be detailed enough to resume without the conversation; link large specifications by Task ID instead of duplicating them. Unknowns stay explicit and are resolved before dependent implementation. Update initial hypotheses after investigation rather than preserving a misleading initial strategy forever. project_dir is only a live call argument; persist logical project identity, relative paths and returned record IDs.

All Tasks an agent creates belong to this session, including investigation, planning, parent deliveries, subtasks, review, documentation, corrective work and batch creates. Pass session_id explicitly, especially to delegated workers. MCP may resolve it from the parent Task or the actor's live session; lack of that context is an error, not permission to create an unassociated agent Task. Parents and children share the same session; a Task's association does not move to another session. The optional no-session case belongs to manual CLI use outside an agent session. Existing historical Tasks can still be read as evidence without attaching them.

## Ownership, checkpoint and revision

Sessions use the same statuses as Tasks: create produces open; claim produces in_progress; release or expired-lease recovery returns open; explicit complete/cancel produces completed/cancelled. Task checks still govern each Task; a session adds the whole-demand closure gate, not a second copy of its workers' checks.

The coordinator has one session claim; each worker has its own Task claim. These are independent: the coordinator may hold a session and one ready Task while workers claim other ready Tasks in that session. Share IDs and context, never claim tokens. A worker need not and must not take session coordination merely to execute a delegated Task. Its Task progress/results are inputs for the coordinator's session checkpoint.

Owner mutations use the same actor and the private claim_token returned for that entity. A Task token cannot mutate a session or vice versa. graphit_task_session_heartbeat renews coordination during long work; Task heartbeat/progress renews the separate Task lease. Reads do not establish ownership. After release/expiry a new coordinator claims and receives its own token. An active conflicting owner is not a retry signal: coordinate/release or use graphit_task_session_force_takeover only for intentional recovery of an unreachable owner with exact id/confirm_id, current expected_revision, reason and positive replacement lease. Follow the exposed schema. Do not switch identity or fabricate a token to get around rejection.

At a meaningful work outcome call graphit_task_session_checkpoint. Use:

| Field | Useful content |
|---|---|
| summary | What changed, results/artifacts, affected Task/requirement IDs and concrete evidence; distinguish done, failed and unrun |
| problems | Observed issue, consequence, current blocker and how to resolve it; distinguish resolved from still open |
| decisions | Choice, rationale, supporting evidence and rejected alternative where consequential |
| strategy | Current ordering/approach, delegation and changes needed to reach the user's result |
| next_step | Exact action, target/record, prerequisite and finish condition; required even for a checkpoint near the end |

Record real deltas, not every read/tool invocation and not 'working on it'. Preserve Task-specific evidence with task_progress/check/comment; the session checkpoint summarizes cross-Task state and points to that evidence. Problems and decisions remain recoverable historically. A checkpoint with a changed strategy does not replace the current session specification: use graphit_task_session_revise to reconcile its authoritative description/strategy.

When the user adds work, changes direction, or evidence invalidates the plan, revise the current title/description/strategy as needed using latest expected_revision and a reason BEFORE incompatible execution. Preserve accepted requirements; explicitly retire superseded ones with rationale. Reconcile affected Task descriptions/checks, dependencies and scope coverage using the normal claimed/blocked revision workflow. Session revision does not revise Tasks automatically. A cancellation, checkpoint or chat acknowledgment alone cannot correct stale specifications.

## Worked lifecycle: archive browsing with a later scope reduction

The following is fictional. Adapt the language, architecture, policies, checks and count of Tasks to the project. Payloads use illustrative returned IDs. Replace them with real responses; bind private tokens only in live calls. No example pass status is executed evidence.

### 1. Save the complete demand before planning

User request: 'Add archive browsing to the project portal and investigate downloadable reports. Keep existing permissions. You may implement archive browsing after planning; confirm the report contract before implementation.' No matching open session was found after selected reads. AST/Knowledge inspection is still pending; the initial record must say so.

graphit_task_session_create:

~~~yaml
project_dir: /example/catalog
title: Deliver archive browsing and investigate project reports
idempotency_key: portal-archive-report-demand
description: |
  ## Requested outcome and scope
  Readers must be able to include archived projects while retaining the
  default active-only workflow and current membership permissions.
  R1: omitted archive selection preserves current visible rows and totals.
  R2: archive selection includes permitted archived rows without exposing
  another reader's records. R3: the control and guide must explain the mode
  and failure/retry behavior. R4: investigate downloadable reports and
  present an evidenced contract before any report implementation.
  The user authorizes archive implementation after planning, not a report
  implementation, permission redesign, archive/restore action or migration.
  ## Starting context and open questions
  Project Catalog's portal lists projects. Current filter, authorization,
  paging, error contracts and test harness still need AST/Knowledge review.
  Do not assume report format, export scope or snapshot semantics.
  ## Finish
  Deliver archive behavior with checks and matched user/API documentation;
  record the report investigation result or an explicit later scope decision.
  Task-level contracts, fixtures and coverage will be referenced by saved IDs.
strategy: |
  Claim a planning Task; inspect current listing, readers and documentation.
  Resolve the archive contract, save complete producer/integration packets
  and requirement coverage, then execute ready units with separate ownership.
  Keep report discovery separately bounded; resolve material report choices
  with the user before defining its implementation. Close only after all
  linked work and the final request are reconciled.
ai_optimized: true
~~~

Assume creation returned ses-a101. Claim it with graphit_task_session_claim using id: ses-a101 and the live project_dir. Keep its returned claim_token private. Save that ID in every Task create. Create/claim planning P in ses-a101 with a full investigation packet; before writing the graph read [the worked feature](worked-feature.md). It supplies complete archive contracts, fixtures and P/E/A/U/V Task packets. Adapt P's demand/authorization to this session; its original planning-only example is not this user's implementation authorization.

### 2. Save the graph and checkpoint findings

After current evidence settles archive semantics, use the feature example's complete fields, adding session_id: ses-a101 to P, E, A, U and V. Create parents first; batch the fully specified A/U packets with returned parent/dependency IDs; inspect each result. Create V after A/U IDs exist. Keep A/U/V blocked on planning where appropriate. Save report-discovery Task R using the full packet below, adapted to observed evidence; leave it unclaimed until selected. It is a separate outcome within this session, not a child of the archive delivery E.

graphit_task_create:

~~~yaml
project_dir: /example/catalog
session_id: ses-a101
title: Establish the project report contract before implementation
type: task
depends_on: [tsk-a101]
idempotency_key: portal-report-contract
description: |
  ## Outcome and scope
  Address session R4: investigate downloadable project reports and preserve
  an evidenced contract or the exact remaining user decisions. No report
  endpoint, UI control, export job or storage policy is authorized here.
  ## Starting context
  Read ses-a101 current demand/strategy and completed tsk-a101 archive
  contract, fixtures and listing evidence. The archive producers preserve
  reader membership, mode, paging and totals. Those facts do not determine
  report format, full-result versus current-page scope or snapshot semantics.
  Use Graphit AST to locate current download helpers/consumers and Knowledge
  for any maintained report contract; read selected sources before reuse.
  ## Investigation and decision packet
  Identify reusable access/filter logic and actual download capabilities.
  Compare only options supported by those sources against the user's goal.
  Ask for unresolved material format/scope choices after evidence review;
  do not invent defaults. Record source/symbol/page references, selected
  option and rationale, rejected alternatives and unresolved decision owner.
  Name affected future API/UI/documentation contracts and prerequisites.
  If a choice remains unanswered, preserve its exact question and blocked
  implementation; a proposal is not approval or delivered report behavior.
  ## Verification and documentation
  Read back the decision packet against ses-a101 and tsk-a101. Check its
  stated current behavior against selected AST/Knowledge evidence; label
  proposals separately and record any divergence for reconciliation.
  No product test passes solely because this investigation is complete.
acceptance_criteria:
  - '[R-A1] Every report format/scope claim must be supported by a source or explicitly identified as an unresolved user decision.'
  - '[R-A2] The report contract must preserve existing access requirements and identify future consumers, prerequisites and implementation authorization limits.'
tests:
  - '[R-T1] Compare the saved report decision matrix with ses-a101, tsk-a101 and selected AST/Knowledge sources; record provenance, contradiction resolution and remaining questions.'
  - '[R-T2] Read the packet without the conversation: identify approved choices, unresolved decision owner, excluded implementation and the exact next action; proposals must not appear as shipped behavior.'
ai_optimized: true
~~~

Suppose returned IDs are P=tsk-a101, E=tsk-e101, A=tsk-a201, U=tsk-a202, V=tsk-a203, R=tsk-a204. These aliases differ from session ID ses-a101. Read them back and map requirements/check IDs as shown in planning.md. A checkpoint after this real planning outcome would have this form:

Requirement labels are scoped: session R1 (default rows/totals) maps to P.R1/P.R4; session R2 (permitted archived records) to P.R1/P.R2/P.R3/P.R4; session R3 (control and guidance) to P.R5-P.R8; session R4 (report investigation) to R's investigation checks. Preserve that map; do not confuse an aggregate session obligation with a single similarly numbered delivery requirement.

graphit_task_session_checkpoint:

~~~yaml
project_dir: /example/catalog
id: ses-a101
claim_token: <private-session-token>
summary: |
  Archive investigation settled the shared row/count predicate and strict
  optional boolean contract. tsk-a101 records sources, R1-R3 coverage and
  fixture cases; tsk-e101 owns delivery, tsk-a201/tsk-a202 API/UI producers,
  and tsk-a203 integration. Definitions and dependency IDs were read back.
  No producer or product check has run. Report discovery is tsk-a204.
problems: |
  Report format and page-versus-full export scope remain undecided; no
  report implementation is ready or authorized. Archive planning still
  needs its final saved-coverage review before producers can be claimed.
decisions: |
  Reuse the existing membership predicate for rows and totals; changing
  permissions is excluded. Keep report discovery separate because its
  unanswered contract must not delay the settled archive behavior.
strategy: |
  Finish tsk-a101 coverage review, then allow API/UI owners with compatible
  edits; integration waits for both. Resolve report choices only in tsk-a204.
next_step: |
  Read back tsk-a101 and producer check IDs, finish coverage validation and
  complete planning; then claim ready tsk-a201. Do not mark product checks
  passed from this planning review.
ai_optimized: true
~~~

Task progress/checks carry the actual planning evidence. If inspection changes the session's stored initial strategy, revise that current strategy too; the checkpoint retains the discovery history.

### 3. A new user instruction changes the scope

Before report discovery starts the user says: 'Leave reports for another request. Finish archive browsing only.' The coordinator first gets the latest session and uses its current revision. Suppose it is 4; this is illustrative, never a constant for real calls.

graphit_task_session_revise:

~~~yaml
project_dir: /example/catalog
id: ses-a101
claim_token: <private-session-token>
expected_revision: 4
reason: The user deferred all report work to a separate future request.
title: Deliver archive browsing
description: |
  ## Current requested outcome
  Deliver archive browsing for Catalog readers. R1 preserves active-only
  defaults and totals; R2 includes only permitted archived rows when selected;
  R3 supplies accessible mode/error/retry behavior and matched user/API docs.
  tsk-a101 holds verified contracts, fixture cases and requirement coverage;
  tsk-e101 with tsk-a201/tsk-a202/tsk-a203 owns delivery and integration.
  ## Scope change and finish
  The user explicitly deferred former R4 report investigation and every
  report implementation to another request. tsk-a204 must be cancelled with
  this provenance; it is not a delivered requirement. Permissions and
  archive/restore actions remain unchanged. Finish when R1-R3 and their
  documentation are verified and all associated Tasks are terminal.
strategy: |
  Reconcile tsk-a101 current scope/checks and cancel untouched tsk-a204 with
  the user's reason. Finish planning before API/UI execution; integrate
  both producers, compare docs and current requirements, then close session.
ai_optimized: true
~~~

Reconcile P while claimed: update its description/coverage and supersede report obligations with rationale; rerecord planning checks after the revision resets them. Cancel R with the user's reason. Confirm the affected Task states; do not leave an obsolete open R silently blocking session closure. P can then complete while E/A/U/V remain open. Checkpoint the scope decision and actual reconciliation, including pending corrections if a write failed. A report task already in progress would instead require coordination and preservation of actual partial work; never claim it was untouched.

### 4. Delegate and hand off without losing the demand

Coordinator holds the session claim and may claim A; a worker gets ses-a101, U, P and the agreed file boundaries, claims only U and reports through its Task. The worker uses session_get/task_get to read intent and dependencies but cannot use the coordinator's token. New worker Tasks must pass session_id: ses-a101 and stay in authorized scope. Changes affecting the global plan go to the coordinator for session revision; workers do not independently overwrite the demand.

Suppose A has verified ordinary/filter/permission cases, but the injected storage-failure case is still failing. U is complete with its own evidence; V has not run. Before interruption the coordinator writes Task progress and a session checkpoint like:

- Summary: A's implemented handler/query/count and API-guide comparison are recorded in tsk-a201; U evidence is in tsk-a202. V remains blocked, so no integrated-delivery claim is made.
- Problem: A's failure fixture produces an unexpected envelope; name the exact observed mismatch and test output in A. Its affected checks remain failed/pending.
- Decision: preserve the existing documented failure contract; the earlier user scope reduction still excludes reports. Do not redesign errors to bless a failing assertion.
- Strategy: correct or diagnose A's fixture/handler against the contract, rerun the affected cases/docs, then execute V and close E.
- Next step: get A and the named failed check, inspect the recorded failure path and relevant source/test, resolve the mismatch, run the saved focused command and record observed evidence before completing A.

The Task owner releases unfinished claimed Tasks with their handoffs. The coordinator calls graphit_task_session_release with id, its private claim_token, summary and next_step; this leaves an open session with durable continuation. It does not close the work. A Stop hook, absent native session identity or expired lease cannot supply this semantic handoff automatically.

A replacement agent lists relevant open/in_progress sessions, gets ses-a101, reads its revised demand and latest checkpoint, then gets A/P and relevant U results. It observes R cancelled by user direction, not silently delivered. After release/expiry it claims session coordination with its own identity/token, claims ready A separately, verifies source/check freshness and continues from the recorded failure. If another coordinator still holds a valid claim, it does not overwrite that ownership. Full backlog and historical logs are read only when a remaining question requires them.

### 5. Close the demand, not just the last Task

After actual fixes and evidence, complete A, execute/complete V, and complete E using their normal checks. P/U were already completed and R cancelled for the accepted scope reduction. Read all associated Task states, exhausting pages as needed. Reconcile current R1-R3, validation and user/API documentation; confirm no unresolved promised work was hidden by cancellation. A terminal Task list is a mechanical gate, not proof of semantic delivery.

graphit_task_session_complete receives id: ses-a101, the current session claim_token and a descriptive summary naming delivered R1-R3, E/V evidence, code/doc comparison and R's explicitly deferred scope. For example, after real evidence exists: 'Archive browsing delivered against tsk-a101 current R1-R3; tsk-a201/tsk-a202 and tsk-a203 contain producer/integration checks and matched API/user guides. tsk-a204 was cancelled at the user's request; reports were not implemented. All associated work is terminal; no remaining archive obligation.' Do not copy this summary before those conditions hold.

Confirm complete succeeded before telling the user the session's work is finished. A premature close rejection means inspect and resolve remaining Tasks, not retry blindly or cancel them to satisfy the gate. graphit_task_session_cancel is for an abandoned demand with terminal associated Tasks; it requires an active session claim/token and reason, is not a success substitute and never auto-cancels Tasks. An analysis-only session may close with a substantive final result if no executable Tasks were needed, but never fabricate validations. Hooks and end-of-turn sync never complete sessions.
