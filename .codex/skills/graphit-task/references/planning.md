# Specify and plan executable work

Read before defining or materially changing a feature, system, multi-outcome analysis or backlog. The output is saved Task descriptions, checks and relationships. The sections below are an authoring model, not extra API fields or mandatory files. Write in the user's language and project terminology. Keep relevant substance; omit inapplicable sections with no placeholder boilerplate. For a complete filled example, read [worked-feature.md](worked-feature.md).

## 1. Establish the unit of intent

Start from the matching durable session's current demand and strategy; read [session.md](session.md) before creating or resuming its coordination. Session intent is the overall request, not a replacement for complete Task specifications. A new planning Task, its deliveries and every leaf carry the same session_id. Update the session when discovery or the user changes that intent, then reconcile the affected Task packets before incompatible execution.

Capture the requested outcome and why it matters, intended users/consumers, scope exclusions, supplied examples, constraints and available evidence. Preserve exact business rules and limits. Inventory each distinct requirement from a large prompt before compressing it; do not replace ten requested capabilities with 'build the system'. Identify what can deliver value independently and what is a shared prerequisite. A small fix needs a single execution packet; a feature may need a parent and slices; a system needs multiple deliveries, cross-delivery contracts and observable milestone exits.

Separate three kinds of statement:

| Kind | What to record | Consequence |
|---|---|---|
| Verified fact | Observation, authoritative source and relevant version/path | Ground the plan in it; check freshness if it affects a decision |
| Supported assumption | Choice, supporting evidence, impact if false and validation route | Proceed only where failure would not silently change material intent |
| Open decision | Exact question, affected requirements, source/person that can resolve it and what is blocked | Investigate/clarify before affected implementation; continue independent work |

Missing access rules, retention periods, provider selection, destructive behavior or required compatibility are not harmless defaults. Do not invent an answer to make a plan appear ready. Avoid an arbitrary question quota: ask only for decisions whose answer changes scope, correctness, contracts or verification, after inspecting available evidence. Persist accepted answers into the affected requirements/contracts and remove superseded contradictions, retaining rationale in revision history.

## 2. Specification in the planning description

Use stable identifiers, such as J1 for a journey and R1 for a requirement, within this delivery. IDs survive task splits and wording improvements. They are prose references, not Graphit IDs.

### Outcome, scope and journeys

For each user/consumer journey state the actor and starting condition, intended action, observable result, priority with a reason, and an independent demonstration. A secondary journey need not be an independent deployment if it depends on an existing journey; state that dependency honestly. Do not claim parallelism merely because stories have different names.

Describe alternate, empty, loading, boundary, invalid-input, denied, partial-failure and recovery states where relevant. For state-changing work include permitted transitions, retry/idempotency behavior, concurrency/conflict handling and rollback/recovery. For read-only work do not invent mutation machinery. Accessibility, localization, performance, availability and security are requirements when the request or verified project constraints make them relevant.

### Requirements and success

Write one testable obligation per requirement: under an identified condition, the product must produce/prevent an observable result. Record its origin (user instruction, current policy, contract or approved decision) and journey. Replace 'fast', 'secure' and 'works correctly' with the applicable measure or invariant; do not fabricate latency targets, capacity limits or business KPIs. Keep external behavior separate from suggested implementation unless a technical choice is itself required.

Distinguish release criteria that can be proved now from post-release outcomes that need production data. Define the latter's measurement owner/window if known; do not pass them from unit tests or make unauthorized production actions part of routine validation.

### Domain and contract boundaries

Name entities, identifiers, ownership, required/optional fields, accepted values, uniqueness, null/empty distinctions, relationships and lifecycle when material. Record existing constraints and intended changes. Describe interfaces in the project's own form: HTTP requests/responses, CLI arguments/output/exit codes, public methods, events, files or UI state transitions. Include defaults, omitted versus explicit values, incompatible inputs, failure results and boundary behavior. Link verified authoritative contracts; retain execution-critical details locally so a missing conversation cannot change interpretation.

### Specification quality gate

Before planning implementation, check the writing itself: are obligations complete, singular, measurable and mutually consistent; are all relevant journeys/failure paths specified; do terms/data contracts agree; are assumptions justified and blockers explicit? A passing specification review means intent is clear, not that software works. Save the concrete finding and fix, not a generic checked box. Example: 'R4 said retry is safe but R6 created a new payment on each retry; reconciled both to the approved idempotency contract.'

## 3. Technical plan in the same record

Record the actual starting architecture, relevant language/runtime versions, dependencies, data store and test harness only when they affect the work. Read existing code with AST and selected sources, documentation through Knowledge, relevant memory and prior Task outcomes. Resolve ecosystem projects/artifacts using the Hub route in the main skill. Do not prescribe a new framework before checking what the project already uses.

Include:

- Evidence map: path/symbol/page or task ID, what it establishes, and impact. Mark a proposed new path as new; do not present it as an observed file.
- Design: affected components, data/control flow, interfaces and exact agreed contract; existing conventions to reuse; responsibility at each boundary.
- Decision log: selected option, reason grounded in requirements/evidence, material alternatives rejected and why. 'Best practice' alone is insufficient rationale.
- Work sequence: prerequisites, first useful slice, subsequent deliveries and integration/milestones. Include migrations, compatibility/rollout/recovery only when applicable; distinguish implementation authorization from release authorization.
- Validation: each requirement's method, setup/fixtures, action, expected evidence and owner task; existing tests to reuse, new tests warranted, and needed runtime/environment. Define meaningful failure/boundary coverage without duplicating identical cases.
- Documentation: current user and technical surfaces by domain/audience, exact sections to add/update or verified no-impact rationale. Every code/config/behavior unit checks its affected docs; every documentation unit checks the authoritative behavior it describes. Integration review does not postpone per-unit consistency.

Research work is its own executable outcome when a material unknown prevents design. Its acceptance is a sourced decision/contract with consumers and consequences, not 'researched X'. Delivery depends on it. A plan may be complete as a backlog with explicit blocked refinement, but the affected implementation is not ready.

## 4. Decompose and save the graph

Group by verifiable outcome, not arbitrary file count or tool calls. Each leaf has one accountable outcome, compatible edit boundaries, explicit inputs/outputs and completion evidence. Combine tightly coupled edits that must be verified together; split separately ownable behavior, contract discovery, migration or integration. A long prompt usually produces a hierarchy, not a larger single description. Priority selects between ready work; dependencies establish legal order.

Create prerequisite and parent records before referencing their returned IDs. Use parent_id for scope ownership and depends_on for work that must finish first. A parent automatically waits for descendants at completion; never make its child depend on that parent. Integration tasks depend on producers. A separate planning record can finish while implementation remains open. No leaf may require a change to its own unfinished prerequisite as its exit condition.

Once multiple task packets are fully specified, prefer task_batch creates with their own complete fields and already-returned parent/dependency IDs. The worked feature shows two full sibling packets in one batch. Create parents first, batch siblings with known inputs next, then create dependents requiring those newly returned IDs. A dependency may still be incomplete; it must already exist. key is correlation only, not ID substitution. Inspect every item and retain successful results; retry only failed/uncertain creates with the same idempotency_key. The batch changes transport cost, not specification quality or execution readiness.

Parallel eligibility needs both satisfied prerequisites and compatible ownership of files, generated outputs, shared environments and contracts. Record the reason in the plan. When two leaves touch the same interface or doc page, assign one owner, split sections only if safely coordinated, or serialize. Do not add unnecessary all-to-all dependencies that prevent useful work.

Each agent create needs session_id, title, description, acceptance_criteria and tests; batch items each carry the association too. The session must be nonterminal, and parent/child must share it. Types are labels; there are no dedicated spec/plan/milestone fields. Use a stable idempotency_key per logical work unit. Every task, including a planning task or parent, needs at least one acceptance criterion and one validation. A parent check is a product-level integration/release condition, not just 'children exist'.

### Leaf description model

1. **Outcome and scope:** requirement/journey IDs, behavior and concrete deliverables; exclusions and exact constraints.
2. **Starting context:** current facts, logical project identity, repository-relative paths/symbols and their roles, source revision, prerequisites and the exact results/decisions to read.
3. **Plan and contracts:** implementation/research steps, inputs/outputs, errors/boundaries, choices already settled, allowed freedom, risks and unresolved blockers.
4. **Verification and documentation:** fixture/setup, action/command, expected result, evidence location; code and documentation surfaces to compare and update.
5. **Continuation:** when partially done, current artifacts/results, failed or unrun checks and next executable action. Update this via progress and keep changed scope in the description itself.

Use acceptance_criteria to state required outcomes; use tests to define how to prove them. Named local labels inside check text, such as '[A1]' or '[T1]', help connect a human-readable coverage map to returned checks[].id. The API creates real IDs: read the created task and store the mapping. Labels never replace check_id in mutations.

## 5. Readiness and coverage audit

Save a compact table mapping requirement/journey -> producer task -> acceptance check -> validation check -> integration/doc evidence. Replace symbolic task/check aliases with returned IDs. Check both directions: each requirement has a delivery and proof, and each task/check has a scope justification. Include required decisions, nonfunctional constraints and failure behavior; a title match is not coverage.

Read back saved definitions and relations. Detect omissions, ambiguous terms, contradictory contracts, unsupported assumptions, unavailable test prerequisites, stale source references, invalid parallelism and hierarchy/dependency deadlocks. Fix within authorized scope; a read-only assessment reports fixes without applying them. Do not silently dilute a requirement to remove a finding. Known gaps become explicit refinement/correction work with affected IDs; never claim an unchanged blocked snapshot was revised.

A cold-start agent must identify the next action and prove completion from the leaf and named records, without reconstructing the conversation. 'Implement search; follow the plan; tests pass' fails this test. A useful task says which query contract changes, why current behavior fails, where it is implemented, how callers/docs are affected, and what exact cases prove it.

Before finishing planning, revise the claimed planning description with final contracts and returned-ID coverage; the revision resets its checks, so record planning evidence afterward. The coordinator reconciles session description/strategy and checkpoints the saved graph, decisions, unresolved issues and next action. Leave future delivery checks pending and work unclaimed. Completing a planning Task does not close a session with implementation pending. For a planning-only request, future implementation Tasks stay open; hand off/release the session without calling the whole delivery complete. Follow the main skill's claim/revision rules for later corrections. Continue with [execution.md](execution.md) before implementation or handoff.
