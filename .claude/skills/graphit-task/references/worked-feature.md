# Worked feature: browse active and archived projects

This is a fully filled example, not a universal project layout or a fixed number of tasks. Languages, commands, paths, UI wording and contracts are fictional verified facts of this example; adapt them to actual evidence and the user's language. Never copy invented observations into real work. P, E, A, U and V denote task IDs returned by creates. A.A1 denotes the returned ID of the check whose text begins [A1], not an ID to send literally. Persist those bindings when constructing the real backlog.

## Request and evidence established before planning

Example request: 'Readers need an option to see archived projects. Keep the current default and access rules. Plan the change and leave implementation for later.'

Start by finding or creating the durable session as taught in [session.md](session.md). Assume it returned ses-a101 and its current description preserves this planning-only authorization, scope and strategy. Every P/E/A/U/V record below belongs to ses-a101. Session coordination is separate from the one Task claim per agent; a worker shares the session ID, never its coordinator's token.

| Evidence | Observed fact | Planning consequence |
|---|---|---|
| User clarification | Include archived alongside active; no archive-only mode, remembered preference or archive/restore actions | Scope is read-only listing; unchecked on each new visit |
| internal/http/projects.go / ListProjectsHandler | Auth middleware runs first; parses page/page_size; returns {items,total,page,page_size} | Extend this handler without a new endpoint/envelope |
| internal/http/query.go / StrictOptionalBool and query_test.go | Omitted -> false; exactly one lowercase true/false accepted; empty, repeated or other values -> 400 INVALID_QUERY | Reuse the verified convention, including its error behavior |
| internal/projects/list.go / ListProjects | Membership predicate AND archived_at IS NULL, then order by id, then pagination; count uses the same predicates | Keep authorization, condition only the archive predicate in both count and rows |
| internal/projects/types.go / Project | id immutable; archived_at nullable timestamp; response exposes id, name and archived boolean | No new stored state or schema migration |
| web/projects.tsx / ProjectList and web/projects-api.ts / listProjects | Component owns page/request state; API client accepts page/page_size; stale-response guard exists in web/useLatestRequest.ts | Add a typed option; reuse latest-request guard |
| web/package.json and playwright.config.ts | npm test -- --run runs component tests; npm run test:e2e starts fixture backend/browser | Validation commands below have a known harness |
| docs/projects/listing.md and docs/api/projects.md | User/API guides describe active-only default, membership scope and page_size 1..100 | Both audience surfaces must evolve with their owning slices |

The source observations above are recorded with actual source references in a real P. They are not instructions to search this repository for these fictional files.

## P description — specification

### Outcome, actors and boundaries

An authenticated project reader can inspect their archived projects without changing the default active-project workflow. Existing readers keep the same access boundary. No permissions, project state, archive/restore operation, persisted preference or API response field is added. This is an additive API option; clients omitting it retain existing behavior.

### Journeys and priority rationale

| Journey | Priority and reason | Independent demonstration |
|---|---|---|
| J1: list active projects as before | Highest: existing callers must not regress | Request without the option and with false; same authorized active IDs/count as current contract |
| J2: inspect archived projects | Next: requested new value | API caller sends true and sees authorized active plus archived projects; works without the UI |
| J3: toggle the browser list and recover from failed requests | Completes the reader experience; depends on J1/J2 contract | Start unchecked, turn on/off, use keyboard, retry a simulated error and verify final mode/list |

Priority is a delivery/value rationale, not a dependency edge or a claim that the UI is ready before the API.

### Requirements and measurable release outcomes

| ID | Observable obligation | Origin |
|---|---|---|
| R1 | GET /projects with include_archived absent or false returns only active projects; true includes both statuses | Request + clarification |
| R2 | All modes return/count only projects the authenticated reader may access; unauthenticated calls remain 401 | Existing access contract |
| R3 | The option accepts exactly one lowercase true/false; omitted means false. Empty, repeated or other values return 400 with code INVALID_QUERY and do not call the repository | Existing parser convention |
| R4 | Apply authorization and status filtering before stable id ordering/pagination. total counts the filtered authorized set, including when the selected page is empty. Existing page/page_size validation remains unchanged | Existing listing contract |
| R5 | A new page visit starts unchecked. Toggling sends the selected mode and resets page to 1 while preserving page_size. Both transitions refresh the list | Clarified interaction |
| R6 | Loading hides old rows; only the latest request may display rows/counts. On failure show the existing localized error with Retry, retain selected mode, show no rows and retry that mode/page. A superseded response cannot replace current results | Existing request/error convention applied to new control |
| R7 | The control has visible/localized 'Show archived' labeling and works with keyboard; a new visit does not remember the previous selection | Existing accessibility/localization pattern + clarification |
| R8 | User and API guides explain default/option, access boundary, paging/errors and supported examples, consistent with delivered behavior | Project documentation contract |

Release evidence: the fixture cases below produce the exact required IDs/totals/status codes; the UI scenarios demonstrate both modes and request recovery; docs are checked against those behaviors. There is no invented latency/SLA target or post-release adoption claim. Existing project performance gates still apply if they cover listing.

### Domain and wire contract

Project identity and membership do not change. archived_at=null means active; a timestamp means archived. The response continues to expose archived as a boolean, not the database timestamp. No new persistence, migration or write endpoint is needed.

- Request: authenticated GET /projects; existing page (positive integer) and page_size (1..100), plus optional include_archived described in R3.
- Success: HTTP 200, existing envelope {items:[{id,name,archived}],total,page,page_size}; ordered ascending by id. No matching rows -> items=[], total=0; page beyond end -> items=[], total remains filtered count.
- Authentication failure: existing 401 behavior before query parsing or repository work. No cross-reader items/counts leak.
- Query failure: authenticated request with invalid include_archived -> HTTP 400, existing error envelope with code INVALID_QUERY, no repository call. Repeated true/false is invalid even if values agree.
- Storage failure: existing 500 error envelope; no partial list returned. The UI follows R6 and does not reinterpret failure as an empty successful list.

### Decisions, assumptions and blockers

| Item | Decision and evidence | Rejected alternative / blocker rule |
|---|---|---|
| D1 | Extend the existing endpoint because envelope/access semantics are unchanged | New /archived endpoint duplicates authorization and paging |
| D2 | Filter in the repository before count/pagination, retaining authorization in both query paths | Client filtering hides page entries but produces wrong totals and cannot prove access isolation |
| D3 | Reuse StrictOptionalBool and current error envelope | Permissive strings such as 'yes' would diverge from the verified API convention |
| D4 | Reuse the existing latest-request guard; render only current mode results | Debounce alone cannot prevent a slower previous response overwriting current data |
| A1 | Existing membership helper is authoritative; source and tests establish its behavior | If consumers have a different access contract, stop affected implementation and refine R2; do not choose a policy |
| A2 | No new performance target or persistence is requested; existing mechanisms are reused | If observation shows full-table loading or another regression, investigate before completion |

No unresolved material decision remains in this fictional plan. If the real archive definition, parser convention or access model is unknown, create a refinement prerequisite with a sourced-contract deliverable. Do not label a missing policy 'assumption' merely to mark implementation ready.

## P description — implementation plan

1. Backend slice A extends existing handler/options and repository query/count. It owns API tests and docs/api/projects.md. Authorization remains the first predicate; status restriction is conditional. It preserves all other request defaults and response fields.
2. UI slice U extends the typed client and page control using the settled wire contract. It owns component tests and docs/projects/listing.md. Request mocks use the exact envelope/cases below; U may develop against that contract while A is in progress, but the feature is not integrated until V.
3. V exercises the actual UI/backend together, confirms both audience docs against observed behavior and records remaining gaps. It owns only the end-to-end test file; it does not silently rewrite A/U's specification or mark failed producer checks passed.

No dependency or framework installation, migration, new service or publish step is required by this plan. API/UI source and doc files are disjoint; shared contract is finalized in P. If implementation needs to change that contract, suspend affected work and revise/reconcile producer and consumer checks before continuing. Test fixtures are local and reversible; no production data or deployment is implied.

### Reproducible fixture and validation matrix

Reader alice belongs to projects p01 and p03. bob owns p02 and p04; alice has no membership there. Database rows sorted by id: p01 active, p02 active, p03 archived, p04 archived. Use the fixture session for alice; default validation page=1, page_size=2.

| Case | Setup/action | Expected evidence |
|---|---|---|
| C1 | Alice, flag absent; repeat with false | 200, IDs [p01], total=1, page=1, page_size=2 |
| C2 | Alice, true | 200, IDs [p01,p03], total=2; p02/p04 absent |
| C3 | Alice, true, page_size=1, page=2 | IDs [p03], total=2; proves authorization/filtering before paging |
| C4 | Alice, false, page=2, page_size=1 | items=[], total=1; page beyond end differs from zero matches |
| C5 | Reader with no memberships, both modes | items=[], total=0 |
| C6 | Alice, option empty, 'yes', 'TRUE', or repeated true/false and true/true | Each returns 400 INVALID_QUERY; repository spy sees zero calls |
| C7 | No session, absent/false/true | Existing 401; repository spy sees zero calls |
| C8 | Repository failure | Existing 500 envelope, no items; UI shows error and Retry rather than empty-success state |
| C9 | Mount UI, toggle on, then off | Unchecked/active; true shows p01,p03; false returns p01; each toggle resets page=1 |
| C10 | Delay true response; issue false and resolve it first, then true | UI keeps unchecked state and [p01], never renders obsolete p03 |
| C11 | Fail true request, then Retry succeeds | Selected true remains; error/no rows then loading then [p01,p03], total=2 |
| C12 | Keyboard focus and Space; leave/re-enter page | Toggle accessible by label; re-entry unchecked; no persisted selection |

C1 tests absent and explicit false separately. C2/C3 prove inaccessible active and archived rows cannot distort results/counts. Reuse existing page validation tests for bounds 0, 1, 100 and 101 rather than adding an unrelated paging redesign.

## Saved task graph and creation order

| Alias | Outcome | type | parent_id | depends_on | Owned edits |
|---|---|---|---|---|---|
| P | Specify and register archive browsing | task | omitted | [] | Task records only |
| E | Deliver archive browsing | feature | omitted | [P] | Product acceptance after children |
| A | Implement listing contract | task | E | [P] | internal/http/projects.go, internal/projects/list.go, their tests, docs/api/projects.md |
| U | Implement reader control | task | E | [P] | web/projects.tsx, web/projects-api.ts, component tests, docs/projects/listing.md |
| V | Verify integrated reader journeys | task | E | [A,U] | web/e2e/projects-archive.spec.ts plus evidence |

Every create supplies session_id: ses-a101, uses the host-resolved project_dir only in its MCP envelope and ai_optimized=true; saved descriptions/checks use project identity and relative references, never that checkout root; omit parent_id where the table says omitted. The table supplies type/relations and the packets below descriptions/checks. Create and claim P with planning-only scope/checks; P has no delivery children. Create E, then batch A/U once specified, then V with returned producer IDs. API/UI are parallel eligible after P completes because contracts/ownership agree. V waits for both producers; E waits for its children. No child depends on E. Do not claim E while trying to own A with the same agent.

### P creation fields

- title: Specify and register archive browsing
- session_id: ses-a101
- idempotency_key: archive-browsing-plan
- description: the complete Specification, Implementation plan, task graph and coverage in this example, using real observations and returned IDs
- acceptance_criteria: '[P1] Every R1–R8 must have an executable producer and observable validation'; '[P2] Contracts, blockers and edit ownership must permit a cold-start executor to act without guessing'
- tests: '[PT1] Read back P/E/A/U/V: compare each saved requirement/check/edge against the coverage map; no missing requirement or hierarchy/dependency cycle'; '[PT2] Read each leaf plus named P sections: identify next action, fixture/expected results and both code/documentation targets without conversation history'

These are checks of planning quality. Even when P passes, C1–C12 have not been executed and all product checks remain pending.

### E creation fields

- title: Deliver archive browsing
- session_id: ses-a101
- idempotency_key: archive-browsing-delivery
- description: Deliver J1–J3 under R1–R8. Read P Specification and Contracts; A/U own implementation, V owns integrated evidence. Preserve existing default, membership isolation, envelope and pagination; no archive/restore or persisted preference. Completion requires producer and integration results plus guide consistency. No publish/deployment is authorized by this record.
- acceptance_criteria: '[E1] Readers must browse both modes with R1–R7 behavior and without access regression'; '[E2] R8 user/API guidance must match delivered behavior'
- tests: '[ET1] Read completed A/U/V checks and reproduce V current-mode/access scenario using P fixtures; actual expected IDs/counts must hold'; '[ET2] Compare published-in-repository guide examples with verified API/UI behavior and record exact reviewed sections'

### A/U batch creation packet — preserve both complete specifications

The plan is settled and both packets are fully written. Assume creates returned session=ses-a101, P=tsk-a101 and E=tsk-e101; E is open and P still claimed for planning. These are fictional returned values, not IDs to copy into real calls. Batch creation does not require P completed: A/U can exist blocked by it while P records their coverage. The Task session_id belongs to each operation; it is not a batch-envelope field.

Use graphit_task_batch once for the two creates below instead of two separate creation calls. This is YAML presentation of one MCP payload; send the equivalent structured object. project_dir and ai_optimized belong to the envelope. Each operation retains its own complete description, acceptance_criteria, tests, parent, dependencies and stable idempotency_key. A/U here are correlation keys only, never references that Graphit substitutes into IDs.

~~~yaml
project_dir: /example/catalog
ai_optimized: true
operations:
  - action: create
    key: A
    session_id: ses-a101
    title: Implement archived-project listing contract
    type: task
    parent_id: tsk-e101
    depends_on: [tsk-a101]
    idempotency_key: archive-browsing-api
    description: |
      ## Outcome and scope
      Implement R1-R4 and the API half of R8 for J1/J2. Deliver the existing
      GET /projects option without changing response fields, access rules,
      archive/restore behavior or stored schema. No UI files are owned here.
      ## Starting context
      Read tsk-a101 Specification, Contracts, Decisions and fixture matrix C1-C8.
      ListProjectsHandler in internal/http/projects.go performs authentication
      and paging parsing. StrictOptionalBool in internal/http/query.go defines
      absent=false and rejects empty/duplicate/non-lowercase booleans.
      ListProjects in internal/projects/list.go currently applies membership
      AND archived_at IS NULL before id ordering/pagination and matching count.
      internal/http/projects_test.go tests request/errors; list_test.go tests
      membership/counts. docs/api/projects.md describes the current endpoint.
      ## Plan and contracts
      Reuse StrictOptionalBool; pass IncludeArchived through the listing options.
      Keep membership filtering in rows and count. Only omit archived_at IS NULL
      when IncludeArchived=true; preserve filter-before-pagination and id order.
      Preserve existing error/response envelopes and page bounds. Extend tests
      with tsk-a101 fixture C1-C8 and existing paging-bound checks. Update API guide
      request examples, accepted/default values, errors and count semantics.
      Before editing, inspect callers/options through AST and confirm source
      still matches tsk-a101; reconcile material drift instead of copying a stale plan.
      ## Verification and documentation
      Run go test ./internal/http ./internal/projects. Assert exact C1-C8
      outcomes, parser no-call cases and existing page validation regression.
      Compare docs/api/projects.md examples to tested handler/query behavior;
      record inspected symbols/sections and concrete outputs. No unresolved
      decision remains in this example. A missing access/parser contract blocks
      affected implementation, not an invitation to invent it.
    acceptance_criteria:
      - '[A1] R1: absent/false must return only active and true both statuses.'
      - '[A2] R2: items and total must retain membership isolation; no-session calls must remain 401.'
      - '[A3] R3: empty, repeated and invalid booleans must return 400 INVALID_QUERY before repository work.'
      - '[A4] R4: rows and total must apply identical access/status filtering before stable id paging; empty pages must retain the filtered total.'
      - '[A5] R8: API guide defaults, request examples, errors and paging statements must match the delivered handler/repository contract.'
    tests:
      - '[AT1] Seed tsk-a101 fixture; issue absent and false separately, then true as alice. Expect C1/C2 exact IDs and totals, excluding p02 and p04.'
      - '[AT2] Seed tsk-a101 fixture; run C3/C4/C5 with page_size=1 and a no-membership reader. Expect [p03]/2, []/1 and []/0 respectively; existing page bounds must still pass.'
      - '[AT3] As alice run every C6 input and inject C8 storage failure; without session run C7. Expect exact 400/500/401 envelopes; invalid-query/unauthenticated cases make zero repository calls.'
      - '[AT4] Run go test ./internal/http ./internal/projects; compare docs/api/projects.md relevant sections to observed C1-C8 outputs. Record command/result and matched code/doc references.'
  - action: create
    key: U
    session_id: ses-a101
    title: Add accessible archive browsing control
    type: task
    parent_id: tsk-e101
    depends_on: [tsk-a101]
    idempotency_key: archive-browsing-ui
    description: |
      ## Outcome and scope
      R5–R7 and user half of R8; J3 consumes the R1–R4 wire contract in tsk-a101. Add the reader control, request-state behavior, component tests and user guide. Do not edit backend files, shared parser or archive operations.
      ## Starting context
      read tsk-a101 Contracts, Decisions D3/D4 and fixtures C9–C12. web/projects-api.ts/listProjects owns typed arguments; web/projects.tsx/ProjectList owns page/list state. web/useLatestRequest.ts already guards response ordering. web/projects.test.tsx has mocked list transport and the existing error/Retry/translation patterns. docs/projects/listing.md documents reading projects. The provided package scripts run existing component tests; no new testing stack is needed.
      ## Plan and contracts
      add include_archived boolean to the client; keep it false on a new visit. Add the existing localized checkbox pattern labeled Show archived; each toggle resets page to 1 and preserves page_size. Feed both mode and page into the latest-request guard. Loading hides rows; success renders only the matching current request. Failure keeps chosen mode/page, shows localized error+Retry with no rows; Retry issues that same request. Preserve existing keyboard/focus semantics and avoid persistence. Update the user guide with default, archive toggle, access limitation, empty/error/retry behavior and no archive/restore action.
      ## Verification and documentation
      component mocks use tsk-a101 envelopes/fixtures, with deferred responses for ordering and rejected promises for failure. Run npm --prefix web test -- --run projects.test.tsx. Compare guide instructions against rendered labeled controls and states; record exact sections and evidence. API mock success is not integration proof; V must exercise the actual backend.
    acceptance_criteria:
      - '[U1] R5: initial mount must be unchecked; toggle on/off must send true/false, preserve page_size and reset page=1.'
      - '[U2] R6: only the latest request may render; loading/failure must not show old rows; Retry must preserve selected mode/page.'
      - '[U3] R7: the labeled control must be keyboard-operable and each new visit must reset it to unchecked.'
      - '[U4] R8: the user guide must describe observable controls/states and their access/scope limits accurately.'
    tests:
      - '[UT1] Mount with page_size=2 and fixture C1; navigate to another page, toggle on then off. Inspect requests and results: C9, page=1 after each toggle, unchanged page_size.'
      - '[UT2] Run deferred C10: resolve false before earlier true. Only [p01] remains. Run C11: reject true, assert error/no rows/current selection; Retry resolves [p01,p03]/2.'
      - '[UT3] Focus checkbox by accessible label, press Space, leave and re-enter route: C12. Existing localization/focus tests remain passing.'
      - '[UT4] Run npm --prefix web test -- --run projects.test.tsx; compare docs/projects/listing.md instructions to the exercised component states, recording code/doc references.'
~~~

#### Inspect every item and construct the next stage

The response has succeeded/failed totals and ordered results with index, key, action, ok, id, value or error. A successful create exposes the returned task/checks in value. Match by index/key and save the real IDs and checks; do not decide success from transport status or aggregate count alone. Both successful creates remain open and unclaimed. Batch creation is not parallel implementation, and batch cannot grant multiple live claims to one agent.

Suppose both succeed as A=tsk-a102 and U=tsk-a103. Read their saved definitions and then create V from its full packet below, using parent_id=tsk-e101 and depends_on=[tsk-a102,tsk-a103]. V needs the IDs returned by the A/U batch, so it belongs to the next call. Do not send depends_on=[A,U], key expressions or guessed IDs in the original batch. The same staging applies to a new parent, returned claim_token or revision. Independent work already referencing known IDs can share a batch even when its execution dependencies are incomplete.

For a partial failure, suppose A is ok:true and U is ok:false with an error. Preserve A and its returned checks; correct only U's reported problem, then send the complete U create operation alone with the same idempotency_key. Do not resend known successes, invent a new key, claim failed work or create V before both producer identities are established. All items are attempted and successful writes are not rolled back. Even an error can follow an authoritative write before its projections finish; do not assume ok:false means nothing was created.

If the response is lost or creation is uncertain, selectively retry uncertain creates using their original idempotency_key. An existing key returns the saved task; it does not apply a changed description or compare all new fields. Read the recovered record and reconcile changed scope through the normal claim/revise lifecycle, not a repeated create. Verify the response and saved packets before updating coverage or completing P. A failed/ambiguous creation never counts as a saved planning deliverable.

For more than 100 operations, split by known-input stages and bounded groups of at most 100; use smaller groups if context or response size warrants. Never shorten specifications or merge distinct tasks to fit a batch. Other actions also support batch when their IDs/tokens/revisions are already known; per-item lifecycle checks still apply.

### V creation packet — complete integration and consistency slice

- title: Verify archive browsing across API and UI
- session_id: ses-a101
- idempotency_key: archive-browsing-integration; parent_id: E; depends_on: [A,U]; type: task
- description:
  - **Outcome and scope:** prove J1–J3/R1–R8 against combined producers. Own web/e2e/projects-archive.spec.ts and evidence; do not reimplement producer behavior or defer their documentation responsibilities to this task.
  - **Starting context:** read P final contract/fixture matrix plus A/U completion summaries, check evidence and pending-change notes. The configured end-to-end harness starts a local fixture backend; use its alice/bob sessions and the four-row dataset. If producers changed a contract, reconcile their records and P references before testing it.
  - **Plan and contracts:** seed P fixture; exercise actual GET requests for C1–C8 and the browser for C9–C12, including injected transport failure/delays supported by the harness. Assert IDs, totals, request parameters and displayed mode. Compare both guides to actual observed behavior; test API examples and follow user instructions. Classify any gap as missing, partial, contradictory or unrequested and attach requirement/producer IDs. Return substantive defects to a claimed producer/refinement path; never weaken expected results to obtain a pass.
  - **Verification and documentation:** run npm --prefix web run test:e2e -- projects-archive.spec.ts with the fixture backend, plus targeted producer regressions if integration required changes. Record command/environment, individual failed/passed scenarios and code/doc references. If the harness cannot run, keep the integration check pending/failed with the exact recovery action; mocks or planning review do not substitute.
- acceptance_criteria:
  - '[V1] R1–R7: combined API/UI must satisfy all C1–C12 outcomes, including omitted/false equivalence, access isolation, current-mode rendering and recovery.'
  - '[V2] R8: both guides and their runnable examples must agree with actual API/UI behavior; no unresolved contract/documentation contradiction may remain.'
- tests:
  - '[VT1] With the local four-row fixture, run the end-to-end command and direct requests for C1–C12; expect exact matrix results and no inaccessible IDs/counts in any mode.'
  - '[VT2] Read docs/api/projects.md and docs/projects/listing.md; execute API examples and follow the toggle/retry instructions against the combined result. Record matching sections/symbols/observations or flag specific divergences.'

## Requirement-to-evidence coverage saved in P

| Requirement | Producer acceptance | Producer validation | Integrated / parent proof |
|---|---|---|---|
| R1 | A.A1 | A.AT1 | V.V1/VT1; E.E1/ET1 |
| R2 | A.A2 | A.AT1/AT2/AT3 | V.V1/VT1; E.E1/ET1 |
| R3 | A.A3 | A.AT3 | V.V1/VT1; E.E1/ET1 |
| R4 | A.A4 | A.AT2/AT4 | V.V1/VT1; E.E1/ET1 |
| R5 | U.U1 | U.UT1 | V.V1/VT1; E.E1/ET1 |
| R6 | U.U2 | U.UT2 | V.V1/VT1; E.E1/ET1 |
| R7 | U.U3 | U.UT3 | V.V1/VT1; E.E1/ET1 |
| R8 | A.A5, U.U4 | A.AT4, U.UT4 | V.V2/VT2; E.E2/ET2 |

After creates, bind every alias above to actual task/check IDs returned by Graphit. In claimed P, revise its description with this map and settled contracts using the latest revision. Then verify PT1/PT2 and P1/P2 against saved records and record concrete evidence; only then complete P. A/U/V/E remain open, unclaimed and unchecked for a planning-only request. No milestone or implementation is 'done' because this document exists.

## Example of later handoff, not fabricated completion

For the original planning-only request, finish P's coverage checks, checkpoint the session with the saved graph and implementation authorization boundary, and release coordination. E/A/U/V stay open/unclaimed; the session remains unfinished because linked delivery work remains. Tell the user planning is delivered and implementation is pending. Do not execute or cancel that backlog merely to close the session. On a later implementation request, resume/revise the same open session's authorization/strategy before claiming producers.

The following illustrates the shape of a hypothetical A checkpoint; it is not a claim that these commands ran:

- Result: handler/options/query/count implemented; C1–C7 and existing page-bound tests pass in the local fixture; docs/api/projects.md Query parameters/Error behavior updated and compared with those outputs.
- Remaining: C8 failure-envelope regression is not yet run; A.AT3/AT4 and affected acceptance remain unresolved. No completion request is made.
- Known decision: StrictOptionalBool rejects repeated values; no custom parser added. Source references remain P D3 plus internal/http/query.go.
- Next step: inject the repository failure in internal/http/projects_test.go, verify existing 500 envelope/no partial items, rerun go test ./internal/http ./internal/projects, finish API-guide evidence and record remaining check IDs. No UI edits.
- Handoff: Task progress/release carries this state. The coordinator checkpoints session-wide progress/problems/decisions/strategy with A/P references and releases coordination if stopping. A worker releases only its own Task. The next coordinator reads the session's current demand and checkpoint, gets A and prerequisite P, then claims released coordination and ready A with separate private tokens, confirms revisions and reconciles drift.

Use actual commands, results, IDs and artifacts in real evidence. Never paste these hypothetical pass statuses as executed checks. After eventual delivery, reconcile the session's current scope, complete all required Tasks, and call session_complete with final evidence; completing A or E alone does not close the session.
