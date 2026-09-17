# Worked system: a project portal with browsing and downloadable reports

Read this for a request spanning multiple independently accepted capabilities. Also read [worked-feature.md](worked-feature.md), whose complete browsing packets are reused below. This example is one bounded system increment, not a universal minimum architecture, stack or task count. All source observations and business answers are fictional evidence to illustrate how a real plan must be grounded. Adapt them; do not assert them about the user's project.

Aliases P/S/D1/A/U/V/D2/B/C/W/G represent returned task IDs; check labels bind to returned check IDs. They are not literal API IDs. Every create has the current host's resolved project_dir in the MCP envelope only (never in saved descriptions/checks), ai_optimized=true, an outcome-specific idempotency_key, and the type/parent/dependencies below. The description, acceptance_criteria and tests packets are required for every record; prose headings are not extra API fields.

## Investigate the whole demand before drawing the delivery tree

Request: 'Build out our project portal so readers can browse archived projects and download project reports from the view. Keep current permissions. Investigate and save the full implementation plan before starting.'

Find/create and claim the durable session before material planning as described in [session.md](session.md). Its description captures both capabilities and the user's planning-before-implementation boundary; its strategy starts with the investigation below. Assume the returned session ID is ses-a101. All P/S/D1/D2 and leaf Tasks share this session_id; S is a Task alias for the system delivery, not the session itself. Delegated workers receive this ID without sharing coordination ownership.

Create and claim P for investigation with this known request, boundaries and planning-quality checks below. Do not start coding from this initial broad record. In P, gather the browsing evidence from the feature example and investigate the report consumer/producer boundary:

| Evidence established through source, documentation or a user answer | Effect on the plan |
|---|---|
| Existing listing source, access, parser, response and UI conventions are exactly those in the feature example | Reuse its R1-R8, C1-C12, A/U/V packets, not a vague 'implement browsing' child |
| Product owner clarifies report format is JSON, with the current page/mode/page_size; there is no all-pages export, background job, saved report, historical snapshot or CSV requirement | Report contract becomes precise; no queue, database migration or arbitrary export limit is invented |
| Product owner accepts data being re-evaluated at download time and temporary disabling of filter/paging controls during download | No promise that an earlier screen is an immutable data snapshot; request parameters cannot drift while download is pending |
| internal/http/routes.go registers authenticated project routes; internal/http/download.go / WriteJSONAttachment uses a fixed filename, serializes before writing success headers, and propagates the normal error envelope before any attachment | Add a sibling authenticated route and reuse the established download helper, preserving the error boundary |
| web/download-json.ts / requestDownload rejects non-2xx responses, downloads only a successful JSON response and exposes a promise; component tests already mock this helper | Reuse the browser download mechanism; do not make up object-URL lifecycle code or ignore failed HTTP responses |
| docs/api/project-reports.md and docs/projects/reports.md do not yet exist; docs/projects/index.md links the current listing guide | B creates API report docs; C creates user report docs and the navigation entry; no hidden shared editing ownership |
| Existing test:e2e harness captures downloads and authenticated fixture requests | W/G can verify real file content and access behavior, not merely a click spy |

The initial sketch had 'download report' as one child. Discovery found an authenticated HTTP producer, a browser consumer sharing U's view-state file, and a real-download validation responsibility. P therefore changes the map to B/C/W, adds A→B and U→C ordering, and records the new report checks before creating delivery records. This is refinement from evidence, not a prescribed number of subtasks.

If format, scope of 'view', permissions or download failure behavior is still unresolved in a real request, ask the material question or create a bounded refinement prerequisite. Preserve unaffected facts; do not mark report leaves ready with invented answers. Stop only the affected branch. A full delivery plan can name unresolved refinement outputs, but implementation readiness waits for their results and reconciliation into each affected packet.

## P saved specification and design

### Journeys, scope and success

J1: an existing reader keeps the active-project workflow and access boundary. J2: the reader chooses to include archived projects. These are D1 and retain the feature example's priorities, R1-R8, contracts and fixture C1-C12 in full.

J3: a reader downloads the selected report page for external inspection, can recover from failure, and understands that its data is current at request time. This is D2. J1/access safety has priority over adding report convenience; D1 and D2 can be separately demonstrated. There is no login redesign, membership administration, write operation, scheduled export, persistent report, new format, deployment or adoption target in this request.

| ID | Observable obligation | Local contract/check consequence |
|---|---|---|
| S1 | All R1-R8 browsing obligations must hold as specified | Instantiate the complete D1/A/U/V packets and map all eight requirements; do not replace them with S1 alone |
| S2 | Authenticated GET /projects/report must apply the same include_archived, page and page_size semantics, access filtering, order and count as GET /projects at the time of the report request | Reuse the service, not a separate authorization/query implementation; response JSON is the same {items,total,page,page_size} envelope |
| S3 | A successful report must be a JSON attachment named projects.json; invalid query, absent session and storage failure must retain ordinary 400/401/500 errors and must not produce a success attachment or partial download | Fixed Content-Disposition attachment filename; application/json success type; serialize before success headers |
| S4 | Download uses the currently displayed mode/page/page_size. It is unavailable while listing is loading, failed or empty. During download, report/filter/paging controls are disabled; success or failure restores them | Capture the validated current parameters once; no duplicate request or mode drift during the pending download |
| S5 | A failed download must show the existing localized report error, preserve rows/mode/page and allow retry; only success may save a file | A failure is not an empty successful report; retry sends the same current parameters unless the user subsequently changes the view |
| S6 | Report names, identifiers and archived booleans must survive JSON parsing, including Unicode, quotes and empty names allowed by the existing data contract | Use standard serialization; compare parsed values, not string-concatenated output |
| S7 | User/API guides must describe page scope, request-time data, controls, response, errors and membership isolation consistently with browsing docs | B/C own their audience docs; W/G verify both surfaces and all cross-links |

Release evidence means observable J1-J3 behavior and the checks below. No desired adoption metric or later field measurement is represented as a test already passed.

### Decisions and cross-delivery contracts

- Reuse ListProjects for browsing/report rows and total: two separate query implementations would drift on status/access/paging. B depends on A's settled service option and must read A's final signature/result before editing. A documents the callable contract in its progress/result.
- Use a sibling /projects/report route rather than changing /projects response headers: existing clients must retain list responses. Existing routes/helper establish the exact registration/serialization pattern.
- Keep D2 separate because report delivery has its own HTTP behavior, browser state and demonstrable outcome. Do not make D2 a check on U or bundle two capabilities into one giant task.
- C follows U because both edit web/projects.tsx view state. B/C can then execute concurrently once their separate prerequisites finish; their shared report wire contract is settled here and their edit ownership is disjoint. Parallel eligibility does not require parallel execution.
- Request-time evaluation, not snapshot storage, is explicit product scope. If a project is archived between browsing and a false-mode report, the report excludes it and recomputes total. Documentation explains this behavior; an executor must not add snapshot persistence to make screens/files identical.
- No known policy question remains in this fictional plan. An actual mismatch in the helper's error semantics, route precedence or authenticated service boundary triggers refinement of B/C/W and coverage before implementation. A source observation is evidence, not permanent truth.

### Fixtures and report validation

Use the feature fixture: alice belongs to p01 active and p03 archived; bob owns p02 active and p04 archived. page_size=2 unless stated. In this report fixture set p01.name to the literal text Café "North" and p03.name to an empty string; names do not affect membership/order. Keep browsing assertions based on IDs/counts rather than assuming different display text.

| Check scenario | Fixture/action | Exact expected result |
|---|---|---|
| Q1 | Alice requests /projects/report with flag absent, then false | Each yields 200 attachment projects.json; parsed IDs [p01], total=1, page=1, page_size=2; archived=false |
| Q2 | Alice requests true | Parsed IDs [p01,p03], total=2, archived=[false,true]; p02/p04 absent |
| Q3 | Alice true, page=2, page_size=1; then false with the same page | First IDs [p03], total=2; second items=[], total=1; page=2/page_size=1 retained |
| Q4 | Reader with no memberships, both modes | Valid API attachment with items=[], total=0; the UI independently disables its empty-view download action |
| Q5 | Empty/yes/TRUE/repeated true,false/repeated true,true include_archived; existing invalid page/page_size bounds; no session; injected storage error | Corresponding 400/401/500 and existing envelope; no success Content-Disposition attachment, no partial JSON file; parser/auth failures call no repository |
| Q6 | Parse Q2 file | Names are exactly Café "North" and empty string, IDs/booleans preserved; valid JSON from standard serializer |
| Q7 | UI settled at true/page=2/page_size=1; click report, hold response; attempt second click/filter/page change; then resolve | One request with captured true/2/1, all relevant controls disabled while pending; saved file contains p03; controls restored |
| Q8 | Same view, reject report then retry | Existing rows/mode/page unchanged; localized error visible; no file; controls restored; retry makes one same-parameter request, then one successful file |
| Q9 | UI listing loading, failed or successfully empty | Report action disabled in each state; click/keyboard cannot issue a request |
| Q10 | List false, then archive p01 in test fixture before report false | Report re-evaluates and returns items=[],total=0; earlier UI rows are not misrepresented as a persisted snapshot |

Q4 intentionally distinguishes an API empty-result contract from a UI convenience restriction. Q10 is a controlled fixture change, not a requirement to add archive actions to this delivery. Reuse existing query-bound cases rather than inventing a new limit.

## Every record saved before implementation

Every creation packet below includes session_id: ses-a101, including inherited feature packets and batch items; replace the illustrative ID with the actual session. A parent/child may not belong to different sessions. The session preserves the evolving whole demand while these Tasks retain complete execution contracts and check evidence.

| Alias/type | parent_id | depends_on | Outcome/owned work |
|---|---|---|---|
| P task | omitted | [] | Investigate, specify and save complete system backlog |
| S epic | omitted | [P] | Accept whole portal increment |
| D1 feature | S | [P] | Accept browsing delivery |
| A task | D1 | [P] | Complete backend/API-doc packet from feature example |
| U task | D1 | [P] | Complete browser/user-doc packet from feature example |
| V task | D1 | [A,U] | Complete browsing integration packet from feature example |
| D2 feature | S | [V] | Accept report delivery after browsing is integrated |
| B task | D2 | [A] | Report HTTP producer and API guide |
| C task | D2 | [U] | Report consumer and user guide |
| W task | D2 | [B,C,V] | Report integration with actual browsing |
| G task | S | [D1,D2] | Whole-system acceptance and residual coverage review |

Create in table order using returned IDs, then read back every record and map every requirement/check. This evidence yields eleven records, including P, two deliverables and their executable subtasks; other demands yield other counts. Hierarchy means aggregation, dependency means a prerequisite. No descendant depends on S/D1/D2. G waits for the two delivery acceptance records, which wait for their own descendants; neither delivery waits for G, so no completion cycle exists.

P is independent of delivery descendants. Complete P after plan-quality verification and leave S/D1/A/U/V/D2/B/C/W/G open. The example request authorizes planning only. With later execution authorization, finish each ready leaf and aggregate deliveries when their descendants complete; do not hold S or a delivery claim while trying to claim its child with the same agent. G then completes, and S is the final aggregate. Parent readiness from P/V alone does not prove its descendants are complete.

### P packet — investigation, specification and saved graph

- title: Specify the project portal and register executable deliveries
- idempotency_key: portal-system-plan
- description: Initially record the request, investigation sources/questions above and expected planning artifacts. During investigation, persist actual findings/answers, then use task_revise with the current revision to save this complete specification, design, fixture matrix, returned-ID graph and coverage. Include the full browsing specification/plan from the feature example as named P sections, not a link requiring an unavailable example. No product implementation is part of P.
- acceptance_criteria: '[P1] The saved scope must resolve material report/browsing contracts or identify blocking refinement outputs'; '[P2] Every S1-S7 and nested R1-R8 must have saved producer, consumer where applicable, validation and documentation coverage'; '[P3] Every record must be executable or explicitly blocked, with legal hierarchy and dependency ordering'
- tests: '[PT1] Read back all eleven records and returned checks; compare coverage and dependencies with this plan, including A→B/U→C and no ancestor edge'; '[PT2] Cold-start walkthrough of A/B/C/W/G must identify inputs, next action, output and fixture/expected result without conversation history'; '[PT3] Compare saved source observations and guide responsibilities to authoritative code/docs, preserving known contradictions as blockers'

P's revision occurs before checking its final scope; revised descriptions reset active checks. Final results bind aliases to returned IDs and each local check label to its returned checks[].id. Save the final description, obtain its current revision, then record planning checks with actual record/source evidence. Do not record Q1-Q10 or browsing C1-C12 as passed during planning.

### S packet — whole-system result

- title: Deliver archive-aware project portal and reports
- idempotency_key: portal-system-delivery
- description: Deliver J1-J3 under P's complete scope. D1 owns R1-R8 browsing; D2 owns S2-S7 report behavior and producer/consumer compatibility; G independently reconciles the whole scope. Read their final results and evidence, not just completion flags. No extra administration, scheduling, persistence or deployment is authorized. S introduces no file ownership; it accepts the integrated system only after all descendants complete.
- acceptance_criteria: '[S1] Readers must complete J1-J3 with the same access/paging semantics and documented request-time report data'; '[S2] No required scope or code/documentation divergence may remain unresolved'
- tests: '[ST1] Read D1/D2/G final checks, reconcile all R1-R8/S2-S7 coverage and reproduce G recorded cross-delivery demonstration or inspect its reproducible artifact'; '[ST2] Verify all descendants completed, no required residual gap/flag remains and final user/API guide references match checked behavior'

### D1/A/U/V packets — fully instantiate the browsing branch

Use the feature example's complete E/A/U/V creation descriptions, acceptance_criteria and tests, including source map, P fixture C1-C12, R1-R8 and docs responsibilities. Rename E→D1, set D1.parent_id=S and bind all P/E/session_id values to this system's returned P/D1/session IDs. A/U/V retain full packets and map A1-A5/AT1-AT4, U1-U4/UT1-UT4, V1-V2/VT1-VT2 to real check IDs. D1 retains E1/E2/ET1/ET2 labels; its idempotency_key identifies this system's browsing delivery.

This is authoring reuse, not permission to save 'see example' as the leaf description. Persist the instantiated packets and shared spec in this backlog so a cold-start executor need not find this skill's example. A's output names the actual ListProjects/options signature and tests; U's output names current mode/page state and pending/error guard; these are B/C's explicit inputs. Verify C1-C12 still hold with the Q6 name fixture. Do not alter D1 acceptance merely because D2 adds a later sibling capability.

### D2 packet — downloadable report result

- title: Deliver reports for the current project view
- idempotency_key: portal-report-delivery
- description: Deliver S2-S7/J3 using P report contract and Q1-Q10. B produces the authenticated report endpoint and API guide; C consumes it from the settled browsing state and owns the user guide; W exercises the real browser/backend. Read V's browsing result before final acceptance. Report mode/page/page_size/access/count are shared with D1, but report data is re-evaluated at request time. Empty API results remain valid; empty UI views disable the action. No all-pages/historical/background export or format choice remains open. Compare producer/consumer assumptions before accepting the delivery.
- acceptance_criteria: '[D2A1] Report producer and consumer must satisfy S2-S6 without access, request-state or error regression'; '[D2A2] S7 report guidance must match actual file contents, page scope and request-time evaluation'
- tests: '[D2T1] Read B/C/W passing checks and their actual Q1-Q10 evidence; verify no consumer contract differs from the endpoint'; '[D2T2] Compare API/user report docs and browsing cross-links against W download/failed-download observations'

### B packet — executable HTTP producer

- title: Add authenticated report endpoint with shared listing semantics
- idempotency_key: portal-report-api
- description: Implement S2/S3/S6 and API half of S7. Read P report contract/Q1-Q6/Q10 and completed A for actual service signature/access/query outcomes. Own new internal/http/project_report.go and project_report_test.go, registration in internal/http/routes.go, and docs/api/project-reports.md. Inspect routes.go and WriteJSONAttachment in internal/http/download.go before editing; do not duplicate query parsing/access behavior from A. Register GET /projects/report under existing authentication, parse the same include_archived/page/page_size contract and call the finalized ListProjects service. Serialize its unchanged envelope through the fixed projects.json attachment helper only on success; preserve ordinary errors before writing headers. Tests exercise both absent and explicit false, true, cross-member rows/counts, beyond-page/zero matches, bad query, absent session, storage error, Unicode/quotes/empty names and request-time data change. Update API guide with endpoint, exact inputs/defaults, response/headers, errors, page scope and no snapshot promise; compare each example to actual test observations. Output the endpoint/signature/helper evidence and check results for C/W; if A or the download helper conflicts with P, refine the affected contracts before implementation.
- acceptance_criteria: '[B1] S2: report rows/count/order/paging and access must match current listing semantics for every supported mode'; '[B2] S3: only successful responses may be projects.json attachments; failures must preserve the specified statuses/envelopes'; '[B3] S6/S7: valid JSON must preserve allowed field values and API guidance must describe tested request-time/page behavior'
- tests: '[BT1] Run go test ./internal/http ./internal/projects with report scenarios Q1-Q6 and Q10; assert exact IDs/totals/statuses/headers/parsed fields and no repository call for parser/auth failure'; '[BT2] Reuse existing page/page_size bound tests for report parsing and verify report route reaches its handler rather than a project-id route'; '[BT3] Compare docs/api/project-reports.md input/success/error examples against handler, helper and actual test output; record exact reviewed sections and any resolved divergence'

### C packet — executable browser consumer

- title: Download the selected project report and recover from failures
- idempotency_key: portal-report-ui
- description: Implement S4/S5 and user half of S7. Read P S2-S7/Q7-Q10, completed U's actual mode/page state and current loading/error guards, and the settled report contract; B need not be complete because that wire contract is fixed in P. Own web/projects.tsx after U, new web/project-report-api.ts, component tests, docs/projects/reports.md and its link in docs/projects/index.md. Reuse web/download-json.ts requestDownload after verifying its non-2xx behavior. Add the localized, keyboard-operable report action, disabled when list loading/error/empty. Capture displayed include_archived/page/page_size for /projects/report; during its promise disable report/filter/paging controls. On success save exactly one file; on rejection preserve list/mode/page and show the established localized report error with retry. Restore controls on either outcome. Do not change U's latest-list-response guard, storage policy or paging rules. Use exact P response/error mocks and parse expected file data in integration W. Document selected-page scope, request-time re-evaluation, pending controls and retry behavior; compare guide wording to component states. Output actual state/helper integration and test evidence for W. A mismatch in B's eventual result requires reconciliation before integration, not an undocumented client workaround.
- acceptance_criteria: '[C1] S4: current parameters and pending/disabled states must prevent duplicate download or control drift'; '[C2] S5: failure must create no file, retain view state and permit correct retry'; '[C3] S7: user guidance and accessible labels must match the implemented report flow'
- tests: '[CT1] Run npm test -- --run from web; component cases Q7-Q9 assert exact request parameters, disabled keyboard/click actions, one download, restored controls and preserved state after rejection'; '[CT2] Repeat U listing-state/toggle tests to show report pending/error additions do not break R5-R7; assert accessible label and keyboard report activation'; '[CT3] Compare docs/projects/reports.md and index link to component/helper behavior; record inspected states/sections and verify API cross-link resolves'

### W packet — report integration

- title: Verify real report downloads against the browsing contract
- idempotency_key: portal-report-integration
- description: Verify S2-S7/J3 using completed B/C/V, P's fixtures and Q1-Q10. Own web/e2e/projects-report.spec.ts; read actual source/helper results before relying on mocks. Use the existing isolated backend/browser fixture and download capture. Exercise report after both browse modes, selected page, disabled/error/retry behavior and allowed field values; make direct authenticated API calls for empty/bad-query/unauthenticated/service-failure cases the UI intentionally prevents. Archive p01 through the test fixture between false listing/report for Q10, proving request-time re-evaluation without adding a product archive operation. Compare API/user report docs and existing browse docs with observed controls, request parameters and file contents. If a producer is wrong, record its requirement/check and concrete defect; create/revise bounded residual work with real dependency ordering rather than weakening expected outputs or claiming a failed check passed. No deployment is performed.
- acceptance_criteria: '[W1] Actual browser/backend report behavior must satisfy S2-S6, including the view-state and data-time boundaries'; '[W2] Both audience docs must match observed report/browsing behavior and all referenced pages must resolve'
- tests: '[WT1] Run npm run test:e2e -- projects-report from web with P fixture; capture/parse downloaded JSON and compare exact Q1-Q10 outcomes, pairing direct API cases where needed'; '[WT2] Repeat projects-archive end-to-end cases after report integration; R1-R8/C1-C12 remain valid'; '[WT3] Review docs/api/project-reports.md, docs/projects/reports.md, docs/projects/index.md and both browse guides against test evidence; record matching sections or resolve divergence'

### G packet — system acceptance and residual reconciliation

- title: Reconcile portal deliveries with the complete request
- idempotency_key: portal-system-validation
- description: Read P's final specification/coverage, completed D1/D2 with descendant evidence, and current authoritative code/docs. Verify the complete J1-J3 flow rather than trusting independent completion badges. Own the system-level acceptance record; change code only through separately specified residual units if new defects appear. Use alice and bob fixture boundaries: visit default active list, turn archived on, select page2/size1, download p03 only, trigger/report error and retry, then return to default browse. Verify count/access and request-time behavior. Trace R1-R8 and S2-S7 to actual checks/artifacts and review all five user/API guide/navigation surfaces. Classify residuals as missing, partial, contradictory or outside requested scope, deduplicate against saved work, and either create bounded corrective units/reconcile blocked closure or record an empty residual set with evidence. Do not invent a task just to make review nonempty.
- acceptance_criteria: '[G1] Each requested journey and contract must have current compatible end-to-end evidence across both deliveries'; '[G2] No required uncovered or contradictory behavior/documentation may remain at closure'
- tests: '[GT1] Run npm run test:e2e -- projects-archive projects-report from web using the same isolated fixture; review the complete journey/download artifacts and compare exact authorized IDs/counts and report error recovery'; '[GT2] Audit P coverage against real returned checks plus current source/docs; record every requirement as proven or a concrete unresolved residual, never assumed from a completed parent'; '[GT3] Read documented listing/report examples against actual handler, UI and captured file outputs; confirm index links and scope exclusions remain accurate'

## Traceability and execution/handoff contract

| Requirement | Producers and checks | Integrated/system proof |
|---|---|---|
| S1 / R1-R8 | Full feature coverage mapping instantiated to D1/A/U/V, with every original returned check ID | V/D1 plus W.WT2 and G.GT1/GT2 |
| S2 | B.B1/BT1/BT2; C.C1/CT1 for parameter consumption | W.W1/WT1, Q1-Q5/Q7/Q10; G.GT1/GT2 |
| S3 | B.B2/BT1; C.C2/CT1 | W.WT1 Q5/Q8; G.GT1 |
| S4 | C.C1/CT1/CT2 | W.WT1 Q7/Q9; G.GT1 |
| S5 | C.C2/CT1 | W.WT1 Q8; G.GT1 |
| S6 | B.B3/BT1 | W.WT1 Q6; G.GT1/GT2 |
| S7 | B.B3/BT3, C.C3/CT3 | W.W2/WT3, D2.D2A2/D2T2 and G.GT3 |

Bind these labels to real task/check IDs in P's final coverage. Preserve the complete feature coverage table as well; a single S1 summary must not hide an untested R1-R8 case. All product checks start pending. P's successful graph/packet review establishes a plan, not implemented behavior.

If G finds a report defect after D2 completed, D2 cannot accept a new child. Create a specific correction R under still-open S with the failed S/Q requirement, current code/doc targets, exact reproduction, checks and D2 provenance. R may depend on completed D2, never on G or S. Save the failure/next step and release G; add R as G's prerequisite while G is open. Complete R, then claim G, reconcile its current description/coverage with R's result and rerun affected system/documentation checks. S remains incomplete throughout. This is new corrective work with preserved history, not an invented reopen operation or permission to mark G passed before the repair.

At execution, consume prerequisite results and reconcile each packet against current source before coding. If A changes its planned options type, B must use the actual supported signature and revise its description/checks if material; a progress note alone is insufficient. If C discovers requestDownload cannot preserve the specified errors, save the concrete contradiction and affected S3/S5/Q8 scope in refinement, then reconcile B/C/W before further affected work. Read [execution.md](execution.md) for claimed/blocked revision mechanics; never drop dependencies to acquire a claim.

Checkpoint each meaningful unit with code/documentation evidence. A handoff from C identifies current wiring/revision; actual passed/failed checks and artifacts; unimplemented retry/guide steps; decisions; prerequisite results; next action/expected result. Example: 'In web/projects.tsx, preserve rows/mode/page in the rejected report promise, add Q8 in projects.test.tsx, run the component suite, then reconcile docs/projects/reports.md failure/retry; C2/CT1/CT3 remain pending until this passes.' Do not claim the example happened or publish a token. Release the Task if stopping. The coordinator checkpoints system-wide effects/problems/decisions/strategy in the session and revises current intent if C changes an agreed contract.

Planning completion preserves the graph without claiming implementation success. For a planning-only stop, checkpoint/release the session with pending delivery IDs; do not close while those Tasks remain open. To resume implementation, read current session intent/authorization, recent checkpoints and chosen Task/prerequisites; obtain separate coordinator/Task claims as needed. Once deliveries/integration and S complete, reconcile every current requirement and scope change, read all associated Task states and explicitly complete the session with final evidence. Closing S is necessary delivery evidence, but never substitutes for closing the session. Hooks cannot decide that transition.
