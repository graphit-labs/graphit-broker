# Worked domain: project lifecycle

This is a complete illustrative documentation set for a fictional product, Workboard 2.4. Paths, HTTP contracts, UI labels, data and evidence below define this example only; they are not Graphit APIs or observations of the current repository. Adapt to the actual domain, language, interface, DOCS_ROOT, supported version and verified sources. Do not copy invented rules into a real project. The example uses handbook/ because that fictional project's configured documentation root is handbook/.

Contents: discovery and coverage; placement; complete root/domain/guide/contract/runbook pages; two drift exercises and check evidence. Read the page type or maintenance exercise relevant to the current work; retain previously read context.

## Discovery and coverage decision

Request in this fixture: document how project readers find archived work, how maintainers archive/restore it, and how another product can integrate safely.

Source inventory in the fictional checkout:
- internal/projects/list.go: ListProjects applies membership before the status predicate; list_test.go covers flag parsing, status and access.
- internal/projects/lifecycle.go: ArchiveProject and RestoreProject authorize maintainers, lock one project, enforce revision and write state plus audit event atomically.
- internal/tasks/create.go: CreateTask takes the same project lock and rejects archived projects.
- internal/projects/model.go and migrations/024_project_archive.sql: status/revision/archive metadata and invariants.
- web/projects/list.tsx and web/projects/detail.tsx: filter, badge and lifecycle controls.
- tests/e2e/project_lifecycle.spec.ts: reader filtering, maintainer actions, task creation rejection and recovery.

Task holds this scope and the documentation checks. Do not claim these sources exist in an unrelated checkout.

| Actor / journey | Rule | Evidence in fixture | Documentation coverage |
|---|---|---|---|
| Reader finds ongoing projects | R1: absent/false include_archived shows active memberships only | ListProjects; ListDefault and ListFalse tests | Domain overview; guide “Find a project”; contract “List” |
| Reader finds prior work | R2: true adds archived memberships, never another workspace's projects | ListIncludesArchived and ListAccessIsolation | Guide “Find a project”; contract “Access and errors” |
| Maintainer archives a project | R3: archive preserves existing work and membership, hides from default list, prevents new tasks | ArchiveProject; CreateTask; ArchiveAndCreateConcurrent | Guide “Archive”; contract “State and transaction” |
| Maintainer restores a project | R4: restore makes project active and permits new tasks | RestoreProject; RestoreThenCreate | Guide “Restore”; contract “State and transaction” |
| Reader attempts lifecycle change | R5: reader gets forbidden; unknown/inaccessible IDs do not reveal existence | AuthorizeLifecycle tests | Guide “Problems”; contract “Access and errors” |
| Integrator retries or races an edit | R6: stale revision gives conflict; same-state request at current revision is no-op | LifecycleRevision and LifecycleNoop | Contract “Mutation”; runbook “Conflict or timeout” |
| Operator diagnoses missing/blocked work | R7: use status/access and audit evidence; no direct database edits | state + transactional audit read path | Runbook; guide links to operator path |

Coverage decision: one domain can share archive/restore rules; a reader guide and an integration contract need different detail. A runbook is justified because uncertain writes and access failures need diagnosis. No separate glossary, migration manual or page per endpoint is needed for this bounded domain; define terms and upgrade constraints in the contract. A whole-system request would map its other domains separately instead of pretending this set covers them.

## Proposed placement, adapted to the fixture

~~~
handbook/
  index.md
  projects/
    index.md
    guides/find-archive-restore.md
    reference/lifecycle.md
    operations/resolve-lifecycle-problems.md
~~~

Keep the real project's conventions if it already separates guides/reference/operations at the root. This tree is a result of the coverage map, not a required count or universal layout. Each page below contains usable content. Relative links are written as they would appear in those destination files.

## Page: handbook/index.md

~~~~markdown
# Workboard documentation

Workboard helps workspace members organize projects and their tasks. This documentation describes release 2.4. Proposed behavior is labeled explicitly; it is not available merely because a design page describes it.

## Projects

- Readers and maintainers: [Find, archive and restore projects](projects/guides/find-archive-restore.md).
- Understand the business rules: [Project lifecycle](projects/index.md).
- Integrate another application: [Lifecycle contract](projects/reference/lifecycle.md).
- Diagnose a missing project or uncertain change: [Lifecycle operations](projects/operations/resolve-lifecycle-problems.md).

These pages cover project visibility and active/archived lifecycle only. Task editing and workspace membership administration belong to their own domains; archiving never replaces either process.
~~~~

## Page: handbook/projects/index.md

~~~~markdown
# Project lifecycle

Audience: project readers, maintainers, integration developers and support operators. Applies to Workboard 2.4.

A project groups related tasks inside one workspace. “Active” means new work can be added. “Archived” means work is retained for reference: it is hidden from the default list and accepts no new tasks. Archiving is reversible and does not delete existing tasks or membership.

## Rules and boundaries

| Rule | Observable behavior |
|---|---|
| R1 / R2 — visibility | The normal list shows active projects the caller can read. “Show archived” includes archived projects with the same access restrictions. |
| R3 — archive | Only a maintainer can archive. Existing content and access remain; new task creation is rejected until restoration. |
| R4 — restore | A maintainer restores an archived project to active. It returns to the normal list and accepts new tasks. |
| R5 — access | A reader can view but cannot archive/restore. Workspace boundaries apply in every state. |
| R6 — concurrent changes | A stale mutation is rejected, never silently applied over a newer change. Repeating the same desired state at its current revision changes nothing. |
| R7 — uncertain outcome | Refresh status and audit evidence before retrying. A lost response is not proof that the operation failed. |

Deletion, bulk archive, scheduled retention, editing existing tasks and membership administration are outside this contract. There is no automatic deletion or expiry of archived projects in release 2.4.

## Choose a path

- [Reader and maintainer guide](guides/find-archive-restore.md): prerequisites, steps and recovery.
- [Technical contract](reference/lifecycle.md): request/response, access, state/data invariants and source provenance.
- [Operational diagnosis](operations/resolve-lifecycle-problems.md): conflicts, uncertain writes and rejected task creation.

Shared rules live here; detailed protocol guarantees live in the contract. [Documentation home](../index.md).
~~~~

## Page: handbook/projects/guides/find-archive-restore.md

~~~~markdown
# Find, archive and restore projects

Use this guide to retrieve previous work or move a project out of the active queue without deleting its content. Applies to Workboard 2.4.

## Before you start

Sign in to the correct workspace. Readers may list/view projects; a maintainer role is required to archive or restore. Use a sandbox project if practicing: lifecycle changes affect everyone working on that project. Before archiving, tell collaborators through your normal process that new tasks will be blocked; the product does not send that notice for you.

## Find a project

1. Open Projects in the intended workspace. “Show archived” starts unchecked.
2. Look for the project by its name. The initial list contains only active projects you can read.
3. If it is missing, turn on “Show archived”. Archived entries appear with an Archived badge; unrelated workspaces remain invisible.
4. Open the project. Confirm its name, workspace and status before any change.

An empty list means no projects match your access and filter; it does not prove that a project was deleted. If it remains missing, use [operational diagnosis](../operations/resolve-lifecycle-problems.md#missing-project).

## Archive an active project

1. Open the project's details and confirm that it is Active.
2. As a maintainer, choose Archive and review the confirmation naming the project and explaining that new tasks will be blocked.
3. Confirm Archive once. Wait for the details page to show Archived.
4. Return to Projects with “Show archived” off: the project is absent. Turn it on: the same project appears with its existing tasks and membership.

Archiving preserves existing work; it does not grant or revoke access. Creating a new task now shows “Restore this project before adding tasks.” To resume work, restore the project instead of creating a duplicate.

## Restore an archived project

1. Find the project with “Show archived” enabled and open it.
2. As a maintainer, choose Restore.
3. Wait for Active. The project now appears with “Show archived” off and new task creation is available again.

The existing tasks are still there; restoration does not recreate or duplicate them.

## Problems and recovery

| What you see | Meaning | Next action |
|---|---|---|
| Archive/Restore unavailable to a reader | Your role cannot change lifecycle | Ask your workspace maintainer to perform the change or grant the appropriate role through the normal access process. |
| “Project changed; refresh before retrying” | Another action changed the project after you opened it | Refresh, read the current state, and decide whether your intended change still applies. Do not repeatedly click the stale action. |
| Request times out or connection drops | The server may have committed the change | Refresh details first. If already in the desired state, stop. If status is unclear, follow [conflict or timeout diagnosis](../operations/resolve-lifecycle-problems.md#conflict-or-timeout). |
| “Restore this project before adding tasks” | The project is archived | Restore as a maintainer, then create the task once. Do not retry creation indefinitely. |
| Project not found | Wrong workspace, missing access or unknown ID | Check workspace and filter; have an authorized maintainer verify access without exposing data from another workspace. |

For API integrations use the [technical contract](../reference/lifecycle.md); for business meaning use [Project lifecycle](../index.md).
~~~~

## Page: handbook/projects/reference/lifecycle.md

~~~~markdown
# Project lifecycle contract

Audience: integrators and maintainers. Applies to Workboard API release 2.4, after database migration 024. This is the current contract for the illustrative release, not a proposed API. The browser and other consumers use the same authorization and lifecycle service.

## Architecture and ownership

The authenticated HTTP handler derives the subject/workspace, validates input and calls the project service. The service applies membership/role checks. ListProjects applies access filtering before the status predicate. ArchiveProject, RestoreProject and CreateTask serialize on the same project row so task creation cannot pass an earlier active check while an archive commits. Repository writes and lifecycle audit events share one database transaction.

Responsibilities and source provenance:
- internal/projects/list.go / ListProjects: filtering and query defaults.
- internal/projects/lifecycle.go / ArchiveProject, RestoreProject: access, revision checks and transitions.
- internal/tasks/create.go / CreateTask: archived-project guard under the project lock.
- internal/projects/model.go and migrations/024_project_archive.sql: authoritative row shape and constraints.
- web/projects/list.tsx, web/projects/detail.tsx: UI controls and state refresh; these are consumers, not authorization boundaries.
- internal/projects/list_test.go, lifecycle_test.go and tests/e2e/project_lifecycle.spec.ts: contract and user-journey verification.

Repository-relative references identify the release-2.4 source baseline in this example. In real documentation, record the actual release/commit inspected. A supported API is the integration boundary; importing these internal packages is not a supported alternative.

## Read and list

The caller must have project-read access in the authenticated workspace.

GET /projects?include_archived=true includes both states the caller may read. Omit the parameter or pass false to return active only. Only literal true/false are valid; any other nonempty value returns 400 invalid_include_archived. GET /projects/{id} returns one accessible project in either state.

Example response for GET /projects?include_archived=true:

~~~json
{
  "items": [
    {"id":"p-17","workspace_id":"w-3","name":"Launch","status":"archived","revision":8,
     "archived_at":"2026-08-10T14:00:00Z","archived_by":"u-9"}
  ]
}
~~~

No matching rows returns 200 with items: []; it does not reveal whether inaccessible projects exist. Filtering does not alter the shape or membership rules. This example's endpoint returns all matching rows; do not infer a pagination contract for a real service without verifying it.

## Mutations and retries

POST /projects/{id}/archive and POST /projects/{id}/restore require maintainer access and a JSON body containing the last observed revision:

~~~json
{"expected_revision":8}
~~~

A successful transition returns 200 with the updated project representation and revision. Archive records the authenticated actor and a UTC timestamp; restore clears those archive fields. If the current state already matches the requested state and expected_revision is current, return 200 with the unchanged representation and no new audit event.

Validate authorization before revealing state. Check expected_revision before the no-op decision: a stale request returns 409 revision_conflict even if another actor already reached the desired state. After conflict or an uncertain network result, GET the project, evaluate its state and retry only if a change is still intended, using the returned revision. Do not replay the old revision blindly.

## Data and transition invariants

| Field | Meaning / invariant |
|---|---|
| id | Immutable project identity; belongs to one workspace. |
| workspace_id | Immutable access boundary for this contract. |
| status | Exactly active or archived. |
| revision | Positive integer, incremented once per effective lifecycle transition. No-op leaves it unchanged. |
| archived_at / archived_by | Both absent for active; both present for archived. Timestamp in UTC; actor is server-derived. |

| Current state / operation | Result | Effects |
|---|---|---|
| active / archive, current revision, maintainer | archived | Increment revision; set archive fields; one project.archived event. |
| archived / restore, current revision, maintainer | active | Increment revision; clear archive fields; one project.restored event. |
| already desired state / same action, current revision | unchanged | No new event or revision. |
| either state / stale revision | unchanged | 409 revision_conflict. |
| archived / create task | unchanged | 409 project_archived; no task inserted. |

Archive does not move/delete tasks, change their IDs or modify membership. State, revision, archive fields and one audit event commit atomically; transaction failure exposes neither a partial transition nor a successful mutation response. Archive and task creation use the same lock: whichever commits first determines whether that creation is accepted. Existing tasks stay readable under ordinary permissions. No retention worker deletes them in release 2.4.

## Access and errors

| Condition | Response / guarantee |
|---|---|
| Unauthenticated | 401 unauthenticated. |
| Unknown or inaccessible project ID | 404 project_not_found; do not distinguish the cases. |
| Accessible project but caller is a reader performing a mutation | 403 maintainer_required. |
| Missing/non-positive/non-integer expected_revision | 400 invalid_revision. |
| Stale revision | 409 revision_conflict; caller must reread. |
| New task on archived project | 409 project_archived; no partial task. |

Errors use {"error":{"code":"revision_conflict","message":"Project changed; refresh before retrying"}} with the condition's code/message. Consumers branch on code, not localized message text. Permission and input errors are not transient retry signals.

## Version and operational boundaries

The default list excludes archived projects starting in 2.4. Consumers that previously depended on archived results must explicitly send include_archived=true. Deploy migration 024 before the 2.4 service; old binaries are not supported against lifecycle writes until their compatibility has been checked. This domain has no feature flag, archive TTL, bulk mutation or automatic retry policy. Do not invent one.

Use [operational diagnosis](../operations/resolve-lifecycle-problems.md) for uncertain outcomes. Use [the user guide](../guides/find-archive-restore.md) for UI workflows and [domain rules](../index.md) for business meaning. Change verification belongs in Task; this page records the supported contract and source baseline.
~~~~

## Page: handbook/projects/operations/resolve-lifecycle-problems.md

~~~~markdown
# Resolve lifecycle problems

Audience: support operators with read access; lifecycle changes additionally require maintainer access. Applies to Workboard 2.4. Diagnose the project in its intended workspace. Do not modify database rows or membership to bypass lifecycle/access checks.

## Missing project

1. Verify the signed-in workspace and whether “Show archived” is enabled.
2. If you know the project ID, use the authorized project details view or GET /projects/{id}.
3. An Archived response explains absence from the default list. A 404 cannot distinguish an unknown ID from missing access; use the normal access-verification process with an authorized maintainer.
4. Confirm recovery by locating the intended accessible project. Do not restore solely to make it visible; readers can enable “Show archived”.

## Conflict or timeout

Capture the project ID, workspace, approximate request time and request correlation ID if returned. Do not capture access tokens.

1. Reread GET /projects/{id} with the same authorized workspace identity.
2. Compare the returned status/revision with the desired action. If already achieved, stop; a retry is unnecessary.
3. If investigation is needed, an authorized operator inspects the corresponding project.archived/project.restored audit event in the existing audit console. Its project, actor, timestamp and revision identify the transition; repeated identical-state requests should have no extra event.
4. If still in the other state, confirm the action is still wanted and use the latest revision once. Repeated conflicts require coordinating competing changes, not an unbounded retry loop.
5. A failed diagnostic read means outcome remains unknown. Record that limitation and escalate with the captured identifiers; do not report that archive failed merely because the network failed.

Recovery is verified when the authorized read shows the intended state and ordinary list/task behavior matches that state.

## Task creation blocked

Read project status. If archived, a maintainer must restore before a task can be created. If active, capture the observed revision/error and investigate concurrent lifecycle activity. After restoration, retry creation using the application's normal duplicate-prevention rules; this lifecycle contract does not define a task-creation idempotency key.

## Release or database mismatch

Check service release and the migration-024 record through the standard deployment tooling. Stop lifecycle writes and escalate if rollout order or compatibility is uncertain. Do not roll back by removing archive metadata or manually clearing status. A data rollback procedure is not defined by this release's lifecycle contract; use the verified deployment recovery procedure for the actual environment.

[Technical guarantees](../reference/lifecycle.md) · [User steps](../guides/find-archive-restore.md) · [Domain overview](../index.md).
~~~~

## Drift exercise A: code → docs in the same work unit

Fixture change: release 2.3 listed both states by default. An authorized 2.4 work unit changes ListProjects so absent/false hides archived rows, and adds the initially unchecked “Show archived” UI control. Archive/restore behavior itself is unchanged.

The agent reads the old domain overview, guide, list contract and missing-project runbook alongside ListProjects and list.tsx. It finds “Projects lists all your work” in the old guide and no query-default statement in the contract. Updating only the API code would leave users and consuming projects with the wrong behavior.

The delivered 2.4 pages above reconcile R1/R2: explicit default and opt-in in the contract; initial toggle and missing-project recovery in the guide/runbook; navigation and version statements kept consistent. R3–R7 are inspected as unchanged; no unrelated retention or permission feature is added.

Illustrative Task evidence packet (a real agent must replace it with observed results):
- Targets: list.go/ListProjects, list_test.go, list.tsx, all five page paths above; lifecycle.go inspected for unchanged archive/restore semantics.
- Requirement coverage: R1/R2 → ListDefault, ListFalse, ListIncludesArchived, ListAccessIsolation → guide “Find a project” and contract “Read and list”.
- Validation to execute: go test ./internal/projects and the project's configured end-to-end runner for project_lifecycle.spec.ts. Default/off must show only accessible active records; on must add accessible archived records; neither shows inaccessible records. Do not substitute an invented test command.
- Documentation check: follow root→domain→guide→contract→runbook links and compare example IDs/status/revision; search affected pages for the obsolete all-states default.
- Record actual command exit/output, browser observations and failures in Task checks. If the browser runner is unavailable, the end-to-end check is pending; source agreement alone does not prove the UI scenario passed.

## Drift exercise B: docs → code without manufacturing a feature

Fixture request: improve the archive guide. An existing draft says “Archived projects are deleted after 30 days.” AST inspection of lifecycle.go, model.go, migration 024 and the configured job entrypoints finds archive/restore state only; no timer, deletion job or accepted retention requirement supports that sentence.

Classify the statement as unsupported current-behavior documentation, not an invitation to add a retention worker. Check the release contract and Task intent. In this fixture both confirm preservation until an explicit lifecycle change. Correct the guide/domain overview to state that release 2.4 has no automatic deletion; keep the actual retention policy outside this bounded contract unless authoritative evidence defines one. Verify the archive/restore and preservation tests and affected links; record inspected sources and actual results.

If the user instead explicitly requests a future 30-day retention policy, preserve it as proposed intent in a clearly labeled specification with unresolved requirements (start time, exemptions, permissions, recovery and migration). Link a Task planning unit. Do not present a runnable deletion API, promise recoverability, mark delivery checks passed or implement it from a docs-only request.

Illustrative completed-unit evidence distinguishes the two:
- Documentation correction: unsupported claim removed; source/test targets named; user/technical pages agree about the current release. No code change needed, because no accepted current requirement was violated.
- Future design alternative: intent documented, implementation missing, planning Task open; current user guide still states actual behavior. The documentation/design unit may complete on its own checks; the future feature is not implemented.

## Cold-reader review of the set

A reader can find archived work and recover from a missing project without knowing database internals. A maintainer can predict preservation and the new-task restriction. An integrator can construct requests, interpret defaults/errors and retry against a current revision without internal-package access. An operator can diagnose uncertain outcomes without guessing success or editing storage.

Review the real delivered set using those scenarios, not by counting files or checking that headings exist. Search and source-read selected pages after indexing only when retrieval/navigation freshness needs verification; do not force a full sync after every documentation edit. Publishing these pages through Hub is a separate authorized action with verified artifact/version/target.
