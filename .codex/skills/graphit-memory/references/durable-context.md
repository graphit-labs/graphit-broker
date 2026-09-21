# Recall, capture and reconciliation

Read for the first unfamiliar mid-work recall, correction, duplicate merge or durable discovery; reuse thereafter. Sections: contextual recall; correction; no-write and first capture; duplicate preservation; uncertainty and scope.

Examples are fictional and illustrative: substitute observed IDs, project paths, facts and source references. They do not prescribe a language, toolchain, host path or universal policy. A user correction's actual conditions take precedence over an example.

## Case: a new question halfway through implementation

The session is already active and its task is claimed. While reading a webhook handler, the agent finds a 48-hour replay guard and asks why that duration exists. Nothing is blocked and no new plan or session has started; this is still a recall trigger. The retained context explains the current edit but not this behavior's reason.

1. Choose the missing knowledge: Memory may hold the known provider constraint; Task may hold the earlier investigation and rejected alternatives. A known relevant memory ID goes straight to graphit_memory_source. Otherwise one focused graphit_memory_search:
~~~json
{"project_dir":"/work/portal","query":"webhook replay 48 hour retention","exclude_mandatory":true,"top_k":5,"ai_optimized":true}
~~~
2. Suppose returned titles include a relevant replay-policy entry and an unrelated deployment entry. Read only the relevant returned ID with graphit_memory_source. Its content explains a provider retry window and references the task that established it. Do not infer this conclusion from the title.
3. If that entry answers the question, stop recall. If the agent also needs the measured retry evidence or rejected alternatives, read the referenced task ID directly with graphit_task_get. If no ID is known, first use graphit_task_search for the missing topic, then get the selected task. The Task skill governs that read. Reading historical work does not claim/reopen it or replace the current work task.
4. Compare the recorded provider/version/date and prior test evidence with current AST source and Knowledge contract before treating the old reason as current truth. A past success or stated policy is evidence of that scope, not proof of today's behavior. Preserve a remaining contradiction explicitly instead of choosing whichever source is convenient.
5. Record the finding and its effect in the current Task's meaningful checkpoint. Update Memory only for a new/corrected reusable conclusion; do not rewrite it just because it was read.

The /work/portal path above exists only in the illustrative live MCP envelope. The saved conclusion cites project identity, relative handler path, source revision and returned task/memory IDs. No machine root belongs in the content.

Later in the same session, a question about ordering rather than replay duration can need a new focused search even in the same module. The same replay question with sufficient retained evidence needs zero calls. Mandatory-memory bootstrap remains once per missing scope; contextual searches have no once-per-session limit.

## Case 1: preserve a correction without losing its boundaries

A user says: “For our ecosystem projects, resolve the local cluster first. Public React usage doesn't need Hub. If XPTO is only published, install the relevant context and consult it.”

The current host temporarily resolves the initialized portal project to /work/portal; that root belongs only in the MCP envelope, never in the saved content. The user's cluster-first guidance is durable: capture that rule now, without waiting for a separate “remember” request. If a matching mandatory entry is already in context, reuse it directly. Otherwise one focused graphit_memory_search:
~~~json
{"project_dir":"/work/portal","scope":"project","query":"ecosystem discovery Hub local cluster","exclude_mandatory":true,"top_k":5,"ai_optimized":true}
~~~

Suppose it identifies current memory 01J00000000000000000000004, “Ecosystem discovery,” whose title alone does not reveal its conditions. Read graphit_memory_source:
~~~json
{"project_dir":"/work/portal","scope":"project","id":"01J00000000000000000000004"}
~~~

Assume its current content says every external dependency must first be found in Hub, while also requiring exact version selection and resolving local project paths at call time. The first statement is superseded; the latter conditions still matter. Update the same subject with graphit_memory_update:

~~~json
{
  "project_dir":"/work/portal",
  "scope":"project",
  "id":"01J00000000000000000000004",
  "title":"Resolve ecosystem projects locally before published artifacts",
  "content":"For this project's work, resolve named unfamiliar ecosystem systems through the local cluster first and use the selected absolute directory only as the current call's project_dir; save logical project identity and relative source references, not the expanded host path. If no local match exists in that scope, discover the published Hub project and select the relevant supported artifact and exact version. Announce and install an obvious authorized fit, then consult its content through the appropriate module; ask for a choice only when candidates differ materially. Known public technologies such as React need no mandatory Hub lookup, while an explicit Hub artifact request still does. A published artifact implies no checkout: only a resolved global install without a local path uses its exact id@version context. Installation of runnable content does not by itself authorize execution. Rationale: preserve the engineer's working project context while using the published ecosystem when local context is absent. Source: user correction recorded in the current Task's decision checkpoint; supersedes the old blanket external-dependency Hub-first rule."
}
~~~

In a real write, replace the source phrase with the known task ID/decision location. Do not invent an ID. Preserve all still-valid conditions actually present; this example's added details are assumed confirmed for the case, not inferred from one sentence.

This is an update, not an extra insert that leaves two contradictory “current” rules. The successful acknowledgement is durability evidence; no routine search, list or sync follows. Full discussion and tool evidence stay in Task. If maintained instruction documentation also contains the obsolete policy, reconcile it through the authorized Task/Knowledge workflow; changing Memory alone does not fix those documents.

The update schema changes title/content and optional structured references. When source records are known, explicitly send their typed IDs in references; prose alone does not establish a relation. Omission preserves the existing list; [] clears it. It does not accept type, mandatory, important or ai_optimized. If confirmed recall needs now require every-session visibility, use graphit_memory_mark_mandatory separately with the same project/scope/id. Do not promote every correction by default or claim content editing changed its classification.

## Case 2: unchanged repetition and new structural knowledge

### Repetition: no write

In a later related step, the user repeats “React doesn't require Hub.” The current memory already records that condition. Reuse it. No insert, update, source reread or promotion is needed unless the remembered conditions are missing or new evidence changes the rule.

### First capture: a reusable source-of-truth discovery

Suppose an investigation confirms that instructions are generated from rule.go plus module content/reference providers; editing installed copies is overwritten on installation. That discovery affects future maintenance and is costly to rediscover. Before insertion, search the subject once unless a matching entry is already known.

If no current matching subject exists, graphit_memory_insert can store:
~~~json
{
  "project_dir":"/work/portal",
  "scope":"project",
  "title":"Generated instructions must be changed at their module source",
  "type":"fact",
  "important":true,
  "content":"In this project, module InstallSkill code selects generated module content and installs the agent skill and its references. Change the authored module providers, then validate the relevant installer and reader; editing only installed SKILL.md copies will not survive regeneration. Scope: generated Graphit module instructions, not user-authored project documentation or arbitrary external skills. Rationale: keep every agent and MCP reader consistent with one maintained source. Evidence: verified module installation/content source and the generator tests linked in the current investigation Task."
}
~~~

Replace the source summary with exact inspected paths/symbols and task reference. Choose fact only for confirmed behavior; use decision/convention/correction for those actual categories. Important is appropriate here only if the consequence and conditional future value warrant it; mandatory would require every-session relevance. A single test result or routine function signature normally stays in Task/AST.

This example is specific to a verified generated-instruction project. For another repository, preserve its real source-of-truth mechanism, not Graphit's filenames.

## Case 3: duplicate does not mean disposable

Assume two selected memories overlap:
- A says local ecosystem discovery precedes Hub and uses the current host's known absolute path only for tool calls.
- B repeats cluster-first, but uniquely explains global artifact version addressing and why installation does not authorize execution.

Do not delete B because its title looks redundant. Merge the distinct conditions, rationale and provenance into A with graphit_memory_update. Read A once with graphit_memory_source to verify preservation before deleting B with graphit_memory_delete. If preservation is uncertain, keep both and record the conflict. Routine writes do not require this readback; deletion after a merge does.

Never remove unique facts, weaken a user constraint or demote critical guidance to satisfy a token budget. Do not expand this scoped merge into a scan of unrelated memories.

## Uncertainty, changes of scope and unavailable persistence

| Situation | Correct handling |
| --- | --- |
| A code observation appears to conflict with a user policy | Preserve the user condition and observation with provenance. Resolve whether implementation, documentation or the policy's applicability is wrong; do not turn an inference into a superseding correction. |
| Search returns an archived revision | Read its current entry before applying it. History explains earlier behavior, not necessarily today's rule. |
| The fact is only about the current debugging attempt | Keep it in Task with evidence/next action; no durable Memory entry. |
| A cross-project preference is explicitly general | Use user scope; do not widen a project rule merely because it seems reusable. Installed AST/Knowledge artifacts provide no project memory store. |
| The update response is ambiguous | Establish the current entry before retrying a mutation. Do not invent success or duplicate the fact. |
| Memory MCP is unavailable | Keep the conclusion and exact persistence continuation in the available Task handoff and state that it was not saved to Memory. Do not use native memory or Graphit CLI as a substitute. |

A good durable entry lets a future agent answer: what is true or required, where it applies, why it matters, which evidence supports it and what earlier rule changed. A good Task checkpoint preserves how that conclusion was established and what remains unresolved. Keep each in its proper store.
