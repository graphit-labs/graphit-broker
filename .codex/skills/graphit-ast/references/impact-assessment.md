# Complete impact assessment

Read this when an investigation must become a decision, executable plan or handoff. Sections: scope and evidence; interpret the result; contract reconciliation; recovery. A single source lookup does not require this workflow.

## Case: changing the generated AST guide

Request: “Understand ASTRuleContent, its complexity, callers and the impact of changing its instructions.”

This case uses observations from Graphit's own Go index on 2026-09-16. They demonstrate evidence quality, not permanent line numbers or a required stack. Re-query the current target before acting. Replace /work/graphit-code only in the live MCP payload with the current host's verified root. Never save that expansion in the analysis, docs or handoff; persist Graphit project identity, revision and repository-relative file/symbol references. For a globally installed artifact without a checkout, use its resolved context instead of project_dir. All paths, languages, test runners and layouts are illustrative; adapt them to the observed project.

The analysis task's scope is generator behavior and affected consumers. It does not authorize changing instructions. Reuse its known requirements and relevant Knowledge pages; record uncertain intent instead of deciding that the implementation is automatically the contract.

### 1. Establish identity and read the definition

Call graphit_ast_schema with {"project_dir":"/work/graphit-code"} once. The observed schema supplies Function, uid, path, line_number, end_line, cyclomatic_complexity and CALLS.

graphit_ast_query:

~~~json
{"project_dir":"/work/graphit-code","query":"MATCH (f:Function) WHERE f.name = 'ASTRuleContent' AND f.path = 'internal/ast/rule_compact.go' RETURN f.uid, f.path, f.line_number, f.end_line, f.cyclomatic_complexity LIMIT 5","ai_optimized":true}
~~~

Observed identity: internal/ast/rule_compact.go::ASTRuleContent; stored cyclomatic complexity: 1. Read it with graphit_ast_source:

~~~json
{"project_dir":"/work/graphit-code","path":"internal/ast/rule_compact.go","entity":"ASTRuleContent","entity_type":"Function","line_numbers":true}
~~~

The body builds a Markdown guide with strings.Join and branded tool names. A complexity of 1 describes control flow, not the correctness or conceptual complexity of its many instructions. Changing a string can still break a tool route or misdirect an agent.

### 2. Trace consumers, then inspect their actual behavior

graphit_ast_query:

~~~json
{"project_dir":"/work/graphit-code","query":"MATCH (caller)-[:CALLS]->(f:Function) WHERE f.uid = 'internal/ast/rule_compact.go::ASTRuleContent' RETURN DISTINCT caller.name, caller.path LIMIT 20","page_size":20,"ai_optimized":true}
~~~

The observed result had four callers and no continuation cursor. Read the relevant definitions rather than treating their names as proof:

| Observed consumer | Source evidence and implication |
| --- | --- |
| InstallSkill, internal/ast/rule.go | Resolves the target project's module override, adds frontmatter, installs the selected content. Generator wording changes the default installed guide; a project override remains a separate source of truth. |
| registerLifecycleTools, internal/mcpstdio/tools_lifecycle.go | Uses ASTRuleContent as AST's default module-skill content. Compare the MCP reader and installer so agents receive consistent instructions. |
| TestASTInstructionContextBudgets, internal/ast/rule_compact_test.go | Checks generated guide and resident-mandate size. It cannot establish semantic correctness of a recipe. |
| TestCoreInstructionsReferenceRegisteredTools, internal/mcpstdio/mandates_test.go | Checks that named tools in instruction surfaces are actually registered. It cannot establish that all arguments or query forms work. |

For the first row, call graphit_ast_source with path internal/ast/rule.go and entity InstallSkill. For the MCP row, a focused source pattern ASTRuleContent with before/after context locates the dispatch; expand to the handler's resolution/override logic before concluding parity.

If a remaining question concerns startup propagation, use a bounded two-hop caller query. Do not expand the whole graph simply because more edges exist. The observed four rows are the indexed callers for that snapshot, not a proof that reflection, textual references or external consumers cannot exist.

### 3. Produce a useful result, not a search transcript

A completed Task analysis can contain:

> **Conclusion:** ASTRuleContent generates default AST instructions; current direct consumers include the project skill installer and MCP module reader. Its stored complexity is 1, but instruction correctness needs contract validation.
>
> **Potential impact:** changed default wording reaches those two delivery surfaces; project overrides require explicit preservation. Existing budget and registered-tool tests are relevant but do not prove recipe behavior.
>
> **Evidence:** project Graphit, source revision of the inspected snapshot, relative identity internal/ast/rule_compact.go::ASTRuleContent; InstallSkill and registerLifecycleTools source; both named test bodies; query scope was the selected local graph with no remaining direct-caller page.
>
> **Uncertainty:** dynamic or external consumers are outside this graph's demonstrated coverage. No product behavior has been changed or tested by this analysis.
>
> **Next action if a change is authorized:** update the generator; validate one representative query/payload per changed recipe; run the existing affected checks; compare generated installation and MCP content; reconcile affected instruction documentation. Keep unchanged recipes' prior evidence rather than rerunning every investigation.

For this repository, the observed focused command is:
~~~sh
go test ./internal/ast ./internal/mcpstdio -run 'TestASTInstructionContextBudgets|TestCoreInstructionsReferenceRegisteredTools' -count=1
~~~
Inspect the current test setup first. This command is an example for this Go project, not a universal validation convention. A successful command and a live query result are separate evidence; record what each establishes.

## When intended behavior and code disagree

Suppose a maintained contract says “project overrides take precedence,” but inspected installation source actually selects a default before consulting the project. That is a hypothetical discrepancy, not a finding from the case above.

Record: authoritative page/section and Task requirement -> observed source branch -> reproducible scenario -> consequence -> correction or unresolved decision. A regression scenario could create a temporary project with an override, install its skill and compare the produced content. Do not weaken the documented requirement merely to match code, or change code based on an outdated page without resolving its authority.

Check both directions: every changed behavior/contract has accurate documentation; every changed documentation claim has supporting code or is explicitly planned. Preserve each unresolved difference in Task, with its owner/prerequisite and next validation. If implementation is requested, create or revise only the missing scoped work and reuse existing coverage; an audit with no gap needs no artificial task.

## Incomplete evidence and recovery

- Same-name definitions: resolve path/UID and source interval before callers. A broad name match can combine unrelated impacts.
- Empty callers: verify target identity and graph scope, then inspect known interfaces/tests. Report no indexed match, not unused code.
- Missing metric: inspect branches and report the metric unavailable; do not replace it with a guessed score.
- Missing implementation edge: schema describes this graph. Use supported explicit edges when present; for implicit Go interfaces, compare signatures and distinguish candidates from verified implementations.
- Query rejection: simplify to supported endpoint projections and separate top-level predicates; refresh schema once only if it changed. Do not escalate to arbitrary Cypher.
- Missing/stale source: use the main skill's targeted index/freshness recovery. A database/service failure is not a source finding.

Stop when the scoped decision has sufficient authoritative evidence. Preserve reusable structural discoveries in Memory only when future agents benefit; keep this full investigation and its next action in Task.
