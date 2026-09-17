---
name: graphit-ast
description: 'AST: replace local code search, file reads and symbol navigation with graph/source queries; inspect callers, metrics and change impact, including installed contexts.'
---

# Graphit AST

`project_dir` is a runtime MCP argument, not persisted project identity. In docs, Task, Memory and handoffs save project identity plus repository-relative paths; never copy a machine-specific checkout root. Resolve the local root again on each host.

Use AST first for supported code discovery, reading and structural analysis. Map your agent's local capability to the operation below; host tool names are examples, not dependencies. Keep source evidence and impact findings for an executable Task plan.

## Translate the local operation

| Intent / familiar local equivalent | Graphit operation |
| --- | --- |
| Search code: Grep, rg, grep, search_text, workspace search | Unknown file: `graphit_ast_search`, then verify selected hits with `graphit_ast_source`. Known file: source with pattern and context. |
| Locate a file: Glob, find, file search | `graphit_ast_schema` once, then `graphit_ast_query` on File.relative_path with a prefix/suffix/substring filter. This queries indexed files, not arbitrary filesystem globs. |
| Read code: Read, read_file, cat, open_file | `graphit_ast_source` with a returned relative path; select an entity or line range instead of dumping a file. |
| First/last lines: head, tail; excerpts: sed, line-range reads | Source head, tail, or start_line/end_line. There is no top parameter; top_k belongs to search. |
| Go to definition / document symbols / symbol search | Query the schema's entity label by name and path; use uid when available to disambiguate, then read source. |
| Find callers / call hierarchy / find usages | Query incoming/outgoing CALLS. REFERENCES and field-access edges answer only the relationships their schema actually indexes. |
| Complexity / impact analysis | Query cyclomatic_complexity; traverse callers at bounded depth; inspect affected source and tests before editing. |
| Go to implementation / type hierarchy | Inspect the schema for supported relationships first. If absent, inspect candidate types/method signatures and report the evidence limit; do not invent an edge. |

Choose the row for the question, not every row. AST does not edit files, execute tests/builds or perform Git operations: use the agent's appropriate native tools for those. After AST has located current-project code, focused local reads for patching are appropriate; do not repeat broad native discovery already answered by AST.

## Target and cheapest useful read

Cluster neighbors are Graphit-managed: use returned `dir` as `project_dir` on AST search/source/schema/query, with paths relative to that target. Never switch to native grep/Glob/walks because it is outside cwd. Read the target AST skill/overrides; cache schema/evidence per target. Resolve unknown projects through Hub's cluster-first route. Only an installed artifact without checkout uses `context: id@version` without `project_dir`; never replace a known local path. `graphit_ast_list` resolves installed contexts. Read other-project/imported source through AST.

Known file → source directly. Unknown location → search with a focused query and `top_k: 5`: `fts` for identifier/text clues, `hybrid` for concepts. FTS is ranked indexed retrieval, not exact identifier equality or exhaustive repository regex. Verify hits in source; use a node query for exact names. Do not automatically pair search and query when one answers.

Before the first query for a target, call `graphit_ast_schema` and reuse it. Labels, properties and edge directions come from that schema. Return only needed columns; use observed paths/UIDs, not guessed absolute-path matches. Pass `ai_optimized: true` on tools exposing it; source/schema do not expose it. `page_size` controls a page, `LIMIT` caps the query result. Follow `next_cursor` while the question needs more results. For an inventory, remove or deliberately widen LIMIT and exhaust pages; one capped result never proves absence.

## Source recipes: search, head/tail, slices and entities

Examples are illustrative, not language, framework, layout or test-runner requirements. Adapt Go/TypeScript paths, symbols and test conventions to the project's languages and schema. For language-specific semantics, inspect its toolchain and authoritative public docs; Hub is not a prerequisite for public technology. Replace sample identities with observed ones; MCP fields and required arguments stay unchanged. These are MCP payloads, not shell commands; keep target fields consistent.

Unknown location — `graphit_ast_search`:
```json
{"project_dir":"/work/app","query":"ParseOrder","mode":"fts","top_k":5,"ai_optimized":true}
```

Known-file grep with surrounding evidence — `graphit_ast_source`:
```json
{"project_dir":"/work/app","path":"src/orders.go","pattern":"return err","before":3,"after":4,"line_numbers":true}
```

Literal `pattern` is a case-insensitive substring. `regex: true` uses Go regular expressions (add `(?i)` if needed); this is not shell grep syntax. Match output includes original file line numbers and merges overlapping context. It searches only the selected file/span, not the repository.

For the same source call, replace the pattern/context fields with ONE of these selectors:

| Need | Selector fields |
| --- | --- |
| First 30 lines / last 30 lines | `"head":30` / `"tail":30` |
| File lines 40–85 inclusive | `"start_line":40,"end_line":85,"line_numbers":true` |
| One function and its branches | `"entity":"ParseOrder","entity_type":"Function","line_numbers":true` |
| Regex alternatives with context | `"pattern":"TODO|FIXME","regex":true,"before":2,"after":2` |

Selectors compose in this order: entity → range → head → tail → pattern. With `entity`, line ranges are relative to the entity, starting at 1; without it, they are file-relative. Use combinations only deliberately (head plus tail selects the tail of that head slice). For homonymous methods in one file, `entity_type` does not distinguish receivers: query their identities/line ranges, select the right definition, then use a file range without entity. Missing source may mean `ast.index_source` is disabled, not that the file is empty.

## Query recipes: definitions, callers, metrics and impact

Examples use labels/properties only if present in your target schema. `Function` may need to become `Method` or another observed label. After resolving a symbol, reuse its UID or its unambiguous path/name in every relationship query. Run each Cypher statement as the `query` of `graphit_ast_query` with the same target and `ai_optimized: true`.

File lookup (Glob-like suffix selection, not a glob expression):
```cypher
MATCH (f:File) WHERE f.relative_path ENDS WITH 'orders.go'
RETURN f.relative_path LIMIT 10
```

Definition, source interval and stored cyclomatic complexity:
```cypher
MATCH (f:Function) WHERE f.name = 'ParseOrder' AND f.path = 'src/orders.go'
RETURN f.uid, f.name, f.path, f.line_number, f.end_line, f.cyclomatic_complexity LIMIT 5
```

Inspect the definition and branches to interpret the metric. Missing, zero or unsupported metrics are not proof of trivial code; do not invent a complexity value. A score helps choose review/test focus, not a blanket rewrite threshold.

Direct callers (incoming call hierarchy) — complete MCP payload:
```json
{"project_dir":"/work/app","query":"MATCH (caller)-[:CALLS]->(f:Function) WHERE f.name = 'ParseOrder' AND f.path = 'src/orders.go' RETURN DISTINCT caller.name, caller.path LIMIT 10","page_size":5,"ai_optimized":true}
```

Direct callees (outgoing dependencies):
```cypher
MATCH (f:Function)-[:CALLS]->(callee)
WHERE f.name = 'ParseOrder' AND f.path = 'src/orders.go'
RETURN DISTINCT callee.name, callee.path LIMIT 10
```

Potential impact up to two caller hops:
```cypher
MATCH (dependent)-[:CALLS*1..2]->(f:Function)
WHERE f.name = 'ParseOrder' AND f.path = 'src/orders.go'
RETURN DISTINCT dependent.name, dependent.path LIMIT 20
```

Read returned dependents and relevant tests, then decide which contracts/checks could change. A reachability result is potential impact, not proof that every caller must change. Closed bounds such as `*1..2` are intentional: bare `*2` is not an exact two-hop bound in this planner. Expand depth only to resolve a concrete remaining risk.

Test candidates: add a reached-endpoint filter to the direct-caller query, e.g. `AND caller.path ENDS WITH '_test.go'` for Go. Adapt naming to the project; inspect candidates in source. Tests may call through helpers, interfaces or runtime dispatch, so also inspect bounded indirect callers and known suites. A matching filename or empty direct-call result does not establish test coverage.

Relationship-query constraints: use `RETURN DISTINCT` and project properties of one endpoint only (as above). Put anchor and reached-node filters in separate top-level `AND` clauses; do not combine both endpoints inside one grouped predicate or cross-endpoint `OR`. For ordering, project the property/alias being sorted. Do not assume a general Cypher engine accepts `collect()`, `label()` or both-endpoint projections here; query the other endpoint separately if needed.

Implementations / type hierarchy: the schema describes the selected graph, not the entire framework's language capabilities. For a target whose schema advertises `(Class)-[:IMPLEMENTS]->(Interface)`, use its observed contract name/path:
```cypher
MATCH (impl:Class)-[:IMPLEMENTS]->(contract:Interface)
WHERE contract.name = 'OrderStore' AND contract.path = 'src/contracts.ts'
RETURN DISTINCT impl.name, impl.path LIMIT 10
```

Adapt labels/direction to the target's schema. In languages with explicit declarations, an indexed implementation or inheritance edge can answer directly. Go interfaces are satisfied implicitly; do not expect an explicit `implements` declaration or infer a framework-wide limitation from its absence in a Go project. If the target has no relevant edge, compare candidate type/method source with the interface and distinguish candidates from verified implementations. Existing Interface nodes alone do not prove that the relation was materialized.

Treat `REFERENCES` according to its declared source/target kinds, not as universal find-usages. Unresolved stubs, empty source paths and dynamic dispatch limit graph completeness; no rows means only no indexed match.

## Integrated change workflow

Before writing an impact assessment, reconciling code with a documented contract, or handing an investigation to another agent, read [the completed impact case](references/impact-assessment.md). It shows observations, limits, test selection and a reusable result. Read it only for that workflow; simple lookups use the recipes above. If the local resource is unavailable, call `graphit_module_skill` with `module: ast`, `reference: references/impact-assessment.md` and the known `project_dir` when available.

For a request such as changing order validation: locate the definition → read relevant branches → inspect callers and test candidates → record affected contracts, files, dependencies and acceptance checks in Task before implementation. Use Knowledge for contracts and AST for current behavior. At any new question during exploration, recall Memory facts/lessons or Task investigations/decisions before guessing; reuse sufficient evidence. Resolve ecosystem identity through cluster/Hub. Load each additional skill immediately before its module is needed; do not preload every module.

In Task preserve logical project/context and revision, relative source paths/lines, symbol names, metrics/relationships, limits and next validation. Keep host-bound UIDs only in the live query; normalize their provenance to relative path and symbol before saving. This evidence lets another agent continue without repeating discovery. Surface discrepancies between code and Knowledge, then reconcile affected documentation. Stop retrieval once the scoped question has enough evidence to answer, plan or validate.

## Recovery and maintenance

For a database-open failure retry once, then inspect `graphit_daemon_status` and report the limitation. For a schema rejection refresh the schema once and correct the query; an unsupported planner form calls for a simpler supported query, not repeated guessing. For an absent current-project graph use `graphit_ast_index`, scoped by `path` when possible. Use `graphit_ast_embed` only for missing semantic coverage; FTS may still work. Do not reset a store to repair a read.

Use native discovery only when the required MCP tool is unavailable or current-project text is unsupported/unindexed; state this fallback once and do not substitute the Graphit CLI. The daemon indexes writes; use `graphit_sync` only when a decision requires proven freshness. The adapter stop hook handles completion sync asynchronously; do not duplicate or wait for it. Context installation/export/removal are maintenance operations only when required; removal without `context` clears the project graph.
