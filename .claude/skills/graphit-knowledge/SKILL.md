---
name: graphit-knowledge
description: 'Knowledge: retrieve and maintain user/technical documentation by business domain; verify code/documentation consistency for every changed work unit using wiki and implementation evidence.'
---

# Graphit Knowledge

`project_dir` is a runtime MCP argument, not persisted project identity. In docs, Task, Memory and handoffs save project identity plus repository-relative paths; never copy a machine-specific checkout root. Resolve the local root again on each host.

Knowledge maintains user/technical documentation by business domain and reader goal. Make it usable by someone or another project without this conversation. Task owns executable specifications/plans/results; AST proves code behavior; Memory holds durable constraints.

When a task, session, memory or knowledge page relies on another record, explicitly send `references` with each target's `type` and `id`, plus `relation` (for example supports, implements, derived_from or relates_to). Resolve real IDs through the corresponding read tools; never invent them. Mentioning an ID in prose or making a Markdown link does not create a database relation. Send the complete intended explicit list on reference changes; omit it to preserve existing relations, and send [] to clear explicit relations. Structural task/session links remain managed by their existing fields. Qualify cross-project/user targets with `scope` and `scope_id`, and imported knowledge with `context`; use logical identities, never checkout paths.
Example write input: `references: [{"target": {"type": "memory", "id": "<verified memory ID>"}, "relation": "supports"}]`. The source is the record being written; do not repeat a source ID. Read its existing references before replacing the list so unrelated links survive.
Use `graphit_references_query` with source_type/source_id for outgoing relations or target_type/target_id for backlinks. Scope filters retain identity; include_user explicitly adds personal memory. If the result reports incomplete projections, `graphit_references_reconcile` repairs writable local module projections from existing structured data; it never invents relations from prose.
For Knowledge, declare the same typed references in the authoritative Markdown YAML frontmatter under `references`, as a list of objects with `target: {type: memory, id: <verified ID>, scope: project, scope_id: <project ID>}` and `relation: derived_from`. Indexing persists that metadata. Keep existing frontmatter and reference entries when editing; an explicit `references: []` clears authored relations. Ordinary wiki links remain a separate persisted wiki-link relationship.

## Load detail at the decision boundary

Retrieval alone needs no reference. Before planning/reorganizing docs or reviewing domain coverage, read [documentation design](references/documentation-design.md). Before first substantive domain authoring, read [worked domain](references/worked-domain.md); adapt depth, not its stack/rules/file count. Narrow maintenance needs only the design reference's per-unit consistency section when guidance is missing. Reuse retained references. `DOCS_ROOT` means this project's `docs/` or its existing authoritative location.
If local reference files are unavailable, use `graphit_module_skill` with `module: knowledge`, `reference: references/documentation-design.md` or `references/worked-domain.md`, and the known `project_dir` when available; request only the needed reference.

## Retrieve enough evidence

1. Known slug → `graphit_wiki_source`; otherwise `graphit_knowledge_search` for the target/installed `context`, or `graphit_wiki_search` across selected `wikis`/`hub_refs`. A cluster neighbor is Graphit-managed: use its returned `dir` as `project_dir` on wiki/module reads, not native discovery. Read its skill. For unresolved projects use Hub's `graphit_cluster_projects` before its catalog. Hub-only: announce/install Knowledge; the question authorizes preparation. Without a local checkout, use resolved installed `id@version` as `context`, omitting `project_dir`. Public technologies need no Hub; verify version details in official docs.
2. Use focused terms, `top_k: 5`, `ai_optimized: true`; `preview: true` only to disambiguate titles. Titles are not evidence. Read selected `graphit_wiki_source` pages with returned slug as `path`, preserving project/context. Slice long pages; expand for relevant surrounding rules.
3. Reuse results; stop once sources answer the question. Follow `next_cursor` for unresolved coverage/exhaustive inventory only. A miss is not absence: refine once or use `graphit_wiki_browse` with relevant `doc_type`; `graphit_knowledge_list` is for an intended catalogue.
4. Use `graphit_wiki_xrefs` with a shallow depth for unresolved provenance/relationships, or `graphit_wiki_log` for change history. Do not load either for every page.

At any stage, new questions may need Memory facts/lessons or Task investigations/decisions/results. Reuse sufficient context; read its skill and retrieve the missing topic. For Task, known ID → `graphit_task_get`; otherwise `graphit_task_search` → selected records. Check history against current docs/code; do not query both stores mechanically. State gaps if a needed source is unavailable.

## Design and write maintained documentation

Map domains, actors/journeys, rules/contracts, implementation evidence and page targets in Task before writing. Extend existing navigation: root → domain → user/technical/operation pages as needed. File count/headings do not prove coverage; no empty skeletons or generic overview replacing unrelated domains.
Write in `docs/` or the authoritative source, never the generated wiki/store. Users need prerequisites, steps, outcomes and errors/recovery; consumers need contracts, boundaries, data/state, source/version, operations and provenance. Link shared facts; keep examples consistent. Label proposed behavior, assumptions and unverified findings. Resolve scope in Task without inventing rules. Authorized docs maintenance needs no extra approval.

## Verify both directions for every work unit

For EVERY code work unit, inspect/update affected user/technical docs, examples and navigation in that unit. For EVERY doc work unit, inspect corresponding implementation with AST and validate its claims. Check rule → source/test → page and changed page → implementation/consumers; inspect affected references for contradictions. No-impact conclusions name inspected targets and rationale.
Resolve drift: correct stale docs, fix authorized defects, or label future intent/current limitations and preserve unresolved work in Task. Never weaken a requirement to bless a bug or expand code scope to match a draft. Verify relevant commands/examples, links and outcomes. Distinguish documentation quality from implementation agreement, executed tests from inspection. Before unit completion record targets, version/scope, actual evidence, findings and next action in Task progress/checks. The references show review criteria and both drift directions.

Other-project documentation is read only through its resolved wiki tools. If required MCP tools are unavailable or current-project text is unindexed, use focused native reads of current-project authoritative documents, state the fallback once and do not substitute the Graphit CLI.

## Freshness and maintenance

The daemon indexes `docs/` after writes. Use `graphit_knowledge_index` for missing coverage or a specific directory; `graphit_knowledge_sync` only when knowledge freshness is needed for a decision, or `graphit_sync` when multiple indexes must align. Do not duplicate the asynchronous completion hook. On stale/locked reads, check `graphit_daemon_status`; retry a transient failure once before reporting it.

Use `graphit_knowledge_lint`/`graphit_knowledge_schema` for diagnostics, `graphit_wiki_embed` for missing semantic coverage, and `graphit_knowledge_export` for requested exports. `graphit_knowledge_remove` without `context` clears the project wiki; never reset to repair search. For reuse through Hub, make scope/version, prerequisites, supported contracts, navigation and provenance self-contained; use the Hub skill at publication/consumption boundaries. Documentation maintenance alone does not publish an artifact.
