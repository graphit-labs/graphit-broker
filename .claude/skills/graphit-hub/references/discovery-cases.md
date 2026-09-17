# Discovery through useful evidence

Read this before a new ecosystem discovery/install workflow, material artifact choice or unresolved search. Sections: local project; published context; other artifacts; recovery and handoff.

All names, IDs, paths, versions and observations below are fictional supplied responses for illustration. Never construct these identities in real work: substitute returned values. Project language, host OS, repository layout and artifact type are not fixed by these examples. Paths such as /work/portal belong only to live tool payloads. Save project/artifact identity, version and relative references in shared results; resolve local roots anew on another host.

## Case 1: “Explain XPTO's approval contract”

The agent is working in an initialized project at /work/portal, a verified directory. XPTO is a named ecosystem system, not an assumption about a public framework.

Call graphit_cluster_projects:
~~~json
{"project_dir":"/work/portal","ai_optimized":true}
~~~

### Local branch

Assume the result identifies XPTO with absolute dir /work/xpto. This is another Graphit-managed project, not an invitation to use local grep/Glob/read_file on a neighboring directory. Discovery used the portal's project_dir; reads about XPTO now use XPTO's returned dir. The working directory need not change. Never send a path such as ../xpto/src/... under the portal's project_dir.

Read the Knowledge skill for the selected target with graphit_module_skill (or reuse it if already resolved for this target and overrides):
~~~json
{"project_dir":"/work/xpto","module":"knowledge"}
~~~

Respect its enabled configuration and instructions, then graphit_knowledge_search:
~~~json
{"project_dir":"/work/xpto","query":"publication approval roles rejection","top_k":5,"ai_optimized":true}
~~~

Suppose the result returns slug Publication_Approval. Use graphit_wiki_source:
~~~json
{"project_dir":"/work/xpto","path":"Publication_Approval"}
~~~

Read the contract and answer with its rules, exceptions and provenance. A Hub copy may exist, but does not displace the selected checkout's identity. Do not turn the local project ID into an artifact context.

#### Verify implementation in the neighbor

If the question also asks how approval is enforced, read the target AST skill via graphit_module_skill with module ast and the same XPTO project_dir. Use graphit_ast_search instead of native grep:
~~~json
{"project_dir":"/work/xpto","query":"approve publication role","mode":"fts","top_k":5,"ai_optimized":true}
~~~

Suppose a selected hit returns src/approval.ts. Read it with graphit_ast_source:
~~~json
{"project_dir":"/work/xpto","path":"src/approval.ts","pattern":"approve","before":3,"after":8,"line_numbers":true}
~~~

The filename is illustrative; use the actual returned relative path, language and symbol. If callers/impact remain relevant, graphit_ast_schema and the AST skill's bounded queries also use XPTO's project_dir. Do not reuse portal's schema merely because both are local. A native file read justified for patching already-located code does not authorize a new broad discovery pass.

#### Recall the neighbor's rationale only when needed

If current code/docs do not explain why approval requires an editor, read the needed target Memory or Task skill. A Memory policy/lesson gap can use graphit_memory_search:
~~~json
{"project_dir":"/work/xpto","scope":"project","query":"approval editor policy rationale","exclude_mandatory":true,"top_k":5,"ai_optimized":true}
~~~

Apply the Memory skill's scope-change rule first: portal's mandatory project memories are not XPTO's; reuse user-scope context already loaded. Select a returned memory ID and read graphit_memory_source with XPTO's project_dir. If an ID is already known, skip search.

If instead the missing evidence is an earlier investigation/implementation decision, use graphit_task_search:
~~~json
{"project_dir":"/work/xpto","query":"approval editor decision","top_k":5,"ai_optimized":true}
~~~

Read selected returned task IDs with graphit_task_get and the same XPTO project_dir. Do not mechanically call both stores, claim/reopen historical tasks or create work in XPTO just to inspect it. Compare recorded scope/revision with current AST/Knowledge; distinguish historical intent from delivered behavior.

#### Return evidence to the owning task

For this example the active delivery belongs to portal. Its progress/check/complete calls keep portal's project_dir and claim; changing the source being read never transfers that claim to XPTO. Save logical identity XPTO, relative paths/slugs, applicable revision and findings in that task, never /work/xpto. Reading the neighbor does not itself authorize code changes, indexing or other mutations there. If authorized implementation is required, define the owning work and normal lifecycle before it.

When switching back to portal queries, restore portal's target and reuse its retained skills/evidence. The same rule applies to any enabled Graphit module that accepts project_dir. If a required module is disabled/unavailable, report that observed limitation and follow its recovery/fallback contract; being outside the current directory is not evidence of unavailability. An empty indexed search needs focused refinement, not an immediate filesystem walk.

### No local match: published-context branch

The cluster result contains no XPTO in this scope. This does not mean XPTO is absent everywhere. Call graphit_hub_projects:
~~~json
{"page_size":20,"ai_optimized":true}
~~~

Assume a published project called “Experience Portal” describes alias XPTO; its publisher ID is 01J00000000000000000000001. Follow relevant remaining pages if identity is still unresolved. Search its alias and needed type with graphit_hub_search:
~~~json
{"query":"XPTO approval","type":"knowledge","ai_optimized":true}
~~~

Assume a returned Knowledge artifact has globally unambiguous ID 01J00000000000000000000002. Use graphit_hub_show to establish the selected publisher, contents and available version:
~~~json
{"id":"01J00000000000000000000002","project_id":"01J00000000000000000000001","type":"knowledge","ai_optimized":true}
~~~

The requested contract is covered by version 2.3.0. Preserve that exact selection; if the user specified a version or compatibility range, respect it instead of automatically choosing latest.

Tell the user: “Encontrei a documentação de aprovações do XPTO, versão 2.3.0. Vou instalar esse contexto e consultar o contrato.” This is an announcement of the authorized preparation, not a redundant permission request.

With no local XPTO checkout, install the global artifact using graphit_hub_install:
~~~json
{"id":"01J00000000000000000000002@2.3.0","type":"knowledge","ai_optimized":true}
~~~

The install schema has no publisher project_id parameter. Retain the unambiguous returned artifact ID, not merely a display title. After confirmed success, load Knowledge's skill and call graphit_knowledge_search:
~~~json
{"context":"01J00000000000000000000002@2.3.0","query":"publication approval roles rejection","top_k":5,"ai_optimized":true}
~~~

Assume it returns Publication_Approval. Read with graphit_wiki_source:
~~~json
{"context":"01J00000000000000000000002@2.3.0","path":"Publication_Approval"}
~~~

Suppose that page states only editors can approve a pending publication and a rejection requires a reason. An answer can now cite those rules as the selected version's documented contract. Search titles and install success alone could not support that answer. Record the artifact/version/page and unresolved exceptions in Task; do not copy the entire catalog.

If asked whether code enforces it, discover the matching AST artifact/version, announce/install it, then graphit_ast_schema and selected queries/source with its own exact context. An AST artifact can have a different ID from Knowledge. Do not reuse the Knowledge ID as an AST context or assume the two versions correspond without metadata/evidence. graphit_ast_source reads its returned implementation path; no repository checkout is required and none is implied.

### Existing consumer project needs an artifact

If the request is to attach context to the known portal project, use its verified project_dir on graphit_hub_install:
~~~json
{"project_dir":"/work/portal","id":"01J00000000000000000000002@2.3.0","type":"knowledge","alias":"xpto-contracts","ai_optimized":true}
~~~

Use the confirmed installed alias/context under /work/portal for later queries. This is a project claim, unlike the global branch. Never guess an alias was accepted or replace a known project's path with a qualified ID. Reuse an already verified installation; discovery does not require reinstalling the same version.

## Case 2: “Find a skill for reviewing React components”

“Use React” alone requires no Hub discovery. This explicit artifact request does. graphit_hub_search:
~~~json
{"query":"React component review","type":"skill","ai_optimized":true}
~~~

Assume two relevant results: a component accessibility review skill and a legacy class-component migration skill. Inspect metadata with graphit_hub_show and explain their actual difference. If the request includes accessibility, the first is an obvious fit: announce/install the selected version. If the intended review could mean either, present just those useful options and ask the user to select. Do not ask for installation approval simply because installation is the next tool.

After a confirmed project-scoped install, read the selected entrypoint with graphit_hub_content:
~~~json
{"project_dir":"/work/portal","id":"01J00000000000000000000003","type":"skill","path":"SKILL.md"}
~~~

The ID here stands for that skill's returned ID and its project claim selects the version. Globally, omit project_dir and use its exact id@version. Read a further referenced file only when the skill's workflow needs it; omitting path returns all artifact files. Apply selected instructions within the user's request. Installing a command, agent or other runnable artifact does not itself authorize executing it.

Discover other artifact types through exposed schemas/metadata and the same select/version/install/use sequence. Do not assume that colloquial labels such as “run” or a project name are installable types. Some types have different consumption tools: AST/Knowledge are module contexts, not hub_content text.

## Misses, conflicts and failures

| Observation | Next bounded action | Accurate result |
| --- | --- | --- |
| XPTO search returns no candidates | Inspect visible project metadata for aliases such as Experience Portal; search that alias with the needed type or browse the relevant category. Follow pages only while the named resolution needs coverage. | “No match for those terms in the inspected scope,” not “XPTO does not exist.” |
| A valid inventory is exhausted without a match | Report the searched project/type/aliases and useful alternatives actually available; try another configured ecosystem source only if exposed. | No matching visible artifact in the covered inventory. |
| Service reports not configured, access denied or transport failure | Report that failure. Inspect relevant configuration via graphit_config_get when useful and authorized; do not invent an alternate service or reset credentials. | Discovery unavailable; catalog emptiness is unknown. |
| Two publishers share an artifact title | Preserve publisher/project/type and inspect each selected ID. Resolve a real choice before installation. | Names are discovery clues, not unique identities. |
| Requested version or required contract is absent | State the gap; compare actual available compatible options and their tradeoff. | Do not silently install a different contract/version. |
| Installation fails or response is ambiguous | Keep the attempted identity/version and error; establish whether installation succeeded before retry/use. | Do not claim context is available or manufacture a local path. |
| Selected page conflicts with local code | Keep each source's project/context/version; use Task/Knowledge/AST to resolve authority and applicability. | A published snapshot may differ from a local checkout; neither silently overrides the other. |

A useful Task handoff identifies the requested question; cluster scope and logical project identity with repository-relative references OR published artifact IDs/versions; why each artifact was selected; the pages/symbols actually read; supported conclusions; limitations; and the exact next unresolved action. The next host resolves its own project_dir; never save the selected checkout root in this handoff. Preserve reusable operating decisions in Memory and maintained contracts in Knowledge. Stop once the requested decision has adequate evidence.
