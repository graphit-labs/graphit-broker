const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const html = fs.readFileSync(path.join(__dirname, "../crates/broker-presence/assets/admin/index.html"), "utf8");
const start = html.indexOf('      const instructionsPath = ');
const end = html.indexOf('      async function loadConfig()', start);
assert.ok(start >= 0 && end > start, "test the actual instruction controller");
const controller = html.slice(start, end);

class Element {
  constructor(tag = "div") {
    this.tag = tag;
    this.children = [];
    this.value = "";
    this.disabled = false;
    this.classes = new Set();
    this.classList = { toggle: (name, on) => on ? this.classes.add(name) : this.classes.delete(name) };
    this.attributes = {};
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  querySelectorAll(tag) {
    return this.children.flatMap((child) => [ ...(child.tag === tag ? [child] : []), ...child.querySelectorAll(tag) ]);
  }
  reportValidity() { return true; }
  focus() { this.focused = true; }
}
function fixture(api) {
  const elements = new Map();
  const $ = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  for (const id of ["save-instruction", "activate-instruction", "deactivate-instruction", "delete-instruction"]) {
    $(id).tag = "button";
    $("instruction-editor").append($(id));
  }
  const context = vm.createContext({ $, api, sessionGeneration: 1,
    document: { createElement: (tag) => new Element(tag) } });
  vm.runInContext(controller + `\nthis.subject = {
    loadInstructions, saveInstruction, resetInstructions,
    authorize() { instructionAdmin = true; },
    state() { return { document: instructionDocument, selection: instructionSelection,
      saving: instructionSaving, loading: instructionLoading }; }
  };`, context);
  context.subject.authorize();
  return { $ , context, subject: context.subject };
}
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const response = (revision = 0, templates = {}) => [200, { revision, templates }];

test("draft, activate, edit, deactivate and delete preserve the server revision", async () => {
  let document = response()[1];
  const calls = [];
  const f = fixture(async (url, request) => {
    calls.push({ url, request });
    if (request) {
      const input = JSON.parse(request.body);
      assert.equal(input.revision, document.revision);
      document = { ...input, revision: input.revision + 1 };
    }
    return [200, structuredClone(document)];
  });
  await f.subject.loadInstructions();
  f.$("new-instruction").onclick();
  f.$("instruction-name").value = "skills/ast/entry.md";
  f.$("instruction-markdown").value = "Olá {{ brand }}";
  await f.subject.saveInstruction("draft");
  assert.equal(document.templates["skills/ast/entry.md"].enabled, false);
  await f.subject.saveInstruction("activate");
  assert.equal(document.templates["skills/ast/entry.md"].enabled, true);
  f.$("instruction-markdown").value = "Changed template";
  await f.subject.saveInstruction("activate");
  assert.equal(document.templates["skills/ast/entry.md"].markdown, "Changed template");
  await f.subject.saveInstruction("deactivate");
  assert.equal(document.templates["skills/ast/entry.md"].enabled, false);
  await f.subject.saveInstruction("delete");
  assert.deepEqual(document.templates, {});
  assert.equal(document.revision, 5);
  assert.equal(calls.length, 6);
  assert.ok(calls.every((call) => call.url === "/admin/api/v1/agent-instructions"));
});

test("a pending save retains the editor and prevents selection, new and refresh races", async () => {
  const pending = deferred();
  let calls = 0;
  const templates = { "a.md": { enabled: false, markdown: "saved" }, "b.md": { enabled: false, markdown: "other" } };
  const f = fixture(async (_, request) => { calls++; return request ? pending.promise : response(2, templates); });
  await f.subject.loadInstructions();
  f.$("instruction-list").children[0].onclick();
  f.$("instruction-markdown").value = "unsaved";
  const saving = f.subject.saveInstruction("activate");
  assert.equal(f.$("instruction-markdown").readOnly, true);
  assert.equal(f.$("reload-instructions").disabled, true);
  assert.equal(f.$("new-instruction").disabled, true);
  f.$("instruction-list").children[1].onclick();
  f.$("new-instruction").onclick();
  await f.subject.loadInstructions();
  assert.equal(calls, 2);
  assert.equal(f.subject.state().selection, "a.md");
  assert.equal(f.$("instruction-markdown").value, "unsaved");
  pending.resolve(response(3, { ...templates, "a.md": { enabled: true, markdown: "unsaved" } }));
  await saving;
  assert.equal(f.$("reload-instructions").disabled, false);
  assert.equal(f.$("instruction-status").textContent, "Active");
});

test("an old session save cannot replace or unlock a new session request", async () => {
  const old = deferred(), current = deferred();
  let calls = 0;
  const f = fixture(async (_, request) => request ? old.promise : (++calls === 1 ? response() : current.promise));
  await f.subject.loadInstructions();
  f.$("new-instruction").onclick();
  f.$("instruction-name").value = "old.md";
  const saving = f.subject.saveInstruction("activate");
  f.context.sessionGeneration++;
  f.subject.resetInstructions();
  f.subject.authorize();
  const loading = f.subject.loadInstructions();
  old.resolve(response(1, { "old.md": { enabled: true, markdown: "old" } }));
  await saving;
  assert.equal(f.subject.state().document, null);
  assert.equal(f.subject.state().loading, true);
  assert.equal(f.$("reload-instructions").disabled, true);
  current.resolve(response(7));
  await loading;
  assert.equal(f.subject.state().document.revision, 7);
  assert.equal(f.$("instruction-name").value, "");
});

test("a stale load cannot overwrite a new session and conflict keeps unsaved edits", async () => {
  const old = deferred();
  let calls = 0;
  const f = fixture(async (_, request) => {
    if (request) throw Object.assign(new Error("conflict"), { status: 409 });
    return ++calls === 1 ? old.promise : response(9, { "a.md": { enabled: true, markdown: "published" } });
  });
  const loading = f.subject.loadInstructions();
  f.context.sessionGeneration++;
  f.subject.resetInstructions();
  f.subject.authorize();
  await f.subject.loadInstructions();
  old.resolve(response(1));
  await loading;
  assert.equal(f.subject.state().document.revision, 9);
  f.$("instruction-list").children[0].onclick();
  f.$("instruction-markdown").value = "do not lose me";
  await f.subject.saveInstruction("activate");
  assert.equal(f.$("instruction-markdown").value, "do not lose me");
  assert.equal(f.subject.state().document.revision, 9);
  assert.match(f.$("instruction-feedback").textContent, /Copy any unsaved edits/);
});

test("read-only sessions cannot mutate and a failed load does not invent an empty collection", async () => {
  let calls = 0;
  const f = fixture(async () => {
    calls++;
    throw Object.assign(new Error("forbidden"), { status: 403 });
  });
  await f.subject.loadInstructions();
  assert.equal(f.subject.state().document, null);
  assert.equal(f.$("new-instruction").disabled, true);
  assert.equal(f.$("instruction-feedback").textContent, "forbidden");
  await f.subject.saveInstruction("activate");
  assert.equal(calls, 1);
  f.subject.resetInstructions();
  f.context.api = async () => { calls++; return response(4, { "a.md": { enabled: true, markdown: "Read only" } }); };
  await f.subject.loadInstructions();
  f.$("instruction-list").children[0].onclick();
  assert.equal(f.$("instruction-markdown").readOnly, true);
  assert.equal(f.$("instruction-actions").classes.has("hidden"), true);
  await f.subject.saveInstruction("delete");
  assert.equal(calls, 2);
  assert.equal(f.subject.state().document.revision, 4);
});
