// The page's what-if against Python's: for every set of removals in each parity file
// (written by `python -m tests.viewer_fixtures parity tests/js/build`), the same masked
// graph, tier 0, paths, holders, exposure and classification, and the same refusal when
// the mask does not model a change.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadCore } from "./core.mjs";

const BUILD = resolve(dirname(fileURLToPath(import.meta.url)), "build");
const CORE = loadCore();
const files = existsSync(BUILD) ? readdirSync(BUILD).filter((f) => /^whatif-.*\.json$/.test(f)) : [];

const digest = (rows) => createHash("sha256").update(rows.join("\n")).digest("hex");

test("what-if parity files exist", () => {
  assert.ok(files.length >= 10, "run: uv run python -m tests.viewer_fixtures parity tests/js/build");
});

function blastDigest(M, G, c) {
  const a = CORE.findAccount(M, c.account);
  const B = CORE.blastRadius(M, a);
  const rows = B.R.order.map((n) =>
    n + "\t" + CORE.render(CORE.pathRecord(M, CORE.pathTo(M, B.R, n), a)));
  assert.equal(rows.length, c.count, c.account);
  assert.equal(digest(rows), c.digest, c.account);
  assert.deepEqual(B.tier0.map((p) => CORE.render(CORE.pathRecord(M, p, a))), c.tier0, c.account);
}

for (const file of files) {
  const data = JSON.parse(readFileSync(resolve(BUILD, file), "utf-8"));
  test(`${file}: ${data.cases.length} sets match whatif.masked`, () => {
    const G = CORE.graph(data.graph);
    const W = CORE.whatifModel(G, data.whatif);
    const base = CORE.whatifEvaluate(G, W, []);
    assert.equal(base.after.exposed, data.before.exposed, "exposed before");
    assert.equal(base.after.users, data.before.users, "users before");
    assert.equal(base.after.holders, data.before.holders, "holders before");
    assert.equal(base.after.reaching, data.before.found, "found before");
    assert.equal(base.after.routes, data.before.routes, "routes before");
    assert.deepEqual(base.closed, []);
    assert.deepEqual(base.rerouted, []);
    assert.deepEqual(base.new, []);
    let rebuilt = 0;
    for (const c of data.cases) {
      const r = CORE.whatifEvaluate(G, W, c.removed);
      const where = file + " " + JSON.stringify(c.removed);
      assert.equal(r.findings_rechecked, false, where);
      assert.equal(typeof r.note, "string", where);
      if (c.rebuild) {
        rebuilt++;
        assert.ok(r.rebuild.length > 0, where);
        assert.equal(r.after, undefined, where);
        continue;
      }
      assert.deepEqual(r.rebuild, [], where);
      const M = r.graph;
      const edges = [];
      for (let i = 0; i < M.n; i++) {
        for (let e = M.off[i]; e < M.off[i + 1]; e++) edges.push(i + " " + M.dst[e] + " " + M.labels[M.how[e]]);
      }
      assert.equal(edges.length, c.edge_count, "edges " + where);
      assert.equal(digest(edges), c.edges, "edges " + where);
      const alive = M.order.filter((s) => M.off[s + 1] > M.off[s]);
      assert.deepEqual(alive, c.order, "source order " + where);
      assert.deepEqual(r.tier0, c.tier0, "tier0 " + where);
      const S = r.state;
      const found = Array.from(S.order).map((n) => n + "\t" + CORE.whatifFoundText(M, S, n));
      assert.equal(found.length, c.found_count, "found " + where);
      assert.deepEqual(found.slice(0, 10), c.found_first, "found " + where);
      assert.equal(digest(found), c.found, "found " + where);
      const holders = Array.from(S.holders).map(([n, h]) => n + "\t" + CORE.whatifHolderText(M, S, n, h));
      assert.equal(holders.length, c.holder_count, "holders " + where);
      assert.deepEqual(holders.slice(0, 10), c.holders_first, "holders " + where);
      assert.equal(digest(holders), c.holders, "holders " + where);
      assert.equal(r.after.routes, c.routes, "routes " + where);
      assert.equal(r.after.exposed, c.exposed, "exposed " + where);
      assert.equal(r.after.users, c.users, "users " + where);
      assert.equal(r.closed.length, c.closed_count, "closed " + where);
      assert.equal(digest(r.closed.map((x) => String(x.node))), c.closed, "closed " + where);
      assert.equal(r.rerouted.length, c.rerouted_count, "rerouted " + where);
      assert.equal(digest(r.rerouted.map((x) => x.node + "\t" + x.before + "\t" + x.after)), c.rerouted, "rerouted " + where);
      assert.equal(r.open.length, c.open_count, "open " + where);
      assert.equal(digest(r.open.map((x) => x.node + "\t" + x.path)), c.open, "open " + where);
      assert.equal(r.new.length, c.new_count, "new " + where);
      assert.equal(digest(r.new.map((x) => x.node + "\t" + x.path)), c.new, "new " + where);
      for (const b of c.blast) blastDigest(M, G, b);
    }
    assert.ok(rebuilt <= data.cases.length);
  });
}

test("a change the mask does not model gets no number, findings are not rechecked", () => {
  const data = files.map((f) => JSON.parse(readFileSync(resolve(BUILD, f), "utf-8")))
    .find((d) => d.cases.some((c) => c.rebuild));
  assert.ok(data, "some fixture needs a rebuild");
  const G = CORE.graph(data.graph);
  const W = CORE.whatifModel(G, data.whatif);
  const c = data.cases.find((x) => x.rebuild);
  const r = CORE.whatifEvaluate(G, W, c.removed);
  assert.ok(r.note.includes("ad-doctor whatif"));
  assert.ok(!("after" in r) && !("tier0" in r));
  const fine = CORE.whatifEvaluate(G, W, []);
  assert.match(fine.note, /not rechecked in the browser/);
});
