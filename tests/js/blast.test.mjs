// The page's blast-radius search against Python's: for every account in each parity
// file (written by `python -m tests.viewer_fixtures parity tests/js/build`), the same
// objects in the same order, by the same paths, and the same tier-0 verdict.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadCore } from "./core.mjs";

const BUILD = resolve(dirname(fileURLToPath(import.meta.url)), "build");
const CORE = loadCore();
const files = existsSync(BUILD) ? readdirSync(BUILD).filter((f) => /^parity-.*\.json$/.test(f)) : [];

test("parity files exist", () => {
  assert.ok(files.length >= 3, "run: uv run python -m tests.viewer_fixtures parity tests/js/build");
});

for (const file of files) {
  const data = JSON.parse(readFileSync(resolve(BUILD, file), "utf-8"));
  test(`${file}: ${data.cases.length} accounts match paths.blast_radius`, () => {
    const G = CORE.graph(data.graph);
    for (const c of data.cases) {
      const a = CORE.findAccount(G, c.account);
      assert.ok(a, c.account);
      const B = CORE.blastRadius(G, a);
      const rows = B.R.order.map((n) =>
        n + "\t" + CORE.render(CORE.pathRecord(G, CORE.pathTo(G, B.R, n), a)));
      assert.equal(rows.length, c.count, c.account);
      assert.deepEqual(rows.slice(0, c.first.length), c.first, c.account);
      assert.equal(createHash("sha256").update(rows.join("\n")).digest("hex"), c.digest, c.account);
      assert.deepEqual(B.tier0.map((p) => CORE.render(CORE.pathRecord(G, p, a))), c.tier0, c.account);
      // the record the screen draws holds the same objects
      const rec = CORE.subject(G, B, Infinity);
      assert.equal(rec.count, c.count);
      assert.equal(rec.objects.length, c.count);
      assert.equal(rec.reaches, c.tier0.length > 0);
    }
  });

  test(`${file}: every edge label has a family`, () => {
    const known = new Set(CORE.EDGE_KINDS.map(([k]) => k));
    for (const label of data.graph.labels) assert.ok(known.has(CORE.edgeKind(label)), label);
  });
}
