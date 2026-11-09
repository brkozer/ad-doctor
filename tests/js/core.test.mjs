// The other pure functions of the viewer's core.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadCore } from "./core.mjs";

const CORE = loadCore();

test("edge families", () => {
  const cases = {
    "member of": "membership",
    "member of via GPO Tier1 Admins": "gpo",
    "admin to via GPO Workstations": "gpo",
    "linked to domain": "gpo",
    "owns": "owner",
    "contains": "contains",
    "DCSync": "dcsync",
    "read gMSA password": "gmsa",
    "constrained delegation (protocol transition)": "delegation",
    "resource-based delegation": "delegation",
    "resource-based delegation (assumes Domain Admins is in the local Administrators)": "delegation",
    "write RBCD": "acl",
    "SID history": "sidhistory",
    "hosts sync account": "sync",
    "enroll (ESC1-3)": "adcs",
    "enroll (ESC13)": "adcs",
    "enroll (ESC6+ESC16)": "adcs",
    "write template (ESC4)": "adcs",
    "ManageCA (ESC7)": "adcs",
    "full control": "acl",
    "write members, reset password (inherited)": "acl",
    "write altSecurityIdentities (ESC14)": "acl",
    "GPO applies to": "gpo",
    "GPO inherited by": "gpo",
    "GPO reaches": "gpo",
  };
  for (const [how, kind] of Object.entries(cases)) assert.equal(CORE.edgeKind(how), kind, how);
});

test("TOML strings escape what TOML requires", () => {
  assert.equal(CORE.tomlString('a"b\\c'), '"a\\"b\\\\c"');
  assert.equal(CORE.tomlString("x\ny\tz\u0001\u007f"), '"x\\ny\\tz\\u0001\\u007f"');
  assert.equal(CORE.tomlString("\u2028 ok"), '"\u2028 ok"');
  assert.equal(CORE.tomlString("lone \ud800"), '"lone \ufffd"');
});

test("draft entries are checked before they are written", () => {
  const good = { check: "AD-KRB-003", objects: ["svc"], reason: "r", expires: "2027-01-31" };
  assert.deepEqual(CORE.draftProblems(good), []);
  assert.deepEqual(CORE.draftProblems({ ...good, expires: "2027-02-30", reason: " " }),
    ["reason", "expiry date"]);
  assert.deepEqual(CORE.draftProblems({ ...good, objects: [] }), ["objects (or the whole check)"]);
  assert.throws(() => CORE.acceptDraft([{ ...good, check: "x]\n[[accept" }], {}), /check ID/);
  const text = CORE.acceptDraft([{ ...good, all: true, owner: "o" }], { domain: "a\nb", date: "2026-11-05" });
  assert.match(text, /^# Draft acceptances from ad-doctor view \(a b\), 2026-11-05\.\n/);
  assert.match(text, /\[\[accept\]\]\ncheck = "AD-KRB-003"\nreason = "r"\nexpires = 2027-01-31\nowner = "o"\n$/);
});

test("ad-hoc diff keys paths by their start, like ad-doctor diff", () => {
  const old = CORE.parseReport(JSON.stringify({
    tool: "ad-doctor", domain: "d", collected_at: "2026-10-01T00:00:00+00:00", score: 21,
    findings: [
      { id: "AD-PATH-001", title: "p", severity: "high", objects: ["svc -[owns]-> X"] },
      { id: "AD-ACC-001", title: "a", severity: "low", objects: ["bob"] },
      { id: "AD-KRB-002", title: "k", severity: "medium", objects: ["eve"] },
    ],
  }));
  assert.equal(old.grade, "B");
  const current = [
    { id: "AD-PATH-001", title: "p", severity: "high", objects: ["svc -[member of]-> G -[owns]-> X"], keys: ["svc"] },
    { id: "AD-KRB-002", title: "k", severity: "high", objects: ["eve"] },
    { id: "AD-SEC-001", title: "s", severity: "low", objects: ["dc1"] },
  ];
  const held = CORE.diffReports(old, current, new Set(["AD-ACC-001"]));
  assert.deepEqual(held.resolved, []);
  assert.deepEqual(held.not_evaluated.map((r) => r.id + ":" + r.object), ["AD-ACC-001:bob"]);
  const d = CORE.diffReports(old, current);
  assert.deepEqual(d.new.map((r) => r.id + ":" + r.object), ["AD-SEC-001:dc1"]);
  assert.deepEqual(d.resolved.map((r) => r.id + ":" + r.object), ["AD-ACC-001:bob"]);
  assert.deepEqual(d.changed.map((r) => [r.id, r.before, r.before_severity]),
    [["AD-KRB-002", "eve", "medium"], ["AD-PATH-001", "svc -[owns]-> X", "high"]]);
  assert.equal(d.unchanged, 0);
  assert.throws(() => CORE.parseReport("{\"tool\": \"other\"}"), /not an ad-doctor JSON report/);
  assert.throws(() => CORE.parseReport("<html>"), /not JSON/);
});
