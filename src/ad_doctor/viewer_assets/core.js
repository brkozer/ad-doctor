// ad-doctor viewer core: the parts of the page that compute rather than draw. Inlined
// before app.js; the Node tests in tests/js run this same file against Python's output.
//
// - graph(), identity(), reachable(), blastRadius(): a port of paths.reachable,
//   paths._identity and paths.blast_radius over the compact graph viewer_graph.py embeds.
//   The search visits nodes in the same order as Python's, so it finds the same paths.
// - edgeKind(): the family of a control edge, for the path filters.
// - acceptDraft(): accept-draft.toml in the format accept.py reads.
// - parseReport(), diffReports(): an ad-hoc diff against a dropped JSON report, keyed like
//   `ad-doctor diff` (check, object identity).
//
// No DOM, no I/O: every function takes data and returns data.
const CORE = (function () {
  "use strict";

  const MACHINE = 1;
  const DC = 2;
  const SEVERITIES = ["high", "medium", "low", "info"];
  const WEIGHT = { high: 15, medium: 6, low: 2, info: 0 };
  const GRADES = [[10, "A"], [25, "B"], [45, "C"], [70, "D"], [100, "F"]];
  const PATH_STEP = / -\[([^\]]+)\]-> /;

  // ---- graph -------------------------------------------------------------------------

  // The embedded arrays as typed arrays plus lookups. Node i: names[i], kinds[kind[i]],
  // out-edges off[i]..off[i+1] into dst/how (how indexes labels).
  function graph(raw) {
    const n = raw.names.length;
    const off = new Int32Array(n + 1);
    for (let i = 0; i < n; i++) off[i + 1] = off[i] + raw.deg[i];
    const tier0 = new Uint8Array(n);
    for (const i of raw.tier0) tier0[i] = 1;
    const sid = new Map();
    for (const key of Object.keys(raw.sids)) sid.set(key, raw.sids[key]);
    const accounts = raw.accounts.map((row) => ({
      sam: String(row[0]), sid: String(row[1]), node: row[2], primary: row[3], flags: row[4],
    }));
    for (const a of accounts) if (a.node >= 0) sid.set(a.sid, a.node);
    return {
      n: n, names: raw.names, kind: raw.kind, kinds: raw.kinds, labels: raw.labels,
      off: off, dst: Int32Array.from(raw.dst), how: Int32Array.from(raw.how),
      tier0: tier0, sid: sid, accounts: accounts, domainSid: raw.domain_sid,
    };
  }

  function kindOf(G, i) {
    return G.kinds[G.kind[i]];
  }

  function findAccount(G, query) {
    const key = String(query).toLowerCase();
    return G.accounts.find((a) => a.sam.toLowerCase() === key || a.sid.toLowerCase() === key) || null;
  }

  // paths._identity: the account's SID, then the groups it is in without a member link.
  function identity(G, a) {
    const machine = (a.flags & MACHINE) !== 0;
    const primary = a.primary || (machine ? 515 : 513);
    const sids = [a.sid, "S-1-1-0", "S-1-5-11", G.domainSid + "-" + primary];
    if (!machine) sids.push("S-1-5-32-545");
    if (a.flags & DC) sids.push("S-1-5-9");
    return sids;
  }

  // Python starts its queue from sorted(set(starts)) of node IDs ("sid:S-1-..."); a SID
  // with no node has no edges and changes nothing.
  function startNodes(G, sids) {
    const ids = Array.from(new Set(sids.map((s) => "sid:" + s))).sort();
    const out = [];
    for (const id of ids) {
      const i = G.sid.get(id.slice(4));
      if (i !== undefined) out.push(i);
    }
    return out;
  }

  // paths.reachable: breadth first from the starts; prev/via give each node's parent and
  // the label of the edge it was reached by; order is the discovery order.
  function reachable(G, starts) {
    const prev = new Int32Array(G.n).fill(-1);
    const via = new Int32Array(G.n).fill(-1);
    const seen = new Uint8Array(G.n);
    const queue = new Int32Array(G.n);
    const order = [];
    let head = 0;
    let tail = 0;
    for (const s of starts) {
      if (!seen[s]) { seen[s] = 1; queue[tail++] = s; }
    }
    while (head < tail) {
      const node = queue[head++];
      for (let e = G.off[node]; e < G.off[node + 1]; e++) {
        const d = G.dst[e];
        if (!seen[d]) {
          seen[d] = 1;
          prev[d] = node;
          via[d] = G.how[e];
          queue[tail++] = d;
          order.push(d);
        }
      }
    }
    return { prev: prev, via: via, order: order };
  }

  // A path as {start, steps: [[node, how]]}; start -1 stands for an account with no node.
  function pathTo(G, R, end) {
    const steps = [];
    let node = end;
    while (R.prev[node] !== -1) {
      steps.push([node, G.labels[R.via[node]]]);
      node = R.prev[node];
    }
    steps.reverse();
    return { start: node, steps: steps };
  }

  // paths.blast_radius for an account: everything it controls and its tier-0 paths.
  function blastRadius(G, a) {
    const sids = identity(G, a);
    const R = reachable(G, startNodes(G, sids));
    R.order = R.order.filter((n) => kindOf(G, n) !== "scope"); // not controlled objects
    const tier0 = R.order.filter((n) => G.tier0[n]).map((n) => pathTo(G, R, n));
    tier0.sort((x, y) => x.steps.length - y.steps.length); // stable, like Python's sorted
    if (a.node >= 0 && G.tier0[a.node]) {
      tier0.unshift({ start: a.node, steps: [] });
    } else {
      for (const s of sids.slice(1)) {
        const i = G.sid.get(s);
        if (i !== undefined && G.tier0[i]) {
          tier0.unshift({ start: a.node, steps: [[i, "primary group"]] });
          break;
        }
      }
    }
    return { account: a, R: R, tier0: tier0 };
  }

  function nodeName(G, i, a) {
    return i < 0 ? a.sam : G.names[i];
  }

  // A path as viewer_graph.path_record builds it: names, kinds and tier-0 flags.
  function pathRecord(G, p, a) {
    return {
      start: nodeName(G, p.start, a),
      steps: p.steps.map(([n, how]) => [how, G.names[n], kindOf(G, n), G.tier0[n]]),
    };
  }

  function render(rec) {
    let out = rec.start;
    for (const [how, name] of rec.steps) out += " -[" + how + "]-> " + name;
    return out;
  }

  function byName(x, y) {
    if (x.t0 !== y.t0) return y.t0 - x.t0;
    return x.l < y.l ? -1 : x.l > y.l ? 1 : 0;
  }

  // The shape of viewer_graph.subject(), so precomputed and searched results draw alike.
  // perKind limits the objects kept per kind (Infinity keeps all).
  function subject(G, B, perKind) {
    const a = B.account;
    const groups = new Map();
    for (const n of B.R.order) {
      const k = kindOf(G, n);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push({ n: n, t0: G.tier0[n], l: G.names[n].toLowerCase() });
    }
    const counts = {};
    const objects = [];
    let truncated = false;
    for (const k of Array.from(groups.keys()).sort()) {
      const rows = groups.get(k).sort(byName);
      counts[k] = rows.length;
      truncated = truncated || rows.length > perKind;
      for (const r of rows.slice(0, perKind)) {
        const parent = B.R.prev[r.n];
        objects.push([G.names[r.n], k, r.t0, G.labels[B.R.via[r.n]], G.names[parent], r.n]);
      }
    }
    const kind = a.flags & 16 ? "gmsa" : a.flags & 8 ? "computer" : "user";
    return {
      name: a.sam, kind: kind, sid: a.sid, account: true,
      reaches: B.tier0.length > 0, count: B.R.order.length, kinds: counts,
      tier0: B.tier0.map((p) => pathRecord(G, p, a)), tier0_count: B.tier0.length,
      objects: objects, truncated: truncated,
    };
  }

  // ---- edges -------------------------------------------------------------------------

  const EDGE_KINDS = [
    ["membership", "Membership"], ["acl", "ACL rights"], ["owner", "Ownership"],
    ["contains", "Containment"], ["gpo", "Group Policy"], ["adcs", "AD CS"],
    ["dcsync", "DCSync"], ["gmsa", "gMSA password"], ["sync", "Entra sync"],
  ];

  // The family of a paths.build edge label.
  function edgeKind(how) {
    const h = String(how);
    if (/ via GPO /.test(h) || h.startsWith("linked to ") || h.startsWith("GPO ")) return "gpo";
    if (h.startsWith("member of")) return "membership";
    if (h === "owns") return "owner";
    if (h === "contains") return "contains";
    if (h === "DCSync") return "dcsync";
    if (h === "read gMSA password") return "gmsa";
    if (h === "hosts sync account") return "sync";
    if (/^(enroll|write template) \(ESC/.test(h) || / \(ESC7\)$/.test(h)) return "adcs";
    return "acl";
  }

  // ---- acceptance drafts ---------------------------------------------------------------

  // a TOML basic string: quotes, backslashes and control characters escaped; a lone
  // surrogate (not valid UTF-8) becomes U+FFFD
  function tomlString(value) {
    let out = '"';
    for (const ch of String(value)) {
      const c = ch.codePointAt(0);
      if (ch === '"') out += '\\"';
      else if (ch === "\\") out += "\\\\";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\t") out += "\\t";
      else if (ch === "\r") out += "\\r";
      else if (c < 0x20 || c === 0x7f) out += "\\u" + c.toString(16).padStart(4, "0");
      else if (c >= 0xd800 && c <= 0xdfff) out += "\ufffd";
      else out += ch;
    }
    return out + '"';
  }

  function commentText(value) {
    return String(value).replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, " ")
      .replace(/[\ud800-\udfff]/g, "\ufffd");
  }

  function validDate(text) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return false;
    const d = new Date(text + "T00:00:00Z");
    return !isNaN(d) && d.toISOString().slice(0, 10) === text;
  }

  // Problems that would make accept.py refuse the entry, or accept more than meant.
  function draftProblems(e) {
    const out = [];
    if (!/^[A-Z]{2,}-[A-Z0-9]+-\d{3}$/.test(e.check)) out.push("check ID");
    if (!String(e.reason || "").trim()) out.push("reason");
    if (!validDate(String(e.expires || ""))) out.push("expiry date");
    if (!e.all && !(e.objects || []).length) out.push("objects (or the whole check)");
    return out;
  }

  // entries: [{check, objects, all, reason, expires (YYYY-MM-DD), owner, ticket}]
  function acceptDraft(entries, info) {
    const lines = [
      "# Draft acceptances from ad-doctor view" + (info && info.domain ? " (" + commentText(info.domain) + ")" : "") +
        (info && info.date ? ", " + commentText(info.date) : "") + ".",
      "# Review each entry, then merge it into the accept file in your repository;",
      "# that file stays the source of truth. Objects are matched by name, case-insensitively.",
    ];
    for (const e of entries) {
      const bad = draftProblems(e);
      if (bad.length) throw new Error(e.check + ": " + bad.join(", "));
      lines.push("", "[[accept]]", "check = " + tomlString(e.check));
      if (!e.all) lines.push("objects = [" + e.objects.map(tomlString).join(", ") + "]");
      lines.push("reason = " + tomlString(e.reason.trim()), "expires = " + e.expires);
      if (String(e.owner || "").trim()) lines.push("owner = " + tomlString(e.owner.trim()));
      if (String(e.ticket || "").trim()) lines.push("ticket = " + tomlString(e.ticket.trim()));
    }
    return lines.join("\n") + "\n";
  }

  // ---- ad-hoc diff ---------------------------------------------------------------------

  function scoreOf(findings) {
    return Math.min(100, findings.reduce((s, f) => s + (WEIGHT[f.severity] || 0), 0));
  }

  function gradeOf(score) {
    return GRADES.find(([limit]) => score <= limit)[1];
  }

  // An ad-doctor JSON report (`-f json`) as plain, checked data; throws on anything else.
  function parseReport(text) {
    let data;
    try { data = JSON.parse(text); } catch (e) { throw new Error("not JSON"); }
    if (!data || typeof data !== "object" || data.tool !== "ad-doctor" || !Array.isArray(data.findings)) {
      throw new Error("not an ad-doctor JSON report (write one with -f json)");
    }
    const findings = [];
    let exposure = null;
    for (const f of data.findings) {
      if (!f || typeof f !== "object" || !Array.isArray(f.objects)) continue;
      const keys = f.keys && typeof f.keys === "object" && !Array.isArray(f.keys) ? f.keys : null;
      const objects = f.objects.map(String);
      findings.push({
        id: String(f.id), title: String(f.title || ""), objects: objects,
        severity: SEVERITIES.includes(f.severity) ? f.severity : "info",
        keys: objects.map((o) => keyOf(String(f.id), keys, o)),
      });
      if (f.id === "AD-PATH-001" && f.data && typeof f.data === "object") {
        if (Number.isInteger(f.data.exposed) && Number.isInteger(f.data.users)) {
          exposure = [f.data.exposed, f.data.users];
        }
      }
    }
    const score = Number.isInteger(data.score) ? data.score : scoreOf(findings);
    return {
      domain: String(data.domain || ""), collected_at: String(data.collected_at || ""),
      version: String(data.version || ""), score: score, grade: gradeOf(Math.min(Math.max(score, 0), 100)),
      findings: findings, paths: (findings.find((f) => f.id === "AD-PATH-001") || { objects: [] }).objects.length,
      exposed: exposure ? exposure[0] : null, users: exposure ? exposure[1] : null,
    };
  }

  // Finding.key: the report's keys map, else (an old report) a path's start principal
  function keyOf(id, keys, o) {
    if (keys && Object.keys(keys).length) {
      return Object.prototype.hasOwnProperty.call(keys, o) ? String(keys[o]) : o;
    }
    return id === "AD-PATH-001" ? o.split(PATH_STEP)[0] : o;
  }

  function index(findings) {
    const out = new Map();
    for (const f of findings) {
      f.objects.forEach((o, i) => {
        const key = f.keys ? f.keys[i] : o;
        out.set(f.id + "\u0000" + key, { f: f, o: o, sort: [f.id, key] });
      });
    }
    return out;
  }

  function bySortKey(a, b) {
    for (let i = 0; i < 2; i++) {
      if (a.sort[i] < b.sort[i]) return -1;
      if (a.sort[i] > b.sort[i]) return 1;
    }
    return 0;
  }

  // The old report against the current findings ({id, title, severity, objects, keys}),
  // like the --baseline comparison: new, resolved, and changed (same identity, other
  // object text or severity).
  function diffReports(old, current) {
    const before = index(old.findings);
    const after = index(current);
    const row = (x) => ({ id: x.f.id, title: x.f.title, severity: x.f.severity, object: x.o });
    const fresh = [];
    const changed = [];
    let unchanged = 0;
    for (const [k, x] of after) {
      const y = before.get(k);
      if (!y) fresh.push(x);
      else if (y.o !== x.o || y.f.severity !== x.f.severity) {
        changed.push(Object.assign(row(x), { before: y.o, before_severity: y.f.severity, sort: x.sort }));
      } else unchanged++;
    }
    const resolved = [];
    for (const [k, y] of before) if (!after.has(k)) resolved.push(y);
    fresh.sort(bySortKey);
    resolved.sort(bySortKey);
    changed.sort(bySortKey);
    return {
      new: fresh.map(row), resolved: resolved.map(row),
      changed: changed.map((c) => { delete c.sort; return c; }), unchanged: unchanged,
    };
  }

  return {
    graph, kindOf, findAccount, identity, startNodes, reachable, pathTo, blastRadius,
    pathRecord, render, subject, EDGE_KINDS, edgeKind, tomlString, validDate, draftProblems,
    acceptDraft, parseReport, diffReports, scoreOf, gradeOf, keyOf,
  };
})();
