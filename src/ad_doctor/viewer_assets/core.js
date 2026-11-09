// ad-doctor viewer core: the parts of the page that compute rather than draw. Inlined
// before app.js; the Node tests in tests/js run this same file against Python's output.
//
// - graph(), identity(), reachable(), blastRadius(): a port of paths.reachable,
//   paths._identity and paths.blast_radius over the compact graph viewer_graph.py embeds.
//   The search visits nodes in the same order as Python's, so it finds the same paths.
// - edgeKind(): the family of a control edge, for the path filters.
// - whatifModel(), whatifMask(), whatifEvaluate(): a port of whatif.masked and the path half
//   of whatif.run over the model viewer_graph.whatif_model embeds. Findings are not rechecked.
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
    ["delegation", "Delegation"], ["sidhistory", "SID history"],
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
    if (h.startsWith("constrained delegation") || h.startsWith("resource-based delegation")) return "delegation";
    if (h === "SID history") return "sidhistory";
    if (/^(enroll|write template) \(ESC/.test(h) || / \(ESC7\)$/.test(h)) return "adcs";
    return "acl";
  }

  // ---- what-if -------------------------------------------------------------------------

  // A port of whatif.masked and of the numbers of AD-PATH-001, over the model
  // viewer_graph.whatif_model embeds. Every order in it (sources, edges, the reverse
  // search) is Python's, so paths come out the same, ties included. Never a finding:
  // whatifEvaluate says so, and sends what the mask does not model to the command line.
  const WHATIF_FINDINGS_NOTE = "Findings are not rechecked in the browser: these numbers " +
    "are control paths only. Run ad-doctor whatif on the snapshot for the findings that would clear.";
  const WHATIF_REBUILD_NOTE = "Some of these changes can move GPO scope, take a holder out " +
    "of tier 0 or decide whether a delegation edge exists, which needs a rebuild of the " +
    "graph. The page shows no number for them: run ad-doctor whatif on the snapshot.";
  const FACT_GATES = new Set(["same-source", "same-target"]);

  function undelta(values) {
    const out = new Int32Array(values.length);
    let at = 0;
    for (let i = 0; i < values.length; i++) { at += values[i]; out[i] = at; }
    return out;
  }

  // The embedded model, decoded once for a graph(raw).
  function whatifModel(G, raw) {
    const edges = G.dst.length;
    const prim = new Int32Array(edges);
    let fresh = 0;
    raw.prim.forEach((v, e) => { prim[e] = v < 0 ? v : v === 0 ? fresh++ : v - 1; });
    const special = new Uint8Array(edges);
    const options = new Map();
    for (const [e, items] of raw.options) { options.set(e, items); special[e] = 1; }
    const gated = new Map();
    for (const [e, p, gate] of raw.gated) { gated.set(e, [p, gate]); special[e] = 1; }
    const seq = new Int32Array(edges).fill(-1);
    const sources = [];
    for (let i = 0, node = 0; i < raw.seq.length;) {
      node += raw.seq[i++];
      const count = raw.seq[i++];
      let at = 0;
      for (let j = 0; j < count; j++) { at += raw.seq[i++]; seq[G.off[node] + j] = at; }
      sources.push(node);
    }
    sources.sort((a, b) => seq[G.off[a]] - seq[G.off[b]]);
    const notSid = new Uint8Array(G.n);
    for (const i of undelta(raw.not_sid)) notSid[i] = 1;
    const rebuild = new Uint8Array(raw.prim_kind.length);
    for (const p of undelta(raw.rebuild)) rebuild[p] = 1;
    const templates = new Map();
    for (const name of Object.keys(raw.templates)) {
      const t = raw.templates[name];
      templates.set(name, { published: t[0], ess: t[1], approval: t[2], sigs: t[3], ekus: t[4] });
    }
    const pairs = new Map();
    for (const [p, group, member] of raw.tier0.pairs) pairs.set(p, [group, member]);
    return {
      prim: prim, primKind: raw.prim_kind, kinds: raw.kinds, count: raw.prim_kind.length,
      special: special, options: options, gated: gated, gates: raw.gates, templates: templates,
      eku: raw.eku, seq: seq, sources: sources, notSid: notSid, rebuild: rebuild,
      tier0: raw.tier0, tier0Kinds: new Set(raw.tier0.kinds), pairs: pairs,
      memberOf: G.labels.indexOf("member of"), plan: raw.plan, before: null,
    };
  }

  function flagActive(W, f, flag) {
    if (flag === "require-approval") return !f.approval;
    if (flag === "enrollee-supplies-subject") return f.ess;
    const eku = flag === "any-purpose-eku" ? W.eku.any : W.eku.agent;
    return f.ekus.includes(eku) && f.ekus.length > 1;
  }

  // provenance.without_flags: an EKU goes only while another one stays
  function withoutFlags(W, f, flags) {
    let out = f;
    for (const flag of flags) {
      if (!flagActive(W, out, flag)) continue;
      if (flag === "require-approval") out = Object.assign({}, out, { approval: true });
      else if (flag === "enrollee-supplies-subject") out = Object.assign({}, out, { ess: false });
      else {
        const eku = flag === "any-purpose-eku" ? W.eku.any : W.eku.agent;
        out = Object.assign({}, out, { ekus: out.ekus.filter((e) => e !== eku) });
      }
    }
    return out;
  }

  function authenticates(W, f) {
    return !f.ekus.length || f.ekus.includes(W.eku.any) || f.ekus.some((e) => W.eku.client.includes(e));
  }

  function issuable(f) {
    return f.published && !f.approval && f.sigs === 0;
  }

  function escOpen(W, f) {
    const anyUse = !f.ekus.length || f.ekus.includes(W.eku.any) || f.ekus.includes(W.eku.agent);
    return issuable(f) && ((f.ess && authenticates(W, f)) || anyUse);
  }

  function authOpen(W, f) {
    return issuable(f) && authenticates(W, f);
  }

  function officerOpen(W, f) {
    return f.published && f.ess && authenticates(W, f);
  }

  // Provenance.gate_open for a gate one of whose facts is among the removals
  function gateOpen(W, gate, gone) {
    const [kind, template, flags] = gate;
    const taken = flags.filter((x) => gone[x[0]]);
    if (FACT_GATES.has(kind)) return taken.length === 0;
    if (kind === "esc13" || kind === "esc6") {
      if (taken.some((x) => x[1] === null)) return false; // the policy link or a CA flag
      return authOpen(W, withoutFlags(W, W.templates.get(template), taken.map((x) => x[2])));
    }
    const by = new Map();
    for (const x of taken) {
      if (!by.has(x[1])) by.set(x[1], []);
      by.get(x[1]).push(x[2]);
    }
    if (kind === "esc") return escOpen(W, withoutFlags(W, W.templates.get(template), by.get(template) || []));
    for (const [name, facts] of W.templates) {
      if (officerOpen(W, withoutFlags(W, facts, by.get(name) || []))) return true;
    }
    return false;
  }

  // whatif._alive: the edge's label after the removals, or -1 when it is gone
  function edgeLabel(W, e, how, gone, closed) {
    if (W.special[e]) {
      const opts = W.options.get(e);
      if (opts) {
        for (const [p, label] of opts) if (p < 0 || !gone[p]) return label;
        return -1;
      }
      const [p, gate] = W.gated.get(e);
      return gone[p] || closed[gate] ? -1 : how;
    }
    const p = W.prim[e];
    return p < 0 || !gone[p] ? how : -1;
  }

  // changes.privileged_without for one list: the members its removals drop
  function droppedMembers(W, root, skips) {
    const nGroups = W.tier0.groups.length;
    const closure = (skip) => {
      const out = new Set();
      const seen = new Uint8Array(nGroups);
      seen[root] = 1;
      const stack = [root];
      while (stack.length) {
        const group = stack.pop();
        for (const m of W.tier0.groups[group]) {
          if (skip && skips.has(group + "\u0000" + m)) continue;
          if (m < nGroups) {
            if (!seen[m]) { seen[m] = 1; stack.push(m); }
          } else out.add(m);
        }
      }
      return out;
    };
    const kept = closure(true);
    return new Set(Array.from(closure(false)).filter((m) => !kept.has(m)));
  }

  // whatif._tier0, for changes that can take something out of tier 0
  function tier0After(G, W, removed, gone, closed) {
    if (!removed.some((p) => W.tier0Kinds.has(W.kinds[W.primKind[p]]))) return G.tier0;
    const T = W.tier0;
    const tier0 = new Uint8Array(G.n);
    for (const i of T.fixed) tier0[i] = 1;
    for (const [e, node] of T.ca) {
      if (edgeLabel(W, e, 0, gone, closed) >= 0) tier0[node] = 1;
    }
    const skips = new Set();
    for (const p of removed) {
      const pair = W.pairs.get(p);
      if (pair) skips.add(pair[0] + "\u0000" + pair[1]);
    }
    for (const [root, rows] of T.lists) {
      const dropped = root >= 0 && skips.size ? droppedMembers(W, root, skips) : new Set();
      for (const [node, id, hidden] of rows) {
        if (hidden || !dropped.has(id)) tier0[node] = 1;
      }
    }
    return tier0;
  }

  // whatif._reorder: the sources in the order a rebuilt graph would first add an edge of
  // theirs; a source whose first edges went falls behind the ones met before its next.
  function sourceOrder(G, W, late) {
    late.sort((a, b) => a[0] - b[0]);
    if (!late.length) return W.sources;
    const moved = new Set(late.map((x) => x[1]));
    const out = [];
    let j = 0;
    for (const src of W.sources) {
      if (moved.has(src)) continue;
      const first = W.seq[G.off[src]];
      while (j < late.length && late[j][0] < first) out.push(late[j++][1]);
      out.push(src);
    }
    while (j < late.length) out.push(late[j++][1]);
    return out;
  }

  // whatif.masked: the graph without the removed primitives, with the shape graph()
  // returns, so reachable() and blastRadius() work on it unchanged. `removed` is an array
  // of primitive numbers.
  function whatifMask(G, W, removed) {
    if (!removed.length) return Object.assign({}, G, { order: W.sources });
    const gone = new Uint8Array(W.count);
    for (const p of removed) gone[p] = 1;
    const closed = new Uint8Array(W.gates.length);
    W.gates.forEach((gate, i) => {
      if (gate[2].some((x) => gone[x[0]]) && !gateOpen(W, gate, gone)) closed[i] = 1;
    });
    const off = new Int32Array(G.n + 1);
    const dst = new Int32Array(G.dst.length);
    const how = new Int32Array(G.dst.length);
    const late = [];
    let out = 0;
    for (let node = 0; node < G.n; node++) {
      off[node] = out;
      let first = -1;
      for (let e = G.off[node]; e < G.off[node + 1]; e++) {
        const label = edgeLabel(W, e, G.how[e], gone, closed);
        if (label >= 0) {
          if (first < 0) first = e;
          dst[out] = G.dst[e];
          how[out++] = label;
        }
      }
      if (first > G.off[node] && W.seq[G.off[node]] >= 0) late.push([W.seq[first], node]);
    }
    off[G.n] = out;
    const tier0 = tier0After(G, W, removed, gone, closed);
    return Object.assign({}, G, {
      off: off, dst: dst.subarray(0, out), how: how.subarray(0, out), tier0: tier0,
      order: sourceOrder(G, W, late),
    });
  }

  // paths.paths_to_tier0 + direct_holders + exposure on a masked graph: which nodes reach
  // tier 0 (depth > 0: found, 0: tier 0, -1: neither), the next edge of each path, the
  // discovery order, and the holders in the order direct_holders finds them.
  function whatifState(G, W, M) {
    const n = M.n;
    const counts = new Int32Array(n + 1);
    for (const src of M.order) {
      for (let e = M.off[src]; e < M.off[src + 1]; e++) counts[M.dst[e] + 1]++;
    }
    for (let i = 0; i < n; i++) counts[i + 1] += counts[i];
    const fill = counts.slice(0, n);
    const revSrc = new Int32Array(counts[n]);
    const revHow = new Int32Array(counts[n]);
    for (const src of M.order) {
      for (let e = M.off[src]; e < M.off[src + 1]; e++) {
        const at = fill[M.dst[e]]++;
        revSrc[at] = src;
        revHow[at] = M.how[e];
      }
    }
    const depth = new Int32Array(n).fill(-1);
    const nxt = new Int32Array(n).fill(-1);
    const nxtHow = new Int32Array(n).fill(-1);
    const queue = new Int32Array(n);
    let head = 0;
    let tail = 0;
    for (let i = 0; i < n; i++) if (M.tier0[i]) { depth[i] = 0; queue[tail++] = i; }
    const firstFound = tail;
    while (head < tail) {
      const node = queue[head++];
      for (let r = counts[node]; r < counts[node + 1]; r++) {
        const src = revSrc[r];
        if (depth[src] >= 0) continue;
        depth[src] = depth[node] + 1;
        nxt[src] = node;
        nxtHow[src] = revHow[r];
        queue[tail++] = src;
      }
    }
    const order = queue.subarray(firstFound, tail);
    const holders = new Map();
    for (const node of order) {
      if (W.notSid[node]) continue;
      let best = 0;
      let bestDst = -1;
      let bestHow = -1;
      for (let e = M.off[node]; e < M.off[node + 1]; e++) {
        if (M.how[e] === W.memberOf) continue;
        const d = M.dst[e];
        const len = M.tier0[d] ? 1 : depth[d] > 0 ? 1 + depth[d] : 0;
        if (len && (!best || len < best)) { best = len; bestDst = d; bestHow = M.how[e]; }
      }
      if (best) holders.set(node, [bestDst, bestHow]);
    }
    const seenBy = (node) => M.tier0[node] || depth[node] > 0;
    let exposed = 0;
    let users = 0;
    for (const a of M.accounts) {
      if (!(a.flags & 4) || a.flags & (8 | 16) || (a.node >= 0 && M.tier0[a.node])) continue;
      users++;
      const reaches = (a.node >= 0 && depth[a.node] > 0) ||
        identity(M, a).slice(1).some((s) => { const i = M.sid.get(s); return i !== undefined && seenBy(i); });
      if (reaches) exposed++;
    }
    return { graph: M, depth: depth, nxt: nxt, nxtHow: nxtHow, order: order, holders: holders, exposed: exposed, users: users };
  }

  function stepsText(M, S, start) {
    let out = "";
    let node = start;
    while (S.nxt[node] >= 0) {
      out += " -[" + M.labels[S.nxtHow[node]] + "]-> " + M.names[S.nxt[node]];
      node = S.nxt[node];
    }
    return out;
  }

  // Path.render of a found path, or of a holder's (node, [dst, how])
  function foundText(M, S, node) {
    return M.names[node] + stepsText(M, S, node);
  }

  function holderText(M, S, node, h) {
    return M.names[node] + " -[" + M.labels[h[1]] + "]-> " + M.names[h[0]] + stepsText(M, S, h[0]);
  }

  // whatif.run's path half for a set of removals. Either {rebuild: [...]} with no numbers
  // (the mask does not model those), or before/after, tier 0 after the changes and each
  // holder of before closed, rerouted or open, plus the holders that are new. `note`
  // always says findings were not rechecked.
  function whatifEvaluate(G, W, removed) {
    const needsCli = removed.filter((p) => W.rebuild[p]);
    if (needsCli.length) {
      return { rebuild: needsCli, findings_rechecked: false, note: WHATIF_REBUILD_NOTE };
    }
    if (W.before === null) W.before = whatifState(G, W, whatifMask(G, W, []));
    const B = W.before;
    const M = whatifMask(G, W, removed);
    const A = whatifState(G, W, M);
    const closed = [];
    const rerouted = [];
    const open = [];
    const pathsAfter = (node) => {
      const h = A.holders.get(node);
      return h ? holderText(M, A, node, h) : foundText(M, A, node);
    };
    for (const [node, h] of B.holders) {
      const old = holderText(B.graph, B, node, h);
      if (A.depth[node] <= 0 && !A.holders.has(node)) {
        closed.push({ node: node, path: old });
        continue;
      }
      const now = pathsAfter(node);
      if (now === old) open.push({ node: node, path: now });
      else rerouted.push({ node: node, before: old, after: now });
    }
    const fresh = [];
    for (const [node, h] of A.holders) {
      if (!B.holders.has(node)) fresh.push({ node: node, path: holderText(M, A, node, h) });
    }
    const numbers = (S) => ({ exposed: S.exposed, users: S.users, holders: S.holders.size, reaching: S.order.length });
    const tier0 = [];
    for (let i = 0; i < M.n; i++) if (M.tier0[i]) tier0.push(i);
    return {
      rebuild: [], before: numbers(B), after: numbers(A), tier0: tier0,
      closed: closed, rerouted: rerouted, open: open, new: fresh,
      findings_rechecked: false, note: WHATIF_FINDINGS_NOTE,
      graph: M, state: A,
    };
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
    pathRecord, render, subject, whatifModel, whatifMask, whatifState, whatifEvaluate,
    whatifFoundText: foundText, whatifHolderText: holderText, EDGE_KINDS, edgeKind, tomlString, validDate, draftProblems,
    acceptDraft, parseReport, diffReports, scoreOf, gradeOf, keyOf,
  };
})();
