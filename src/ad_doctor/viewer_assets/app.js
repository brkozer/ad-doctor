// ad-doctor viewer. Inlined at build time; the page's CSP allows only this script.
//
// Every string from the report is directory data, and directory names are attacker
// controlled. This file therefore never parses markup: elements are built with h() and
// svg(), text goes in as text nodes, attributes come from an allowlist, and links only
// ever point inside the page. Nothing is stored and nothing is sent anywhere.
(function () {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";
  const SEVERITIES = ["high", "medium", "low", "info"];
  const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
  const VIRTUAL_AFTER = 60;
  const ROW_HEIGHT = 50; // virtual object rows: the object, then its fingerprint
  const KIND_LABEL = {
    user: "User", computer: "Computer", gmsa: "gMSA", group: "Group", ou: "OU",
    container: "Container", gpo: "GPO", domain: "Domain", template: "Template",
    pki: "PKI object", ca: "CA", principal: "Principal", scope: "GPO scope",
  };
  const ATTRIBUTE = new RegExp(
    "^(class|id|role|tabindex|title|type|for|name|value|lang|hidden|disabled|readonly|scope|rows|accept|" +
      "colspan|spellcheck|autocomplete|placeholder|download|aria-[a-z]+|data-[a-z-]+|" +
      "viewBox|x|y|x1|x2|y1|y2|cx|cy|r|width|height|rx|d|points|focusable|text-anchor|" +
      "dominant-baseline|preserveAspectRatio)$"
  );

  let VM = null; // the viewmodel; null until decoded
  let META = null; // build metadata from the page (outside the payload)
  let VERIFIED = null; // payload digest matches the one recorded at build time
  // the embedded data as measured in this tab; shown instead of the header's own claims,
  // which are not covered by the GCM tag
  const ACTUAL = { sha256: "", bytes: 0 };
  let FINDINGS_BY_ID = new Map();
  const state = {
    route: "",
    filters: { sev: new Set(), cat: new Set(), mitre: "", q: "", onlyNew: false },
    open: new Set(),
    path: 0,
    node: -1,
    tab: "new",
    autoprint: false,
    pendingNode: undefined,
    draft: new Map(), // acceptance draft: check ID -> entry; never stored
    adhoc: null, // a report dropped on the Changes screen, and the diff against it
    charts: [], // the Trend screen's charts, redrawn on resize
    focusEdge: "", // the edge filter to focus again after the paths screen redraws
  };

  // ---- DOM helpers ----------------------------------------------------------------

  function setAttributes(el, attrs) {
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "on") {
        for (const [type, fn] of Object.entries(value)) el.addEventListener(type, fn);
      } else if (key === "href") {
        // internal routes only: no javascript:, data: or external URLs, ever
        const href = String(value);
        if (!href.startsWith("#")) throw new Error("only in-page links are allowed");
        el.setAttribute("href", href);
      } else if (ATTRIBUTE.test(key)) {
        el.setAttribute(key, value === true ? "" : String(value));
      } else {
        throw new Error("attribute not allowed: " + key);
      }
    }
  }

  function append(el, kids) {
    for (const kid of [].concat(kids)) {
      if (kid === null || kid === undefined || kid === false) continue;
      if (Array.isArray(kid)) append(el, kid);
      else if (kid instanceof Node) el.appendChild(kid);
      else el.appendChild(document.createTextNode(String(kid)));
    }
    return el;
  }

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    setAttributes(el, attrs);
    return append(el, kids);
  }

  function svg(tag, attrs, ...kids) {
    const el = document.createElementNS(SVG_NS, tag);
    setAttributes(el, attrs);
    return append(el, kids);
  }

  function icon(name, size) {
    const s = size || 14;
    const paths = {
      search: "M7 12.5a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11zM11 11l3.5 3.5",
      chev: "M3 1.5 7 5 3 8.5",
    };
    const view = name === "chev" ? "0 0 10 10" : "0 0 16 16";
    return svg("svg", { width: s, height: s, viewBox: view, "aria-hidden": "true", class: name },
      svg("path", { d: paths[name] }));
  }

  // counts read the same everywhere: 13,338 not 13338
  function num(n) {
    return typeof n === "number" ? n.toLocaleString("en-US") : String(n);
  }

  function plural(n, one, many) {
    return num(n) + " " + (n === 1 ? one : many || one + "s");
  }

  // Text with command-line flags in it: each flag (with the value after it, when the
  // value is a word) stays on one line, so "--accept" never breaks into "--" / "accept".
  function withFlags(text) {
    return String(text).split(/(--?[a-z][a-z0-9-]*(?: [A-Za-z0-9_.\/-]+(?=[ ,.;)]|$))?)/).map((part, i) =>
      i % 2 ? h("span", { class: "nowrap" }, part) : part).filter((x) => x !== "");
  }

  // A command for the reader to copy: it may wrap only between arguments.
  function cmd(text) {
    return h("code", { class: "cmd" }, String(text).split(" ").map((arg, i) =>
      [i ? " " : null, h("span", { class: "arg" }, arg)]));
  }

  function fmtTime(iso) {
    if (!iso) return "unknown";
    const d = new Date(iso);
    if (isNaN(d)) return String(iso);
    const p = (n) => String(n).padStart(2, "0");
    return d.getUTCFullYear() + "-" + p(d.getUTCMonth() + 1) + "-" + p(d.getUTCDate()) +
      " " + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + " UTC";
  }

  function fmtDate(iso) {
    return fmtTime(iso).slice(0, 10);
  }

  function daysSince(iso) {
    const t = Date.parse(iso);
    return isNaN(t) ? 0 : Math.floor((Date.now() - t) / 86400000);
  }

  function sevClass(s) {
    return SEVERITIES.includes(s) ? s : "info";
  }

  function sevTag(s) {
    return h("span", { class: "sev " + sevClass(s) }, SEVERITY_LABEL[s] || s);
  }

  function hrefFor(route, params) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params || {})) {
      if (v !== "" && v !== null && v !== undefined && v !== false) q.set(k, String(v));
    }
    const s = q.toString();
    return "#" + route + (s ? "?" + s : "");
  }

  function announce(text) {
    const live = document.getElementById("live");
    if (live) {
      live.textContent = "";
      setTimeout(() => { live.textContent = text; }, 30);
    }
  }

  // ---- clipboard and downloads ----------------------------------------------------

  function legacyCopy(text) {
    const area = h("textarea", { class: "sr-only", readonly: true, "aria-hidden": "true" });
    area.value = text;
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    area.remove();
    return ok;
  }

  function copyButton(text, label, what) {
    const btn = h("button", { type: "button", class: "btn ghost", title: "Copy " + (what || "") },
      label || "Copy");
    btn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      const value = typeof text === "function" ? text() : text;
      let ok = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(value);
          ok = true;
        }
      } catch (e) { ok = false; }
      if (!ok) ok = legacyCopy(value);
      const before = btn.textContent;
      btn.textContent = ok ? "Copied" : "Copy failed";
      btn.classList.toggle("done", ok);
      announce(ok ? "Copied " + (what || "") : "Copy failed");
      setTimeout(() => { btn.textContent = before; btn.classList.remove("done"); }, 1400);
    });
    return btn;
  }

  function safeName(text) {
    return String(text).replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+/, "").slice(0, 80) ||
      "report";
  }

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type: type }));
    const a = h("a", { download: safeName(name), class: "sr-only" });
    a.href = url; // a blob: URL this page just made, not data from the report
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  function csvCell(value) {
    let s = String(value === null || value === undefined ? "" : value);
    // spreadsheet formula injection: directory names can start with = + - @
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  // ---- payload ----------------------------------------------------------------------

  function base64Bytes(text) {
    const bin = atob(text.trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(buffer) {
    return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function inflate(packed) {
    const stream = new Blob([packed]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Response(stream).arrayBuffer();
  }

  function adopt(bytes) {
    VM = JSON.parse(new TextDecoder().decode(bytes));
    FINDINGS_BY_ID = new Map(VM.findings.map((f) => [f.id, f]));
  }

  async function decodePlain(packed) {
    const bytes = await inflate(packed);
    ACTUAL.bytes = bytes.byteLength;
    if (window.crypto && crypto.subtle) {
      try {
        ACTUAL.sha256 = hex(await crypto.subtle.digest("SHA-256", bytes));
        VERIFIED = ACTUAL.sha256 === META.sha256;
      } catch (e) { VERIFIED = null; }
    }
    adopt(bytes);
  }

  // The version, build time and KDF and cipher parameters; seal.additional_data() builds
  // the same string, and AES-GCM refuses to decrypt if any of them was edited. The size
  // and SHA-256 in the header are not in it: the page measures those itself.
  function additionalData() {
    return new TextEncoder().encode(["ad-doctor-view", META.schema, META.version, META.built_at,
      META.kdf.iterations, META.kdf.salt, META.cipher.nonce].join("|"));
  }

  // PBKDF2-HMAC-SHA256 then AES-256-GCM, as seal.py wrote it. Throws on a wrong passphrase.
  async function decrypt(packed, passphrase) {
    const raw = new TextEncoder().encode(passphrase.normalize("NFC"));
    const base = await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: base64Bytes(META.kdf.salt), iterations: META.kdf.iterations },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    raw.fill(0);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64Bytes(META.cipher.nonce), additionalData: additionalData(), tagLength: 128 },
      key, packed);
    return new Uint8Array(plain);
  }

  function kb(bytes) {
    return bytes < 1024 * 1024 ? Math.max(1, Math.round(bytes / 1024)) + " KB" : (bytes / 1048576).toFixed(1) + " MB";
  }

  // ---- unlock and lock --------------------------------------------------------------

  function showUnlock(packed) {
    const rounds = Number(META.kdf.iterations).toLocaleString("en");
    ACTUAL.bytes = packed.byteLength;
    const input = h("input", { type: "password", id: "passphrase", autocomplete: "off", spellcheck: "false",
      "aria-describedby": "unlock-help unlock-status" });
    const reveal = h("button", { type: "button", class: "btn ghost", "aria-pressed": "false", "aria-controls": "passphrase" }, "Show");
    reveal.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      reveal.textContent = show ? "Hide" : "Show";
      reveal.setAttribute("aria-pressed", String(show));
      input.focus();
    });
    const go = h("button", { type: "button", class: "btn primary" }, "Unlock");
    const status = h("p", { id: "unlock-status", class: "unlock-status", role: "status" });
    const shaText = h("span", { class: "mono" }, "…");
    const digest = h("div", { class: "small muted" }, "checking…");
    // the hash recorded at build time against the data actually in the file: an edited
    // file is refused before any passphrase is tried
    let intact = null;
    const checked = crypto.subtle.digest("SHA-256", packed).then((d) => {
      ACTUAL.sha256 = hex(d);
      intact = ACTUAL.sha256 === META.sha256;
      shaText.textContent = ACTUAL.sha256;
      digest.textContent = intact ? "matches the hash recorded when the file was written"
        : "does not match the hash recorded when the file was written: the file was changed";
      digest.className = "small " + (intact ? "ok-text" : "warn-text");
      return intact;
    });
    let busy = false;
    const refuse = (text) => {
      status.className = "unlock-status bad";
      status.textContent = text;
      input.focus();
      if (input.value) input.select();
    };
    const attempt = async () => {
      if (busy) return;
      if (!input.value) { refuse("Enter the passphrase."); return; }
      if (!(await checked)) {
        refuse("This file was changed after it was written, so it is not opened. Ask for a fresh copy.");
        return;
      }
      busy = true;
      go.disabled = input.disabled = true;
      status.className = "unlock-status";
      status.textContent = "Deriving the key (" + rounds + " rounds)…";
      let bytes = null;
      try { bytes = await decrypt(packed, input.value); } catch (e) { bytes = null; }
      if (bytes === null) {
        busy = false;
        go.disabled = input.disabled = false;
        refuse("That passphrase does not open this file.");
        return;
      }
      input.value = "";
      try {
        adopt(await inflate(bytes));
      } catch (e) {
        fail("The report decrypted but could not be read: the file is damaged.");
        return;
      }
      VERIFIED = true; // the GCM tag authenticated every byte
      boot();
      document.getElementById("main").focus({ preventScroll: true });
    };
    go.addEventListener("click", attempt);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); attempt(); } });
    const card = h("div", { class: "unlock" },
      brand(),
      h("h1", null, "This report is encrypted"),
      h("p", { id: "unlock-help", class: "lede" }, "Enter the passphrase it was written with. It is decrypted in this tab " +
        "and kept in memory only; this file makes no network requests."),
      h("label", { for: "passphrase", class: "field-label" }, "Passphrase"),
      h("div", { class: "unlock-row" }, h("div", { class: "pw" }, input, reveal), go),
      status,
      h("dl", { class: "facts-list unlock-facts" },
        h("dt", null, "Written by"), h("dd", null, "ad-doctor " + META.version),
        h("dt", null, "Built"), h("dd", null, fmtTime(META.built_at)),
        h("dt", null, "Encrypted data"), h("dd", null, kb(ACTUAL.bytes)),
        h("dt", null, "Encryption"), h("dd", null, "AES-256-GCM, key from PBKDF2-HMAC-SHA256 with " + rounds + " rounds"),
        h("dt", null, "SHA-256"), h("dd", null, shaText, digest)),
      h("p", { class: "small muted" }, "The domain, the findings and every directory name are inside the encrypted part; " +
        "nothing shown here is secret."));
    const page = h("div", { id: "app", class: "unlock-page" }, h("main", { class: "unlock-main" }, card));
    document.getElementById("app").replaceWith(page);
    document.title = "Encrypted report · ad-doctor";
    input.focus();
  }

  // Drop every reference to the decrypted data and reload: the page comes back locked.
  function lock() {
    VM = null;
    GRAPH = null;
    FINDINGS_BY_ID = new Map();
    state.draft.clear();
    state.adhoc = null;
    document.getElementById("app").replaceChildren();
    history.replaceState(null, "", location.pathname + location.search);
    location.reload();
  }

  // ---- frame ------------------------------------------------------------------------

  const NAV = [
    ["overview", "Overview"],
    ["findings", "Findings"],
    ["paths", "Control paths"],
    ["blast", "Blast radius"],
    ["changes", "Changes"],
    ["trend", "Trend"],
    ["accepted", "Policy"],
    ["about", "About this file"],
  ];

  function navCount(route) {
    if (route === "findings") return { n: VM.findings.length };
    if (route === "paths") return VM.paths ? { n: VM.paths.list.length, alert: true } : null;
    if (route === "changes") return VM.baseline ? { n: "+" + VM.baseline.new.length } : null;
    if (route === "trend") return VM.trend ? { n: VM.trend.points.length } : null;
    if (route === "accepted") {
      const l = VM.lifecycle;
      const issues = (l.expired || 0) + (l.stale || 0) + (l.drift || 0);
      if (issues) return { n: issues, alert: true };
      return state.draft.size ? { n: "draft " + state.draft.size } : null;
    }
    return null;
  }

  function refreshNav() {
    for (const a of document.querySelectorAll(".nav a")) {
      const c = navCount(a.getAttribute("data-route"));
      const old = a.querySelector(".count");
      if (old) old.remove();
      if (c) a.appendChild(h("span", { class: "count" + (c.alert ? " alert" : "") }, c.n));
    }
  }

  function brand() {
    return h("div", { class: "brand" },
      svg("svg", { width: 18, height: 18, viewBox: "0 0 16 16", "aria-hidden": "true" },
        svg("rect", { class: "brand-mark", width: 16, height: 16, rx: 3.5 }),
        svg("path", {
          class: "brand-cross",
          d: "M6.75 3.5h2.5v3.25h3.25v2.5H9.25v3.25h-2.5V9.25H3.5v-2.5h3.25z",
        })),
      "ad-doctor");
  }

  function frame() {
    const m = VM.meta;
    const nav = h("nav", { class: "nav", "aria-label": "Sections" },
      NAV.map(([route, label]) => {
        const c = navCount(route);
        return h("a", { href: "#" + route, "data-route": route }, h("span", null, label),
          c ? h("span", { class: "count" + (c.alert ? " alert" : "") }, c.n) : null);
      }));
    let locker = null;
    if (META.encrypted) {
      const btn = h("button", { type: "button", class: "btn lock", title: "Forget the decrypted data and lock the file" }, "Lock");
      btn.addEventListener("click", lock);
      locker = h("div", { class: "side-lock" }, btn, h("span", { class: "small muted" }, "Decrypted in this tab"));
    }
    const side = h("header", { class: "side" },
      brand(),
      h("div", { class: "side-domain" },
        h("div", { class: "label" }, m.redacted ? "Redacted snapshot" : "Domain"),
        h("div", { class: "value", title: m.domain }, m.domain),
        h("div", { class: "sub" }, fmtTime(m.collected_at))),
      locker,
      nav,
      h("div", { class: "side-foot" },
        "ad-doctor " + m.version, h("br"), "Offline file. No network access."));
    const main = h("main", { id: "main", class: "main", tabindex: "-1" });
    const live = h("div", { id: "live", class: "sr-only", "aria-live": "polite" });
    const app = h("div", { id: "app", class: "app" }, side, main, live);
    document.getElementById("app").replaceWith(app);
    document.title = m.domain + " · ad-doctor";
  }

  // ---- router -----------------------------------------------------------------------

  const ROUTES = {
    overview: viewOverview,
    findings: viewFindings,
    paths: viewPaths,
    blast: viewBlast,
    changes: viewChanges,
    trend: viewTrend,
    accepted: viewAccepted,
    about: viewAbout,
    print: viewPrint,
  };

  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, "");
    const cut = raw.indexOf("?");
    const path = cut < 0 ? raw : raw.slice(0, cut);
    const params = new URLSearchParams(cut < 0 ? "" : raw.slice(cut + 1));
    const [name, arg] = path.split("/").map((x) => {
      try { return decodeURIComponent(x); } catch (e) { return x; }
    });
    return { name: ROUTES[name] ? name : "overview", arg: arg || "", params: params };
  }

  // On a phone the nav is one scrolling row of tabs: centre the current one in it.
  function revealTab(link) {
    const nav = link && link.parentElement;
    if (!nav || nav.scrollWidth <= nav.clientWidth) return;
    const target = link.offsetLeft - nav.offsetLeft - (nav.clientWidth - link.offsetWidth) / 2;
    nav.scrollLeft = Math.max(0, Math.min(target, nav.scrollWidth - nav.clientWidth));
  }

  function route() {
    const r = parseHash();
    const changed = r.name !== state.route;
    state.route = r.name;
    let current = null;
    for (const a of document.querySelectorAll(".nav a")) {
      if (a.getAttribute("data-route") === r.name) { a.setAttribute("aria-current", "page"); current = a; }
      else a.removeAttribute("aria-current");
    }
    revealTab(current);
    const main = document.getElementById("main");
    main.replaceChildren(h("div", { class: "wrap" }, ROUTES[r.name](r)));
    if (changed) {
      window.scrollTo(0, 0);
      main.focus({ preventScroll: true });
    }
    if (r.name === "print" && state.autoprint) {
      state.autoprint = false;
      setTimeout(() => window.print(), 100);
    }
  }

  function pageHead(eyebrow, title, sub, actions) {
    return h("div", { class: "page-head" },
      h("div", null, h("div", { class: "eyebrow" }, eyebrow), h("h1", null, title),
        sub ? h("div", { class: "sub" }, sub) : null),
      actions ? h("div", { class: "actions no-print" }, actions) : null);
  }

  function sectionTitle(title, extra) {
    return h("div", { class: "section-title" }, h("h2", null, title), extra || null);
  }

  function metaLine() {
    const m = VM.meta;
    const parts = ["Collected " + fmtTime(m.collected_at), "ad-doctor " + m.version];
    if (m.counts) {
      parts.push(plural(m.counts.users, "user"), plural(m.counts.computers, "computer"));
    }
    if (m.dcs && m.dcs.length) {
      const down = m.dcs.filter((d) => d.error).length;
      parts.push(plural(m.dcs.length - down, "DC") + " probed" + (down ? ", " + down + " unreachable" : ""));
    }
    if (m.source === "report") parts.push("from a JSON report");
    return parts.join(" · ");
  }

  function banners() {
    const out = [];
    const m = VM.meta;
    if (m.redacted) {
      out.push(h("div", { class: "banner" }, h("div", null, h("strong", null, "Redacted snapshot. "),
        "Names, hosts and SIDs are pseudonyms; this file cannot reveal the real ones.")));
    }
    const age = daysSince(m.collected_at);
    if (age > 30) {
      out.push(h("div", { class: "banner medium" }, h("div", null,
        h("strong", null, "This snapshot is " + age + " days old. "),
        "The directory has probably changed since; collect a new one before acting on it.")));
    }
    return out;
  }

  // ---- overview ---------------------------------------------------------------------

  function viewOverview() {
    const p = VM.paths;
    const b = VM.baseline;
    const out = [pageHead("Active Directory assessment", VM.meta.domain, metaLine()), banners()];

    // exposure leads: the score saturates at 100, exposure does not
    let exposure;
    if (p && p.users !== null && p.users !== undefined) {
      const pct = p.users ? Math.floor((100 * p.exposed) / p.users) : 0;
      const meter = exposureMeter(pct);
      exposure = h("div", { class: "panel exposure" },
        h("div", { class: "eyebrow" }, "Tier-0 exposure"),
        h("div", { class: "lead" },
          h("div", { class: "hero-num" }, String(pct), h("span", { class: "unit" }, "%")),
          h("p", null, num(p.exposed) + " of " + plural(p.users, "enabled user") +
            " outside tier 0 have a control path to it through their account or groups.")),
        meter,
        h("div", { class: "facts" },
          h("span", null, h("b", null, num(p.list.length)), " principals hold a right directly"),
          h("span", null, h("b", null, num(p.chokepoints.length)), " ",
            p.chokepoints.length === 1 ? "chokepoint" : "chokepoints", " to break first"),
          b && b.users ? h("span", null, "Baseline ", h("b", null,
            Math.floor((100 * b.exposed) / b.users) + "%")) : null),
        p.broad ? h("div", { class: "banner high" }, h("div", null,
          h("strong", null, "Broad groups have a path. "),
          "Every user is effectively tier 0 until those paths are broken.")) : null,
        h("div", { class: "link-row" }, h("a", { href: "#paths" }, "Open control paths →")));
    } else {
      exposure = h("div", { class: "panel exposure" },
        h("div", { class: "eyebrow" }, "Tier-0 exposure"),
        h("div", { class: "lead" }, h("div", { class: "hero-num" }, "0"),
          h("p", null, p ? "Control paths are listed, but this report does not carry the user count."
            : "No principal outside tier 0 has a control path to it in this snapshot.")),
        p ? h("div", { class: "link-row" }, h("a", { href: "#paths" }, "Open control paths →")) : null);
    }

    const out2 = h("div", { class: "grid" },
      h("div", { class: "span-7" }, exposure),
      h("div", { class: "span-5" }, scoreCard()));
    out.push(out2);

    out.push(h("div", { class: "sevbar", style: null, role: "list", "aria-label": "Findings by severity" },
      SEVERITIES.map((s) => {
        const n = VM.counts[s] || 0;
        return h("a", { href: hrefFor("findings", { sev: s }), role: "listitem", class: n ? "" : "zero" },
          sevTag(s), h("span", { class: "n" }, String(n)));
      })));

    const cats = h("div", { class: "panel" }, sectionTitle("Risk by category",
      h("span", { class: "small muted" }, "0 to 100 per category")),
    h("div", { class: "cats" }, VM.categories.map(([name, score]) => {
      const bar = h("span", { class: fillClass(score) });
      bar.style.width = (score ? Math.max(score, 2) : 0) + "%";
      return h("a", { class: "cat" + (score ? "" : " zero"), href: hrefFor("findings", { cat: name }) },
        h("span", { class: "name" }, name), h("span", { class: "track" }, bar),
        h("span", { class: "v" }, String(score)));
    })));

    const acts = h("div", { class: "panel" }, sectionTitle("Top actions",
      h("span", { class: "small muted" }, "high findings, most control paths first")),
    VM.top_actions.length ? h("ol", { class: "actions-list" }, VM.top_actions.map((a) =>
      h("li", null, h("a", { href: hrefFor("findings", { open: a.id }) },
        h("span", { class: "t" }, a.title),
        h("span", { class: "m" }, a.id + " · " + plural(a.objects, "object") +
          (a.paths ? " · first step of " + plural(a.paths, "control path") : "")))))) :
      h("div", { class: "empty" }, "No high-severity findings."));

    out.push(h("div", { class: "grid" }, h("div", { class: "span-6" }, cats),
      h("div", { class: "span-6" }, acts)));

    const chains = VM.findings.filter((f) => f.id.startsWith("AD-CHAIN-"));
    if (chains.length) {
      out.push(h("div", { class: "panel" }, sectionTitle("Compound findings",
        h("span", { class: "small muted" }, "individually medium, together a known compromise")),
      chains.map((f) => h("a", { class: "chain", href: hrefFor("findings", { open: f.id }) },
        h("span", { class: "id" }, f.id), h("span", { class: "t" }, f.title),
        h("span", { class: "d" }, f.detail)))));
    }

    out.push(h("div", null, sectionTitle("Lifecycle"), lifecycleTiles()));

    if (VM.notes.length) {
      out.push(h("div", { class: "panel" }, sectionTitle("Notes",
        h("span", { class: "small muted" }, "what this run could not check, and acceptance warnings")),
      h("ul", { class: "notes" }, VM.notes.map((n) => h("li", null, n)))));
    }
    return h("div", { class: "stack" }, out);
  }

  function exposureMeter(pct) {
    const meter = h("div", { class: "meter", "aria-hidden": "true" }, h("span"));
    meter.firstChild.style.width = Math.max(pct, 1) + "%";
    return meter;
  }

  function fillClass(score) {
    if (!score) return "fill-ok";
    return score > 45 ? "fill-high" : score > 10 ? "fill-medium" : "fill-low";
  }

  function scoreCard() {
    const b = VM.baseline;
    const bands = [[10, "A"], [25, "B"], [45, "C"], [70, "D"], [100, "F"]];
    let lo = 0;
    const track = h("div", { class: "scale-track", "aria-hidden": "true" });
    const labels = h("div", { class: "scale-labels", "aria-hidden": "true" });
    for (const [hi, g] of bands) {
      const seg = h("span", { class: g === VM.grade ? "on" : "" });
      seg.style.flex = String(hi - lo);
      track.appendChild(seg);
      const lab = h("span", null, g);
      lab.style.flex = String(hi - lo);
      labels.appendChild(lab);
      lo = hi;
    }
    const mark = h("span", { class: "scale-mark" });
    mark.style.left = "clamp(1px, calc(" + VM.score + "% - 1.5px), calc(100% - 4px))";
    track.appendChild(mark);
    return h("div", { class: "panel", style: null },
      h("div", { class: "score-top" },
        h("div", null, h("div", { class: "eyebrow" }, "Risk score"),
          h("div", { class: "hero-num" }, String(VM.score), h("span", { class: "unit" }, "/100"))),
        h("div", { class: "grade " + VM.grade, "aria-label": "Grade " + VM.grade }, VM.grade)),
      h("div", { class: "scale" }, track, labels),
      b ? h("div", { class: "delta" }, "Baseline " + fmtDate(b.collected_at) + ": ",
        h("b", null, b.score + " (" + b.grade + ")"), " → ", h("b", null, VM.score + " (" + VM.grade + ")")) : null,
      h("p", { class: "formula" }, "Lower is better. Each high finding adds 15, medium 6, low 2, " +
        "capped at 100; exposure tells more once the score saturates."));
  }

  function lifecycleTiles() {
    const l = VM.lifecycle;
    const tile = (n, label, route, level, hint) => {
      const off = n === null || n === undefined;
      const cls = "tile" + (off ? " off" : n && level ? " " + level : "");
      const kids = [h("span", { class: "n" }, off ? "–" : String(n)),
        h("span", { class: "l" }, off ? withFlags(hint) : label)];
      return off ? h("div", { class: cls, title: hint }, kids) : h("a", { class: cls, href: "#" + route }, kids);
    };
    return h("div", { class: "tiles" },
      tile(l.accepted, "accepted objects", "accepted", ""),
      tile(l.expiring, "expiring in 30 days", "accepted", "warn", "no --accept file"),
      tile(l.expired, "expired acceptances", "accepted", "bad", "no --accept file"),
      tile(l.stale, "stale acceptances", "accepted", "warn", "no --accept file"),
      tile(l.drift, "invariants drifted", "accepted", "bad", "no --invariants file"),
      tile(l.new, "new since baseline", "changes", "bad", "no --baseline"));
  }

  // ---- findings ---------------------------------------------------------------------

  function readFilters(params) {
    const f = state.filters;
    f.sev = new Set((params.get("sev") || "").split(",").filter(Boolean));
    f.cat = new Set((params.get("cat") || "").split(",").filter(Boolean));
    f.mitre = params.get("mitre") || "";
    f.q = params.get("q") || "";
    f.onlyNew = params.get("new") === "1";
    const open = params.get("open");
    if (open) state.open = new Set([open]);
  }

  function writeFilters() {
    const f = state.filters;
    const hash = hrefFor("findings", {
      // typed text can be a directory name: kept out of the URL (and so out of the
      // browser's history) when the file is encrypted
      sev: [...f.sev].join(","), cat: [...f.cat].join(","), mitre: f.mitre, q: META.encrypted ? "" : f.q,
      new: f.onlyNew ? "1" : "",
    });
    history.replaceState(null, "", hash);
  }

  function matches(f, ignore) {
    const s = state.filters;
    if (ignore !== "sev" && s.sev.size && !s.sev.has(f.severity)) return false;
    if (ignore !== "cat" && s.cat.size && !s.cat.has(f.category)) return false;
    if (s.mitre && !(f.mitre || []).includes(s.mitre)) return false;
    if (s.onlyNew && !f.new) return false;
    if (s.q) {
      const q = s.q.toLowerCase();
      const hay = [f.id, f.title, f.detail, f.category, ...(f.mitre || [])].join("\n").toLowerCase();
      if (!hay.includes(q) && !f.objects.some((o) => o.toLowerCase().includes(q))) return false;
    }
    return true;
  }

  function viewFindings(r) {
    if (!VM.findings.length) {
      return h("div", null, pageHead("Findings", "Findings"),
        h("div", { class: "empty good" }, h("strong", null, "No findings: every check that ran passed. "),
          "What this run could not check is listed under ", h("a", { href: "#about" }, "About this file"),
          VM.notes.length ? [" and in the ", h("a", { href: "#overview" }, "notes on the overview")] : null, "."));
    }
    readFilters(r.params);
    const list = h("ul", { class: "flist", "aria-label": "Findings" });
    const count = h("span", null);
    const rail = filterRail(() => update());
    const search = h("input", {
      type: "search", placeholder: "Search findings, objects, check IDs, techniques",
      "aria-label": "Search findings", spellcheck: "false", autocomplete: "off",
    });
    search.value = state.filters.q;
    search.addEventListener("input", () => { state.filters.q = search.value.trim(); update(); });
    search.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { search.value = ""; state.filters.q = ""; update(); }
    });
    const toggle = h("button", { type: "button", class: "btn filter-toggle", "aria-expanded": "false" }, "Filters");
    toggle.addEventListener("click", () => {
      const open = rail.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });

    function shown() {
      return VM.findings.filter((f) => matches(f));
    }

    function update() {
      writeFilters();
      const items = shown();
      count.textContent = items.length === VM.findings.length
        ? plural(items.length, "finding")
        : num(items.length) + " of " + plural(VM.findings.length, "finding");
      list.replaceChildren(...items.map(findingItem));
      if (!items.length) list.appendChild(h("li", null, h("div", { class: "empty" }, "Nothing matches these filters.")));
      refreshRail(rail);
    }

    const exportCsv = h("button", { type: "button", class: "btn" }, "Export CSV");
    exportCsv.addEventListener("click", () => {
      const rows = [["severity", "check", "title", "category", "object", "fingerprint", "new"]];
      for (const f of shown()) {
        f.objects.forEach((o, i) => rows.push([f.severity, f.id, f.title, f.category, o,
          f.fingerprints[i], f.new === undefined ? "" : f.new ? "yes" : "no"]));
      }
      download("ad-doctor-" + VM.meta.domain + "-findings.csv",
        rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n", "text/csv");
    });
    const exportJson = h("button", { type: "button", class: "btn" }, "Export JSON");
    exportJson.addEventListener("click", () => {
      const items = shown().map((f) => ({
        id: f.id, title: f.title, category: f.category, severity: f.severity, detail: f.detail,
        remediation: f.remediation, objects: f.objects, fingerprints: f.fingerprints, mitre: f.mitre,
      }));
      download("ad-doctor-" + VM.meta.domain + "-findings.json",
        JSON.stringify({ domain: VM.meta.domain, collected_at: VM.meta.collected_at, findings: items }, null, 2),
        "application/json");
    });

    const page = h("div", null,
      pageHead("Findings", "Findings", "Sorted by severity, then check. Expand one for the evidence and the fix.",
        [exportCsv, exportJson]),
      h("div", { class: "findings-layout" }, rail,
        h("div", null,
          h("div", { class: "search" }, icon("search", 16), search, h("kbd", { "aria-hidden": "true" }, "/")),
          h("div", { class: "result-line" }, count, toggle),
          list)));
    update();
    const opened = r.params.get("open");
    if (opened) {
      setTimeout(() => {
        const el = document.getElementById("f-" + opened);
        if (el) { el.scrollIntoView({ block: "start" }); el.querySelector(".frow").focus({ preventScroll: true }); }
      }, 0);
    }
    return page;
  }

  function filterRail(onChange) {
    const rail = h("aside", { class: "rail", "aria-label": "Filters" });
    const f = state.filters;
    const group = (legend, values, set, key, label) => h("fieldset", null, h("legend", null, legend),
      values.map((v) => {
        const box = h("input", { type: "checkbox", "data-key": key, "data-value": v });
        box.checked = set.has(v);
        box.addEventListener("change", () => {
          if (box.checked) set.add(v); else set.delete(v);
          onChange();
        });
        return h("label", { class: "check" }, box, label ? label(v) : h("span", null, v),
          h("span", { class: "c", "data-count": key + ":" + v }));
      }));
    const cats = [...new Set(VM.findings.map((x) => x.category))].sort();
    const techniques = [...new Set(VM.findings.flatMap((x) => x.mitre || []))].sort();
    const mitre = h("select", { class: "select", "aria-label": "MITRE ATT&CK technique" },
      h("option", { value: "" }, "Any technique"), techniques.map((t) => h("option", null, t)));
    mitre.value = f.mitre;
    mitre.addEventListener("change", () => { f.mitre = mitre.value; onChange(); });
    append(rail, [
      group("Severity", SEVERITIES, f.sev, "sev", (v) => sevTag(v)),
      group("Category", cats, f.cat, "cat"),
      h("fieldset", null, h("legend", null, "ATT&CK"), mitre),
    ]);
    if (VM.baseline) {
      const box = h("input", { type: "checkbox" });
      box.checked = f.onlyNew;
      box.addEventListener("change", () => { f.onlyNew = box.checked; onChange(); });
      rail.appendChild(h("fieldset", null, h("legend", null, "Baseline"),
        h("label", { class: "check" }, box, h("span", null, "New since baseline only"))));
    }
    const clear = h("button", { type: "button", class: "btn ghost" }, "Clear filters");
    clear.addEventListener("click", () => {
      f.sev.clear(); f.cat.clear(); f.mitre = ""; f.q = ""; f.onlyNew = false;
      location.hash = "#findings";
    });
    rail.appendChild(h("div", null, clear));
    return rail;
  }

  function refreshRail(rail) {
    for (const el of rail.querySelectorAll("[data-count]")) {
      const [key, value] = el.getAttribute("data-count").split(/:(.*)/s);
      const n = VM.findings.filter((x) => matches(x, key) &&
        (key === "sev" ? x.severity === value : x.category === value)).length;
      el.textContent = String(n);
      el.parentElement.classList.toggle("zero", n === 0);
    }
  }

  function findingItem(f) {
    const open = state.open.has(f.id);
    const row = h("button", { type: "button", class: "frow", "aria-expanded": String(open),
      "aria-controls": "fd-" + f.id },
      sevTag(f.severity),
      h("span", { class: "id" }, f.id),
      h("span", { class: "title" }, f.title, f.new ? h("span", { class: "new-badge" }, "NEW") : null),
      h("span", { class: "cat-name" }, f.category),
      h("span", { class: "n", title: plural(f.objects.length, "object") }, String(f.objects.length)),
      icon("chev", 10));
    const li = h("li", { id: "f-" + f.id }, row);
    if (open) li.appendChild(findingDetail(f));
    row.addEventListener("click", () => {
      const now = !state.open.has(f.id);
      if (now) state.open.add(f.id); else state.open.delete(f.id);
      row.setAttribute("aria-expanded", String(now));
      const existing = li.querySelector(".fdetail");
      if (existing) existing.remove();
      if (now) li.appendChild(findingDetail(f));
    });
    return li;
  }

  // "a -[x]-> b -[y]-> c -[z]-> T" as ["a", " -[x]-> b -[y]-> c", " -[z]-> T"]: in a
  // one-line row the middle gives way first, so the start and the target stay readable
  function pathParts(o) {
    const cut = o.split(/(?= -\[[^\]]*\]-> )/);
    if (cut.length < 2) return null;
    return [cut[0], cut.slice(1, -1).join(""), cut[cut.length - 1]];
  }

  function objectText(o, virtual) {
    const parts = virtual ? pathParts(o) : null;
    if (!parts) return [o];
    const cut = parts[2].indexOf("]-> ") + 4; // the last step's label, then the target
    return [h("span", { class: "o-start" }, parts[0]), parts[1] ? h("span", { class: "o-mid" }, parts[1]) : null,
      h("span", { class: "o-how" }, parts[2].slice(0, cut)), h("span", { class: "o-end" }, parts[2].slice(cut))];
  }

  function objectRow(f, o, i, virtual) {
    const isPath = f.id === "AD-PATH-001" && VM.paths;
    const index = isPath ? VM.paths.list.findIndex((p) => p.object === o) : -1;
    const text = index >= 0
      ? h("a", { class: "o", href: "#paths/" + index, title: o }, objectText(o, virtual))
      : h("span", { class: "o", title: virtual ? o : null }, objectText(o, virtual));
    return h("div", { class: "obj", role: "listitem" }, text,
      h("span", { class: "fp", title: "fingerprint of " + f.id + " on this object" }, f.fingerprints[i]),
      copyButton(f.fingerprints[i], "Copy", "fingerprint"));
  }

  function objectList(f) {
    if (f.objects.length <= VIRTUAL_AFTER) {
      return h("div", { class: "objs", role: "list" }, f.objects.map((o, i) => objectRow(f, o, i, false)));
    }
    // thousands of rows (inactive accounts on a big domain): draw only what is visible
    const box = h("div", { class: "vlist", role: "list", tabindex: "0", "aria-label": plural(f.objects.length, "object") });
    const spacer = h("div", { class: "vlist-spacer" });
    spacer.style.height = f.objects.length * ROW_HEIGHT + "px";
    box.style.height = "352px";
    box.appendChild(spacer);
    let first = -1;
    const draw = () => {
      const start = Math.max(0, Math.floor(box.scrollTop / ROW_HEIGHT) - 6);
      if (start === first) return;
      first = start;
      const end = Math.min(f.objects.length, start + Math.ceil((box.clientHeight || 352) / ROW_HEIGHT) + 12);
      const rows = [];
      for (let i = start; i < end; i++) {
        const row = objectRow(f, f.objects[i], i, true);
        row.style.top = i * ROW_HEIGHT + "px";
        rows.push(row);
      }
      spacer.replaceChildren(...rows);
    };
    box.addEventListener("scroll", () => requestAnimationFrame(draw), { passive: true });
    draw();
    return box;
  }

  function findingDetail(f) {
    const objectsText = () => f.objects.map((o, i) => o + "\t" + f.fingerprints[i]).join("\n");
    const left = h("div", null,
      h("section", null, h("h3", null, "Finding"), h("p", null, f.detail)),
      h("section", null,
        h("h3", null, h("span", null, plural(f.objects.length, "object") + " · fingerprints"),
          copyButton(objectsText, "Copy all", "objects and fingerprints")),
        objectList(f)));
    const right = h("div", null);
    if (f.doc) {
      const risk = f.doc.risk || [];
      const rest = h("div", { hidden: true }, risk.slice(1).map((p) => h("p", null, p)));
      const more = risk.length > 1 ? h("button", { type: "button", class: "more", "aria-expanded": "false" }, "Read more") : null;
      if (more) {
        more.addEventListener("click", () => {
          rest.hidden = !rest.hidden;
          more.textContent = rest.hidden ? "Read more" : "Show less";
          more.setAttribute("aria-expanded", String(!rest.hidden));
        });
      }
      append(right, h("section", null, h("h3", null, "Why it matters"),
        h("p", null, f.doc.summary), risk.length ? h("p", null, risk[0]) : null, rest, more));
    }
    append(right, h("section", null, h("h3", null, "Remediation"), h("p", null, f.remediation.replace(/`/g, ""))));
    if (f.fix && f.fix.length) {
      const script = f.fix.join("\n");
      append(right, h("section", null,
        h("h3", null, h("span", null, "Fix script (dry run)"), copyButton(script, "Copy", "fix script")),
        h("pre", { class: "code" }, script)));
    }
    append(right, h("section", { class: "no-print" }, h("h3", null, "Accepted risk"),
      h("div", { class: "draft-add" }, draftButton(f),
        h("span", { class: "small muted" }, "drafts accept-draft.toml on the Policy screen"))));
    if (f.mitre && f.mitre.length) {
      append(right, h("section", null, h("h3", null, "MITRE ATT&CK"),
        h("div", { class: "tags" }, f.mitre.map((t) => h("span", { class: "pill" }, t)))));
    }
    if (f.doc) {
      append(right, h("section", null,
        h("h3", null, h("span", null, "Documentation"), copyButton(f.doc.url, "Copy link", "documentation link")),
        h("div", { class: "url" }, f.doc.url),
        h("div", { class: "small muted" }, "Offline: ad-doctor explain " + f.id)));
    }
    return h("div", { class: "fdetail", id: "fd-" + f.id }, left, right);
  }

  // ---- control paths ----------------------------------------------------------------

  function nodeAt(i) {
    return VM.paths.nodes[i];
  }

  function pathNodes(p) {
    return [p.start, ...p.steps.map((s) => s.node)];
  }

  function viewPaths(r) {
    const P = VM.paths;
    if (!P) {
      return h("div", null, pageHead("Control paths", "Control paths to tier 0"), banners(),
        h("div", { class: "empty" }, "No principal outside tier 0 has a control path to it in this report."));
    }
    const wanted = parseInt(r.arg, 10);
    if (!isNaN(wanted) && wanted >= 0 && wanted < P.list.length) {
      if (state.path !== wanted) state.node = -1;
      state.path = wanted;
    }
    if (state.pendingNode !== undefined) {
      state.node = state.pendingNode;
      state.pendingNode = undefined;
    }
    if (state.path >= P.list.length) state.path = 0;
    // edge families: a path stays listed while every one of its steps is of a shown kind
    const off = new Set((r.params.get("off") || "").split(",").filter(Boolean));
    const usage = new Map();
    const kindsOf = P.list.map((p) => new Set(p.steps.map((st) => CORE.edgeKind(st.how))));
    for (const ks of kindsOf) for (const k of ks) usage.set(k, (usage.get(k) || 0) + 1);
    const visible = P.list.map((_, i) => i).filter((i) => ![...kindsOf[i]].some((k) => off.has(k)));
    if (visible.length && !visible.includes(state.path)) { state.path = visible[0]; state.node = -1; }
    const pathHash = (i, offSet) => {
      const o = [...(offSet || off)].sort().join(",");
      return "#paths/" + i + (o ? "?off=" + o : "");
    };
    const filters = h("div", { class: "edge-filter", role: "group", "aria-label": "Show paths through these edges" },
      h("span", { class: "lbl" }, "Edges"),
      CORE.EDGE_KINDS.filter(([k]) => usage.has(k)).map(([k, label]) => {
        const box = h("input", { type: "checkbox", "data-edge": k, "aria-label": label + ", on " + plural(usage.get(k), "path") });
        box.checked = !off.has(k);
        box.addEventListener("change", () => {
          const next = new Set(off);
          if (box.checked) next.delete(k); else next.add(k);
          state.focusEdge = k;
          location.hash = pathHash(state.path, next);
        });
        return h("label", { class: "fchip" + (off.has(k) ? " off" : "") }, box, h("span", null, label),
          h("span", { class: "c" }, String(usage.get(k))));
      }),
      off.size ? h("a", { class: "reset", href: "#paths/" + state.path }, "Show all") : null,
      h("span", { class: "small muted shown" }, visible.length === P.list.length ? plural(P.list.length, "path")
        : visible.length + " of " + plural(P.list.length, "path")));
    if (state.focusEdge) {
      const k = state.focusEdge;
      state.focusEdge = "";
      setTimeout(() => { const el = document.querySelector('[data-edge="' + k + '"]'); if (el) el.focus(); }, 0);
    }
    const total = P.list.length;
    const pct = P.users ? Math.floor((100 * P.exposed) / P.users) : null;
    const b = VM.baseline;
    const stats = h("div", { class: "stats" },
      stat(pct === null ? "–" : pct + "%", "of enabled users have a path", b && b.users ?
        Math.floor((100 * b.exposed) / b.users) + "%" : null),
      stat(num(total), "principals hold a right directly", b ? num(b.paths) : null),
      stat(num(P.chokepoints.length), "chokepoints (shared by 2+ paths)"),
      stat(String(Math.max(...P.list.map((p) => p.steps.length))), "hops on the longest path"));

    const chainBox = h("div", { class: "panel" });
    const items = visible.map((i) => {
      const p = P.list[i];
      const last = nodeAt(pathNodes(p).slice(-1)[0]);
      const start = nodeAt(p.start);
      const btn = h("button", { type: "button", class: "pitem", "aria-current": String(i === state.path),
        title: p.object },
      h("span", { class: "s" }, start.name),
      h("span", { class: "hops" }, plural(p.steps.length, "hop")),
      h("span", { class: "e" }, (KIND_LABEL[start.kind] || start.kind) + " → " + last.name));
      btn.addEventListener("click", () => {
        history.replaceState(null, "", pathHash(i));
        state.path = i;
        state.node = -1;
        for (const el of list.querySelectorAll(".pitem")) el.setAttribute("aria-current", "false");
        btn.setAttribute("aria-current", "true");
        drawChain(chainBox);
      });
      return h("li", null, btn);
    });
    const list = h("ul", { class: "plist", "aria-label": "Paths, broad groups first, then shortest" }, items);
    if (visible.length) drawChain(chainBox);
    else {
      list.appendChild(h("li", { class: "none" }, "No path uses only the edges shown."));
      chainBox.appendChild(h("div", { class: "empty" }, "Every path goes through an edge kind that is hidden."));
    }

    const copyMermaid = copyButton(() => P.mermaid, "Copy all as Mermaid", "Mermaid flowchart");
    copyMermaid.classList.remove("ghost");

    return h("div", { class: "stack" },
      pageHead("Control paths", "Control paths to tier 0", P.detail, [copyMermaid]),
      banners(),
      P.broad ? h("div", { class: "banner high" }, h("div", null, h("strong", null, "Broad groups have a path. "),
        "Every user is effectively tier 0: fix those first.")) : null,
      stats,
      filters,
      h("div", { class: "paths-layout" }, list, chainBox),
      chokepointTable());
  }

  function stat(n, label, before) {
    return h("div", { class: "stat" },
      h("div", { class: "n" }, before !== null && before !== undefined ? [h("span", { class: "from" }, before + " → "), n] : n),
      h("div", { class: "l" }, label));
  }

  function drawChain(box) {
    const P = VM.paths;
    const p = P.list[state.path];
    const ids = pathNodes(p);
    if (state.node < 0 || !ids.includes(state.node)) state.node = p.start;
    const scroll = h("div", { class: "chain-scroll" });
    const inspector = h("div", null);
    const start = nodeAt(p.start);
    const end = nodeAt(ids[ids.length - 1]);
    box.replaceChildren(
      h("div", { class: "chain-head" },
        h("div", null, h("div", { class: "eyebrow" }, "Path " + (state.path + 1) + " of " + P.list.length +
          " · " + plural(p.steps.length, "hop")),
        h("h2", null, start.name + " → " + end.name)),
        h("div", { class: "no-print" }, copyButton(p.object, "Copy path", "path"),
          copyButton(p.fingerprint, "Copy fingerprint", "fingerprint"))),
      scroll,
      h("div", { class: "section-title node-title" }, h("h2", null, "Selected node")),
      inspector);
    const render = () => {
      scroll.replaceChildren(chainSvg(p, Math.max(scroll.clientWidth || box.clientWidth - 40, 260), (n) => {
        state.node = n;
        render();
      }));
      inspector.replaceChildren(nodeInspector(state.node));
    };
    // width is known once the panel is in the document
    requestAnimationFrame(render);
    render();
  }

  function fit(text, max) {
    return text.length > max ? text.slice(0, Math.max(1, max - 1)) + "…" : text;
  }

  function wrapLabel(text, max) {
    if (text.length <= max) return [text];
    const breaks = [", ", "/", " "];
    for (const sep of breaks) {
      const cut = text.lastIndexOf(sep, max);
      if (cut > 0) {
        const first = text.slice(0, cut + (sep === "/" ? 1 : 0));
        const rest = text.slice(cut + sep.length).trim();
        return [first.trim(), fit(rest, max)];
      }
    }
    return [text.slice(0, max), fit(text.slice(max), max)];
  }

  function chainSvg(p, width, onSelect) {
    const ids = pathNodes(p);
    // left to right when the whole chain fits (shrunk by up to a quarter), else top down
    const n = ids.length;
    const scale = Math.min(1, (width - 4) / (n * 178 + (n - 1) * 150));
    const vertical = scale < 0.75;
    const NH = 56;
    const NW = vertical ? Math.min(width - 4, 360) : Math.floor(178 * scale);
    const GAP = vertical ? 58 : Math.floor(150 * scale);
    const W = vertical ? NW + 4 : ids.length * NW + (ids.length - 1) * GAP + 4;
    const H = vertical ? ids.length * NH + (ids.length - 1) * GAP + 4 : NH + 4;
    const root = svg("svg", { class: "chain-svg", width: W, height: H, viewBox: "0 0 " + W + " " + H,
      role: "group", "aria-label": "Path from " + nodeAt(p.start).name });
    const nameChars = Math.floor((NW - 24) / 7.4);
    ids.forEach((id, i) => {
      const x = vertical ? 2 : 2 + i * (NW + GAP);
      const y = vertical ? 2 + i * (NH + GAP) : 2;
      if (i > 0) {
        const how = p.steps[i - 1].how;
        let line, head, labels;
        if (vertical) {
          const lx = x + 26;
          const y0 = y - GAP;
          line = svg("path", { class: "edge", d: "M" + lx + " " + y0 + "V" + (y - 7) });
          head = svg("path", { class: "head", d: "M" + (lx - 4.5) + " " + (y - 8) + "h9l-4.5 7z" });
          labels = wrapLabel(how, Math.floor((NW - 50) / 6.8)).map((t, k, all) =>
            svg("text", { class: "elabel", x: lx + 14, y: y0 + GAP / 2 + 4 + (k - (all.length - 1) / 2) * 15 }, t));
        } else {
          const x0 = x - GAP;
          line = svg("path", { class: "edge", d: "M" + x0 + " " + (y + NH / 2) + "H" + (x - 7) });
          head = svg("path", { class: "head", d: "M" + (x - 8) + " " + (y + NH / 2 - 4.5) + "v9l7-4.5z" });
          labels = wrapLabel(how, Math.floor((GAP - 14) / 6.8)).map((t, k, all) =>
            svg("text", { class: "elabel", x: x0 + GAP / 2, y: y + NH / 2 + (k === 0 ? -8 : 17),
              "text-anchor": "middle" }, t));
        }
        root.appendChild(svg("g", null, svg("title", null, how), line, head, labels));
      }
      const n = nodeAt(id);
      const kind = (n.tier0 ? "TIER 0 · " : "") + (KIND_LABEL[n.kind] || n.kind).toUpperCase();
      const g = svg("g", {
        class: "node" + (n.tier0 ? " tier0" : "") + (i === 0 ? " start" : "") + (id === state.node ? " sel" : ""),
        tabindex: "0", role: "button", "aria-pressed": String(id === state.node),
        "aria-label": n.name + ", " + (KIND_LABEL[n.kind] || n.kind) + (n.tier0 ? ", tier 0" : ""),
      },
      svg("title", null, n.name),
      svg("rect", { class: "nbox", x: x, y: y, width: NW, height: NH, rx: 6 }),
      svg("text", { class: "nkind", x: x + 12, y: y + 20 }, kind),
      svg("text", { class: "nname", x: x + 12, y: y + 40 }, fit(n.name, nameChars)));
      g.addEventListener("click", () => onSelect(id));
      g.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(id); }
      });
      root.appendChild(g);
    });
    return root;
  }

  function nodeInspector(id) {
    const n = nodeAt(id);
    const P = VM.paths;
    const on = P.list.filter((p) => pathNodes(p).includes(id)).length;
    const starts = P.list.filter((p) => p.start === id).length;
    const links = (n.findings || []).map((fid) =>
      h("a", { href: hrefFor("findings", { open: fid, q: n.name }), title: (FINDINGS_BY_ID.get(fid) || {}).title || fid }, fid));
    return h("dl", { class: "inspector" },
      h("dt", null, "Name"), h("dd", { class: "mono" }, n.name),
      h("dt", null, "Kind"), h("dd", null, KIND_LABEL[n.kind] || n.kind),
      n.sid ? [h("dt", null, "SID"), h("dd", { class: "mono" }, n.sid)] : null,
      h("dt", null, "Tier 0"), h("dd", null, n.tier0 ? h("span", { class: "pill high" }, "Yes") : "No"),
      h("dt", null, "On paths"), h("dd", null, on + " of " + P.list.length + (starts ? " (starts " + starts + ")" : "")),
      h("dt", null, "Also in"), h("dd", null, links.length ? h("span", { class: "links" }, links) :
        h("span", { class: "muted" }, "no other finding names it")));
  }

  function chokepointTable() {
    const P = VM.paths;
    const total = P.list.length;
    const head = sectionTitle("Break here first",
      h("span", { class: "small muted" }, "edges and nodes the most paths share; one change breaks all of them"));
    if (!P.chokepoints.length) {
      return h("div", null, head, h("div", { class: "empty" }, "No step is shared by two or more paths: each path needs its own fix."));
    }
    const rows = P.chokepoints.map((c, i) => {
      const what = c.from !== undefined
        ? [h("span", { class: "mono" }, nodeAt(c.from).name), " ", h("span", { class: "how" }, "-[" + c.how + "]→"), " ",
          h("span", { class: "mono" }, nodeAt(c.to).name)]
        : h("span", { class: "mono" }, nodeAt(c.to).name);
      const bar = h("span");
      bar.style.width = Math.round((100 * c.count) / total) + "%";
      const tr = h("tr", { class: "clickable", tabindex: "0", title: "Show the first path through it" },
        h("td", { class: "num muted" }, String(i + 1)),
        h("td", null, what),
        h("td", { class: "hide-sm" }, c.from !== undefined ? "Edge" : "Node"),
        h("td", { class: "num" }, h("span", { class: "share" }, num(c.count) + " of " + num(total),
          h("span", { class: "track", "aria-hidden": "true" }, bar))));
      const go = () => {
        const idx = P.list.findIndex((p) => {
          const ids = pathNodes(p);
          if (c.from === undefined) return ids.includes(c.to);
          return ids.some((n, k) => n === c.from && ids[k + 1] === c.to && p.steps[k].how === c.how);
        });
        state.pendingNode = c.from !== undefined ? c.from : c.to;
        location.hash = "#paths/" + Math.max(idx, 0);
        if (parseHash().arg === String(Math.max(idx, 0))) route();
      };
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
      return tr;
    });
    return h("div", null, head, h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, h("th", { class: "num" }, "#"), h("th", null, "Where"), h("th", { class: "hide-sm" }, "Type"),
        h("th", { class: "num" }, "Paths"))),
      h("tbody", null, rows))));
  }

  // ---- changes ----------------------------------------------------------------------

  function viewChanges() {
    const b = VM.baseline;
    const ad = state.adhoc;
    const drop = dropZone();
    if (!b && !ad) {
      return h("div", { class: "stack" }, pageHead("Changes", "Changes since a baseline"), h("div", { class: "empty" },
        "No baseline in this file. Build it with ", cmd("ad-doctor view new.json --baseline old.json"),
        ", or compare with a JSON report below."), drop);
    }
    const P = VM.paths;
    const warn = [];
    let c, title, sub, actions = null;
    if (ad) {
      const rep = ad.report;
      c = Object.assign({ score: rep.score, grade: rep.grade, exposed: rep.exposed, users: rep.users }, ad.diff);
      title = "Changes since " + fmtDate(rep.collected_at);
      sub = "Compared in this tab with " + ad.name + " (" + fmtTime(rep.collected_at) +
        (rep.version ? ", ad-doctor " + rep.version : "") + "), object by object. " + c.unchanged + " unchanged.";
      const back = h("button", { type: "button", class: "btn" }, b ? "Back to the built-in baseline" : "Clear the comparison");
      back.addEventListener("click", () => { state.adhoc = null; route(); });
      actions = [back];
      if (rep.domain.toLowerCase() !== String(VM.meta.domain).toLowerCase()) {
        warn.push(h("div", { class: "banner medium" }, h("div", null, h("strong", null, "Another domain. "),
          "The dropped report is of " + rep.domain + ", this file of " + VM.meta.domain + ".")));
      }
      if (Date.parse(rep.collected_at) > Date.parse(VM.meta.collected_at)) {
        warn.push(h("div", { class: "banner" }, h("div", null, h("strong", null, "The dropped report is newer. "),
          "New and resolved are still read from this file's point of view.")));
      }
      if (VM.acceptances) {
        warn.push(h("div", { class: "banner" }, h("div", null,
          "The dropped report is compared as it was written, with its own acceptances, not this file's.")));
      }
    } else {
      c = b;
      title = "Changes since " + fmtDate(b.collected_at);
      sub = "Baseline " + b.name + " (" + fmtTime(b.collected_at) + ") compared with this run, object by object. " +
        b.unchanged + " unchanged.";
    }
    const pct = (x, n) => (n ? Math.floor((100 * x) / n) + "%" : x === 0 ? "0%" : "–");
    const stats = h("div", { class: "stats" },
      stat(VM.score + " (" + VM.grade + ")", "risk score", c.score + " (" + c.grade + ")"),
      stat(P && P.users ? pct(P.exposed, P.users) : "–", "users with a path to tier 0",
        c.users ? pct(c.exposed, c.users) : null),
      stat(c.new.length ? "+" + c.new.length : "0", "new findings on objects"),
      stat(c.resolved.length ? "−" + c.resolved.length : "0", "resolved"));
    const tabs = [["new", "New", c.new], ["resolved", "Resolved", c.resolved], ["changed", "Changed", c.changed]];
    const body = h("div", null);
    const bar = h("div", { class: "tabs", role: "tablist" });
    const show = (key) => {
      state.tab = key;
      for (const t of bar.children) t.setAttribute("aria-selected", String(t.getAttribute("data-tab") === key));
      const rows = tabs.find((t) => t[0] === key)[2];
      body.replaceChildren(changeTable(key, rows));
    };
    for (const [key, label, rows] of tabs) {
      const t = h("button", { type: "button", class: "tab", role: "tab", "data-tab": key }, label,
        h("span", { class: "c" }, String(rows.length)));
      t.addEventListener("click", () => show(key));
      bar.appendChild(t);
    }
    show(state.tab);
    return h("div", { class: "stack" }, pageHead("Changes", title, sub, actions), warn, stats,
      h("div", null, bar, body), drop);
  }

  function changeTable(kind, rows) {
    if (!rows.length) {
      const text = { new: "Nothing new since the baseline.", resolved: "Nothing was resolved.",
        changed: "No finding changed shape or severity." }[kind];
      return h("div", { class: "empty" }, text);
    }
    const head = kind === "changed"
      ? ["Severity", "Check", "Object", "Was"]
      : ["Severity", "Check", "Object", "Finding"];
    return h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, head.map((x) => h("th", null, x)))),
      h("tbody", null, rows.map((r) => h("tr", null,
        h("td", null, sevTag(r.severity)),
        h("td", { class: "nowrap" }, kind === "resolved" ? h("span", { class: "mono" }, r.id) :
          h("a", { class: "mono", href: hrefFor("findings", { open: r.id }) }, r.id)),
        h("td", null, h("span", { class: "mono" }, r.object)),
        kind === "changed"
          ? h("td", null, r.before_severity !== r.severity ? [sevTag(r.before_severity), " "] : null,
            r.before !== r.object ? h("span", { class: "mono was" }, r.before) : null)
          : h("td", null, r.title))))));
  }

  // ---- accepted risks and invariants ------------------------------------------------

  const STATUS = {
    active: ["Active", "ok"], expiring: ["Expiring", "medium"], expired: ["Expired", "high"],
    stale: ["Stale", "medium"], skipped: ["Not judged", ""],
  };

  // a table whose rows become labelled cards on a phone (CSS: table.cards)
  function cards(table) {
    table.classList.add("cards");
    const heads = Array.from(table.querySelectorAll("thead th"), (th) => th.textContent);
    for (const tr of table.querySelectorAll("tbody tr")) {
      Array.from(tr.children).forEach((td, i) => td.setAttribute("data-label", heads[i] || ""));
    }
    return table;
  }

  function viewAccepted() {
    const out = [pageHead("Policy", "Accepted risks & invariants",
      "The TOML files in your repository stay the source of truth: this screen reads them, and the draft only downloads."),
    draftSection()];
    const entries = VM.acceptances;
    out.push(sectionTitle("Acceptance file", entries ? h("span", { class: "small muted" }, plural(entries.length, "entry", "entries")) : null));
    if (!entries) {
      out.push(h("div", { class: "empty" }, "No acceptance file in this build. Pass ", cmd("--accept accept.toml"), "."));
    } else if (!entries.length) {
      out.push(h("div", { class: "empty" }, "The acceptance file is empty."));
    } else {
      out.push(h("div", { class: "table-wrap" }, cards(h("table", null,
        h("thead", null, h("tr", null, ["Status", "Check", "Objects", "Reason", "Owner", "Expires"].map((x) => h("th", null, x)))),
        h("tbody", null, entries.map((e) => {
          const [label, cls] = STATUS[e.status] || [e.status, ""];
          const when = e.days < 0 ? Math.abs(e.days) + " days ago" : e.days === 0 ? "today" : "in " + plural(e.days, "day");
          return h("tr", null,
            h("td", null, h("span", { class: "pill " + cls }, label)),
            h("td", { class: "nowrap" }, h("span", { class: "mono" }, e.check)),
            h("td", null, e.objects.length ? h("span", { class: "mono" }, e.objects.join(", ")) : h("span", { class: "muted" }, "all objects")),
            h("td", null, e.reason),
            h("td", null, [e.owner, e.ticket].filter(Boolean).join(" · ") || h("span", { class: "muted" }, "–")),
            h("td", { class: "num" }, e.expires, h("div", { class: "small muted" }, when)));
        }))))));
    }
    out.push(sectionTitle("Accepted in this report", h("span", { class: "small muted" }, "removed from the findings and the score")));
    if (!VM.accepted.length) {
      out.push(h("div", { class: "empty" }, "Nothing was accepted in this run."));
    } else {
      out.push(h("div", { class: "table-wrap" }, cards(h("table", null,
        h("thead", null, h("tr", null, ["Check", "Objects", "Reason", "Until"].map((x) => h("th", null, x)))),
        h("tbody", null, VM.accepted.map((a) => h("tr", null,
          h("td", { class: "nowrap" }, h("span", { class: "mono" }, a.check_id)),
          h("td", null, a.objects.length ? h("span", { class: "mono" }, a.objects.join(", ")) : h("span", { class: "muted" }, "all objects")),
          h("td", null, a.reason), h("td", { class: "num" }, a.expires))))))));
    }
    out.push(sectionTitle("Invariants", h("span", { class: "small muted" }, "declared state against this snapshot")));
    const inv = VM.invariants;
    if (!inv) {
      out.push(h("div", { class: "empty" }, "No invariants file in this build. Pass ", cmd("--invariants invariants.toml"), "."));
    } else if (!inv.sections.length) {
      out.push(h("div", { class: "empty" }, "The invariants file declares nothing."));
    } else {
      out.push(h("div", { class: "table-wrap" }, cards(h("table", null,
        h("thead", null, h("tr", null, ["State", "Section", "Declared", "Actual"].map((x) => h("th", null, x)))),
        h("tbody", null, inv.sections.map((s) => h("tr", null,
          h("td", null, h("span", { class: "pill " + (s.holds ? "ok" : "high") }, s.holds ? "Holds" : "Drift")),
          h("td", { class: "nowrap" }, h("div", null, "[" + s.section + "]"), h("div", { class: "small muted mono" }, s.check)),
          h("td", null, h("ul", { class: "decl" }, s.declared.map(([k, v]) =>
            h("li", null, k + " = " + (typeof v === "string" ? v : JSON.stringify(v)))))),
          h("td", null, s.holds ? h("span", { class: "muted" }, "as declared") :
            h("ul", { class: "decl" }, s.drift.map((d) => h("li", null, d)))))))))));
    }
    return h("div", { class: "stack" }, out);
  }

  // ---- about ------------------------------------------------------------------------

  function viewAbout() {
    const m = VM.meta;
    const e = m.embedded;
    const csp = (document.querySelector('meta[http-equiv="Content-Security-Policy"]') || {}).content || "";
    const yes = (v, extra) => h("span", { class: v ? "yes" : "no" }, (v ? "Yes" : "No") + (extra ? " · " + extra : ""));
    const check = h("span", { class: "muted" }, "not run");
    const run = h("button", { type: "button", class: "btn" }, "Run self-check");
    run.addEventListener("click", async () => {
      check.textContent = "checking…";
      try {
        await fetch("data:text/plain,ad-doctor");
        check.textContent = "FAILED: the page could make a request";
        check.className = "pill high";
      } catch (err) {
        check.textContent = "Network requests are blocked";
        check.className = "pill ok";
      }
    });
    const exportVm = h("button", { type: "button", class: "btn" },
      e.encrypted ? "Download viewer data (JSON, not encrypted)" : "Download viewer data (JSON)");
    exportVm.addEventListener("click", () => download("ad-doctor-" + m.domain + "-view.json",
      JSON.stringify(VM, null, 2), "application/json"));
    const print = h("button", { type: "button", class: "btn" }, "Print executive summary");
    print.addEventListener("click", () => { state.autoprint = true; location.hash = "#print"; });
    return h("div", { class: "stack" },
      pageHead("About this file", "About this file",
        "A view of one ad-doctor run, not evidence: anyone can edit an HTML file. Rebuild it from the snapshot to be sure."),
      h("div", { class: "panel" }, sectionTitle("Contents"),
        h("dl", { class: "facts-list" },
          h("dt", null, "Domain"), h("dd", null, m.domain),
          h("dt", null, "Collected"), h("dd", null, fmtTime(m.collected_at)),
          h("dt", null, "Built"), h("dd", null, fmtTime(m.built_at) + " with ad-doctor " + m.version),
          h("dt", null, "Built from"), h("dd", null, m.source === "report" ? "a JSON report" : "a snapshot"),
          h("dt", null, "Command"), h("dd", null, m.command ? cmd(m.command) : "–"),
          h("dt", null, "Report"), h("dd", null, yes(e.report, plural(VM.findings.length, "finding"))),
          h("dt", null, "Control paths"), h("dd", null, yes(e.paths, VM.paths ? plural(VM.paths.list.length, "path") : "")),
          h("dt", null, "Control graph"), h("dd", null, yes(e.graph, e.graph === "full"
            ? "full: " + plural(VM.graph.names.length, "node") + ", " + plural(VM.graph.dst.length, "edge") + ", " +
              plural(VM.graph.accounts.length, "account")
            : e.graph === "paths" ? "blast radius precomputed for " + plural(VM.blast.subjects.length, "principal") : "")),
          h("dt", null, "History"), h("dd", null, yes(e.history, e.history ? plural(e.history, "earlier report") : "")),
          h("dt", null, "Baseline"), h("dd", null, yes(e.baseline, VM.baseline ? VM.baseline.name : "")),
          h("dt", null, "Acceptance file"), h("dd", null, yes(e.acceptances)),
          h("dt", null, "Invariants file"), h("dd", null, yes(e.invariants)),
          h("dt", null, "Fix script lines"), h("dd", null, yes(e.fixes)),
          h("dt", null, "Raw snapshot"), h("dd", null, yes(e.snapshot, "never embedded")),
          h("dt", null, "Redacted"), h("dd", null, yes(m.redacted, m.redacted ? "names are pseudonyms" : "")),
          h("dt", null, "Encrypted"), h("dd", null, yes(e.encrypted, e.encrypted
            ? "AES-256-GCM, key from PBKDF2-HMAC-SHA256 (" + Number(META.kdf.iterations).toLocaleString("en") + " rounds)" : "")))),
      h("div", { class: "panel" }, sectionTitle("Integrity"),
        h("dl", { class: "facts-list" },
          h("dt", null, META.encrypted ? "Ciphertext SHA-256" : "Payload SHA-256"), h("dd", { class: "mono" }, ACTUAL.sha256 || "–"),
          h("dt", null, "Payload check"), h("dd", null, VERIFIED === true ? h("span", { class: "pill ok" },
            META.encrypted ? "Authenticated: the AES-GCM tag matched" : "Matches the build") :
            VERIFIED === false ? h("span", { class: "pill high" }, "Does not match: the data was changed after the build") :
              h("span", { class: "muted" }, "not available in this browser")),
          h("dt", null, "Payload size"), h("dd", null, META.encrypted ? kb(ACTUAL.bytes) + " encrypted (gzip-compressed JSON inside)"
            : kb(ACTUAL.bytes) + " of JSON, gzip-compressed in the file"))),
      h("div", { class: "panel" }, sectionTitle("Security policy"),
        h("p", { class: "small muted" }, "Enforced by the browser from this file's Content-Security-Policy: only this page's own " +
          "script and style run, and nothing can be fetched, posted or framed. Nothing is stored in the browser."),
        h("pre", { class: "code" }, csp.split("; ").join(";\n")),
        h("div", { class: "no-print row-top" }, run, " ", check)),
      h("div", { class: "panel no-print" }, sectionTitle("Export"),
        h("div", { class: "page-head", style: null }, h("div", { class: "actions" }, exportVm, print)),
        h("p", { class: "small muted" }, "Downloads are made in this tab from the embedded data; nothing leaves the machine.")));
  }

  // ---- print ------------------------------------------------------------------------

  function viewPrint() {
    const highs = VM.findings.filter((f) => f.severity === "high");
    const P = VM.paths;
    const back = h("button", { type: "button", class: "btn" }, "Print");
    back.addEventListener("click", () => window.print());
    return h("div", { class: "stack" },
      pageHead("Executive summary", VM.meta.domain, metaLine(), [back]),
      banners(),
      h("div", { class: "grid" },
        h("div", { class: "span-7" }, h("div", { class: "panel" },
          h("div", { class: "eyebrow" }, "Tier-0 exposure"),
          P && P.users ? [h("div", { class: "hero-num" }, Math.floor((100 * P.exposed) / P.users) + "%"),
            h("div", { class: "row-top" }, exposureMeter(Math.floor((100 * P.exposed) / P.users))),
            h("p", { class: "row-top" }, num(P.exposed) + " of " + plural(P.users, "enabled user") + " have a control path to tier 0; " +
              plural(P.list.length, "principal") + " hold a right directly.")]
            : h("p", null, P ? P.detail : "No control path to tier 0."))),
        h("div", { class: "span-5" }, scoreCard())),
      h("div", { class: "sevbar" }, SEVERITIES.map((s) => h("a", { href: hrefFor("findings", { sev: s }) },
        sevTag(s), h("span", { class: "n" }, String(VM.counts[s] || 0))))),
      VM.top_actions.length ? h("div", { class: "panel" }, sectionTitle("Top actions"),
        h("ol", { class: "actions-list" }, VM.top_actions.map((a) => h("li", null, h("a", { href: hrefFor("findings", { open: a.id }) },
          h("span", { class: "t" }, a.title), h("span", { class: "m" }, a.id + " · " + a.remediation)))))) : null,
      h("div", { class: "panel" }, sectionTitle("High-severity findings", h("span", { class: "small muted" }, String(highs.length))),
        highs.length ? highs.map((f) => h("div", { class: "print-finding" },
          h("div", { class: "head" }, h("span", { class: "mono" }, f.id), h("strong", null, f.title)),
          h("p", { class: "small" }, f.detail),
          h("div", { class: "objects" }, f.objects.slice(0, 8).join(" · ") + (f.objects.length > 8 ? " · +" + (f.objects.length - 8) + " more" : "")),
          h("p", { class: "small muted" }, "Fix: " + f.remediation))) : h("p", null, "None.")));
  }

  // ---- charts (trend) ----------------------------------------------------------------

  // nice round steps for an axis from 0 to max
  function ticks(max, count) {
    if (max <= 0) return [0, 1];
    const raw = max / count;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw);
    const out = [];
    for (let v = 0; v <= max + step / 2; v += step) out.push(Math.round(v * 100) / 100);
    if (out[out.length - 1] < max) out.push(out[out.length - 1] + step);
    return out;
  }

  // One line chart: series [{label, cls, values (null for a gap)}] over the scans, one
  // y axis, markers where the tool changed, a crosshair with every value on hover or
  // with the arrow keys. The table under the charts carries the same numbers as text.
  function lineChart(opts) {
    const box = h("div", { class: "chart", tabindex: "0", role: "img", "aria-label": opts.label });
    const tip = h("div", { class: "chart-tip", hidden: true, "aria-hidden": "true" });
    const draw = () => {
      const W = Math.max(box.clientWidth || 640, 280);
      const H = opts.height || 220;
      const m = { l: 44, r: 74, t: 22, b: 30 }; // the same for every chart, so scans line up
      const n = opts.points.length;
      const all = opts.series.flatMap((s) => s.values.filter((v) => v !== null));
      const ys = ticks(Math.max(opts.min || 0, ...all, 1), 4);
      const top = ys[ys.length - 1];
      const x = (i) => m.l + (n === 1 ? (W - m.l - m.r) / 2 : (i * (W - m.l - m.r)) / (n - 1));
      const y = (v) => m.t + (H - m.t - m.b) * (1 - v / top);
      const root = svg("svg", { width: W, height: H, viewBox: "0 0 " + W + " " + H, "aria-hidden": "true" });
      for (const v of ys) {
        root.appendChild(svg("line", { class: "grid", x1: m.l, x2: W - m.r, y1: y(v), y2: y(v) }));
        root.appendChild(svg("text", { class: "axis", x: m.l - 8, y: y(v) + 4, "text-anchor": "end" },
          opts.format ? opts.format(v) : String(v)));
      }
      const names = scanLabels(opts.points);
      const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - m.l - m.r) / (names[0].length * 7 + 18)))));
      names.forEach((label, i) => {
        if (i % every === 0 || i === n - 1) {
          root.appendChild(svg("text", { class: "axis", x: x(i), y: H - 9, "text-anchor": "middle" }, label));
        }
      });
      for (const mk of opts.markers || []) {
        const mx = (x(mk.index - 1) + x(mk.index)) / 2;
        root.appendChild(svg("g", { class: "marker" },
          svg("line", { x1: mx, x2: mx, y1: m.t - 6, y2: H - m.b }),
          svg("rect", { x: mx - 7, y: m.t - 18, width: 14, height: 14, rx: 3 }),
          svg("text", { x: mx, y: m.t - 7.5, "text-anchor": "middle" }, String(mk.n))));
      }
      const ends = [];
      for (const s of opts.series) {
        let d = "";
        let pen = false;
        s.values.forEach((v, i) => {
          if (v === null) { pen = false; return; }
          d += (pen ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1);
          pen = true;
        });
        root.appendChild(svg("path", { class: "line " + s.cls, d: d }));
        s.values.forEach((v, i) => {
          if (v !== null) root.appendChild(svg("circle", { class: "dot " + s.cls, cx: x(i), cy: y(v), r: 3.5 }));
        });
        const last = s.values.length - 1;
        if (opts.series.length > 1 && s.values[last] !== null) ends.push({ s: s, y: y(s.values[last]) });
      }
      // end labels, nudged apart so they never overlap (a line apart, kept inside the
      // plot), with a short leader to the line's end when a label had to move
      const GAP = 15;
      ends.sort((a, b) => a.y - b.y);
      for (const e of ends) e.at = e.y;
      for (let i = 1; i < ends.length; i++) ends[i].y = Math.max(ends[i].y, ends[i - 1].y + GAP);
      const floor = H - m.b;
      if (ends.length && ends[ends.length - 1].y > floor) {
        ends[ends.length - 1].y = floor;
        for (let i = ends.length - 2; i >= 0; i--) ends[i].y = Math.min(ends[i].y, ends[i + 1].y - GAP);
      }
      for (const e of ends) {
        if (Math.abs(e.y - e.at) > 2) {
          root.appendChild(svg("path", { class: "leader", d: "M" + (W - m.r + 4) + " " + e.at.toFixed(1) + "L" +
            (W - m.r + 8) + " " + e.y.toFixed(1) }));
        }
        root.appendChild(svg("text", { class: "end-label", x: W - m.r + 10, y: e.y + 4 }, e.s.label));
      }
      const cross = svg("line", { class: "cross off", x1: 0, x2: 0, y1: m.t, y2: H - m.b });
      root.appendChild(cross);
      const show = (i) => {
        if (i < 0) { cross.classList.add("off"); tip.hidden = true; return; }
        cross.setAttribute("x1", x(i));
        cross.setAttribute("x2", x(i));
        cross.classList.remove("off");
        const p = opts.points[i];
        const mk = (opts.markers || []).find((k) => k.index === i);
        tip.replaceChildren(h("div", { class: "t" }, fmtDate(p.at) + " · " + p.name),
          opts.series.map((s) => h("div", { class: "row" }, h("span", { class: "key " + s.cls }), s.label,
            h("b", null, s.values[i] === null ? "–" : opts.format ? opts.format(s.values[i]) : String(s.values[i])))),
          mk ? h("div", { class: "note" }, mk.notes.join(" · ")) : null);
        tip.hidden = false;
        const left = Math.min(Math.max(x(i) + 12, 0), W - 200);
        tip.style.left = (x(i) + 220 > W ? x(i) - 212 : left) + "px";
        tip.style.top = m.t + "px";
      };
      let at = -1;
      root.addEventListener("mousemove", (e) => {
        const r = root.getBoundingClientRect();
        const px = e.clientX - r.left;
        let best = 0;
        for (let i = 1; i < n; i++) if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i;
        at = best;
        show(at);
      });
      root.addEventListener("mouseleave", () => show(-1));
      box.onkeydown = (e) => {
        if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
          e.preventDefault();
          at = at < 0 ? n - 1 : Math.min(n - 1, Math.max(0, at + (e.key === "ArrowRight" ? 1 : -1)));
          show(at);
        } else if (e.key === "Escape") { at = -1; show(-1); }
      };
      box.onblur = () => show(-1);
      box.replaceChildren(root, tip);
    };
    box.redraw = draw;
    requestAnimationFrame(draw);
    return box;
  }

  // axis labels for scans: the date, or date and time when two scans share a day
  function scanLabels(points) {
    const days = points.map((p) => fmtDate(p.at));
    if (new Set(days).size === days.length) return days.map((d) => (d.length === 10 ? d.slice(2) : d));
    return points.map((p) => { const t = fmtTime(p.at); return t.length > 16 ? t.slice(5, 16) : t; });
  }

  function legend(series) {
    return h("div", { class: "legend", "aria-hidden": "true" },
      series.map((s) => h("span", null, h("span", { class: "key " + s.cls }), s.label)));
  }

  function heat(score) {
    if (score === null || score === undefined) return "h-none";
    if (score === 0) return "h0";
    return score <= 10 ? "h1" : score <= 25 ? "h2" : score <= 45 ? "h3" : score <= 70 ? "h4" : "h5";
  }

  function exposurePct(p) {
    if (p.exposed === null || p.exposed === undefined) return null;
    if (p.exposed === 0) return 0;
    return p.users ? Math.round((1000 * p.exposed) / p.users) / 10 : null;
  }

  // ---- trend ------------------------------------------------------------------------

  function viewTrend() {
    const T = VM.trend;
    if (!T) {
      return h("div", null, pageHead("Trend", "Trend across scans"), h("div", { class: "empty" },
        "No history in this file. Keep each run's ", cmd("-f json"), " report in a directory and build with ",
        cmd("ad-doctor view snap.json --history reports/"), "."));
    }
    const pts = T.points;
    const markers = T.markers.map((m, k) => Object.assign({ n: k + 1 }, m));
    const first = pts[0];
    const last = pts[pts.length - 1];
    const sevSeries = SEVERITIES.map((s) => ({ label: SEVERITY_LABEL[s], cls: s, values: pts.map((p) => p.counts[s]) }));
    const expSeries = [{ label: "Exposure", cls: "exposure", values: pts.map(exposurePct) }];
    const fmtPct = (v) => (Math.round(v * 10) / 10) + "%";
    const firstExp = exposurePct(first);
    const lastExp = exposurePct(last);
    const stats = h("div", { class: "stats" },
      stat(String(last.score) + " (" + last.grade + ")", "risk score", first.score + " (" + first.grade + ")"),
      stat(lastExp === null ? "–" : fmtPct(lastExp), "users with a path to tier 0", firstExp === null ? "–" : fmtPct(firstExp)),
      stat(String(last.counts.high), "high findings", String(first.counts.high)),
      stat(String(last.objects), "objects in findings", String(first.objects)));
    const charts = [
      lineChart({ label: "Findings by severity per scan", points: pts, series: sevSeries, markers: markers }),
      lineChart({ label: "Share of enabled users with a path to tier 0 per scan", points: pts, series: expSeries,
        markers: markers, format: fmtPct, min: 10, height: 180 }),
    ];
    state.charts = charts;
    const markerList = markers.length ? h("ol", { class: "marker-list" }, markers.map((m) =>
      h("li", null, h("span", { class: "badge" }, String(m.n)),
        h("span", null, h("b", null, fmtDate(pts[m.index].at)), " ", m.notes.join(" · "))))) : null;

    const heatmap = h("div", { class: "table-wrap" }, h("table", { class: "heat" },
      h("thead", null, h("tr", null, h("th", { scope: "col" }, "Category"),
        scanLabels(pts).map((label, i) => h("th", { scope: "col", class: "num", title: pts[i].name +
          (markers.some((m) => m.index === i) ? " (tool changed)" : "") },
          label, markers.some((m) => m.index === i) ? h("span", { class: "tick" }, "*") : null)))),
      h("tbody", null, T.categories.map((c) => h("tr", null, h("th", { scope: "row" }, c),
        pts.map((p) => {
          const v = p.categories[c];
          return h("td", { class: "num " + heat(v) }, v === undefined ? "–" : String(v));
        }))))));

    const table = h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Scan", "Report", "ad-doctor", "Score", "High", "Medium", "Low", "Info", "Exposure"].map((x, i) =>
        h("th", { class: i >= 3 ? "num" : "" }, x)))),
      h("tbody", null, pts.slice().reverse().map((p) => {
        const e = exposurePct(p);
        return h("tr", null,
          h("td", { class: "nowrap" }, fmtDate(p.at)), h("td", null, h("span", { class: "mono" }, p.name)),
          h("td", { class: "nowrap" }, p.version + (p.checks ? " · " + p.checks + " checks" : "")),
          h("td", { class: "num" }, p.score + " (" + p.grade + ")"),
          SEVERITIES.map((s) => h("td", { class: "num" }, String(p.counts[s]))),
          h("td", { class: "num" }, e === null ? "–" : fmtPct(e) + (p.users ? " (" + p.exposed + "/" + p.users + ")" : "")));
      }))));

    return h("div", { class: "stack" },
      pageHead("Trend", "Trend across " + plural(pts.length, "scan"),
        fmtDate(first.at) + " to " + fmtDate(last.at) + ". Numbers are after acceptances, as each report wrote them."),
      stats,
      h("div", { class: "panel" }, sectionTitle("Findings by severity", legend(sevSeries)), charts[0]),
      h("div", { class: "panel" }, sectionTitle("Tier-0 exposure",
        h("span", { class: "small muted" }, "share of enabled users outside tier 0 with a control path to it")), charts[1]),
      markerList ? h("div", { class: "panel" }, sectionTitle("Tool changes",
        h("span", { class: "small muted" }, "a step here can be the scanner, not the domain")), markerList) : null,
      h("div", null, sectionTitle("Risk by category", h("span", { class: "small muted" }, "0 to 100 per category; * the tool changed")), heatmap),
      h("div", null, sectionTitle("Scans"), table));
  }

  // ---- blast radius -----------------------------------------------------------------

  let GRAPH = null; // CORE.graph(VM.graph), built on first use

  function graphOf() {
    if (!GRAPH && VM.graph) GRAPH = CORE.graph(VM.graph);
    return GRAPH;
  }

  // the subjects the typeahead offers: every account (full graph) or the precomputed ones
  function subjects() {
    if (!VM.blast) return [];
    if (VM.blast.mode === "full") {
      return graphOf().accounts.map((a, index) => ({
        index: index, name: a.sam, sid: a.sid, kind: a.flags & 16 ? "gmsa" : a.flags & 8 ? "computer" : "user",
        disabled: !(a.flags & 4), account: a,
      }));
    }
    return VM.blast.subjects.map((s, index) => ({ index: index, name: s.name, sid: s.sid || "", kind: s.kind,
      holder: s.holder, record: s }));
  }

  // "@N" is the Nth subject (what the page writes into the URL: no name ever goes in the
  // address bar or the history); a name or SID also works, for a link typed by hand.
  // "@" cannot occur in a sAMAccountName.
  function findSubject(list, query) {
    const q = String(query || "").toLowerCase();
    if (/^@\d+$/.test(q)) return list[Number(q.slice(1))] || null;
    return q ? list.find((s) => s.name.toLowerCase() === q || s.sid.toLowerCase() === q) || null : null;
  }

  function resultOf(subject) {
    if (subject.record) return subject.record;
    if (!subject.cache) {
      const G = graphOf();
      subject.cache = CORE.subject(G, CORE.blastRadius(G, subject.account), Infinity);
    }
    return subject.cache;
  }

  // an accessible combobox: type to filter, arrows to move, Enter to pick
  function typeahead(list, value, label, onPick, missing) {
    const id = "ta-" + label.replace(/\W+/g, "");
    const input = h("input", { type: "text", role: "combobox", "aria-expanded": "false", "aria-controls": id,
      "aria-autocomplete": "list", "aria-label": label, placeholder: "sAMAccountName or SID", spellcheck: "false",
      autocomplete: "off" });
    input.value = value || "";
    const box = h("ul", { id: id, role: "listbox", class: "ta-list", hidden: true, "aria-label": label });
    let shown = [];
    let active = -1;
    const close = () => { box.hidden = true; input.setAttribute("aria-expanded", "false"); input.removeAttribute("aria-activedescendant"); };
    const mark = () => {
      Array.from(box.children).forEach((li, i) => li.setAttribute("aria-selected", String(i === active)));
      if (active >= 0) { input.setAttribute("aria-activedescendant", id + "-" + active); box.children[active].scrollIntoView({ block: "nearest" }); }
    };
    const fill = () => {
      const q = input.value.trim().toLowerCase();
      const starts = [];
      const has = [];
      for (const s of list) {
        const n = s.name.toLowerCase();
        if (!q || n.startsWith(q) || s.sid.toLowerCase() === q) starts.push(s);
        else if (n.includes(q)) has.push(s);
        if (starts.length >= 12) break;
      }
      shown = starts.concat(has).slice(0, 12);
      active = shown.length ? 0 : -1;
      box.replaceChildren(...shown.map((s, i) => {
        const li = h("li", { role: "option", id: id + "-" + i, "aria-selected": "false" },
          h("span", { class: "n" }, s.name),
          h("span", { class: "k" }, (KIND_LABEL[s.kind] || s.kind) + (s.holder ? " · holds a path" : "") + (s.disabled ? " · disabled" : "")));
        li.addEventListener("mousedown", (e) => { e.preventDefault(); pick(s); });
        return li;
      }));
      if (!shown.length) box.appendChild(h("li", { class: "none" }, withFlags(missing || "No match")));
      box.hidden = false;
      input.setAttribute("aria-expanded", "true");
      mark();
    };
    const pick = (s) => { input.value = s.name; close(); onPick(s); };
    input.addEventListener("input", fill);
    input.addEventListener("focus", () => { if (!input.value) fill(); });
    input.addEventListener("blur", () => setTimeout(close, 120));
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        if (box.hidden) fill();
        if (shown.length) active = (active + (e.key === "ArrowDown" ? 1 : shown.length - 1)) % shown.length;
        mark();
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (!box.hidden && active >= 0) pick(shown[active]);
        else { const s = findSubject(list, input.value.trim()); if (s) pick(s); }
      } else if (e.key === "Escape") close();
    });
    return h("div", { class: "ta" }, input, box);
  }

  function pathLine(rec) {
    return h("div", { class: "pline" }, h("span", { class: "pn start" }, rec.start),
      rec.steps.map(([how, name, , t0]) => [h("span", { class: "how" }, " -[" + how + "]-> "),
        h("span", { class: "pn" + (t0 ? " t0" : "") }, name)]));
  }

  function kindWord(k) {
    const label = KIND_LABEL[k] || k;
    return /^[A-Z][a-z]/.test(label) ? label.toLowerCase() : label; // gMSA, GPO, CA stay
  }

  function blastPanel(subject) {
    const r = resultOf(subject);
    const head = h("div", { class: "verdict " + (r.reaches ? "bad" : "good") },
      h("div", { class: "v" }, r.reaches ? "Reaches tier 0" : "Does not reach tier 0"),
      h("div", { class: "who" }, h("b", null, r.name), " · " + (KIND_LABEL[r.kind] || r.kind) +
        (r.sid ? " · " : ""), r.sid ? h("span", { class: "mono" }, r.sid) : null),
      h("div", { class: "facts" }, h("span", null, "controls ", h("b", null, num(r.count)), " objects"),
        Object.keys(r.kinds).sort().map((k) => h("span", null, h("b", null, num(r.kinds[k])), " " +
          kindWord(k) + (r.kinds[k] === 1 ? "" : "s")))));
    const out = [head];
    if (r.tier0.length) {
      const limit = 8;
      const list = h("div", { class: "plines" });
      const drawPaths = (n) => list.replaceChildren(...r.tier0.slice(0, n).map(pathLine));
      drawPaths(limit);
      const more = r.tier0.length > limit ? h("button", { type: "button", class: "more" }, "Show all " + r.tier0.length) : null;
      if (more) more.addEventListener("click", () => { drawPaths(r.tier0.length); more.remove(); });
      out.push(h("section", null, h("h3", null, "Paths into tier 0" + (r.tier0_count > r.tier0.length ?
        " (first " + r.tier0.length + " of " + r.tier0_count + ")" : "")), list, more));
    }
    const groups = new Map();
    for (const row of r.objects) {
      if (!groups.has(row[1])) groups.set(row[1], []);
      groups.get(row[1]).push(row);
    }
    for (const [kind, rows] of groups) {
      const total = r.kinds[kind] || rows.length;
      const body = h("tbody");
      let shown = 0;
      const more = h("button", { type: "button", class: "more" });
      const draw = (n) => {
        const next = rows.slice(shown, shown + n);
        for (const [name, , t0, how, parent] of next) {
          body.appendChild(h("tr", null,
            h("td", null, h("span", { class: "mono" }, name), t0 ? h("span", { class: "pill high t0pill" }, "tier 0") : null),
            h("td", { class: "via" }, h("span", { class: "mono" }, parent), h("span", { class: "how" }, " -[" + how + "]->"))));
        }
        shown += next.length;
        const left = rows.length - shown;
        more.hidden = left <= 0;
        more.textContent = "Show " + Math.min(left, 100) + " more of " + left;
      };
      more.addEventListener("click", () => draw(100));
      draw(12);
      out.push(h("section", null,
        h("h3", null, (KIND_LABEL[kind] || kind) + " · " + total.toLocaleString("en") +
          (rows.length < total ? " (first " + rows.length + " kept in this file)" : "")),
        h("div", { class: "table-wrap" }, h("table", { class: "blast-table" },
          h("thead", null, h("tr", null, h("th", null, "Object"), h("th", null, "Via"))), body)), more));
    }
    if (!r.count) out.push(h("div", { class: "empty" }, "Controls nothing beyond itself."));
    return h("div", { class: "panel blast" }, out);
  }

  function viewBlast(r) {
    const B = VM.blast;
    if (!B) {
      const verb = (VM.meta.command || "").split(" ")[1];
      const why = VM.meta.source === "report" ? ["It was built from a JSON report, which holds no graph."]
        : verb && verb !== "view" ? ["Pages from ", cmd("ad-doctor " + verb + " -f html"), " carry no control graph."]
          : ["It was built with ", cmd("--graph none"), "."];
      return h("div", null, pageHead("Blast radius", "Blast radius"), h("div", { class: "empty" },
        "No control graph in this file. ", why, " Build the page from a snapshot with ",
        cmd("ad-doctor view snap.json"), " to look up any account."));
    }
    const list = subjects();
    const a = findSubject(list, r.params.get("a"));
    const b = findSubject(list, r.params.get("b"));
    const compare = r.params.has("b");
    const go = (x, y, both) => { location.hash = blastHash(x, y, both); };
    const missing = B.mode === "paths" ? "Not precomputed in this file. Rebuild with --blast-radius-for NAME or --graph full."
      : "No account by that name or SID in this file.";
    const left = typeahead(list, a ? a.name : "", "Account", (s) => go(s, b, compare), missing);
    const toggle = h("button", { type: "button", class: "btn", "aria-pressed": String(compare) },
      compare ? "Single account" : "Compare two accounts");
    toggle.addEventListener("click", () => { location.hash = blastHash(a, null, !compare); });
    const right = compare ? typeahead(list, b ? b.name : "", "Second account", (s) => go(a, s, true), missing) : null;
    const holders = list.filter((s) => s.holder).length;
    const named = list.length - holders;
    const note = B.mode === "paths"
      ? h("div", { class: "banner" }, h("div", null, h("strong", null, "Large-domain mode. "),
        "This file holds the blast radius of " + plural(holders, "principal") + " that hold a right on a control path" +
        (named ? " and of " + plural(named, "account") + " named with " : ""), named ? cmd("--blast-radius-for") : null,
        ", up to " + num(B.limits.per_kind) + " objects per kind each. For any other account, rebuild with ",
        cmd("--blast-radius-for NAME"), " or ", cmd("--graph full"), "."))
      : null;
    const pickers = h("div", { class: "pickers" + (compare ? " two" : "") }, left, right, toggle);
    const results = [];
    if (compare) {
      results.push(h("div", { class: "compare" }, a ? blastPanel(a) : pickHint("first"), b ? blastPanel(b) : pickHint("second")));
      if (a && b) results.unshift(compareSummary(a, b));
    } else if (a) {
      results.push(blastPanel(a));
    } else if (!list.length) {
      results.push(h("div", { class: "empty" }, B.mode === "full"
        ? "No account in this snapshot has a SID to search from."
        : "No principal holds a right on a control path, so nothing was precomputed."));
    } else {
      results.push(h("div", { class: "empty" }, B.mode === "full"
        ? "Type an account name or SID to see everything it controls through its rights, its groups and theirs, " +
          "and whether that reaches tier 0. " + plural(list.length, "account") + " in this file" +
          (VM.paths ? "." : "; none of them has a control path to tier 0.")
        : "Pick one of the principals above."));
    }
    const picks = B.mode === "paths" ? list : !a ? quickPicks(list).slice(0, 14) : [];
    const suggestions = picks.length ? h("div", { class: "chips" },
      h("span", { class: "small muted" }, B.mode === "paths" ? "Precomputed:" : "Try:"),
      picks.map((s) => h("a", { class: "chip", href: blastHash(s, b, compare) }, s.name))) : null;
    return h("div", { class: "stack" },
      pageHead("Blast radius", "Blast radius",
        "What one account controls, computed " + (B.mode === "full" ? "in this tab from the embedded control graph" :
          "when the file was built") + ". The same search as ad-doctor blast-radius."),
      note, pickers, suggestions, results);
  }

  // #blast?a=@I&b=@J (indexes into subjects()); b is present (maybe empty) in compare mode
  function blastHash(a, b, compare) {
    const q = new URLSearchParams();
    if (a) q.set("a", "@" + a.index);
    if (compare) q.set("b", b ? "@" + b.index : "");
    const s = q.toString();
    return "#blast" + (s ? "?" + s : "");
  }

  // accounts worth a first look: the ones that start a control path, then the rest
  function quickPicks(list) {
    const P = VM.paths;
    const starts = new Set(P ? P.list.map((p) => P.nodes[p.start].name.toLowerCase()) : []);
    return list.filter((s) => starts.has(s.name.toLowerCase())).concat(list.filter((s) => !s.disabled).slice(0, 6));
  }

  function pickHint(which) {
    return h("div", { class: "empty" }, "Pick the " + which + " account.");
  }

  function compareSummary(a, b) {
    const ra = resultOf(a);
    const rb = resultOf(b);
    let common = null;
    if (VM.blast.mode === "full") {
      const set = new Set(ra.objects.map((o) => o[5]));
      common = rb.objects.reduce((n, o) => n + (set.has(o[5]) ? 1 : 0), 0);
    }
    const verdict = ra.reaches && rb.reaches ? "Both reach tier 0" : ra.reaches ? "Only " + ra.name + " reaches tier 0"
      : rb.reaches ? "Only " + rb.name + " reaches tier 0" : "Neither reaches tier 0";
    return h("div", { class: "stats" },
      stat(verdict, "verdict"),
      stat(ra.count.toLocaleString("en"), ra.name + " controls"),
      stat(rb.count.toLocaleString("en"), rb.name + " controls"),
      stat(common === null ? "–" : common.toLocaleString("en"), "objects both control"));
  }

  // ---- acceptance draft ---------------------------------------------------------------

  function todayPlus(days) {
    const d = new Date(Date.now() + days * 86400000);
    const p = (n) => String(n).padStart(2, "0");
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
  }

  function addDraft(f) {
    state.draft.set(f.id, {
      check: f.id, title: f.title, all: false, reason: "", owner: "", ticket: "", expires: todayPlus(90),
      objects: f.objects.map((o, i) => ({ key: f.keys ? f.keys[i] : o, text: o, on: true })),
    });
  }

  function draftEntry(e) {
    return {
      check: e.check, all: e.all, objects: e.all ? [] : e.objects.filter((o) => o.on).map((o) => o.key),
      reason: e.reason, expires: e.expires, owner: e.owner, ticket: e.ticket,
    };
  }

  function draftButton(f) {
    const btn = h("button", { type: "button", class: "btn" });
    const sync = () => { btn.textContent = state.draft.has(f.id) ? "In the draft · open Policy" : "Add to acceptance draft"; };
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      if (state.draft.has(f.id)) { location.hash = "#accepted"; return; }
      addDraft(f);
      sync();
      refreshNav();
      announce(f.id + " added to the acceptance draft");
    });
    sync();
    return btn;
  }

  function field(label, input, wide) {
    return h("label", { class: "field" + (wide ? " wide" : "") }, h("span", null, label), input);
  }

  function draftCard(e, changed) {
    const input = (type, key, attrs) => {
      const el = h(type === "textarea" ? "textarea" : "input", Object.assign(type === "textarea" ? { rows: 2 } : { type: type }, attrs || {}));
      el.value = e[key];
      el.addEventListener("input", () => { e[key] = el.value; changed(); });
      return el;
    };
    const all = h("input", { type: "checkbox" });
    all.checked = e.all;
    const shownObjects = e.objects.slice(0, 200);
    const objs = h("div", { class: "draft-objs" }, shownObjects.map((o) => {
      const box = h("input", { type: "checkbox" });
      box.checked = o.on;
      box.addEventListener("change", () => { o.on = box.checked; changed(); });
      return h("label", { class: "check", title: o.text }, box, h("span", { class: "mono" }, o.text));
    }), e.objects.length > shownObjects.length ? h("p", { class: "small muted" },
      "+" + (e.objects.length - shownObjects.length) + " more objects, included") : null);
    objs.hidden = e.all;
    all.addEventListener("change", () => { e.all = all.checked; objs.hidden = e.all; changed(); });
    const remove = h("button", { type: "button", class: "btn ghost" }, "Remove");
    remove.addEventListener("click", () => { state.draft.delete(e.check); refreshNav(); route(); });
    return h("div", { class: "panel draft" },
      h("div", { class: "draft-head" }, h("div", null, h("span", { class: "mono" }, e.check), " ", h("b", null, e.title)), remove),
      h("label", { class: "check" }, all, h("span", null, "Accept the whole check (every object, now and later)")),
      objs,
      h("div", { class: "fields" },
        field("Reason (required)", input("textarea", "reason", { placeholder: "why the risk is accepted" }), true),
        field("Owner", input("text", "owner", { autocomplete: "off" })),
        field("Ticket", input("text", "ticket", { autocomplete: "off" })),
        field("Expires", input("date", "expires"))));
  }

  function draftSection() {
    const entries = Array.from(state.draft.values());
    const head = sectionTitle("Acceptance draft", h("span", { class: "small muted" },
      entries.length ? plural(entries.length, "entry", "entries") + " · lives in this tab only" : "lives in this tab only"));
    if (!entries.length) {
      return h("div", null, head, h("div", { class: "empty" }, "Empty. Open a finding and choose ",
        h("b", null, "Add to acceptance draft"), "; entries collect here and download as accept-draft.toml for review."));
    }
    const status = h("p", { class: "small", role: "status" });
    const dl = h("button", { type: "button", class: "btn primary" }, "Download accept-draft.toml");
    const text = () => CORE.acceptDraft(entries.map(draftEntry), { domain: VM.meta.domain, date: todayPlus(0) });
    const check = () => {
      const bad = entries.map((e) => [e.check, CORE.draftProblems(draftEntry(e))]).filter((x) => x[1].length);
      dl.disabled = bad.length > 0;
      status.className = "small " + (bad.length ? "warn-text" : "ok-text");
      status.textContent = bad.length
        ? "Still needed: " + bad.map(([c, p]) => c + " (" + p.join(", ") + ")").join("; ") + "."
        : "Ready. Merge it into your accept file after review; that file stays the source of truth.";
    };
    dl.addEventListener("click", () => download("accept-draft.toml", text(), "application/toml"));
    const copy = copyButton(() => { try { return text(); } catch (err) { return ""; } }, "Copy TOML", "acceptance draft");
    copy.classList.remove("ghost");
    const cards = entries.map((e) => draftCard(e, check));
    check();
    return h("div", null, head, h("div", { class: "stack" }, cards),
      h("div", { class: "draft-foot" }, h("div", { class: "actions" }, dl, copy), status));
  }

  // ---- ad-hoc diff ------------------------------------------------------------------------

  const MAX_DROP = 64 * 1024 * 1024;

  function currentFindings() {
    return VM.findings.map((f) => ({ id: f.id, title: f.title, severity: f.severity, objects: f.objects, keys: f.keys || null }));
  }

  async function loadReport(file, msg) {
    if (!file) return;
    if (file.size > MAX_DROP) {
      msg.textContent = "That file is over 64 MB; a JSON report is far smaller.";
      msg.className = "small warn-text";
      return;
    }
    try {
      const rep = CORE.parseReport(await file.text());
      state.adhoc = { name: file.name, report: rep, diff: CORE.diffReports(rep, currentFindings()) };
      state.tab = "new";
      announce("Compared with " + file.name);
      route();
    } catch (err) {
      msg.textContent = file.name + ": " + err.message;
      msg.className = "small warn-text";
    }
  }

  function dropZone() {
    const input = h("input", { type: "file", accept: ".json,application/json", class: "sr-only", tabindex: "-1", "aria-hidden": "true" });
    const msg = h("p", { class: "small muted", role: "status" }, "Read in this tab only; nothing is stored or sent.");
    const pick = h("button", { type: "button", class: "btn" }, "Choose a report…");
    pick.addEventListener("click", () => input.click());
    input.addEventListener("change", () => loadReport(input.files[0], msg));
    const zone = h("div", { class: "drop no-print" },
      h("div", { class: "drop-text" }, h("strong", null, "Compare with another report"),
        h("div", { class: "small muted" }, "Drop a JSON report (", h("code", null, "-f json"), ") of an earlier or later run here.")),
      pick, input, msg);
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      zone.classList.remove("over");
      loadReport(e.dataTransfer && e.dataTransfer.files[0], msg);
    });
    return zone;
  }

  // ---- start ------------------------------------------------------------------------

  function fail(message) {
    const box = document.getElementById("app");
    box.removeAttribute("aria-busy");
    box.replaceChildren(h("p", null, message));
  }

  let booted = false;

  function boot() {
    frame();
    if (!booted) {
      booted = true;
      window.addEventListener("hashchange", route);
      document.addEventListener("keydown", (e) => {
        if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
          const box = document.querySelector(".search input");
          if (box) { e.preventDefault(); box.focus(); }
        }
      });
      let resizeTimer = 0;
      window.addEventListener("resize", () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
          if (state.route === "paths") route();
          if (state.route === "trend") for (const c of state.charts) c.redraw();
        }, 150);
      });
      // a file dropped anywhere but the drop zone must not replace this page
      document.addEventListener("dragover", (e) => e.preventDefault());
      document.addEventListener("drop", (e) => e.preventDefault());
    }
    route();
  }

  async function start() {
    let packed;
    try {
      META = JSON.parse(document.getElementById("adoc-meta").textContent);
      packed = base64Bytes(document.getElementById("adoc-data").textContent);
    } catch (err) {
      fail("The embedded report could not be read: the file is damaged or was edited.");
      return;
    }
    if (typeof DecompressionStream === "undefined") {
      fail("This browser cannot open the report (it lacks DecompressionStream). Use a current Chrome, Edge, Firefox or Safari.");
      return;
    }
    if (META.encrypted) {
      if (!(window.crypto && crypto.subtle)) {
        fail("This browser cannot decrypt the report (WebCrypto is unavailable). Use a current Chrome, Edge, Firefox or Safari.");
        return;
      }
      showUnlock(packed);
      return;
    }
    try {
      await decodePlain(packed);
    } catch (err) {
      fail("The embedded report could not be read: the file is damaged or was edited.");
      return;
    }
    boot();
  }

  start();
})();
