// The viewer in a real browser: every screen renders, nothing leaves the page, and
// directory names that are XSS payloads stay text.
import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const BUILD = resolve(dirname(fileURLToPath(import.meta.url)), "build");
const ROOT = resolve(BUILD, "../../..");
const ROUTES = ["overview", "findings", "paths", "blast", "changes", "whatif", "trend", "accepted", "about", "print"];
const PAGES = ["xss", "full", "paths"];

function url(name) {
  const file = resolve(BUILD, name + ".html");
  if (!existsSync(file)) throw new Error(`${file} is missing: run npm run fixtures first`);
  return pathToFileURL(file).href;
}

// Collects every request and every console error or uncaught exception on the page.
function watch(page) {
  const seen = { requests: [], errors: [] };
  page.on("request", (r) => seen.requests.push(r.url()));
  page.on("console", (m) => { if (m.type() === "error") seen.errors.push(m.text()); });
  page.on("pageerror", (e) => seen.errors.push(String(e)));
  return seen;
}

function external(requests) {
  return requests.filter((u) => !/^(file|data|blob):/.test(u));
}

for (const name of PAGES) {
  test(`${name}: every screen renders, makes no request and runs no injected script`, async ({ page }) => {
    const seen = watch(page);
    await page.goto(url(name));
    await expect(page.locator(".nav a")).toHaveCount(9);
    for (const route of ROUTES) {
      await page.evaluate((r) => { location.hash = "#" + r; }, route);
      await expect(page.locator("main h1")).toBeVisible();
      await expect(page.locator("main")).not.toBeEmpty();
    }

    // open every finding: objects, fingerprints, fix lines and docs all render
    await page.evaluate(() => { location.hash = "#findings"; });
    const rows = page.locator(".frow");
    const n = await rows.count();
    expect(n).toBeGreaterThan(0);
    for (let i = 0; i < n; i++) await rows.nth(i).click();
    await expect(page.locator(".fdetail")).toHaveCount(n);

    // every path, and every node on the selected one
    await page.evaluate(() => { location.hash = "#paths"; });
    const paths = page.locator(".pitem");
    for (let i = 0; i < (await paths.count()); i++) {
      await paths.nth(i).click();
      const nodes = page.locator(".chain-svg .node");
      for (let k = 0; k < (await nodes.count()); k++) await nodes.nth(k).click();
    }
    for (const tab of await page.locator("#main .tab").all()) await tab.click();

    // every edge filter off and on again
    await page.evaluate(() => { location.hash = "#paths"; });
    for (const box of await page.locator(".edge-filter input").all()) {
      await box.uncheck();
      await page.locator(".edge-filter input:focus").check();
    }

    // the blast radius of every suggested account, alone and compared with the first
    await page.evaluate(() => { location.hash = "#blast"; });
    const picks = await page.locator(".chips .chip").allTextContents();
    expect(picks.length).toBeGreaterThan(0);
    for (const name of picks) {
      await page.evaluate((a) => { location.hash = "#blast?a=" + encodeURIComponent(a); }, name);
      await expect(page.locator(".verdict")).toHaveCount(1);
    }
    await page.evaluate(([a, b]) => { location.hash = "#blast?a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b); }, [picks[0], picks[picks.length - 1]]);
    await expect(page.locator(".verdict")).toHaveCount(2);
    for (const more of await page.locator(".blast .more:visible").all()) await more.click();

    expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
    expect(await page.locator("img, iframe, object, embed, script[src], link[rel=stylesheet]").count()).toBe(0);
    expect(await page.locator("script").count()).toBe(3);
    expect(external(seen.requests)).toEqual([]);
    expect(seen.errors).toEqual([]);
  });
}

test("hostile names are shown as text, everywhere", async ({ page }) => {
  await page.goto(url("xss") + "#findings?q=onerror");
  for (const row of await page.locator(".frow").all()) await row.click();
  const payload = '<img src=x onerror="window.__pwned=1">';
  const shown = await page.locator(".obj .o").allTextContents();
  expect(shown).toContain(payload); // the AS-REP finding lists it as an account name
  expect(shown.some((t) => t.startsWith(payload + " (enroll"))).toBe(true); // and ESC1 as a template
  await expect(page).toHaveTitle("<svg onload=window.__pwned=6>.test · ad-doctor");
  await page.evaluate(() => { location.hash = "#paths"; });
  await expect(page.locator(".chain-svg")).toBeVisible();
  // the domain in the frame, a node label in the SVG: text nodes, not elements
  expect(await page.locator("svg svg, main svg foreignObject, main svg script").count()).toBe(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

test("the self-check proves the page cannot make requests", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("full") + "#about");
  await page.getByRole("button", { name: "Run self-check" }).click();
  await expect(page.getByText("Network requests are blocked")).toBeVisible();
  await expect(page.getByText("Matches the build")).toBeVisible();
  expect(external(seen.requests)).toEqual([]);
  // the refused fetch is the only thing in the console, and Chromium names the CSP for it
  expect(seen.errors.length).toBeGreaterThan(0);
  for (const e of seen.errors) expect(e).toMatch(/Content Security Policy/);
});

test("filters live in the URL and survive a reload", async ({ page }) => {
  await page.goto(url("full") + "#findings?sev=high");
  const high = await page.locator(".frow").count();
  await page.locator(".search input").fill("eve");
  await expect(page).toHaveURL(/q=eve/);
  await page.reload();
  await expect(page.locator(".search input")).toHaveValue("eve");
  expect(await page.locator(".frow").count()).toBeLessThanOrEqual(high);
});

test("the page fits the screen without sideways scrolling", async ({ page }) => {
  await page.goto(url("full"));
  for (const route of ROUTES) {
    await page.evaluate((r) => { location.hash = "#" + r; }, route);
    await expect(page.locator("main h1")).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, route).toBeLessThanOrEqual(0);
  }
});

test("a damaged payload fails closed with a message", async ({ page }) => {
  const seen = watch(page);
  const html = readFileSync(fileURLToPath(url("full")), "utf-8");
  const tampered = html.replace(/(<script id="adoc-data" type="application\/json">)[^<]*/, "$1AAAA");
  await page.setContent(tampered, { waitUntil: "load" });
  await expect(page.locator("#app")).toContainText("could not be read");
  expect(external(seen.requests)).toEqual([]);
});

// ---- phase 2: encryption, blast radius, trend, drafts, ad-hoc diff, edge filters ----------

const PASSPHRASE = "fixture-only passphrase 7x"; // tests/viewer_fixtures.py, a test value

test("an encrypted file opens with the passphrase and only with it", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("sealed"));
  await expect(page.locator("h1")).toHaveText("This report is encrypted");
  await expect(page).toHaveTitle("Encrypted report · ad-doctor");
  // before unlock: the header only, and the ciphertext digest checks out
  await expect(page.getByText("matches the hash recorded when the file was written")).toBeVisible();
  expect(await page.locator("body").innerText()).not.toContain("lab.test");
  const field = page.getByLabel("Passphrase", { exact: true });
  const unlock = page.getByRole("button", { name: "Unlock" });
  await unlock.click(); // nothing typed: say so, and put the cursor back
  await expect(page.locator("#unlock-status")).toHaveText("Enter the passphrase.");
  await expect(field).toBeFocused();
  await field.fill(PASSPHRASE + "!");
  await unlock.click();
  // the file is intact, so a failure can only be the passphrase
  await expect(page.locator("#unlock-status")).toHaveText("That passphrase does not open this file.");
  await expect(field).toBeFocused();
  await field.fill("");
  await unlock.click();
  await expect(page.locator("#unlock-status")).toHaveText("Enter the passphrase.");
  await expect(field).toBeFocused();
  await field.fill(PASSPHRASE);
  await field.press("Enter");
  await expect(page.locator(".side-domain .value")).toHaveText("lab.test");
  await expect(page.locator(".nav a")).toHaveCount(9);
  await page.evaluate(() => { location.hash = "#about"; });
  await expect(page.getByText("Authenticated: the AES-GCM tag matched")).toBeVisible();
  // Lock forgets everything: the page reloads locked, without the route in the URL
  await page.getByRole("button", { name: "Lock" }).click();
  await expect(page.locator("h1")).toHaveText("This report is encrypted");
  expect(new URL(page.url()).hash).toBe("");
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  expect(external(seen.requests)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("an edited header makes decryption fail", async ({ page }) => {
  // a file:// page like the real one (about:blank is not a secure context: no WebCrypto)
  const html = readFileSync(fileURLToPath(url("sealed")), "utf-8");
  const tampered = resolve(BUILD, "sealed-tampered-" + test.info().project.name + ".html");
  writeFileSync(tampered, html.replace(/("built_at":")\d{4}/, "$12001"));
  await page.goto(pathToFileURL(tampered).href);
  await page.getByLabel("Passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.locator("#unlock-status")).toContainText("does not open this file");
});

test("an edited size or SHA-256 in the header is never shown as authenticated", async ({ page }) => {
  // neither is GCM additional data: the page measures both and refuses an edited hash
  const html = readFileSync(fileURLToPath(url("sealed")), "utf-8");
  const tampered = resolve(BUILD, "sealed-tampered-sha-" + test.info().project.name + ".html");
  const meta = JSON.parse(html.match(/<script id="adoc-meta" type="application\/json">([^<]*)</)[1]);
  const forged = html.replace('"sha256":"' + meta.sha256 + '"', '"sha256":"' + "0".repeat(64) + '"')
    .replace('"bytes":' + meta.bytes, '"bytes":1');
  expect(forged).not.toBe(html);
  writeFileSync(tampered, forged);
  await page.goto(pathToFileURL(tampered).href);
  await expect(page.locator(".unlock-facts")).toContainText(meta.sha256); // measured, not the header's
  await expect(page.locator(".unlock-facts")).not.toContainText("0".repeat(64));
  await expect(page.locator(".unlock-facts")).toContainText("the file was changed");
  await page.getByLabel("Passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.locator("#unlock-status")).toContainText("changed after it was written, so it is not opened");
  await expect(page.locator(".side-domain")).toHaveCount(0);
});

test("Lock leaves no account name in the session history", async ({ page }) => {
  await page.goto(url("sealed"));
  await page.getByLabel("Passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.locator(".side-domain .value")).toHaveText("lab.test");
  // blast radius picks and the findings search go through the URL: indexes only
  await page.getByRole("link", { name: "Blast radius" }).click();
  await page.locator(".chips .chip").first().click();
  await expect(page.locator(".verdict")).toHaveCount(1);
  expect(decodeURIComponent(page.url())).toMatch(/#blast\?a=@\d+$/);
  await page.getByRole("link", { name: "Findings" }).click();
  await page.locator(".search input").fill("legacy");
  await page.getByRole("link", { name: "Overview" }).click();
  const visited = [];
  page.on("framenavigated", (f) => { if (f === page.mainFrame()) visited.push(f.url()); });
  await page.getByRole("button", { name: "Lock" }).click();
  await expect(page.locator("h1")).toHaveText("This report is encrypted");
  for (let i = 0; i < 4; i++) {
    await page.goBack().catch(() => null);
    visited.push(page.url());
  }
  const names = ["legacy", "eve", "svc_web", "WS9", "bob"];
  for (const u of visited) for (const n of names) expect(decodeURIComponent(u), u).not.toContain(n);
});
test("blast radius: typeahead, verdict, grouped results and compare", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("xss") + "#blast");
  const box = page.getByRole("combobox", { name: "Account", exact: true });
  await box.fill("<img");
  await expect(page.getByRole("option").first()).toContainText("<img src=x onerror");
  await box.press("Enter");
  await expect(page).toHaveURL(/#blast\?a=%40\d+$/); // an index: no name in the address bar
  await expect(page.locator(".verdict .v")).toHaveText("Reaches tier 0");
  await expect(page.locator(".pline").first()).toContainText("template");
  await expect(page.locator(".blast h3").first()).toBeVisible();
  // compare with a second account
  await page.getByRole("button", { name: "Compare two accounts" }).click();
  const second = page.getByRole("combobox", { name: "Second account" });
  await second.fill("WS");
  await second.press("ArrowDown");
  await second.press("Enter");
  await expect(page.locator(".compare .blast")).toHaveCount(2);
  await expect(page.locator(".stats")).toContainText("objects both control");
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  expect(external(seen.requests)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("trend: lines, markers where the tool changed, and a keyboard crosshair", async ({ page }) => {
  await page.goto(url("full") + "#trend");
  await expect(page.locator("main h1")).toHaveText("Trend across 4 scans");
  await expect(page.locator(".chart")).toHaveCount(2);
  await expect(page.locator(".chart").first().locator(".line")).toHaveCount(4);
  await expect(page.locator(".marker-list li")).toHaveCount(3);
  await expect(page.locator(".marker-list")).toContainText("ad-doctor 0.5.0");
  await expect(page.locator("table.heat tbody tr").first()).toBeVisible();
  const chart = page.locator(".chart").first();
  await chart.focus();
  await chart.press("ArrowLeft");
  await expect(chart.locator(".chart-tip")).toBeVisible();
  await expect(chart.locator(".chart-tip")).toContainText("this run");
  await chart.press("ArrowLeft");
  await expect(chart.locator(".chart-tip")).toContainText("2026-10.json");
});

test("acceptance draft downloads TOML for accept.py", async ({ page }) => {
  await page.goto(url("full") + "#findings?open=AD-KRB-002");
  await page.getByRole("button", { name: "Add to acceptance draft" }).click();
  await expect(page.getByRole("button", { name: "In the draft · open Policy" })).toBeVisible();
  await page.evaluate(() => { location.hash = "#accepted"; });
  const dl = page.getByRole("button", { name: "Download accept-draft.toml" });
  await expect(dl).toBeDisabled();
  await page.getByLabel("Reason (required)").fill('vendor "appliance"\nreviewed');
  await page.getByLabel("Owner", { exact: true }).fill("infra");
  // the finding has two objects; accept one of them
  await page.locator(".draft-objs label", { hasText: "legacy" }).locator("input").uncheck();
  await expect(dl).toBeEnabled();
  const [file] = await Promise.all([page.waitForEvent("download"), dl.click()]);
  expect(file.suggestedFilename()).toBe("accept-draft.toml");
  const text = readFileSync(await file.path(), "utf-8");
  expect(text).toContain('[[accept]]\ncheck = "AD-KRB-002"\nobjects = ["eve"]');
  expect(text).toContain('reason = "vendor \\"appliance\\"\\nreviewed"');
  expect(text).toMatch(/expires = \d{4}-\d{2}-\d{2}\nowner = "infra"/);
});

async function tabCounts(page) {
  return page.locator("#main .tab .c").allTextContents();
}

test("a dropped report is compared like the built-in baseline", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("full") + "#changes");
  const builtIn = await tabCounts(page);
  await page.locator(".drop input[type=file]").setInputFiles(resolve(BUILD, "old-report.json"));
  await expect(page.locator(".page-head .sub")).toContainText("Compared in this tab with old-report.json");
  expect(await tabCounts(page)).toEqual(builtIn);
  await page.getByRole("button", { name: "Back to the built-in baseline" }).click();
  await expect(page.locator(".page-head .sub")).toContainText("Baseline old.json");
  // the same through drag and drop, and a file that is not a report is refused
  const drop = async (name, body) => {
    const dt = await page.evaluateHandle(([n, b]) => {
      const t = new DataTransfer();
      t.items.add(new File([b], n, { type: "application/json" }));
      return t;
    }, [name, body]);
    await page.locator(".drop").dispatchEvent("drop", { dataTransfer: dt });
  };
  await drop("x.json", '{"tool": "something else"}');
  await expect(page.locator(".drop [role=status]")).toContainText("x.json: not an ad-doctor JSON report");
  await drop("old.json", readFileSync(resolve(BUILD, "old-report.json"), "utf-8"));
  await expect(page.locator(".page-head .sub")).toContainText("Compared in this tab with old.json");
  expect(external(seen.requests)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("edge filters hide the paths that use a kind of edge", async ({ page }) => {
  await page.goto(url("full") + "#paths");
  const adcs = page.getByRole("checkbox", { name: /^AD CS/ });
  await expect(adcs).toBeChecked();
  await adcs.uncheck();
  await expect(page).toHaveURL(/off=adcs/);
  await expect(page.locator(".plist .none")).toHaveText("No path uses only the edges shown.");
  await expect(page.getByRole("checkbox", { name: /^AD CS/ })).toBeFocused();
  await page.reload();
  await expect(page.getByRole("checkbox", { name: /^AD CS/ })).not.toBeChecked();
  await page.getByRole("link", { name: "Show all" }).click();
  await expect(page.locator(".pitem")).toHaveCount(1);
});

// ---- review fixes: phone layout, print, empty and large-domain states ---------------

test("the current section's tab is in view on a phone", async ({ page }, info) => {
  test.skip(info.project.name !== "phone", "the nav scrolls only at phone width");
  await page.goto(url("full"));
  for (const route of ["overview", "findings", "paths", "blast", "changes", "trend", "accepted", "about"]) {
    await page.evaluate((r) => { location.hash = "#" + r; }, route);
    const tab = page.locator('.nav a[aria-current="page"]');
    await expect(tab).toHaveAttribute("data-route", route);
    const box = await tab.boundingBox();
    const width = page.viewportSize().width;
    expect(box.x, route).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width, route).toBeLessThanOrEqual(width);
  }
});

test("policy tables stack into readable cards on a phone", async ({ page }, info) => {
  test.skip(info.project.name !== "phone", "cards only at phone width");
  await page.goto(url("full") + "#accepted");
  const cells = page.locator("table.cards td");
  expect(await cells.count()).toBeGreaterThan(8);
  for (const td of await cells.all()) {
    const label = await td.getAttribute("data-label");
    expect(label).toBeTruthy();
    // the value column is wide enough for words: no letter-by-letter wrapping
    const w = await td.evaluate((el) => el.clientWidth - parseFloat(getComputedStyle(el).paddingLeft));
    expect(w, label).toBeGreaterThan(200);
  }
});

test("print keeps the bars and gives findings their full width", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop", "one print layout");
  await page.goto(url("full") + "#print");
  await page.emulateMedia({ media: "print" });
  for (const sel of [".meter > span", ".scale-track > span.on", ".sev::before"]) {
    const exact = await page.evaluate((s) => {
      const [css, pseudo] = s.split("::");
      const el = document.querySelector(css);
      return el && getComputedStyle(el, pseudo ? "::" + pseudo : null).printColorAdjust;
    }, sel);
    expect(exact, sel).toBe("exact");
  }
  await page.evaluate(() => { location.hash = "#findings"; });
  await expect(page.locator(".frow").first()).toBeVisible();
  const widths = await page.locator(".frow .title").evaluateAll((els) => els.map((e) => e.getBoundingClientRect().width));
  expect(Math.min(...widths)).toBeGreaterThan(300);
  const pdf = await page.pdf({ format: "A4" });
  expect(pdf.length).toBeGreaterThan(1000);
});

test("the overview says which checks gave no answer and calls the score a minimum", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("clean"));
  const panel = page.locator(".panel").filter({ hasText: "Check coverage" });
  await expect(panel).toContainText("not evaluated");
  await expect(panel.locator("tbody tr").first()).toContainText("AD-");
  await expect(page.locator(".panel").filter({ hasText: "Risk score" })).toContainText("A minimum:");
  expect(seen.errors).toEqual([]);
});

test("a clean domain reads as good news, and says why there is no graph", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("clean") + "#findings");
  // the clean fixture holds no probe results, so it does not read as all clear
  await expect(page.locator(".empty").first()).toContainText("No findings in the checks judged:");
  await expect(page.locator(".empty.good")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Export CSV" })).toHaveCount(0);
  await page.evaluate(() => { location.hash = "#blast"; });
  await expect(page.locator(".empty")).toContainText("Pages from ad-doctor analyze -f html carry no control graph.");
  await expect(page.locator(".empty")).not.toContainText("--graph none");
  expect(seen.errors).toEqual([]);
});

test("a failed search no rule ties to a check keeps the page from reading as clean", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("minimum") + "#findings");
  await expect(page.locator(".empty").first()).toContainText("No findings in the checks judged: a failed search was not tied to a check.");
  await expect(page.locator(".empty.good")).toHaveCount(0);
  await page.evaluate(() => { location.hash = "#overview"; });
  const panel = page.locator(".panel").filter({ hasText: "Check coverage" });
  await expect(panel).toContainText("A failed search was not tied to a check");
  await expect(panel).not.toContainText("Every check that applies was judged.");
  await expect(page.locator(".empty.good")).toHaveCount(0);
  expect(seen.errors).toEqual([]);
});

test("no control path is only claimed when the check gave an answer", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("unevaluated") + "#paths");
  await expect(page.locator(".empty").last()).toContainText("Control paths were not evaluated");
  await expect(page.locator(".empty").last()).toContainText("resource-based");
  await expect(page.getByText("No principal outside tier 0 has a control path")).toHaveCount(0);
  await page.evaluate(() => { location.hash = "#overview"; });
  await expect(page.locator(".exposure .hero-num")).toHaveText("–");
  await expect(page.locator(".exposure")).toContainText("Control paths were not evaluated");
  await page.goto(url("partial") + "#paths");
  await expect(page.locator(".banner", { hasText: "Judged in part." })).toContainText("resource-based");
  expect(seen.errors).toEqual([]);
});

test("a check the baseline did not evaluate is not new", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("older") + "#changes");
  const before = page.getByRole("tab", { name: /Not evaluated before/ });
  await expect(before).toContainText("1");
  await before.click();
  await expect(page.locator("tbody")).toContainText("AD-PRIV-014");
  await page.getByRole("tab", { name: /^New/ }).click();
  await expect(page.locator(".empty").last()).toContainText("Nothing new since the baseline.");
  expect(seen.errors).toEqual([]);
});

test("declared tier 0: paths and assets say which set they belong to", async ({ page }) => {
  await page.goto(url("declared") + "#paths");
  const panel = page.locator(".panel", { hasText: "Declared tier 0 (extended targets)" });
  await expect(panel).toContainText("JUMP01$");
  await expect(panel).toContainText("Not evaluated");
  await expect(panel).toContainText("svc_other");
  const item = page.locator(".pitem", { hasText: "(declared tier 0)" });
  await expect(item).toHaveCount(1);
  await item.click();
  await expect(page.locator(".chain-head .eyebrow")).toContainText("to declared tier 0");
});

test("large-domain mode lists every precomputed principal and explains a miss", async ({ page }) => {
  await page.goto(url("paths") + "#blast");
  const chips = await page.locator(".chips .chip").count();
  await expect(page.locator(".banner")).toContainText("blast radius of " + chips + " principal");
  const box = page.getByRole("combobox", { name: "Account", exact: true });
  await box.fill("svc_web"); // in the domain, but it holds no path
  await expect(page.locator(".ta-list .none")).toHaveText(
    "Not precomputed in this file. Rebuild with --blast-radius-for NAME or --graph full.");
  // flags in the banner never break at their hyphen
  for (const el of await page.locator(".banner code.cmd .arg").all()) {
    expect(await el.evaluate((e) => getComputedStyle(e).whiteSpace)).toBe("nowrap");
  }
});

test("long object lists keep each path's start and target", async ({ page }) => {
  await page.goto(url("bench") + "#findings?open=AD-PATH-001");
  const rows = page.locator(".vlist .obj");
  await expect(rows.first()).toBeVisible();
  for (const row of (await rows.all()).slice(0, 6)) {
    const r = await row.boundingBox();
    const start = await row.locator(".o-start").boundingBox();
    const end = await row.locator(".o-end").boundingBox();
    const text = await row.locator(".o").boundingBox();
    // the target is drawn in full inside the row, and the text clears the dividers
    expect(end.width).toBeGreaterThan(20);
    expect(end.x + end.width).toBeLessThanOrEqual(text.x + text.width + 1);
    expect(start.x).toBeGreaterThanOrEqual(text.x - 1);
    expect(text.y).toBeGreaterThanOrEqual(r.y + 3);
    const full = await row.locator(".o").getAttribute("title");
    const tail = await row.locator(".o-end").textContent();
    expect(full.endsWith(" " + tail)).toBe(true);
    // the target's name is drawn in full when it is short
    expect(await row.locator(".o-end").evaluate((e) => e.scrollWidth <= e.clientWidth)).toBe(true);
    // the start is drawn in full when it is short
    expect(await row.locator(".o-start").evaluate((e) => e.scrollWidth <= e.clientWidth)).toBe(true);
  }
});

test("the risk score marker stands out of the scale, inside its ends", async ({ page }) => {
  await page.goto(url("full"));
  const [mark, track] = await page.evaluate(() => {
    const m = document.querySelector(".scale-mark");
    const r = (e) => { const b = e.getBoundingClientRect(); return [b.left, b.top, b.width, b.height]; };
    return [r(m), r(m.parentElement)];
  });
  expect(mark[3]).toBeGreaterThan(track[3]); // taller than the bar, not hidden in it
  expect(mark[0]).toBeGreaterThanOrEqual(track[0]);
  expect(mark[0] + mark[2]).toBeLessThanOrEqual(track[0] + track[2]);
});

test("what-if: the embedded plan shows steps, change IDs and fix lines", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("full") + "#whatif");
  await expect(page.locator("main h1")).toHaveText("Plan to close the paths to tier 0");
  await expect(page.locator(".wi-steps > li").first()).toBeVisible();
  await expect(page.locator(".wi-change code").first()).toHaveText(/^c:[0-9a-f]{12}$/);
  await page.locator(".wi-change summary").first().click();
  await expect(page.locator(".wi-change pre.code").first()).toContainText("-WhatIf");
  await page.goto(url("paths") + "#whatif");
  await expect(page.locator("main .empty")).toContainText("--whatif plan.json");
  expect(external(seen.requests)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("what-if: a failed check, rerouted paths and absent changes are shown as they are", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("whatif") + "#whatif");
  const main = page.locator("main");
  await expect(main.locator(".banner.high")).toContainText("This check failed");
  await expect(main.locator(".banner.high")).toContainText("closes_all: still open");
  await expect(main).toContainText("was a -> b");
  await expect(main).toContainText("a -> c -> b");
  await expect(main).toContainText("stale");
  await expect(main).toContainText("does not resolve");
  await expect(main).toContainText("alice: 9 objects (2 tier 0)");
  await expect(main).toContainText("Not rechecked");
  await expect(main).toContainText("absent");
  await expect(main).not.toContainText("cost null");
  await page.evaluate(() => { location.hash = "#about"; });
  await expect(page.locator("main")).toContainText("What-if plan");
  expect(seen.errors).toEqual([]);
});

for (const name of ["full", "xss", "whatif"]) {
  test(`what-if: ${name} does not scroll sideways`, async ({ page }) => {
    await page.goto(url(name) + "#whatif");
    await expect(page.locator("main h1")).toBeVisible();
    const width = page.viewportSize().width;
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}

// ---- what-if, live ------------------------------------------------------------------

function results(page) {
  return page.locator(".wl-results").evaluate((el) => ({
    exposed: Number(el.dataset.exposed), users: Number(el.dataset.users), holders: Number(el.dataset.holders),
    routes: el.dataset.routes === "" ? null : Number(el.dataset.routes),
    closed: Number(el.dataset.closed), rerouted: Number(el.dataset.rerouted), new: Number(el.dataset.new),
  }));
}

async function downloadPlan(page, name) {
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download plan.toml" }).click()]);
  expect(dl.suggestedFilename()).toBe("plan.toml");
  const file = resolve(BUILD, "download-" + name + "-" + test.info().project.name + "-" + test.info().retry + ".toml");
  await dl.saveAs(file);
  return file;
}

// the Python command on the snapshot the page was built from, with the page's own file
function runPlan(name, file, ...more) {
  const out = execFileSync("uv", ["run", "ad-doctor", "whatif", resolve(BUILD, name + "-snapshot.json"), "--plan", file,
    "--paths-only", "-f", "json", ...more], { cwd: ROOT, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
  return JSON.parse(out);
}

function sameNumbers(doc, page) {
  expect({ exposed: doc.after.exposed, users: doc.after.users, holders: doc.after.holders, routes: doc.after.routes,
    closed: doc.paths.closed.length, rerouted: doc.paths.rerouted.length, new: doc.paths.new.length })
    .toEqual({ exposed: page.exposed, users: page.users, holders: page.holders, routes: page.routes,
      closed: page.closed, rerouted: page.rerouted, new: page.new });
}

for (const name of ["live", "xss", "noplan"]) {
  test(`what-if: a download from ${name} gives Python the numbers the page showed`, async ({ page }) => {
    const seen = watch(page);
    await page.goto(url(name) + "#whatif");
    await expect(page.locator(".wl-results")).toBeVisible();
    if (name === "noplan") {
      await page.evaluate(() => { location.hash = "#paths"; });
      await page.locator(".wl-edges .wl-add").first().click();
      await page.evaluate(() => { location.hash = "#whatif"; });
    } else if (name === "live") {
      // one change of the plan off, so it is the selection and not the plan that is written
      await page.locator(".wl-row input:not(:disabled)").first().uncheck();
      await page.evaluate(() => { location.hash = "#paths"; });
      await page.locator(".wl-choke .wl-add").first().click();
      await page.evaluate(() => { location.hash = "#whatif"; });
    }
    await expect(page.locator(".wl-row input:checked").first()).toBeVisible();
    const shown = await results(page);
    const file = await downloadPlan(page, name);
    const text = readFileSync(file, "utf-8");
    const doc = runPlan(name, file, "--check");
    sameNumbers(doc, shown);
    expect(doc.kind).toBe("whatif");
    expect(doc.plan_status.every((s) => s.problems.every((p) => !p.includes("edited")))).toBe(true);
    const ids = new Set(doc.plan_status.map((s) => s.id));
    const want = await page.locator(".wl-row:has(input:checked)").evaluateAll((rows) => rows.map((r) => r.dataset.change));
    expect(ids).toEqual(new Set(want));
    if (name === "xss") {
      expect(text).toContain('window.__pwned=1'); // the hostile name is a string in the file
      expect(doc.plan_status.length).toBeGreaterThan(0);
    }
    expect(external(seen.requests)).toEqual([]);
    expect(seen.errors).toEqual([]);
  });
}

test("what-if: the plan can be turned off and on, numbers follow, the difference is shown", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("live") + "#whatif");
  await expect(page.locator(".wl-same")).toBeVisible();
  const before = await results(page);
  const first = page.locator(".wl-row input:not(:disabled)").first();
  await first.uncheck();
  await expect(page.locator(".wl-diff")).toContainText("Left out (1)");
  const off = await results(page);
  expect(off).not.toEqual(before);
  await first.check();
  await expect(page.locator(".wl-diff")).not.toContainText("Left out");
  await expect(page.locator(".wl-results")).toHaveAttribute("data-exposed", String(before.exposed));
  // nothing selected: nothing to download, and the numbers are the snapshot's
  await page.getByRole("button", { name: "Start from nothing" }).click();
  await expect(page.locator(".wl-row input:checked")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Download plan.toml" })).toBeDisabled();
  const nothing = await results(page);
  expect([nothing.closed, nothing.rerouted, nothing.new]).toEqual([0, 0, 0]);
  await page.getByRole("button", { name: "Back to the plan" }).click();
  await expect(page.locator(".wl-same")).toBeVisible();
  expect(await results(page)).toEqual(before);
  expect(seen.errors).toEqual([]);
});

test("what-if: a change that needs a rebuild is unavailable, says why and stays out of the file", async ({ page }) => {
  await page.goto(url("live") + "#whatif");
  const row = page.locator(".wl-row:has(.wl-unavailable)").first();
  await expect(row.locator("input")).toBeDisabled();
  await expect(row.locator("input")).not.toBeChecked();
  await expect(row.locator(".wl-unavailable")).toContainText("Unavailable here:");
  await expect(row.locator(".wl-unavailable")).toContainText("ad-doctor whatif");
  const id = await row.getAttribute("data-change");
  const text = readFileSync(await downloadPlan(page, "rebuild"), "utf-8");
  expect(text).toContain("# left out, needs the command line: " + id);
  expect(text).not.toContain('id = "' + id + '"');
});

test("what-if: changes come from the path screen's edges and chokepoints", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("live") + "#whatif");
  await page.getByRole("button", { name: "Start from nothing" }).click();
  await page.evaluate(() => { location.hash = "#paths"; });
  const add = page.locator(".wl-edges .wl-add").first();
  await expect(add).toHaveText("Add to what-if");
  await add.click();
  await expect(add).toHaveText("In what-if: remove");
  await add.click();
  await expect(add).toHaveText("Add to what-if");
  await add.click();
  await expect(page.locator(".nav a[data-route=whatif] .count")).toHaveText("1");
  const choke = page.locator(".wl-choke .wl-add");
  expect(await choke.count()).toBeGreaterThan(0);
  await choke.first().click();
  await choke.last().click(); // an edge row and a node row
  await page.evaluate(() => { location.hash = "#whatif"; });
  const added = page.locator(".wl-row:has-text('added')");
  await expect(added.first()).toBeVisible();
  await expect(added.first().locator("input")).toBeChecked();
  const count = await added.count();
  await added.first().getByRole("button", { name: /^Remove from the selection/ }).click();
  await expect(page.locator(".wl-row:has-text('added')")).toHaveCount(count - 1);
  expect(seen.errors).toEqual([]);
});

// Adds the first step of every path on the screen that is not in the selection yet.
async function addEveryStep(page, each) {
  for (const item of await page.locator(".pitem").all()) {
    await item.click();
    for (const step of await page.locator(".wl-edges .wl-add[aria-pressed=false]").all()) {
      await step.click();
      if (await each(step)) return step;
    }
  }
  return null;
}

test("what-if: a step and a chokepoint of the same change show the same state", async ({ page }) => {
  await page.goto(url("live") + "#whatif");
  await page.getByRole("button", { name: "Start from nothing" }).click();
  await page.evaluate(() => { location.hash = "#paths"; });
  const pressed = page.locator(".wl-choke .wl-add[aria-pressed=true]");
  await expect(pressed).toHaveCount(0);
  const step = await addEveryStep(page, async () => (await pressed.count()) > 0);
  expect(step).not.toBeNull(); // no chokepoint button was clicked: the step's add moved it
  await expect(pressed.first()).toHaveText("In what-if: remove");
  const count = page.locator(".nav a[data-route=whatif] .count");
  const before = Number(await count.textContent());
  await pressed.first().click();
  await expect(step).toHaveText("Add to what-if");
  await expect(step).toHaveAttribute("aria-pressed", "false");
  await expect(count).toHaveText(String(before - 1));
});

test("what-if: the keyboard stays in the list after Remove and Clear", async ({ page }) => {
  await page.goto(url("live") + "#whatif");
  await page.getByRole("button", { name: "Start from nothing" }).click();
  await page.evaluate(() => { location.hash = "#paths"; });
  await addEveryStep(page, async () => false);
  await page.evaluate(() => { location.hash = "#whatif"; });
  const remove = page.getByRole("button", { name: /^Remove from the selection/ });
  await expect(remove).toHaveCount(2);
  await remove.first().focus();
  await page.keyboard.press("Enter"); // the row after it moves up
  await expect(remove).toHaveCount(1);
  await expect(remove.first()).toBeFocused();
  await page.keyboard.press("Enter"); // the last row: the one before it, a row of the plan
  await expect(remove).toHaveCount(0);
  await expect(page.locator(".wl-list .wl-row input:not(:disabled)").last()).toBeFocused();
  for (const name of ["Back to the plan", "Start from nothing"]) {
    await page.getByRole("button", { name }).focus();
    await page.keyboard.press("Enter");
    await expect(page.locator(".wl-list")).toBeFocused();
  }
  await page.goto(url("noplan") + "#paths");
  await page.locator(".wl-edges .wl-add").first().click();
  await page.evaluate(() => { location.hash = "#whatif"; });
  await remove.first().focus();
  await page.keyboard.press("Enter"); // nothing left: the list
  await expect(page.locator("main")).toContainText("Nothing selected yet");
  await expect(page.locator(".wl-list")).toBeFocused();
  await page.evaluate(() => { location.hash = "#paths"; });
  await page.locator(".wl-edges .wl-add").first().click();
  await page.evaluate(() => { location.hash = "#whatif"; });
  await page.getByRole("button", { name: "Clear" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(".wl-list")).toBeFocused();
});

for (const name of ["noplan", "live", "xss", "redacted"]) {
  test(`what-if: ${name} lists the limits next to the numbers`, async ({ page }) => {
    await page.goto(url(name) + "#whatif");
    const limits = page.locator(".wl-results .wl-limits");
    await expect(limits).toContainText("Edges ad-doctor does not see stay: sessions");
    await expect(limits).toContainText("What an attacker already planted is not undone");
    await expect(limits).toContainText("Collect again after the changes and run: ad-doctor whatif NEW.json --plan plan.toml --check");
  });
}

test("what-if: a plan from a redacted snapshot says it does not resolve against the real one", async ({ page }) => {
  const text = "does not resolve against the real one";
  await page.goto(url("noplan") + "#whatif");
  await expect(page.locator(".wl-redacted")).toHaveCount(0);
  await page.goto(url("redacted") + "#whatif");
  await expect(page.locator(".wl-redacted")).toContainText(text);
  await page.evaluate(() => { location.hash = "#paths"; });
  await page.locator(".wl-edges .wl-add").first().click();
  await page.evaluate(() => { location.hash = "#whatif"; });
  const file = await downloadPlan(page, "redacted");
  const lines = readFileSync(file, "utf-8").split("\n");
  expect(lines[0]).toContain("changes to make in AD");
  expect(lines[1]).toMatch(/^# Note: redacted snapshot: .*does not resolve against the real one$/);
  expect(runPlan("redacted", file).kind).toBe("whatif"); // a comment: the file still loads
});

test("what-if: an empty selection can be neither downloaded nor copied", async ({ page }) => {
  await page.goto(url("noplan") + "#whatif");
  const dl = page.getByRole("button", { name: "Download plan.toml" });
  const copy = page.getByRole("button", { name: "Copy TOML" });
  await expect(dl).toBeDisabled();
  await expect(copy).toBeDisabled();
  await page.evaluate(() => { location.hash = "#paths"; });
  await page.locator(".wl-edges .wl-add").first().click();
  await page.evaluate(() => { location.hash = "#whatif"; });
  await expect(copy).toBeEnabled();
  await page.locator(".wl-row input").first().uncheck();
  await expect(copy).toBeDisabled();
});

test("what-if: a page from a whatif document keeps the goal of an all-paths plan", async ({ page }) => {
  await page.goto(url("allpaths") + "#whatif");
  const file = await downloadPlan(page, "allpaths");
  expect(readFileSync(file, "utf-8")).toContain('goal = "all-paths"');
  await expect(page.locator(".wl-results")).not.toContainText("not comparable");
  expect(runPlan("allpaths", file).goal).toBe("all-paths");
});

test("what-if: an edge no change can take out says why", async ({ page }) => {
  await page.goto(url("live") + "#paths");
  let why = await page.locator(".wl-why").count();
  for (const item of await page.locator(".pitem").all()) {
    if (why) break;
    await item.click();
    why = await page.locator(".wl-why").count();
  }
  expect(why).toBeGreaterThan(0);
  await expect(page.locator(".wl-why").first()).toContainText(/cannot be removed|unavailable here/);
});

test("what-if: starting from nothing and the screen without a graph", async ({ page }) => {
  await page.goto(url("noplan") + "#whatif");
  await expect(page.locator("main")).toContainText("Nothing selected yet");
  await expect(page.getByRole("button", { name: "Download plan.toml" })).toBeDisabled();
  await page.goto(url("whatif") + "#whatif");
  await expect(page.locator(".wl-results")).toHaveCount(0);
});

test("what-if: hostile names stay text in the selection, the paths and the file", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("xss") + "#paths");
  await page.locator(".wl-edges .wl-add").first().click();
  await page.evaluate(() => { location.hash = "#whatif"; });
  const payload = '<img src=x onerror="window.__pwned=1">';
  await expect(page.locator(".wl-row").filter({ hasText: payload }).first()).toBeVisible();
  for (const box of await page.locator(".wl-row input:not(:disabled)").all()) { await box.uncheck(); await box.check(); }
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  expect(await page.locator("img, iframe, object, embed, script[src], main svg svg").count()).toBe(0);
  expect(external(seen.requests)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("what-if: works in an encrypted file and is gone after Lock", async ({ page }) => {
  const seen = watch(page);
  await page.goto(url("sealed"));
  await page.getByLabel("Passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.locator(".nav a")).toHaveCount(9);
  await page.evaluate(() => { location.hash = "#whatif"; });
  await expect(page.locator(".wl-results")).toBeVisible();
  const box = page.locator(".wl-row input:not(:disabled)").first();
  await box.uncheck();
  await expect(page.locator(".wl-diff")).toContainText("Left out (1)");
  await box.check();
  const file = await downloadPlan(page, "sealed");
  expect(readFileSync(file, "utf-8")).toContain("[[change]]");
  await page.locator(".btn.lock").click();
  await expect(page.locator("h1")).toHaveText("This report is encrypted");
  expect(external(seen.requests)).toEqual([]);
});

for (const [name, hash] of [["live", "#whatif"], ["live", "#paths"], ["xss", "#whatif"], ["xss", "#paths"]]) {
  test(`what-if: ${name}${hash} does not scroll sideways with the controls`, async ({ page }) => {
    await page.goto(url(name) + hash);
    await expect(page.locator("main h1")).toBeVisible();
    const width = page.viewportSize().width;
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
