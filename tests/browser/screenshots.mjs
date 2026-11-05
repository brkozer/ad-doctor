// Screenshots of every screen of a viewer page, at desktop and phone width, light and dark.
//
//   node screenshots.mjs report.html OUTDIR [--only overview,paths] [--viewport] [--account NAME]
//
// An encrypted page is shot locked ("unlock"), then opened with the passphrase from
// AD_DOCTOR_VIEW_PASSPHRASE for the other screens. --account picks the blast-radius
// account (default: the first suggestion). Used for the README images and for reviewing
// design changes; not part of the tests.
import { chromium } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [input, outDir = "shots", ...rest] = process.argv.slice(2);
if (!input) {
  console.error("usage: node screenshots.mjs report.html OUTDIR [--only route,route] [--viewport] [--account NAME]");
  process.exit(2);
}
const flag = (name) => rest.indexOf(name);
const only = flag("--only") >= 0 ? new Set(rest[flag("--only") + 1].split(",")) : null;
const crop = flag("--viewport") >= 0; // the first screenful instead of the whole page
const account = flag("--account") >= 0 ? rest[flag("--account") + 1] : null;

async function firstPick(page) {
  await page.locator(".chips .chip").first().waitFor();
  return (await page.locator(".chips .chip").allTextContents());
}

const SHOTS = [
  ["overview", "#overview"],
  ["findings", "#findings"],
  ["finding-open", "#findings?open=AD-PATH-001"],
  ["paths", "#paths"],
  ["blast", "#blast", async (page) => {
    const name = account || (await firstPick(page))[0];
    await page.evaluate((a) => { location.hash = "#blast?a=" + encodeURIComponent(a); }, name);
    await page.locator(".verdict").waitFor();
  }],
  ["blast-compare", "#blast", async (page) => {
    const picks = await firstPick(page);
    const a = account || picks[0];
    const b = picks.find((p) => p !== a) || a;
    await page.evaluate(([x, y]) => {
      location.hash = "#blast?a=" + encodeURIComponent(x) + "&b=" + encodeURIComponent(y);
    }, [a, b]);
    await page.locator(".compare .verdict").nth(1).waitFor();
  }],
  ["changes", "#changes"],
  ["trend", "#trend"],
  ["accepted", "#accepted"],
  ["draft", "#findings?open=AD-PATH-001", async (page) => {
    await page.getByRole("button", { name: "Add to acceptance draft" }).click();
    await page.evaluate(() => { location.hash = "#accepted"; });
    // accept one path, the sync server's, and leave the others to be fixed
    for (const label of await page.locator(".draft-objs label").all()) {
      if (!/^ENTRA01\$ -\[hosts sync account\]/.test(await label.innerText())) await label.locator("input").uncheck();
    }
    await page.getByLabel("Reason (required)").fill("Sync server is tier 0 by design; isolated network, reviewed quarterly");
    await page.getByLabel("Owner", { exact: true }).fill("identity-team");
    await page.getByLabel("Ticket", { exact: true }).fill("SEC-142");
  }],
  ["about", "#about"],
  ["print", "#print"],
];
const SIZES = { desktop: { width: 1440, height: 900 }, phone: { width: 390, height: 844 } };

async function open(page, href, hash, locked) {
  await page.goto("about:blank");
  await page.goto(href + hash);
  if (locked) {
    await page.getByLabel("Passphrase", { exact: true }).fill(process.env.AD_DOCTOR_VIEW_PASSPHRASE || "");
    await page.getByRole("button", { name: "Unlock" }).click();
  }
  await page.locator("main h1").waitFor();
  if (locked && hash !== "#overview") await page.evaluate((x) => { location.hash = x; }, hash);
}

mkdirSync(outDir, { recursive: true });
const href = pathToFileURL(resolve(input)).href;
const browser = await chromium.launch();
for (const [size, viewport] of Object.entries(SIZES)) {
  for (const scheme of ["light", "dark"]) {
    const page = await browser.newPage({
      viewport, colorScheme: scheme, deviceScaleFactor: size === "phone" ? 2 : 1,
      isMobile: size === "phone", hasTouch: size === "phone",
    });
    await page.goto(href);
    const locked = (await page.locator("#passphrase").count()) > 0;
    if (locked && (!only || only.has("unlock"))) {
      const file = resolve(outDir, `unlock-${size}-${scheme}.png`);
      await page.screenshot({ path: file });
      console.log(file);
    }
    for (const [name, hash, act] of SHOTS) {
      if (only && !only.has(name)) continue;
      if (locked && !process.env.AD_DOCTOR_VIEW_PASSPHRASE) continue;
      await open(page, href, hash, locked);
      // the list is ordered broad groups first, then by length: show the longest path
      if (name === "paths" && (await page.locator(".pitem").count())) await page.locator(".pitem").last().click();
      if (act) await act(page);
      await page.waitForTimeout(200);
      const file = resolve(outDir, `${name}-${size}-${scheme}.png`);
      // the finding list is long: show the screen as a reader lands on it
      const full = !crop && !name.startsWith("finding");
      if (!full) await page.evaluate(() => window.scrollBy(0, -16));
      await page.screenshot({ path: file, fullPage: full });
      console.log(file);
    }
    await page.close();
  }
}
await browser.close();
