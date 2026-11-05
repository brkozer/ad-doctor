// Loads the viewer's core.js (the same file the page inlines) as a classic script and
// returns its CORE object, for the Node tests and for pytest through run.mjs.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

export const CORE_JS = resolve(
  dirname(fileURLToPath(import.meta.url)), "../../src/ad_doctor/viewer_assets/core.js");

let core = null;

export function loadCore() {
  // this realm, so results compare with node:assert like any other object
  if (core === null) core = vm.runInThisContext(readFileSync(CORE_JS, "utf-8") + "\nCORE;", { filename: CORE_JS });
  return core;
}
