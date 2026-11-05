// node tests/js/run.mjs FUNCTION < args.json
// Calls CORE[FUNCTION](...args) from the viewer's core.js and prints the result as JSON.
// pytest uses it to check the JavaScript's output with the Python that reads it.
import { readFileSync } from "node:fs";
import { loadCore } from "./core.mjs";

const name = process.argv[2];
const CORE = loadCore();
if (typeof CORE[name] !== "function") {
  console.error("no such function: " + name);
  process.exit(2);
}
const args = JSON.parse(readFileSync(0, "utf-8"));
process.stdout.write(JSON.stringify(CORE[name](...args)));
