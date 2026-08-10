// Node-only conveniences for jco-transpiled suite drivers (#59's node
// half): core-module loading, the tests-export spellings, results-file
// writing. The case loop itself is `runSuiteJsonl` in ./viewer/harness.mjs
// (browser-safe); what stays in each consumer is its frame — argv, SUT
// and environment wiring, concurrency topology.

import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

// Browser-safe logic lives in the harness; re-exported here so node
// drivers keep one import site.
export { resolveTestsExport } from "./viewer/harness.mjs";

/**
 * Compile a transpiled suite's core modules from `dir`, in name order:
 * `<prefix>.core*.wasm` when `prefix` is given (several suites may
 * share one generated tree), every `*.wasm` otherwise. Returns
 * `modules` (name → WebAssembly.Module, for `instantiate`'s
 * getCoreModule) and `coreBytes` (for `inventoryLookup` — the tags
 * custom section rides the suite's core module through composition
 * and transpilation).
 */
export async function loadCoreModules(dir, prefix) {
  const modules = new Map();
  const coreBytes = [];
  for (const name of (await readdir(dir)).sort()) {
    if (!name.endsWith(".wasm")) continue;
    if (prefix !== undefined && !name.startsWith(`${prefix}.core`)) continue;
    const bytes = new Uint8Array(await readFile(join(dir, name)));
    coreBytes.push(bytes);
    modules.set(name, await WebAssembly.compile(bytes));
  }
  if (modules.size === 0) {
    throw new Error(
      `no ${prefix === undefined ? "" : `${prefix}.core`}*.wasm under ${dir} (transpile first)`,
    );
  }
  return { modules, coreBytes };
}

/**
 * Write one target's results stream to `<dir>/<target>.jsonl`
 * (trailing newline included), creating `dir` as needed. Returns the
 * path.
 */
export async function writeResultsFile({ dir, target, lines }) {
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${target}.jsonl`);
  await writeFile(path, `${lines.join("\n")}\n`);
  return path;
}
