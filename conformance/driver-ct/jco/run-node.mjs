// The jco-node leg of the conformance harness: runs a transpiled
// composed artifact (the shared suite fused with one TLS delivery)
// under Node 24 JSPI and writes component-test results JSONL for the
// aggregate. The artifact imports only wasi 0.2 and test-context, so
// the import object is entirely the upstream builder's — there is no
// SUT host module on this leg.
//
// Fresh instance per case (freshCases): JSPI attempts cannot be
// cancelled, so a timed-out case's instance may be wedged
// mid-suspension, and a fresh TLS component per case also contains
// poisoning the way --cases-per-instance 1 would.
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { cli, clocks, io, random, filesystem } from "@bytecodealliance/preview2-shim";
import { envelope, inventoryLookup, runCases } from "@polymorph/component-test-js/harness";
import { Context } from "@polymorph/component-test-js/context";
import { bindImports } from "@polymorph/component-test-js/imports";

const JCO_DIR = dirname(fileURLToPath(import.meta.url));

// The single-attempt wall bound per case, matching the wasmtime leg's
// defaults in spirit: a wedged case is reported, never retried, and
// never allowed to hang the leg.
const CASE_TIMEOUT_MS = 60_000;

const { values } = parseArgs({
  options: {
    // Transpile name of the composed artifact (suite-plain | suite-delegated).
    suite: { type: "string" },
    // The lockfile suite identity (the un-composed suite's wasm stem);
    // the composed artifact's name never appears in results.
    "suite-name": { type: "string", default: "conformance-guest-ct" },
    missing: { type: "string", default: "" },
    target: { type: "string" },
    out: { type: "string", default: join(JCO_DIR, "..", "results") },
  },
});
if (!values.suite || !values.target) {
  throw new Error("usage: run-node.mjs --suite <name> --target <key> [--missing f1,f2] [--out dir]");
}
const missing = values.missing.split(",").filter(Boolean);

const generatedDir = join(JCO_DIR, "generated");
const coreBytes = [];
const modules = new Map();
for (const name of (await readdir(generatedDir)).sort()) {
  if (!name.startsWith(`${values.suite}.core`) || !name.endsWith(".wasm")) continue;
  const bytes = new Uint8Array(await readFile(join(generatedDir, name)));
  coreBytes.push(bytes);
  modules.set(name, await WebAssembly.compile(bytes));
}
// The tags custom section rides the suite's core module through both
// wac composition and transpilation, so the composed cores carry the
// full inventory.
const tagsOf = inventoryLookup(coreBytes);

const { instantiate } = await import(join(generatedDir, `${values.suite}.js`));
// wasi minors differ across the fused halves (the suite's std imports
// and the TLS component's), so bind both spellings the generated core
// asks for.
const imports = bindImports({
  wasi: { cli, clocks, io, random, filesystem },
  wasiVersions: ["0.2.0", "0.2.6"],
});
const newTests = async () => {
  const instance = await instantiate((name) => modules.get(name), imports);
  const tests =
    instance.tests ?? instance["polymorph:test/tests@0.1.0"] ?? instance["polymorph:test/tests"];
  if (!tests) {
    throw new Error(`suite instance exports no tests interface: ${Object.keys(instance)}`);
  }
  return tests;
};

const lines = [JSON.stringify(envelope(values.target, values["suite-name"]))];
const counts = await runCases({
  cases: await (await newTests()).all(),
  Context,
  tagsOf,
  missing,
  emit: (event) => {
    lines.push(JSON.stringify(event));
    process.stderr.write(`[${values.target}] ${event.case} … ${event.status}\n`);
  },
  caseTimeoutMs: CASE_TIMEOUT_MS,
  freshCases: async () => (await newTests()).all(),
});
if (counts.total === 0) {
  throw new Error("suite enumerated zero cases (empty selection is a run error)");
}
lines.push('{"segment-end":true}');

await mkdir(values.out, { recursive: true });
const outPath = join(values.out, `${values.target}.jsonl`);
await writeFile(outPath, `${lines.join("\n")}\n`);
process.stderr.write(`wrote ${outPath} (${counts.total} cases, ${counts.failed} failed)\n`);
process.exit(counts.failed === 0 ? 0 : 1);
