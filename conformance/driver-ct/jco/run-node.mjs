// The jco-node leg of the conformance harness: runs a transpiled
// composed artifact (the shared suite fused with one TLS delivery)
// under Node 24 JSPI and writes component-test results JSONL for the
// aggregate. The artifact imports only wasi 0.2 and test-context, so
// the import object is entirely the upstream builder's — there is no
// SUT host module on this leg. The case loop and driver plumbing are
// the upstream helpers; this file is just the frame: argv and wiring.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { cli, clocks, io, random, filesystem } from "@bytecodealliance/preview2-shim";
import { runSuiteJsonl } from "@polymorph/component-test-js/harness";
import { inventoryLookup } from "@polymorph/component-test-js/harness";
import { bindImports } from "@polymorph/component-test-js/imports";
import {
  loadCoreModules,
  resolveTestsExport,
  writeResultsFile,
} from "@polymorph/component-test-js/node-runner";

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

const { modules, coreBytes } = await loadCoreModules(join(JCO_DIR, "generated"), values.suite);
const { instantiate } = await import(join(JCO_DIR, "generated", `${values.suite}.js`));
// wasi minors differ across the fused halves (the suite's std imports
// and the TLS component's), so bind both spellings the generated core
// asks for.
const imports = bindImports({
  wasi: { cli, clocks, io, random, filesystem },
  wasiVersions: ["0.2.0", "0.2.6"],
});

const lines = [];
const counts = await runSuiteJsonl({
  newTests: async () =>
    resolveTestsExport(await instantiate((name) => modules.get(name), imports)),
  tagsOf: inventoryLookup(coreBytes),
  target: values.target,
  suiteName: values["suite-name"],
  missing: values.missing.split(",").filter(Boolean),
  caseTimeoutMs: CASE_TIMEOUT_MS,
  emit: (line) => lines.push(line),
  log: (msg) => process.stderr.write(`[${values.target}] ${msg}\n`),
});

const outPath = await writeResultsFile({ dir: values.out, target: values.target, lines });
process.stderr.write(`wrote ${outPath} (${counts.total} cases, ${counts.failed} failed)\n`);
process.exit(counts.failed === 0 ? 0 : 1);
