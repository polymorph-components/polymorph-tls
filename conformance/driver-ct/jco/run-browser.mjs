// The jco-browser leg: both composed artifacts run inside headless
// Chromium through the upstream page driver — the page, worker pool,
// stall watchdog, and Chrome ladder all live in
// @polymorph/component-test-js; this file is the frame: core-URL
// enumeration, target configuration, and results-file writing.
//
// Gates in CI (the Actions runner image ships Chrome); locally it runs
// under CONFORMANCE_BROWSER=1 (`just conformance-ct::all`) or directly
// via `just conformance-ct::run-browser`.
import { readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import {
  buildHarnessPage,
  findChrome,
  runPageHarness,
} from "@polymorph/component-test-js/browser-driver";
import { writeResultsFile } from "@polymorph/component-test-js/node-runner";

const JCO_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(JCO_DIR, "..", "..", "..");
const BASE = "/conformance/driver-ct/jco";
const CASE_TIMEOUT_MS = 60_000;
// The pool heartbeats per suite and per 25 rows; with 7-case suites the
// quiet time is bounded by one suite's slowest handshakes.
const STALL_TIMEOUT_MS = 90_000;

const { values } = parseArgs({
  options: {
    out: { type: "string", default: join(JCO_DIR, "..", "results") },
  },
});

async function coreUrls(transpileName) {
  const names = (await readdir(join(JCO_DIR, "generated"))).sort();
  return names
    .filter((n) => n.startsWith(`${transpileName}.core`) && n.endsWith(".wasm"))
    .map((n) => `${BASE}/generated/${n}`);
}

const common = {
  suite: "conformance-guest-ct",
  importsUrl: `${BASE}/browser-imports.mjs`,
  caseTimeoutMs: CASE_TIMEOUT_MS,
};
const SUITES = [
  {
    ...common,
    target: "jco-browser",
    moduleUrl: `${BASE}/generated/suite-plain.js`,
    coreUrls: await coreUrls("suite-plain"),
    missing: ["delegated-signer"],
  },
  {
    ...common,
    target: "jco-browser-delegated",
    moduleUrl: `${BASE}/generated/suite-delegated.js`,
    coreUrls: await coreUrls("suite-delegated"),
    missing: [],
  },
];

const playwright = await import("playwright-core");
const outcome = await runPageHarness({
  playwright,
  engine: "chromium",
  executablePath: await findChrome(),
  repoRoot: REPO_ROOT,
  html: buildHarnessPage({
    title: "polymorph:tls conformance (jco-browser)",
    config: { jobs: 1, suites: SUITES },
  }),
  stallTimeoutMs: STALL_TIMEOUT_MS,
});

let failed = 0;
for (const { target } of SUITES) {
  const run = outcome[target];
  if (!run) throw new Error(`the page reported no run for target ${target}`);
  const outPath = await writeResultsFile({ dir: values.out, target, lines: run.lines });
  const c = run.counts;
  process.stderr.write(
    `${target}: ${c.passed} passed, ${c.failed} failed, ${c.skipped} skipped, ` +
      `${c.na} not applicable, ${c.total} total (wrote ${outPath})\n`,
  );
  failed += c.failed;
}
process.exit(failed === 0 ? 0 : 1);
