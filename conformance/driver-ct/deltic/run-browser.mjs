// The deltic-browser leg: both composed artifacts run runtime-linked
// inside headless Chromium — the page, worker pool, stall watchdog, and
// Chrome ladder all live in @polymorph/component-test-js, and the
// upstream DELTIC worker (js/runner-deltic/browser-worker.mjs) loads the
// pinned deltic-embedder.mjs release asset and links the suite in the
// browser: no transpile step, no generated tree. This file is the frame:
// asset URL wiring, target configuration, and results-file writing —
// the browser sibling of ../deltic/run.ts exactly as ../jco/run-browser.mjs
// is the browser sibling of ../jco/run-node.mjs.
//
// The artifacts import only wasi 0.2 and test-context, so there is no
// SUT host module on this leg and the stock upstream worker serves it
// unmodified (wasiShims + test-context are inside the bundle).
//
// Gates in CI (the Actions runner image ships Chrome); locally it runs
// under CONFORMANCE_BROWSER=1 (`just conformance-ct::all`) or directly
// via `just conformance-ct::run-deltic-browser`. The justfile recipe
// fetches the sha256-pinned release assets first (fetch-translator.ts
// --asset translator|embedder), cached under target/deltic/<tag>/ and
// served to the page from the repository-root server.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import {
  buildHarnessPage,
  findChrome,
  MOUNT,
  runPageHarness,
} from "@polymorph/component-test-js/browser-driver";
import { writeResultsFile } from "@polymorph/component-test-js/node-runner";

const DELTIC_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(DELTIC_DIR, "..", "..", "..");
// Must agree with fetch-translator.ts's TAG (assets are served from its
// cache directory).
const TAG = "pre-83fff30";
const ASSETS = `/target/deltic/${TAG}`;
const CASE_TIMEOUT_MS = 60_000;
const STALL_TIMEOUT_MS = 90_000;

const { values } = parseArgs({
  options: {
    out: { type: "string", default: join(DELTIC_DIR, "..", "results") },
  },
});

const common = {
  suite: "conformance-guest-ct",
  bundleUrl: `${ASSETS}/deltic-embedder.mjs`,
  translatorUrl: `${ASSETS}/deltic-translator-shim.wasm`,
  caseTimeoutMs: CASE_TIMEOUT_MS,
};
const SUITES = [
  {
    ...common,
    target: "deltic-browser",
    suiteUrl: "/target/conformance/suite-plain.wasm",
    missing: ["delegated-signer"],
  },
  {
    ...common,
    target: "deltic-browser-delegated",
    suiteUrl: "/target/conformance/suite-delegated.wasm",
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
    title: "polymorph:tls conformance (deltic-browser)",
    config: {
      jobs: 1,
      workerUrl: `${MOUNT}/js/runner-deltic/browser-worker.mjs`,
      suites: SUITES,
    },
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
