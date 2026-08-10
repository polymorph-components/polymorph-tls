// The deltic leg of the conformance harness: runs a composed artifact
// (the shared suite fused with one TLS delivery) runtime-linked under
// deltic on stock Deno, and writes component-test results JSONL for the
// aggregate — the deltic analogue of the retired jco run-node.mjs
// (removed with the jco legs; see git history), mirroring its
// frame exactly:
//
//   run-node.mjs                          | this runner
//   --------------------------------------+---------------------------
//   jco transpile + loadCoreModules       | translator.translate(bytes)
//   bindImports (preview2-shim, both      | wasiShims() (track-keyed:
//     wasi minor spellings bound)         |   one @0.2 provider serves
//                                         |   every minor)
//   inventoryLookup(coreBytes) + missing  | deltic reads the suite's own
//     via runSuiteJsonl                   |   embedded inventory; missing
//                                         |   via runSuite (deltic#25)
//   node --experimental-wasm-jspi         | stock deno, callback ABI —
//                                         |   no engine flag
//
// The artifacts import only wasi 0.2 and test-context, so there is no
// SUT host module on this leg (the TLS delivery is fused in-guest);
// deltic's runner supplies test-context itself. No network, no PKI:
// the suite's cryptography runs in-guest.
//
//   deno run --allow-read=../../.. --allow-write=../results \
//     --config deno.json --frozen run.ts --suite suite-plain \
//     --missing delegated-signer --target deltic-deno \
//     --translator <shim.wasm>

import { Translator } from "@deltic/runtime/shim";
import type { ComponentArtifacts } from "@deltic/runtime/embedder";
import { runSuite } from "@deltic/ct-runner";
import { wasiShims } from "@deltic/wasi-shims";

const ROOT = new URL("../../../", import.meta.url);
const RESULTS = new URL("../results/", import.meta.url);
/** The un-composed suite: results provenance points here, exactly like
 * the wasmtime legs' `--suite-artifact` (wac-composed artifacts each
 * hash differently; the aggregate warns on mixed provenance). */
const GUEST = new URL(
  "target/wasm32-wasip2/release/conformance_guest_ct.wasm",
  ROOT,
);

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// The single-attempt wall bound per case, matching the other legs.
const CASE_TIMEOUT_MS = 60_000;

interface Cli {
  suite: string;
  target: string;
  suiteName: string;
  missing: string[];
  translator: string;
}

function parseCli(argv: string[]): Cli {
  let suite: string | undefined;
  let target: string | undefined;
  // The lockfile suite identity (the un-composed suite's wasm stem);
  // the composed artifact's name never appears in results.
  let suiteName = "conformance-guest-ct";
  let missing: string[] = [];
  let translator: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--suite":
        suite = argv[++i];
        break;
      case "--target":
        target = argv[++i];
        break;
      case "--suite-name":
        suiteName = argv[++i];
        break;
      case "--missing":
        missing = argv[++i].split(",").filter((f) => f !== "");
        break;
      case "--translator":
        translator = argv[++i];
        break;
      default:
        throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  if (!suite || !target || !translator) {
    console.error(
      "usage: run.ts --suite <suite-plain|suite-delegated> --target <key> " +
        "--translator <shim.wasm> [--missing f1,f2] [--suite-name name]",
    );
    Deno.exit(2);
  }
  return { suite, target, suiteName, missing, translator };
}

async function main() {
  const cli = parseCli(Deno.args);
  const componentBytes = await Deno.readFile(
    new URL(`target/conformance/${cli.suite}.wasm`, ROOT),
  );
  const translator = await Translator.create(
    await Deno.readFile(cli.translator),
  );
  const { plan, adapters } = translator.translate(componentBytes);
  const artifacts: ComponentArtifacts = { plan, componentBytes, adapters };

  const lines: string[] = [];
  const counts = await runSuite(artifacts, {
    imports: wasiShims(),
    target: cli.target,
    suiteName: cli.suiteName,
    missing: cli.missing,
    caseTimeoutMs: CASE_TIMEOUT_MS,
    emit: (line) => lines.push(line),
    log: (msg) => console.error(`  ${msg}`),
  });

  // --suite-artifact semantics (see GUEST above): re-point the envelope's
  // artifact-sha256 at the un-composed suite.
  const envelope = JSON.parse(lines[0]);
  envelope.suite["artifact-sha256"] = await sha256Hex(await Deno.readFile(GUEST));
  lines[0] = JSON.stringify(envelope);

  await Deno.mkdir(RESULTS, { recursive: true });
  const out = new URL(`${cli.target}.jsonl`, RESULTS);
  await Deno.writeTextFile(out, lines.join("\n") + "\n");
  console.error(
    `${counts.passed} passed | ${counts.failed} failed | ${counts.skipped} skipped | ` +
      `${counts.na} n/a (${counts.total} total) -> ${out.pathname}`,
  );
  if (!(counts.failed === 0 && counts.total > 0)) Deno.exit(1);
}

await main();
