// The browser worker's import-object module: loaded by the upstream
// browser-worker via URL (module workers cannot see import maps), so
// every specifier here is a server path — the harness core through the
// driver's self-mount, the wasi shims through this tree's
// node_modules, both served over the repository-root server.
import { bindImports } from "/__component-test/js/viewer/imports.mjs";
import * as cli from "./node_modules/@bytecodealliance/preview2-shim/dist/browser/cli.js";
import * as clocks from "./node_modules/@bytecodealliance/preview2-shim/dist/browser/clocks.js";
import * as io from "./node_modules/@bytecodealliance/preview2-shim/dist/browser/io.js";
import * as random from "./node_modules/@bytecodealliance/preview2-shim/dist/browser/random.js";
import * as filesystem from "./node_modules/@bytecodealliance/preview2-shim/dist/browser/filesystem.js";

/** The composed artifacts import only wasi 0.2 and test-context; wasi
 *  minors differ across the fused halves, so both spellings bind. */
export async function suiteImports() {
  return bindImports({
    wasi: { cli, clocks, io, random, filesystem },
    wasiVersions: ["0.2.0", "0.2.6"],
  });
}
