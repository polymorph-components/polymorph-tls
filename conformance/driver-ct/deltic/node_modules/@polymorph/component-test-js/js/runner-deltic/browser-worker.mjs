// The deltic browser-side shard worker — the runtime-linked sibling of
// js/viewer/browser-worker.mjs (same reply protocol, same harness case
// loop, no transpiled artifacts). Drop-in for page-runner.mjs's
// runSuitesInPage via its workerUrl parameter; suite entries carry this
// worker's run message instead of the jco one:
//
//   {
//     bundleUrl,      // the pinned deltic-embedder.mjs (release asset)
//     translatorUrl,  // the pinned deltic-translator-shim.wasm
//     suiteUrl,       // the suite COMPONENT wasm (no transpile, no cores)
//     env?,           // [name, value] pairs for wasi:cli/environment
//     missing?, only?, shard?, caseTimeoutMs?,
//   }
//
// Replies: { kind: "event", index, event } per case,
// { kind: "counts", counts } on completion, { kind: "error", error }
// on harness breakage.

import { runCases } from "../viewer/harness.mjs";
import { loadSuite } from "./engine.mjs";

self.onunhandledrejection = (event) => {
  event.preventDefault?.();
  self.postMessage({ kind: "error", error: String(event.reason?.stack ?? event.reason) });
};

async function fetchBytes(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetching ${url}: ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

self.onmessage = async ({ data }) => {
  const {
    bundleUrl,
    translatorUrl,
    suiteUrl,
    env = [],
    missing = [],
    only,
    shard,
    caseTimeoutMs,
  } = data;
  try {
    const [translatorBytes, suiteBytes] = await Promise.all([
      fetchBytes(translatorUrl),
      fetchBytes(suiteUrl),
    ]);
    const { newTests, Context, tagsOf } = await loadSuite({
      bundle: bundleUrl,
      translatorBytes,
      suiteBytes,
      env,
    });

    const counts = await runCases({
      cases: await (await newTests()).all(),
      Context,
      tagsOf,
      missing,
      only,
      shard,
      caseTimeoutMs,
      emit: (event, index) => self.postMessage({ kind: "event", index, event }),
      freshCases: async () => (await newTests()).all(),
    });
    self.postMessage({ kind: "counts", counts });
  } catch (err) {
    self.postMessage({ kind: "error", error: String(err?.stack ?? err) });
  }
};
