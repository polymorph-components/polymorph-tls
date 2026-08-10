// The generic browser-side shard worker for jco-transpiled suites
// (#59's browser half): compiles the cores it is handed, builds the
// import object through the consumer's imports module, and runs one
// shard of the case loop, streaming indexed events back to the page.
//
// Browser-safe module Worker; workers cannot see the page's import
// map, so every module reference arrives as a URL in the run message:
//
//   {
//     moduleUrl,      // the transpiled suite's .js (instantiation: async)
//     coreUrls,       // its core wasm files, fetch order = name order
//     importsUrl,     // module exporting suiteImports(env) -> imports object
//     contextUrl?,    // module exporting Context; upstream default otherwise
//     env?,           // [name, value] pairs handed to suiteImports
//     missing?, shard?, caseTimeoutMs?,
//   }
//
// Replies: { kind: "event", index, event } per case,
// { kind: "counts", counts } on completion, { kind: "error", error }
// on harness breakage.

import { inventoryLookup, resolveTestsExport, runCases } from "./harness.mjs";
import { Context as DefaultContext } from "./context.js";

// A rejection escaping the awaited chain (e.g. a platform quirk
// surfacing through the transpiled guest's async plumbing) would
// otherwise leave the worker silently wedged: unhandled rejections
// fire neither the catch below nor the page's worker.onerror.
self.onunhandledrejection = (event) => {
  event.preventDefault?.();
  self.postMessage({ kind: "error", error: String(event.reason?.stack ?? event.reason) });
};

self.onmessage = async ({ data }) => {
  const {
    moduleUrl,
    coreUrls,
    importsUrl,
    contextUrl,
    env = [],
    missing = [],
    only,
    shard,
    caseTimeoutMs,
  } = data;
  try {
    const coreBytes = [];
    const modules = new Map();
    for (const url of coreUrls) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`fetching ${url}: ${res.status}`);
      const bytes = new Uint8Array(await res.arrayBuffer());
      coreBytes.push(bytes);
      // instantiate() asks for cores by file name.
      modules.set(new URL(url, self.location.href).pathname.split("/").pop(), await WebAssembly.compile(bytes));
    }
    const tagsOf = inventoryLookup(coreBytes);

    const { instantiate } = await import(moduleUrl);
    const { suiteImports } = await import(importsUrl);
    const Context = contextUrl ? (await import(contextUrl)).Context : DefaultContext;
    const imports = await suiteImports(env);
    const newTests = async () =>
      resolveTestsExport(await instantiate((name) => modules.get(name), imports));

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
