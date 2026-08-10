// Shared engine glue for the deltic legs (browser shard worker + Node
// selftest): load the pinned deltic embedder bundle, translate the suite
// component, and hand back exactly what harness.mjs `runCases` needs.
// deltic is a runtime linker — the suite arrives as the COMPONENT wasm
// (no transpiled module, no core files, no imports module; WASI comes
// from the bundle's wasiShims, test-context from its ct-runner glue).
//
// The Context handed to runCases MUST be the bundle's own Context class:
// `testContextImportRecord()` registers that exact class as the
// `polymorph:test/test-context` host resource, and deltic lowers borrows
// of it by class identity.

/**
 * @param {object} input
 * @param {object|string} input.bundle  The deltic embedder module, or a URL
 *   string to import it from (workers pass the URL; Node imports first).
 * @param {Uint8Array} input.translatorBytes  deltic-translator-shim.wasm.
 * @param {Uint8Array} input.suiteBytes  The suite COMPONENT wasm.
 * @param {[string, string][]} [input.env]  wasi:cli environment pairs.
 * @returns {Promise<{newTests: () => Promise<object>, Context, tagsOf}>}
 */
export async function loadSuite({ bundle, translatorBytes, suiteBytes, env = [] }) {
  const deltic = typeof bundle === "string" ? await import(bundle) : bundle;
  const translator = await deltic.Translator.create(translatorBytes);
  const { plan, adapters } = translator.translate(suiteBytes);
  const artifacts = { plan, componentBytes: suiteBytes, adapters };

  const imports = {
    ...deltic.wasiShims({ cli: { env: Object.fromEntries(env) } }),
    ...deltic.testContextImportRecord(),
  };

  const newTests = async () => {
    const inst = await deltic.instantiate(artifacts, imports);
    const tests = inst.exports["polymorph:test/tests@0.1.0"] ?? inst.exports["tests"];
    if (tests === undefined) {
      throw new Error(
        `suite exports no tests interface: ${Object.keys(inst.exports)}`,
      );
    }
    return tests;
  };

  // The suite's own L0 inventory (deltic reads it from the component,
  // nested core modules included — the same records harness.mjs's
  // inventoryLookup reads from transpiled cores). A suite without records
  // yields an always-undefined lookup, and runCases throws inventory
  // drift on the first case — same posture as the jco worker.
  const inventory = deltic.loadTagsInventory(suiteBytes);
  const tagsOf = inventory === null
    ? () => undefined
    : (name) => deltic.tagsOf(inventory, name);

  return { newTests, Context: deltic.Context, tagsOf };
}
