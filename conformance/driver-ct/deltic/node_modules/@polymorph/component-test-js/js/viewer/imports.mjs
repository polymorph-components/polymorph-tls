// The suite import object for jco `-I async` instantiation, shared by
// the consumers' Node and browser drivers (#58): the wasi 0.2
// interfaces from the caller's preview2-shim namespaces, the upstream
// test-context provider, an explicit environment, and the caller's
// system-under-test imports. Browser-safe: no Node APIs; the caller
// supplies the shim namespaces (Node or browser build).

import { Context } from "./context.js";

/**
 * One environment interface for every leg (explicit beats
 * shim-internal state): `vars` is the `[name, value]` pair list the
 * suite reads through `wasi:cli/environment`.
 */
export function envInterface(vars) {
  return {
    getEnvironment: () => vars,
    getArguments: () => [],
    initialCwd: () => undefined,
  };
}

/**
 * Build the import object for an `-I async`-transpiled suite.
 *
 * Every interface is bound under its bare name and each versioned
 * spelling (generated cores mix the two, and the versioned spelling
 * carries the exact minor the component was built against — pass
 * `wasiVersions` when the default does not match the generated code's
 * import names).
 *
 * - `wasi`: preview2-shim namespaces (`{ cli, clocks, io, random,
 *   filesystem }`); absent members are simply not bound.
 * - `env`: `[name, value]` pairs served through `wasi:cli/environment`
 *   (always the explicit list, never the shim's ambient environment).
 * - `sut`: system-under-test imports by interface name, e.g.
 *   `{ "polymorph:websocket/connections": connections }`, bound bare
 *   and with each `sutVersions` suffix.
 *
 * `polymorph:test/test-context` is always bound to the upstream
 * [`Context`] provider at the contract's version.
 */
export function bindImports({
  wasi = {},
  env = [],
  sut = {},
  wasiVersions = ["0.2.0"],
  sutVersions = ["0.1.0"],
}) {
  const imports = {};
  const bind = (name, impl, versions) => {
    if (!impl) return;
    imports[name] = impl;
    for (const v of versions) {
      imports[`${name}@${v}`] = impl;
    }
  };
  const { cli = {}, clocks = {}, io = {}, random = {}, filesystem = {} } = wasi;
  bind("wasi:cli/environment", envInterface(env), wasiVersions);
  bind("wasi:cli/exit", cli.exit, wasiVersions);
  bind("wasi:cli/stdin", cli.stdin, wasiVersions);
  bind("wasi:cli/stdout", cli.stdout, wasiVersions);
  bind("wasi:cli/stderr", cli.stderr, wasiVersions);
  bind("wasi:cli/terminal-input", cli.terminalInput, wasiVersions);
  bind("wasi:cli/terminal-output", cli.terminalOutput, wasiVersions);
  bind("wasi:cli/terminal-stdin", cli.terminalStdin, wasiVersions);
  bind("wasi:cli/terminal-stdout", cli.terminalStdout, wasiVersions);
  bind("wasi:cli/terminal-stderr", cli.terminalStderr, wasiVersions);
  bind("wasi:clocks/monotonic-clock", clocks.monotonicClock, wasiVersions);
  bind("wasi:clocks/wall-clock", clocks.wallClock, wasiVersions);
  bind("wasi:io/error", io.error, wasiVersions);
  bind("wasi:io/poll", io.poll, wasiVersions);
  bind("wasi:io/streams", io.streams, wasiVersions);
  bind("wasi:random/random", random.random, wasiVersions);
  bind("wasi:random/insecure", random.insecure, wasiVersions);
  bind("wasi:random/insecure-seed", random.insecureSeed, wasiVersions);
  bind("wasi:filesystem/types", filesystem.types, wasiVersions);
  bind("wasi:filesystem/preopens", filesystem.preopens, wasiVersions);
  bind("polymorph:test/test-context", { Context }, ["0.1.0"]);
  for (const [name, impl] of Object.entries(sut)) {
    bind(name, impl, sutVersions);
  }
  return imports;
}
