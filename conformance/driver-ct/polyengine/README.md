# conformance/driver-ct/polyengine

The polyengine leg of the conformance matrix: the composed artifacts
(`suite-plain`, `suite-delegated`) run **runtime-linked** under
[polyengine](https://github.com/polymorph-components/polyengine) on
stock Deno — no transpile step, no generated tree, no
`--experimental-wasm-jspi` (the WIT contract's async exports run on the
callback ABI). Targets `polyengine-deno` and `polyengine-deno-delegated`
in `../targets.toml`.

There is no SUT host module on this leg (the TLS delivery is fused
in-guest, the artifacts import only wasi 0.2 and test-context), so the
whole import surface is polyengine's own `wasiShims()` + its
runner-supplied `test-context`. Tag scheduling reads the suite's
embedded `component-test:tags@0.1` inventory (it survives wac
composition); `--missing` mirrors `targets.toml` per target.

```sh
just conformance-ct::run-polyengine            # suite-plain  -> polyengine-deno
just conformance-ct::run-polyengine-delegated  # suite-delegated -> polyengine-deno-delegated
```

The on-demand webcrypto composition (`suite-delegated-webcrypto`) runs
under polyengine the same way — polyengine's own repo smokes it
(`tools/smoke-tls`) — but like the wasmtime row it is not a standing
target here.

## Pinning

polyengine is pinned to an exact JSR release (`0.3.0`; see `deno.json`'s
import-map, `deno.lock` carries module-graph integrity, enforced with
`--frozen`). The browser leg's embedder bundle and translator wasm are
built from that SAME pinned graph (`../justfile`'s
`_polyengine-browser-build` recipe: `deno bundle` for the embedder,
`deno info` + copy for the translator wasm) — no sha256 bookkeeping, no
GitHub release-asset fetch. A repo-wide pin gate (`../justfile`'s
`_polyengine-pin-check`) asserts every `deno.json` in the repo agrees on
one `@polyengine` version.

To bump: update the version in this directory's `deno.json` import-map
entries, delete `deno.lock`, run `deno install --config deno.json
--entrypoint run.ts browser-bundle-entry.ts` here, and commit the diff
(the pin gate asserts agreement).
