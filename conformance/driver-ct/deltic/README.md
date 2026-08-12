# conformance/driver-ct/deltic

The deltic leg of the conformance matrix: the composed artifacts
(`suite-plain`, `suite-delegated`) run **runtime-linked** under
[deltic](https://github.com/lann/deltic) on stock Deno — no transpile
step, no generated tree, no `--experimental-wasm-jspi` (the WIT
contract's async exports run on the callback ABI). Targets
`deltic-deno` and `deltic-deno-delegated` in `../targets.toml`.

There is no SUT host module on this leg (the TLS delivery is fused
in-guest, the artifacts import only wasi 0.2 and test-context), so the
whole import surface is deltic's own `wasiShims()` + its runner-supplied
`test-context`. Tag scheduling reads the suite's embedded
`component-test:tags@0.1` inventory (it survives wac composition);
`--missing` mirrors `targets.toml` per target.

```sh
just conformance-ct::run-deltic            # suite-plain  -> deltic-deno
just conformance-ct::run-deltic-delegated  # suite-delegated -> deltic-deno-delegated
```

The on-demand webcrypto composition (`suite-delegated-webcrypto`) runs
under deltic the same way — deltic's own repo smokes it
(`tools/smoke-tls`) — but like the wasmtime row it is not a standing
target here.

## Pinning

deltic is pinned to an exact JSR prerelease (`0.1.0-pre.g078aa15`; the
hash names one upstream commit) via `deno.json`'s import-map (`deno.lock`
carries module-graph integrity, enforced with `--frozen`). The browser
leg's embedder bundle and translator wasm are built from that SAME
pinned graph (`../justfile`'s `_deltic-browser-build` recipe: `deno
bundle` for the embedder, `deno info` + copy for the translator wasm) —
no sha256 bookkeeping, no GitHub release-asset fetch. A repo-wide pin
gate (`../justfile`'s `_deltic-pin-check`) asserts every `deno.json` in
the repo agrees on one `@deltic` version.

To bump: update the version in this directory's `deno.json` import-map
entries, delete `deno.lock`, run `deno install --config deno.json
--entrypoint run.ts browser-bundle-entry.ts` here, and commit the diff
(the pin gate asserts agreement).
