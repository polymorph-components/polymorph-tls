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

deltic is pinned to a release tag in `deno.json` (import-map URLs;
`deno.lock` carries the module-graph integrity, enforced with
`--frozen`) and `fetch-translator.ts` (TAG + sha256 for the
`deltic-translator-shim.wasm` release asset, cached under
`target/deltic/<tag>/`), cross-checked at run time. To bump: update the
tag in both files and the sha from the release's `SHA256SUMS`, delete
`deno.lock`, re-run `deno cache run.ts fetch-translator.ts` here, and
commit the diff.
