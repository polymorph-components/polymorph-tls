// Bundle entry for the deltic-browser leg: this is upstream
// tools/release-bundle/entry.ts's exact public surface, vendored here so
// the browser bundle is built from the SAME pinned JSR graph as the Deno
// legs instead of a sha256-pinned release asset (see README.md's
// "Pinning" section and ../justfile's `_deltic-browser-build` recipe).
export * from "@deltic/runtime/embedder";
export { Translator } from "@deltic/runtime/shim";
export * from "@deltic/ct-runner";
export { wasiShims } from "@deltic/wasi-shims";
export type { WasiShims, WasiShimsOptions } from "@deltic/wasi-shims";
