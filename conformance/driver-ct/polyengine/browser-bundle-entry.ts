// Bundle entry for the polyengine-browser leg: this is upstream
// tools/release-bundle/entry.ts's exact public surface, vendored here so
// the browser bundle is built from the SAME pinned JSR graph as the Deno
// legs instead of a sha256-pinned release asset (see README.md's
// "Pinning" section and ../justfile's `_polyengine-browser-build` recipe).
export * from "@polyengine/runtime/embedder";
export { Translator } from "@polyengine/runtime/shim";
export * from "@polyengine/ct-runner";
export { wasi } from "@polyengine/wasi";
export type { WasiImports, WasiOptions } from "@polyengine/wasi";
