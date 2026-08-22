#!/usr/bin/env python3
"""Extract the translator wasm from the lock-pinned @polyengine/translator
module graph (`deno info --json`) into the browser-asset output dir.

No network, no sha256 bookkeeping: JSR package integrity lives in
deno.lock; this only truncates the already-fetched, --frozen-verified
cache entry down to its module bytes (Deno's on-disk remote-cache file
carries a trailing "\n// denoCacheMetadata={...}" line after the wasm
body — see the truncation + sanity checks below). See ../justfile's
`_polyengine-browser-build` recipe and README.md's "Pinning" section.

Usage: extract-translator-wasm.py <deno-info.json> <out-wasm-path> <expected-version>
"""
import json
import sys


def main() -> int:
    info_path, out_path, expected_version = sys.argv[1], sys.argv[2], sys.argv[3]
    graph = json.load(open(info_path))
    mods = [m for m in graph["modules"] if "/@polyengine/" in m.get("specifier", "")]
    bad = {m["specifier"] for m in mods if expected_version not in m["specifier"]}
    if bad:
        print(f"pin drift in translator graph: {bad}", file=sys.stderr)
        return 1
    wasm = next(
        (m for m in mods if m["specifier"].endswith("/translator_shim.wasm")),
        None,
    )
    if wasm is None:
        print("no translator_shim.wasm module found in the graph", file=sys.stderr)
        return 1

    # WARNING, learned the hard way: Deno's on-disk remote-cache file is
    # module bytes PLUS a trailing "\n// denoCacheMetadata={...}" line.
    # A plain copy yields a CORRUPT wasm (WebAssembly.compile: "unexpected
    # section <Code>"; wasm-tools: "section out of order" near EOF) —
    # Deno's own ESM wasm-module import reads through the cache API
    # (trailer stripped), which is why that path never noticed. Truncate
    # to the byte size `deno info` reports, then sanity-check both ends.
    data = open(wasm["local"], "rb").read()
    size = wasm.get("size")
    if size is None:
        print("deno info did not report a size for the translator module", file=sys.stderr)
        return 1
    body, rest = data[:size], data[size:]
    if body[:4] != b"\0asm":
        print("not wasm after truncation to the reported size", file=sys.stderr)
        return 1
    if rest and not rest.startswith(b"\n// denoCacheMetadata="):
        print("unexpected cache-file layout; refusing to copy", file=sys.stderr)
        return 1
    with open(out_path, "wb") as f:
        f.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
