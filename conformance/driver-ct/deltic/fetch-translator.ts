// Fetch (and cache) pinned deltic release assets.
//
// deltic is a runtime linker: components are translated by a wasm build of
// its translator, shipped as a release asset so consumers need no Rust
// toolchain; the browser leg additionally loads `deltic-embedder.mjs` (one
// platform-neutral ES module: embedder API + Translator + runner glue +
// wasi shims). This script downloads the selected asset once into
// target/deltic/, verifies it against the pinned sha256, and prints the
// cached path on stdout (the `conformance-ct::run-deltic*` recipes capture
// it).
//
//   fetch-translator.ts [--asset translator|embedder]   (default: translator)
//
// THE PIN lives here (TAG + per-asset sha256) and in the sibling
// deno.json's import-map URLs. `assertPinConsistency` fails loud if the
// two drift. Bumping: update TAG here and in deno.json, update the shas
// from the release's SHA256SUMS, delete deno.lock, and re-run
// `deno cache run.ts fetch-translator.ts` in this directory to
// regenerate it (commit the diff).

const TAG = "pre-83fff30";
const ASSETS: Record<string, { file: string; sha256: string }> = {
  translator: {
    file: "deltic-translator-shim.wasm",
    sha256: "6d02b363785593595a789d083cda0aebb1de790726718ccf543198354fa3870c",
  },
  embedder: {
    file: "deltic-embedder.mjs",
    sha256: "b9ceb33c78abdaa4311f681c1388b14a3471f8a17ebd2dbf2dddd4a596df72c3",
  },
};

const HERE = new URL(".", import.meta.url);
const REPO_ROOT = new URL("../../../", HERE);
const CACHE_DIR = new URL(`target/deltic/${TAG}/`, REPO_ROOT);

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes as BufferSource,
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** The one-pin-everywhere gate: every raw.githubusercontent URL in the
 * sibling import map must reference TAG. */
async function assertPinConsistency(): Promise<void> {
  const denoJson = await Deno.readTextFile(new URL("deno.json", HERE));
  const urls = denoJson.match(/https:\/\/raw\.githubusercontent\.com[^"]+/g) ?? [];
  if (urls.length === 0) {
    throw new Error("deno.json: no pinned deltic URLs found");
  }
  for (const url of urls) {
    if (!url.includes(`/lann/deltic/${TAG}/`)) {
      throw new Error(
        `pin drift: deno.json pins ${url}\nbut fetch-translator.ts pins ${TAG}`,
      );
    }
  }
}

async function main() {
  await assertPinConsistency();

  const flag = Deno.args.indexOf("--asset");
  const name = flag === -1 ? "translator" : Deno.args[flag + 1];
  const asset = ASSETS[name];
  if (!asset) {
    throw new Error(
      `unknown asset ${JSON.stringify(name)}; expected one of: ${
        Object.keys(ASSETS).join(", ")
      }`,
    );
  }
  const cached = new URL(asset.file, CACHE_DIR);

  try {
    const bytes = await Deno.readFile(cached);
    if (await sha256Hex(bytes) === asset.sha256) {
      console.log(cached.pathname);
      return;
    }
    console.error(`cached ${asset.file} has a stale digest; re-fetching`);
  } catch {
    // not cached yet
  }

  const releaseUrl =
    `https://github.com/lann/deltic/releases/download/${TAG}/${asset.file}`;
  console.error(`fetching ${releaseUrl} …`);
  const resp = await fetch(releaseUrl);
  if (!resp.ok) {
    throw new Error(`GET ${releaseUrl}: ${resp.status} ${resp.statusText}`);
  }
  const bytes = new Uint8Array(await resp.arrayBuffer());
  const got = await sha256Hex(bytes);
  if (got !== asset.sha256) {
    throw new Error(
      `sha256 mismatch for ${asset.file}@${TAG}:\n  want ${asset.sha256}\n  got  ${got}`,
    );
  }
  await Deno.mkdir(CACHE_DIR, { recursive: true });
  await Deno.writeFile(cached, bytes);
  console.log(cached.pathname);
}

await main();
