// The node-only browser page driver (#59's browser half): a static
// server over the consumer's repository root with this package
// self-mounted, a headless Playwright engine running a generated
// harness page, heartbeat-based stall detection, and the
// Chrome-binary ladder. The in-page halves are ./viewer/page-runner.mjs
// and ./viewer/browser-worker.mjs, reached through the self-mount.
//
// This module imports only Node builtins; the caller passes in its own
// playwright-core module, since each npm tree pins its own version.
//
// The page contract: the harness calls `window.__progress(note)` as
// work streams (the heartbeat the stall watchdog observes) and
// `window.__report(outcome)` exactly once at the end, with `{ error }`
// carrying an in-page failure.

import { access, readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Where this package self-mounts on the harness server. */
export const MOUNT = "/__component-test";

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".wasm": "application/wasm",
  ".map": "application/json",
  ".json": "application/json",
};

/** The import-map entries resolving this package's bare specifiers to
 *  the self-mount (module workers cannot see the map; they receive
 *  URLs instead). */
export function componentTestImportMap() {
  return {
    "@polymorph/component-test-js/harness": `${MOUNT}/js/viewer/harness.mjs`,
    "@polymorph/component-test-js/context": `${MOUNT}/js/viewer/context.js`,
    "@polymorph/component-test-js/imports": `${MOUNT}/js/viewer/imports.mjs`,
  };
}

/**
 * A minimal harness document: the import map (this package's entries
 * plus the caller's), then a module script handing `config` to
 * [`runSuitesInPage`]. `config.suites[*].{moduleUrl,coreUrls,importsUrl,contextUrl}`
 * must be server-absolute paths.
 */
export function buildHarnessPage({ title = "component-test conformance", importMap = {}, config }) {
  const map = JSON.stringify({ imports: { ...componentTestImportMap(), ...importMap } });
  return `<!doctype html>
<link rel="icon" href="data:,">
<title>${title}</title>
<script type="importmap">${map}</script>
<script type="module">
import { runSuitesInPage } from "${MOUNT}/js/viewer/page-runner.mjs";
await runSuitesInPage({
  workerUrl: "${MOUNT}/js/viewer/browser-worker.mjs",
  ...${JSON.stringify(config)},
});
</script>`;
}

/** Serve `repoRoot` statically plus the harness page at "/" and this
 *  package under [`MOUNT`]; `routes(req, res) => boolean` (optional)
 *  claims a request before the static paths. */
function serve({ repoRoot, html, routes }) {
  const server = createServer(async (req, res) => {
    if (routes && (await routes(req, res))) return;
    const path = new URL(req.url, "http://localhost").pathname;
    if (path === "/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(html);
      return;
    }
    const file = path.startsWith(`${MOUNT}/`)
      ? join(PACKAGE_ROOT, path.slice(MOUNT.length + 1))
      : join(repoRoot, path);
    try {
      const body = await readFile(file);
      res.writeHead(200, {
        "content-type": MIME[extname(file)] ?? "application/octet-stream",
      });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end("not found");
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function launchBrowser(playwright, engine, executablePath, timeout, launchArgs) {
  if (engine === "firefox") {
    // Gecko's JSPI pref: the transpiled guests suspend on JSPI, which
    // Firefox has not yet shipped by default.
    return playwright.firefox.launch({
      headless: true,
      timeout,
      args: launchArgs,
      firefoxUserPrefs: {
        "javascript.options.wasm_js_promise_integration": true,
      },
    });
  }
  const options = { headless: true, timeout, args: launchArgs };
  if (executablePath !== undefined) options.executablePath = executablePath;
  return playwright[engine].launch(options);
}

/**
 * Locate a Chromium/Chrome binary: CHROME_PATH, common system names,
 * then the Playwright browser cache. Throws when nothing is found.
 */
export async function findChrome(env = process.env) {
  const candidates = [];
  if (env.CHROME_PATH) candidates.push(env.CHROME_PATH);
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    for (const dir of ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]) {
      candidates.push(join(dir, name));
    }
  }
  const cache = join(env.HOME ?? "", ".cache", "ms-playwright");
  try {
    const { readdir } = await import("node:fs/promises");
    for (const entry of (await readdir(cache)).sort().reverse()) {
      if (entry.startsWith("chromium_headless_shell-")) {
        candidates.push(join(cache, entry, "chrome-linux", "headless_shell"));
      } else if (entry.startsWith("chromium-")) {
        candidates.push(join(cache, entry, "chrome-linux", "chrome"));
      }
    }
  } catch {
    // No playwright cache.
  }
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next candidate.
    }
  }
  throw new Error(
    "no Chromium/Chrome binary found: set CHROME_PATH or install one " +
      "(e.g. `npx playwright-core install chromium`)",
  );
}

/**
 * Run a harness page to completion and return what it reported.
 *
 * Watchdog bounds: browser launch and page load get hard timeouts; the
 * run itself is bounded by *inactivity* — the harness heartbeats as
 * results stream in, so a stall means the page hung (a wedged worker,
 * a deadlocked JSPI suspension, an uncaught error nothing was
 * listening for), and the watchdog fails fast with the last heartbeat
 * naming where. `stallTimeoutMs` is per-caller: the tolerable quiet
 * time depends on the harness's heartbeat cadence.
 *
 * @param {object} options
 * @param {object} options.playwright  The caller's playwright-core module.
 * @param {string} options.engine  "chromium" | "firefox" | "webkit".
 * @param {string} [options.executablePath]  A specific browser binary,
 *   instead of Playwright's own build of the engine.
 * @param {string} options.repoRoot  Directory the static server serves.
 * @param {string} options.html  The harness document served at "/".
 * @param {function} [options.routes]  `(req, res) => boolean` claiming a
 *   request before the static paths (proxies, health checks).
 * @param {string[]} [options.launchArgs]  Extra browser launch arguments
 *   (sandbox flags, certificate-trust provisioning for a test PKI).
 * @param {number} options.stallTimeoutMs  Max quiet time between heartbeats.
 * @param {number} [options.launchTimeoutMs]
 * @param {number} [options.loadTimeoutMs]
 * @returns {Promise<object>} The page's `__report` payload; throws if it
 *   carries `error`, if the page crashes or throws, or on a stall.
 */
export async function runPageHarness({
  playwright,
  engine,
  executablePath,
  repoRoot,
  html,
  routes,
  launchArgs,
  stallTimeoutMs,
  launchTimeoutMs = 120_000,
  loadTimeoutMs = 60_000,
}) {
  const [browser, server] = await Promise.all([
    launchBrowser(playwright, engine, executablePath, launchTimeoutMs, launchArgs),
    serve({ repoRoot, html, routes }),
  ]);
  try {
    const { port } = server.address();
    const page = await browser.newPage();
    page.on("console", (msg) => {
      if (msg.type() === "error") console.error("[page]", msg.text());
    });

    let lastBeat = { at: Date.now(), note: "page created" };
    await page.exposeFunction("__progress", (note) => {
      lastBeat = { at: Date.now(), note: String(note) };
    });
    let settled = false;
    const report = new Promise((resolve, reject) => {
      page.exposeFunction("__report", resolve);
      page.on("crash", () =>
        reject(new Error(`page crashed (last heartbeat: ${lastBeat.note})`)),
      );
      page.on("pageerror", (err) =>
        reject(new Error(`uncaught page error: ${err} (last heartbeat: ${lastBeat.note})`)),
      );
      const watchdog = setInterval(() => {
        if (settled) {
          clearInterval(watchdog);
          return;
        }
        const stalled = Date.now() - lastBeat.at;
        if (stalled > stallTimeoutMs) {
          clearInterval(watchdog);
          reject(
            new Error(
              `harness stalled: no heartbeat for ${Math.round(stalled / 1000)}s ` +
                `(last: ${lastBeat.note})`,
            ),
          );
        }
      }, 5_000);
      watchdog.unref?.();
    });

    await page.goto(`http://127.0.0.1:${port}/`, { timeout: loadTimeoutMs });
    const outcome = await report.finally(() => {
      settled = true;
    });
    if (outcome.error) throw new Error(`in-page harness failed: ${outcome.error}`);
    return outcome;
  } finally {
    await browser.close();
    server.close();
  }
}
