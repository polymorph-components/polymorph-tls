// The in-page pool runner for jco-transpiled suites (#59's browser
// half): for each configured suite, stripes the case loop over a pool
// of module Web Workers (browser-worker.mjs), restores suite order,
// and reports one results payload per suite through the page driver's
// `__report`, heartbeating `__progress` as rows stream in.
//
// Loaded by the driver-built harness page (see ./browser-driver's
// buildHarnessPage); browser-safe.

import { envelope, mergeCounts, workerCount } from "./harness.mjs";

const beat = (note) => {
  try {
    window.__progress(note)?.catch?.(() => {});
  } catch {
    // A closing page must not turn a heartbeat into an unhandled rejection.
  }
};

/** One shard of one suite: a fresh worker running its stripe to
 *  completion. Workers are per-shard (not reused across suites) so
 *  each suite gets fresh instances. */
function runShard(workerUrl, config, shard, onRow) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerUrl, { type: "module" });
    const events = [];
    worker.onmessage = ({ data }) => {
      if (data.kind === "event") {
        events.push(data);
        onRow(data);
      } else if (data.kind === "counts") {
        worker.terminate();
        resolve({ events, counts: data.counts });
      } else {
        worker.terminate();
        reject(new Error(`worker (shard ${shard.index}): ${data.error}`));
      }
    };
    worker.onerror = (e) => {
      worker.terminate();
      reject(new Error(`worker (shard ${shard.index}): ${e.message ?? e}`));
    };
    worker.postMessage({ ...config, shard });
  });
}

/**
 * Run every configured suite and report, keyed by each entry's `key`
 * (default: its `target`). Neither `suite` nor `target` is unique on
 * its own across consumers — one suite may run as several targets (a
 * plain and a delegated composition), and one target may run several
 * suites (a main and a signing corpus) — so the caller owns the key.
 * `suites` entries carry the browser-worker run message minus `shard`
 * (moduleUrl, coreUrls, importsUrl, contextUrl?, env?, missing?,
 * only?, caseTimeoutMs?) plus `suite` (the results identity in the
 * envelope) and `target`. `jobs` defaults to the capped hardware
 * parallelism; pass 1 for sequential corpora.
 */
export async function runSuitesInPage({ workerUrl, suites, jobs }) {
  const pool = jobs ?? workerCount(navigator.hardwareConcurrency ?? 4);
  let rows = 0;
  try {
    const out = {};
    for (const { suite, target, key = target, ...config } of suites) {
      beat(`suite ${suite}: ${pool} workers`);
      const shards = await Promise.all(
        Array.from({ length: pool }, (_, index) =>
          runShard(workerUrl, config, { index, count: pool }, (data) => {
            rows += 1;
            if (rows % 25 === 0) beat(`row ${rows}: ${data.event.case}`);
          }),
        ),
      );
      const events = shards.flatMap((s) => s.events);
      events.sort((a, b) => a.index - b.index);
      out[key] = {
        lines: [
          JSON.stringify(envelope(target, suite)),
          ...events.map((e) => JSON.stringify(e.event)),
          '{"segment-end":true}',
        ],
        counts: mergeCounts(shards.map((s) => s.counts)),
      };
    }
    window.__report(out);
  } catch (err) {
    window.__report({ error: String(err?.stack ?? err) });
  }
}
