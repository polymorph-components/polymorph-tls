// The browser-safe core of the JS runners: static tag inventory
// (custom sections of transpiled core wasm), mark scheduling against a
// target's missing-features, and the per-case run loop producing
// results-JSONL event objects. Shared by the viewer page's live-run
// Web Workers (worker.mjs), the Node selftest (selftest.mjs), and —
// per the one-harness rule (#5) — any future gating jco adapter: the
// gate and the page must not drift.
//
// Browser-safe by construction: no Node builtins; callers supply the
// core-wasm bytes and the transpiled suite module.

import { Context } from "./context.js";

export const TAGS_SECTION = "component-test:tags@0.1";

/** Custom sections named `wanted` from a core wasm module's bytes. */
export function customSections(bytes, wanted) {
  // core-module format: 4-byte magic, 4-byte version, then sections.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let out = [];
  let off = 8;
  const uleb = () => {
    let result = 0, shift = 0, byte;
    do {
      byte = view.getUint8(off++);
      result |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    return result;
  };
  while (off < bytes.length) {
    const id = view.getUint8(off++);
    const size = uleb();
    const end = off + size;
    if (id === 0) {
      const start = off;
      const nameLen = uleb();
      const name = new TextDecoder().decode(bytes.subarray(off, off + nameLen));
      off += nameLen;
      if (name === wanted) out.push(bytes.subarray(off, end));
      off = start; // reset; jump via size below
    }
    off = end;
  }
  return out;
}

/**
 * Build the case-name → tags lookup from the tag inventory sections of
 * the given core modules' bytes. Throws if no inventory is found.
 * @param {Uint8Array[]} coreModules
 * @returns {(name: string) => string[] | undefined}
 */
export function inventoryLookup(coreModules) {
  const records = [];
  for (const bytes of coreModules) {
    for (const section of customSections(bytes, TAGS_SECTION)) {
      for (const line of new TextDecoder().decode(section).split("\n")) {
        if (!line.trim()) continue;
        const [name, ...tags] = line.split(" ").filter(Boolean);
        records.push({ name, tags });
      }
    }
  }
  if (records.length === 0) throw new Error("no tag inventory found in core wasm");
  const exact = new Map();
  const prefixes = [];
  for (const r of records) {
    if (r.name.endsWith("/*")) prefixes.push({ prefix: r.name.slice(0, -2), tags: r.tags });
    else exact.set(r.name, r.tags);
  }
  prefixes.sort((a, b) => b.prefix.length - a.prefix.length); // longest first
  return (name) => {
    if (exact.has(name)) return exact.get(name);
    const hit = prefixes.find((p) => name.startsWith(p.prefix + "/"));
    return hit ? hit.tags : undefined;
  };
}

/** Whether a case with these tags applies given the missing-features. */
export function applies(tags, missing) {
  return tags.every((t) =>
    t.startsWith("!") ? missing.includes(t.slice(1)) : !missing.includes(t)
  );
}

/**
 * The results-JSONL envelope line for one target × suite run. The
 * suite name is normalized to the lockfile identity — the wasm file
 * stem, underscores — so callers can pass the kebab-case package name
 * as-is.
 */
export function envelope(target, suite) {
  return {
    "component-test-results": "0.1",
    target,
    suite: { name: suite.replaceAll("-", "_") },
    run: { segment: 0 },
  };
}

/**
 * Run the suite's case loop: mark scheduling against `missing`, one
 * results-JSONL event object per case through `emit` (including the
 * not-applicable rows). Thrown on inventory drift (a case no tags
 * record covers) — the run is unsound, not failing.
 *
 * `shard` selects a stripe of the suite (case `i` belongs to shard
 * `i % count`), letting several workers — each with its own instance
 * of the transpiled suite — run disjoint slices concurrently. Striping
 * balances load better than contiguous chunks: expensive cases cluster
 * by group. The default runs everything. `emit` receives the case's
 * suite-order index alongside the event so a sharded consumer can
 * restore suite order.
 *
 * The gating-adapter options (#50), both opt-in:
 *
 * `freshCases` gives every case a fresh instance: census and striping
 * still come from `cases`, but each execution re-enumerates from the
 * factory and runs the matching case (a vanished case throws — drift,
 * unsound, not a failing case). For instantiation-mode transpiles this
 * is the wasmtime runner's instance-per-case granularity; module-mode
 * transpiles are singletons and cannot use it.
 *
 * `caseTimeoutMs` is the per-case wall bound (the runner's
 * `--case-timeout`): on expiry the case fails with
 * `{"limit-exceeded":"case-timeout"}` provenance and the loop moves
 * on. JSPI attempts cannot be cancelled — the abandoned attempt keeps
 * running until its instance is dropped, so pair this with
 * `freshCases` (a timed-out shared instance may be wedged
 * mid-suspension, poisoning every later case).
 *
 * `name()` may be Promise-shaped: deltic's embedder exports are
 * uniformly async (contracts/embedder-api.md "Functions and async"),
 * while jco sync-lifted exports return plain values; awaiting a plain
 * value is a no-op, so this loop is host-agnostic.
 *
 * @param {object} options
 * @param {Array} options.cases  `tests.all()` from the transpiled suite.
 * @param {new (onDiagnostic: (msg: string) => void) => object} options.Context
 * @param {(name: string) => string[] | undefined} options.tagsOf
 * @param {string[]} options.missing
 * @param {string} [options.only]  Substring filter (skips emit entirely).
 * @param {(event: object, index: number) => void} options.emit
 * @param {{ index: number, count: number }} [options.shard]
 * @param {() => Promise<Array>} [options.freshCases]
 * @param {number} [options.caseTimeoutMs]
 * @returns {Promise<{passed, failed, skipped, na, total}>}
 */
export async function runCases({
  cases,
  Context,
  tagsOf,
  missing,
  only,
  emit,
  shard,
  freshCases,
  caseTimeoutMs,
}) {
  const { index: shardIndex, count: shardCount } = shard ?? { index: 0, count: 1 };
  let passed = 0, failed = 0, skipped = 0, na = 0, total = 0;
  for (const [caseIndex, testCase] of cases.entries()) {
    if (caseIndex % shardCount !== shardIndex) continue;
    total++;
    const name = String(await testCase.name());
    if (only && !name.includes(only)) continue;
    const tags = tagsOf(name);
    if (tags === undefined) {
      throw new Error(`inventory drift: no tags record covers ${name}`);
    }
    if (!applies(tags, missing)) {
      na++;
      const excluding = tags.find((t) =>
        t.startsWith("!") ? !missing.includes(t.slice(1)) : missing.includes(t)
      );
      emit({ case: name, status: "not-applicable", detail: excluding ?? "" }, caseIndex);
      continue;
    }
    let executed = testCase;
    if (freshCases) {
      const fresh = await freshCases();
      executed = undefined;
      for (const c of fresh) {
        if (String(await c.name()) === name) {
          executed = c;
          break;
        }
      }
      if (!executed) {
        throw new Error(`case ${name} vanished on re-enumeration`);
      }
    }
    const diags = [];
    const ctx = new Context((msg) => diags.push(msg));
    let event;
    try {
      const attempt = executed.run(ctx);
      let timedOut = false;
      if (caseTimeoutMs) {
        let timer;
        timedOut = await Promise.race([
          attempt.then(() => false),
          new Promise((resolve) => {
            timer = setTimeout(() => resolve(true), caseTimeoutMs);
          }),
        ]).finally(() => clearTimeout(timer));
      } else {
        await attempt;
      }
      if (timedOut) {
        failed++;
        event = {
          case: name,
          status: "fail",
          provenance: { "limit-exceeded": "case-timeout" },
          detail: `case timeout exceeded (${caseTimeoutMs / 1000}s)`,
          "diagnostics-complete": false,
        };
      } else {
        passed++;
        event = { case: name, status: "pass", provenance: "returned" };
      }
    } catch (e) {
      const payload = e?.payload ?? e;
      if (payload?.tag === "failed") {
        failed++;
        event = { case: name, status: "fail", provenance: "returned", detail: payload.val };
      } else if (payload?.tag === "skipped") {
        skipped++;
        event = { case: name, status: "skipped", provenance: "returned", detail: payload.val };
      } else {
        failed++;
        event = {
          case: name,
          status: "fail",
          provenance: "trap",
          detail: `trap: ${e?.message ?? e}`,
          "diagnostics-complete": false,
        };
      }
    }
    if (diags.length > 0) event.diagnostics = diags;
    emit(event, caseIndex);
  }
  return { passed, failed, skipped, na, total };
}

/** Merge per-shard `runCases` counts (shards partition the suite). */
export function mergeCounts(parts) {
  const out = { passed: 0, failed: 0, skipped: 0, na: 0, total: 0 };
  for (const c of parts) {
    out.passed += c.passed;
    out.failed += c.failed;
    out.skipped += c.skipped;
    out.na += c.na;
    out.total += c.total;
  }
  return out;
}

/** The worker-pool size for a machine (capped: instances are heavy). */
export function workerCount(available) {
  return Math.max(1, Math.min(available ?? 1, 8));
}

/**
 * The suite's `tests` interface from an instantiated component,
 * whichever spelling the transpile used. Throws with the instance's
 * export names when none matches.
 */
export function resolveTestsExport(instance) {
  const tests =
    instance.tests ?? instance["polymorph:test/tests@0.1.0"] ?? instance["polymorph:test/tests"];
  if (!tests) {
    throw new Error(`suite instance exports no tests interface: ${Object.keys(instance)}`);
  }
  return tests;
}

/**
 * Run one suite's whole case loop and emit a complete results-JSONL
 * stream: envelope, one serialized event per case, terminator. The
 * sequential-driver shape shared by the consumers' Node legs and
 * browser workers; pool topologies compose [`runCases`] +
 * [`mergeCounts`] directly instead.
 *
 * Browser-safe: the caller supplies instantiation and I/O.
 *
 * - `newTests`: async () => the suite's tests interface on a *fresh*
 *   instance. Called once for the census and — with `freshCases`, the
 *   default — once per case: JSPI attempts cannot be cancelled, so a
 *   timed-out case's instance may be wedged mid-suspension, and a
 *   fresh instance per case also contains trap poisoning.
 * - `suiteName` may be the kebab-case transpile name; the envelope
 *   normalizes to the lockfile identity.
 * - `emit(line, index?)` receives each JSONL line (the envelope and
 *   terminator carry no index).
 * - `Context` defaults to the upstream provider; a driver with its own
 *   diagnostic transport passes its class.
 *
 * Returns [`runCases`]' counts. Throws when the census is empty (an
 * empty selection is a run error, per the results contract).
 */
export async function runSuiteJsonl({
  newTests,
  tagsOf,
  target,
  suiteName,
  missing = [],
  only,
  shard,
  emit,
  caseTimeoutMs,
  freshCases = true,
  Context: ContextClass = Context,
  log,
}) {
  emit(JSON.stringify(envelope(target, suiteName)));
  const counts = await runCases({
    cases: await (await newTests()).all(),
    Context: ContextClass,
    tagsOf,
    missing,
    only,
    shard,
    emit: (event, index) => {
      emit(JSON.stringify(event), index);
      log?.(`${event.case} … ${event.status}`);
    },
    caseTimeoutMs,
    ...(freshCases ? { freshCases: async () => (await newTests()).all() } : {}),
  });
  if (counts.total === 0) {
    throw new Error("suite enumerated zero cases (empty selection is a run error)");
  }
  emit('{"segment-end":true}');
  return counts;
}
