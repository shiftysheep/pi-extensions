/**
 * Jev classifier benchmark (CLI).
 *
 * Evaluates the permission-gate's Jev danger classifier against the labeled set
 * in `classifier-benchmark-data.ts` and reports how well the model's verdicts
 * match expectations. This is a DEV/eval tool — it needs a real
 * TYPESAFE_API_KEY and network access, so it is NOT part of `npm test` or
 * `npm run check` (those must pass offline). The pure scoring/validation logic
 * lives in `classifier-benchmark-core.ts` and is unit-tested.
 *
 * Run:
 *   npm run benchmark:classifier
 *   npm run benchmark:classifier -- --model jev-latest --confirm 0.7 --deny 0.85 --concurrency 4
 *   npm run benchmark:classifier -- --json     # machine-readable
 *   npm run benchmark:classifier -- --view classifier   # classifier alone (no static backstop)
 *
 * Views (--view): "composed" (default) = the real gate (static rules first,
 * classifier on a miss — shows the true residual gaps; a static confirm
 * preempts the classifier, so the gate is non-monotonic); "classifier" = the
 * classifier alone (for model/prompt comparison); "both" = both.
 *
 * Expectations: benign → proceed, dangerous → confirm/deny, malicious → deny.
 * The run exits non-zero if any dangerous/malicious command is not handled as
 * expected (the safety-critical failures, including operational unavailability);
 * benign false-positives are reported but do not fail the run.
 */
import { parseArgs } from "node:util";
import {
  buildClassifierRequest,
  DEFAULT_CONFIRM_THRESHOLD,
  DEFAULT_DENY_THRESHOLD,
  DEFAULT_JEV_MODEL,
  decideClassifier,
  effectiveThresholds,
  parseClassifierProbs,
  TYPESAFE_API_KEY_ENV,
} from "../extensions/permission-gate/classifier.js";
import { callJev } from "../extensions/permission-gate/jev-client.js";
import {
  type BenchConfig,
  type BenchmarkSummary,
  type ComposedRow,
  type ComposedSummary,
  composedDecision,
  expectedPass,
  type Row,
  summarizeComposedRows,
  summarizeRows,
  validateBenchmarkArgs,
} from "./classifier-benchmark-core.js";
import { CASES } from "./classifier-benchmark-data.js";

function printHelp(): void {
  console.log(
    [
      "Usage: npm run benchmark:classifier -- [options]",
      "  --model <id>        Jev model id (default jev-latest)",
      "  --confirm <0-1>     confirm threshold (default 0.7)",
      "  --deny <0-1>        deny threshold (default 0.85)",
      "  --timeout <ms>      per-call timeout, 1..60000 (default 15000)",
      "  --concurrency <n>   parallel calls, positive integer (default 4)",
      "  --view <v>          composed (default) | classifier | both",
      "  --json              machine-readable output",
      "",
      "Requires TYPESAFE_API_KEY and network access.",
    ].join("\n"),
  );
}

/** Run every case through the classifier with a bounded concurrency pool. */
async function runCases(
  apiKey: string,
  config: BenchConfig,
  thresholds: { confirm: number; deny: number },
): Promise<Row[]> {
  const rows: Row[] = new Array(CASES.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < CASES.length) {
      const i = next++;
      const c = CASES[i];
      const result = await callJev(buildClassifierRequest(c.command, config.model, c.shell), {
        apiKey,
        timeoutMs: config.timeoutMs,
      });
      if (!result.ok) {
        rows[i] = {
          command: c.command,
          expect: c.expect,
          malicious: null,
          dangerous: null,
          verdict: "unavailable",
          pass: false,
        };
        continue;
      }
      const probs = parseClassifierProbs(result.body);
      if (!probs) {
        rows[i] = {
          command: c.command,
          expect: c.expect,
          malicious: null,
          dangerous: null,
          verdict: "malformed",
          pass: false,
        };
        continue;
      }
      const verdict = decideClassifier(probs, thresholds).action;
      rows[i] = {
        command: c.command,
        expect: c.expect,
        malicious: probs.malicious,
        dangerous: probs.dangerous,
        verdict,
        pass: expectedPass(c.expect, verdict),
      };
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(config.concurrency, CASES.length) }, () => worker()),
  );
  return rows;
}

function reportText(
  rows: Row[],
  summary: BenchmarkSummary,
  model: string,
  thresholds: { confirm: number; deny: number },
): void {
  const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
  console.log(
    `\nJev classifier benchmark — model=${model} confirm≥${thresholds.confirm} deny≥${thresholds.deny}\n`,
  );
  const header = `${"COMMAND".padEnd(52)} ${"EXPECT".padEnd(10)} ${"MAL".padStart(5)} ${"DANG".padStart(5)} ${"VERDICT".padEnd(11)} RESULT`;
  console.log(header);
  console.log("-".repeat(header.length));
  for (const r of rows) {
    const mal = r.malicious === null ? "-" : r.malicious.toFixed(2);
    const dang = r.dangerous === null ? "-" : r.dangerous.toFixed(2);
    console.log(
      `${trunc(r.command, 52).padEnd(52)} ${r.expect.padEnd(10)} ${mal.padStart(5)} ${dang.padStart(5)} ${r.verdict.padEnd(11)} ${r.pass ? "ok" : "XX"}`,
    );
  }

  const { benign, dangerous, malicious, unscored, totalPassed } = summary;
  console.log("\nSummary:");
  console.log(
    `  benign    ${benign.proceeded}/${benign.total} proceeded   (false positives: ${benign.flagged})`,
  );
  console.log(
    `  dangerous ${dangerous.flagged}/${dangerous.total} flagged   (missed: ${dangerous.proceeded})`,
  );
  console.log(
    `  malicious ${malicious.denied}/${malicious.total} denied    (missed: ${malicious.proceeded})`,
  );
  if (unscored > 0)
    console.log(`  (unscored unavailable/malformed: ${unscored} — not a model verdict)`);
  console.log(`  overall   ${totalPassed}/${rows.length} correct`);

  if (summary.missedCritical > 0) {
    console.log(
      `\n${summary.missedCritical} dangerous/malicious command(s) were not handled as expected.`,
    );
  }
}

/**
 * Print the composed (real-usage) view: each case routed by shell to its
 * static rules first, the classifier only on a miss. Shows which tier decided
 * each case and whether the final action matches the expectation.
 */
function reportComposed(
  rows: ComposedRow[],
  summary: ComposedSummary,
  model: string,
  thresholds: { confirm: number; deny: number },
): void {
  const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
  console.log(
    `\nComposed gate benchmark (static rules first, classifier on misses) — model=${model} confirm≥${thresholds.confirm} deny≥${thresholds.deny}\n`,
  );
  const header = `${"COMMAND".padEnd(52)} ${"SHELL".padEnd(11)} ${"EXPECT".padEnd(10)} ${"SRC".padEnd(11)} ${"RULE".padEnd(24)} ${"ACTION".padEnd(11)} RESULT`;
  console.log(header);
  console.log("-".repeat(header.length));
  for (const r of rows) {
    const src = r.source === "static" ? "static" : "classifier";
    const rule = r.rule ? trunc(r.rule, 24) : "-";
    console.log(
      `${trunc(r.command, 52).padEnd(52)} ${r.shell.padEnd(11)} ${r.expect.padEnd(10)} ${src.padEnd(11)} ${rule.padEnd(24)} ${r.action.padEnd(11)} ${r.pass ? "ok" : "XX"}`,
    );
  }

  const { benign, dangerous, malicious, staticHandled, classifierHandled, totalPassed } = summary;
  console.log("\nSummary (composed gate):");
  console.log(`  decided by: static rules ${staticHandled} · classifier ${classifierHandled}`);
  console.log(
    `  benign    ${benign.passed}/${benign.total} as expected   (not proceeded: ${benign.missed})`,
  );
  console.log(
    `  dangerous ${dangerous.passed}/${dangerous.total} as expected   (slipped: ${dangerous.missed})`,
  );
  console.log(
    `  malicious ${malicious.passed}/${malicious.total} as expected   (not denied: ${malicious.missed})`,
  );
  console.log(`  overall   ${totalPassed}/${rows.length} correct`);

  if (summary.missedCritical > 0) {
    console.log(
      `\n${summary.missedCritical} dangerous/malicious command(s) were not handled as expected in real usage.`,
    );
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      model: { type: "string", default: DEFAULT_JEV_MODEL },
      confirm: { type: "string", default: String(DEFAULT_CONFIRM_THRESHOLD) },
      deny: { type: "string", default: String(DEFAULT_DENY_THRESHOLD) },
      timeout: { type: "string", default: "15000" },
      concurrency: { type: "string", default: "4" },
      view: { type: "string", default: "composed" },
      json: { type: "boolean", default: false },
      help: { type: "boolean", default: false, short: "h" },
    },
  });

  if (values.help) {
    printHelp();
    return;
  }

  const validation = validateBenchmarkArgs({
    model: values.model,
    confirm: values.confirm,
    deny: values.deny,
    timeout: values.timeout,
    concurrency: values.concurrency,
  });
  if (!validation.ok) {
    console.error(validation.error);
    process.exit(2);
  }
  const config = validation.config;

  const view = values.view;
  if (view !== "composed" && view !== "classifier" && view !== "both") {
    console.error(`--view must be one of: composed, classifier, both (got "${view}")`);
    process.exit(2);
  }

  const rawKey = process.env[TYPESAFE_API_KEY_ENV];
  if (!rawKey) {
    console.error(`${TYPESAFE_API_KEY_ENV} is not set. Export it and re-run.`);
    process.exit(2);
  }
  const apiKey: string = rawKey;

  const thresholds = effectiveThresholds({
    classifierConfirmThreshold: config.confirm,
    classifierDenyThreshold: config.deny,
  });
  const rows = await runCases(apiKey, config, thresholds);
  const summary = summarizeRows(rows);

  // Composed (real-usage) view: static rules first, classifier only on a miss.
  const composedRows: ComposedRow[] = rows.map((r, i) => {
    const c = CASES[i];
    const d = composedDecision(c.shell, c.command, r.verdict);
    return {
      command: c.command,
      shell: c.shell,
      expect: c.expect,
      source: d.source,
      rule: d.rule,
      action: d.action,
      pass: expectedPass(c.expect, d.action),
    };
  });
  const composedSummary = summarizeComposedRows(composedRows);

  // Set the exit status BEFORE choosing output format, so --json failures are
  // reported the same way as text failures. The "classifier" view uses the
  // classifier-alone misses; "composed"/"both" use the real-usage (composed)
  // misses — the faithful safety measure.
  const exitMissed =
    view === "classifier" ? summary.missedCritical : composedSummary.missedCritical;
  if (exitMissed > 0) process.exitCode = 1;

  if (values.json) {
    console.log(
      JSON.stringify(
        {
          model: config.model,
          thresholds,
          view,
          composed: { summary: composedSummary, rows: composedRows },
          classifier: { summary, rows },
        },
        null,
        2,
      ),
    );
    return;
  }
  if (view === "composed" || view === "both")
    reportComposed(composedRows, composedSummary, config.model, thresholds);
  if (view === "classifier" || view === "both") reportText(rows, summary, config.model, thresholds);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
