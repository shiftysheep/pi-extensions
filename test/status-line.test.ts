import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import statusLine, {
  addSubagentTotals,
  createStreamState,
  createSubagentTotals,
  extractSubagentMeta,
  formatSubagentCost,
  formatTokenCount,
  formatTokensPerSecond,
  formatWorkingMessage,
  providerTokensPerSecond,
  recordOutputDelta,
} from "../extensions/status-line.js";

test("does not report a live rate before the stream is meaningful", () => {
  const state = createStreamState();

  recordOutputDelta(state, "12345678", 1_000);
  assert.equal(state.messageStartTime, 1_000);
  assert.equal(state.firstOutputTime, 1_000);
  assert.equal(state.liveTokensPerSecond, null);

  recordOutputDelta(state, "x", 1_200);
  assert.equal(state.liveTokensPerSecond, null);
});

test("estimates live throughput from UTF-8 output bytes", () => {
  const state = createStreamState();

  recordOutputDelta(state, "😀😀😀😀😀😀😀😀", 1_000);
  const rate = recordOutputDelta(state, "😀😀😀😀😀😀😀😀", 2_000);

  assert.equal(state.outputBytes, 64);
  assert.equal(rate, 16);
  assert.equal(state.liveTokensPerSecond, 16);
});

test("provider throughput includes the complete assistant message duration", () => {
  const state = createStreamState();
  state.messageStartTime = 10_000;

  assert.equal(providerTokensPerSecond(state, 12_000, 100), 50);
  assert.equal(providerTokensPerSecond(state, 10_100, 100), null);
  assert.equal(providerTokensPerSecond(state, 12_000, 100, "aborted"), null);
  assert.equal(providerTokensPerSecond(state, 12_000, 100, "error"), null);
  assert.equal(providerTokensPerSecond(state, 12_000, 0), null);
});

test("formats live and provider-confirmed rates distinctly", () => {
  assert.equal(formatTokensPerSecond(42), "≈42 tok/s");
  assert.equal(formatTokensPerSecond(42, true), "42 tok/s*");
  assert.equal(formatTokensPerSecond(0.5), null);
  assert.equal(formatTokensPerSecond(Number.NaN), null);
  assert.equal(formatWorkingMessage(null), "Working...");
  assert.equal(formatWorkingMessage(50), "Working... ≈50 tok/s");
  assert.equal(formatWorkingMessage(50, true), "Working... 50 tok/s*");
});

test("extractSubagentMeta parses names and bodies, rejecting malformed input", () => {
  const runId = "11111111-2222-3333-4444-555555555555";
  // Producer-shaped fixture: pi-subagents writes usage.cost as a NUMBER.
  const ok = extractSubagentMeta(`${runId}_worker_meta.json`, {
    timestamp: 123,
    usage: { input: 1, output: 2, cacheRead: 3, cacheWrite: 4, cost: 0.5, turns: 2 },
  });
  assert.deepEqual(ok, {
    runId,
    completedAt: 123,
    totals: { input: 1, output: 2, cacheRead: 3, cacheWrite: 4, cost: 0.5 },
  });
  // A { total } object cost is tolerated.
  const objectCost = extractSubagentMeta(`${runId}_worker_meta.json`, {
    usage: { input: 0, output: 0, cost: { total: 1.5 } },
  });
  assert.equal(objectCost?.totals.cost, 1.5);
  assert.equal(objectCost?.completedAt, null);
  assert.equal(extractSubagentMeta("no-run-id_meta.json", {}), null);
  assert.equal(extractSubagentMeta(`${runId}_worker.json`, {}), null);
  assert.equal(extractSubagentMeta(`${runId}_worker_meta.json`, "nope"), null);
  const partial = extractSubagentMeta(`${runId}_worker_meta.json`, { usage: { output: "x" } });
  assert.equal(partial?.completedAt, null);
  assert.equal(partial?.totals.output, 0);
  assert.equal(partial?.totals.cost, 0);
});

test("addSubagentTotals accumulates into the receiver", () => {
  const acc = createSubagentTotals();
  addSubagentTotals(acc, { input: 1, output: 2, cacheRead: 3, cacheWrite: 4, cost: 0.5 });
  addSubagentTotals(acc, { input: 9, output: 8, cacheRead: 7, cacheWrite: 6, cost: 0.25 });
  assert.deepEqual(acc, { input: 10, output: 10, cacheRead: 10, cacheWrite: 10, cost: 0.75 });
});

test("formatSubagentCost and formatTokenCount", () => {
  assert.equal(
    formatSubagentCost({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0 }),
    null,
  );
  assert.equal(
    formatSubagentCost({ input: 100, output: 200, cacheRead: 0, cacheWrite: 0, cost: 0.1234 }),
    "300 tok $0.123",
  );
  assert.equal(
    formatSubagentCost({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 2 }),
    "$2.000",
  );
  assert.equal(formatTokenCount(999), "999");
  assert.equal(formatTokenCount(1234), "1.2k");
  assert.equal(formatTokenCount(15000), "15k");
  assert.equal(formatTokenCount(2_345_678), "2.3M");
});

test("shows the async subagent total from artifact meta files in the footer status", () => {
  const dir = mkdtempSync(join(tmpdir(), "pi-status-line-"));
  const artDir = join(dir, "subagent-artifacts");
  mkdirSync(artDir, { recursive: true });
  const runId = "11111111-2222-3333-4444-555555555555";
  const afterSession = Date.parse("2026-01-02T00:00:00Z");
  const beforeSession = Date.parse("2025-12-31T12:00:00Z");
  try {
    // Multi-step run: two meta files share the runId; BOTH steps count.
    writeFileSync(
      join(artDir, `${runId}_worker_0_meta.json`),
      JSON.stringify({
        timestamp: afterSession,
        usage: { input: 100, output: 200, cacheRead: 0, cacheWrite: 0, cost: 0.1, turns: 1 },
      }),
    );
    writeFileSync(
      join(artDir, `${runId}_worker_1_meta.json`),
      JSON.stringify({
        timestamp: afterSession,
        usage: { input: 50, output: 50, cacheRead: 0, cacheWrite: 0, cost: 0.0234, turns: 1 },
      }),
    );
    // A run completed before this session must not be counted.
    writeFileSync(
      join(artDir, "99999999-2222-3333-4444-555555555555_worker_meta.json"),
      JSON.stringify({
        timestamp: beforeSession,
        usage: { input: 5, output: 5, cost: 1, turns: 1 },
      }),
    );
    // A meta without a timestamp must not be counted (unknown completion).
    writeFileSync(
      join(artDir, "88888888-2222-3333-4444-555555555555_worker_meta.json"),
      JSON.stringify({ usage: { input: 7, output: 7, cost: 1, turns: 1 } }),
    );
    // Malformed meta and non-meta artifacts are skipped without crashing.
    writeFileSync(
      join(artDir, "77777777-2222-3333-4444-555555555555_worker_meta.json"),
      "not json",
    );
    writeFileSync(join(artDir, `${runId}_worker_0_transcript.jsonl`), "not json either");

    const handlers = new Map<string, (event: any, ctx: any) => void>();
    const statuses: Array<[string, string | undefined]> = [];
    statusLine({
      on(name: string, handler: (event: any, ctx: any) => void) {
        handlers.set(name, handler);
      },
    } as any);

    const ctx = {
      mode: "tui",
      sessionManager: {
        getSessionDir: () => dir,
        getEntries: () => [{ timestamp: "2026-01-01T00:00:00Z" }],
      },
      ui: {
        theme: {
          fg(_color: string, text: string) {
            return text;
          },
          bold(text: string) {
            return text;
          },
        },
        setWorkingMessage() {},
        setWidget() {},
        setStatus(key: string, text: string | undefined) {
          statuses.push([key, text]);
        },
      },
    };

    handlers.get("session_start")?.({}, ctx);
    assert.deepEqual(statuses.at(-1), ["subagents", undefined]);

    handlers.get("agent_end")?.({}, ctx);
    // 100+200+50+50 = 400 tok; 0.1 + 0.0234 = $0.123 (both steps counted).
    assert.deepEqual(statuses.at(-1), ["subagents", "[ subagents · 400 tok $0.123 ]"]);

    // Throttled: a second scan within the window adds nothing new.
    handlers.get("agent_end")?.({}, ctx);
    assert.deepEqual(statuses.at(-1), ["subagents", "[ subagents · 400 tok $0.123 ]"]);

    handlers.get("session_shutdown")?.({}, ctx);
    assert.deepEqual(statuses.at(-1), ["subagents", undefined]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("updates the animated working message in the TUI and leaves other modes inert", () => {
  const handlers = new Map<string, (event: any, ctx: any) => void>();
  const workingMessages: Array<string | undefined> = [];
  const widgets: Array<[string, string[] | undefined]> = [];
  statusLine({
    on(name: string, handler: (event: any, ctx: any) => void) {
      handlers.set(name, handler);
    },
  } as any);

  const context = (mode: "tui" | "rpc") => ({
    mode,
    ui: {
      theme: {
        fg(_color: string, text: string) {
          return text;
        },
        bold(text: string) {
          return text;
        },
      },
      setWorkingMessage(message?: string) {
        workingMessages.push(message);
      },
      setWidget(key: string, content: string[] | undefined) {
        widgets.push([key, content]);
      },
      setStatus() {},
    },
  });
  const assistantStart = { message: { role: "assistant" } };
  const assistantUpdate = {
    assistantMessageEvent: { type: "text_delta", delta: "😀😀😀😀😀😀😀😀" },
  };
  const assistantEnd = {
    message: { role: "assistant", usage: { output: 100 }, stopReason: "stop" },
  };
  const originalNow = Date.now;

  try {
    Date.now = () => 1_000;
    handlers.get("session_start")?.({}, context("rpc"));
    handlers.get("message_start")?.(assistantStart, context("rpc"));
    handlers.get("message_update")?.(assistantUpdate, context("rpc"));
    handlers.get("agent_end")?.({}, context("rpc"));
    assert.deepEqual(workingMessages, []);
    assert.deepEqual(widgets, []);

    Date.now = () => 2_000;
    handlers.get("session_start")?.({}, context("tui"));
    handlers.get("message_start")?.(assistantStart, context("tui"));
    handlers.get("message_update")?.(assistantUpdate, context("tui"));

    Date.now = () => 3_000;
    handlers.get("message_update")?.(assistantUpdate, context("tui"));
    assert.equal(workingMessages.at(-1), "[ response speed · ≈16 tok/s ]");

    Date.now = () => 4_000;
    handlers.get("message_end")?.(assistantEnd, context("tui"));
    assert.equal(workingMessages.at(-1), "[ response speed · 50 tok/s* ]");

    handlers.get("agent_end")?.({}, context("tui"));
    assert.deepEqual(widgets.at(-1), ["status-line", ["[ response speed · 50 tok/s* ]"]]);

    handlers.get("agent_start")?.({}, context("tui"));
    assert.deepEqual(widgets.at(-1), ["status-line", undefined]);

    handlers.get("message_start")?.(assistantStart, context("tui"));
    handlers.get("message_end")?.(
      { message: { role: "assistant", stopReason: "stop" } },
      context("tui"),
    );

    handlers.get("session_shutdown")?.({}, context("tui"));
    assert.equal(workingMessages.at(-1), undefined);
    assert.deepEqual(widgets.at(-1), ["status-line", undefined]);
  } finally {
    Date.now = originalNow;
  }
});
