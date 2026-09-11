import assert from "node:assert/strict";
import test from "node:test";

import statusLine, {
  createStreamState,
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
    assert.deepEqual(widgets.at(-1), [
      "status-line-tokens-per-second",
      ["[ response speed · 50 tok/s* ]"],
    ]);

    handlers.get("agent_start")?.({}, context("tui"));
    assert.deepEqual(widgets.at(-1), ["status-line-tokens-per-second", undefined]);

    handlers.get("message_start")?.(assistantStart, context("tui"));
    handlers.get("message_end")?.(
      { message: { role: "assistant", stopReason: "stop" } },
      context("tui"),
    );

    handlers.get("session_shutdown")?.({}, context("tui"));
    assert.equal(workingMessages.at(-1), undefined);
    assert.deepEqual(widgets.at(-1), ["status-line-tokens-per-second", undefined]);
  } finally {
    Date.now = originalNow;
  }
});
