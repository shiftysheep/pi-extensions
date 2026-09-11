/**
 * Pi working indicator with a live and provider-confirmed output
 * tokens-per-second rate, plus a session total for ASYNC subagent runs.
 *
 * The extension updates Pi's built-in animated working indicator rather than
 * replacing the footer. This keeps the extension independent of footer
 * internals as Pi's UI evolves.
 *
 * Subagent costs: SYNC subagent runs are already counted in the built-in
 * footer (pi-subagents sets an aggregated top-level `usage` on the tool
 * result, which the footer sums). ASYNC runs are not: their usage only lands
 * in {sessionDir}/subagent-artifacts/{runId}_{agent}_meta.json. We scan those
 * (throttled, deduped by runId, only runs started after this session) and
 * show the total as a second widget line, mirroring the rate badge.
 */

import * as fs from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

export const MIN_STREAM_MS = 250;
export const DEFAULT_WORKING_MESSAGE = "Working...";
const WIDGET_KEY = "status-line";
const SUBAGENT_SCAN_MS = 2000; // artifacts dir is rescanned at most this often
const RUN_ID_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_/i;
const UTF8_ENCODER = new TextEncoder();

export interface StreamState {
  messageStartTime: number | null;
  firstOutputTime: number | null;
  outputBytes: number;
  liveTokensPerSecond: number | null;
}

export function createStreamState(): StreamState {
  return {
    messageStartTime: null,
    firstOutputTime: null,
    outputBytes: 0,
    liveTokensPerSecond: null,
  };
}

/** Record one streamed text, thinking, or tool-call delta. */
export function recordOutputDelta(
  state: StreamState,
  delta: string,
  now = Date.now(),
): number | null {
  if (delta.length === 0) return state.liveTokensPerSecond;

  state.messageStartTime ??= now;
  state.firstOutputTime ??= now;
  state.outputBytes += UTF8_ENCODER.encode(delta).byteLength;

  const estimatedTokens = state.outputBytes / 4;
  const elapsedMs = now - state.firstOutputTime;
  if (estimatedTokens < 8 || elapsedMs < MIN_STREAM_MS) {
    state.liveTokensPerSecond = null;
    return null;
  }

  state.liveTokensPerSecond = estimatedTokens / (elapsedMs / 1_000);
  return state.liveTokensPerSecond;
}

/**
 * Calculate a final rate from the provider's output count and full message
 * duration. Tool time after message_end is therefore excluded naturally.
 */
export function providerTokensPerSecond(
  state: StreamState,
  endedAt: number,
  outputTokens: number,
  stopReason?: string,
): number | null {
  if (
    state.messageStartTime === null ||
    stopReason === "aborted" ||
    stopReason === "error" ||
    !Number.isFinite(outputTokens) ||
    outputTokens <= 0
  ) {
    return null;
  }

  const elapsedMs = endedAt - state.messageStartTime;
  if (elapsedMs < MIN_STREAM_MS) return null;

  return outputTokens / (elapsedMs / 1_000);
}

export function formatTokensPerSecond(
  rate: number | null,
  providerConfirmed = false,
): string | null {
  if (rate === null || !Number.isFinite(rate) || rate <= 0.5) return null;
  return `${providerConfirmed ? "" : "≈"}${Math.round(rate)} tok/s${providerConfirmed ? "*" : ""}`;
}

export function formatWorkingMessage(rate: number | null, providerConfirmed = false): string {
  const formattedRate = formatTokensPerSecond(rate, providerConfirmed);
  return formattedRate ? `${DEFAULT_WORKING_MESSAGE} ${formattedRate}` : DEFAULT_WORKING_MESSAGE;
}

/** Token/cost totals accumulated from async subagent artifact meta files. */
export interface SubagentTotals {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  cost: number;
}

export function createSubagentTotals(): SubagentTotals {
  return { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0 };
}

/**
 * Parse one artifact meta file: the run id comes from the file name
 * ({runId}_{agent}_meta.json), the start time and usage from the JSON body.
 * Malformed names/bodies yield null (skipped, never thrown).
 */
export function extractSubagentMeta(
  fileName: string,
  meta: unknown,
): { runId: string; startedAt: number | null; totals: SubagentTotals } | null {
  if (!fileName.endsWith("_meta.json")) return null;
  const m = fileName.match(RUN_ID_RE);
  if (!m) return null;
  if (typeof meta !== "object" || meta === null) return null;
  const usage = (meta as { usage?: unknown }).usage;
  const u = typeof usage === "object" && usage !== null ? (usage as Record<string, unknown>) : {};
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  const costObj = (u.cost ?? {}) as Record<string, unknown>;
  return {
    runId: m[1],
    startedAt:
      typeof (meta as { timestamp?: unknown }).timestamp === "number"
        ? ((meta as { timestamp: number }).timestamp as number)
        : null,
    totals: {
      input: num(u.input),
      output: num(u.output),
      cacheRead: num(u.cacheRead),
      cacheWrite: num(u.cacheWrite),
      cost: num(costObj.total),
    },
  };
}

/** Add one run's totals into an accumulator (mutates `acc`). */
export function addSubagentTotals(acc: SubagentTotals, add: SubagentTotals): void {
  acc.input += add.input;
  acc.output += add.output;
  acc.cacheRead += add.cacheRead;
  acc.cacheWrite += add.cacheWrite;
  acc.cost += add.cost;
}

/** Compact token count: 1234 -> "1.2k", 2_345_678 -> "2.3M". */
export function formatTokenCount(count: number): string {
  if (count < 1000) return count.toString();
  if (count < 10000) return `${(count / 1000).toFixed(1)}k`;
  if (count < 1000000) return `${Math.round(count / 1000)}k`;
  if (count < 10000000) return `${(count / 1000000).toFixed(1)}M`;
  return `${Math.round(count / 1000000)}M`;
}

/** Badge text for the async subagent total, or null when nothing to show. */
export function formatSubagentCost(totals: SubagentTotals): string | null {
  const tokens = totals.input + totals.output + totals.cacheRead + totals.cacheWrite;
  if (tokens <= 0 && totals.cost <= 0) return null;
  const parts: string[] = [];
  if (tokens > 0) parts.push(`${formatTokenCount(tokens)} tok`);
  if (totals.cost > 0) parts.push(`$${totals.cost.toFixed(3)}`);
  return parts.join(" ");
}

export default function statusLine(pi: ExtensionAPI): void {
  let stream = createStreamState();
  let lastTokensPerSecond: number | null = null;
  let lastDisplayedRate: { rate: number; providerConfirmed: boolean } | null = null;
  let tuiEnabled = false;

  // Async subagent cost accumulation (artifact meta scan).
  let subagentTotals = createSubagentTotals();
  const countedRunIds = new Set<string>();
  let subagentScanAt = 0;
  let sessionStartMs: number | null = null;
  let sessionDir: string | undefined;

  function resetSubagentTracking(): void {
    subagentTotals = createSubagentTotals();
    countedRunIds.clear();
    subagentScanAt = 0;
    sessionStartMs = null;
    sessionDir = undefined;
  }

  /** Rescan the per-cwd subagent-artifacts dir (throttled) and fold in any
   *  completed async runs started after this session, deduped by runId. */
  function refreshSubagentTotals(ctx: ExtensionContext): void {
    const now = Date.now();
    if (now - subagentScanAt < SUBAGENT_SCAN_MS) return;
    subagentScanAt = now;
    try {
      const sm = ctx.sessionManager;
      sessionDir ??= sm.getSessionDir();
      if (sessionStartMs === null) {
        // The artifacts dir is shared by all sessions in this cwd, so only
        // count runs started at or after this session's first entry.
        const first = sm.getEntries()[0];
        const t = first?.timestamp;
        sessionStartMs = typeof t === "string" && !Number.isNaN(Date.parse(t)) ? Date.parse(t) : 0;
      }
      const artDir = join(sessionDir, "subagent-artifacts");
      for (const name of fs.readdirSync(artDir)) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(fs.readFileSync(join(artDir, name), "utf8"));
        } catch {
          continue; // unreadable/partial meta: skip
        }
        const meta = extractSubagentMeta(name, parsed);
        if (!meta || countedRunIds.has(meta.runId)) continue;
        if (meta.startedAt !== null && meta.startedAt < sessionStartMs) continue;
        countedRunIds.add(meta.runId);
        addSubagentTotals(subagentTotals, meta.totals);
      }
    } catch {
      /* no artifacts dir (or unreadable): nothing to add */
    }
  }

  function setWorkingMessage(ctx: ExtensionContext, message?: string): void {
    if (tuiEnabled && ctx.mode === "tui") ctx.ui.setWorkingMessage(message);
  }

  function formatBadge(ctx: ExtensionContext, label: string, text: string): string {
    const theme = ctx.ui.theme;
    return [
      theme.fg("muted", "[ "),
      theme.fg("accent", label),
      theme.fg("muted", " · "),
      theme.bold(theme.fg("success", text)),
      theme.fg("muted", " ]"),
    ].join("");
  }

  function setWorkingRate(
    ctx: ExtensionContext,
    rate: number | null,
    providerConfirmed = false,
  ): void {
    const text = formatTokensPerSecond(rate, providerConfirmed);
    setWorkingMessage(
      ctx,
      text === null ? DEFAULT_WORKING_MESSAGE : formatBadge(ctx, "response speed", text),
    );
  }

  /** Widget lines: the most recent rate badge plus the async subagent total
   *  (when non-zero). undefined clears the widget. */
  function setWidgetLines(ctx: ExtensionContext, lines: string[] | undefined): void {
    if (tuiEnabled && ctx.mode === "tui") {
      ctx.ui.setWidget(WIDGET_KEY, lines && lines.length > 0 ? lines : undefined);
    }
  }

  function currentWidgetLines(ctx: ExtensionContext): string[] {
    const lines: string[] = [];
    const rateText =
      lastDisplayedRate === null
        ? null
        : formatTokensPerSecond(lastDisplayedRate.rate, lastDisplayedRate.providerConfirmed);
    if (rateText !== null) lines.push(formatBadge(ctx, "response speed", rateText));
    const subText = formatSubagentCost(subagentTotals);
    if (subText !== null) lines.push(formatBadge(ctx, "subagents", subText));
    return lines;
  }

  pi.on("session_start", (_event, ctx) => {
    stream = createStreamState();
    lastTokensPerSecond = null;
    lastDisplayedRate = null;
    tuiEnabled = ctx.mode === "tui";
    resetSubagentTracking();
    setWorkingMessage(ctx);
    setWidgetLines(ctx, undefined);
  });

  pi.on("agent_start", (_event, ctx) => {
    setWidgetLines(ctx, undefined);
  });

  pi.on("message_start", (event, ctx) => {
    if (event.message.role !== "assistant") return;
    setWidgetLines(ctx, undefined);
    stream = createStreamState();
    stream.messageStartTime = Date.now();
    setWorkingRate(ctx, lastTokensPerSecond, true);
  });

  pi.on("message_update", (event, ctx) => {
    const assistantEvent = event.assistantMessageEvent;
    if (
      assistantEvent.type !== "text_delta" &&
      assistantEvent.type !== "thinking_delta" &&
      assistantEvent.type !== "toolcall_delta"
    ) {
      return;
    }

    const liveRate = recordOutputDelta(stream, assistantEvent.delta);
    if (liveRate !== null) {
      setWorkingRate(ctx, liveRate);
    }
  });

  pi.on("message_end", (event, ctx) => {
    if (event.message.role !== "assistant") return;

    const providerRate = providerTokensPerSecond(
      stream,
      Date.now(),
      event.message.usage?.output ?? 0,
      event.message.stopReason,
    );
    if (providerRate !== null) lastTokensPerSecond = providerRate;

    if (providerRate !== null) {
      lastDisplayedRate = { rate: providerRate, providerConfirmed: true };
      setWorkingRate(ctx, providerRate, true);
    } else if (stream.liveTokensPerSecond !== null) {
      lastDisplayedRate = { rate: stream.liveTokensPerSecond, providerConfirmed: false };
      setWorkingRate(ctx, stream.liveTokensPerSecond);
    } else {
      lastDisplayedRate =
        lastTokensPerSecond === null
          ? null
          : { rate: lastTokensPerSecond, providerConfirmed: true };
      setWorkingRate(ctx, lastTokensPerSecond, true);
    }
    stream = createStreamState();
  });

  pi.on("agent_end", (_event, ctx) => {
    refreshSubagentTotals(ctx);
    setWidgetLines(ctx, currentWidgetLines(ctx));
  });

  pi.on("session_shutdown", (_event, ctx) => {
    setWorkingMessage(ctx);
    setWidgetLines(ctx, undefined);
    tuiEnabled = false;
    stream = createStreamState();
    lastTokensPerSecond = null;
    lastDisplayedRate = null;
    resetSubagentTracking();
  });
}
