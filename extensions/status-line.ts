/**
 * Pi working indicator with a live and provider-confirmed output
 * tokens-per-second rate, plus a session total for ASYNC subagent runs.
 *
 * The extension updates Pi's built-in animated working indicator rather than
 * replacing the footer. This keeps the extension independent of footer
 * internals as Pi's UI evolves.
 *
 * Subagent costs: SYNC subagent runs and runs awaited via `bg_wait` are
 * already counted in the built-in footer (pi-subagents sets an aggregated
 * top-level `usage` on those tool results, which the footer sums). ASYNC
 * runs that complete WITHOUT a `bg_wait` are not: their usage only lands in
 * {sessionDir}/subagent-artifacts/{runId}_{agent}[_{step}]_meta.json. We
 * scan those (TUI only, on agent_end, throttled to 2 s, deduped by meta
 * file name so multi-step runs sum every step, only runs COMPLETED after
 * this session's first entry — the meta timestamp is a completion time)
 * and show the total as a footer status line (`ctx.ui.setStatus`), which
 * the built-in footer appends below itself — keeping this extension's own
 * surface (working indicator + rate widget) lightweight. Note the status
 * line intentionally overlaps the footer's $ total for bg_wait-ed runs:
 * it is the session's TOTAL async subagent cost, not a delta.
 */

import * as fs from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

export const MIN_STREAM_MS = 250;
export const DEFAULT_WORKING_MESSAGE = "Working...";
const WIDGET_KEY = "status-line";
const SUBAGENT_STATUS_KEY = "subagents";
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
 * ({runId}_{agent}[_{step}]_meta.json), the completion time and usage from
 * the JSON body. The producer (pi-subagents) writes `usage.cost` as a
 * NUMBER; a `{ total }` object is also accepted for tolerance. Malformed
 * names/bodies yield null (skipped, never thrown).
 */
export function extractSubagentMeta(
  fileName: string,
  meta: unknown,
): { runId: string; completedAt: number | null; totals: SubagentTotals } | null {
  if (!fileName.endsWith("_meta.json")) return null;
  const m = fileName.match(RUN_ID_RE);
  if (!m) return null;
  if (typeof meta !== "object" || meta === null) return null;
  const usage = (meta as { usage?: unknown }).usage;
  const u = typeof usage === "object" && usage !== null ? (usage as Record<string, unknown>) : {};
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  const rawCost = u.cost;
  const cost =
    typeof rawCost === "number" && Number.isFinite(rawCost)
      ? rawCost
      : typeof rawCost === "object" && rawCost !== null
        ? num((rawCost as { total?: unknown }).total)
        : 0;
  const stamp = (meta as { timestamp?: unknown }).timestamp;
  return {
    runId: m[1],
    completedAt: typeof stamp === "number" && Number.isFinite(stamp) ? stamp : null,
    totals: {
      input: num(u.input),
      output: num(u.output),
      cacheRead: num(u.cacheRead),
      cacheWrite: num(u.cacheWrite),
      cost,
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
  const countedMetaFiles = new Set<string>();
  let subagentScanAt = 0;
  let sessionDir: string | undefined;

  function resetSubagentTracking(): void {
    subagentTotals = createSubagentTotals();
    countedMetaFiles.clear();
    subagentScanAt = 0;
    sessionDir = undefined;
  }

  /** Rescan the per-cwd subagent-artifacts dir (throttled, TUI only) and
   *  fold in completed async runs finished after this session's first
   *  entry. Deduped by meta FILE NAME (multi-step runs write one meta per
   *  step sharing the runId — every step counts); meta files are the only
   *  files read (input/output/transcript artifacts are never touched). */
  function refreshSubagentTotals(ctx: ExtensionContext): void {
    if (!tuiEnabled || ctx.mode !== "tui") return;
    const now = Date.now();
    if (now - subagentScanAt < SUBAGENT_SCAN_MS) return;
    subagentScanAt = now;
    try {
      const sm = ctx.sessionManager;
      sessionDir ??= sm.getSessionDir();
      // The artifacts dir is shared by all sessions in this cwd, so only
      // count runs completed at or after this session's first entry. The
      // cutoff is recomputed each scan (cheap) and an unknown first entry
      // skips the scan rather than attributing stale runs.
      const first = sm.getEntries()[0];
      const t = first?.timestamp;
      if (typeof t !== "string" || Number.isNaN(Date.parse(t))) return;
      const sessionStartMs = Date.parse(t);
      const artDir = join(sessionDir, "subagent-artifacts");
      for (const name of fs.readdirSync(artDir)) {
        if (!name.endsWith("_meta.json") || countedMetaFiles.has(name)) continue;
        let parsed: unknown;
        try {
          parsed = JSON.parse(fs.readFileSync(join(artDir, name), "utf8"));
        } catch {
          continue; // unreadable/partial meta: skip
        }
        const meta = extractSubagentMeta(name, parsed);
        if (!meta) continue;
        if (meta.completedAt === null || meta.completedAt < sessionStartMs) continue;
        countedMetaFiles.add(name);
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

  /** Widget: the most recent rate badge only. undefined clears it. */
  function setRateWidget(ctx: ExtensionContext, text: string | undefined): void {
    if (tuiEnabled && ctx.mode === "tui") {
      const widgetText = text === undefined ? undefined : formatBadge(ctx, "response speed", text);
      ctx.ui.setWidget(WIDGET_KEY, widgetText === undefined ? undefined : [widgetText]);
    }
  }

  /** Footer status line (appended below the built-in footer): the session's
   *  total async subagent cost, or cleared when zero. */
  function setSubagentStatus(ctx: ExtensionContext): void {
    if (!tuiEnabled || ctx.mode !== "tui") return;
    const text = formatSubagentCost(subagentTotals);
    ctx.ui.setStatus(
      SUBAGENT_STATUS_KEY,
      text === null ? undefined : formatBadge(ctx, "subagents", text),
    );
  }

  pi.on("session_start", (_event, ctx) => {
    stream = createStreamState();
    lastTokensPerSecond = null;
    lastDisplayedRate = null;
    tuiEnabled = ctx.mode === "tui";
    resetSubagentTracking();
    setWorkingMessage(ctx);
    setRateWidget(ctx, undefined);
    setSubagentStatus(ctx);
  });

  pi.on("agent_start", (_event, ctx) => {
    setRateWidget(ctx, undefined);
  });

  pi.on("message_start", (event, ctx) => {
    if (event.message.role !== "assistant") return;
    setRateWidget(ctx, undefined);
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
    setSubagentStatus(ctx);
    if (lastDisplayedRate !== null) {
      setRateWidget(
        ctx,
        formatTokensPerSecond(lastDisplayedRate.rate, lastDisplayedRate.providerConfirmed) ??
          undefined,
      );
    }
  });

  pi.on("session_shutdown", (_event, ctx) => {
    setWorkingMessage(ctx);
    setRateWidget(ctx, undefined);
    stream = createStreamState();
    lastTokensPerSecond = null;
    lastDisplayedRate = null;
    resetSubagentTracking();
    setSubagentStatus(ctx); // totals are zero now → clears the status line
    tuiEnabled = false;
  });
}
