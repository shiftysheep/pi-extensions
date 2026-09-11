/**
 * Pi working indicator with a live and provider-confirmed output
 * tokens-per-second rate.
 *
 * The extension updates Pi's built-in animated working indicator rather than
 * replacing the footer. This keeps the extension independent of footer
 * internals as Pi's UI evolves.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

export const MIN_STREAM_MS = 250;
export const DEFAULT_WORKING_MESSAGE = "Working...";
const RATE_WIDGET_KEY = "status-line-tokens-per-second";
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

export function formatWorkingMessage(
  rate: number | null,
  providerConfirmed = false,
): string {
  const formattedRate = formatTokensPerSecond(rate, providerConfirmed);
  return formattedRate ? `${DEFAULT_WORKING_MESSAGE} ${formattedRate}` : DEFAULT_WORKING_MESSAGE;
}

export default function statusLine(pi: ExtensionAPI): void {
  let stream = createStreamState();
  let lastTokensPerSecond: number | null = null;
  let lastDisplayedRate: { rate: number; providerConfirmed: boolean } | null = null;
  let tuiEnabled = false;

  function setWorkingMessage(ctx: ExtensionContext, message?: string): void {
    if (tuiEnabled && ctx.mode === "tui") ctx.ui.setWorkingMessage(message);
  }

  function formatRateBadge(ctx: ExtensionContext, text: string): string {
    const theme = ctx.ui.theme;
    return [
      theme.fg("muted", "[ "),
      theme.fg("accent", "response speed"),
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
    setWorkingMessage(ctx, text === null ? DEFAULT_WORKING_MESSAGE : formatRateBadge(ctx, text));
  }

  function setRateWidget(ctx: ExtensionContext, text: string | undefined): void {
    if (tuiEnabled && ctx.mode === "tui") {
      const widgetText = text === undefined ? undefined : formatRateBadge(ctx, text);
      ctx.ui.setWidget(RATE_WIDGET_KEY, widgetText === undefined ? undefined : [widgetText]);
    }
  }

  pi.on("session_start", (_event, ctx) => {
    stream = createStreamState();
    lastTokensPerSecond = null;
    lastDisplayedRate = null;
    tuiEnabled = ctx.mode === "tui";
    setWorkingMessage(ctx);
    setRateWidget(ctx, undefined);
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
      lastDisplayedRate = lastTokensPerSecond === null
        ? null
        : { rate: lastTokensPerSecond, providerConfirmed: true };
      setWorkingRate(ctx, lastTokensPerSecond, true);
    }
    stream = createStreamState();
  });

  pi.on("agent_end", (_event, ctx) => {
    if (lastDisplayedRate !== null) {
      setRateWidget(
        ctx,
        formatTokensPerSecond(
          lastDisplayedRate.rate,
          lastDisplayedRate.providerConfirmed,
        ) ?? undefined,
      );
    }
  });

  pi.on("session_shutdown", (_event, ctx) => {
    setWorkingMessage(ctx);
    setRateWidget(ctx, undefined);
    tuiEnabled = false;
    stream = createStreamState();
    lastTokensPerSecond = null;
    lastDisplayedRate = null;
  });
}
