/**
 * Custom footer — replaces the built-in one via ctx.ui.setFooter() and mirrors its layout,
 * plus tok/s. Pass undefined to setFooter() instead to restore pi's original footer.
 *
 * Layout (matches FooterComponent in modes/interactive/components/footer.js):
 *   line 1: ~/cwd (git-branch) • sessionName                       [dim]
 *   line 2: ↑in ↓out Rread Wwrite CH% $cost ctx%/window            model | thinking    [left dim, right-aligned name on right side; ctx% colored at warn/error levels]
 *           └─ our addition in the trailing slot when available: "≈N tok/s" while a response
 *              is streaming (estimated from cumulative UTF-8 bytes/4 since first output), or dimmed
 *              "N tok/s*" using provider-reported output tokens over the complete assistant stream.
 *   line 3: other extensions' ctx.ui.setStatus() texts (sorted by key, space-joined), only if any exist
 *
 * Live rate starts at the first streamed output. Final provider-reported rate starts at Pi's
 * assistant message_start event so hidden reasoning included in usage.output is also inside
 * the measured interval. Streams shorter than 250ms are considered too short to be meaningful.
 */

import * as fs from "node:fs";
import { homedir } from "node:os";
import { relative, resolve, sep } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";

const MIN_STREAM_MS = 250;
const RENDER_INTERVAL_MS = 16; // ~60fps max on our own requestRender() calls during streaming (pi's TUI already coalesces actual paint frames)
const UTF8_ENCODER = new TextEncoder();

interface StreamState {
  messageStartTime: number | null;
  firstOutputTime: number | null;
  outputBytes: number;
}

function newStream(): StreamState {
  return { messageStartTime: null, firstOutputTime: null, outputBytes: 0 };
}

function sanitizeStatusText(text: string): string {
  return text
    .replace(/[\r\n\t]/g, " ")
    .replace(/ +/g, " ")
    .trim();
}

export default function (pi: ExtensionAPI) {
  let stream = newStream();
  let lastTPS: number | null = null; // persisted rate of the previous completed response, shown until the next one finishes
  const snap = { liveTPS: null as number | null };
  let renderAt = 0;

  const refs: { tui?: any; theme?: any; footerData?: any } = {};
  let lastCtx: any;
  let unsubBranch: (() => void) | undefined;

  // --- OpenAI Codex subscription quota (chatgpt.com/backend-api/wham/usage) ---
  const QUOTA_CACHE_MS = 90_000; // poll no more often than this (windows change ~once/min)
  const QUOTA_FAIL_RETRY_MS = 5 * 60_000; // after a hard failure, don't hammer the network every render
  interface QuotaState {
    pct: number | null; // primary (short, e.g. 5-hour) window
    windowSec: number;
    sPct: number | null; // secondary (e.g. weekly) window, if present
    sWindowSec: number;
    fetchedAt: number;
  }
  let quotaCache: QuotaState | undefined;
  let quotaInFlight: Promise<QuotaState | undefined> | null = null;
  let lastQuotaFailAt = 0; // throttle retries after a hard failure (e.g. logged-out codex session)

  function codexAuthPath(): string {
    return resolve(homedir(), ".codex", "auth.json");
  }

  async function openaiCodexAccessToken(): Promise<string | null> {
    let auth: any;
    try {
      auth = JSON.parse(fs.readFileSync(codexAuthPath(), "utf8"));
    } catch {
      return null;
    }
    const tokens: any = auth?.tokens ?? {};
    if (!tokens.access_token) return null;

    // Decode the id/access token's exp claim to see if it's stale.
    const jwtExp = (jwt?: string): number | null => {
      try {
        const b64 = jwt!.split(".")[1];
        const payload: any = JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));
        return typeof payload.exp === "number" ? payload.exp : null;
      } catch {
        return null;
      }
    };
    const expMs =
      (jwtExp(tokens.access_token) ?? jwtExp(tokens.id_token)) != null
        ? Math.max(jwtExp(tokens.access_token) ?? 0, jwtExp(tokens.id_token) ?? 0) * 1000
        : Infinity;
    if (Date.now() < expMs - 5 * 60_000) return tokens.access_token; // still valid with a 5min safety margin

    // Expired — try a one-shot OAuth refresh and persist it back for other tools.
    const refreshToken: string | undefined = tokens.refresh_token;
    if (!refreshToken) return null;
    let client_id = "";
    try {
      const b64 = (tokens.id_token ?? tokens.access_token).split(".")[1];
      client_id = JSON.parse(Buffer.from(b64, "base64url").toString("utf8")).client_id || client_id;
    } catch {
      /* ignore */
    }

    const body: Record<string, string> = {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      audience: "https://api.openai.com/v1",
    };
    if (client_id) body.client_id = client_id;

    let res: Response;
    try {
      res = await fetch("https://auth.openai.com/oauth/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(body).toString(),
      });
    } catch {
      return null;
    }
    if (!res.ok) return tokens.access_token; // don't overwrite a possibly-still-working token on refresh failure

    let json: any;
    try {
      json = await res.json();
    } catch {
      return tokens.access_token;
    }
    const freshAccess: string | undefined = json?.access_token ?? json?.id_token;
    if (!freshAccess) return tokens.access_token;
    // Persist the new set of tokens back where codex expects them so we don't
    // burn repeated refreshes (refresh tokens are single-ish use in practice).
    try {
      const next = { ...auth, tokens: { ...tokens } };
      if (json.access_token) next.tokens.access_token = json.access_token;
      next.last_refresh = new Date().toISOString();
      fs.writeFileSync(codexAuthPath(), JSON.stringify(next, null, "\t"));
    } catch {
      /* non-fatal: just don't persist */
    }
    return freshAccess === json.id_token
      ? tokens.access_token
      : (json.access_token ?? tokens.access_token);
  }

  function fetchQuota(): Promise<QuotaState | undefined> {
    const now = Date.now();
    if (quotaInFlight) return quotaInFlight;
    // Fresh enough for our purposes → no network call at all.
    if (quotaCache && now - quotaCache.fetchedAt < QUOTA_CACHE_MS)
      return Promise.resolve(quotaCache);
    // Fail-throttle: if a recent fetch failed, keep showing the stale value instead of re-hitting
    // the network on every cache-expired render until we've waited our retry window.
    if (lastQuotaFailAt && now - lastQuotaFailAt < QUOTA_FAIL_RETRY_MS) {
      return Promise.resolve(quotaCache); // may be undefined → footer just shows no quota tag
    }

    const doFetch = async (): Promise<QuotaState | undefined> => {
      const token = await openaiCodexAccessToken();
      if (!token) throw new Error("no codex auth token");
      const res = await fetch("https://chatgpt.com/backend-api/wham/usage", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`wham/usage HTTP ${res.status}`);
      const json: any = await res.json();
      const p: any = json?.rate_limit?.primary_window ?? null;
      const s: any = json?.rate_limit?.secondary_window ?? null;
      if (!p && !s) throw new Error("no window data");
      return {
        pct: typeof p?.used_percent === "number" ? p.used_percent : null,
        windowSec: typeof p?.limit_window_seconds === "number" ? p.limit_window_seconds : 0,
        sPct: typeof s?.used_percent === "number" ? s.used_percent : null,
        sWindowSec: typeof s?.limit_window_seconds === "number" ? s.limit_window_seconds : 0,
        fetchedAt: Date.now(),
      };
    };

    quotaInFlight = doFetch()
      .then((q) => {
        lastQuotaFailAt = 0;
        quotaInFlight = null;
        if (q) quotaCache = q;
        return q;
      })
      .catch(() => {
        lastQuotaFailAt = Date.now();
        quotaInFlight = null;
        return undefined;
      });
    return quotaInFlight;
  }

  /**
   * True when the currently selected model is billed via a subscription OAuth token
   * (e.g. Codex / Kimi Code) rather than pay-as-you-go API billing.
   */
  function currentModelIsSubscription(): boolean {
    try {
      const m: any = lastCtx?.model;
      if (!m) return false;
      if (m.provider === "kimi-coding") return true; // kept parity with the previous hardcoded check for this provider
      return Boolean(
        (lastCtx as any)?.modelRegistry?.isUsingOAuth?.(m) &&
          (lastCtx as any)?.modelRegistry?.getProvider?.(m.provider)?.auth?.oauth?.isSubscription,
      );
    } catch {
      return false; /* optional provider/auth metadata */
    }
  }

  function windowLabelSec(sec: number): string {
    if (sec <= 0) return "";
    const h = sec / 3600;
    if (h < 48) return `${Math.round(h)}h`;
    return `${Math.round(sec / (24 * 3600))}d`;
  }

  /**
   * Renders a compact subscription-usage tag shown right after the "$x.xxx (sub)" cost marker,
   * e.g. `5% /5h 19% /7d`. Both windows are shown when both exist (primary + secondary);
   * returns "" if we have no data yet for this session.
   */
  function quotaLabel(q: QuotaState): string {
    const segs: string[] = [];
    if (q.pct != null) segs.push(`${Math.round(q.pct)}%/${windowLabelSec(q.windowSec)}`);
    if (q.sPct != null) segs.push(`${Math.round(q.sPct)}%/${windowLabelSec(q.sWindowSec)}`);
    return segs.join(" ");
  }

  function requestRender(): void {
    try {
      refs.tui?.requestRender?.();
    } catch {
      /* not a live TUI (headless mode / closed); ignore */
    }
  }

  function refresh(): void {
    const now = Date.now();
    if (now - renderAt < RENDER_INTERVAL_MS) return;
    renderAt = now;
    requestRender();
  }

  function formatTokens(count: number): string {
    if (count < 1000) return count.toString();
    if (count < 10000) return `${(count / 1000).toFixed(1)}k`;
    if (count < 1000000) return `${Math.round(count / 1000)}k`;
    if (count < 10000000) return `${(count / 1000000).toFixed(1)}M`;
    return `${Math.round(count / 1000000)}M`;
  }

  function formatCwdForFooter(cwd: string, home: string): string {
    const resolvedHome = resolve(home);
    const relPath = relative(resolvedHome, resolve(cwd));
    const isInsideHome =
      relPath === "" ||
      (relPath !== ".." &&
        !relPath.startsWith(`..${sep}`) &&
        !(relPath.startsWith("/") || /^[A-Za-z]:/.test(relPath)));
    if (!isInsideHome) return cwd;
    return relPath === "" ? "~" : `~${sep}${relPath}`;
  }

  function computeTotals(sm: any): {
    input: number;
    output: number;
    cacheRead: number;
    cacheWrite: number;
    cost: number;
    latestCacheHitRate?: number;
  } {
    let input = 0,
      output = 0,
      cacheRead = 0,
      cacheWrite = 0,
      cost = 0;
    let latestCacheHitRate: number | undefined;
    for (const entry of sm.getEntries()) {
      const msg: any = entry.message ?? {};
      if (entry.type === "message" && msg.role === "assistant") {
        const u: any = msg.usage;
        if (!u) continue;
        input += u.input ?? 0;
        output += u.output ?? 0;
        cacheRead += u.cacheRead ?? 0;
        cacheWrite += u.cacheWrite ?? 0;
        cost += u.cost?.total ?? 0;
        const latestPromptTokens = (u.input ?? 0) + (u.cacheRead ?? 0) + (u.cacheWrite ?? 0);
        latestCacheHitRate =
          latestPromptTokens > 0 ? ((u.cacheRead ?? 0) / latestPromptTokens) * 100 : undefined;
      } else if (entry.type === "message" && msg.role === "toolResult" && msg.usage) {
        const u: any = msg.usage;
        input += u.input ?? 0;
        output += u.output ?? 0;
        cacheRead += u.cacheRead ?? 0;
        cacheWrite += u.cacheWrite ?? 0;
        cost += u.cost?.total ?? 0;
      } else if (
        (entry.type === "branch_summary" || entry.type === "compaction") &&
        (entry as any).usage
      ) {
        const u: any = (entry as any).usage;
        input += u.input ?? 0;
        output += u.output ?? 0;
        cacheRead += u.cacheRead ?? 0;
        cacheWrite += u.cacheWrite ?? 0;
        cost += u.cost?.total ?? 0;
      }
    }
    return { input, output, cacheRead, cacheWrite, cost, latestCacheHitRate };
  }

  function tpsLabel(theme: any): string | null {
    if (snap.liveTPS != null && Number.isFinite(snap.liveTPS) && snap.liveTPS > 0.5) {
      return `≈${Math.round(snap.liveTPS)}tok/s`; // live estimate while streaming
    }
    if (lastTPS != null && Number.isFinite(lastTPS) && lastTPS > 0.5) {
      return theme.fg("dim", `${Math.round(lastTPS)}tok/s*`); // * = provider-confirmed rate of the most recent completed response, until a new one streams
    }
    return null;
  }

  function renderLines(width: number): string[] {
    const theme = refs.theme;
    const footerData = refs.footerData;
    const sm: any = lastCtx?.sessionManager;
    const model: any = lastCtx?.model;
    if (!theme || !sm) return [""];

    const totals = computeTotals(sm);

    const contextUsage: any =
      typeof lastCtx?.getContextUsage === "function" ? lastCtx.getContextUsage() : null;
    const percentValue: number =
      contextUsage && contextUsage.percent != null ? contextUsage.percent : 0;
    const contextWindow: number = contextUsage?.contextWindow ?? model?.contextWindow ?? 0;

    // Auto-compaction state is not exposed through ExtensionContext. Do not
    // claim it is enabled when rendering this replacement footer.
    const ctxDisplay = (pct: string | undefined): string =>
      contextUsage?.percent === null || !contextUsage
        ? `?/${formatTokens(contextWindow)}`
        : `${pct}%/${formatTokens(contextWindow)}`;
    let ctxPercentStr: string;
    if (contextUsage && contextUsage.percent !== null) {
      const pct = contextUsage.percent.toFixed(1);
      ctxPercentStr =
        percentValue > 90
          ? theme.fg("error", ctxDisplay(pct))
          : percentValue > 70
            ? theme.fg("warning", ctxDisplay(pct))
            : ctxDisplay(pct);
    } else {
      ctxPercentStr = ctxDisplay(undefined);
    }

    const statsParts: string[] = [];
    if (totals.input) statsParts.push(`↑${formatTokens(totals.input)}`);
    if (totals.output) statsParts.push(`↓${formatTokens(totals.output)}`);
    if (totals.cacheRead) statsParts.push(`R${formatTokens(totals.cacheRead)}`);
    if (totals.cacheWrite) statsParts.push(`W${formatTokens(totals.cacheWrite)}`);
    if (
      (totals.cacheRead > 0 || totals.cacheWrite > 0) &&
      totals.latestCacheHitRate !== undefined
    ) {
      statsParts.push(`CH${totals.latestCacheHitRate.toFixed(1)}%`);
    }
    const usingSubscription = currentModelIsSubscription();
    if (totals.cost || usingSubscription)
      statsParts.push(`$${totals.cost.toFixed(3)}${usingSubscription ? " (sub)" : ""}`);
    // Show subscription quota usage right next to the cost marker when it's an OAuth/subscription model.
    if (usingSubscription && quotaCache && (quotaCache.pct != null || quotaCache.sPct != null)) {
      const tag = quotaLabel(quotaCache);
      if (tag) statsParts.push(theme.fg("dim", tag));
    }

    const tps = tpsLabel(theme); // our addition: live estimate while streaming, else previous response's provider-confirmed rate
    if (tps && lastCtx?.model) statsParts.push(tps);
    statsParts.push(ctxPercentStr);

    let statsLeft = statsParts.join(" ");
    const minPadding = 2;
    const rightSideRaw: string = (() => {
      const modelName = model?.id || "no-model";
      let rs = modelName;
      if (model?.reasoning) {
        const lvl: string | undefined = lastCtx?.thinkingLevel ?? "off";
        rs = lvl === "off" ? `${modelName} • thinking off` : `${modelName} • ${lvl}`;
      }
      return rs;
    })();

    let rightSide = rightSideRaw;
    try {
      const providerCount: number = footerData?.getAvailableProviderCount?.() ?? 0;
      if (providerCount > 1 && model) rightSide = `(${model.provider}) ${rightSideRaw}`;
    } catch {
      /* accessor unavailable in this build version */
    }

    let statsLeftWidth = visibleWidth(statsLeft);
    if (statsLeftWidth + minPadding > width) {
      statsLeft = truncateToWidth(statsLeft, Math.max(0, width - minPadding), "...");
      statsLeftWidth = visibleWidth(statsLeft);
    }
    if (
      rightSide !== rightSideRaw &&
      statsLeftWidth + minPadding + visibleWidth(rightSide) > width
    ) {
      rightSide = rightSideRaw;
    }
    const rightSideWidth = visibleWidth(rightSide);

    let statsLine: string;
    if (statsLeftWidth + minPadding + rightSideWidth <= width) {
      statsLine =
        statsLeft + " ".repeat(Math.max(0, width - statsLeftWidth - rightSideWidth)) + rightSide;
    } else {
      const availableForRight = width - statsLeftWidth - minPadding;
      if (availableForRight > 0) {
        const truncatedRight = truncateToWidth(rightSide, availableForRight, "");
        statsLine =
          statsLeft +
          " ".repeat(Math.max(0, width - statsLeftWidth - visibleWidth(truncatedRight))) +
          truncatedRight;
      } else {
        statsLine = statsLeft;
      }
    }

    let line1: string;
    try {
      line1 = formatCwdForFooter(
        sm.getCwd ? sm.getCwd() : "",
        process.env.HOME || (process as any).env?.USERPROFILE || homedir(),
      );
    } catch (err) {
      console.error("footer-cwd error", err);
      line1 = "";
    } // should not happen, but avoid throwing out of render()

    let gitLabel = "";
    try {
      const branch: string | null = footerData?.getGitBranch?.() ?? null;
      if (branch) gitLabel = ` (${branch})`;
    } catch {
      /* ignore */
    }
    line1 += gitLabel;

    let sessionName = "";
    try {
      sessionName = sm.getSessionName?.() || "";
      if (sessionName) line1 += ` • ${sessionName}`;
    } catch (err) {
      console.error("footer-session-name error", err);
    } // ignore failures around names

    const lines: string[] = [
      truncateToWidth(theme.fg("dim", line1), width, theme.fg("dim", "...")),
      // statsLeft is an exact string prefix, including ANSI sequences, so this
      // split preserves both the highlighted context percentage and dim model.
      theme.fg("dim", statsLeft) + theme.fg("dim", statsLine.slice(statsLeft.length)),
    ];

    try {
      const statuses = footerData?.getExtensionStatuses?.();
      if (statuses instanceof Map && statuses.size > 0) {
        const statusTexts: string[] = Array.from(statuses.entries())
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([, t]) => sanitizeStatusText(String(t ?? "")));
        const joined = statusTexts.join(" ").trim();
        if (joined) lines.push(truncateToWidth(joined, width, theme.fg("dim", "...")));
      }
    } catch {
      /* ignore: extension statuses are optional */
    }

    return lines;
  }

  function touchCtx(ctx: any): void {
    // pi may hand us a fresh context object per event — keep our stale-copy refs in sync
    lastCtx = ctx;
  }

  /** Kick off an (async, cached) quota fetch and re-render once we have fresh data. Safe to call often;
   *  only hits the network when a subscription model is selected. */
  function maybeFetchQuota(): void {
    try {
      if (!currentModelIsSubscription()) return;
      fetchQuota()
        .then((q) => {
          if (q) requestRender();
        })
        .catch(() => {});
    } catch {}
  }

  function installFooter(ctx: any): void {
    lastCtx = ctx; // captured once per session instance (ctx stable for the lifetime of a TUI run); refreshes come from events below via lastTPS/snap and tui.requestRender()
    ctx.ui.setFooter((tui: any, theme: any, footerData: any) => {
      refs.tui = tui;
      refs.theme = theme;
      refs.footerData = footerData;
      try {
        unsubBranch?.();
        if (typeof footerData?.onBranchChange === "function")
          unsubBranch = footerData.onBranchChange(requestRender);
      } catch {
        /* optional */
      }

      return {
        render: (w: number) => renderLines(w),
        invalidate() {},
        dispose: () => {
          try {
            unsubBranch?.();
          } catch {}
        },
      };
    });
  }

  pi.on("session_start", async (_event, ctx: any) => {
    if (ctx.mode !== "tui") return; // no TUI footer in headless modes
    stream = newStream();
    lastTPS = null;
    snap.liveTPS = null;
    renderAt = 0;
    try {
      unsubBranch?.();
    } catch {}
    refs.tui = refs.theme = refs.footerData = undefined;
    lastCtx = ctx;
    installFooter(ctx); // full replacement of the built-in footer for this session instance
    maybeFetchQuota(); // fire an async, cached fetch when a subscription model might already be selected at startup
  });

  pi.on("model_select", async (_event, ctx: any) => {
    touchCtx(ctx);
    maybeFetchQuota();
    refresh();
  });

  pi.on("message_end", async (event: any, ctx: any) => {
    const msg = event?.message;
    if (!msg || msg.role !== "assistant") return;
    touchCtx(ctx); // context usage/model may have settled by end-of-message
    let finalRate: number | null = null;
    if (
      stream.messageStartTime != null &&
      msg.stopReason !== "aborted" &&
      msg.stopReason !== "error"
    ) {
      const durMs = Date.now() - stream.messageStartTime;
      if (
        durMs >= MIN_STREAM_MS &&
        typeof (msg.usage as any)?.output === "number" &&
        (msg.usage as any).output > 0
      ) {
        finalRate = ((msg.usage as any).output as number) / (durMs / 1000);
      }
    }
    if (finalRate != null && Number.isFinite(finalRate)) lastTPS = finalRate;
    stream = newStream();
    snap.liveTPS = null; // switch display from live estimate snapshot to the accurate provider-reported rate above, once it exists
    requestRender();
  });

  pi.on("turn_end", async (_event, ctx: any) => {
    touchCtx(ctx); // end-of-turn may be a good time to check for newly available quota (window might have rolled over since stream start)
    maybeFetchQuota();
    refresh();
  });

  pi.on("message_start", (e: any, ctx: any) => {
    touchCtx(ctx);
    if (e.message?.role === "assistant") {
      stream = newStream();
      stream.messageStartTime = Date.now();
    }
  });

  pi.on("message_update", (event: any, ctx: any) => {
    touchCtx(ctx);
    const ev = event?.assistantMessageEvent;
    if (!ev || typeof ev.type !== "string") return;
    let d: string | undefined;
    if (ev.type === "text_delta") d = ev.delta;
    else if (ev.type === "thinking_delta")
      d = ev.delta; // reasoning tokens are output tokens too (subset of usage.output)
    else if (ev.type === "toolcall_delta") d = ev.delta; // tool-call JSON args also count toward reported output token totals (approximate, but keeps live estimate in the right ballpark versus final * value)
    if (!d) return;

    const now = Date.now();
    stream.messageStartTime ??= now; // defensive fallback if a provider omitted message_start
    stream.firstOutputTime ??= now; // text, thinking, and tool-call-only responses all count
    stream.outputBytes += UTF8_ENCODER.encode(d).byteLength;
    const estimatedTokens = stream.outputBytes / 4;

    snap.liveTPS = null;
    if (stream.firstOutputTime != null && estimatedTokens >= 8) {
      const elapsedS = (now - stream.firstOutputTime) / 1000;
      if (elapsedS > MIN_STREAM_MS / 1000) snap.liveTPS = estimatedTokens / elapsedS; // avoid dividing by ~0 before meaningfully many tokens have arrived
    }
    refresh();
  });

  const cleanup = () => {
    try {
      unsubBranch?.();
    } catch {}
  };
  process.on("exit", cleanup);
  pi.on("session_shutdown", () => {
    cleanup();
    process.off("exit", cleanup); // avoid accumulating listeners across /reload
  });
}
