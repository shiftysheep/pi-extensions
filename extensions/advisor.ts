/**
 * Advisor: consult a separate model from the active Pi agent.
 *
 * Model defaults live in ~/.pi/agent/advisor.json and can be managed with the
 * /advisor command (show config, or pick primary/fallback models — interactive
 * picker or arguments). Any configured Pi model can be selected per consultation,
 * including models from custom providers.
 */

import { renameSync } from "node:fs";
import { type Model, type Usage, uuidv7 } from "@earendil-works/pi-ai";
import type {
  AgentToolResult,
  AgentToolUpdateCallback,
  ExtensionAPI,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
  CONFIG_PATH,
  describeConfig,
  loadConfigSafe,
  saveConfig,
  saveConfigValidated,
} from "./advisor/config.js";
import {
  type AdvisorSlot,
  findModel,
  pickModel,
  preRefreshProviderAuth,
  resolveSpec,
} from "./advisor/models.js";
import { sessionTranscript } from "./advisor/request.js";
import {
  type AdvisorConsultResult,
  type AdvisorStatus,
  consultWithChildProcess,
} from "./advisor/transports.js";
import {
  type AdvisorCandidate,
  type AdvisorConfig,
  type AdvisorReasoningEffort,
  type AdvisorTarget,
  addUsage,
  buildCandidates,
  capDiagnosticText,
  composeAdviceText,
  createConcurrencyLimiter,
  isReasoningEffort,
  REASONING_EFFORTS,
  remainingBudgetMs,
  resolveConsultTimeoutMs,
  timeoutPrefix,
  withSlot,
} from "./lib/advisor-utils.js";

/** Cap on concurrent advisor consultations (each is a whole agent session); excess calls queue. */
const ADVISOR_MAX_CONCURRENT = 2;

// Kept on globalThis so the cap survives pi's /reload within one process (same
// nonce pattern as cron.ts); a new process gets a fresh limiter.
const advisorRuntime = globalThis as typeof globalThis & {
  __piAdvisorProcessNonce?: string;
  __piAdvisorLimiter?: ReturnType<typeof createConcurrencyLimiter>;
};
if (advisorRuntime.__piAdvisorProcessNonce === undefined) {
  advisorRuntime.__piAdvisorProcessNonce = uuidv7();
}
if (advisorRuntime.__piAdvisorLimiter === undefined) {
  advisorRuntime.__piAdvisorLimiter = createConcurrencyLimiter(ADVISOR_MAX_CONCURRENT);
}
const advisorLimiter = advisorRuntime.__piAdvisorLimiter;

/**
 * Run one consultation under the process-level cap; callers beyond the cap queue,
 * never reject. A call aborted while queued refuses to start once its slot arrives.
 */
async function withAdvisorSlot<T>(work: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  return withSlot(advisorLimiter, signal, work);
}

/**
 * Every advisor model turn and tool call runs in an isolated child pi process
 * (extensions/advisor/transports.ts): a throwaway agent dir holding only a copy
 * of auth.json, the prompt delivered as an @path file, NDJSON events parsed
 * back. This is a privilege boundary, not a filesystem sandbox — the child's
 * read tools still reach anything the OS user can read.
 */

/**
 * Terminal result for a finished attempt: advice-capped text plus the status
 * footer and structured details. `prefix` lets a timed-out attempt keep its
 * full (capped) partial output instead of collapsing to a short error string.
 */
function buildResult(
  result: AdvisorConsultResult,
  modelLabel: string,
  source: string,
  statusFooter: (status: string) => string,
  status: AdvisorStatus,
  prefix: string,
  mode: string,
  elapsedMs: number,
  usage: Usage | undefined,
): AgentToolResult<Record<string, unknown>> {
  return {
    content: [{ type: "text", text: composeAdviceText(prefix, result.text, statusFooter(status)) }],
    details: {
      model: modelLabel,
      source,
      status,
      mode,
      toolCalls: result.toolCalls,
      modelRequests: result.modelRequests,
      elapsedMs,
    },
    usage,
  };
}
/**
 * Terminal outcome of one candidate attempt. `terminal` outcomes end the
 * consultation (the caller returns the built result); `failed` outcomes record
 * a diagnostic and let the fallback chain advance to the next candidate.
 *
 * `usage` is the usage accumulated ACROSS all attempts so far (the caller owns
 * the running total and passes it in; the attempt adds its own result.usage).
 */
type CandidateAttempt =
  | { kind: "terminal"; result: AgentToolResult<Record<string, unknown>> }
  | { kind: "failed"; failure: string };

/**
 * Attempt one candidate in the fallback chain: resolve the model, pre-refresh
 * its OAuth credential, run the consultation in a child process, and classify
 * the outcome. The shared absolute `deadline` bounds the whole chain, so an
 * attempt that finds no remaining budget reports a skip without spawning.
 *
 * The `statusFooter` closure is built here (it captures the candidate's index,
 * the chain's first target, and the caller's active model) so the terminal
 * result carries the model-visible disclosure of who answered, whether the
 * chain degraded, and whether independence was lost.
 */
async function attemptCandidate(opts: {
  candidate: AdvisorCandidate;
  candidateIndex: number;
  firstTarget: AdvisorTarget;
  ctx: ExtensionContext;
  mode: "review" | "explore";
  question: string;
  transcript: string;
  effort: AdvisorReasoningEffort | undefined;
  config: AdvisorConfig;
  deadline: number;
  timeoutMs: number;
  signal: AbortSignal | undefined;
  explicit: boolean;
  onUpdate: AgentToolUpdateCallback | undefined;
  /** Running usage total from prior attempts; the attempt adds its own. */
  combinedUsage: Usage | undefined;
}): Promise<CandidateAttempt> {
  const { candidate, candidateIndex, firstTarget, ctx, mode, question, transcript } = opts;
  if (remainingBudgetMs(opts.deadline, performance.now()) <= 0) {
    return {
      kind: "failed",
      failure: `${candidate.source}: skipped, consultation timed out before this attempt`,
    };
  }
  let model: Model<any>;
  try {
    model = findModel(ctx, candidate.target);
  } catch (error) {
    return {
      kind: "failed",
      failure: `${candidate.source}: ${capDiagnosticText((error as Error).message)}`,
    };
  }

  const modelLabel = `${model.provider}/${model.id}`;
  // Best-effort pre-refresh of a near-expiry OAuth credential in the HOST's
  // canonical credential store before the child copies auth.json, so the child
  // inherits a fresh access token. The child's auth.json copy has its refresh
  // token STRIPPED (see transports.ts), so the child can never perform a
  // refresh — which is what protects the host's refresh token from being
  // rotated server-side. A failure here just lets the child report its own
  // auth error and fall back.
  await preRefreshProviderAuth(ctx, model.provider);
  // Effort priority: tool-call override > per-model config > global default > medium.
  const selectedEffort =
    opts.effort ?? candidate.target.effort ?? opts.config.reasoningEffort ?? "medium";
  const startedAt = Date.now();
  try {
    opts.onUpdate?.({
      content: [
        { type: "text", text: `Consulting ${modelLabel} (${candidate.source}, ${mode})...` },
      ],
      details: { model: modelLabel, source: candidate.source, mode },
    });
    // Both modes run in an isolated child pi process: no advisor model turn or
    // tool call executes in the host process (privilege boundary, not a
    // filesystem sandbox — the child's read tools reach what the OS user can).
    const result = await consultWithChildProcess({
      model,
      modelLabel,
      question,
      transcript,
      effort: selectedEffort,
      cwd: ctx.cwd,
      mode,
      deadline: opts.deadline,
      signal: opts.signal,
      config: opts.config,
      onUpdate: (update) => opts.onUpdate?.(update),
    });
    const elapsedMs = Date.now() - startedAt;
    // Accumulate this attempt's usage into the running total (the result
    // carries the total INCLUDING this attempt, matching the original behavior).
    const totalUsage = result.usage
      ? addUsage(opts.combinedUsage, result.usage)
      : opts.combinedUsage;

    // The footer is the model-visible disclosure: it always names who answered,
    // whether the chain degraded, and whether independence was lost.
    const flags: string[] = [];
    if (candidateIndex > 0) {
      flags.push(`fallbackFrom=${firstTarget.provider ?? "*"}/${firstTarget.model}`);
    }
    const selfReview =
      ctx.model && model.provider === ctx.model.provider && model.id === ctx.model.id;
    if (selfReview) flags.push("independent=false");
    const statusFooter = (status: string) =>
      `\n\n---\n[advisor: mode=${mode}, model=${modelLabel}, status=${status}, toolCalls=${result.toolCalls}, elapsed=${Math.round(elapsedMs / 1000)}s${flags.length > 0 ? `, ${flags.join(", ")}` : ""}${selfReview ? " — this advice came from the model already driving this session; treat it as self-review, not a second opinion" : ""}]`;

    if (result.status === "aborted")
      return {
        kind: "terminal",
        result: {
          content: [{ type: "text", text: "Advisor consultation cancelled." }],
          details: {
            model: modelLabel,
            source: candidate.source,
            status: "aborted",
            mode,
            elapsedMs,
          },
          usage: totalUsage,
        },
      };
    if (result.status === "timed_out") {
      // A timeout is a terminal incomplete result, not a chain failure: the
      // deadline is shared, so no later candidate could have had time anyway.
      // Return the full (advice-capped) partial output with metrics and usage.
      return {
        kind: "terminal",
        result: buildResult(
          result,
          modelLabel,
          candidate.source,
          statusFooter,
          "timed_out",
          timeoutPrefix(opts.mode, opts.timeoutMs, result.text),
          mode,
          elapsedMs,
          totalUsage,
        ),
      };
    }
    return {
      kind: "terminal",
      result: buildResult(
        result,
        modelLabel,
        candidate.source,
        statusFooter,
        "completed",
        "",
        mode,
        elapsedMs,
        totalUsage,
      ),
    };
  } catch (error) {
    if (opts.signal?.aborted) {
      return {
        kind: "terminal",
        result: {
          content: [{ type: "text", text: "Advisor consultation cancelled." }],
          details: { model: modelLabel, source: candidate.source },
        },
      };
    }
    const message = capDiagnosticText(error instanceof Error ? error.message : String(error));
    if (opts.explicit) throw new Error(`${modelLabel}: ${message}`);
    return { kind: "failed", failure: `${candidate.source} (${modelLabel}): ${message}` };
  }
}

async function advisorExecute(
  params: {
    question: string;
    provider?: string;
    model?: string;
    mode?: string;
    effort?: string;
    includeSession?: boolean;
    timeoutMs?: number;
  },
  signal: AbortSignal | undefined,
  onUpdate: AgentToolUpdateCallback | undefined,
  ctx: ExtensionContext,
): Promise<AgentToolResult<Record<string, unknown>>> {
  if (params.effort !== undefined && !isReasoningEffort(params.effort)) {
    throw new Error(
      `Invalid advisor effort "${params.effort}". Expected one of: ${REASONING_EFFORTS.join(", ")}.`,
    );
  }
  const modeParam = params.mode ?? "review";
  if (modeParam !== "review" && modeParam !== "explore") {
    throw new Error(`Invalid advisor mode "${modeParam}". Expected "review" or "explore".`);
  }
  const mode: "review" | "explore" = modeParam;
  if (
    params.timeoutMs !== undefined &&
    (typeof params.timeoutMs !== "number" ||
      !Number.isFinite(params.timeoutMs) ||
      params.timeoutMs <= 0)
  ) {
    throw new Error(
      `Invalid advisor timeoutMs "${params.timeoutMs}". Expected a positive number of milliseconds (clamped to 30000..1800000).`,
    );
  }

  // Tolerate an unreadable advisor.json so explicit provider/model selections still work.
  const { config, loadError } = loadConfigSafe();
  const { candidates, explicit } = buildCandidates({
    provider: params.provider,
    modelId: params.model,
    config,
    activeModel: ctx.model ? { provider: ctx.model.provider, id: ctx.model.id } : undefined,
  });
  if (!explicit && candidates.length === 0) {
    throw new Error(
      "No advisor models configured. Run /advisor set <primary>,<fallback> (or just /advisor) to pick models.",
    );
  }
  // Timeout priority: per-call > config > mode default (5 min review / 10 min explore),
  // clamped to 30 s..30 min. The budget covers the WHOLE consultation, fallback
  // chain included: every attempt (including its auth/session setup) runs against
  // one shared absolute deadline, on a monotonic clock.
  const timeoutMs = resolveConsultTimeoutMs({
    perCall: params.timeoutMs,
    config: config.timeoutMs,
    mode,
  });
  const deadline = performance.now() + timeoutMs;
  // Ground-truth default: no session content is sent unless explicitly requested.
  const transcript = params.includeSession === true ? sessionTranscript(ctx) : "";
  const failures: string[] = [];

  // Each attempt starts with combinedUsage: undefined because the accumulation
  // across attempts is a no-op in practice: a non-terminal attempt is a failure
  // (the consultation threw, so there is no result.usage to add), and a terminal
  // attempt's result carries its own usage. The only edge case where accumulation
  // would matter is if result formatting (footer construction, buildResult) throws
  // AFTER the consultation succeeds and adds result.usage to the local totalUsage —
  // in that case the original code would have retained the usage in the mutable
  // combinedUsage accumulator, but the new code discards it. This edge case is
  // negligible (the footer is a template string that cannot realistically throw),
  // so we pass undefined and let each attempt compute its own total from scratch.
  for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex++) {
    const attempt = await attemptCandidate({
      candidate: candidates[candidateIndex],
      candidateIndex,
      firstTarget: candidates[0].target,
      ctx,
      mode,
      question: params.question,
      transcript,
      effort: params.effort as AdvisorReasoningEffort | undefined,
      config,
      deadline,
      timeoutMs,
      signal,
      explicit,
      onUpdate,
      combinedUsage: undefined,
    });
    if (attempt.kind === "terminal") {
      return attempt.result;
    }
    failures.push(attempt.failure);
  }

  const configWarning = loadError
    ? ` Note: advisor config was unreadable (${loadError}); run /advisor reset to recover.`
    : "";
  throw new Error(
    `No usable advisor model (tried: ${candidates.map((c) => c.source).join(" → ")}). ${failures.join("; ")}${configWarning}`,
  );
}

export default function (pi: ExtensionAPI) {
  const slotFromArg = (raw: string): AdvisorSlot => {
    const value = raw.toLowerCase();
    if (value === "primary") return "primary";
    if (value === "fallback" || value === "secondary") return "fallback";
    throw new Error(`Unknown slot "${raw}". Expected primary or fallback.`);
  };

  const usageHints =
    'Usage:\n  /advisor                              show current configuration, then offer the interactive picker\n  /advisor set <primary>,<fallback>   set both (provider/model ids; provider optional if unambiguous)\n  /advisor primary|fallback <spec>    change one slot\n  /advisor effort <level>             set the shared default reasoning effort (none|minimal|low|medium|high|xhigh|max)\n  /advisor clear [slot]               remove a slot, the default effort (effort=slot), or everything (no slot)\n  /advisor reset                      back up the config to advisor.json.bak and start clean (recovers from a broken file)\n\nadvisor.json is strictly validated: unknown keys (in the top level or a model slot) are rejected with an error naming the field, and primary/fallback must be different models. Optional keys: reasoningEffort, activeModelFallback (bool), timeoutMs (ms, clamped 30 s..30 min, covers the whole consultation including the fallback chain; the per-call timeoutMs parameter overrides it).\n\nSpecs may end with @effort to set a per-model effort: /advisor primary openai-codex/gpt-6-astra@high\nNo model is ever picked implicitly: with no configured slots the advisor fails and points back at /advisor. The active model of the calling session is only retried last when "activeModelFallback": true is set in advisor.json — that is a self-review, and the tool result says so. Effort "none" requests no reasoning level (session default); it does not force reasoning off.\nThe advisor tool does NOT see the session by default: cite workspace paths for anything on disk, and paste only evidence that exists nowhere on disk (includeSession:true opt-in attaches the redacted transcript as optional, verify-against-the-workspace context). Every consultation runs in an isolated child pi process with a throwaway agent dir (only a copy of auth.json, mode 0600; removed in a finally block) — a privilege boundary, not a filesystem sandbox. Optional key piBinary (path to the pi binary to spawn; default "pi" on PATH, or $PI_BINARY). Tool modes: "review" (default, single model call) and "explore" (read-only sub-agent with read/grep/find/ls that verifies against the workspace itself; bounded by the consultation timeout only — tool-call count, model-request count, and elapsed time are reported for cost visibility, but never abort a consultation). At most 2 consultations run concurrently (extras queue, never reject); returned advice is capped at 100k characters and error diagnostics at 4k, both marked with a visible [truncated] notice.';

  pi.registerCommand("advisor", {
    description:
      "Configure advisor (second-opinion) models in ~/.pi/agent/advisor.json; no args shows config and offers the picker.",
    handler: async (args, ctx) => {
      const { config, loadError } = loadConfigSafe();
      const parts = args.trim().split(/\s+/).filter(Boolean);
      const activeLabel = ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined;
      const warn = loadError
        ? `WARNING: ignoring unreadable advisor config (${loadError}). /advisor reset backs it up and starts clean.\n\n`
        : "";

      async function interactivePicker(): Promise<void> {
        // Collect both picks before writing: Esc at either prompt aborts the whole change.
        const pickedPrimary = await pickModel(ctx, "primary");
        if (pickedPrimary === undefined) return;
        const pickedFallback = await pickModel(ctx, "fallback");
        if (pickedFallback === undefined) {
          ctx.ui.notify("advisor picker cancelled: no changes saved.", "warning");
          return;
        }
        if (pickedPrimary === "unset") delete config.primary;
        else config.primary = pickedPrimary;
        if (pickedFallback === "unset") delete config.fallback;
        else config.fallback = pickedFallback;
        const backedUp = saveConfigValidated(config, loadError);
        ctx.ui.notify(
          `advisor updated:\n${describeConfig(config)}${backedUp ? `\n(Broken previous file backed up to ${CONFIG_PATH}.bak.)` : ""}`,
          "info",
        );
      }

      if (parts.length === 0) {
        ctx.ui.notify(`${warn}${describeConfig(config, activeLabel)}`, "info");
        if (ctx.hasUI && ctx.mode === "tui") {
          const answer = await ctx.ui.confirm(
            "Update advisor models now?",
            "(primary, then secondary/fallback; Esc cancels)",
          );
          if (answer) return interactivePicker();
        }
        return;
      }

      const sub = parts[0];
      if (sub === "reset") {
        if (parts.length > 1)
          throw new Error(
            "/advisor reset takes no arguments. It moves advisor.json to advisor.json.bak and writes an empty config.",
          );
        let backedUp: string | undefined;
        try {
          renameSync(CONFIG_PATH, `${CONFIG_PATH}.bak`);
          backedUp = `${CONFIG_PATH}.bak`;
        } catch (error: unknown) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT")
            throw new Error(`Could not back up ${CONFIG_PATH}: ${(error as Error).message}`);
        }
        saveConfig({});
        ctx.ui.notify(
          `advisor config reset.${backedUp ? ` Previous file moved to ${backedUp}.` : ""}${loadError ? ` (previous file was unreadable: ${loadError})` : ""}\n\n${describeConfig({}, activeLabel)}`,
          backedUp || loadError ? "warning" : "info",
        );
        return;
      }
      if (sub === "show" || sub === "--help") {
        ctx.ui.notify(`${warn}${describeConfig(config, activeLabel)}\n\n${usageHints}`, "info");
        return;
      }
      if (sub === "set") {
        const specs = parts
          .slice(1)
          .join(" ")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        if (specs.length !== 2)
          throw new Error(
            `/advisor set expects two model specs: /advisor set <primary>,<fallback>\n\n${describeConfig(config)}\n\n${usageHints}`,
          );
        config.primary = resolveSpec(ctx, specs[0]);
        config.fallback = resolveSpec(ctx, specs[1]);
      } else if (sub === "primary" || sub === "fallback" || sub === "secondary") {
        const slot: AdvisorSlot = slotFromArg(sub);
        if (parts.length !== 2)
          throw new Error(
            `/advisor ${slot} needs exactly one model spec.\n\n${describeConfig(config)}\n\n${usageHints}`,
          );
        config[slot] = resolveSpec(ctx, parts[1]);
      } else if (sub === "clear") {
        if (parts.length > 2)
          throw new Error("/advisor clear takes at most one slot: primary, fallback, or effort.");
        if (parts.length === 2 && parts[1].toLowerCase() === "effort") {
          delete config.reasoningEffort;
        } else {
          const slot = parts.length === 1 ? undefined : slotFromArg(parts[1]);
          if (slot) delete config[slot];
          else {
            delete config.primary;
            delete config.fallback;
          }
        }
      } else if (sub === "effort") {
        if (parts.length !== 2)
          throw new Error(
            `/advisor effort needs one level: ${REASONING_EFFORTS.join(", ")}.\n\n${describeConfig(config)}\n\n${usageHints}`,
          );
        const level = parts[1];
        if (!isReasoningEffort(level))
          throw new Error(
            `Invalid advisor effort "${level}". Expected one of: ${REASONING_EFFORTS.join(", ")}.`,
          );
        config.reasoningEffort = level;
      } else {
        throw new Error(`Unknown advisor subcommand "${sub}".\n\n${usageHints}`);
      }

      const backedUp = saveConfigValidated(config, loadError);
      ctx.ui.notify(
        `${warn}advisor updated:\n${describeConfig(config, activeLabel)}${backedUp ? `\n(Broken previous file backed up to ${CONFIG_PATH}.bak.)` : ""}`,
        "info",
      );
    },
  });

  pi.registerTool({
    name: "advisor",
    label: "Advisor",
    description:
      'Independent check on a proposed change or diagnosis. One-way doors (hard to reverse: deleting data, shipping breaking changes, migrations) — consult before committing. Two-way doors (easy to reverse: renames, config tweaks, new tests) — skip. Ask what assumption could be wrong and what evidence would distinguish the alternatives. No transcript by default: cite paths and summarize relevant evidence. Use "explore" to verify source; "review" for self-contained questions.',
    promptSnippet: "Independent check — one-way doors consult, two-way doors skip",
    promptGuidelines: [
      "One-way door (hard to reverse): consult advisor ONCE before committing, if an assumption is unchecked. Two-way door (easy to reverse): skip. Stuck after 2 failed fixes with unclear cause: consult. Routine work: skip. Don't repeat without new evidence.",
    ],
    parameters: Type.Object({
      question: Type.String({
        description: "The precise review, diagnosis, or design question for the advisor.",
      }),
      provider: Type.Optional(
        Type.String({
          description: "Pi provider ID to use, for example openai-codex, anthropic, or ollama.",
        }),
      ),
      model: Type.Optional(
        Type.String({
          description:
            "Configured Pi model ID to use. Explicit selection does not use configured fallbacks.",
        }),
      ),
      mode: Type.Optional(
        Type.String({
          description:
            'Consultation mode. "review" (default): a single model call that answers from the question; cheap, but it cannot read the workspace — use it for self-contained questions. "explore": the advisor child runs a read-only agent (read/grep/find/ls) that verifies the question against the workspace itself — use it for code reviews and any answer that must come from the source; bounded by the consultation timeout only (actual tool calls and elapsed time are reported in the footer) and costs more tokens and time.',
          enum: ["review", "explore"],
        }),
      ),
      effort: Type.Optional(
        Type.String({
          description:
            'Override the configured advisor reasoning effort for this consultation (priority: this parameter > the model-specific "effort" in advisor.json > the global "reasoningEffort" > medium). "none" requests no reasoning level, so the advisor session falls back to its own default.',
          enum: [...REASONING_EFFORTS],
        }),
      ),
      includeSession: Type.Optional(
        Type.Boolean({
          description:
            "Opt in to including the redacted session transcript as optional context the advisor must verify against the workspace. Default: false — no session content is sent unless requested.",
        }),
      ),
      timeoutMs: Type.Optional(
        Type.Number({
          description:
            'Consultation timeout in milliseconds for this call (clamped to 30000..1800000). Covers the whole consultation, fallback chain included. Overrides the "timeoutMs" key in advisor.json, which overrides the mode default (5 min review / 10 min explore).',
        }),
      ),
    }),
    execute: (_toolCallId, params, signal, onUpdate, ctx) =>
      withAdvisorSlot(() => advisorExecute(params, signal, onUpdate, ctx), signal),
  });
}
