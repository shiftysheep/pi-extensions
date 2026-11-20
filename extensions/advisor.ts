/**
 * Advisor: consult a separate model from the active Pi agent.
 *
 * Model defaults live in ~/.pi/agent/advisor.json and can be managed with the
 * /advisor command (show config, or pick primary/fallback models — interactive
 * picker or arguments). Any configured Pi model can be selected per consultation,
 * including models from custom providers.
 */

import { renameSync } from "node:fs";
import { uuidv7 } from "@earendil-works/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
  CONFIG_PATH,
  describeConfig,
  loadConfigSafe,
  saveConfig,
  saveConfigValidated,
} from "./advisor/config.js";
import { advisorExecute, type CandidateAttempt } from "./advisor/execute.js";
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

// The advisorExecute, buildResult, and CandidateAttempt type are now in
// advisor/execute.ts (extracted for testability). advisor.ts imports them
// above and uses them in the tool registration below.

export default function (pi: ExtensionAPI) {
  const slotFromArg = (raw: string): AdvisorSlot => {
    const value = raw.toLowerCase();
    if (value === "primary") return "primary";
    if (value === "fallback" || value === "secondary") return "fallback";
    throw new Error(`Unknown slot "${raw}". Expected primary or fallback.`);
  };

  const usageHints =
    'Usage:\n  /advisor                              show current configuration, then offer the interactive picker\n  /advisor set <primary>,<fallback>   set both (provider/model ids; provider optional if unambiguous)\n  /advisor primary|fallback <spec>    change one slot\n  /advisor effort <level>             set the shared default reasoning effort (none|minimal|low|medium|high|xhigh|max)\n  /advisor clear [slot]               remove a slot, the default effort (effort=slot), or everything (no slot)\n  /advisor reset                      back up the config to advisor.json.bak and start clean (recovers from a broken file)\n\nadvisor.json is strictly validated: unknown keys (in the top level or a model slot) are rejected with an error naming the field, and primary/fallback must be different models. Optional keys: reasoningEffort, activeModelFallback (bool), timeoutMs (ms, clamped 30 s..30 min, covers the whole consultation including the fallback chain; the per-call timeoutMs parameter overrides it).\n\nSpecs may end with @effort to set a per-model effort: /advisor primary openai-codex/gpt-6-astra@high\nNo model is ever picked implicitly: with no configured slots the advisor fails and points back at /advisor. The active model of the calling session is only retried last when "activeModelFallback": true is set in advisor.json — that is a self-review, and the tool result says so. Effort "none" requests no reasoning level (session default); it does not force reasoning off.\nThe advisor tool does NOT see the session by default: cite workspace paths for anything on disk, and paste only evidence that exists nowhere on disk (includeSession:true opt-in attaches the redacted transcript as optional, verify-against-the-workspace context). Every consultation runs in an isolated child pi process with a throwaway agent dir (only a copy of auth.json, mode 0600; removed in a finally block) — a privilege boundary, not a filesystem sandbox. Optional key piBinary (path to the pi binary to spawn; default "pi" on PATH, or $PI_BINARY). Tool modes: "review" (default, single model call) and "explore" (read-only sub-agent with read/grep/find/ls that verifies against the workspace itself; bounded by the consultation timeout only — tool-call count, model-request count, and elapsed time are reported for cost visibility, but never abort a consultation). At most 2 consultations run concurrently (extras queue, never reject); returned advice is capped at 100k characters and error diagnostics at 4k, both marked with a visible [truncated] notice.';

  /** Handle a /advisor subcommand: mutate the config and return the updated config (or throw). */
  function handleAdvisorSubcommand(
    sub: string,
    parts: string[],
    config: AdvisorConfig,
    ctx: ExtensionContext,
  ): AdvisorConfig {
    if (sub === "reset") {
      if (parts.length > 1)
        throw new Error(
          "/advisor reset takes no arguments. It moves advisor.json to advisor.json.bak and writes an empty config.",
        );
      return {};
    }
    if (sub === "show" || sub === "--help") {
      return config;
    }
    if (sub === "set") return handleSet(parts, config, ctx);
    if (sub === "primary" || sub === "fallback" || sub === "secondary")
      return handleSlotSet(sub, parts, config, ctx);
    if (sub === "clear") return handleClear(parts, config);
    if (sub === "effort") return handleEffort(parts, config);
    throw new Error(`Unknown advisor subcommand "${sub}".\n\n${usageHints}`);
  }

  /** /advisor set <primary>,<fallback> — set both slots from two comma-separated specs. */
  function handleSet(parts: string[], config: AdvisorConfig, ctx: ExtensionContext): AdvisorConfig {
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
    return config;
  }

  /** /advisor primary|fallback <spec> — change one slot. */
  function handleSlotSet(
    sub: string,
    parts: string[],
    config: AdvisorConfig,
    ctx: ExtensionContext,
  ): AdvisorConfig {
    const slot: AdvisorSlot = slotFromArg(sub);
    if (parts.length !== 2)
      throw new Error(
        `/advisor ${slot} needs exactly one model spec.\n\n${describeConfig(config)}\n\n${usageHints}`,
      );
    config[slot] = resolveSpec(ctx, parts[1]);
    return config;
  }

  /** /advisor clear [slot] — remove a slot, the default effort, or everything. */
  function handleClear(parts: string[], config: AdvisorConfig): AdvisorConfig {
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
    return config;
  }

  /** /advisor effort <level> — set the shared default reasoning effort. */
  function handleEffort(parts: string[], config: AdvisorConfig): AdvisorConfig {
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
    return config;
  }

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

      if (parts.length === 0) {
        await handleNoArgs(config, activeLabel, warn, ctx, loadError);
        return;
      }

      const sub = parts[0];
      if (sub === "reset") {
        handleReset(activeLabel, loadError, ctx);
        return;
      }
      if (sub === "show" || sub === "--help") {
        ctx.ui.notify(`${warn}${describeConfig(config, activeLabel)}\n\n${usageHints}`, "info");
        return;
      }

      const updatedConfig = handleAdvisorSubcommand(sub, parts, config, ctx);
      const backedUp = saveConfigValidated(updatedConfig, loadError);
      ctx.ui.notify(
        `${warn}advisor updated:\n${describeConfig(updatedConfig, activeLabel)}${backedUp ? `\n(Broken previous file backed up to ${CONFIG_PATH}.bak.)` : ""}`,
        "info",
      );
    },
  });

  /** No-args /advisor: show config, then offer the interactive picker in TUI mode. */
  async function handleNoArgs(
    config: AdvisorConfig,
    activeLabel: string | undefined,
    warn: string,
    ctx: ExtensionContext,
    loadError: string | undefined,
  ): Promise<void> {
    ctx.ui.notify(`${warn}${describeConfig(config, activeLabel)}`, "info");
    if (!(ctx.hasUI && ctx.mode === "tui")) return;
    const answer = await ctx.ui.confirm(
      "Update advisor models now?",
      "(primary, then secondary/fallback; Esc cancels)",
    );
    if (!answer) return;
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

  /** /advisor reset: back up the config to advisor.json.bak and start clean. */
  function handleReset(
    activeLabel: string | undefined,
    loadError: string | undefined,
    ctx: ExtensionContext,
  ): void {
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
  }

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
