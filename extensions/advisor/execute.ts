/**
 * Advisor execution: the fallback-chain orchestration and per-candidate attempt.
 */

import type { Model, Usage } from "@earendil-works/pi-ai";
import type {
  AgentToolResult,
  AgentToolUpdateCallback,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import {
  type AdvisorCandidate,
  type AdvisorConfig,
  type AdvisorReasoningEffort,
  type AdvisorTarget,
  buildCandidates,
  capDiagnosticText,
  composeAdviceText,
  isReasoningEffort,
  REASONING_EFFORTS,
  remainingBudgetMs,
  resolveConsultTimeoutMs,
  timeoutPrefix,
} from "../lib/advisor-utils.js";
import { loadConfigSafe } from "./config.js";
import { findModel, preRefreshProviderAuth } from "./models.js";
import { sessionTranscript } from "./request.js";
import {
  type AdvisorConsultResult,
  type AdvisorStatus,
  consultWithChildProcess,
} from "./transports.js";

/** Outcome of one candidate attempt: `terminal` ends the consultation, `failed` advances the fallback chain. */
export type CandidateAttempt =
  | { kind: "terminal"; result: AgentToolResult<Record<string, unknown>> }
  | { kind: "failed"; failure: string };

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

/** Attempt one candidate: resolve the model, pre-refresh its OAuth credential, run the consultation, and classify the outcome. */
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
  /**
   * Internal test seam (used only by test/advisor-execute.test.ts). Lets a test
   * inject a fake transport and a fake model resolver. All default to the real
   * implementations, so production behaviour is unchanged. Never set elsewhere.
   */
  __test?: {
    consultImpl?: typeof consultWithChildProcess;
    findModelImpl?: typeof findModel;
    preRefreshImpl?: typeof preRefreshProviderAuth;
  };
}): Promise<CandidateAttempt> {
  const { candidate, candidateIndex, firstTarget, ctx, mode, question, transcript } = opts;
  if (remainingBudgetMs(opts.deadline, performance.now()) <= 0) {
    return {
      kind: "failed",
      failure: `${candidate.source}: skipped, consultation timed out before this attempt`,
    };
  }
  const findModelImpl = opts.__test?.findModelImpl ?? findModel;
  const preRefreshImpl = opts.__test?.preRefreshImpl ?? preRefreshProviderAuth;
  const consultImpl = opts.__test?.consultImpl ?? consultWithChildProcess;
  let model: Model<any>;
  try {
    model = findModelImpl(ctx, candidate.target);
  } catch (error) {
    return {
      kind: "failed",
      failure: `${candidate.source}: ${capDiagnosticText((error as Error).message)}`,
    };
  }

  const modelLabel = `${model.provider}/${model.id}`;
  await preRefreshImpl(ctx, model.provider);
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
    const result = await consultImpl({
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
          usage: result.usage,
        },
      };
    if (result.status === "timed_out") {
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
          result.usage,
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
        result.usage,
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

/** Execute an advisor consultation: validate params, load config, build the candidate chain, and run the fallback chain. */
export async function advisorExecute(
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
  __test?: {
    loadConfigImpl?: typeof loadConfigSafe;
    findModelImpl?: typeof findModel;
    preRefreshImpl?: typeof preRefreshProviderAuth;
    consultImpl?: typeof consultWithChildProcess;
  },
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

  const loadConfigImpl = __test?.loadConfigImpl ?? loadConfigSafe;
  const { config, loadError } = loadConfigImpl();
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
  const timeoutMs = resolveConsultTimeoutMs({
    perCall: params.timeoutMs,
    config: config.timeoutMs,
    mode,
  });
  const deadline = performance.now() + timeoutMs;
  const transcript = params.includeSession === true ? sessionTranscript(ctx) : "";
  const failures: string[] = [];

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
      __test: __test
        ? {
            findModelImpl: __test.findModelImpl,
            preRefreshImpl: __test.preRefreshImpl,
            consultImpl: __test.consultImpl,
          }
        : undefined,
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
