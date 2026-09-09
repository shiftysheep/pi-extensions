/**
 * Consultation transports for the advisor extension: the cheap single-call
 * review transport and the read-only agent-session explore transport. Both
 * run against one shared absolute deadline; neither aborts on tool-call or
 * model-request counts.
 */

import { type Model, type Usage, type UserMessage, uuidv7 } from "@earendil-works/pi-ai";
import {
  createAgentSession,
  DefaultResourceLoader,
  type ExtensionContext,
  getAgentDir,
  SessionManager,
} from "@earendil-works/pi-coding-agent";
import {
  AdvisorEventAccumulator,
  type AdvisorReasoningEffort,
  assembleRequestText,
  remainingBudgetMs,
  textFromContent,
} from "../lib/advisor-utils.js";
import { ADVISOR_SYSTEM_PROMPT, neutralReasoningEffort, REVIEW_SYSTEM_PROMPT } from "./request.js";

export const ADVISOR_TOOLS = ["read", "grep", "find", "ls"];

export type AdvisorStatus = "completed" | "timed_out" | "aborted";
export type AdvisorConsultResult = {
  text: string;
  usage?: Usage;
  toolCalls: number;
  modelRequests: number;
  status: AdvisorStatus;
};

/**
 * Cheap review mode: a single streamSimple call that answers from the question
 * (plus the redacted transcript only when the caller opted in). No tools, no
 * repo claims.
 */
export async function consultWithStreamSimple(opts: {
  model: Model<any>;
  modelLabel: string;
  question: string;
  transcript: string;
  effort: AdvisorReasoningEffort;
  ctx: ExtensionContext;
  /** Absolute monotonic-clock deadline (performance.now() base) for the whole consultation. */
  deadline: number;
  signal?: AbortSignal;
}): Promise<AdvisorConsultResult> {
  const { model, ctx } = opts;
  const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
  if (!auth.ok) throw new Error(auth.error);
  const provider = ctx.modelRegistry.getProvider(model.provider);
  if (!provider) throw new Error(`Provider "${model.provider}" is not registered.`);
  const requestModel = auth.baseUrl ? { ...model, baseUrl: auth.baseUrl } : model;
  const request: UserMessage = {
    role: "user",
    content: [
      {
        type: "text",
        text: assembleRequestText(
          model,
          opts.question,
          opts.transcript,
          ADVISOR_SYSTEM_PROMPT.length,
        ),
      },
    ],
    timestamp: Date.now(),
  };

  // The deadline is absolute: time spent in async setup above is already
  // deducted, and an exhausted budget never starts a model request.
  if (opts.signal?.aborted) throw new Error("aborted before the consultation started");
  const remainingMs = remainingBudgetMs(opts.deadline, performance.now());
  if (remainingMs <= 0) throw new Error("consultation timed out during setup");
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, remainingMs);
  const onOuterAbort = () => controller.abort();
  opts.signal?.addEventListener("abort", onOuterAbort, { once: true });
  try {
    const response = await provider
      .streamSimple(
        requestModel,
        { systemPrompt: REVIEW_SYSTEM_PROMPT, messages: [request] },
        {
          apiKey: auth.apiKey,
          headers: auth.headers,
          env: auth.env,
          signal: controller.signal,
          reasoning: neutralReasoningEffort(model, opts.effort),
          // Bound the response so the char-budget over-reserve stays honest.
          ...(model.maxTokens && model.maxTokens > 0 ? { maxTokens: model.maxTokens } : {}),
          cacheRetention: "none",
          sessionId: uuidv7(),
        },
      )
      .result();
    // A review is exactly one model request (0 tool calls by construction).
    if (timedOut)
      return {
        text: "",
        usage: response.usage,
        toolCalls: 0,
        modelRequests: 1,
        status: "timed_out",
      };
    if (opts.signal?.aborted === true || response.stopReason === "aborted")
      return { text: "", usage: response.usage, toolCalls: 0, modelRequests: 1, status: "aborted" };
    if (response.stopReason === "error")
      throw new Error(
        response.errorMessage || "The advisor request failed without an error message.",
      );
    return {
      text: textFromContent(response.content).trim() || "The advisor returned no text.",
      usage: response.usage,
      toolCalls: 0,
      modelRequests: 1,
      status: "completed",
    };
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onOuterAbort);
  }
}

/**
 * Explore mode: a nested read-only agent session. The advisor model sees the
 * question (plus the redacted transcript only when the caller opted in) and
 * verifies it against the workspace with read/grep/find/ls before answering.
 * Bounded by the consultation timeout only — tool-call and model-request
 * counts are reported in the result (cost visibility) but never abort a
 * consultation.
 */
export async function consultWithAgentSession(opts: {
  model: Model<any>;
  modelLabel: string;
  question: string;
  transcript: string;
  effort: AdvisorReasoningEffort;
  cwd: string;
  /** Absolute monotonic-clock deadline (performance.now() base) for the whole consultation. */
  deadline: number;
  signal?: AbortSignal;
  onUpdate?: (update: {
    content: Array<{ type: "text"; text: string }>;
    details: Record<string, unknown>;
  }) => void;
}): Promise<AdvisorConsultResult> {
  const loader = new DefaultResourceLoader({
    cwd: opts.cwd,
    agentDir: getAgentDir(),
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    systemPrompt: ADVISOR_SYSTEM_PROMPT,
  });
  await loader.reload();

  const { session } = await createAgentSession({
    cwd: opts.cwd,
    model: opts.model,
    thinkingLevel: neutralReasoningEffort(opts.model, opts.effort) ?? "medium",
    tools: ADVISOR_TOOLS,
    resourceLoader: loader,
    sessionManager: SessionManager.inMemory(opts.cwd),
  });

  // Per-message accumulation: agent_end fires once at the end of the whole run,
  // and an interrupted run can end in an empty/synthetic assistant message, so
  // findings and usage are collected per message_end (one per assistant message).
  const acc = new AdvisorEventAccumulator();
  const unsubscribe = session.subscribe((event) => {
    acc.record(event);
    if (event.type === "tool_execution_start") {
      opts.onUpdate?.({
        content: [
          {
            type: "text",
            text: `${opts.modelLabel} is exploring the workspace (tool call ${acc.toolCalls}: ${event.toolName})...`,
          },
        ],
        details: { model: opts.modelLabel, toolCalls: acc.toolCalls, toolName: event.toolName },
      });
    }
  });

  // The deadline is absolute: session creation above is already deducted. The
  // checks live inside the try so a setup-time abort/timeout still disposes the
  // already-created session and removes its subscription.
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const onOuterAbort = () => {
    void session.abort();
  };
  try {
    if (opts.signal?.aborted) throw new Error("aborted before the consultation started");
    const remainingMs = remainingBudgetMs(opts.deadline, performance.now());
    if (remainingMs <= 0) throw new Error("consultation timed out during setup");
    timer = setTimeout(() => {
      timedOut = true;
      void session.abort();
    }, remainingMs);
    opts.signal?.addEventListener("abort", onOuterAbort, { once: true });
    await session.prompt(
      assembleRequestText(opts.model, opts.question, opts.transcript, ADVISOR_SYSTEM_PROMPT.length),
      {
        expandPromptTemplates: false,
      },
    );
  } finally {
    if (timer) clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onOuterAbort);
    unsubscribe();
    session.dispose();
  }

  const interrupted = timedOut || opts.signal?.aborted === true;
  const text = acc.finalText(interrupted);
  if (timedOut)
    return {
      text,
      usage: acc.usage,
      toolCalls: acc.toolCalls,
      modelRequests: acc.modelRequests,
      status: "timed_out",
    };
  if (opts.signal?.aborted === true)
    return {
      text,
      usage: acc.usage,
      toolCalls: acc.toolCalls,
      modelRequests: acc.modelRequests,
      status: "aborted",
    };
  return {
    text: text || "The advisor returned no text.",
    usage: acc.usage,
    toolCalls: acc.toolCalls,
    modelRequests: acc.modelRequests,
    status: "completed",
  };
}
