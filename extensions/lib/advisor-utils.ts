/**
 * Pure helpers for the advisor extension: config parsing, secret redaction,
 * prompt character budgeting, model candidate ordering, and effort-suffix
 * parsing. Kept free of pi imports and side effects (no fs, no
 * ExtensionContext) so they can be unit-tested without a live session.
 */

import { StringDecoder } from "node:string_decoder";
import type { Usage } from "@earendil-works/pi-ai";

export const REASONING_EFFORTS = [
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
] as const;
export type AdvisorReasoningEffort = (typeof REASONING_EFFORTS)[number];

export const MAX_QUESTION_CHARS = 20_000;
const APPROX_CHARS_PER_TOKEN = 3.5;
const MIN_RESPONSE_RESERVE_TOKENS = 1_024;

export type AdvisorTarget = { provider?: string; model: string; effort?: AdvisorReasoningEffort };
export type AdvisorConfig = {
  primary?: AdvisorTarget;
  fallback?: AdvisorTarget;
  reasoningEffort?: AdvisorReasoningEffort;
  /** Opt in to retrying the caller's active model last (a self-review, disclosed in the result). */
  activeModelFallback?: boolean;
  /** Consultation timeout in milliseconds, clamped to [ADVISOR_MIN_TIMEOUT_MS, ADVISOR_MAX_TIMEOUT_MS]. */
  timeoutMs?: number;
  /** Explicit path to the pi binary the child-process transport spawns (default: "pi" on PATH). */
  piBinary?: string;
  /** AWS profile for the child only (sets AWS_PROFILE). No default — applied as-is. */
  awsProfile?: string;
  /** AWS region for the child only (sets AWS_REGION and AWS_DEFAULT_REGION). No default. */
  awsRegion?: string;
  /**
   * Additional environment variables applied to the child process ONLY (host
   * process.env is never mutated). Applied on top of the base allowlist and the
   * awsProfile/awsRegion mapping, so an explicit key here overrides them.
   */
  env?: Record<string, string>;
};

/** Allowed top-level advisor.json keys; anything else is a typo and is rejected. */
export const ALLOWED_CONFIG_KEYS = [
  "primary",
  "fallback",
  "reasoningEffort",
  "activeModelFallback",
  "timeoutMs",
  "piBinary",
  "awsProfile",
  "awsRegion",
  "env",
] as const;

export const TARGET_KEYS = ["provider", "model", "effort"] as const;

/** Floor and ceiling for consultation timeouts (per-call and config are clamped to this range). */
export const ADVISOR_MIN_TIMEOUT_MS = 30_000;
export const ADVISOR_MAX_TIMEOUT_MS = 30 * 60_000;
/** Default timeout when none is configured: review is one model call, explore is a whole agent session. */
export const ADVISOR_DEFAULT_REVIEW_TIMEOUT_MS = 5 * 60_000;
export const ADVISOR_DEFAULT_EXPLORE_TIMEOUT_MS = 10 * 60_000;

/**
 * Resolve the effective consultation timeout: per-call override > config >
 * mode default, clamped to [ADVISOR_MIN_TIMEOUT_MS, ADVISOR_MAX_TIMEOUT_MS].
 */
export function resolveConsultTimeoutMs(opts: {
  perCall?: number;
  config?: number;
  mode: "review" | "explore";
}): number {
  const requested =
    opts.perCall ??
    opts.config ??
    (opts.mode === "explore"
      ? ADVISOR_DEFAULT_EXPLORE_TIMEOUT_MS
      : ADVISOR_DEFAULT_REVIEW_TIMEOUT_MS);
  return Math.min(ADVISOR_MAX_TIMEOUT_MS, Math.max(ADVISOR_MIN_TIMEOUT_MS, Math.round(requested)));
}
export type AdvisorCandidate = { target: AdvisorTarget; source: string };

/** Minimal model shape needed for prompt budgeting (pi's Model satisfies it). */
export type BudgetModel = { contextWindow: number; maxTokens?: number };

export function textFromContent(content: unknown): string {
  if (!Array.isArray(content)) return "";
  return content
    .filter((part): part is { type: string; text: string } =>
      Boolean(
        part &&
          typeof part === "object" &&
          (part as { type?: unknown }).type === "text" &&
          typeof (part as { text?: unknown }).text === "string",
      ),
    )
    .map((part) => part.text)
    .join("\n");
}

/**
 * Best-effort guardrail only; callers should still avoid putting secrets in advisor context.
 * Covers PEM blocks, authorization headers, key/value assignments (bare, single- or
 * double-quoted values), and well-known token prefixes. Not a guarantee: treat a
 * session-derived transcript as potentially sensitive.
 */
export function redactSensitiveText(text: string): string {
  return text
    .replace(
      /-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/gi,
      "[REDACTED PRIVATE KEY]",
    )
    .replace(/\b(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+/gi, "$1[REDACTED]")
    .replace(
      /(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd|secret)\b(?:"|')?\s*[=:]\s*)("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|[^\s"'}\]]+)/gi,
      "$1[REDACTED]",
    )
    .replace(/\b(?:gh[gpousr]|github_pat)[A-Za-z0-9_-]{16,}\b/g, "[REDACTED TOKEN]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED TOKEN]")
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED TOKEN]")
    .replace(/\bAKIA[A-Z0-9]{16}\b/g, "[REDACTED TOKEN]");
}

export function keepEnd(text: string, maxChars: number, marker: string): string {
  if (text.length <= maxChars) return text;
  if (maxChars <= marker.length) return marker.slice(0, Math.max(0, maxChars));
  return `${marker}${text.slice(-(maxChars - marker.length))}`;
}

export function keepStart(text: string, maxChars: number, marker: string): string {
  if (text.length <= maxChars) return text;
  if (maxChars <= marker.length) return marker.slice(0, Math.max(0, maxChars));
  return `${text.slice(0, maxChars - marker.length)}${marker}`;
}

export function isReasoningEffort(value: unknown): value is AdvisorReasoningEffort {
  return typeof value === "string" && (REASONING_EFFORTS as readonly string[]).includes(value);
}

export function parseTarget(
  value: unknown,
  field: string,
  configPath: string,
): AdvisorTarget | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object")
    throw new Error(`${configPath}: ${field} must be an object.`);
  const candidate = value as { provider?: unknown; model?: unknown; effort?: unknown };
  const unknownTargetKeys = Object.keys(candidate).filter(
    (k) => !(TARGET_KEYS as readonly string[]).includes(k),
  );
  if (unknownTargetKeys.length > 0) {
    throw new Error(
      `${configPath}: ${field} has unknown key${unknownTargetKeys.length > 1 ? "s" : ""} ${unknownTargetKeys.map((k) => `"${k}"`).join(", ")} (allowed: ${TARGET_KEYS.join(", ")}).`,
    );
  }
  if (typeof candidate.model !== "string" || !candidate.model.trim()) {
    throw new Error(`${configPath}: ${field}.model must be a non-empty string.`);
  }
  if (
    candidate.provider !== undefined &&
    (typeof candidate.provider !== "string" || !candidate.provider.trim())
  ) {
    throw new Error(`${configPath}: ${field}.provider must be a non-empty string when provided.`);
  }
  const effort =
    candidate.effort === undefined
      ? undefined
      : (() => {
          if (!isReasoningEffort(candidate.effort))
            throw new Error(
              `${configPath}: ${field}.effort must be one of: ${REASONING_EFFORTS.join(", ")}.`,
            );
          return candidate.effort;
        })();
  return {
    provider: candidate.provider?.trim() as string | undefined,
    model: candidate.model.trim(),
    effort,
  };
}

/** Parse a fully deserialized advisor config object; throws with an actionable message on invalid fields. */
export function parseConfig(parsed: unknown, configPath: string): AdvisorConfig {
  if (!parsed || typeof parsed !== "object")
    throw new Error(`${configPath}: top level must be an object.`);
  const config = parsed as Record<string, unknown>;
  // Strict key validation: a typo'd key ("fallBack", "reasoning_effort", ...) used to be
  // silently ignored, leaving the advisor running on defaults with no warning.
  const unknownKeys = Object.keys(config).filter(
    (k) => !(ALLOWED_CONFIG_KEYS as readonly string[]).includes(k),
  );
  if (unknownKeys.length > 0) {
    throw new Error(
      `${configPath}: unknown key${unknownKeys.length > 1 ? "s" : ""} ${unknownKeys.map((k) => `"${k}"`).join(", ")} (allowed: ${ALLOWED_CONFIG_KEYS.join(", ")}).`,
    );
  }
  if (config.reasoningEffort !== undefined && !isReasoningEffort(config.reasoningEffort)) {
    throw new Error(
      `${configPath}: reasoningEffort must be one of: ${REASONING_EFFORTS.join(", ")}.`,
    );
  }
  if (config.activeModelFallback !== undefined && typeof config.activeModelFallback !== "boolean") {
    throw new Error(`${configPath}: activeModelFallback must be a boolean.`);
  }
  if (
    config.timeoutMs !== undefined &&
    (typeof config.timeoutMs !== "number" ||
      !Number.isFinite(config.timeoutMs) ||
      config.timeoutMs <= 0)
  ) {
    throw new Error(`${configPath}: timeoutMs must be a positive number of milliseconds.`);
  }
  if (
    config.piBinary !== undefined &&
    (typeof config.piBinary !== "string" || !config.piBinary.trim())
  ) {
    throw new Error(`${configPath}: piBinary must be a non-empty string path to the pi binary.`);
  }
  if (
    config.awsProfile !== undefined &&
    (typeof config.awsProfile !== "string" || !config.awsProfile.trim())
  ) {
    throw new Error(`${configPath}: awsProfile must be a non-empty string.`);
  }
  if (
    config.awsRegion !== undefined &&
    (typeof config.awsRegion !== "string" || !config.awsRegion.trim())
  ) {
    throw new Error(`${configPath}: awsRegion must be a non-empty string.`);
  }
  if (config.env !== undefined && !isChildEnv(config.env)) {
    throw new Error(
      `${configPath}: env must be an object mapping names to non-empty string values.`,
    );
  }
  const primary = parseTarget(config.primary, "primary", configPath);
  const fallback = parseTarget(config.fallback, "fallback", configPath);
  if (primary && fallback && sameModel(primary, fallback)) {
    throw new Error(
      `${configPath}: primary and fallback are the same model ("${primary.provider ?? "*"}/${primary.model}"), so the fallback would just rerun it; configure a different model or omit one slot.`,
    );
  }
  return {
    primary,
    fallback,
    reasoningEffort: config.reasoningEffort,
    activeModelFallback: config.activeModelFallback,
    timeoutMs: config.timeoutMs,
    piBinary: config.piBinary,
    awsProfile: config.awsProfile,
    awsRegion: config.awsRegion,
    env: config.env,
  };
}

/** True when two targets resolve to the same model (an absent provider matches any provider). */
function sameModel(a: AdvisorTarget, b: AdvisorTarget): boolean {
  return a.model === b.model && (!a.provider || !b.provider || a.provider === b.provider);
}

/** Parse an optional `@effort` suffix from a model spec, e.g. `openai-codex/gpt-6-astra@max`. */
export function splitEffortSuffix(spec: string): {
  base: string;
  effort: AdvisorReasoningEffort | undefined;
} {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return { base: spec, effort: undefined };
  const effort = spec.slice(at + 1).trim();
  if (!isReasoningEffort(effort))
    throw new Error(
      `Invalid advisor effort "${effort}" in "${spec}". Expected one of: ${REASONING_EFFORTS.join(", ")} or no suffix.`,
    );
  return { base: spec.slice(0, at).trim(), effort };
}

/**
 * Build the retry chain: an explicit provider/model selection wins outright;
 * otherwise the configured slots in order. No model is ever picked implicitly:
 * with no configured slots the caller gets an empty chain, and the caller's
 * active model is only added as a last resort when `activeModelFallback` is
 * explicitly enabled in config (a self-review, disclosed in the result).
 */
export function buildCandidates(opts: {
  provider: string | undefined;
  modelId: string | undefined;
  config: AdvisorConfig;
  activeModel?: { provider: string; id: string };
}): { candidates: AdvisorCandidate[]; explicit: boolean } {
  const { provider, modelId, config, activeModel } = opts;
  if (provider || modelId) {
    if (!modelId)
      throw new Error(
        "An explicit advisor selection needs a model id (a provider alone is ambiguous).",
      );
    return {
      candidates: [{ target: { provider, model: modelId }, source: "explicit" }],
      explicit: true,
    };
  }

  const candidates: AdvisorCandidate[] = [];
  if (config.primary) candidates.push({ target: config.primary, source: "config primary" });
  if (config.fallback) candidates.push({ target: config.fallback, source: "config fallback" });
  if (
    config.activeModelFallback &&
    activeModel &&
    !candidates.some(
      ({ target }) =>
        target.model === activeModel.id &&
        (!target.provider || target.provider === activeModel.provider),
    )
  ) {
    candidates.push({
      target: { provider: activeModel.provider, model: activeModel.id },
      source: "active model fallback",
    });
  }
  return { candidates, explicit: false };
}

/** Character budget for the advisor request: context window minus a response reserve, minus the system prompt. */
export function requestCharBudget(model: BudgetModel, promptChars: number): number {
  if (!Number.isFinite(model.contextWindow) || model.contextWindow <= 0) return MAX_QUESTION_CHARS;
  const proportionalReserve = Math.max(
    MIN_RESPONSE_RESERVE_TOKENS,
    Math.floor(model.contextWindow * 0.2),
  );
  const responseReserve = Math.min(model.maxTokens || proportionalReserve, proportionalReserve);
  const inputTokens = Math.max(512, model.contextWindow - responseReserve);
  return Math.max(512, Math.floor(inputTokens * APPROX_CHARS_PER_TOKEN) - promptChars);
}

/**
 * Cap applied to EACH transcript entry before the transcript is joined, so
 * one large tool result cannot evict the rest of the caller-supplied context.
 */
export const MAX_TRANSCRIPT_ENTRY_CHARS = 8_000;
/** Marker used when a single transcript entry is capped. */
export const TRANSCRIPT_ENTRY_CAP_MARKER = "\n[entry truncated]";

/** Cap every entry of a caller-supplied transcript before joining. */
export function capTranscriptEntries(entries: string[]): string[] {
  return entries.map((entry) =>
    keepStart(entry, MAX_TRANSCRIPT_ENTRY_CHARS, TRANSCRIPT_ENTRY_CAP_MARKER),
  );
}

/**
 * Assemble the advisor request, shrinking to fit the model's budget. The
 * request always starts with the question. When the caller explicitly
 * supplied a transcript, it is appended under an "optional context" header
 * and trimmed first on overflow (it is the least load-bearing part); if the
 * transcript cannot absorb the overflow at all, it is dropped — including
 * its header — before the question is touched.
 */
export function assembleRequestText(
  model: BudgetModel,
  questionInput: string,
  transcriptInput: string,
  promptChars: number,
): string {
  const marker = "\n[Omitted to fit the advisor model's context window.]";
  const questionSection = `## Question\n${keepStart(questionInput, MAX_QUESTION_CHARS, marker)}`;
  const transcriptHeader =
    "## Optional context supplied by the caller (redacted, may be truncated; verify against the workspace)";
  const budget = requestCharBudget(model, promptChars);

  if (transcriptInput) {
    // Optional context may shrink to make room for the question, but it must
    // never force the question to truncate: drop it entirely if it cannot
    // coexist with the full question. The overhead is measured, not computed,
    // so the rendered output is guaranteed to fit the budget.
    const overhead = `${questionSection}\n\n${transcriptHeader}\n`.length;
    const room = budget - overhead;
    if (room >= transcriptInput.length) {
      return `${questionSection}\n\n${transcriptHeader}\n${transcriptInput}`;
    }
    if (room > 0) {
      // Shrink the transcript (tail-keeping) to exactly fill the room left by
      // the full question; verify the length before trusting it.
      const trimmed = keepEnd(transcriptInput, room, "[Earlier session context omitted.]\n\n");
      if (trimmed.length <= room) {
        return `${questionSection}\n\n${transcriptHeader}\n${trimmed}`;
      }
    }
    // No room for even a truncated transcript: drop it and fall through.
  }
  // The question alone, truncated only if the question itself exceeds the
  // budget (accounting for the "## Question\n" header).
  let question = keepStart(questionInput, MAX_QUESTION_CHARS, marker);
  const overflow = question.length + 12 - budget;
  if (overflow > 0) question = keepStart(question, Math.max(0, question.length - overflow), marker);
  return `## Question\n${question}`;
}

/** Ceiling for advice returned to the caller (the advisor's job is to save caller context, not spend it twice). */
export const ADVISOR_MAX_ADVICE_CHARS = 100_000;
/** Tighter ceiling for diagnostic/error text, which is not advice. */
export const ADVISOR_MAX_DIAGNOSTIC_CHARS = 4_000;

/**
 * Truncate text at a ceiling with a visible `[truncated]` marker. Text at or
 * under the limit passes through unchanged.
 */
function capText(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const omitted = text.length - limit;
  return `${text.slice(0, limit)}\n\n[truncated: ${omitted} more characters omitted]`;
}

/** Cap advice text at ADVISOR_MAX_ADVICE_CHARS with a visible truncation marker. */
export function capAdviceText(text: string): string {
  return capText(text, ADVISOR_MAX_ADVICE_CHARS);
}

/** Cap diagnostic/error text at ADVISOR_MAX_DIAGNOSTIC_CHARS with a visible truncation marker. */
export function capDiagnosticText(text: string): string {
  return capText(text, ADVISOR_MAX_DIAGNOSTIC_CHARS);
}

/**
 * A simple FIFO concurrency limiter: at most `max` units of work run at once;
 * further callers queue and complete in order rather than being rejected.
 */
export type ConcurrencyLimiter = {
  acquire(): Promise<void>;
  release(): void;
};

export function createConcurrencyLimiter(max: number): ConcurrencyLimiter {
  let active = 0;
  const queue: Array<() => void> = [];
  return {
    acquire(): Promise<void> {
      return new Promise<void>((resolve) => {
        if (active < max) {
          active += 1;
          resolve();
        } else {
          queue.push(() => {
            active += 1;
            resolve();
          });
        }
      });
    },
    release(): void {
      active -= 1;
      const next = queue.shift();
      if (next) next();
    },
  };
}

/**
 * Acquire a concurrency slot, but refuse to start the work if the caller was
 * aborted — already-aborted calls reject immediately without consuming a
 * slot, and calls aborted while queued refuse to start once their slot
 * arrives. A cancelled consultation must never start paid work.
 */
export async function withSlot<T>(
  limiter: ConcurrencyLimiter,
  signal: AbortSignal | undefined,
  run: () => Promise<T>,
): Promise<T> {
  if (signal?.aborted) throw new Error("aborted before the consultation started");
  await limiter.acquire();
  if (signal?.aborted) {
    limiter.release();
    throw new Error("aborted before the consultation started");
  }
  try {
    return await run();
  } finally {
    limiter.release();
  }
}

/** Milliseconds left on a deadline (0 once exhausted); pure so the chain wiring is testable. */
export function remainingBudgetMs(deadline: number, now: number): number {
  return Math.max(deadline - now, 0);
}

/** Sum two usage records, preserving optional fields' absence when neither side has them. */
export function addUsage(total: Usage | undefined, usage: Usage): Usage {
  if (!total) return structuredClone(usage);
  const reasoning =
    total.reasoning !== undefined || usage.reasoning !== undefined
      ? (total.reasoning ?? 0) + (usage.reasoning ?? 0)
      : undefined;
  const cacheWrite1h =
    total.cacheWrite1h !== undefined || usage.cacheWrite1h !== undefined
      ? (total.cacheWrite1h ?? 0) + (usage.cacheWrite1h ?? 0)
      : undefined;
  return {
    input: total.input + usage.input,
    output: total.output + usage.output,
    cacheRead: total.cacheRead + usage.cacheRead,
    cacheWrite: total.cacheWrite + usage.cacheWrite,
    ...(cacheWrite1h === undefined ? {} : { cacheWrite1h }),
    ...(reasoning === undefined ? {} : { reasoning }),
    totalTokens: total.totalTokens + usage.totalTokens,
    cost: {
      input: total.cost.input + usage.cost.input,
      output: total.cost.output + usage.cost.output,
      cacheRead: total.cost.cacheRead + usage.cost.cacheRead,
      cacheWrite: total.cost.cacheWrite + usage.cost.cacheWrite,
      total: total.cost.total + usage.cost.total,
    },
  };
}

/**
 * Accumulate one explore consultation's agent events into its result pieces.
 *
 * `agent_end` fires exactly once, at the end of the WHOLE run, and a failed or
 * interrupted run can end in an empty or synthetic assistant message — so
 * findings and usage must be collected per `message_end` (one per completed
 * assistant message), not from the terminal event.
 */
export class AdvisorEventAccumulator {
  toolCalls = 0;
  modelRequests = 0;
  private combinedUsage: Usage | undefined;
  private findings: string[] = [];
  private lastText = "";
  private lastErrorMessage: string | undefined;
  private sawAssistant = false;
  private lastStopReason: string | undefined;

  record(event: {
    type: string;
    toolName?: string;
    message?: unknown;
    messages?: unknown[];
  }): void {
    if (event.type === "turn_start") {
      this.modelRequests += 1;
      return;
    }
    if (event.type === "tool_execution_start") {
      this.toolCalls += 1;
      return;
    }
    if (event.type !== "message_end") return;
    const message = event.message as
      | {
          role?: string;
          content?: unknown;
          usage?: Usage;
          stopReason?: string;
          errorMessage?: string;
        }
      | undefined;
    if (message?.role !== "assistant") return;
    // Compute every derived value before mutating state, so a malformed usage
    // object (or content) cannot leave the accumulator half-updated: the
    // completion signal, stop reason, and final text must stay consistent even
    // if usage aggregation throws.
    const stopReason = message.stopReason;
    const isError = stopReason === "error";
    const errorMessage = isError ? message.errorMessage || "the model request failed" : undefined;
    const text = textFromContent(message.content).trim();
    let usage: Usage | undefined;
    if (message.usage) {
      try {
        usage = addUsage(this.combinedUsage, message.usage);
      } catch {
        // A malformed usage object must not corrupt completion tracking.
      }
    }
    this.sawAssistant = true;
    if (usage) this.combinedUsage = usage;
    if (stopReason !== undefined) this.lastStopReason = stopReason;
    // A failed turn records its error; a successful terminal turn clears the
    // history, so a transient error followed by a retry is not mislabeled as
    // "an error after this output".
    this.lastErrorMessage = errorMessage;
    this.lastText = text;
    if (text) {
      if (this.findings[this.findings.length - 1] !== text) this.findings.push(text);
    }
  }

  /** Final answer for a completed run; earlier findings for an interrupted one. */
  finalText(interrupted: boolean): string {
    return interrupted ? this.findings.join("\n\n") : this.lastText;
  }

  get usage(): Usage | undefined {
    return this.combinedUsage;
  }

  /** Error message from the last assistant message that ended in an error (if any). */
  get lastError(): string | undefined {
    return this.lastErrorMessage;
  }

  /** Stop reason of the last assistant message (if any assistant message arrived). */
  get stopReason(): string | undefined {
    return this.lastStopReason;
  }

  /** True once at least one assistant message_end event was recorded. */
  get assistantResponse(): boolean {
    return this.sawAssistant;
  }
}

/**
 * Prompt file content for the child process: the mode's system prompt plus the
 * budgeted request text. The child wraps file content in its own tags, so this
 * is delivered as a single @path argument.
 */
export function assembleChildPrompt(systemPrompt: string, requestText: string): string {
  return `${systemPrompt}\n\n---\n\n${requestText}`;
}

/** Host environment variables the child process needs to run (and nothing else). */
export function childBaseEnv(): Record<string, string> {
  const keys = [
    "PATH",
    "HOME",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
  ] as const;
  const env: Record<string, string> = {};
  for (const key of keys) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return env;
}

/**
 * Compose the child process environment. Starts from the base allowlist (never
 * touching the host process.env), then applies the child-scoped AWS settings
 * (awsProfile -> AWS_PROFILE, awsRegion -> AWS_REGION + AWS_DEFAULT_REGION) and
 * finally the verbatim `env` map, so an explicit `env` key overrides the AWS
 * mapping. There is no built-in profile or region default: each is applied only
 * when configured. The result is a fresh object — the host process.env is never
 * mutated, so concurrent consultations cannot race on it.
 */
export function buildChildEnv(
  config: { awsProfile?: string; awsRegion?: string; env?: Record<string, string> } | undefined,
  base: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = { ...base };
  if (!config) return out;
  if (config.awsProfile) out.AWS_PROFILE = config.awsProfile;
  if (config.awsRegion) {
    out.AWS_REGION = config.awsRegion;
    out.AWS_DEFAULT_REGION = config.awsRegion;
  }
  if (config.env) {
    for (const [key, value] of Object.entries(config.env)) out[key] = value;
  }
  return out;
}

/** True when a config `env` value is an object mapping names to non-empty string values. */
export function isChildEnv(value: unknown): value is Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.values(value as Record<string, unknown>).every(
    (v) => typeof v === "string" && v.length > 0,
  );
}

/**
 * Resolve the pi binary the child-process transport spawns:
 * config piBinary > $PI_BINARY > "pi" (resolved on PATH by the OS).
 */
export function resolvePiBinary(config: { piBinary?: string } | undefined, env: NodeJS.ProcessEnv) {
  const fromConfig = config?.piBinary?.trim();
  if (fromConfig) return fromConfig;
  const fromEnv = env.PI_BINARY?.trim();
  if (fromEnv) return fromEnv;
  return "pi";
}

/**
 * Remove OAuth refresh tokens from an auth.json document, so a spawned child
 * can never perform a token refresh. This is what protects the host's canonical
 * refresh token: a refresh the child performs would rotate it on the provider's
 * side (invalidating the host's token) *before* any local persistence, which a
 * read-only copy of the file does not prevent. With the refresh token stripped,
 * the child uses its (pre-refreshed, fresh) access token directly; if that
 * token ever expires mid-run, the child's refresh fails cleanly (no refresh
 * token to send) and degrades to an auth error handled by the fallback chain,
 * instead of corrupting the host credential.
 *
 * Pure and defensive: returns the input unchanged if it is not a JSON object of
 * provider -> credential maps; otherwise returns a re-serialized copy with each
 * credential's `refresh` field removed (all other fields preserved).
 */
export function stripRefreshTokens(authJsonText: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(authJsonText);
  } catch {
    return authJsonText;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return authJsonText;
  }
  const providers = parsed as { [providerId: string]: unknown };
  for (const id of Object.keys(providers)) {
    const credential = providers[id];
    if (typeof credential === "object" && credential !== null && !Array.isArray(credential)) {
      delete (credential as { [field: string]: unknown }).refresh;
    }
  }
  return JSON.stringify(parsed);
}

/**
 * Observed state of a finished, not-interrupted child advisor process, for
 * decideChildOutcome. Timeout and abort are handled by the caller before this
 * is reached, so they are not part of the state here.
 */
export type ChildCompletionState = {
  exitCode: number;
  /** Termination signal, if the child died to one. */
  signalCode: string | null;
  /** True once at least one assistant message_end event arrived. */
  assistantResponse: boolean;
  /** Stop reason of the last assistant message. */
  stopReason?: string;
  lastError?: string;
  /** Final answer for a completed run; earlier findings when interrupted. */
  text: string;
  /** Capped child stderr tail, for diagnostics. */
  stderr: string;
};

/**
 * Decide how a finished, non-interrupted child consultation is reported.
 *
 * pi exits 0 even when the model call failed (the error rides in the assistant
 * message) and even for some startup diagnostics, so the exit code alone is
 * not a success signal. Only a run that produced nonempty assistant text and
 * ended in a successful stop reason is "completed"; every failed, empty,
 * aborted, or abnormal run throws so the caller routes it to the fallback
 * model. Deadline timeouts and caller aborts are reported by the caller as
 * "timed_out" / "aborted" and never reach this function.
 */
export function decideChildOutcome(state: ChildCompletionState): {
  text: string;
  status: "completed";
} {
  if (state.signalCode)
    throw new Error(
      `the advisor child process was killed by signal ${state.signalCode} before completing`,
    );
  if (!state.assistantResponse)
    throw new Error(
      state.stderr.trim() ||
        state.lastError ||
        `the advisor child process (exit ${state.exitCode}) returned no assistant response`,
    );
  if (state.stopReason === "error") throw new Error(state.lastError ?? state.stderr);
  if (state.stopReason === "aborted") throw new Error("the advisor model call was aborted");
  // Only a clean "stop" is a completed answer. A response truncated at the
  // token limit ("length"), cut off for a tool call ("toolUse"), a still
  // unresolved deferred call ("deferred"), a pending turn, or a missing stop
  // reason is an incomplete/abnormal run — route it to the fallback model
  // rather than reporting partial advice as a completed answer. (pi's
  // AssistantMessage.stopReason is required, so a real finished turn always
  // carries "stop"; anything else means the run did not actually complete.)
  if (state.stopReason !== "stop")
    throw new Error(
      state.stopReason === undefined
        ? "the advisor model call ended without a stop reason"
        : `the advisor model call ended with stopReason "${state.stopReason}" (incomplete answer)`,
    );
  if (state.exitCode !== 0)
    throw new Error(
      `the advisor child process exited abnormally (exit ${state.exitCode})` +
        (state.stderr.trim() ? `: ${state.stderr.trim()}` : ""),
    );
  if (!state.text) throw new Error("the advisor returned no text");
  return { text: state.text, status: "completed" };
}

/**
 * Decode a stream of child stdout bytes into NDJSON events. Multibyte
 * characters can split across chunk boundaries (StringDecoder keeps decoding
 * consistent), and the final event may not be terminated by a newline —
 * `end()` flushes the decoder and surfaces any remaining partial line. Pass
 * an `onLine` callback that never throws; malformed lines are dropped by
 * `parseNdjsonLine`, never by this buffer.
 */
export class NdjsonLineBuffer {
  private readonly decoder = new StringDecoder("utf8");
  private pending = "";

  write(chunk: Buffer, onLine: (line: string) => void): void {
    this.pending += this.decoder.write(chunk);
    let idx = this.pending.indexOf("\n");
    while (idx >= 0) {
      const line = this.pending.slice(0, idx);
      this.pending = this.pending.slice(idx + 1);
      onLine(line);
      idx = this.pending.indexOf("\n");
    }
  }

  end(onLine: (line: string) => void): void {
    this.pending += this.decoder.end();
    if (this.pending.trim()) onLine(this.pending);
    this.pending = "";
  }
}

/**
 * Split one chunk of child stdout into complete NDJSON lines. Returns the
 * lines plus the (possibly empty) remainder to prepend to the next chunk.
 */
export function splitNdjsonLines(buffer: string): { lines: string[]; rest: string } {
  const lines: string[] = [];
  let rest = buffer;
  let idx = rest.indexOf("\n");
  while (idx >= 0) {
    lines.push(rest.slice(0, idx));
    rest = rest.slice(idx + 1);
    idx = rest.indexOf("\n");
  }
  return { lines, rest };
}

/**
 * Parse one NDJSON line into the event shape AdvisorEventAccumulator accepts.
 * Returns undefined for empty, non-JSON, or non-object lines — malformed
 * output must never crash the host process.
 */
export function parseNdjsonLine(
  line: string,
): { type: string; toolName?: string; message?: unknown; messages?: unknown[] } | undefined {
  const trimmed = line.trim();
  if (!trimmed) return undefined;
  let event: unknown;
  try {
    event = JSON.parse(trimmed);
  } catch {
    return undefined;
  }
  if (typeof event !== "object" || event === null) return undefined;
  const typed = event as {
    type?: unknown;
    toolName?: unknown;
    message?: unknown;
    messages?: unknown;
  };
  if (typeof typed.type !== "string") return undefined;
  const toolName = typeof typed.toolName === "string" ? typed.toolName : undefined;
  const messages = Array.isArray(typed.messages) ? typed.messages : undefined;
  return { type: typed.type, toolName, message: typed.message, messages };
}

/**
 * Build the argv for the child advisor pi process. The prompt is delivered as a
 * `@path` file reference (never as inline text) so prompt content cannot be
 * parsed as options or land in the child's argv.
 */
export function buildChildPiArgs(opts: {
  provider: string;
  modelId: string;
  effort: AdvisorReasoningEffort;
  /** Tools the child may use; empty for review mode (child gets --no-tools). */
  tools: string[];
  /** Absolute path to the prompt file inside the child's temp agent dir. */
  promptPath: string;
}): string[] {
  const args = [
    "--provider",
    opts.provider,
    "--model",
    opts.modelId,
    "--mode",
    "json",
    "--print",
    "--no-session",
    "--no-extensions",
    "--no-skills",
    "--no-prompt-templates",
    "--no-themes",
    "--no-context-files",
    "--no-approve",
  ];
  const thinking = effortToThinkingLevel(opts.effort);
  if (thinking) args.push("--thinking", thinking);
  args.push(
    opts.tools.length > 0 ? "--tools" : "--no-tools",
    ...(opts.tools.length > 0 ? [opts.tools.join(",")] : []),
  );
  args.push("--", `@${opts.promptPath}`);
  return args;
}

/** Map an advisor effort to the child's --thinking level ("none" means: omit the flag). */
export function effortToThinkingLevel(effort: AdvisorReasoningEffort): string | undefined {
  return effort === "none" ? undefined : effort;
}

/** Render a terminal result's text: optional prefix + advice-capped body + status footer. */
export function composeAdviceText(prefix: string, text: string, footer: string): string {
  return `${prefix}${capAdviceText(text)}${footer}`;
}

/**
 * Prefix for a timed-out consultation's terminal result: the incomplete marker
 * plus the partial output the caller still produced (advice-cap applied by the
 * caller, so this stays pure text).
 */
export function timeoutPrefix(
  mode: "review" | "explore",
  timeoutMs: number,
  partialText: string,
): string {
  const message =
    mode === "explore"
      ? `advisor timed out after ${Math.round(timeoutMs / 1000)} seconds (incomplete)`
      : `advisor request timed out after ${Math.round(timeoutMs / 1000)} seconds (incomplete)`;
  return (
    message +
    (partialText ? "\n\nPartial output before the timeout (incomplete, not a verdict):\n" : "")
  );
}
