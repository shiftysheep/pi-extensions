/**
 * Pure helpers for the advisor extension: config parsing, secret redaction,
 * prompt character budgeting, model candidate ordering, and effort-suffix
 * parsing. Kept free of pi imports and side effects (no fs, no
 * ExtensionContext) so they can be unit-tested without a live session.
 */

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
// Defaults for explore-mode spend caps; tunable per install via advisor.json `exploreBudget`.
export const ADVISOR_MAX_TOOL_CALLS = 24;
export const ADVISOR_MAX_MODEL_REQUESTS = 12;
// Hard ceilings for configured budgets, so a typo can't make an exploration unbounded.
export const EXPLORE_BUDGET_LIMITS = { toolCalls: 100, modelRequests: 40 } as const;
const APPROX_CHARS_PER_TOKEN = 3.5;
const MIN_RESPONSE_RESERVE_TOKENS = 1_024;

export type AdvisorTarget = { provider?: string; model: string; effort?: AdvisorReasoningEffort };
export type AdvisorExploreBudget = { toolCalls: number; modelRequests: number };
export type AdvisorConfig = {
  primary?: AdvisorTarget;
  fallback?: AdvisorTarget;
  reasoningEffort?: AdvisorReasoningEffort;
  exploreBudget?: AdvisorExploreBudget;
  /** Opt in to retrying the caller's active model last (a self-review, disclosed in the result). */
  activeModelFallback?: boolean;
  /** Consultation timeout in milliseconds, clamped to [ADVISOR_MIN_TIMEOUT_MS, ADVISOR_MAX_TIMEOUT_MS]. */
  timeoutMs?: number;
};

/** Allowed top-level advisor.json keys; anything else is a typo and is rejected. */
export const ALLOWED_CONFIG_KEYS = [
  "primary",
  "fallback",
  "reasoningEffort",
  "exploreBudget",
  "activeModelFallback",
  "timeoutMs",
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

export function parseExploreBudget(
  value: unknown,
  configPath: string,
): AdvisorExploreBudget | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object")
    throw new Error(`${configPath}: exploreBudget must be an object with toolCalls/modelRequests.`);
  const candidate = value as { toolCalls?: unknown; modelRequests?: unknown };
  const unknownBudgetKeys = Object.keys(candidate).filter(
    (k) => k !== "toolCalls" && k !== "modelRequests",
  );
  if (unknownBudgetKeys.length > 0) {
    throw new Error(
      `${configPath}: exploreBudget has unknown key${unknownBudgetKeys.length > 1 ? "s" : ""} ${unknownBudgetKeys.map((k) => `"${k}"`).join(", ")} (allowed: toolCalls, modelRequests).`,
    );
  }
  if (candidate.toolCalls === undefined && candidate.modelRequests === undefined) {
    throw new Error(
      `${configPath}: exploreBudget requires at least one of toolCalls/modelRequests.`,
    );
  }
  const parseField = (name: "toolCalls" | "modelRequests", v: unknown, fallback: number) => {
    if (v === undefined) return fallback;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1)
      throw new Error(`${configPath}: exploreBudget.${name} must be a positive integer.`);
    if (v > EXPLORE_BUDGET_LIMITS[name])
      throw new Error(
        `${configPath}: exploreBudget.${name} must be at most ${EXPLORE_BUDGET_LIMITS[name]}.`,
      );
    return v;
  };
  return {
    toolCalls: parseField("toolCalls", candidate.toolCalls, ADVISOR_MAX_TOOL_CALLS),
    modelRequests: parseField("modelRequests", candidate.modelRequests, ADVISOR_MAX_MODEL_REQUESTS),
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
    exploreBudget: parseExploreBudget(config.exploreBudget, configPath),
    activeModelFallback: config.activeModelFallback,
    timeoutMs: config.timeoutMs,
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
 * Assemble the advisor request, shrinking to fit the model's budget. The
 * transcript is trimmed first (it is the least load-bearing part); the
 * question is only truncated once the transcript is already at its floor.
 */
export function assembleRequestText(
  model: BudgetModel,
  questionInput: string,
  transcriptInput: string,
  promptChars: number,
): string {
  const marker = "\n[Omitted to fit the advisor model's context window.]";
  let question = keepStart(questionInput, MAX_QUESTION_CHARS, marker);
  let transcript = transcriptInput || "(empty)";
  const render = () =>
    `## Question\n${question}\n\n## Recent session history (redacted; may be truncated)\nYou can also inspect the workspace yourself with read/grep/find/ls.\n${transcript}`;
  const budget = requestCharBudget(model, promptChars);

  let overflow = render().length - budget;
  if (overflow > 0) {
    transcript = keepEnd(
      transcript,
      Math.max(0, transcript.length - overflow),
      "[Earlier session context omitted.]\n\n",
    );
    overflow = render().length - budget;
  }
  if (overflow > 0) question = keepStart(question, Math.max(0, question.length - overflow), marker);
  return render();
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
