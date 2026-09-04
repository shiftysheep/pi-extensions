/**
 * Advisor: consult a separate model from the active Pi agent.
 *
 * Model defaults live in ~/.pi/agent/advisor.json. Any configured Pi model can
 * be selected per consultation, including models from custom providers.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { uuidv7, type Model, type ThinkingLevel, type Usage, type UserMessage } from "@earendil-works/pi-ai";
import { getAgentDir, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const CONFIG_PATH = join(getAgentDir(), "advisor.json");
const LEGACY_PREFERRED_MODEL = "gpt-5.6-sol";
const MAX_SESSION_CONTEXT_CHARS = 60_000;
const MAX_EXTRA_CONTEXT_CHARS = 40_000;
const MAX_QUESTION_CHARS = 20_000;
const APPROX_CHARS_PER_TOKEN = 3.5;
const MIN_RESPONSE_RESERVE_TOKENS = 1_024;

const REASONING_EFFORTS = ["none", "minimal", "low", "medium", "high", "xhigh", "max"] as const;
type AdvisorReasoningEffort = (typeof REASONING_EFFORTS)[number];

const SYSTEM_PROMPT = `You are an independent senior engineering advisor. Give the
calling coding agent a rigorous second opinion; do not attempt to use tools or
claim that you inspected anything not included in the request. Prioritize concrete
issues, correctness, security, maintainability, and a practical next action.

For reviews, list only material findings, explain impact, and identify the affected
file/function when supplied. For design questions, compare viable options and make
a recommendation. Be concise but specific. State uncertainty or missing evidence
instead of inventing facts.`;

type AdvisorTarget = { provider?: string; model: string };
type AdvisorConfig = { primary?: AdvisorTarget; fallback?: AdvisorTarget; reasoningEffort?: AdvisorReasoningEffort };
type AdvisorCandidate = { target: AdvisorTarget; source: string };

function textFromContent(content: unknown): string {
	if (!Array.isArray(content)) return "";
	return content
		.filter((part): part is { type: string; text: string } =>
			Boolean(part && typeof part === "object" && (part as { type?: unknown }).type === "text" && typeof (part as { text?: unknown }).text === "string"),
		)
		.map((part) => part.text)
		.join("\n");
}

/** Best-effort guardrail only; callers should still avoid putting secrets in advisor context. */
function redactSensitiveText(text: string): string {
	return text
		.replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/gi, "[REDACTED PRIVATE KEY]")
		.replace(/\b(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+/gi, "$1[REDACTED]")
		.replace(
			/(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)\b\s*[=:]\s*)(["']?)[^\s,"'}\]]+/gi,
			"$1$2[REDACTED]",
		)
		.replace(/\b(?:sk|ghp|github_pat|xox[baprs])-[A-Za-z0-9_\-]{12,}\b/g, "[REDACTED TOKEN]");
}

function keepEnd(text: string, maxChars: number, marker: string): string {
	if (text.length <= maxChars) return text;
	if (maxChars <= marker.length) return marker.slice(0, Math.max(0, maxChars));
	return `${marker}${text.slice(-(maxChars - marker.length))}`;
}

function keepStart(text: string, maxChars: number, marker: string): string {
	if (text.length <= maxChars) return text;
	if (maxChars <= marker.length) return marker.slice(0, Math.max(0, maxChars));
	return `${text.slice(0, maxChars - marker.length)}${marker}`;
}

function sessionTranscript(ctx: { sessionManager: { getBranch(): unknown[] } }): string {
	const lines: string[] = [];
	for (const entry of ctx.sessionManager.getBranch() as Array<Record<string, unknown>>) {
		if (entry.type !== "message") continue;
		const message = entry.message as { role?: string; content?: unknown; toolName?: string } | undefined;
		if (!message) continue;
		const text = textFromContent(message.content);
		if (!text) continue;
		const label = message.role === "toolResult" ? `tool ${message.toolName ?? "result"}` : message.role ?? "message";
		lines.push(`### ${label}\n${text}`);
	}

	const transcript = redactSensitiveText(lines.join("\n\n"));
	return keepEnd(transcript, MAX_SESSION_CONTEXT_CHARS, "[Earlier session context omitted.]\n\n");
}

function responseText(content: unknown): string {
	return textFromContent(content).trim() || "The advisor returned no text.";
}

function addUsage(total: Usage | undefined, usage: Usage): Usage {
	if (!total) return structuredClone(usage);
	const reasoning = total.reasoning !== undefined || usage.reasoning !== undefined
		? (total.reasoning ?? 0) + (usage.reasoning ?? 0)
		: undefined;
	const cacheWrite1h = total.cacheWrite1h !== undefined || usage.cacheWrite1h !== undefined
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

function parseTarget(value: unknown, field: string): AdvisorTarget | undefined {
	if (value === undefined) return undefined;
	if (!value || typeof value !== "object") throw new Error(`${CONFIG_PATH}: ${field} must be an object.`);
	const candidate = value as { provider?: unknown; model?: unknown };
	if (typeof candidate.model !== "string" || !candidate.model.trim()) {
		throw new Error(`${CONFIG_PATH}: ${field}.model must be a non-empty string.`);
	}
	if (candidate.provider !== undefined && (typeof candidate.provider !== "string" || !candidate.provider.trim())) {
		throw new Error(`${CONFIG_PATH}: ${field}.provider must be a non-empty string when provided.`);
	}
	return { provider: candidate.provider?.trim() as string | undefined, model: candidate.model.trim() };
}

function isReasoningEffort(value: unknown): value is AdvisorReasoningEffort {
	return typeof value === "string" && (REASONING_EFFORTS as readonly string[]).includes(value);
}

function loadConfig(): AdvisorConfig {
	try {
		const parsed: unknown = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
		if (!parsed || typeof parsed !== "object") throw new Error(`${CONFIG_PATH}: top level must be an object.`);
		const config = parsed as { primary?: unknown; fallback?: unknown; reasoningEffort?: unknown };
		if (config.reasoningEffort !== undefined && !REASONING_EFFORTS.includes(config.reasoningEffort as AdvisorReasoningEffort)) {
			throw new Error(`${CONFIG_PATH}: reasoningEffort must be one of: ${REASONING_EFFORTS.join(", ")}.`);
		}
		return {
			primary: parseTarget(config.primary, "primary"),
			fallback: parseTarget(config.fallback, "fallback"),
			reasoningEffort: config.reasoningEffort as AdvisorReasoningEffort | undefined,
		};
	} catch (error: unknown) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
		if (error instanceof SyntaxError) throw new Error(`${CONFIG_PATH}: invalid JSON: ${error.message}`);
		throw error;
	}
}

function findModel(ctx: ExtensionContext, target: AdvisorTarget): Model<any> {
	const matches = ctx.modelRegistry
		.getAll()
		.filter((model) => model.id === target.model && (!target.provider || model.provider === target.provider));
	if (matches.length === 1) return matches[0];
	if (matches.length > 1) throw new Error(`Model "${target.model}" is offered by multiple providers. Specify advisor.provider.`);
	const scope = target.provider ? ` on provider "${target.provider}"` : "";
	throw new Error(`Advisor model "${target.model}" is not configured${scope}. Use a provider/model shown by Pi's /model command.`);
}

function buildCandidates(
	ctx: ExtensionContext,
	provider: string | undefined,
	modelId: string | undefined,
	config: AdvisorConfig,
): { candidates: AdvisorCandidate[]; explicit: boolean } {
	if (provider || modelId) {
		return {
			candidates: [{ target: { provider, model: modelId ?? LEGACY_PREFERRED_MODEL }, source: "explicit" }],
			explicit: true,
		};
	}

	const candidates: AdvisorCandidate[] = [];
	if (config.primary) candidates.push({ target: config.primary, source: "config primary" });
	if (config.fallback) candidates.push({ target: config.fallback, source: "config fallback" });
	if (candidates.length === 0) candidates.push({ target: { model: LEGACY_PREFERRED_MODEL }, source: "built-in preference" });
	if (ctx.model && !candidates.some(({ target }) => target.model === ctx.model?.id && (!target.provider || target.provider === ctx.model?.provider))) {
		candidates.push({ target: { provider: ctx.model.provider, model: ctx.model.id }, source: "active model fallback" });
	}
	return { candidates, explicit: false };
}

function requestCharBudget(model: Model<any>): number {
	if (!Number.isFinite(model.contextWindow) || model.contextWindow <= 0) return MAX_QUESTION_CHARS + MAX_EXTRA_CONTEXT_CHARS;
	const proportionalReserve = Math.max(MIN_RESPONSE_RESERVE_TOKENS, Math.floor(model.contextWindow * 0.2));
	const responseReserve = Math.min(model.maxTokens || proportionalReserve, proportionalReserve);
	const inputTokens = Math.max(512, model.contextWindow - responseReserve);
	return Math.max(512, Math.floor(inputTokens * APPROX_CHARS_PER_TOKEN) - SYSTEM_PROMPT.length);
}

function assembleRequestText(
	model: Model<any>,
	questionInput: string,
	contextInput: string | undefined,
	transcriptInput: string,
): string {
	const marker = "\n[Omitted to fit the advisor model's context window.]";
	let question = keepStart(questionInput, MAX_QUESTION_CHARS, marker);
	let suppliedContext = keepStart(contextInput ?? "(none supplied)", MAX_EXTRA_CONTEXT_CHARS, marker);
	let transcript = transcriptInput || "(empty)";
	const render = () => `## Question\n${question}\n\n## Evidence supplied by the calling agent\n${suppliedContext}\n\n## Recent session history (supplemental; may be incomplete and is redacted)\n${transcript}`;
	const budget = requestCharBudget(model);

	let overflow = render().length - budget;
	if (overflow > 0) {
		transcript = keepEnd(transcript, Math.max(0, transcript.length - overflow), "[Earlier session context omitted.]\n\n");
		overflow = render().length - budget;
	}
	if (overflow > 0) {
		suppliedContext = keepStart(suppliedContext, Math.max(0, suppliedContext.length - overflow), marker);
		overflow = render().length - budget;
	}
	if (overflow > 0) question = keepStart(question, Math.max(0, question.length - overflow), marker);
	return render();
}

function neutralReasoningEffort(model: Model<any>, effort: AdvisorReasoningEffort): ThinkingLevel | undefined {
	if (!model.reasoning || effort === "none") return undefined;
	return effort;
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "advisor",
		label: "Advisor",
		description: 'Consult any configured Pi model for an independent expert review, debugging second opinion, or design recommendation. Optionally select provider, model, and reasoning effort ("none".."max"). Defaults and request-level fallback are read from ~/.pi/agent/advisor.json. Session history is included only when includeSession is explicitly true.',
		promptSnippet: "Consult a configured Pi model for an independent expert review or design second opinion",
		promptGuidelines: [
			"Use advisor after gathering relevant evidence when a task would benefit from an independent code review, debugging second opinion, security assessment, or design decision.",
			"Use advisor.provider and advisor.model to select a configured Pi model when the configured advisor defaults are not appropriate.",
			"Give advisor the specific question and relevant evidence in context; do not include secrets. Include session history only when its disclosure to the advisor provider is appropriate.",
			"Treat the advisor response as advice to validate, not authority to blindly follow.",
		],
		parameters: Type.Object({
			question: Type.String({ description: "The precise review, diagnosis, or design question for the advisor." }),
			provider: Type.Optional(Type.String({ description: "Pi provider ID to use, for example openai-codex, anthropic, or ollama." })),
			model: Type.Optional(Type.String({ description: "Configured Pi model ID to use. Explicit selection does not use configured fallbacks." })),
			context: Type.Optional(Type.String({ description: "Relevant code, diff, logs, constraints, and findings already gathered. Do not include secrets." })),
			effort: Type.Optional(Type.String({
				description: 'Override the configured advisor reasoning effort for this consultation (defaults to advisor.json "reasoningEffort", then medium). "none" disables reasoning.',
				enum: [...REASONING_EFFORTS],
			})),
			includeSession: Type.Optional(Type.Boolean({ description: "Include recent redacted textual session history as supplemental context. Default: false." })),
		}),
		async execute(
			_toolCallId,
			params: {
				question: string;
				provider?: string;
				model?: string;
				context?: string;
				effort?: string;
				includeSession?: boolean;
			},
			signal,
			onUpdate,
			ctx,
		) {
			if (params.effort !== undefined && !isReasoningEffort(params.effort)) {
				throw new Error(`Invalid advisor effort "${params.effort}". Expected one of: ${REASONING_EFFORTS.join(", ")}.`);
			}

			const hasExplicitTarget = Boolean(params.provider || params.model);
			const config = !hasExplicitTarget || params.effort === undefined ? loadConfig() : {};
			const selectedEffort = (params.effort as AdvisorReasoningEffort | undefined) ?? config.reasoningEffort ?? "medium";
			const { candidates, explicit } = buildCandidates(ctx, params.provider, params.model, config);
			const transcript = params.includeSession === true ? sessionTranscript(ctx) : "(not included)";
			const failures: string[] = [];
			let combinedUsage: Usage | undefined;

			for (const candidate of candidates) {
				let model: Model<any>;
				try {
					model = findModel(ctx, candidate.target);
				} catch (error) {
					failures.push(`${candidate.source}: ${(error as Error).message}`);
					continue;
				}

				const modelLabel = `${model.provider}/${model.id}`;
				try {
					const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
					if (!auth.ok) throw new Error(auth.error);
					const provider = ctx.modelRegistry.getProvider(model.provider);
					if (!provider) throw new Error(`Provider "${model.provider}" is not registered.`);
					const requestModel = auth.baseUrl ? { ...model, baseUrl: auth.baseUrl } : model;
					const request: UserMessage = {
						role: "user",
						content: [{ type: "text", text: assembleRequestText(model, params.question, params.context, transcript) }],
						timestamp: Date.now(),
					};

				onUpdate?.({
					content: [{ type: "text", text: `Consulting ${modelLabel} (${candidate.source})...` }],
					details: { model: modelLabel, source: candidate.source },
				});
					const response = await provider
						.streamSimple(
							requestModel,
							{ systemPrompt: SYSTEM_PROMPT, messages: [request] },
							{
								apiKey: auth.apiKey,
								headers: auth.headers,
								env: auth.env,
								signal,
								reasoning: neutralReasoningEffort(model, selectedEffort),
								cacheRetention: "none",
								sessionId: uuidv7(),
							},
						)
						.result();

					combinedUsage = addUsage(combinedUsage, response.usage);
					if (response.stopReason === "aborted") return {
						content: [{ type: "text", text: "Advisor consultation cancelled." }],
						details: { model: modelLabel, source: candidate.source },
						usage: combinedUsage,
					};
					if (response.stopReason === "error") throw new Error(response.errorMessage || "The advisor request failed without an error message.");
					return {
						content: [{ type: "text", text: responseText(response.content) }],
						details: { model: modelLabel, source: candidate.source, stopReason: response.stopReason },
						usage: combinedUsage,
					};
				} catch (error) {
					if (signal?.aborted) {
						return { content: [{ type: "text", text: "Advisor consultation cancelled." }], details: { model: modelLabel, source: candidate.source } };
					}
					const message = error instanceof Error ? error.message : String(error);
					if (explicit) throw new Error(`${modelLabel}: ${message}`);
					failures.push(`${candidate.source} (${modelLabel}): ${message}`);
				}
			}

			throw new Error(`No usable advisor model. ${failures.join("; ")}`);
		},
	});
}
