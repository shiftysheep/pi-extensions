/**
 * In-session scheduled wakes for pi.
 *
 * The `cron` tool supports one-shot delays/timestamps and repeating intervals.
 * When a job is due, its message is sent as a user message so an idle agent
 * wakes up. State is snapshotted in the session with `appendEntry`, allowing
 * schedules to survive `/reload` without introducing a separate daemon.
 *
 * Schedules are scoped to the current session. They do not create OS-level cron
 * jobs and cannot wake pi after the process has exited.
 */

import { randomUUID } from "node:crypto";
import { StringEnum } from "@earendil-works/pi-ai";
import type { AgentToolResult } from "@earendil-works/pi-agent-core";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type, type Static } from "typebox";

const MAX_TIMER_DELAY_MS = 2_147_483_647; // Node's practical setTimeout limit (~24.8 days)
const MIN_EVERY_MS = 60_000;
const MAX_JOBS = 20;
const MAX_MESSAGE_LENGTH = 4_000;
const RESTORE_CATCH_UP_DELAY_MS = 250;
const CRON_STATE_TYPE = "cron-state";
const runtimeState = globalThis as typeof globalThis & { __piCronProcessNonce?: string };
// Kept on globalThis so `/reload` can restore schedules, while a new pi
// process gets a different nonce and ignores snapshots from older processes.
const PROCESS_NONCE = runtimeState.__piCronProcessNonce ?? (runtimeState.__piCronProcessNonce = randomUUID());
const DURATION_UNIT_MS: Record<string, number> = {
	s: 1_000,
	m: 60_000,
	h: 3_600_000,
	d: 86_400_000,
};
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,63}$/;

export type CronTrigger =
	| { kind: "once"; atMs: number }
	| { kind: "every"; everyMs: number; anchorAt: number; nextRunAt: number };

export interface CronJob {
	name: string;
	trigger: CronTrigger;
	message: string;
	paused: boolean;
	firedCount: number;
	lastFiredAt?: number;
}

export interface CronDetails {
	count: number;
	schedules: Array<{
		name: string;
		message: string;
		paused: boolean;
		firedCount: number;
		lastFiredAt?: number;
		trigger: CronTrigger;
	}>;
}

function invalid(message: string): never {
	throw new Error(`[cron] ${message}`);
}

function parseDuration(spec: string): number {
	const match = spec.trim().match(/^(\d+)([smhd])$/);
	if (!match) {
		invalid(`invalid duration "${spec}"; use <number><s|m|h|d>, for example "15m" or "2h".`);
	}

	const amount = Number(match[1]);
	const milliseconds = amount * DURATION_UNIT_MS[match[2]];
	if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) {
		invalid(`invalid duration "${spec}".`);
	}
	return milliseconds;
}

/** Parse a relative +delay or an ISO timestamp. Timestamps without a zone use local time. */
export function parseAt(value: string, now = Date.now()): number {
	const input = value.trim();
	const relative = input.match(/^\+(\d+)([smhd])$/);
	if (relative) {
		const delayMs = Number(relative[1]) * DURATION_UNIT_MS[relative[2]];
		if (!Number.isSafeInteger(delayMs) || delayMs < 1_000) {
			invalid(`invalid one-shot delay "${value}"; minimum relative delay is +1s.`);
		}
		if (delayMs > MAX_TIMER_DELAY_MS) {
			invalid("one-shot delays cannot exceed approximately 24 days.");
		}
		return now + delayMs;
	}

	const match = input.match(
		/^(\d{4})-(\d{2})-(\d{2})(?:T| )(\d{2}):(\d{2})(?::(\d{2}))?(Z|[+-]\d{2}:?\d{2})?$/,
	);
	if (!match) {
		invalid(
			`invalid at value "${value}"; use "+<number><s|m|h|d>" (for example "+30m") or an ISO timestamp like "2026-07-15T21:00".`,
		);
	}

	const year = Number(match[1]);
	const month = Number(match[2]);
	const day = Number(match[3]);
	const hour = Number(match[4]);
	const minute = Number(match[5]);
	const second = Number(match[6] ?? 0);
	if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
		invalid(`invalid timestamp "${value}".`);
	}
	const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
	if (day < 1 || day > daysInMonth) invalid(`invalid calendar date "${value}".`);

	const zone = match[7];
	if (zone?.toUpperCase() === "Z") {
		return Date.UTC(year, month - 1, day, hour, minute, second);
	}

	if (zone) {
		const normalized = input.replace(/([+-]\d{2})(\d{2})$/, "$1:$2").replace(" ", "T");
		const timestamp = new Date(normalized).getTime();
		if (Number.isNaN(timestamp)) invalid(`invalid timestamp "${value}".`);
		return timestamp;
	}

	const timestamp = new Date(year, month - 1, day, hour, minute, second).getTime();
	if (Number.isNaN(timestamp)) invalid(`invalid timestamp "${value}".`);
	return timestamp;
}

export function parseEvery(value: string): number {
	const milliseconds = parseDuration(value);
	if (milliseconds < MIN_EVERY_MS) invalid(`repeat interval "${value}" is too small; minimum is 1m.`);
	if (milliseconds > MAX_TIMER_DELAY_MS) invalid("repeat intervals cannot exceed approximately 24 days.");
	return milliseconds;
}

function nextRunAt(job: CronJob): number {
	return job.trigger.kind === "once" ? job.trigger.atMs : job.trigger.nextRunAt;
}

function formatDuration(milliseconds: number): string {
	if (milliseconds % 86_400_000 === 0) return `${milliseconds / 86_400_000}d`;
	if (milliseconds % 3_600_000 === 0) return `${milliseconds / 3_600_000}h`;
	if (milliseconds % 60_000 === 0) return `${milliseconds / 60_000}m`;
	return `${Math.round(milliseconds / 1_000)}s`;
}

function relativeTime(milliseconds: number): string {
	if (milliseconds <= 500) return "now";
	const seconds = Math.round(milliseconds / 1_000);
	if (seconds < 60) return `in ${seconds}s`;
	if (seconds < 3_600) return `in ${Math.floor(seconds / 60)}m${seconds % 60 ? ` ${seconds % 60}s` : ""}`;
	if (seconds < 86_400) return `in ${(milliseconds / 3_600_000).toFixed(1)}h`;
	return `in ${(milliseconds / 86_400_000).toFixed(1)}d`;
}

function oneLine(value: string): string {
	return value.replace(/[\r\n]+/g, " ");
}

function truncate(value: string, maxLength: number): string {
	const normalized = oneLine(value);
	return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized;
}

function describeJob(job: CronJob, now = Date.now()): string {
	const runAt = nextRunAt(job);
	if (job.trigger.kind === "once") {
		return `one-time ${new Date(runAt).toLocaleString()} (${relativeTime(Math.max(0, runAt - now))})`;
	}
	return `every ${formatDuration(job.trigger.everyMs)}; next ${new Date(runAt).toLocaleString()} (${relativeTime(runAt - now)})`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function parsePersistedJob(value: unknown): CronJob | undefined {
	if (!isRecord(value)) return undefined;
	const name = value.name;
	const message = value.message;
	const trigger = value.trigger;
	if (typeof name !== "string" || !NAME_RE.test(name) || typeof message !== "string" || !message.trim()) return undefined;
	if (!isRecord(trigger) || (trigger.kind !== "once" && trigger.kind !== "every")) return undefined;

	let parsedTrigger: CronTrigger;
	if (trigger.kind === "once") {
		if (typeof trigger.atMs !== "number" || !Number.isFinite(trigger.atMs)) return undefined;
		parsedTrigger = { kind: "once", atMs: trigger.atMs };
	} else {
		if (
			typeof trigger.everyMs !== "number" ||
			!Number.isFinite(trigger.everyMs) ||
			trigger.everyMs < MIN_EVERY_MS ||
			trigger.everyMs > MAX_TIMER_DELAY_MS ||
			typeof trigger.anchorAt !== "number" ||
			!Number.isFinite(trigger.anchorAt) ||
			typeof trigger.nextRunAt !== "number" ||
			!Number.isFinite(trigger.nextRunAt)
		) return undefined;
		parsedTrigger = {
			kind: "every",
			everyMs: trigger.everyMs,
			anchorAt: trigger.anchorAt,
			nextRunAt: trigger.nextRunAt,
		};
	}

	const firedCount = typeof value.firedCount === "number" && Number.isFinite(value.firedCount)
		? Math.max(0, Math.floor(value.firedCount))
		: 0;
	const lastFiredAt = typeof value.lastFiredAt === "number" && Number.isFinite(value.lastFiredAt)
		? value.lastFiredAt
		: undefined;
	return {
		name,
		trigger: parsedTrigger,
		message: message.trim().slice(0, MAX_MESSAGE_LENGTH),
		paused: value.paused === true,
		firedCount,
		lastFiredAt,
	};
}

const CronParamsSchema = Type.Object({
	action: StringEnum(["add", "list", "remove", "pause", "resume", "clear"] as const),
	name: Type.Optional(Type.String({ description: "Schedule name. Required by add/remove/pause/resume." })),
	at: Type.Optional(
		Type.String({
			description: 'One-shot trigger: relative "+30m"/"2h" or ISO timestamp (local time when no zone is given).',
		}),
	),
	every: Type.Optional(
		Type.String({
			description: 'Repeating interval such as "15m" or "2h"; minimum 1 minute.',
		}),
	),
	message: Type.Optional(Type.String({ description: "Message delivered when the schedule fires. Required by add." })),
});
type CronParams = Static<typeof CronParamsSchema>;
type CronResult = AgentToolResult<CronDetails>;

export default function cronExtension(pi: ExtensionAPI): void {
	const jobs = new Map<string, CronJob>();
	const timers = new Map<string, ReturnType<typeof setTimeout>>();
	let generation = 0;

	function details(): CronDetails {
		return {
			count: jobs.size,
			schedules: Array.from(jobs.values()).map((job) => ({
				name: job.name,
				message: job.message,
				paused: job.paused,
				firedCount: job.firedCount,
				...(job.lastFiredAt === undefined ? {} : { lastFiredAt: job.lastFiredAt }),
				trigger: job.trigger,
			})),
		};
	}

	function result(text: string): CronResult {
		return { content: [{ type: "text", text }], details: details() };
	}

	function listText(now = Date.now()): string {
		if (jobs.size === 0) return "[cron] No schedules.";
		const lines = [`[cron] ${jobs.size} schedule(s):`];
		for (const job of jobs.values()) {
			lines.push(
				`- ${job.paused ? "⏸" : "⏰"} ${job.name}: ${describeJob(job, now)}${job.firedCount ? `, fired ${job.firedCount}x` : ""}\n    "${truncate(job.message, 100)}"`,
			);
		}
		return lines.join("\n");
	}

	function persist(): void {
		pi.appendEntry(CRON_STATE_TYPE, {
			version: 1,
			processNonce: PROCESS_NONCE,
			jobs: Array.from(jobs.values()).map((job) => ({
				name: job.name,
				trigger: job.trigger,
				message: job.message,
				paused: job.paused,
				firedCount: job.firedCount,
				lastFiredAt: job.lastFiredAt,
			})),
		});
	}

	function disarm(name: string): void {
		const timer = timers.get(name);
		if (timer !== undefined) clearTimeout(timer);
		timers.delete(name);
	}

	function clearTimers(): void {
		for (const timer of timers.values()) clearTimeout(timer);
		timers.clear();
	}

	function arm(job: CronJob, delayMs: number): void {
		disarm(job.name);
		const timerGeneration = generation;
		const timer = setTimeout(() => {
			if (timerGeneration !== generation || jobs.get(job.name) !== job || job.paused) return;
			const remaining = nextRunAt(job) - Date.now();
			if (remaining > 0) {
				arm(job, remaining); // Re-check after the max setTimeout window.
				return;
			}
			fire(job, timerGeneration);
		}, Math.max(0, Math.min(delayMs, MAX_TIMER_DELAY_MS)));
		// Do not keep a non-interactive `pi -p` process alive solely for a timer.
		(timer as unknown as { unref?: () => void }).unref?.();
		timers.set(job.name, timer);
	}

	function deliver(job: CronJob): void {
		const message = `[cron:${job.name}] scheduled wake — ${job.message}`;
		try {
			// When idle this starts a turn immediately.
			pi.sendUserMessage(message);
		} catch {
			// While streaming, the no-options form throws; queue it after the turn.
			try {
				pi.sendUserMessage(message, { deliverAs: "steer" });
			} catch (error) {
				console.warn(`[cron:${job.name}] could not deliver scheduled wake: ${(error as Error).message}`);
			}
		}
	}

	function fire(job: CronJob, timerGeneration: number): void {
		if (timerGeneration !== generation || jobs.get(job.name) !== job || job.paused) return;
		disarm(job.name);

		const now = Date.now();
		job.firedCount += 1;
		job.lastFiredAt = now;
		if (job.trigger.kind === "once") {
			jobs.delete(job.name);
		} else {
			let next = job.trigger.nextRunAt;
			while (next <= now) next += job.trigger.everyMs;
			job.trigger.nextRunAt = next;
			arm(job, next - now);
		}
		// Persist the post-fire state before causing a new turn.
		persist();
		deliver(job);
	}

	function restore(ctx: ExtensionContext): void {
		generation += 1;
		clearTimers();
		jobs.clear();

		let latest: unknown;
		for (const entry of ctx.sessionManager.getEntries()) {
			if (
				entry.type === "custom" &&
				entry.customType === CRON_STATE_TYPE &&
				isRecord(entry.data) &&
				entry.data.version === 1 &&
				entry.data.processNonce === PROCESS_NONCE
			) {
				latest = entry.data;
			}
		}
		if (!isRecord(latest) || !Array.isArray(latest.jobs)) return;

		let changed = false;
		for (const raw of latest.jobs.slice(-MAX_JOBS)) {
			const job = parsePersistedJob(raw);
			if (!job || jobs.has(job.name)) {
				if (job) changed = true;
				continue;
			}
			jobs.set(job.name, job);

			if (job.paused) continue;
			const dueAt = nextRunAt(job);
			if (dueAt <= Date.now()) {
				// The snapshot is from this process, so a due job was interrupted by
				// reload/session switching. Keep the original due time so recurring
				// jobs preserve their cadence; fire() advances past missed slots.
				arm(job, RESTORE_CATCH_UP_DELAY_MS);
			} else {
				arm(job, dueAt - Date.now());
			}
		}

		if (changed) persist();
		const active = Array.from(jobs.values()).filter((job) => !job.paused);
		if (active.length > 0) {
			const soonest = Math.min(...active.map(nextRunAt));
			ctx.ui.notify(`[cron] restored ${jobs.size} schedule(s); next due ${relativeTime(soonest - Date.now())}.`, "info");
		}
	}

	pi.registerTool({
		name: "cron",
		label: "Cron Schedules",
		description: [
			"Manage in-session scheduled wakes for this pi session.",
			"When due, a schedule sends its message as a user message prefixed [cron:<name>] and wakes the agent if idle.",
			"",
			"Actions:",
			"- add: provide name, message, and exactly one of at or every.",
			"  at accepts +30m/+2h delays or ISO timestamps; every accepts intervals such as 15m or 2h.",
			"- list, remove, pause, resume, or clear.",
			"Schedules survive /reload and resume of this session file, but not a brand-new session or an exited pi process.",
			`Guardrails: at most ${MAX_JOBS} jobs, repeat intervals are at least 1 minute, and one-shot delays/repeats are at most about 24 days.`,
		].join("\n"),
		promptSnippet: "Schedule one-shot (+30m) or repeating (15m) wakes for this session",
		promptGuidelines: [
			"Use cron for delayed follow-up work in the current session; use list before creating duplicates and remove or clear schedules that are no longer needed.",
		],
		parameters: CronParamsSchema,
		async execute(_toolCallId, params: CronParams): Promise<CronResult> {
			switch (params.action) {
				case "add": {
					const name = params.name?.trim();
					if (!name || !NAME_RE.test(name)) invalid("add requires a valid name: start with a letter/digit and use at most 64 letters, digits, spaces, or . _ : -.");
					if (jobs.has(name)) invalid(`schedule "${name}" already exists; remove it first or choose another name.`);
					if (jobs.size >= MAX_JOBS) invalid(`cannot add another schedule; the limit is ${MAX_JOBS}.`);

					const hasAt = typeof params.at === "string" && params.at.trim().length > 0;
					const hasEvery = typeof params.every === "string" && params.every.trim().length > 0;
					if (hasAt === hasEvery) invalid("add requires exactly one of at or every.");
					const message = params.message?.trim();
					if (!message) invalid("add requires a non-empty message.");
					if (message.length > MAX_MESSAGE_LENGTH) invalid(`message is too long; maximum is ${MAX_MESSAGE_LENGTH} characters.`);

					const now = Date.now();
					let trigger: CronTrigger;
					if (hasAt) {
						const atMs = parseAt(params.at!, now);
						if (atMs <= now) invalid("one-shot time is already in the past.");
						if (atMs - now > MAX_TIMER_DELAY_MS) invalid("one-shot timestamps cannot be more than approximately 24 days away.");
						trigger = { kind: "once", atMs };
					} else {
						const everyMs = parseEvery(params.every!);
						trigger = { kind: "every", everyMs, anchorAt: now, nextRunAt: now + everyMs };
					}

					const job: CronJob = { name, trigger, message, paused: false, firedCount: 0 };
					jobs.set(name, job);
					persist();
					arm(job, nextRunAt(job) - now);
					return result(`scheduled "${name}": ${describeJob(job)}\n> fires as: [cron:${name}] ${truncate(message, 160)}`);
				}

				case "list":
					return result(listText());

				case "remove": {
					const name = params.name?.trim();
					if (!name) invalid("remove requires a name.");
					if (!jobs.has(name)) invalid(`no schedule named "${name}".`);
					disarm(name);
					jobs.delete(name);
					persist();
					return result(`removed "${name}".`);
				}

				case "pause": {
					const name = params.name?.trim();
					const job = name ? jobs.get(name) : undefined;
					if (!job) invalid(`no schedule named "${name ?? ""}".`);
					if (!job.paused) {
						job.paused = true;
						disarm(job.name);
						persist();
					}
					return result(`paused "${job.name}".`);
				}

				case "resume": {
					const name = params.name?.trim();
					const job = name ? jobs.get(name) : undefined;
					if (!job) invalid(`no schedule named "${name ?? ""}".`);
					job.paused = false;
					const delay = Math.max(0, nextRunAt(job) - Date.now());
					persist();
					arm(job, delay);
					return result(`resumed "${job.name}": ${describeJob(job)}.`);
				}

				case "clear": {
					const count = jobs.size;
					clearTimers();
					jobs.clear();
					persist();
					return result(count ? `cleared ${count} schedule(s).` : "nothing to clear.");
				}
			}
		},
	});

	pi.registerCommand("cron", {
		description: "Show in-session cron schedules",
		handler: async (_args, ctx) => {
			ctx.ui.notify(listText(), "info");
		},
	});

	pi.on("session_start", (_event, ctx) => {
		restore(ctx);
	});

	pi.on("session_shutdown", () => {
		generation += 1;
		clearTimers();
		jobs.clear();
	});
}
