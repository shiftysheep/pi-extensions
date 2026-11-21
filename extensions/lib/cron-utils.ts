/**
 * Pure scheduling/validation logic for the cron extension. Everything here is
 * side-effect free (no timers, no session state, no pi API) so it can be unit-tested
 * directly; the extension wires these into the tool/timers in extensions/cron.ts.
 */

export const MAX_TIMER_DELAY_MS = 2_147_483_647; // Node's practical setTimeout limit (~24.8 days)
export const MIN_EVERY_MS = 60_000;
export const MAX_JOBS = 20;
export const MAX_MESSAGE_LENGTH = 4_000;
export const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,63}$/;

export const DURATION_UNIT_MS: Record<string, number> = {
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

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

export function invalid(message: string): never {
  throw new Error(`[cron] ${message}`);
}

export function parseDuration(spec: string): number {
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
  if (milliseconds < MIN_EVERY_MS)
    invalid(`repeat interval "${value}" is too small; minimum is 1m.`);
  if (milliseconds > MAX_TIMER_DELAY_MS)
    invalid("repeat intervals cannot exceed approximately 24 days.");
  return milliseconds;
}

export function nextRunAt(job: CronJob): number {
  return job.trigger.kind === "once" ? job.trigger.atMs : job.trigger.nextRunAt;
}

/**
 * The next slot after a recurring job fires at `now` (>= now): the smallest
 * future multiple of the cadence strictly after `now`.
 */
export function advanceRecurringRunAt(
  trigger: Extract<CronTrigger, { kind: "every" }>,
  now: number,
): number {
  let next = trigger.nextRunAt;
  while (next <= now) next += trigger.everyMs;
  return next;
}

/** Build a trigger from the validated at/every params. Exactly one of the two is required. */
export function createCronTrigger(
  params: { at?: string; every?: string },
  now: number,
): CronTrigger {
  const hasAt = typeof params.at === "string" && params.at.trim().length > 0;
  const hasEvery = typeof params.every === "string" && params.every.trim().length > 0;
  if (hasAt === hasEvery) invalid("add requires exactly one of at or every.");
  if (!hasAt) {
    const everyMs = parseEvery(params.every ?? "");
    return { kind: "every", everyMs, anchorAt: now, nextRunAt: now + everyMs };
  }
  const atMs = parseAt(params.at ?? "", now);
  if (atMs <= now) invalid("one-shot time is already in the past.");
  if (atMs - now > MAX_TIMER_DELAY_MS)
    invalid("one-shot timestamps cannot be more than approximately 24 days away.");
  return { kind: "once", atMs };
}

export function validateCronName(input: string | undefined): string {
  const name = input?.trim();
  if (!name || !NAME_RE.test(name))
    invalid(
      "add requires a valid name: start with a letter/digit and use at most 64 letters, digits, spaces, or . _ : -.",
    );
  return name;
}

export function validateCronMessage(input: string | undefined): string {
  const message = input?.trim();
  if (!message) invalid("add requires a non-empty message.");
  if (message.length > MAX_MESSAGE_LENGTH)
    invalid(`message is too long; maximum is ${MAX_MESSAGE_LENGTH} characters.`);
  return message;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** Validate a restored (persisted) job from the session snapshot. Returns undefined for malformed entries. */
export function parsePersistedJob(value: unknown): CronJob | undefined {
  if (!isRecord(value)) return undefined;
  const name = value.name;
  const message = value.message;
  const trigger = value.trigger;
  if (
    typeof name !== "string" ||
    !NAME_RE.test(name) ||
    typeof message !== "string" ||
    !message.trim()
  )
    return undefined;
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
    )
      return undefined;
    parsedTrigger = {
      kind: "every",
      everyMs: trigger.everyMs,
      anchorAt: trigger.anchorAt,
      nextRunAt: trigger.nextRunAt,
    };
  }

  const firedCount =
    typeof value.firedCount === "number" && Number.isFinite(value.firedCount)
      ? Math.max(0, Math.floor(value.firedCount))
      : 0;
  const lastFiredAt =
    typeof value.lastFiredAt === "number" && Number.isFinite(value.lastFiredAt)
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

export function formatDuration(milliseconds: number): string {
  if (milliseconds % 86_400_000 === 0) return `${milliseconds / 86_400_000}d`;
  if (milliseconds % 3_600_000 === 0) return `${milliseconds / 3_600_000}h`;
  if (milliseconds % 60_000 === 0) return `${milliseconds / 60_000}m`;
  return `${Math.round(milliseconds / 1_000)}s`;
}

export function relativeTime(milliseconds: number): string {
  if (milliseconds <= 500) return "now";
  const seconds = Math.round(milliseconds / 1_000);
  if (seconds < 60) return `in ${seconds}s`;
  if (seconds < 3_600)
    return `in ${Math.floor(seconds / 60)}m${seconds % 60 ? ` ${seconds % 60}s` : ""}`;
  if (seconds < 86_400) return `in ${(milliseconds / 3_600_000).toFixed(1)}h`;
  return `in ${(milliseconds / 86_400_000).toFixed(1)}d`;
}

export function oneLine(value: string): string {
  return value.replace(/[\r\n]+/g, " ");
}

export function truncate(value: string, maxLength: number): string {
  const normalized = oneLine(value);
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized;
}
