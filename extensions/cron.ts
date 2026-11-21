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
import type { AgentToolResult } from "@earendil-works/pi-agent-core";
import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { type Static, Type } from "typebox";
import {
  advanceRecurringRunAt,
  type CronJob,
  type CronTrigger,
  createCronTrigger,
  formatDuration,
  invalid,
  isRecord,
  MAX_JOBS,
  MAX_TIMER_DELAY_MS,
  nextRunAt,
  parsePersistedJob,
  relativeTime,
  truncate,
  validateCronMessage,
  validateCronName,
} from "./lib/cron-utils.js";

export type { CronJob, CronTrigger };

const RESTORE_CATCH_UP_DELAY_MS = 250;
const CRON_STATE_TYPE = "cron-state";
const runtimeState = globalThis as typeof globalThis & { __piCronProcessNonce?: string };
// Kept on globalThis so `/reload` can restore schedules, while a new pi
// process gets a different nonce and ignores snapshots from older processes.
if (runtimeState.__piCronProcessNonce === undefined) {
  runtimeState.__piCronProcessNonce = randomUUID();
}
const PROCESS_NONCE = runtimeState.__piCronProcessNonce;

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

function describeJob(job: CronJob, now = Date.now()): string {
  const runAt = nextRunAt(job);
  if (job.trigger.kind === "once") {
    return `one-time ${new Date(runAt).toLocaleString()} (${relativeTime(Math.max(0, runAt - now))})`;
  }
  return `every ${formatDuration(job.trigger.everyMs)}; next ${new Date(runAt).toLocaleString()} (${relativeTime(runAt - now)})`;
}

const CronParamsSchema = Type.Object({
  action: StringEnum(["add", "list", "remove", "pause", "resume", "clear"] as const),
  name: Type.Optional(
    Type.String({ description: "Schedule name. Required by add/remove/pause/resume." }),
  ),
  at: Type.Optional(
    Type.String({
      description:
        'One-shot trigger: relative "+30m"/"2h" or ISO timestamp (local time when no zone is given).',
    }),
  ),
  every: Type.Optional(
    Type.String({
      description: 'Repeating interval such as "15m" or "2h"; minimum 1 minute.',
    }),
  ),
  message: Type.Optional(
    Type.String({ description: "Message delivered when the schedule fires. Required by add." }),
  ),
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
    const timer = setTimeout(
      () => {
        if (timerGeneration !== generation || jobs.get(job.name) !== job || job.paused) return;
        const remaining = nextRunAt(job) - Date.now();
        if (remaining > 0) {
          arm(job, remaining); // Re-check after the max setTimeout window.
          return;
        }
        fire(job, timerGeneration);
      },
      Math.max(0, Math.min(delayMs, MAX_TIMER_DELAY_MS)),
    );
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
        console.warn(
          `[cron:${job.name}] could not deliver scheduled wake: ${(error as Error).message}`,
        );
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
      job.trigger.nextRunAt = advanceRecurringRunAt(job.trigger, now);
      const next = job.trigger.nextRunAt;
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

    const latest = latestCronSnapshot(ctx);
    if (!isRecord(latest) || !Array.isArray(latest.jobs)) return;

    const changed = restoreJobs(latest.jobs);

    if (changed) persist();
    const active = Array.from(jobs.values()).filter((job) => !job.paused);
    if (active.length > 0) {
      const soonest = Math.min(...active.map(nextRunAt));
      ctx.ui.notify(
        `[cron] restored ${jobs.size} schedule(s); next due ${relativeTime(soonest - Date.now())}.`,
        "info",
      );
    }
  }

  function latestCronSnapshot(ctx: ExtensionContext): Record<string, unknown> | undefined {
    let latest: unknown;
    for (const entry of ctx.sessionManager.getEntries()) {
      if (
        entry.type === "custom" &&
        entry.customType === CRON_STATE_TYPE &&
        isRecord(entry.data) &&
        entry.data.version === 1 &&
        entry.data.processNonce === PROCESS_NONCE
      )
        latest = entry.data;
    }
    return isRecord(latest) ? latest : undefined;
  }

  function restoreJobs(rawJobs: unknown[]): boolean {
    let changed = false;
    for (const raw of rawJobs.slice(-MAX_JOBS)) {
      const job = parsePersistedJob(raw);
      if (!job || jobs.has(job.name)) {
        if (job) changed = true;
        continue;
      }
      jobs.set(job.name, job);
      if (!job.paused) armRestoredJob(job);
    }
    return changed;
  }

  function armRestoredJob(job: CronJob): void {
    const dueAt = nextRunAt(job);
    // Keep overdue recurring jobs on their original cadence; fire() advances missed slots.
    arm(job, dueAt <= Date.now() ? RESTORE_CATCH_UP_DELAY_MS : dueAt - Date.now());
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
        case "add":
          return handleAdd(params);
        case "list":
          return result(listText());
        case "remove":
          return handleRemove(params);
        case "pause":
          return handlePause(params);
        case "resume":
          return handleResume(params);
        case "clear": {
          const count = jobs.size;
          clearTimers();
          jobs.clear();
          persist();
          return result(count ? `cleared ${count} schedule(s).` : "nothing to clear.");
        }
        default:
          return invalid("unknown action.");
      }
    },
  });

  /** /cron add: validate and create a new schedule. */
  function handleAdd(params: CronParams): CronResult {
    const name = validateCronName(params.name);
    if (jobs.has(name))
      invalid(`schedule "${name}" already exists; remove it first or choose another name.`);
    if (jobs.size >= MAX_JOBS) invalid(`cannot add another schedule; the limit is ${MAX_JOBS}.`);

    const message = validateCronMessage(params.message);

    const now = Date.now();
    const trigger = createCronTrigger(params, now);

    const job: CronJob = { name, trigger, message, paused: false, firedCount: 0 };
    jobs.set(name, job);
    persist();
    arm(job, nextRunAt(job) - now);
    return result(
      `scheduled "${name}": ${describeJob(job)}\n> fires as: [cron:${name}] ${truncate(message, 160)}`,
    );
  }

  /** /cron remove: remove a schedule by name. */
  function handleRemove(params: CronParams): CronResult {
    const name = params.name?.trim();
    if (!name) invalid("remove requires a name.");
    if (!jobs.has(name)) invalid(`no schedule named "${name}".`);
    disarm(name);
    jobs.delete(name);
    persist();
    return result(`removed "${name}".`);
  }

  /** /cron pause: pause a schedule. */
  function handlePause(params: CronParams): CronResult {
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

  /** /cron resume: resume a paused schedule. */
  function handleResume(params: CronParams): CronResult {
    const name = params.name?.trim();
    const job = name ? jobs.get(name) : undefined;
    if (!job) invalid(`no schedule named "${name ?? ""}".`);
    job.paused = false;
    const delay = Math.max(0, nextRunAt(job) - Date.now());
    persist();
    arm(job, delay);
    return result(`resumed "${job.name}": ${describeJob(job)}.`);
  }

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
