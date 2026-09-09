/**
 * Consultation transport for the advisor extension: every advisor model turn
 * and tool call runs in an isolated child `pi` process, never in the host
 * process. The child gets a throwaway agent dir (mkdtemp) holding only a copy
 * of auth.json plus the host's models config (mode 0600, so custom providers
 * and model overrides resolve identically), receives the prompt as an @path
 * file reference, and streams NDJSON events back; the temp dir is removed in a
 * finally block on success, failure, timeout, and abort.
 *
 * This is a privilege boundary, not a filesystem sandbox: the child's read
 * tools still reach anything the OS user can read.
 */

import { type ChildProcess, spawn } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Model, Usage } from "@earendil-works/pi-ai";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import {
  AdvisorEventAccumulator,
  type AdvisorReasoningEffort,
  assembleChildPrompt,
  assembleRequestText,
  buildChildPiArgs,
  childBaseEnv,
  decideChildOutcome,
  NdjsonLineBuffer,
  parseNdjsonLine,
  remainingBudgetMs,
  resolvePiBinary,
  stripRefreshTokens,
} from "../lib/advisor-utils.js";
import { ADVISOR_SYSTEM_PROMPT, REVIEW_SYSTEM_PROMPT } from "./request.js";

/** Read-only tools the explore-mode child may use. */
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
 * Run one advisor consultation in a child pi process. Both modes share the
 * transport: review mode spawns the child with --no-tools (a single model
 * call), explore mode with the read-only tool allowlist. Bounded by the
 * consultation timeout only — tool-call and model-request counts are reported
 * in the result (cost visibility) but never abort a consultation.
 */
export async function consultWithChildProcess(opts: {
  model: Model<any>;
  modelLabel: string;
  question: string;
  transcript: string;
  effort: AdvisorReasoningEffort;
  cwd: string;
  mode: "review" | "explore";
  /** Absolute monotonic-clock deadline (performance.now() base) for the whole consultation. */
  deadline: number;
  signal?: AbortSignal;
  config?: { piBinary?: string };
  onUpdate?: (update: {
    content: Array<{ type: "text"; text: string }>;
    details: Record<string, unknown>;
  }) => void;
}): Promise<AdvisorConsultResult> {
  // The deadline is absolute: an exhausted budget or an aborted call never
  // spawns the child (no paid work, no temp dir).
  if (opts.signal?.aborted) throw new Error("aborted before the consultation started");
  const remainingMs = remainingBudgetMs(opts.deadline, performance.now());
  if (remainingMs <= 0) throw new Error("consultation timed out during setup");

  const systemPrompt = opts.mode === "review" ? REVIEW_SYSTEM_PROMPT : ADVISOR_SYSTEM_PROMPT;
  const tools = opts.mode === "explore" ? ADVISOR_TOOLS : [];
  const workDir = mkdtempSync(join(tmpdir(), "pi-advisor-"));
  const promptPath = join(workDir, "prompt.txt");
  // The first interruption cause wins: an abort that is followed by the
  // deadline firing during the SIGTERM grace period is still reported as an
  // abort, and vice versa.
  let interruptCause: "timed_out" | "aborted" | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  // Owned, cleared timers for the bounded waits. A bare delay() in a
  // Promise.race leaves a pending timer that keeps the event loop alive long
  // after the wait settles (a fast successful consultation would otherwise keep
  // the host alive until the absolute deadline), so every wait owns its timer
  // and clears it on settle.
  let closeGraceTimer: ReturnType<typeof setTimeout> | undefined;
  let hardBoundTimer: ReturnType<typeof setTimeout> | undefined;
  let stderrTail = "";
  let child: ChildProcess | undefined;
  // The child is spawned in its own process group (detached) so we can signal
  // the whole group, not just the immediate PID. A piBinary wrapper (or any
  // descendant) that inherits the stdio pipes and outlives the immediate
  // process would otherwise keep the pipes open, delaying "close" and hanging
  // the consultation, the concurrency slot, and the credential dir.
  // We gate on "have we signalled yet", NOT on the immediate child being
  // alive: the child may already have exited (cleanly) while a descendant
  // still holds the pipes, and the group signal is still required to drain.
  let groupSignalled = false;
  let groupKillScheduled = false;
  // Resolves when the immediate child process dies. A SIGKILL to the process
  // group kills the child, so this is a reliable "group teardown issued" hook
  // that does not depend on pipe closure (a descendant can outlive the pipes).
  let groupDeadResolve: (() => void) | undefined;
  const groupDead = new Promise<void>((resolve) => (groupDeadResolve = resolve));
  // Resolves when the interrupt-driven hard backstop fires (see startHardBound).
  // It is a plain promise (not a timer), so it does not keep the event loop
  // alive; only the timer that resolves it does, and that timer is owned/cleared.
  let hardBoundResolve: (() => void) | undefined;
  const hardBound = new Promise<void>((resolve) => (hardBoundResolve = resolve));
  // Shared teardown budget: on the first interrupt (deadline or abort) record an
  // absolute deadline, comfortably beyond the SIGTERM->SIGKILL escalation (5s) +
  // the close grace (1s). BOTH the close-wait hard backstop and the final
  // teardown cap draw from this one deadline (the cap uses its remaining time),
  // so they do not stack — an early abort with an unkillable child waits at most
  // this margin after the abort, not margin + margin.
  let teardownDeadline: number | undefined;
  const TEARDOWN_MARGIN_MS = 15_000;
  const startHardBound = (): void => {
    if (hardBoundTimer !== undefined) return;
    teardownDeadline = performance.now() + TEARDOWN_MARGIN_MS;
    hardBoundTimer = setTimeout(() => hardBoundResolve?.(), TEARDOWN_MARGIN_MS);
  };
  const signalGroup = (signal: NodeJS.Signals): void => {
    if (!child || child.pid === undefined) return;
    try {
      process.kill(-child.pid, signal);
    } catch {
      try {
        child.kill(signal);
      } catch {
        // Already gone.
      }
    }
  };
  const killChild = (): void => {
    if (groupSignalled) return;
    groupSignalled = true;
    signalGroup("SIGTERM");
    if (groupKillScheduled) return;
    groupKillScheduled = true;
    if (killTimer === undefined)
      killTimer = setTimeout(() => {
        if (!groupSignalled) return;
        signalGroup("SIGKILL");
      }, 5_000);
  };
  const onDeadline = () => {
    if (interruptCause === undefined) interruptCause = "timed_out";
    killChild();
    startHardBound();
  };
  const onOuterAbort = () => {
    if (interruptCause === undefined) interruptCause = "aborted";
    killChild();
    startHardBound();
  };
  // Finish tearing down the group before the consultation returns. On the
  // interrupt path the immediate child may have died to SIGTERM while a
  // descendant still lives (e.g. a piBinary wrapper that spawned a
  // SIGTERM-ignoring child and detached the pipes): "close" then fires even
  // though the group is not gone. Escalate to SIGKILL and await the child
  // dying, bounded by a hard cap so a wedged process can never hang the slot.
  const awaitGroupTearDown = async (): Promise<void> => {
    if (killTimer !== undefined) {
      clearTimeout(killTimer);
      killTimer = undefined;
    }
    // No successfully-spawned process (e.g. ENOENT): "exit" will never fire, so
    // there is nothing to await and the wait would only burn its cap.
    if (!child || child.pid === undefined) return;
    signalGroup("SIGKILL");
    // Bounded wait on the child dying. It shares the interrupt-driven teardown
    // deadline with the close-wait backstop (drawing only its remaining time), so
    // the two do not stack. The cap timer is owned and cleared on settle so it
    // cannot keep the event loop alive after the wait finishes.
    const capMs =
      teardownDeadline !== undefined ? Math.max(0, teardownDeadline - performance.now()) : 10_000;
    await new Promise<void>((resolve) => {
      let settled = false;
      let capTimer: ReturnType<typeof setTimeout> | undefined;
      const settle = () => {
        if (settled) return;
        settled = true;
        if (capTimer !== undefined) {
          clearTimeout(capTimer);
          capTimer = undefined;
        }
        resolve();
      };
      groupDead.then(settle);
      capTimer = setTimeout(settle, capMs);
    });
  };
  const acc = new AdvisorEventAccumulator();
  try {
    writeFileSync(
      promptPath,
      assembleChildPrompt(
        systemPrompt,
        assembleRequestText(opts.model, opts.question, opts.transcript, systemPrompt.length),
      ),
      { mode: 0o600 },
    );
    // The child resolves the same model catalog as the host: credentials and
    // custom provider/model definitions (models.json, models-store.json) are
    // copied over 0600. Extensions are still not loaded in the child.
    const hostAgentDir = getAgentDir();
    // Read-only model catalogs (custom providers / overrides): copy 0600 as-is.
    for (const name of ["models.json", "models-store.json"]) {
      const hostFile = join(hostAgentDir, name);
      if (existsSync(hostFile)) {
        copyFileSync(hostFile, join(workDir, name));
        chmodSync(join(workDir, name), 0o600);
      }
    }
    // auth.json: the credential store. The child's copy has its OAuth refresh
    // tokens STRIPPED and is written 0400 (read-only). Stripping the refresh
    // token is what actually protects the host: a refresh the child performs
    // would rotate the token on the provider's side (invalidating the host's
    // refresh token) before any local write, which a read-only file does not
    // prevent. With no refresh token, the child uses its (pre-refreshed, fresh)
    // access token directly; if it ever expires mid-run, the child's refresh
    // fails cleanly and degrades to an auth error handled by the fallback
    // chain, instead of corrupting the host's canonical credential. The
    // read-only mode is defense-in-depth (the child can't persist anything).
    const hostAuth = join(hostAgentDir, "auth.json");
    if (existsSync(hostAuth)) {
      writeFileSync(
        join(workDir, "auth.json"),
        stripRefreshTokens(readFileSync(hostAuth, "utf8")),
        {
          mode: 0o400,
        },
      );
    }

    const args = buildChildPiArgs({
      provider: opts.model.provider,
      modelId: opts.model.id,
      effort: opts.effort,
      tools,
      promptPath,
    });
    // The deadline is absolute and setup above consumed real time: re-check
    // immediately before starting paid work, and time the kill from the
    // absolute deadline, not from the pre-setup measurement.
    if (opts.signal?.aborted) throw new Error("aborted before the consultation started");
    if (remainingBudgetMs(opts.deadline, performance.now()) <= 0)
      throw new Error("consultation timed out during setup");
    const env = { ...childBaseEnv(), PI_CODING_AGENT_DIR: workDir };
    const proc = spawn(resolvePiBinary(opts.config, process.env), args, {
      cwd: opts.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      // Own process group, so timeout/abort can signal the whole subtree.
      // detached does not unref the child; we still await it explicitly.
      detached: true,
    });
    // stdio: ["ignore","pipe","pipe"] makes both streams non-null pipes.
    child = proc;
    // "exit" (not "close") fires when the immediate child dies, which is what
    // the group-teardown await keys on — a SIGKILL to the group always kills it.
    proc.once("exit", () => groupDeadResolve?.());
    const stdout = proc.stdout;
    const stderr = proc.stderr;
    if (!stdout || !stderr) throw new Error("child process streams were not pipes");

    timer = setTimeout(onDeadline, remainingBudgetMs(opts.deadline, performance.now()));
    opts.signal?.addEventListener("abort", onOuterAbort, { once: true });

    // Events arrive split arbitrarily across chunks, and multibyte characters
    // can split across chunk boundaries; the buffer's decoder stays consistent.
    // The final event may not be newline-terminated, so end() must flush it.
    // A malformed line or a throwing update callback is skipped, never thrown,
    // so the host never crashes and the child is never orphaned.
    const ndjson = new NdjsonLineBuffer();
    const handleLine = (line: string): void => {
      try {
        const parsed = parseNdjsonLine(line);
        if (!parsed) return;
        acc.record(parsed);
        if (parsed.type === "tool_execution_start")
          opts.onUpdate?.({
            content: [
              {
                type: "text",
                text: `${opts.modelLabel} is exploring the workspace (tool call ${acc.toolCalls}: ${parsed.toolName})...`,
              },
            ],
            details: {
              model: opts.modelLabel,
              toolCalls: acc.toolCalls,
              toolName: parsed.toolName,
            },
          });
      } catch {
        // A malformed event (or a throwing update callback) must never crash
        // the host or orphan the child: skip it and keep draining the stream.
      }
    };
    stdout.on("data", (chunk: Buffer) => ndjson.write(chunk, handleLine));
    stderr.on("data", (chunk: Buffer) => {
      stderrTail = (stderrTail + chunk.toString("utf8")).slice(-4_000);
    });

    // A spawn failure (ENOENT, bad argv) surfaces as the child's "error" event.
    // A successful spawn ends in "close" — but "close" requires ALL pipe holders
    // to die, and a descendant (e.g. a piBinary wrapper that spawned its own
    // subprocess and moved it to a new session) can outlive the immediate child
    // while still holding a pipe. So bound the wait: once the immediate child
    // has exited, give the pipes a short grace to flush the child's final output,
    // then stop waiting even if a descendant still holds them. Waiting on an
    // out-of-group descendant would hang the slot and the credential dir.
    let spawnError: Error | undefined;
    proc.once("error", (error) => (spawnError = error));
    const CLOSE_GRACE_MS = 1_000;
    // The normal path resolves on "close" (the child exited and its pipe closed).
    // The grace backstop resolves shortly after the child exits if "close" is held
    // open by a descendant; the child's own output is already flushed by then.
    // The hard backstop (started by the first interrupt, see startHardBound)
    // resolves even if the child is stuck in an uninterruptible state and never
    // reports exit/close, so the bounded teardown in finally still runs and
    // releases the slot and the credential dir. All timers are owned and cleared
    // on settle, so a settled wait cannot keep the event loop alive.
    await new Promise<void>((resolve) => {
      let settled = false;
      const settle = () => {
        if (settled) return;
        settled = true;
        proc.removeListener("close", settle);
        proc.removeListener("exit", onExit);
        if (closeGraceTimer !== undefined) {
          clearTimeout(closeGraceTimer);
          closeGraceTimer = undefined;
        }
        if (hardBoundTimer !== undefined) {
          clearTimeout(hardBoundTimer);
          hardBoundTimer = undefined;
        }
        resolve();
      };
      const onExit = () => {
        // Guard: a late "exit" after settlement (e.g. after the hard backstop
        // fired) must not create a new grace timer that is never cleared.
        if (settled) return;
        if (closeGraceTimer === undefined) closeGraceTimer = setTimeout(settle, CLOSE_GRACE_MS);
      };
      proc.on("close", settle);
      proc.on("exit", onExit);
      hardBound.then(settle);
    });
    if (spawnError)
      throw new Error(
        `Could not start the advisor child process "${resolvePiBinary(opts.config, process.env)}": ${spawnError.message}`,
      );
    // stdout has ended by now; flush the decoder tail and the last
    // (possibly unterminated) line so a final event without a trailing
    // newline is not silently dropped.
    ndjson.end(handleLine);
    const exitCode = proc.exitCode ?? -1;

    if (interruptCause !== undefined) {
      const interruptedText = acc.finalText(true);
      return {
        text: interruptedText,
        usage: acc.usage,
        toolCalls: acc.toolCalls,
        modelRequests: acc.modelRequests,
        status: interruptCause,
      };
    }
    // pi exits 0 even for failed or no-response consultations, so the outcome
    // is decided from the observed events, not the exit code.
    const outcome = decideChildOutcome({
      exitCode,
      signalCode: proc.signalCode,
      assistantResponse: acc.assistantResponse,
      stopReason: acc.stopReason,
      lastError: acc.lastError,
      // Not interrupted on this path, so the final answer is the last text.
      text: acc.finalText(false),
      stderr: stderrTail,
    });
    return {
      text: outcome.text,
      usage: acc.usage,
      toolCalls: acc.toolCalls,
      modelRequests: acc.modelRequests,
      status: outcome.status,
    };
  } finally {
    // Finish group teardown UNCONDITIONALLY, on every exit path (not just the
    // interrupt path): an in-group descendant can outlive the immediate child
    // after a clean exit too, and must not be left running. Escalate to
    // SIGKILL and bound the wait on the immediate child dying, so a wedged
    // group can never hang the slot. (No-op for a normally-exited plain child.
    // A descendant that escaped to a new session cannot be signalled by group —
    // a portable limitation — but destroying the pipes below still stops the
    // host from being held alive by the open pipe.)
    await awaitGroupTearDown();
    // Stop reading the child's pipes. A descendant that escaped to a new
    // session can still hold the write end after the group is gone; destroying
    // the host's read handles stops it from keeping this process's event loop
    // alive and from firing data/update callbacks after we have returned.
    try {
      child?.stdout?.destroy();
      child?.stderr?.destroy();
    } catch {
      /* already destroyed */
    }
    if (killTimer !== undefined) clearTimeout(killTimer);
    clearTimeout(timer);
    // Give up on any still-live child handle: it would otherwise keep the host's
    // event loop alive. In the normal path the child has already exited (a no-op);
    // in the unkillable-child path this lets the host exit rather than holding the
    // slot for a process we cannot signal.
    try {
      child?.unref();
    } catch {
      /* already gone */
    }
    opts.signal?.removeEventListener("abort", onOuterAbort);
    rmSync(workDir, { recursive: true, force: true });
  }
}
