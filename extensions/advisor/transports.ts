/**
 * Consultation transport for the advisor extension: every advisor model turn
 * and tool call runs in an isolated child `pi` process, never in the host
 * process. The child gets a throwaway agent dir (mkdtemp) holding only a copy
 * of auth.json (mode 0600), receives the prompt as an @path file reference,
 * and streams NDJSON events back; the temp dir is removed in a finally block
 * on success, failure, timeout, and abort.
 *
 * This is a privilege boundary, not a filesystem sandbox: the child's read
 * tools still reach anything the OS user can read.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
  remainingBudgetMs,
  resolvePiBinary,
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
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  let stderrTail = "";
  let child: ChildProcess | undefined;
  const killChild = (): void => {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGTERM");
    if (killTimer === undefined)
      killTimer = setTimeout(() => {
        if (child && (child.exitCode === null || child.signalCode === null)) child.kill("SIGKILL");
      }, 5_000);
  };
  const onOuterAbort = () => killChild();
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
    const hostAuth = join(getAgentDir(), "auth.json");
    if (existsSync(hostAuth)) {
      copyFileSync(hostAuth, join(workDir, "auth.json"));
      chmodSync(join(workDir, "auth.json"), 0o600);
    }

    const args = buildChildPiArgs({
      provider: opts.model.provider,
      modelId: opts.model.id,
      effort: opts.effort,
      tools,
      promptPath,
    });
    const env = { ...childBaseEnv(), PI_CODING_AGENT_DIR: workDir };
    const proc = spawn(resolvePiBinary(opts.config, process.env), args, {
      cwd: opts.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    // stdio: ["ignore","pipe","pipe"] makes both streams non-null pipes.
    child = proc;
    const stdout = proc.stdout;
    const stderr = proc.stderr;
    if (!stdout || !stderr) throw new Error("child process streams were not pipes");

    const onDeadline = () => {
      timedOut = true;
      killChild();
    };
    timer = setTimeout(onDeadline, remainingMs);
    opts.signal?.addEventListener("abort", onOuterAbort, { once: true });

    // NDJSON line buffer: events arrive split arbitrarily across chunks.
    let buffer = "";
    const handleLine = (line: string): void => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let event: unknown;
      try {
        event = JSON.parse(trimmed);
      } catch {
        return;
      }
      const typed = event as { type?: string; toolName?: string };
      if (typeof typed.type !== "string") return;
      const message = (event as { message?: unknown }).message;
      const messages = (event as { messages?: unknown[] }).messages;
      acc.record({ type: typed.type, toolName: typed.toolName, message, messages });
      if (typed.type === "tool_execution_start") {
        opts.onUpdate?.({
          content: [
            {
              type: "text",
              text: `${opts.modelLabel} is exploring the workspace (tool call ${acc.toolCalls}: ${typed.toolName})...`,
            },
          ],
          details: { model: opts.modelLabel, toolCalls: acc.toolCalls, toolName: typed.toolName },
        });
      }
    };
    stdout.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      let idx = buffer.indexOf("\n");
      while (idx >= 0) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        handleLine(line);
        idx = buffer.indexOf("\n");
      }
    });
    stderr.on("data", (chunk: Buffer) => {
      stderrTail = (stderrTail + chunk.toString("utf8")).slice(-4_000);
    });

    const exitCode = await new Promise<number>((resolve, reject) => {
      proc.once("error", (error) => reject(error));
      proc.once("close", (code) => resolve(code ?? -1));
    }).catch((error: Error) => {
      throw new Error(
        `Could not start the advisor child process "${resolvePiBinary(opts.config, process.env)}": ${error.message}`,
      );
    });

    const interrupted = timedOut || opts.signal?.aborted === true;
    if (proc.signalCode && !timedOut && !opts.signal?.aborted)
      throw new Error(`the advisor child process was killed by signal ${proc.signalCode}`);
    let text = acc.finalText(interrupted);
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
    const lastError = acc.lastError;
    if (exitCode !== 0 && !text) {
      const detail =
        stderrTail.trim() ||
        lastError ||
        `the advisor child process exited with code ${exitCode} without output`;
      throw new Error(detail);
    }
    // pi exits 0 even when the model call failed (the error rides in the
    // assistant message): surface it, so a failed review degrades to the
    // fallback instead of returning an empty "completed" answer.
    if (lastError && !text) throw new Error(lastError);
    if (lastError && text)
      text = `${text}\n\n(advisor child reported an error after this output: ${lastError})`;
    return {
      text: text || "The advisor returned no text.",
      usage: acc.usage,
      toolCalls: acc.toolCalls,
      modelRequests: acc.modelRequests,
      status: "completed",
    };
  } finally {
    if (killTimer !== undefined) clearTimeout(killTimer);
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onOuterAbort);
    rmSync(workDir, { recursive: true, force: true });
  }
}
