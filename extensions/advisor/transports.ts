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
import { chmodSync, copyFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StringDecoder } from "node:string_decoder";
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
  parseNdjsonLine,
  remainingBudgetMs,
  resolvePiBinary,
  splitNdjsonLines,
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
    // The child resolves the same model catalog as the host: credentials and
    // custom provider/model definitions (models.json, models-store.json) are
    // copied over 0600. Extensions are still not loaded in the child.
    const hostAgentDir = getAgentDir();
    for (const name of ["auth.json", "models.json", "models-store.json"]) {
      const hostFile = join(hostAgentDir, name);
      if (existsSync(hostFile)) {
        copyFileSync(hostFile, join(workDir, name));
        chmodSync(join(workDir, name), 0o600);
      }
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
    timer = setTimeout(onDeadline, remainingBudgetMs(opts.deadline, performance.now()));
    opts.signal?.addEventListener("abort", onOuterAbort, { once: true });

    // NDJSON line buffer: events arrive split arbitrarily across chunks, and
    // multibyte characters can split across chunk boundaries (StringDecoder
    // keeps decoding consistent). Malformed lines are skipped, never thrown.
    let buffer = "";
    const decoder = new StringDecoder("utf8");
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
    const handleChunk = (chunk: Buffer): void => {
      const { lines, rest } = splitNdjsonLines(buffer + decoder.write(chunk));
      buffer = rest;
      for (const line of lines) handleLine(line);
    };
    stdout.on("data", handleChunk);
    stderr.on("data", (chunk: Buffer) => {
      stderrTail = (stderrTail + chunk.toString("utf8")).slice(-4_000);
    });

    // A spawn failure (ENOENT, bad argv) surfaces as the child's "error" event;
    // a successful spawn always ends in "close", so awaiting close is enough.
    let spawnError: Error | undefined;
    proc.once("error", (error) => (spawnError = error));
    await new Promise<void>((resolve) => proc.once("close", () => resolve()));
    if (spawnError)
      throw new Error(
        `Could not start the advisor child process "${resolvePiBinary(opts.config, process.env)}": ${spawnError.message}`,
      );
    handleChunk(Buffer.alloc(0)); // flush the decoder tail + the last un-newlined line
    const exitCode = proc.exitCode ?? -1;

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
    // pi exits 0 even for failed or no-response consultations, so the outcome
    // is decided from the observed events, not the exit code.
    const outcome = decideChildOutcome({
      exitCode,
      signalCode: proc.signalCode,
      timedOut: false,
      aborted: false,
      assistantResponse: acc.assistantResponse,
      stopReason: acc.stopReason,
      lastError: acc.lastError,
      text,
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
    if (killTimer !== undefined) clearTimeout(killTimer);
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onOuterAbort);
    rmSync(workDir, { recursive: true, force: true });
  }
}
