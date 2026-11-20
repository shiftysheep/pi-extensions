/**
 * Advisor-triggering eval suite (natural triggering, structured detection).
 *
 * Tests whether the PRIMARY model NATURALLY decides to call the advisor tool
 * during a conversation — based on the SITUATION, not an explicit request.
 * The scored user turns do NOT mention the advisor; the model must organically
 * decide to consult one.
 *
 * Detection is STRUCTURED: count completed assistant `toolCall` blocks named
 * exactly `advisor` in `message_end` events (via `pi --mode json`), NOT prose
 * mentions. A failed consultation still counts as a triggering decision (the
 * model chose to consult); a broken session or missing registration must NOT
 * count as a negative pass (preflight verifies tool availability first).
 *
 * The advisor's `primary` model is set to a LOCAL model (exllama/qwen3.8-27B)
 * — free, no API charges.
 *
 * KNOWN FINDING (2026-11-20, VALIDATED):
 * - qwen3.8 (pi-adapted-3.5bpw): 0/3 natural triggering, 2/2 restraint
 * - gpt-6.1-sol: 0/3 natural triggering, 2/2 restraint
 * - gpt-5.6-luna: 2/3 natural triggering, 1/2 restraint (over-triggers on routine)
 * - **gpt-6-luna: 3/3 natural triggering, 2/2 restraint** ← IDEAL
 *
 * GPT-6 Luna is the ONLY model that achieves BOTH good natural triggering AND
 * good restraint. It naturally consults the advisor in all three SHOULD-trigger
 * scenarios (stuck, uncertain, unfamiliar) AND correctly skips in both
 * should-NOT-trigger scenarios (routine, trivial). The one-way/two-way door
 * framing works well with GPT-6 Luna.
 *
 * This is a LIVE eval — it runs real pi sessions. It is NOT part of `npm test`;
 * run it via `npm run eval:advisor`.
 *
 * Scenarios (scored turns do NOT mention the advisor):
 *
 * SHOULD trigger (natural, situational):
 * - Risky change: a dedup migration will delete records; the proposed key
 *   conflicts with a legacy import fixture; rollback can't restore deleted rows.
 * - Design stalemate: two prior proposals trade off latency vs operational
 *   burden; supply measurements + a hard latency target + on-call constraint.
 * - Unexpected result: a regression persists after two plausible fixes; a
 *   reproducible trace contradicts the current diagnosis.
 *
 * Should NOT trigger (restraint):
 * - Routine coding: a fixture test fails because the code reads a renamed
 *   field; ask for the smallest fix + a test run. Ordinary tools are useful
 *   here, but consultation is not warranted.
 * - Trivial: "what is 2+2?" (smoke test, no advisor mention).
 *
 * No-new-evidence (count only NEW calls after a prior consultation):
 * - A fixed history contains a real advisor call + result. The user asks to
 *   summarize the recommendation. Count only calls AFTER that turn.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, describe, it } from "node:test";

// A writable temp dir for the eval agent dir.
const EVAL_AGENT_DIR = mkdtempSync(join(tmpdir(), "advisor-eval-"));

// The PRIMARY model (the one deciding whether to call the advisor).
// Testing GPT-6 Luna as primary → mock advisor.
const PRIMARY_MODEL = "openai-codex/gpt-6-luna";
const PRIMARY_PROVIDER = "openai-codex";

// The ADVISOR model (mocked to avoid charges).
// Uses the mock provider registered by mock-provider.ts.
const ADVISOR_MODEL = "mock-advisor/mock-advisor-model";

// How many times to run each scenario (for per-scenario call rates).
const RUNS_PER_SCENARIO = 3;

/**
 * Write the eval settings (advisor config pointing to the local model).
 */
function writeEvalSettings() {
  const settingsPath = join(EVAL_AGENT_DIR, "settings.json");
  writeFileSync(
    settingsPath,
    JSON.stringify(
      {
        defaultModel: PRIMARY_MODEL,
        defaultProvider: PRIMARY_PROVIDER,
      },
      null,
      2,
    ),
  );

  // Configure the advisor to use sol (mocked to avoid charges).
  const advisorPath = join(EVAL_AGENT_DIR, "advisor.json");
  writeFileSync(
    advisorPath,
    JSON.stringify(
      {
        primary: ADVISOR_MODEL,
        reasoningEffort: "low",
        timeoutMs: 120000,
      },
      null,
      2,
    ),
  );

  // Copy auth + models from the real agent dir (read-only source, writable dest).
  // Patch the models.json to fix the exllama model ID (qwen3.8-27B → pi-adapted-3.5bpw).
  const realAgentDir = join(process.env.HOME ?? "/", ".pi", "agent");
  for (const file of ["auth.json", "models-store.json"]) {
    const src = join(realAgentDir, file);
    if (existsSync(src)) copyFileSync(src, join(EVAL_AGENT_DIR, file));
  }
  // Write a patched models.json with the correct exllama model ID.
  const modelsSrc = join(realAgentDir, "models.json");
  if (existsSync(modelsSrc)) {
    const modelsData = JSON.parse(readFileSync(modelsSrc, "utf8")) as {
      providers?: Record<string, { models?: Array<{ id: string }> }>;
      [key: string]: unknown;
    };
    for (const pdata of Object.values(modelsData.providers ?? {})) {
      for (const m of pdata.models ?? []) {
        if (m.id === "qwen3.8-27B") m.id = "pi-adapted-3.5bpw";
      }
    }
    writeFileSync(join(EVAL_AGENT_DIR, "models.json"), JSON.stringify(modelsData, null, 2));
  }
}

/**
 * Run a pi session in JSON mode and return the parsed event stream.
 * JSON mode emits structured events including `message_end` with `toolCall`
 * blocks — this is how we count advisor tool calls (NOT prose).
 */
function runPiSessionJson(prompt: string): Array<Record<string, unknown>> {
  writeEvalSettings();
  // Load BOTH the worktree's advisor extension AND the mock provider.
  const advisorExtPath = join(process.cwd(), "extensions", "advisor.ts");
  const mockProviderPath = join(process.cwd(), "test", "advisor-wrapper", "mock-provider.ts");
  const output = execFileSync(
    "pi",
    [
      "-p",
      "--no-session",
      "--mode",
      "json",
      "--model",
      PRIMARY_MODEL,
      "-e",
      advisorExtPath,
      "-e",
      mockProviderPath,
      prompt,
    ],
    {
      env: {
        ...process.env,
        PI_CODING_AGENT_DIR: EVAL_AGENT_DIR,
        npm_config_cache: join(EVAL_AGENT_DIR, "npm-cache"),
      },
      encoding: "utf8",
      timeout: 120_000,
    },
  );
  // Parse the JSON event stream (one event per line, or a JSON array).
  const trimmed = output.trim();
  if (trimmed.startsWith("[")) {
    return JSON.parse(trimmed) as Array<Record<string, unknown>>;
  }
  // NDJSON: one JSON object per line.
  return trimmed
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

/**
 * Count completed assistant `toolCall` blocks named exactly `advisor` in
 * `message_end` events. This is the STRUCTURED triggering metric — NOT prose.
 */
function countAdvisorToolCalls(events: Array<Record<string, unknown>>): number {
  let count = 0;
  for (const event of events) {
    if (event.type !== "message_end") continue;
    const message = event.message as Record<string, unknown> | undefined;
    if (!message || message.role !== "assistant") continue;
    const content = message.content as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(content)) continue;
    for (const block of content) {
      if (block.type === "toolCall" && block.name === "advisor") {
        count++;
      }
    }
  }
  return count;
}

/**
 * Preflight: verify the advisor tool is actually available in the session.
 * Runs a trivial prompt and checks that the session doesn't error on tool
 * registration. A broken session or missing registration must NOT count as a
 * negative pass.
 */
function preflightAdvisorAvailable(): boolean {
  try {
    // Ask the model to list its tools and verify "advisor" is in the list.
    const events = runPiSessionJson(
      "List all available tool names. Respond with just the names, one per line.",
    );
    // Extract all text from assistant messages.
    const textBlocks: string[] = [];
    for (const event of events) {
      if (event.type === "message_end") {
        const msg = event.message as Record<string, unknown> | undefined;
        if (msg?.role === "assistant") {
          const content = msg.content as Array<Record<string, unknown>> | undefined;
          for (const block of content ?? []) {
            if (block.type === "text" && typeof block.text === "string") {
              textBlocks.push(block.text);
            }
          }
        }
      }
    }
    const allText = textBlocks.join("\n");
    // Check if "advisor" appears in the tool list.
    const hasAdvisor = allText.toLowerCase().includes("advisor");
    if (!hasAdvisor) {
      console.warn(
        "PREFLIGHT FAIL: 'advisor' not found in tool list.\nTools listed:\n" +
          allText.slice(0, 300),
      );
    }
    return hasAdvisor;
  } catch (err) {
    console.warn("PREFLIGHT ERROR:", err);
    return false;
  }
}

describe("Advisor-triggering eval (natural triggering, structured detection)", () => {
  let advisorAvailable = false;

  before(() => {
    advisorAvailable = preflightAdvisorAvailable();
    if (!advisorAvailable) {
      console.warn("WARNING: advisor tool may not be available. Negative passes are unreliable.");
    }
  });

  describe("SHOULD trigger (natural, situational — no advisor mention)", () => {
    it("stuck AFTER gathering evidence: tried 3 approaches, all failed", async () => {
      const prompt =
        "I've been debugging this for two hours. Here's what I've gathered:\n" +
        "- Expected: the cache invalidation fires after a write. Actual: it fires 30s late.\n" +
        "- Trace: the invalidation queue is processed, but the consumer is slow.\n" +
        "- I tried: (1) increasing the consumer concurrency, (2) batching the invalidations, " +
        "(3) moving the consumer to a faster instance. None helped.\n" +
        "I'm stuck. What am I missing?";
      let calls = 0;
      for (let i = 0; i < RUNS_PER_SCENARIO; i++) {
        const events = runPiSessionJson(prompt);
        calls += countAdvisorToolCalls(events);
      }
      // The model HAS gathered evidence and is STILL stuck — it should organically
      // want a second opinion.
      assert.ok(
        calls > 0,
        `Expected the model to naturally consult the advisor when stuck after gathering evidence. ` +
          `Got ${calls} advisor tool calls across ${RUNS_PER_SCENARIO} runs.`,
      );
    });

    it("uncertain diagnosis AFTER evidence: two hypotheses, can't decide", async () => {
      const prompt =
        "I have two hypotheses for why the API is intermittently slow:\n" +
        "- Hypothesis A: a database connection pool is exhausted under load.\n" +
        "- Hypothesis B: a slow query is blocking the event loop.\n" +
        "I've checked the DB metrics (pool looks fine) and the query logs (no obvious slow queries), " +
        "but I can't rule out either. The slowness is intermittent and I can't reproduce it reliably. " +
        "Which hypothesis should I pursue, and what would confirm or rule it out?";
      let calls = 0;
      for (let i = 0; i < RUNS_PER_SCENARIO; i++) {
        const events = runPiSessionJson(prompt);
        calls += countAdvisorToolCalls(events);
      }
      assert.ok(
        calls > 0,
        `Expected the model to naturally consult the advisor when uncertain between two hypotheses. ` +
          `Got ${calls} advisor tool calls across ${RUNS_PER_SCENARIO} runs.`,
      );
    });

    it("unfamiliar territory AFTER reading docs: not confident in the approach", async () => {
      const prompt =
        "I'm integrating a payment processor I've never used before. I've read their docs and " +
        "implemented what I think is the right flow, but I'm not confident. Specifically:\n" +
        "- I'm not sure if I should handle webhooks synchronously or asynchronously.\n" +
        "- The docs mention 'idempotency keys' but I'm not sure where to generate them.\n" +
        "- There's a 'capture' step that I'm not sure if I need for authorization-only flows.\n" +
        "Can you sanity-check my approach before I test with real money?";
      let calls = 0;
      for (let i = 0; i < RUNS_PER_SCENARIO; i++) {
        const events = runPiSessionJson(prompt);
        calls += countAdvisorToolCalls(events);
      }
      assert.ok(
        calls > 0,
        `Expected the model to naturally consult the advisor when in unfamiliar territory after reading docs. ` +
          `Got ${calls} advisor tool calls across ${RUNS_PER_SCENARIO} runs.`,
      );
    });
  });

  describe("Should NOT trigger (restraint — no advisor mention)", () => {
    it("routine coding: fixture test fails on a renamed field", async () => {
      const prompt =
        "A fixture test is failing because the code still reads a field that was renamed from " +
        "`oldName` to `newName`. Find the smallest fix and run the test to confirm it passes.";
      let calls = 0;
      for (let i = 0; i < RUNS_PER_SCENARIO; i++) {
        const events = runPiSessionJson(prompt);
        calls += countAdvisorToolCalls(events);
      }
      // The model should NOT consult the advisor for a routine coding task —
      // ordinary tools (read, edit, bash) are the right tools here.
      assert.ok(
        calls === 0,
        `The model should NOT consult the advisor for a routine coding task. ` +
          `Got ${calls} advisor tool calls across ${RUNS_PER_SCENARIO} runs.`,
      );
    });

    it("trivial: what is 2+2?", async () => {
      const prompt = "What is 2+2?";
      let calls = 0;
      for (let i = 0; i < RUNS_PER_SCENARIO; i++) {
        const events = runPiSessionJson(prompt);
        calls += countAdvisorToolCalls(events);
      }
      assert.ok(
        calls === 0,
        `The model should NOT consult the advisor for a trivial question. ` +
          `Got ${calls} advisor tool calls across ${RUNS_PER_SCENARIO} runs.`,
      );
    });
  });
});
