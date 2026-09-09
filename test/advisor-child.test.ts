/**
 * Deterministic lifecycle tests for the child-process advisor transport:
 * a fake `pi` binary (a Node script) stands in for the real one, so the
 * protocol, cleanup, and failure paths are exercised without paying for a
 * model call. The fake binary lives outside the transport's work dir, because
 * the transport removes that dir in a finally block on every exit path.
 */

import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import type { Model } from "@earendil-works/pi-ai";
import { consultWithChildProcess } from "../extensions/advisor/transports.js";

const MODEL = {
  provider: "fake",
  id: "fake-model",
  contextWindow: 8_000,
  maxTokens: 1_000,
} as unknown as Model<any>;
const DEADLINE = () => performance.now() + 30_000;
const fakeDirs: string[] = [];

/** Build a fake script that emits one message_end event (and nothing else). */
function msgEndScript(text: string, extra: Record<string, unknown> = {}): string {
  return (
    "process.stdout.write(JSON.stringify({" +
    'type: "message_end",' +
    "message: Object.assign({" +
    'role: "assistant",' +
    "content: " +
    JSON.stringify(text) +
    '.length ? [{type:"text",text:' +
    JSON.stringify(text) +
    "}] : []" +
    "}, " +
    JSON.stringify(extra) +
    ")" +
    '}) + "\\n");'
  );
}

/** Install a fake pi binary that runs the given Node body; returns its path. */
function fakePi(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "pi-advisor-fake-"));
  fakeDirs.push(dir);
  const bin = join(dir, "pi");
  writeFileSync(bin, `#!/usr/bin/env node\n${body}\n`);
  chmodSync(bin, 0o755);
  return bin;
}

after(() => {
  for (const dir of fakeDirs) rmSync(dir, { recursive: true, force: true });
});

/** Work dirs created by the transport (not by these tests' fake binaries). */
function workDirs(): string[] {
  return readdirSync(tmpdir()).filter(
    (entry) => entry.startsWith("pi-advisor-") && !entry.startsWith("pi-advisor-fake-"),
  );
}

function consult(bin: string, mode: "review" | "explore" = "review") {
  return consultWithChildProcess({
    model: MODEL,
    modelLabel: "fake/fake-model",
    question: "q",
    transcript: "",
    effort: "low",
    cwd: process.cwd(),
    mode,
    deadline: DEADLINE(),
    config: { piBinary: bin },
  });
}

describe("consultWithChildProcess (fake pi lifecycle)", () => {
  it("tolerates malformed NDJSON lines and reports usage", async () => {
    const before = workDirs();
    const usage = {
      input: 3,
      output: 2,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 5,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    };
    const bin = fakePi(
      'process.stdout.write("not json\\nnull\\n[1]\\n");' +
        'process.stdout.write(\'{"type":"turn_start"}\' + "\\n");' +
        msgEndScript("ok", { usage, stopReason: "stop" }),
    );
    const result = await consult(bin);
    assert.equal(result.status, "completed");
    assert.equal(result.text, "ok");
    assert.equal(result.modelRequests, 1);
    assert.equal(result.usage?.totalTokens, 5);
    assert.deepEqual(workDirs(), before, "work dir must be removed after completion");
  });

  it("throws on exit-0 with no assistant response", async () => {
    const bin = fakePi("/* silent */");
    await assert.rejects(consult(bin), /no assistant response/);
  });

  it("throws the assistant error message when the model call failed", async () => {
    const bin = fakePi(
      msgEndScript("", { stopReason: "error", errorMessage: "fake model exploded" }),
    );
    await assert.rejects(consult(bin), /fake model exploded/);
  });

  it("marks partial output from an abnormal exit as incomplete, not a verdict", async () => {
    const bin = fakePi(
      'process.stdout.write(\'{"type":"turn_start"}\' + "\\n");' +
        msgEndScript("partial", { stopReason: "stop" }) +
        "process.exit(3);",
    );
    const result = await consult(bin);
    assert.equal(result.status, "timed_out");
    assert.ok(result.text.includes("exited abnormally (exit 3)"));
    assert.ok(result.text.includes("incomplete, not a verdict"));
    assert.ok(result.text.includes("partial"));
  });

  it("decodes multibyte characters split across chunk boundaries", async () => {
    const text = "café ☕ ok";
    const bin = fakePi(
      'process.stdout.write(\'{"type":"turn_start"}\' + "\\n");' +
        "const line = " +
        JSON.stringify(text) +
        ";" +
        'const full = JSON.stringify({type:"message_end",message:{role:"assistant",content:[{type:"text",text:line}],stopReason:"stop"}}) + "\\n";' +
        "process.stdout.write(full.slice(0, full.length - 5));" +
        "setTimeout(() => process.stdout.write(full.slice(full.length - 5)), 30);",
    );
    const result = await consult(bin);
    assert.equal(result.status, "completed");
    assert.equal(result.text, "café ☕ ok");
  });

  it("copies the host agent config files into the child work dir", async () => {
    const listing = join(process.cwd(), ".advisor-child-test-listing");
    const bin = fakePi(
      'require("node:fs").writeFileSync(' +
        JSON.stringify(listing) +
        "," +
        'require("node:fs").readdirSync(process.env.PI_CODING_AGENT_DIR).join(" "));' +
        msgEndScript("ok", { stopReason: "stop" }),
    );
    try {
      const result = await consult(bin);
      assert.equal(result.status, "completed");
      const files = readFileSync(listing, "utf8").trim().split(/\s+/).filter(Boolean).sort();
      assert.ok(files.includes("prompt.txt"), `work dir missing prompt.txt: ${files}`);
      if (existsSync(join(process.env.HOME ?? "", ".pi", "agent", "auth.json")))
        assert.ok(files.includes("auth.json"), `work dir missing auth.json: ${files}`);
    } finally {
      rmSync(listing, { force: true });
    }
  });

  it("removes the work dir when the fake pi crashes", async () => {
    const before = workDirs();
    const bin = fakePi("process.exit(1);");
    await assert.rejects(consult(bin), /no assistant response/);
    assert.deepEqual(workDirs(), before, "work dir must be removed after a crash");
  });

  it("reports a missing pi binary with a clear error", async () => {
    await assert.rejects(
      consultWithChildProcess({
        model: MODEL,
        modelLabel: "fake/fake-model",
        question: "q",
        transcript: "",
        effort: "low",
        cwd: process.cwd(),
        mode: "review",
        deadline: DEADLINE(),
        config: { piBinary: join(tmpdir(), "definitely-not-a-pi-binary-xyz") },
      }),
      /Could not start the advisor child process/,
    );
  });
});
