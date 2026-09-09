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

  it("throws on a nonzero exit even after partial output, routing to the fallback model", async () => {
    const bin = fakePi(
      'process.stdout.write(\'{"type":"turn_start"}\' + "\\n");' +
        msgEndScript("partial", { stopReason: "stop" }) +
        "process.exit(3);",
    );
    // A nonzero exit is never a verdict: the partial output must not be
    // returned as a completed answer, so the transport throws and the caller
    // falls through to the fallback model.
    await assert.rejects(consult(bin), /exited abnormally \(exit 3\)/);
  });

  it("decodes multibyte characters split across chunk boundaries", async () => {
    const text = "caf\u00e9 \u2615 ok";
    // Build the event line, then split the raw bytes in the middle of the
    // 2-byte UTF-8 "\u00e9" (0xC3 0xA9) so the decoder's cross-chunk state is
    // genuinely exercised, not just near an ASCII suffix.
    const bin = fakePi(
      'const full = JSON.stringify({type:"message_end",message:{role:"assistant",content:[{type:"text",text:' +
        JSON.stringify(text) +
        '}],stopReason:"stop"}}) + "\\n";' +
        "const b = Buffer.from(full);" +
        "const i = b.indexOf(0xc3);" +
        "process.stdout.write(b.subarray(0, i + 1));" +
        "setTimeout(() => process.stdout.write(b.subarray(i + 1)), 30);",
    );
    const result = await consult(bin);
    assert.equal(result.status, "completed");
    assert.equal(result.text, "caf\u00e9 \u2615 ok");
  });

  it("copies the host agent config files into the child work dir 0600, content intact", async () => {
    const listing = join(process.cwd(), ".advisor-child-test-listing");
    const modes = join(process.cwd(), ".advisor-child-test-modes");
    const identical = join(process.cwd(), ".advisor-child-test-identical");
    // The fake pi records the work-dir file list, each file's mode bits, and
    // whether each copied config file is byte-identical to the host original
    // (the work dir is removed before the test could read it back).
    const bin = fakePi(
      'const fs=require("node:fs");const p=require("node:path");const h=require("node:crypto");const dir=process.env.PI_CODING_AGENT_DIR;const names=fs.readdirSync(dir);' +
        "fs.writeFileSync(" +
        JSON.stringify(listing) +
        ',names.join(" "));' +
        "fs.writeFileSync(" +
        JSON.stringify(modes) +
        ',names.map(n=>n+":"+fs.statSync(p.join(dir,n)).mode.toString(8).slice(-3)).join(" "));' +
        'const host=p.join(process.env.HOME,".pi","agent");const hash=(f)=>h.createHash("sha256").update(fs.readFileSync(f)).digest("hex");' +
        'const cfg="auth.json models.json models-store.json".split(" ");' +
        "fs.writeFileSync(" +
        JSON.stringify(identical) +
        ',cfg.filter((n)=>fs.existsSync(p.join(dir,n))&&fs.existsSync(p.join(host,n))).map((n)=>n+":"+(hash(p.join(dir,n))===hash(p.join(host,n))?"same":"diff")).join(" "));' +
        msgEndScript("ok", { stopReason: "stop" }),
    );
    try {
      const result = await consult(bin);
      assert.equal(result.status, "completed");
      const files = readFileSync(listing, "utf8").trim().split(/\s+/).filter(Boolean).sort();
      const modeMap = new Map(
        readFileSync(modes, "utf8")
          .trim()
          .split(/\s+/)
          .filter(Boolean)
          .map((pair) => {
            const i = pair.indexOf(":");
            return [pair.slice(0, i), pair.slice(i + 1)] as const;
          }),
      );
      const identicalMap = new Map(
        readFileSync(identical, "utf8")
          .trim()
          .split(/\s+/)
          .filter(Boolean)
          .map((pair) => {
            const i = pair.indexOf(":");
            return [pair.slice(0, i), pair.slice(i + 1)] as const;
          }),
      );
      assert.ok(files.includes("prompt.txt"), `work dir missing prompt.txt: ${files}`);
      assert.equal(modeMap.get("prompt.txt"), "600", "prompt.txt must be 0600");
      // Each host config file that exists must be copied 0600 and byte-identical.
      const hostAgentDir = join(process.env.HOME ?? "", ".pi", "agent");
      for (const name of ["auth.json", "models.json", "models-store.json"]) {
        if (!existsSync(join(hostAgentDir, name))) continue;
        assert.ok(files.includes(name), `work dir missing ${name}: ${files}`);
        assert.equal(modeMap.get(name), "600", `${name} must be 0600`);
        assert.equal(identicalMap.get(name), "same", `${name} must be byte-identical to host`);
      }
    } finally {
      rmSync(listing, { force: true });
      rmSync(modes, { force: true });
      rmSync(identical, { force: true });
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

  it("flushes a final event that has no trailing newline", async () => {
    // The last NDJSON event is written without a terminating newline; the
    // transport's end() flush must still surface it, or the run would report
    // "no assistant response".
    const bin = fakePi(
      'const full = JSON.stringify({type:"message_end",message:{role:"assistant",content:[{type:"text",text:"final"}],stopReason:"stop"}});process.stdout.write(full);',
    );
    const result = await consult(bin);
    assert.equal(result.status, "completed");
    assert.equal(result.text, "final");
  });

  it("kills the child and reports timed_out when the deadline fires", async () => {
    const before = workDirs();
    const bin = fakePi("setTimeout(()=>{},10000);"); // never emits an event
    const started = performance.now();
    const result = await consultWithChildProcess({
      model: MODEL,
      modelLabel: "fake/fake-model",
      question: "q",
      transcript: "",
      effort: "low",
      cwd: process.cwd(),
      mode: "review",
      deadline: performance.now() + 200,
      config: { piBinary: bin },
    });
    const elapsed = performance.now() - started;
    assert.equal(result.status, "timed_out");
    assert.ok(elapsed < 5_000, `timeout should be bounded, took ${elapsed}ms`);
    assert.deepEqual(workDirs(), before, "work dir must be removed after a timeout");
  });

  it("reports aborted and tears down when the caller aborts mid-run", async () => {
    const before = workDirs();
    const bin = fakePi("setTimeout(()=>{},10000);");
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 100);
    const result = await consultWithChildProcess({
      model: MODEL,
      modelLabel: "fake/fake-model",
      question: "q",
      transcript: "",
      effort: "low",
      cwd: process.cwd(),
      mode: "review",
      deadline: DEADLINE(),
      signal: ac.signal,
      config: { piBinary: bin },
    });
    assert.equal(result.status, "aborted");
    assert.deepEqual(workDirs(), before, "work dir must be removed after an abort");
  });

  it("kills the whole process group, not just the immediate child, on timeout", async () => {
    const before = workDirs();
    // The immediate pi exits right after forking a descendant that inherits
    // stdout and ignores SIGTERM. If the transport only signals the immediate
    // PID, the descendant keeps the pipe open and "close" never fires, so the
    // consultation, the concurrency slot, and the credential dir would hang.
    // Killing the child's process group (detached spawn) must tear it down.
    const bin = fakePi(
      'require("node:child_process").spawn(process.execPath,["-e","process.on(\'SIGTERM\',()=>{});setInterval(()=>{},50);"]' +
        ' , { stdio: ["ignore", "inherit", "inherit"] });' +
        "process.exit(0);",
    );
    const started = performance.now();
    const result = await consultWithChildProcess({
      model: MODEL,
      modelLabel: "fake/fake-model",
      question: "q",
      transcript: "",
      effort: "low",
      cwd: process.cwd(),
      mode: "review",
      deadline: performance.now() + 200,
      config: { piBinary: bin },
    });
    const elapsed = performance.now() - started;
    assert.equal(result.status, "timed_out");
    // Bounded: the SIGKILL escalation (5s) must be the worst case, and the
    // descendant holding stdout must not stall the teardown.
    assert.ok(elapsed < 7_000, `group teardown should be bounded, took ${elapsed}ms`);
    assert.deepEqual(workDirs(), before, "work dir must be removed after group teardown");
  });

  it("survives a throwing update callback without orphaning the child", async () => {
    const before = workDirs();
    // Explore mode emits tool_execution_start events that trigger onUpdate.
    const bin = fakePi(
      'process.stdout.write(\'{"type":"tool_execution_start","toolName":"read"}\' + "\\n");' +
        msgEndScript("done", { stopReason: "stop" }),
    );
    const result = await consultWithChildProcess({
      model: MODEL,
      modelLabel: "fake/fake-model",
      question: "q",
      transcript: "",
      effort: "low",
      cwd: process.cwd(),
      mode: "explore",
      deadline: DEADLINE(),
      config: { piBinary: bin },
      onUpdate: () => {
        throw new Error("callback blew up");
      },
    });
    // The throwing callback must not crash the transport or drop the answer.
    assert.equal(result.status, "completed");
    assert.equal(result.text, "done");
    assert.equal(result.toolCalls, 1);
    assert.deepEqual(workDirs(), before, "work dir must be removed despite the throwing callback");
  });
});
