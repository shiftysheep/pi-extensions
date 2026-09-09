/**
 * Deterministic lifecycle tests for the child-process advisor transport:
 * a fake `pi` binary (a Node script) stands in for the real one, so the
 * protocol, cleanup, and failure paths are exercised without paying for a
 * model call. The fake binary lives outside the transport's work dir, because
 * the transport removes that dir in a finally block on every exit path.
 */

import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
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

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** True if a process with this pid exists and is killable by us. */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
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

  it("strips OAuth refresh tokens from the child auth.json and copies catalogs read-only", async () => {
    const modes = join(process.cwd(), ".advisor-child-test-modes");
    const authRefresh = join(process.cwd(), ".advisor-child-test-authrefresh");
    // A crafted host agent dir with an OAuth credential that HAS a refresh token,
    // plus a model catalog. Pointing PI_CODING_AGENT_DIR here lets us control the
    // source the transport copies from (independent of the real host setup).
    const hostDir = mkdtempSync(join(tmpdir(), "advisor-host-"));
    const savedAgentDir = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = hostDir;
    try {
      writeFileSync(
        join(hostDir, "auth.json"),
        JSON.stringify({
          "test-provider": {
            type: "oauth",
            access: "at.123",
            refresh: "rt.456",
            expires: 9999999999999,
          },
        }),
      );
      writeFileSync(join(hostDir, "models.json"), JSON.stringify({ custom: {} }));
      // The fake pi records each work-dir file's mode bits and whether the child's
      // auth.json still carries any provider's refresh token.
      const bin = fakePi(
        'const fs=require("node:fs");const p=require("node:path");const dir=process.env.PI_CODING_AGENT_DIR;' +
          "fs.writeFileSync(" +
          JSON.stringify(modes) +
          ',fs.readdirSync(dir).map(n=>n+":"+fs.statSync(p.join(dir,n)).mode.toString(8).slice(-3)).join(" "));' +
          'const hasRefresh=(f)=>{try{const j=JSON.parse(fs.readFileSync(f,"utf8"));for(const k of Object.keys(j)){const c=j[k];if(c&&typeof c==="object"&&"refresh"in c)return "yes";}return "no";}catch{return "na";}};' +
          "fs.writeFileSync(" +
          JSON.stringify(authRefresh) +
          ',"child:"+hasRefresh(p.join(dir,"auth.json")));' +
          msgEndScript("ok", { stopReason: "stop" }),
      );
      const result = await consult(bin);
      assert.equal(result.status, "completed");
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
      assert.equal(modeMap.get("prompt.txt"), "600", "prompt.txt must be 0600");
      // auth.json: present, 0400 (read-only), and NO refresh token (stripped).
      assert.equal(modeMap.get("auth.json"), "400", "auth.json must be 0400 (read-only)");
      assert.equal(
        readFileSync(authRefresh, "utf8").trim(),
        "child:no",
        "the child's auth.json must have no refresh token",
      );
      // models.json: present and 0600 (read-only catalog).
      assert.equal(modeMap.get("models.json"), "600", "models.json must be 0600");
    } finally {
      if (savedAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = savedAgentDir;
      rmSync(hostDir, { recursive: true, force: true });
      rmSync(modes, { force: true });
      rmSync(authRefresh, { force: true });
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

  it("kills a SIGTERM-ignoring descendant with detached stdio on timeout", async () => {
    const before = workDirs();
    const dir = mkdtempSync(join(tmpdir(), "pi-advisor-fake-"));
    fakeDirs.push(dir);
    const marker = join(dir, "survived");
    // The descendant detaches stdio ("ignore") so it does NOT hold the pipes, and
    // ignores SIGTERM; if it is still alive ~1s after spawn it writes a marker.
    // The immediate pi forks it and then stays alive, so the (400ms) deadline
    // fires while the immediate child is running. When the immediate child dies
    // and "close" fires, the descendant still lives — the transport must not rely
    // on pipe closure but escalate the group to SIGKILL (the only thing that kills
    // a SIGTERM-ignoring process).
    writeFileSync(
      join(dir, "desc.js"),
      "process.on('SIGTERM',()=>{});\n" +
        `setTimeout(()=>require('node:fs').writeFileSync(${JSON.stringify(marker)},'alive'),1000);\n` +
        "setInterval(()=>{},50);\n",
    );
    const bin = join(dir, "pi");
    writeFileSync(
      bin,
      "#!/usr/bin/env node\n" +
        "require('node:child_process').spawn(process.execPath,[" +
        JSON.stringify(join(dir, "desc.js")) +
        "],{stdio:'ignore'});\n" +
        "setTimeout(()=>{},120000);\n",
    );
    chmodSync(bin, 0o755);
    const result = await consultWithChildProcess({
      model: MODEL,
      modelLabel: "fake/fake-model",
      question: "q",
      transcript: "",
      effort: "low",
      cwd: process.cwd(),
      mode: "review",
      deadline: performance.now() + 400,
      config: { piBinary: bin },
    });
    assert.equal(result.status, "timed_out");
    // Wait past the descendant's 1s "still alive" window; if group teardown
    // failed to SIGKILL it, it would have written the marker.
    await new Promise((resolve) => setTimeout(resolve, 1_600));
    assert.equal(
      existsSync(marker),
      false,
      "the SIGTERM-ignoring descendant must be killed by group teardown",
    );
    assert.deepEqual(workDirs(), before, "work dir must be removed after group teardown");
  });

  it("does not hang when an out-of-group descendant holds the pipe", async () => {
    const before = workDirs();
    const dir = mkdtempSync(join(tmpdir(), "pi-advisor-fake-"));
    fakeDirs.push(dir);
    // The descendant moves itself to a NEW session (detached => setsid) so the
    // transport's group signal cannot reach it, and it INHERITS the immediate
    // pi's stdout (so it holds the pipe). It stays alive. Without a bound on the
    // "close" wait, the transport would hang forever here: the immediate child
    // dies on the deadline's SIGKILL, but "close" never fires because this
    // out-of-group descendant keeps the pipe open.
    const pidFile = join(tmpdir(), `pi-advisor-escape-pid-${process.pid}-${Date.now()}`);
    writeFileSync(
      join(dir, "desc.js"),
      `require('node:fs').writeFileSync(${JSON.stringify(pidFile)},String(process.pid));\n` +
        "setInterval(()=>{},50);\n",
    );
    const bin = join(dir, "pi");
    writeFileSync(
      bin,
      "#!/usr/bin/env node\n" +
        "require('node:child_process').spawn(process.execPath,[" +
        JSON.stringify(join(dir, "desc.js")) +
        "],{detached:true,stdio:['ignore','inherit','ignore']});\n" +
        "setTimeout(()=>{},120000);\n",
    );
    chmodSync(bin, 0o755);
    // Race against a test-side bound so a regression (hang) fails the test
    // rather than stalling the whole suite. The watchdog is cleared after the
    // race so it does not retain the test host for the full 8s.
    let watchdog: ReturnType<typeof setTimeout> | undefined;
    const result = await Promise.race([
      consultWithChildProcess({
        model: MODEL,
        modelLabel: "fake/fake-model",
        question: "q",
        transcript: "",
        effort: "low",
        cwd: process.cwd(),
        mode: "review",
        deadline: performance.now() + 400,
        config: { piBinary: bin },
      }),
      new Promise<never>((_, reject) => {
        watchdog = setTimeout(
          () => reject(new Error("transport hung on an out-of-group descendant")),
          8_000,
        );
      }),
    ]);
    if (watchdog !== undefined) clearTimeout(watchdog);
    assert.equal(result.status, "timed_out");
    // The escaping descendant is in a new session, so the group signal did not
    // reach it; clean it up explicitly (and remove the work dir it is not in).
    try {
      const escPid = Number(readFileSync(pidFile, "utf8").trim());
      process.kill(escPid, "SIGKILL");
    } catch {
      /* already gone */
    }
    rmSync(pidFile, { force: true });
    assert.deepEqual(workDirs(), before, "work dir must be removed after the bounded wait");
  });

  it("bounds an early abort with a SIGTERM-ignoring child (shared teardown budget)", {
    timeout: 20_000,
  }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "pi-advisor-fake-"));
    fakeDirs.push(dir);
    // A child that ignores SIGTERM, so the abort's SIGTERM does not kill it; only
    // the SIGKILL escalation does. Aborting EARLY (well before the long deadline)
    // must return within the shared teardown budget (SIGTERM -> SIGKILL escalation
    // + grace), not wait for the full 120s deadline (which the pre-fix code would
    // approach by stacking a 10s close-wait bound + a 10s teardown cap).
    writeFileSync(
      join(dir, "pi"),
      "#!/usr/bin/env node\nprocess.on('SIGTERM',()=>{});\nsetTimeout(()=>{},120000);\n",
    );
    chmodSync(join(dir, "pi"), 0o755);
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 100);
    const t0 = performance.now();
    const result = await consultWithChildProcess({
      model: MODEL,
      modelLabel: "fake/fake-model",
      question: "q",
      transcript: "",
      effort: "low",
      cwd: process.cwd(),
      mode: "review",
      deadline: performance.now() + 120_000,
      signal: ac.signal,
      config: { piBinary: join(dir, "pi") },
    });
    const elapsed = performance.now() - t0;
    assert.equal(result.status, "aborted");
    assert.ok(
      elapsed < 20_000,
      `early abort took ${Math.round(elapsed)}ms (must be bounded by the shared budget, not wait for the 120s deadline)`,
    );
  });

  it("kills an in-group descendant that holds the pipes after the leader exits (early-exit teardown)", {
    timeout: 15_000,
  }, async () => {
    const before = workDirs();
    const dir = mkdtempSync(join(tmpdir(), "pi-advisor-fake-"));
    fakeDirs.push(dir);
    // pidFile lives in the fake dir (cleaned by the after hook), not the shared
    // tmpdir, so an interrupted run can't leave an artifact that pollutes
    // workDirs() in a later test.
    const pidFile = join(dir, "desc.pid");
    // The leader emits a valid stop, then spawns an in-group descendant that
    // inherits the pipes (holding them open) and stays alive, and exits 0. The
    // "close" wait resolves via the leader dying + grace (NOT the deadline), so
    // the consultation completes on the normal path — and the unconditional
    // group teardown in finally must then SIGKILL the in-group descendant.
    writeFileSync(
      join(dir, "pi"),
      "#!/usr/bin/env node\n" +
        'process.stdout.write(JSON.stringify({type:"message_end",message:{role:"assistant",content:[{type:"text",text:"ok"}],stopReason:"stop",usage:{input:1,output:2}}}) + "\\n");\n' +
        "setTimeout(() => {\n" +
        `  require("node:child_process").spawn(process.execPath, ["-e", "require('node:fs').writeFileSync(process.argv[1],String(process.pid));setInterval(()=>{},50);", ${JSON.stringify(pidFile)}], { stdio: ["ignore", "inherit", "inherit"] });\n` +
        "  process.exit(0);\n" +
        "}, 150);\n",
    );
    chmodSync(join(dir, "pi"), 0o755);
    const result = await consultWithChildProcess({
      model: MODEL,
      modelLabel: "fake/fake-model",
      question: "q",
      transcript: "",
      effort: "low",
      cwd: process.cwd(),
      mode: "review",
      deadline: performance.now() + 8_000,
      config: { piBinary: join(dir, "pi") },
    });
    // The leader exited 0 with a valid stop reason, so the consultation
    // completes (not a timeout).
    assert.equal(result.status, "completed");
    assert.equal(result.text, "ok");
    // The in-group descendant holds the pipes, so without the unconditional
    // group teardown it would survive (and keep the host's event loop alive).
    let pid = 0;
    for (let i = 0; i < 60 && pid === 0; i++) {
      if (existsSync(pidFile)) pid = Number(readFileSync(pidFile, "utf8").trim());
      else await sleep(50);
    }
    assert.ok(pid > 0, "descendant pid was not recorded");
    for (let i = 0; i < 40 && isAlive(pid); i++) await sleep(50);
    assert.equal(isAlive(pid), false, "in-group descendant survived the early-exit teardown");
    rmSync(pidFile, { force: true });
    assert.deepEqual(workDirs(), before, "work dir must be removed");
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

/**
 * Mock-child regression tests for the interrupt-driven hard-bound teardown path.
 *
 * A real spawned child is ALWAYS killed by the group SIGKILL (at interrupt+5s),
 * before the 15s hard bound, so the "child never exits or closes" case cannot be
 * reproduced with a real process (only a kernel-stuck/D-state task escapes
 * SIGKILL, which no test can create). Instead we inject a fake child emitter
 * (via opts.__test.spawnImpl) that never exits, a mocked group-kill (killImpl, so
 * a fabricated pid is never signalled), and a short teardown margin, to verify:
 * (1) the wait settles at first-interrupt + one shared margin (no stacking);
 * (2) a second interrupt fired during teardown is tolerated (no hang/crash) and
 *     does not delay settlement past the shared budget;
 * (3) a late "exit" after settlement is a no-op: it leaves no owned close/exit
 *     listeners behind and creates no new wait.
 *
 * Note: the immutable-budget guard in startHardBound (which refuses to restart
 * the deadline once set) is defence-in-depth. It guards a synchronous window —
 * an interrupt between close-wait settlement and the finally's
 * interrupt-disable — that event-driven interrupts cannot actually reach
 * (the finally disables the deadline timer and abort listener before it awaits
 * teardown). It is therefore not independently observable in a timing test;
 * test (2) covers the observable behaviour (a second interrupt is tolerated).
 */
describe("consultWithChildProcess (mock child — hard-bound teardown)", () => {
  const MARGIN_MS = 400;

  /** A fake child that never emits "exit" or "close" (an unkillable child). */
  function makeFakeChild(): { child: ChildProcess; signals: string[] } {
    const ee = new EventEmitter();
    const stream = { on: () => undefined, destroy: () => undefined };
    const signals: string[] = [];
    const child = {
      on: ee.on.bind(ee),
      once: ee.once.bind(ee),
      removeListener: ee.removeListener.bind(ee),
      emit: ee.emit.bind(ee),
      listenerCount: ee.listenerCount.bind(ee),
      pid: 999_999_999,
      exitCode: null,
      signalCode: null,
      unref: () => undefined,
      kill: (sig?: NodeJS.Signals) => {
        signals.push(sig ?? "SIGTERM");
        return true;
      },
      stdout: stream,
      stderr: stream,
    } as unknown as ChildProcess;
    return { child, signals };
  }

  const baseOpts = {
    model: MODEL,
    modelLabel: "fake/fake-model",
    question: "q",
    transcript: "",
    effort: "low" as const,
    cwd: process.cwd(),
    mode: "review" as const,
  };

  it("settles at first-interrupt + one shared margin (no stacked budget)", async () => {
    const { child } = makeFakeChild();
    const killSignals: string[] = [];
    const t0 = performance.now();
    const result = await consultWithChildProcess({
      ...baseOpts,
      deadline: performance.now() + 120, // fires soon -> the first interrupt
      __test: {
        spawnImpl: () => child,
        killImpl: (_pid, signal) => {
          killSignals.push(signal);
        },
        teardownMarginMs: MARGIN_MS,
      },
    });
    const elapsed = performance.now() - t0;
    assert.equal(result.status, "timed_out");
    // A stacked budget (margin + margin) would settle at ~120 + 800 = 920ms.
    // The shared budget settles at ~120 + 400 = 520ms. Keep the bound well
    // between them.
    assert.ok(
      elapsed < 780,
      `settled at ${Math.round(elapsed)}ms — a stacked budget would settle near 920ms`,
    );
    assert.ok(
      elapsed >= 380,
      `settled too early (${Math.round(elapsed)}ms) to have hit the hard bound`,
    );
    // Group escalation did signal (mocked, so the fabricated pid was not touched).
    assert.ok(killSignals.includes("SIGTERM"));
  });

  it("tolerates a second interrupt during teardown (no hang, no crash)", async () => {
    const { child } = makeFakeChild();
    const ac = new AbortController();
    const t0 = performance.now();
    // The deadline is the first interrupt (+120ms); the abort is a second
    // interrupt fired while the first's hard bound is still pending (+200ms).
    setTimeout(() => ac.abort(), 200);
    const result = await consultWithChildProcess({
      ...baseOpts,
      deadline: performance.now() + 120,
      signal: ac.signal,
      __test: {
        spawnImpl: () => child,
        killImpl: () => undefined,
        teardownMarginMs: MARGIN_MS,
      },
    });
    const elapsed = performance.now() - t0;
    assert.equal(result.status, "timed_out"); // the first interrupt (deadline) wins
    // The second interrupt must not hang the call or push settlement past the
    // shared budget (~120 + 400 = 520ms).
    assert.ok(
      elapsed < 1_000,
      `second interrupt delayed settlement to ${Math.round(elapsed)}ms (should be ~520ms)`,
    );
  });

  it("a late exit after settlement is a no-op (no listeners, no new wait)", async () => {
    const { child } = makeFakeChild();
    const t0 = performance.now();
    const consult = consultWithChildProcess({
      ...baseOpts,
      deadline: performance.now() + 120,
      __test: {
        spawnImpl: () => child,
        killImpl: () => undefined,
        teardownMarginMs: MARGIN_MS,
      },
    });
    // After the hard bound settles the close-wait (~120 + 400ms), emit a LATE
    // "exit" on the abandoned child. The settled guard must make it a no-op
    // (no new grace timer, no hang).
    setTimeout(() => child.emit("exit", null, null), 600);
    const watchdog = setTimeout(() => {
      throw new Error("late exit after settlement caused a hang");
    }, 2_500);
    const result = await consult;
    clearTimeout(watchdog);
    assert.equal(result.status, "timed_out");
    // IMMEDIATELY after settlement (the finally has run), assert the transport
    // removed ALL owned close/exit listeners. This must be checked BEFORE the
    // late "exit" fires (~600ms): a leaked once("exit") listener would be
    // auto-removed by its own delivery, so asserting only after the late exit
    // would miss it (the abandoned child then keeps that listener forever).
    assert.equal(child.listenerCount("close"), 0, "settlement left a 'close' listener behind");
    assert.equal(child.listenerCount("exit"), 0, "settlement left an 'exit' listener behind");
    // Now wait past the late "exit" (~600ms) and re-assert: the late exit must
    // be a no-op (no new listeners, no hang).
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(
      performance.now() - t0 < 1_200,
      `late exit delayed settlement (should settle at the hard bound ~520ms)`,
    );
    assert.equal(child.listenerCount("close"), 0, "a late exit left a 'close' listener behind");
    assert.equal(child.listenerCount("exit"), 0, "a late exit left an 'exit' listener behind");
  });
});
