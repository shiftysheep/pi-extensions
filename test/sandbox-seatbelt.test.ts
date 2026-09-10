/**
 * Integration tests for the Seatbelt (sandbox-exec) profile.
 * Generates a real profile via buildSeatbeltProfile and runs the canary
 * matrix under sandbox-exec. Skips cleanly when not on macOS or
 * sandbox-exec is missing (mirrors test/sandbox-landlock.test.ts). A
 * BROKEN generated profile must FAIL these tests, not skip them — that is
 * the regression this suite exists to catch. Run with `npm test`.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { buildSeatbeltProfile, shellQuote } from "../extensions/lib/sandbox-utils.js";

const RUN_TIMEOUT_MS = 15_000;

function which(cmd: string): string | undefined {
  const res = spawnSync("/bin/sh", ["-c", `command -v ${cmd}`], { encoding: "utf8" });
  return res.status === 0 && res.stdout.trim() ? res.stdout.trim() : undefined;
}

const bin = process.platform === "darwin" ? which("sandbox-exec") : undefined;

let ws: string | undefined;
let skipReason: string | undefined;

if (!bin) {
  skipReason =
    process.platform === "darwin" ? "sandbox-exec not found" : `not macOS (${process.platform})`;
} else {
  // Canonicalize: Seatbelt matches subpaths against canonical paths and
  // $TMPDIR may be a symlinked form (/var/folders -> /private/var/folders).
  const workdir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "pi-seatbelt-test-")));
  ws = path.join(workdir, "ws");
  fs.mkdirSync(ws);
}

describe("seatbelt profile", () => {
  if (skipReason || !ws || !bin) {
    it(`skips: ${skipReason ?? "setup failed"}`, () => {});
    return;
  }
  // Narrowed copies (module-level lets don't narrow inside closures).
  const b = bin;
  const w = ws;

  const profile = (network: "allow" | "deny") =>
    buildSeatbeltProfile({ writableRoots: [w, "/dev"], network });

  function run(command: string, network: "allow" | "deny" = "allow") {
    const res = spawnSync(b, ["-p", profile(network), "/bin/sh", "-c", command], {
      encoding: "utf8",
      cwd: w,
      timeout: RUN_TIMEOUT_MS,
    });
    return { status: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
  }

  it("loads the generated profile", () => {
    const r = run("true");
    assert.equal(r.status, 0, `profile rejected: ${r.stderr}`);
  });

  it("passes through the exit code", () => {
    assert.equal(run("exit 42").status, 42);
  });

  it("allows reading outside the roots", () => {
    const r = run("head -1 /etc/hosts && echo READ_OK");
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes("READ_OK"));
  });

  it("allows writes inside the roots", () => {
    const r = run(`echo hi > ${shellQuote(`${w}/a.txt`)} && cat ${shellQuote(`${w}/a.txt`)}`);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes("hi"));
  });

  it("denies writes outside the roots", () => {
    const r = run(`echo x > ${shellQuote(`${w}/../evil`)}; echo inner=$?`);
    assert.ok(r.stdout.includes("inner="), r.stdout + r.stderr);
    assert.ok(
      !r.stdout.includes("inner=0"),
      `write outside roots must fail: ${r.stdout} ${r.stderr}`,
    );
  });

  it("allows /dev/null when /dev is a root", () => {
    const r = run("ls > /dev/null && echo OK");
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes("OK"));
  });

  it("allows stderr redirects to /dev/null", () => {
    const r = run("printf x 2> /dev/null && echo OK");
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes("OK"));
  });

  it("allows pipes (file-write on anonymous pipes under deny-default)", () => {
    const r = run("echo hi | cat && echo PIPE_OK");
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes("PIPE_OK"));
  });

  it("allows tee to /dev/stderr (fd alias grant)", () => {
    const r = run("echo warn | tee /dev/stderr >/dev/null; echo tee=$?");
    assert.ok(r.stdout.includes("tee="), r.stdout + r.stderr);
    assert.ok(r.stdout.includes("tee=0"), `tee /dev/stderr must succeed: ${r.stdout} ${r.stderr}`);
  });

  it("allows bash process substitution (writes to /dev/fd/N)", () => {
    const res = spawnSync(b, ["-p", profile("allow"), "/bin/bash", "-c", "cat < <(echo sub)"], {
      encoding: "utf8",
      timeout: RUN_TIMEOUT_MS,
    });
    assert.equal(res.status, 0, res.stderr);
    assert.ok(res.stdout.includes("sub"), res.stdout + res.stderr);
  });

  it("executes external binaries with args intact", () => {
    const res = spawnSync(b, ["-p", profile("allow"), "/bin/echo", "a b", "c'd"], {
      encoding: "utf8",
      timeout: RUN_TIMEOUT_MS,
    });
    assert.ok(res.stdout.includes("a b c'd"), res.stdout);
  });

  const CONNECT_SCRIPT = (port: number) =>
    `const net=require("node:net");const s=net.connect(${port},"127.0.0.1");` +
    `s.on("connect",()=>{console.log("NET_OK");process.exit(0)});` +
    `s.on("error",(e)=>{console.log("NET_ERR "+(e&&e.code));process.exit(1)});` +
    `setTimeout(()=>{console.log("NET_TIMEOUT");process.exit(2)},5000);`;

  async function withServer(fn: (port: number) => void | Promise<void>): Promise<void> {
    const server = net.createServer();
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("no server port");
    try {
      await fn(addr.port);
    } finally {
      server.close();
    }
  }

  it("allows outbound network when policy allows", async () => {
    await withServer((port) => {
      const res = spawnSync(
        b,
        ["-p", profile("allow"), process.execPath, "-e", CONNECT_SCRIPT(port)],
        {
          encoding: "utf8",
          timeout: RUN_TIMEOUT_MS,
        },
      );
      assert.equal(res.status, 0, res.stderr);
      assert.ok(res.stdout.includes("NET_OK"), res.stdout + res.stderr);
    });
  });

  it("denies outbound network when policy denies", async () => {
    await withServer((port) => {
      const res = spawnSync(
        b,
        ["-p", profile("deny"), process.execPath, "-e", CONNECT_SCRIPT(port)],
        {
          encoding: "utf8",
          timeout: RUN_TIMEOUT_MS,
        },
      );
      // A connection ERROR (not a crash/timeout) is the proof of enforcement.
      assert.equal(res.status, 1, `expected connect error: ${res.stdout} ${res.stderr}`);
      assert.ok(res.stdout.includes("NET_ERR"), res.stdout + res.stderr);
    });
  });
});
