/**
 * Integration tests for the bubblewrap wrapper (wrapWithBwrap).
 * Runs the ACTUAL generated command line and verifies the mount layout:
 * fresh private /tmp and /proc (host contents hidden), writable roots
 * bound rw, everything else read-only. Skips cleanly when bwrap is
 * missing or unprivileged user namespaces are blocked (e.g. AppArmor
 * restrict_unprivileged_userns). Run with `npm test`.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { type SandboxPolicy, wrapWithBwrap } from "../extensions/lib/sandbox-utils.js";

const RUN_TIMEOUT_MS = 15_000;

function which(cmd: string): string | undefined {
  const res = spawnSync("/bin/sh", ["-c", `command -v ${cmd}`], { encoding: "utf8" });
  return res.status === 0 && res.stdout.trim() ? res.stdout.trim() : undefined;
}

const bin = which("bwrap");

let ws: string | undefined;
let hostTmpMarker: string | undefined;
let skipReason: string | undefined;

if (!bin) {
  skipReason = "bwrap not found (install bubblewrap)";
} else {
  // Canary: namespace creation may be blocked (AppArmor
  // restrict_unprivileged_userns, seccomp, containers).
  const canaryPolicy: SandboxPolicy = {
    writableRoots: ["/tmp", "/dev", "/proc"],
    network: "allow",
    loginShell: true,
  };
  const canary = spawnSync(
    "/bin/sh",
    [
      "-c",
      wrapWithBwrap("true", canaryPolicy, {
        cwd: os.tmpdir(),
        homeDir: os.homedir(),
        shellPath: "/bin/bash",
      }),
    ],
    { encoding: "utf8", timeout: RUN_TIMEOUT_MS },
  );
  if (canary.status !== 0) {
    skipReason = `bwrap canary failed (exit ${canary.status ?? "?"}): ${canary.stderr?.trim() ?? "namespace creation blocked"}`;
  } else {
    const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-bwrap-test-"));
    ws = path.join(workdir, "ws");
    fs.mkdirSync(ws);
    // A file that exists in the HOST /tmp: invisible inside the sandbox's
    // fresh tmpfs.
    hostTmpMarker = path.join(os.tmpdir(), "pi-bwrap-host-marker");
    fs.writeFileSync(hostTmpMarker, "host");
  }
}

describe("bwrap wrapper", () => {
  if (skipReason || !ws) {
    it(`skips: ${skipReason ?? "setup failed"}`, () => {});
    return;
  }
  // Narrowed copies (module-level lets don't narrow inside closures).
  const w = ws;
  const marker = hostTmpMarker as string;
  const hostPid = process.pid;

  const policy: SandboxPolicy = {
    writableRoots: [w, "/tmp", "/dev", "/proc"],
    network: "allow",
    loginShell: true,
  };

  function run(command: string) {
    const wrapped = wrapWithBwrap(command, policy, {
      cwd: w,
      homeDir: os.homedir(),
      shellPath: "/bin/bash",
    });
    const res = spawnSync("/bin/sh", ["-c", wrapped], {
      encoding: "utf8",
      cwd: w,
      timeout: RUN_TIMEOUT_MS,
    });
    return { status: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
  }

  it("runs the generated command line", () => {
    assert.equal(run("true").status, 0);
  });

  it("mounts a FRESH /tmp: writes work, host /tmp contents are hidden", () => {
    const r = run(
      `echo x > /tmp/pi-bwrap-canary && cat /tmp/pi-bwrap-canary && [ ! -e ${marker} ] && echo HIDDEN`,
    );
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(r.stdout.includes("x"), r.stdout + r.stderr);
    assert.ok(r.stdout.includes("HIDDEN"), `host /tmp marker leaked into sandbox: ${r.stdout}`);
  });

  it("mounts a FRESH /proc: host pids are not visible", () => {
    const r = run(`[ -r /proc/self/status ] && [ ! -d /proc/${hostPid} ] && echo FRESH`);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(r.stdout.includes("FRESH"), r.stdout + r.stderr);
  });

  it("binds writable roots rw", () => {
    const r = run(`echo hi > ${w}/a.txt && cat ${w}/a.txt`);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes("hi"));
  });

  it("keeps everything else read-only", () => {
    const r = run(`touch /etc/pi-bwrap-evil 2>/dev/null; echo inner=$?`);
    assert.ok(r.stdout.includes("inner="), r.stdout + r.stderr);
    assert.ok(
      !r.stdout.includes("inner=0"),
      `write outside roots must fail: ${r.stdout} ${r.stderr}`,
    );
  });

  it("allows /dev/null", () => {
    const r = run("ls > /dev/null && echo OK");
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes("OK"));
  });
});
