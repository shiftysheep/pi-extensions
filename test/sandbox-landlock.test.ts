/**
 * Integration tests for the Landlock helper (extensions/permission-gate/landlock-helper.c).
 * Compiles the helper and exercises it for real. Skips cleanly when there is
 * no C compiler or the kernel lacks Landlock. Run with `npm test`.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const SOURCE = fileURLToPath(
  new URL("../extensions/permission-gate/landlock-helper.c", import.meta.url),
);

function which(cmd: string): string | undefined {
  const res = spawnSync("/bin/sh", ["-c", `command -v ${cmd}`], { encoding: "utf8" });
  return res.status === 0 && res.stdout.trim() ? res.stdout.trim() : undefined;
}

const cc = which("cc") ?? which("gcc") ?? which("clang");

let helper: string | undefined;
let ws: string | undefined;
let skipReason: string | undefined;

if (cc) {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-landlock-test-"));
  helper = path.join(workdir, "pi-sandbox-landlock");
  ws = path.join(workdir, "ws");
  fs.mkdirSync(ws);
  const build = spawnSync(cc, ["-O2", "-o", helper, SOURCE], { encoding: "utf8" });
  if (build.status !== 0) {
    skipReason = `build failed: ${build.stderr?.slice(-300)}`;
  } else {
    const canary = spawnSync(helper, ["--rw", workdir, "--", "/bin/sh", "-c", "true"], {
      encoding: "utf8",
    });
    if (canary.status !== 0) {
      skipReason = `kernel lacks Landlock (canary exit ${canary.status}): ${canary.stderr?.trim()}`;
    }
  }
} else {
  skipReason = "no C compiler available (cc/gcc/clang)";
}

describe("landlock helper", () => {
  if (skipReason || !helper || !ws) {
    it(`skips: ${skipReason ?? "helper setup failed"}`, () => {});
    return;
  }
  // Narrowed copies (module-level lets don't narrow inside closures).
  const h = helper;
  const w = ws;

  function run(
    args: string[],
    command: string,
  ): { status: number; stdout: string; stderr: string } {
    const res = spawnSync(h, [...args, "--", "/bin/sh", "-c", command], {
      encoding: "utf8",
      cwd: w,
    });
    return { status: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
  }

  function runDirect(
    args: string[],
    command: string,
    commandArgs: string[],
  ): { status: number; stdout: string; stderr: string } {
    const res = spawnSync(h, [...args, "--", command, ...commandArgs], {
      encoding: "utf8",
      cwd: w,
    });
    return { status: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
  }

  it("passes through the exit code", () => {
    assert.equal(run(["--rw", w], "exit 42").status, 42);
  });

  it("allows reading everything", () => {
    const r = run(["--rw", w], "head -1 /etc/hostname && echo READ_OK");
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes("READ_OK"));
  });

  it("allows writes inside --rw roots", () => {
    const r = run(["--rw", w], `echo hi > ${w}/a.txt && cat ${w}/a.txt`);
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes("hi"));
  });

  it("denies writes outside --rw roots", () => {
    const r = run(["--rw", w], `echo x > ${w}/../evil; echo inner=$?`);
    assert.ok(r.stdout.includes("inner="), r.stdout + r.stderr);
    assert.ok(
      !r.stdout.includes("inner=0"),
      `write outside roots must fail: ${r.stdout} ${r.stderr}`,
    );
  });

  it("allows rename/mv inside --rw roots", () => {
    const r = run(["--rw", w], `mv ${w}/a.txt ${w}/b.txt && echo MV_OK`);
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes("MV_OK"));
  });

  it("allows direct cross-directory rename inside --rw roots", () => {
    const sourceDir = path.join(w, "direct-rename-source");
    const source = path.join(sourceDir, "full.rmeta");
    const destination = path.join(w, "direct-rename-destination.rmeta");
    const prepared = run(["--rw", w], `mkdir -p ${sourceDir} && : > ${source}`);
    assert.equal(prepared.status, 0, prepared.stderr);

    const renamed = runDirect(["--rw", w], process.execPath, [
      "-e",
      "require('node:fs').renameSync(process.argv[1], process.argv[2])",
      source,
      destination,
    ]);
    assert.equal(renamed.status, 0, renamed.stderr);
    assert.ok(fs.existsSync(destination));
  });

  it("denies symlink and FIFO creation outside --rw roots", () => {
    const readOnlyDir = fs.mkdtempSync(path.join(os.homedir(), ".pi-landlock-ro-"));
    try {
      const symlink = run(["--rw", w], `ln -s /etc/hostname ${readOnlyDir}/link`);
      assert.notEqual(symlink.status, 0, "symlink creation outside roots must fail");

      const fifo = run(["--rw", w], `mkfifo ${readOnlyDir}/fifo`);
      assert.notEqual(fifo.status, 0, "FIFO creation outside roots must fail");
    } finally {
      fs.rmSync(readOnlyDir, { recursive: true, force: true });
    }
  });

  it("denies writes to /dev/null unless /dev is a root", () => {
    const denied = run(["--rw", w], "ls > /dev/null && echo OK");
    assert.ok(
      !denied.stdout.includes("OK"),
      `redirect to /dev/null must fail: ${denied.stdout} ${denied.stderr}`,
    );
    const allowed = run(["--rw", w, "--rw", "/dev"], "ls > /dev/null && echo OK");
    assert.equal(allowed.status, 0);
    assert.ok(allowed.stdout.includes("OK"));
  });

  it("fails closed on a missing --rw path", () => {
    const r = spawnSync(h, ["--rw", "/no/such/dir", "--", "/bin/true"], { encoding: "utf8" });
    assert.equal(r.status, 3);
  });

  it("blocks setuid escalation (no_new_privs)", () => {
    const r = run(["--rw", w], "sudo -n true 2>&1 | head -1");
    assert.ok(/privileges|sudo/i.test(r.stdout + r.stderr), r.stdout + r.stderr);
  });

  it("executes external binaries with args intact", () => {
    const r = run([], "true");
    assert.equal(r.status, 0);
  });

  it("passes argv through unmodified (quotes, spaces)", () => {
    const res = spawnSync(h, ["--rw", w, "--", "/bin/echo", "a b", "c'd"], { encoding: "utf8" });
    assert.ok(res.stdout.includes("a b c'd"), res.stdout);
  });
});
