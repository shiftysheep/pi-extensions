/**
 * Sandbox runner resolution (impure): binary probing, Landlock helper
 * compilation, and canary runs. Called once per session at session_start.
 *
 * `auto` on Linux prefers bwrap (stronger: user/pid namespaces, optional
 * network off) and falls back to the Landlock helper. On macOS only
 * sandbox-exec (Seatbelt) exists.
 */

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildSeatbeltProfile,
  isNoexecPath,
  normalizeHelperPath,
  resolveExistingRoot,
  type SandboxRunner,
  type SandboxRunnerChoice,
  shellQuote,
} from "../lib/sandbox-utils.js";

export type RunnerProbeResult =
  | { ok: true; runner: SandboxRunner; detail: string; helperPath?: string }
  | { ok: false; reason: string };

const CANARY_TIMEOUT_MS = 10_000;
const BUILD_TIMEOUT_MS = 30_000;

function which(cmd: string): string | undefined {
  const res = spawnSync("/bin/sh", ["-c", `command -v ${cmd}`], {
    encoding: "utf8",
    timeout: 5_000,
  });
  return res.status === 0 && res.stdout.trim() ? res.stdout.trim() : undefined;
}

/** bwrap canary: create the namespaces and verify a write inside works. */
function probeBwrap(): RunnerProbeResult {
  const bin = which("bwrap");
  if (!bin) return { ok: false, reason: "bwrap not found (install bubblewrap)" };
  const canary = spawnSync(
    bin,
    [
      "--ro-bind",
      "/",
      "/",
      "--bind",
      "/tmp",
      "/tmp",
      "--unshare-user",
      "--unshare-pid",
      "--",
      "/bin/sh",
      "-c",
      "test -w /tmp && echo ok",
    ],
    { encoding: "utf8", timeout: CANARY_TIMEOUT_MS },
  );
  if (canary.status === 0) return { ok: true, runner: "bwrap", detail: bin };
  const stderr = (canary.stderr ?? "").trim().split("\n").pop() ?? "";
  return {
    ok: false,
    reason: `bwrap canary failed${canary.status != null ? ` (exit ${canary.status})` : ""}: ${stderr || "namespace creation blocked (e.g. AppArmor restrict_unprivileged_userns)"}`,
  };
}

const HELPER_SOURCE = fileURLToPath(new URL("./landlock-helper.c", import.meta.url));

/**
 * Known-good SHA-256 of landlock-helper.c. The helper is compiled from this
 * source on first use; a tampered/modified source fails the probe CLOSED
 * instead of silently compiling unexpected code. Update in the same commit
 * that changes the source.
 */
export const HELPER_SOURCE_SHA256 =
  "7e9071c027c127ef6ff57544b760e3043108022f3e41f402b4a617822f1ba149";

export function landlockHelperPath(): string {
  return path.join(os.homedir(), ".cache", "pi-extensions", "pi-sandbox-landlock");
}

/**
 * Landlock: use a prebuilt helper when configured (no compilation),
 * otherwise build the helper (if stale) behind a source-integrity check,
 * and verify the kernel accepts it.
 */
function probeLandlock(override?: string): RunnerProbeResult {
  let out: string;
  if (override !== undefined) {
    // An explicit override is a directive: a missing/unusable file fails
    // the probe instead of silently compiling a different binary. The path
    // is normalized to absolute so validation and execution refer to the
    // same binary (a relative path would be cwd-relative for accessSync
    // but a PATH search for spawn).
    const resolved = normalizeHelperPath(override, os.homedir());
    if (resolved === undefined) {
      return {
        ok: false,
        reason: `landlockHelper must be an absolute path (or start with ~): ${override}`,
      };
    }
    try {
      fs.accessSync(resolved, fs.constants.X_OK);
    } catch {
      return {
        ok: false,
        reason: `configured landlockHelper is not an executable file: ${resolved}`,
      };
    }
    out = resolved;
  } else {
    const cc = which("cc") ?? which("gcc") ?? which("clang");
    if (!cc)
      return {
        ok: false,
        reason: "no C compiler found (cc/gcc/clang) to build the landlock helper",
      };
    out = landlockHelperPath();
    // noexec cache dir (common on hardened /home): fail with an actionable
    // message instead of a confusing exec failure after a wasted build.
    // Canonicalize first: a symlinked ancestor can sit on a different mount.
    try {
      const dir = path.dirname(out);
      const base = resolveExistingRoot(dir, (p) => {
        try {
          fs.statSync(p);
          return true;
        } catch {
          return false;
        }
      });
      let canonBase = base;
      try {
        canonBase = fs.realpathSync(base);
      } catch {
        // keep the literal base
      }
      const mountinfo = fs.readFileSync("/proc/self/mountinfo", "utf8");
      if (isNoexecPath(mountinfo, canonBase + dir.slice(base.length))) {
        return {
          ok: false,
          reason: `landlock helper cache dir is mounted noexec: ${path.dirname(out)} — set "landlockHelper" to an exec-capable path`,
        };
      }
    } catch {
      // mountinfo unreadable (odd container); the canary below will surface
      // any exec failure.
    }
    // Source integrity: refuse to compile unexpected code.
    try {
      const digest = crypto
        .createHash("sha256")
        .update(fs.readFileSync(HELPER_SOURCE))
        .digest("hex");
      if (digest !== HELPER_SOURCE_SHA256) {
        return {
          ok: false,
          reason: `landlock-helper.c failed the integrity check (sha256 ${digest.slice(0, 12)}\u2026 \u2260 expected) — refusing to compile; restore the pristine source or set "landlockHelper" to a trusted prebuilt binary`,
        };
      }
    } catch (err) {
      return { ok: false, reason: `landlock helper source unreadable: ${String(err)}` };
    }
    try {
      fs.mkdirSync(path.dirname(out), { recursive: true });
      const srcStat = fs.statSync(HELPER_SOURCE);
      const stale = !fs.existsSync(out) || fs.statSync(out).mtimeMs < srcStat.mtimeMs;
      if (stale) {
        const build = spawnSync(cc, ["-O2", "-o", out, HELPER_SOURCE], {
          encoding: "utf8",
          timeout: BUILD_TIMEOUT_MS,
        });
        if (build.status !== 0) {
          return {
            ok: false,
            reason: `landlock helper build failed: ${(build.stderr ?? "").trim().slice(-300)}`,
          };
        }
        fs.chmodSync(out, 0o700);
      }
    } catch (err) {
      return { ok: false, reason: `landlock helper build failed: ${String(err)}` };
    }
  }
  const canary = spawnSync(out, ["--rw", "/tmp", "--", "/bin/sh", "-c", "true"], {
    encoding: "utf8",
    timeout: CANARY_TIMEOUT_MS,
  });
  if (canary.status === 0) return { ok: true, runner: "landlock", detail: out, helperPath: out };
  return {
    ok: false,
    reason: `landlock canary failed${canary.status != null ? ` (exit ${canary.status})` : ""}: ${
      (canary.stderr ?? "").trim() || "kernel may not support Landlock (need >= 5.13)"
    }`,
  };
}

/**
 * sandbox-exec: run a real canary, like the bwrap/Landlock probes. A
 * presence-only check let broken profiles through (invalid SBPL, see #43) and
 * then failed EVERY command at runtime instead of degrading to gate-only.
 * The canary proves the generated profile parses and the write boundary
 * holds: write inside the root OK, write outside denied.
 */
function probeSandboxExec(): RunnerProbeResult {
  const bin = which("sandbox-exec");
  if (!bin) return { ok: false, reason: "sandbox-exec not found (macOS only)" };
  let parent: string | undefined;
  try {
    parent = fs.mkdtempSync(path.join(os.tmpdir(), "pi-sandbox-exec-probe-"));
    // Seatbelt matches subpaths against CANONICAL paths; mkdtemp under
    // $TMPDIR may be a symlinked form (/var/folders -> /private/var/folders).
    // mkdir FIRST: realpath(3) requires the path to exist.
    const canaryDirRaw = path.join(parent, "canary");
    fs.mkdirSync(canaryDirRaw);
    const canaryDir = fs.realpathSync(canaryDirRaw);
    const canaryFile = path.join(canaryDir, "canary");
    const outside = path.join(parent, "outside.txt");
    // Baseline: the outside target must be writable WITHOUT the sandbox, so
    // a later denial is attributable to the sandbox, not file permissions.
    const baseline = spawnSync("/bin/sh", ["-c", `touch ${shellQuote(outside)}`], {
      encoding: "utf8",
      timeout: CANARY_TIMEOUT_MS,
    });
    if (baseline.status !== 0) {
      return {
        ok: false,
        reason: `sandbox-exec canary setup failed: outside target not writable (${(
          baseline.stderr ?? ""
        ).trim()})`,
      };
    }
    const profile = buildSeatbeltProfile({ writableRoots: [canaryDir], network: "allow" });
    const write = spawnSync(
      bin,
      [
        "-p",
        profile,
        "/bin/sh",
        "-c",
        `printf ok > ${shellQuote(canaryFile)} && cat ${shellQuote(canaryFile)}`,
      ],
      { encoding: "utf8", timeout: CANARY_TIMEOUT_MS },
    );
    if (write.status !== 0 || !write.stdout.includes("ok")) {
      return {
        ok: false,
        reason: `sandbox-exec canary failed (exit ${write.status ?? "?"}): ${
          (write.stderr ?? "").trim() || "profile rejected or write boundary broken"
        }`,
      };
    }
    const denied = spawnSync(
      bin,
      ["-p", profile, "/bin/sh", "-c", `touch ${shellQuote(outside)} && echo SHOULD_BE_DENIED`],
      { encoding: "utf8", timeout: CANARY_TIMEOUT_MS },
    );
    if (denied.status === null) {
      return { ok: false, reason: "sandbox-exec canary timed out on the denied-write check" };
    }
    if (denied.status === 0) {
      return {
        ok: false,
        reason:
          "sandbox-exec canary: write outside the writable roots was NOT denied (boundary broken)",
      };
    }
    return { ok: true, runner: "sandbox-exec", detail: bin };
  } catch (err) {
    return { ok: false, reason: `sandbox-exec canary setup failed: ${String(err)}` };
  } finally {
    if (parent) {
      try {
        fs.rmSync(parent, { recursive: true, force: true });
      } catch {
        // cleanup failure must not override the probe result
      }
    }
  }
}

export type RunnerProbeOptions = {
  /** Prebuilt Landlock helper path (sandbox.json "landlockHelper"). */
  landlockHelper?: string;
};

export function resolveRunner(
  choice: SandboxRunnerChoice,
  opts: RunnerProbeOptions = {},
): RunnerProbeResult {
  if (choice === "none") return { ok: false, reason: 'runner is set to "none"' };

  if (process.platform === "darwin") {
    if (choice === "bwrap" || choice === "landlock") {
      return { ok: false, reason: `${choice} is not available on macOS` };
    }
    return probeSandboxExec();
  }

  if (process.platform === "linux") {
    if (choice === "sandbox-exec") return { ok: false, reason: "sandbox-exec is macOS-only" };
    if (choice === "bwrap") return probeBwrap();
    if (choice === "landlock") return probeLandlock(opts.landlockHelper);
    // auto: bwrap first (stronger isolation), landlock as fallback
    const bwrap = probeBwrap();
    if (bwrap.ok) return bwrap;
    const landlock = probeLandlock(opts.landlockHelper);
    if (landlock.ok) return landlock;
    return {
      ok: false,
      reason: `no usable runner: bwrap: ${bwrap.ok ? "" : bwrap.reason}; landlock: ${landlock.ok ? "" : landlock.reason}`,
    };
  }

  return { ok: false, reason: `unsupported platform: ${process.platform}` };
}
