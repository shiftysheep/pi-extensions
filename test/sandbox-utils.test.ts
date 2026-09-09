/**
 * Unit tests for the pure sandbox helpers in extensions/lib/sandbox-utils.ts.
 * Run with `npm test` (node --test via tsx).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildSeatbeltProfile,
  buildWritableRoots,
  isInsideAnyRoot,
  isInsideRoot,
  normalizeSandboxPath,
  parseSandboxConfig,
  type RunnerContext,
  resolveExistingRoot,
  type SandboxConfig,
  shellQuote,
  wrapCommand,
  wrapWithBwrap,
  wrapWithLandlock,
  wrapWithSandboxExec,
} from "../extensions/lib/sandbox-utils.js";

const CTX: RunnerContext = { cwd: "/home/u/proj", homeDir: "/home/u", shellPath: "/bin/bash" };
const FS = new Set([
  "/home/u/proj",
  "/home/u",
  "/tmp",
  "/dev",
  "/proc",
  "/etc",
  "/home/u/proj/sub",
]);
const exists = (p: string) => FS.has(p);

describe("parseSandboxConfig", () => {
  const P = "/agent/sandbox.json";
  it("accepts an empty object", () => {
    assert.deepEqual(parseSandboxConfig({}, P), {});
  });
  it("accepts a full valid config", () => {
    const cfg = parseSandboxConfig(
      {
        enabled: true,
        runner: "landlock",
        writable: ["~/cache", "data/"],
        home: "rw",
        network: "deny",
        userCommands: true,
      },
      P,
    );
    assert.equal(cfg.enabled, true);
    assert.equal(cfg.runner, "landlock");
    assert.equal(cfg.home, "rw");
    assert.equal(cfg.network, "deny");
    assert.equal(cfg.userCommands, true);
  });
  it("rejects non-objects", () => {
    assert.throws(() => parseSandboxConfig(null, P), /expected a JSON object/);
    assert.throws(() => parseSandboxConfig([], P), /expected a JSON object/);
  });
  it("rejects unknown keys", () => {
    assert.throws(() => parseSandboxConfig({ bogus: 1 }, P), /unknown key "bogus"/);
  });
  it("rejects bad types", () => {
    assert.throws(() => parseSandboxConfig({ enabled: "yes" }, P), /"enabled" must be a boolean/);
    assert.throws(() => parseSandboxConfig({ runner: "docker" }, P), /"runner" must be one of/);
    assert.throws(() => parseSandboxConfig({ writable: ["a", 2] }, P), /"writable" must be/);
    assert.throws(() => parseSandboxConfig({ home: "maybe" }, P), /"home" must be/);
    assert.throws(() => parseSandboxConfig({ network: "sometimes" }, P), /"network" must be/);
  });
});

describe("shellQuote", () => {
  it("wraps in single quotes", () => {
    assert.equal(shellQuote("ls -la"), "'ls -la'");
  });
  it("escapes embedded single quotes", () => {
    assert.equal(shellQuote("echo 'hi'"), `'echo '\\''hi'\\'''`);
  });
  it("round-trips through a real shell", async () => {
    const { execFileSync } = await import("node:child_process");
    const tricky = 'it\'s a "test" with $vars && and | pipes; and `backticks`';
    const out = execFileSync("/bin/sh", ["-c", `printf %s ${shellQuote(tricky)}`]);
    assert.equal(out.toString(), tricky);
  });
});

describe("normalizeSandboxPath", () => {
  it("expands ~ and ~/", () => {
    assert.equal(normalizeSandboxPath("~", CTX), "/home/u");
    assert.equal(normalizeSandboxPath("~/cache", CTX), "/home/u/cache");
  });
  it("resolves relative paths against cwd", () => {
    assert.equal(normalizeSandboxPath("data/out", CTX), "/home/u/proj/data/out");
  });
  it("keeps absolute paths", () => {
    assert.equal(normalizeSandboxPath("/etc", CTX), "/etc");
  });
});

describe("resolveExistingRoot", () => {
  it("returns the path when it exists", () => {
    assert.equal(resolveExistingRoot("/home/u/proj/sub", exists), "/home/u/proj/sub");
  });
  it("walks up to the deepest existing ancestor", () => {
    assert.equal(resolveExistingRoot("/home/u/proj/sub/new/deeper", exists), "/home/u/proj/sub");
  });
  it("falls back to /", () => {
    assert.equal(resolveExistingRoot("/nope/way/nope", exists), "/");
  });
});

describe("buildWritableRoots", () => {
  it("includes cwd, system roots, and dedupes subsumed paths", () => {
    const roots = buildWritableRoots({}, CTX, exists);
    assert.ok(roots.includes("/home/u/proj"));
    assert.ok(roots.includes("/tmp"));
    assert.ok(roots.includes("/dev"));
    assert.ok(roots.includes("/proc"));
    assert.ok(!roots.includes("/home/u")); // home ro by default
  });
  it("adds HOME when rw", () => {
    const roots = buildWritableRoots({ home: "rw" }, CTX, exists);
    assert.ok(roots.includes("/home/u"));
    // cwd is subsumed by HOME and dropped
    assert.ok(!roots.includes("/home/u/proj"));
  });
  it("adds configured writable paths (expanded, ancestor-resolved)", () => {
    const roots = buildWritableRoots({ writable: ["~/cache", "data/new"] }, CTX, exists);
    assert.ok(roots.includes("/home/u")); // ~/cache -> ancestor /home/u
    assert.ok(!roots.includes("/home/u/proj/data/new")); // doesn't exist
  });
});

describe("path containment", () => {
  it("isInsideRoot matches root and descendants, not siblings", () => {
    assert.ok(isInsideRoot("/home/u/proj", "/home/u/proj"));
    assert.ok(isInsideRoot("/home/u/proj/a/b", "/home/u/proj"));
    assert.ok(!isInsideRoot("/home/u/proj2", "/home/u/proj"));
    assert.ok(!isInsideRoot("/home/u", "/home/u/proj"));
  });
  it("isInsideAnyRoot matches any root", () => {
    assert.ok(isInsideAnyRoot("/tmp/x", ["/home/u/proj", "/tmp"]));
    assert.ok(!isInsideAnyRoot("/etc/passwd", ["/home/u/proj", "/tmp"]));
  });
});

describe("wrapWithBwrap", () => {
  const policy = {
    writableRoots: ["/home/u/proj", "/tmp", "/dev", "/proc"],
    network: "deny" as const,
  };
  it("ro-binds / first, binds rw roots, unshares net/user/pid", () => {
    const cmd = wrapWithBwrap("ls -la", policy, CTX);
    assert.ok(cmd.startsWith("bwrap --ro-bind / / "));
    assert.ok(cmd.includes(`--bind '/home/u/proj' '/home/u/proj'`));
    assert.ok(cmd.includes("--dev /dev"));
    assert.ok(cmd.includes("--unshare-net"));
    assert.ok(cmd.includes("--unshare-user --unshare-pid"));
    assert.ok(cmd.endsWith(`-- /bin/bash -lc 'ls -la'`));
  });
  it("keeps network when allow", () => {
    const cmd = wrapWithBwrap("ls", { ...policy, network: "allow" }, CTX);
    assert.ok(!cmd.includes("--unshare-net"));
  });
});

describe("wrapWithLandlock", () => {
  it("passes rw roots and the helper path", () => {
    const policy = { writableRoots: ["/home/u/proj", "/tmp"], network: "allow" as const };
    const cmd = wrapWithLandlock("ls", policy, {
      ...CTX,
      helperPath: "/home/u/.cache/pi-sandbox-landlock",
    });
    assert.ok(
      cmd.startsWith(
        "'/home/u/.cache/pi-sandbox-landlock' --rw '/home/u/proj' --rw '/tmp' -- /bin/bash -lc 'ls'",
      ),
    );
  });
});

describe("buildSeatbeltProfile", () => {
  it("is deny-by-default with rw subpaths and network gating", () => {
    const profile = buildSeatbeltProfile({
      writableRoots: ["/Users/u/proj", "/tmp"],
      network: "deny",
    });
    assert.ok(profile.includes("(deny default)"));
    assert.ok(profile.includes("(allow file-read*)"));
    assert.ok(profile.includes("(subpath '/Users/u/proj')"));
    assert.ok(!profile.includes("network-outbound"));
  });
  it("allows network when policy allows", () => {
    const profile = buildSeatbeltProfile({ writableRoots: ["/tmp"], network: "allow" });
    assert.ok(profile.includes("network-outbound"));
  });
});

describe("wrapWithSandboxExec", () => {
  it("embeds the profile inline (no -- separator)", () => {
    const cmd = wrapWithSandboxExec("ls", { writableRoots: ["/tmp"], network: "allow" }, CTX);
    assert.ok(cmd.startsWith("sandbox-exec -p '"));
    assert.ok(cmd.includes("(version 1)"));
    assert.ok(cmd.endsWith("/bin/bash -lc 'ls'"));
    assert.ok(!cmd.includes(" -- "));
  });
});

describe("wrapCommand dispatch", () => {
  const policy = { writableRoots: ["/tmp"], network: "allow" as const };
  const cfg: SandboxConfig = {};
  it("routes to each runner", () => {
    assert.ok(wrapCommand("bwrap", "ls", policy, CTX).startsWith("bwrap "));
    assert.ok(wrapCommand("landlock", "ls", policy, CTX).includes("--rw '/tmp'"));
    assert.ok(wrapCommand("sandbox-exec", "ls", policy, CTX).startsWith("sandbox-exec "));
    void cfg;
  });
  it("throws on unknown runner", () => {
    assert.throws(
      () => wrapCommand("docker" as never, "ls", policy, CTX),
      /unknown sandbox runner/,
    );
  });
});
