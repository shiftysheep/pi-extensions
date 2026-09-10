/**
 * Unit tests for the pure sandbox helpers in extensions/lib/sandbox-utils.ts.
 * Run with `npm test` (node --test via tsx).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  applySandboxToggle,
  buildSeatbeltProfile,
  buildWritableRoots,
  canonicalizeTarget,
  isInsideAnyRoot,
  isInsideRoot,
  mergeSandboxConfigs,
  normalizeSandboxPath,
  parseSandboxConfig,
  parseWritableList,
  type RunnerContext,
  resolveExistingRoot,
  type SandboxConfig,
  sandboxConfigPath,
  sbplQuote,
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
  "/home/u/.cache",
  "/home/u/.npm",
  "/home/u/.cargo",
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
        homeCaches: "ro",
        network: "deny",
        userCommands: true,
        loginShell: false,
      },
      P,
    );
    assert.equal(cfg.enabled, true);
    assert.equal(cfg.runner, "landlock");
    assert.equal(cfg.home, "rw");
    assert.equal(cfg.homeCaches, "ro");
    assert.equal(cfg.network, "deny");
    assert.equal(cfg.userCommands, true);
    assert.equal(cfg.loginShell, false);
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
    assert.throws(() => parseSandboxConfig({ homeCaches: "maybe" }, P), /"homeCaches" must be/);
    assert.throws(() => parseSandboxConfig({ network: "sometimes" }, P), /"network" must be/);
    assert.throws(() => parseSandboxConfig({ loginShell: "yes" }, P), /"loginShell" must be/);
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
  it("adds existing $HOME cache dirs by default (homeCaches rw)", () => {
    const roots = buildWritableRoots({}, CTX, exists);
    assert.ok(roots.includes("/home/u/.cache"));
    assert.ok(roots.includes("/home/u/.npm"));
    assert.ok(roots.includes("/home/u/.cargo"));
    assert.ok(!roots.includes("/home/u")); // $HOME itself still ro
  });
  it("skips a missing cache dir instead of walking up to $HOME", () => {
    // /home/u/.rustup is NOT in FS; it must be skipped, not resolved to /home/u.
    const roots = buildWritableRoots({}, CTX, exists);
    assert.ok(!roots.includes("/home/u/.rustup"));
    assert.ok(!roots.includes("/home/u")); // no silent $HOME write access
  });
  it("omits $HOME cache dirs when homeCaches is ro", () => {
    const roots = buildWritableRoots({ homeCaches: "ro" }, CTX, exists);
    assert.ok(!roots.includes("/home/u/.cache"));
    assert.ok(!roots.includes("/home/u/.npm"));
    assert.ok(!roots.includes("/home/u/.cargo"));
  });
  it("drops cache dirs subsumed by home rw", () => {
    const roots = buildWritableRoots({ home: "rw" }, CTX, exists);
    assert.ok(roots.includes("/home/u"));
    assert.ok(!roots.includes("/home/u/.cache")); // subsumed by /home/u
  });
  it("canonicalizes symlinked roots (macOS /tmp -> /private/tmp)", () => {
    const REALPATH: Record<string, string> = {
      "/tmp": "/private/tmp",
      "/tmp/scratch": "/private/tmp/scratch",
      "/dev": "/some/dev", // even if /dev were a symlink, it stays literal
      "/var/scratch": "/private/var/scratch",
      "/var/folders/xx/T": "/private/var/folders/xx/T",
    };
    const fs2 = new Set(FS).add("/tmp/scratch").add("/var/scratch").add("/var/folders/xx/T");
    const roots = buildWritableRoots(
      { writable: ["/tmp/scratch", "/var/scratch"] },
      { ...CTX, tmpDir: "/var/folders/xx/T" },
      (p) => fs2.has(p),
      (p) => REALPATH[p] ?? p,
    );
    assert.ok(roots.includes("/private/tmp")); // system root canonicalized
    assert.ok(!roots.includes("/tmp")); // literal symlink form never emitted
    // configured paths canonicalized; /tmp/scratch subsumed by /private/tmp
    assert.ok(!roots.includes("/tmp/scratch"));
    assert.ok(!roots.includes("/private/tmp/scratch"));
    assert.ok(roots.includes("/private/var/scratch"));
    assert.ok(!roots.includes("/var/scratch"));
    assert.ok(roots.includes("/private/var/folders/xx/T")); // $TMPDIR added, canonicalized
    assert.ok(roots.includes("/dev")); // device root stays literal (bwrap --dev)
    assert.ok(!roots.includes("/some/dev"));
  });
  it("skips a $TMPDIR that canonicalizes to /", () => {
    const roots = buildWritableRoots(
      {},
      { ...CTX, tmpDir: "/var/folders/root" },
      (p) => FS.has(p) || p === "/var/folders/root",
      (p) => (p === "/var/folders/root" ? "/" : p),
    );
    assert.ok(!roots.includes("/"));
  });
  it("omits $TMPDIR when ctx.tmpDir is unset", () => {
    const roots = buildWritableRoots({}, CTX, exists);
    assert.ok(!roots.some((r) => r.includes("/var/folders")));
  });
  it("skips a missing $TMPDIR instead of walking up to /", () => {
    const roots = buildWritableRoots({}, { ...CTX, tmpDir: "/var/folders/gone" }, exists);
    assert.ok(!roots.includes("/"));
    assert.ok(!roots.some((r) => r.includes("/var/folders")));
  });
});

describe("canonicalizeTarget", () => {
  const REALPATH: Record<string, string> = { "/tmp": "/private/tmp" };
  const rp = (p: string) => REALPATH[p] ?? p;
  it("canonicalizes via the deepest existing ancestor", () => {
    assert.equal(canonicalizeTarget("/tmp/file.txt", exists, rp), "/private/tmp/file.txt");
  });
  it("appends the missing tail for new files", () => {
    assert.equal(
      canonicalizeTarget("/home/u/proj/sub/new/f.txt", exists, rp),
      "/home/u/proj/sub/new/f.txt",
    );
  });
  it("canonicalizes an existing directory target", () => {
    assert.equal(canonicalizeTarget("/tmp", exists, rp), "/private/tmp");
  });
  it("falls back to the literal path when nothing exists", () => {
    assert.equal(canonicalizeTarget("/nope/way/nope/f", exists, rp), "/nope/way/nope/f");
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
    loginShell: true,
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
  it("uses fresh --tmpfs /tmp and --proc /proc instead of rw host binds", () => {
    const cmd = wrapWithBwrap("ls", policy, CTX);
    assert.ok(cmd.includes("--tmpfs /tmp"));
    assert.ok(cmd.includes("--proc /proc"));
    assert.ok(!cmd.includes("--bind '/tmp'"));
    assert.ok(!cmd.includes("--bind '/proc'"));
    // --proc must come after the pid namespace is unshared
    assert.ok(cmd.indexOf("--unshare-pid") < cmd.indexOf("--proc /proc"));
  });
  it("omits --tmpfs/--proc when /tmp and /proc are not roots", () => {
    const cmd = wrapWithBwrap(
      "ls",
      { writableRoots: ["/home/u/proj"], network: "allow", loginShell: true },
      CTX,
    );
    assert.ok(!cmd.includes("--tmpfs"));
    assert.ok(!cmd.includes("--proc"));
  });
  it("keeps network when allow", () => {
    const cmd = wrapWithBwrap("ls", { ...policy, network: "allow" }, CTX);
    assert.ok(!cmd.includes("--unshare-net"));
  });
  it("uses -c when loginShell is false", () => {
    const cmd = wrapWithBwrap("ls", { ...policy, loginShell: false }, CTX);
    assert.ok(cmd.endsWith("-- /bin/bash -c 'ls'"));
  });
});

describe("wrapWithLandlock", () => {
  it("passes rw roots and the helper path", () => {
    const policy = {
      writableRoots: ["/home/u/proj", "/tmp"],
      network: "allow" as const,
      loginShell: true,
    };
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
  it("uses -c when loginShell is false", () => {
    const cmd = wrapWithLandlock(
      "ls",
      { writableRoots: ["/tmp"], network: "allow", loginShell: false },
      CTX,
    );
    assert.ok(cmd.endsWith("-- /bin/bash -c 'ls'"));
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
    assert.ok(profile.includes('(subpath "/Users/u/proj")'));
    assert.ok(!profile.includes("network-outbound"));
  });
  it("uses SBPL double-quoted strings, never shell single quotes", () => {
    const profile = buildSeatbeltProfile({
      writableRoots: ["/Users/u/proj", "/tmp"],
      network: "allow",
    });
    assert.ok(profile.includes('(subpath "/Users/u/proj")'));
    assert.ok(profile.includes('(subpath "/tmp")'));
    assert.ok(!profile.includes("'"));
  });
  it("allows network when policy allows", () => {
    const profile = buildSeatbeltProfile({ writableRoots: ["/tmp"], network: "allow" });
    assert.ok(profile.includes("network-outbound"));
  });
  it("emits no file-write rule for empty writable roots (deny-all writes)", () => {
    const profile = buildSeatbeltProfile({ writableRoots: [], network: "deny" });
    assert.ok(!profile.includes("file-write"));
  });
  it("handles special characters in roots", () => {
    const profile = buildSeatbeltProfile({
      writableRoots: ['/spaced "dir"', "/back\\slash"],
      network: "deny",
    });
    assert.ok(profile.includes('(subpath "/spaced \\"dir\\"")'));
    assert.ok(profile.includes('(subpath "/back\\\\slash")'));
  });
  it("grants /dev as specific device literals, not a subpath", () => {
    const profile = buildSeatbeltProfile({ writableRoots: ["/tmp", "/dev"], network: "deny" });
    assert.ok(!profile.includes('(subpath "/dev")'));
    assert.ok(profile.includes('(allow file-write-data (literal "/dev/null")'));
    assert.ok(profile.includes('(literal "/dev/stdout")'));
    assert.ok(profile.includes('(literal "/dev/stderr")'));
    assert.ok(profile.includes('(literal "/dev/tty")'));
    assert.ok(profile.includes('(subpath "/tmp")'));
  });
  it("emits no device grants when /dev is not a root", () => {
    const profile = buildSeatbeltProfile({ writableRoots: ["/tmp"], network: "deny" });
    assert.ok(!profile.includes("file-write-data"));
  });
  it("/dev-only roots still emit the device grants", () => {
    const profile = buildSeatbeltProfile({ writableRoots: ["/dev"], network: "deny" });
    assert.ok(!profile.includes("file-write*"));
    assert.ok(profile.includes("file-write-data"));
  });
});

describe("sbplQuote", () => {
  it("double-quotes and escapes backslashes and double quotes", () => {
    assert.equal(sbplQuote("/tmp"), '"/tmp"');
    assert.equal(sbplQuote('/weird"path'), '"/weird\\"path"');
    assert.equal(sbplQuote("/back\\slash"), '"/back\\\\slash"');
  });
});

describe("wrapWithSandboxExec", () => {
  it("embeds the profile inline (no -- separator)", () => {
    const cmd = wrapWithSandboxExec(
      "ls",
      { writableRoots: ["/tmp"], network: "allow", loginShell: true },
      CTX,
    );
    assert.ok(cmd.startsWith("sandbox-exec -p '"));
    assert.ok(cmd.includes("(version 1)"));
    assert.ok(cmd.endsWith("/bin/bash -lc 'ls'"));
    assert.ok(!cmd.includes(" -- "));
  });
  it("uses -c when loginShell is false", () => {
    const cmd = wrapWithSandboxExec(
      "ls",
      { writableRoots: ["/tmp"], network: "allow", loginShell: false },
      CTX,
    );
    assert.ok(cmd.endsWith("/bin/bash -c 'ls'"));
  });
});

describe("wrapCommand dispatch", () => {
  const policy = { writableRoots: ["/tmp"], network: "allow" as const, loginShell: true };
  it("routes to each runner", () => {
    assert.ok(wrapCommand("bwrap", "ls", policy, CTX).startsWith("bwrap "));
    assert.ok(wrapCommand("landlock", "ls", policy, CTX).includes("--rw '/tmp'"));
    assert.ok(wrapCommand("sandbox-exec", "ls", policy, CTX).startsWith("sandbox-exec "));
  });
  it("throws on unknown runner", () => {
    assert.throws(
      () => wrapCommand("docker" as never, "ls", policy, CTX),
      /unknown sandbox runner/,
    );
  });
});

describe("sandboxConfigPath", () => {
  const paths = { agentDir: "/home/u/.pi/agent", projectDir: "/home/u/proj/.pi" };
  it("global maps under the agent dir", () => {
    assert.equal(sandboxConfigPath("global", paths), "/home/u/.pi/agent/sandbox.json");
  });
  it("project maps under the project .pi dir", () => {
    assert.equal(sandboxConfigPath("project", paths), "/home/u/proj/.pi/sandbox.json");
  });
});

describe("mergeSandboxConfigs", () => {
  it("returns global when project is empty", () => {
    const merged = mergeSandboxConfigs({ enabled: true, runner: "bwrap" }, {});
    assert.deepEqual(merged, { enabled: true, runner: "bwrap" });
  });
  it("project keys override global per-key", () => {
    const merged = mergeSandboxConfigs(
      { enabled: true, runner: "bwrap", network: "deny", home: "rw" },
      { enabled: false, network: "allow" },
    );
    assert.equal(merged.enabled, false); // project wins
    assert.equal(merged.network, "allow"); // project wins
    assert.equal(merged.runner, "bwrap"); // falls back to global
    assert.equal(merged.home, "rw"); // falls back to global
  });
  it("does not mutate its inputs", () => {
    const g = { enabled: true };
    const p = { network: "deny" as const };
    mergeSandboxConfigs(g, p);
    assert.deepEqual(g, { enabled: true });
    assert.deepEqual(p, { network: "deny" });
  });
  it("project can re-enable a globally-disabled sandbox", () => {
    const merged = mergeSandboxConfigs({ enabled: false }, { enabled: true });
    assert.equal(merged.enabled, true);
  });
  it("project writable: [] overrides a non-empty global list (empty is defined)", () => {
    const merged = mergeSandboxConfigs({ writable: ["~/g"] }, { writable: [] });
    assert.deepEqual(merged.writable, []);
  });
});

describe("applySandboxToggle", () => {
  it("on with no runner defaults runner to auto", () => {
    assert.deepEqual(applySandboxToggle({}, true), { enabled: true, runner: "auto" });
  });
  it("on keeps an inherited explicit runner instead of defaulting to auto", () => {
    assert.deepEqual(applySandboxToggle({}, true, "bwrap"), { enabled: true, runner: "bwrap" });
    assert.deepEqual(applySandboxToggle({}, true, "none"), { enabled: true, runner: "none" });
  });
  it("on keeps this scope's own runner over the inherited one", () => {
    assert.deepEqual(applySandboxToggle({ runner: "landlock" }, true, "bwrap"), {
      enabled: true,
      runner: "landlock",
    });
  });
  it("on keeps an explicit runner", () => {
    assert.deepEqual(applySandboxToggle({ runner: "bwrap" }, true), {
      enabled: true,
      runner: "bwrap",
    });
  });
  it("on preserves other options", () => {
    assert.deepEqual(applySandboxToggle({ network: "deny", home: "rw" }, true), {
      network: "deny",
      home: "rw",
      enabled: true,
      runner: "auto",
    });
  });
  it("off sets enabled false and keeps the rest", () => {
    assert.deepEqual(applySandboxToggle({ enabled: true, runner: "landlock" }, false), {
      enabled: false,
      runner: "landlock",
    });
  });
  it("does not mutate its input", () => {
    const cfg: SandboxConfig = { runner: "bwrap" };
    applySandboxToggle(cfg, true);
    assert.deepEqual(cfg, { runner: "bwrap" });
  });
});

describe("parseWritableList", () => {
  it("splits, trims, and drops empties", () => {
    assert.deepEqual(parseWritableList("~/a, ~/b , c/"), ["~/a", "~/b", "c/"]);
  });
  it("returns [] for blank input", () => {
    assert.deepEqual(parseWritableList(""), []);
    assert.deepEqual(parseWritableList("  ,,  "), []);
  });
  it("single unquoted path", () => {
    assert.deepEqual(parseWritableList("/tmp/x"), ["/tmp/x"]);
  });
});
