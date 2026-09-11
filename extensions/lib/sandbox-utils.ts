/**
 * Pure helpers for the permission-gate sandbox: sandbox.json config parsing,
 * policy building, per-runner command wrapping (bubblewrap, Landlock helper,
 * macOS sandbox-exec/Seatbelt), shell quoting, and path-containment checks.
 *
 * Kept free of pi imports, fs, and side effects so they can be unit-tested
 * without a live session or a working sandbox runner.
 */

export const SANDBOX_RUNNERS = ["bwrap", "landlock", "sandbox-exec"] as const;
export type SandboxRunner = (typeof SANDBOX_RUNNERS)[number];
export type SandboxRunnerChoice = "auto" | SandboxRunner | "none";
export const SANDBOX_RUNNER_CHOICES = ["auto", "none", ...SANDBOX_RUNNERS] as const;

/** Config file scopes: global (~/.pi/agent) or project (<cwd>/.pi). */
export type SandboxScope = "global" | "project";

export const SANDBOX_ALLOWED_KEYS = [
  "enabled",
  "runner",
  "writable",
  "home",
  "homeCaches",
  "network",
  "userCommands",
  "loginShell",
  "landlockHelper",
  "failIfUnavailable",
  "blockTerminates",
] as const;

/**
 * $HOME-relative cache/tool dirs made writable when homeCaches: "rw"
 * (opt-in) so common dev tooling works out of the box: XDG cache
 * (pre-commit, pip, uv, virtualenv, huggingface, …), package-manager caches,
 * and tool install locations. Default is "ro": several of these dirs can
 * hold credentials or executable shims (.cargo, .gem, .m2, .local/bin), and
 * a silently-writable toolchain is a supply-chain risk. Deliberately
 * excludes credential/config dirs (.ssh, .aws, .gnupg, .config).
 * Home-relative so they track $HOME; extended in buildWritableRoots only
 * for dirs that already exist (a missing dir is skipped, never walked up
 * to $HOME).
 */
export const HOME_CACHE_ROOTS = [
  ".cache",
  ".npm",
  ".pnpm-store",
  ".yarn",
  ".bun",
  ".cargo",
  ".rustup",
  ".gem",
  ".m2",
  ".gradle",
  ".ivy2",
  ".nvm",
  ".volta",
  ".asdf",
  ".pyenv",
  ".rbenv",
  ".rvm",
  ".gvm",
  ".sdkman",
  ".local/share/uv",
  ".local/bin",
] as const;

export type SandboxConfig = {
  /** Master switch. Default: disabled (gate behaves exactly as before). */
  enabled?: boolean;
  /** Which runner to use. Default: "auto" (platform/probe-based). */
  runner?: SandboxRunnerChoice;
  /** Extra writable paths ("~" expands, relative = cwd-relative). */
  writable?: string[];
  /** Access to $HOME. Default: "ro". */
  home?: "rw" | "ro";
  /** Writable $HOME cache/tool dirs (HOME_CACHE_ROOTS). Default: "ro" (these
   * dirs can hold credentials/executables). Set "rw" to let common dev
   * tooling write to them. */
  homeCaches?: "rw" | "ro";
  /** Network policy. Default: "allow". Enforced by bwrap/seatbelt; a no-op
   * (with a warning) on landlock, which cannot restrict networks. */
  network?: "allow" | "deny";
  /** Also sandbox user `!` commands. Default: false. */
  userCommands?: boolean;
  /**
   * Run sandboxed commands in a LOGIN shell (`bash -lc`, sources
   * /etc/profile + ~/.bash_profile) vs a plain non-login shell (`bash -c`).
   * Default: true (preserves the historical behavior and login-profile env).
   * Note: `bash -c` still honors an inherited BASH_ENV.
   */
  loginShell?: boolean;
  /**
   * Explicit path to a prebuilt Landlock helper binary. When set, the
   * helper is used as-is and NO compilation happens (an explicit override
   * is a directive, not a hint — a missing file fails the probe instead
   * of falling back to a build). Linux/landlock only.
   */
  landlockHelper?: string;
  /**
   * Fail CLOSED when the sandbox is enabled but no runner can be resolved:
   * bash/powershell/write/edit are BLOCKED instead of running unsandboxed
   * with a warning (the default, fail-open, suits interactive/dev use).
   * For enforced/fleet adoption.
   */
  failIfUnavailable?: boolean;
  /**
   * When the gate BLOCKS a call (declined confirm, no UI, hard deny,
   * fail-closed), set the early-termination hint so the agent's turn stops
   * after the current tool batch. Default: false — the block reason is
   * returned to the model as a tool error and the turn CONTINUES, so the
   * model can read the reason and adapt instead of the turn dying.
   */
  blockTerminates?: boolean;
};

export type SandboxPolicy = {
  /** Absolute writable roots (deduped, existing). Everything else is read-only. */
  writableRoots: string[];
  network: "allow" | "deny";
  /** Login shell (`-lc`) vs plain `-c` for the wrapped command. */
  loginShell: boolean;
};

/** Effective sandbox state after config + runner probing. */
export type SandboxState =
  | { active: false; enabled: false }
  | {
      active: false;
      enabled: true;
      reason: string;
      /** failIfUnavailable: commands are BLOCKED, not run unsandboxed. */
      failClosed?: boolean;
    }
  | {
      active: true;
      enabled: true;
      runner: "bwrap" | "landlock" | "sandbox-exec";
      policy: SandboxPolicy;
      helperPath?: string;
      /** false when network=deny is requested but the runner cannot enforce it (landlock). */
      networkEnforced: boolean;
    };

/** Compact identity of a SandboxState, used to detect changes between turns.
 * Active states include the writable roots and network enforcement so
 * policy-only edits are noticed, not just runner changes. */
export function sandboxStateSignature(state: SandboxState): string {
  if (state.active)
    return `active:${state.runner}:${state.policy.writableRoots.join(",")}:net=${state.policy.network}${state.networkEnforced ? "" : "-unenforced"}`;
  if (!state.enabled) return "off";
  return state.failClosed ? "failclosed" : "enabled-unavailable";
}

/** One-line human/model-readable description of the effective sandbox state. */
export function describeSandboxState(state: SandboxState): string {
  if (state.active) {
    const network =
      state.policy.network !== "deny"
        ? "allowed"
        : state.networkEnforced
          ? "denied"
          : "deny requested but NOT enforced";
    return `ACTIVE (${state.runner}): writes only inside ${state.policy.writableRoots.join(", ")}; network ${network}`;
  }
  if (!state.enabled) return "DISABLED: no filesystem restrictions";
  return `enabled but no runner available${state.failClosed ? "; affected commands are BLOCKED" : "; commands run UNSANDBOXED"}`;
}

export type RunnerContext = {
  cwd: string;
  homeDir: string;
  shellPath: string;
  /** landlock runner only: path to the compiled helper binary. */
  helperPath?: string;
  /**
   * Platform temp dir ($TMPDIR on macOS: /var/folders/...). Added to the
   * writable roots when set; canonical resolution of /tmp alone misses it.
   */
  tmpDir?: string;
};

/**
 * Validate parsed sandbox.json. Mirrors advisor's parseConfig: unknown keys
 * and wrong types are rejected with the config path in the message.
 */
export function parseSandboxConfig(raw: unknown, configPath: string): SandboxConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${configPath}: expected a JSON object`);
  }
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!(SANDBOX_ALLOWED_KEYS as readonly string[]).includes(key)) {
      throw new Error(
        `${configPath}: unknown key "${key}" (allowed: ${SANDBOX_ALLOWED_KEYS.join(", ")})`,
      );
    }
  }
  const config: SandboxConfig = {};
  if (obj.enabled !== undefined) {
    if (typeof obj.enabled !== "boolean")
      throw new Error(`${configPath}: "enabled" must be a boolean`);
    config.enabled = obj.enabled;
  }
  if (obj.runner !== undefined) {
    if (
      typeof obj.runner !== "string" ||
      !(SANDBOX_RUNNER_CHOICES as readonly string[]).includes(obj.runner)
    ) {
      throw new Error(
        `${configPath}: "runner" must be one of: ${SANDBOX_RUNNER_CHOICES.join(", ")}`,
      );
    }
    config.runner = obj.runner as SandboxRunnerChoice;
  }
  if (obj.writable !== undefined) {
    if (
      !Array.isArray(obj.writable) ||
      obj.writable.some((p) => typeof p !== "string" || p.length === 0)
    ) {
      throw new Error(`${configPath}: "writable" must be an array of non-empty strings`);
    }
    config.writable = obj.writable as string[];
  }
  if (obj.home !== undefined) {
    if (obj.home !== "rw" && obj.home !== "ro") {
      throw new Error(`${configPath}: "home" must be "rw" or "ro"`);
    }
    config.home = obj.home;
  }
  if (obj.homeCaches !== undefined) {
    if (obj.homeCaches !== "rw" && obj.homeCaches !== "ro") {
      throw new Error(`${configPath}: "homeCaches" must be "rw" or "ro"`);
    }
    config.homeCaches = obj.homeCaches;
  }
  if (obj.network !== undefined) {
    if (obj.network !== "allow" && obj.network !== "deny") {
      throw new Error(`${configPath}: "network" must be "allow" or "deny"`);
    }
    config.network = obj.network;
  }
  if (obj.userCommands !== undefined) {
    if (typeof obj.userCommands !== "boolean") {
      throw new Error(`${configPath}: "userCommands" must be a boolean`);
    }
    config.userCommands = obj.userCommands;
  }
  if (obj.loginShell !== undefined) {
    if (typeof obj.loginShell !== "boolean") {
      throw new Error(`${configPath}: "loginShell" must be a boolean`);
    }
    config.loginShell = obj.loginShell;
  }
  if (obj.landlockHelper !== undefined) {
    if (typeof obj.landlockHelper !== "string" || obj.landlockHelper.length === 0) {
      throw new Error(`${configPath}: "landlockHelper" must be a non-empty string`);
    }
    config.landlockHelper = obj.landlockHelper;
  }
  if (obj.failIfUnavailable !== undefined) {
    if (typeof obj.failIfUnavailable !== "boolean") {
      throw new Error(`${configPath}: "failIfUnavailable" must be a boolean`);
    }
    config.failIfUnavailable = obj.failIfUnavailable;
  }
  if (obj.blockTerminates !== undefined) {
    if (typeof obj.blockTerminates !== "boolean") {
      throw new Error(`${configPath}: "blockTerminates" must be a boolean`);
    }
    config.blockTerminates = obj.blockTerminates;
  }
  return config;
}

/**
 * Config file path for a scope. Pure: no fs.
 * `projectDir` is pi's project config dir (<cwd>/.pi) — passed pre-resolved so
 * this module stays free of pi imports.
 */
export function sandboxConfigPath(
  scope: SandboxScope,
  paths: { agentDir: string; projectDir: string },
): string {
  return scope === "global" ? `${paths.agentDir}/sandbox.json` : `${paths.projectDir}/sandbox.json`;
}

/**
 * Merge global + project sandbox configs: per-key, project wins. Undefined
 * project keys fall back to the global value. Pure.
 */
export function mergeSandboxConfigs(
  globalConfig: SandboxConfig,
  projectConfig: SandboxConfig,
): SandboxConfig {
  const merged: SandboxConfig = { ...globalConfig };
  for (const key of SANDBOX_ALLOWED_KEYS) {
    const value = projectConfig[key];
    if (value !== undefined) (merged as Record<string, unknown>)[key] = value;
  }
  return merged;
}

/**
 * Apply an on/off toggle to one scope's config. Pure.
 * Turning on defaults the runner to "auto" only when this scope has no
 * explicit runner AND no explicit runner is effective in the merged config
 * (`inheritedRunner`), so an existing "bwrap"/"landlock"/... choice in
 * either scope is preserved.
 */
export function applySandboxToggle(
  config: SandboxConfig,
  enabled: boolean,
  inheritedRunner?: SandboxRunnerChoice,
): SandboxConfig {
  if (!enabled) return { ...config, enabled: false };
  return {
    ...config,
    enabled: true,
    ...(config.runner === undefined ? { runner: inheritedRunner ?? ("auto" as const) } : {}),
  };
}

/**
 * Managed (admin) sandbox config file path. Pure: platform (and the
 * Windows ProgramData dir) are injected. This is the third, highest-
 * precedence scope — see applyManagedSandboxConfig.
 */
export function managedSandboxConfigPath(platform: string, programData?: string): string {
  return platform === "win32"
    ? `${programData ?? "C:\\ProgramData"}\\pi\\agent\\sandbox.json`
    : "/etc/pi/agent/sandbox.json";
}

/**
 * Apply the managed (admin) layer on top of a merged user config
 * (mirrors the managed-settings model of other agent CLIs):
 * - scalar keys (`enabled`, `failIfUnavailable`, `blockTerminates`, `runner`,
 *   `network`, `home`, `homeCaches`, `userCommands`, `loginShell`,
 *   `landlockHelper`):
 *   the managed value WINS — an admin can pin `enabled: true` and cap
 *   what developers can change;
 * - `writable`: lower scopes can only NARROW, never widen — the effective
 *   list is the intersection (entries the lower scopes chose that the
 *   managed layer also allows); an unset managed `writable` leaves the
 *   lower scope unrestricted.
 * Pure.
 */
export function applyManagedSandboxConfig(
  user: SandboxConfig,
  managed: SandboxConfig,
): SandboxConfig {
  if (Object.keys(managed).length === 0) return user;
  const merged: SandboxConfig = { ...user };
  for (const key of SANDBOX_ALLOWED_KEYS) {
    const value = managed[key];
    if (value === undefined) continue;
    if (key === "writable") {
      const allowed = value as string[];
      const lower = user.writable ?? [];
      (merged as Record<string, unknown>).writable = lower.filter((p) => allowed.includes(p));
    } else {
      (merged as Record<string, unknown>)[key] = value;
    }
  }
  return merged;
}

/** Split a comma-separated writable-paths line (the config UI input). Pure. */
export function parseWritableList(input: string): string[] {
  return input
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Single-quote a string for safe embedding in a shell command line. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * Double-quote a string for embedding in a Seatbelt (SBPL) profile. SBPL
 * only accepts double-quoted strings — shellQuote's single quotes produce
 * profiles that sandbox-exec rejects ("unexpected symbol argument").
 */
export function sbplQuote(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

/** Expand a leading "~" and resolve relative paths against cwd. Pure: no fs. */
export function normalizeSandboxPath(input: string, ctx: { cwd: string; homeDir: string }): string {
  let p = input;
  if (p === "~") p = ctx.homeDir;
  else if (p.startsWith("~/")) p = `${ctx.homeDir}${p.slice(1)}`;
  if (!p.startsWith("/")) p = `${ctx.cwd}/${p}`;
  return p;
}

/**
 * Walk up to the deepest existing ancestor of a path (the requested path may
 * not exist yet — e.g. a new workspace subdirectory). Pure: existence is
 * injected.
 */
export function resolveExistingRoot(path: string, exists: (p: string) => boolean): string {
  let current = path;
  while (!exists(current)) {
    const parent = current.replace(/\/+$/, "").replace(/\/[^/]*$/, "");
    if (parent === current) return "/";
    current = parent;
  }
  return current === "" ? "/" : current;
}

/**
 * Build the effective writable-root set from config. Pure: fs injected.
 *
 * `realpath` canonicalizes each root (fs.realpath at the call site). This
 * matters for Seatbelt: `(subpath ...)` matches the CANONICAL filesystem
 * path, so on macOS a literal /tmp root never matches writes that resolve
 * to /private/tmp. Defaults to the identity so pure callers/tests can omit
 * it; for bwrap/landlock canonicalization is harmless (both resolve paths
 * to the same inode view).
 *
 * Configured `writable` entries that DO NOT EXIST are omitted and reported
 * in `missingWritable` — never resolved to an existing ancestor. Widening
 * `/missing/path` to `/` would silently make the whole filesystem writable.
 */
export function buildWritableRoots(
  config: SandboxConfig,
  ctx: RunnerContext,
  exists: (p: string) => boolean,
  realpath: (p: string) => string = (p) => p,
): { roots: string[]; missingWritable: string[] } {
  const roots = new Set<string>();
  const missingWritable: string[] = [];
  const add = (p: string) => roots.add(realpath(p));
  add(ctx.cwd); // workspace
  for (const entry of config.writable ?? []) {
    const norm = normalizeSandboxPath(entry, ctx);
    if (exists(norm)) add(norm);
    else missingWritable.push(norm);
  }
  // DAC-backstopped pseudo-roots that keep common patterns working:
  // `> /dev/null`, /proc/self writes, scratch space. /dev stays LITERAL:
  // it is a mount point (never a symlink in practice) and the bwrap wrapper
  // keys the minimal `--dev /dev` off the exact string "/dev".
  if (exists("/tmp")) roots.add(realpath("/tmp"));
  if (exists("/dev")) roots.add("/dev");
  if (exists("/proc")) roots.add(realpath("/proc"));
  // The platform temp dir ($TMPDIR on macOS) — /tmp's canonical form does
  // not cover it. Added only when it EXISTS and canonicalizes to something
  // narrower than "/": a missing or degenerate TMPDIR must be skipped, never
  // ancestor-walked (that could escalate to "/").
  if (ctx.tmpDir && exists(ctx.tmpDir)) {
    const tmp = realpath(ctx.tmpDir);
    if (tmp !== "/") roots.add(tmp);
  }
  if (config.home === "rw") add(ctx.homeDir);
  // Opt-in writable $HOME cache/tool dirs (homeCaches: "rw").
  // Added only when the dir EXISTS: a missing cache dir must NOT fall back
  // to its ancestor via resolveExistingRoot, or an absent ~/.cargo would
  // silently make all of $HOME writable.
  if (config.homeCaches === "rw") {
    for (const rel of HOME_CACHE_ROOTS) {
      const abs = `${ctx.homeDir}/${rel}`;
      if (exists(abs)) roots.add(realpath(abs));
    }
  }
  // A root subsuming another is redundant.
  const deduped = [...roots].filter(
    (r) => ![...roots].some((other) => other !== r && isInsideRoot(r, other)),
  );
  return { roots: deduped, missingWritable };
}

/**
 * Canonicalize a write target for containment checks against canonicalized
 * writable roots: resolve the deepest existing ancestor via realpath, then
 * append the missing trailing components lexically (the target may not exist
 * yet — e.g. a new file). Pure: fs injected.
 */
export function canonicalizeTarget(
  target: string,
  exists: (p: string) => boolean,
  realpath: (p: string) => string,
): string {
  const base = resolveExistingRoot(target, exists);
  return realpath(base) + target.slice(base.length);
}

/**
 * Decode a mount point from /proc/self/mountinfo: the kernel octal-escapes
 * special characters (\040 space, \011 tab, \012 newline, \134 backslash);
 * a backslash is always followed by exactly three octal digits.
 */
export function decodeMountPoint(encoded: string): string {
  return encoded.replace(/\\([0-7]{3})/g, (_, oct: string) =>
    String.fromCharCode(parseInt(oct, 8)),
  );
}

/**
 * True when `dir` sits on a mount whose options include noexec (common on
 * hardened /home). Pure: the /proc/self/mountinfo text is injected.
 * Picks the LONGEST matching mount point (the innermost mount).
 */
export function isNoexecPath(mountinfo: string, dir: string): boolean {
  let best: { mp: string; noexec: boolean } | undefined;
  for (const line of mountinfo.split("\n")) {
    const parts = line.split(" ");
    if (parts.length < 6) continue;
    const mp = decodeMountPoint(parts[4]);
    if (mp !== "/" && dir !== mp && !dir.startsWith(`${mp}/`)) continue;
    const noexec = parts[5].split(",").includes("noexec");
    if (!best || mp.length > best.mp.length) best = { mp, noexec };
  }
  return best?.noexec ?? false;
}

/**
 * Normalize a configured landlockHelper path: expand a leading ~ and
 * require an absolute result. Pure. Returns undefined when the input is
 * not absolute (after ~ expansion) — a relative path would let the
 * validation (cwd-relative) and the execution (PATH search) refer to
 * different binaries.
 */
export function normalizeHelperPath(override: string, homeDir: string): string | undefined {
  let p = override;
  if (p === "~") p = homeDir;
  else if (p.startsWith("~/")) p = `${homeDir}${p.slice(1)}`;
  return p.startsWith("/") ? p : undefined;
}

/** True when `candidate` equals `root` or is beneath it (string-based). */
export function isInsideRoot(candidate: string, root: string): boolean {
  if (candidate === root) return true;
  const prefix = root.endsWith("/") ? root : `${root}/`;
  return candidate.startsWith(prefix);
}

/** True when `candidate` is contained in any root. */
export function isInsideAnyRoot(candidate: string, roots: string[]): boolean {
  return roots.some((r) => isInsideRoot(candidate, r));
}

/**
 * Wrap a command for bubblewrap: everything read-only, writable roots bound
 * rw, minimal /dev, unshared user/pid namespaces; network unshared on deny.
 * /tmp and /proc get FRESH private mounts (--tmpfs/--proc) instead of rw
 * bind-mounts of the host dirs: scratch space still works, but the sandbox
 * can neither read nor clobber other processes' sockets/temp state.
 * (Surviving rw binds are never under /tmp or /proc — buildWritableRoots
 * subsumes them into those roots.)
 */
export function wrapWithBwrap(command: string, policy: SandboxPolicy, ctx: RunnerContext): string {
  const binds = policy.writableRoots
    .filter((r) => r !== "/dev" && r !== "/tmp" && r !== "/proc")
    .map((r) => `--bind ${shellQuote(r)} ${shellQuote(r)}`)
    .join(" ");
  const net = policy.network === "deny" ? "--unshare-net " : "";
  const dev = policy.writableRoots.includes("/dev") ? "--dev /dev " : "";
  const tmpfs = policy.writableRoots.includes("/tmp") ? "--tmpfs /tmp " : "";
  // --proc after --unshare-pid: the fresh procfs must be mounted in the
  // sandbox's own pid namespace.
  const proc = policy.writableRoots.includes("/proc") ? "--proc /proc " : "";
  const shellFlags = policy.loginShell ? "-lc" : "-c";
  return [
    "bwrap",
    "--ro-bind / /",
    binds ? ` ${binds}` : "",
    dev,
    tmpfs,
    "--unshare-user --unshare-pid",
    proc,
    net,
    `-- ${ctx.shellPath} ${shellFlags} ${shellQuote(command)}`,
  ]
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Wrap a command for the Landlock helper. /tmp, /dev, /proc are expected in
 * policy.writableRoots (buildWritableRoots adds them); landlock cannot block
 * the network — the extension warns about that separately.
 */
export function wrapWithLandlock(
  command: string,
  policy: SandboxPolicy,
  ctx: RunnerContext,
): string {
  const helper = ctx.helperPath ?? "pi-sandbox-landlock";
  const rwArgs = policy.writableRoots.map((r) => `--rw ${shellQuote(r)}`).join(" ");
  const shellFlags = policy.loginShell ? "-lc" : "-c";
  return `${shellQuote(helper)} ${rwArgs} -- ${ctx.shellPath} ${shellFlags} ${shellQuote(command)}`;
}

/**
 * Devices the Seatbelt profile grants write access to when /dev is a
 * writable root — explicit literals instead of a blanket /dev subpath
 * grant (raw block-device writes are exactly what the gate's `system`
 * category treats as dangerous). Mirrors SAFE_DEV_TARGETS in
 * permission-gate/rules.ts (minus /dev/full and /dev/fd, which are never
 * written to intentionally).
 */
export const SEATBELT_DEV_WRITABLE = [
  "/dev/null",
  "/dev/stdout",
  "/dev/stderr",
  "/dev/tty",
] as const;

/**
 * Generate a Seatbelt (sandbox-exec) profile: deny-by-default, reads and
 * process ops allowed, writes only under the writable roots, network gated
 * by policy. Validated on macOS 26.6.2 (arm64) against a canary matrix
 * (read/write/exec/network). NOTE: sandbox-exec is Apple-deprecated (still
 * functional as of macOS 26.6.2); see the README for the removal risk.
 */
export function buildSeatbeltProfile(
  policy: Pick<SandboxPolicy, "writableRoots" | "network">,
): string {
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-fork process-exec process-info* mach-lookup sysctl-read)",
    "(allow file-read*)",
  ];
  // With no writable roots, emit no file-write rule at all: a bare
  // `(allow file-write*)` would grant unrestricted writes.
  if (policy.writableRoots.length > 0) {
    const subpaths = policy.writableRoots
      .filter((r) => r !== "/dev")
      .map((r) => `(subpath ${sbplQuote(r)})`)
      .join(" ");
    if (subpaths) lines.push(`(allow file-write* ${subpaths})`);
  }
  // /dev: grant the specific safe devices only, never the whole subpath.
  if (policy.writableRoots.includes("/dev")) {
    lines.push(
      `(allow file-write-data ${SEATBELT_DEV_WRITABLE.map((d) => `(literal ${sbplQuote(d)})`).join(" ")})`,
    );
  }
  if (policy.network === "allow")
    lines.push("(allow network-bind network-outbound network-inbound)");
  return lines.join("\n");
}

/** Wrap a command with macOS sandbox-exec (no "--" separator: the first
 * non-flag argument is the command). */
export function wrapWithSandboxExec(
  command: string,
  policy: SandboxPolicy,
  ctx: RunnerContext,
): string {
  const profile = buildSeatbeltProfile(policy);
  const shellFlags = policy.loginShell ? "-lc" : "-c";
  return `sandbox-exec -p ${shellQuote(profile)} ${ctx.shellPath} ${shellFlags} ${shellQuote(command)}`;
}

/** Dispatch to the per-runner wrapper. Throws on an unknown runner. */
export function wrapCommand(
  runner: SandboxRunner,
  command: string,
  policy: SandboxPolicy,
  ctx: RunnerContext,
): string {
  switch (runner) {
    case "bwrap":
      return wrapWithBwrap(command, policy, ctx);
    case "landlock":
      return wrapWithLandlock(command, policy, ctx);
    case "sandbox-exec":
      return wrapWithSandboxExec(command, policy, ctx);
    default:
      throw new Error(`unknown sandbox runner: ${String(runner)}`);
  }
}
