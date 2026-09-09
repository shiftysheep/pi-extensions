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

export const SANDBOX_ALLOWED_KEYS = [
  "enabled",
  "runner",
  "writable",
  "home",
  "network",
  "userCommands",
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
  /** Network policy. Default: "allow". Enforced by bwrap/seatbelt; a no-op
   * (with a warning) on landlock, which cannot restrict networks. */
  network?: "allow" | "deny";
  /** Also sandbox user `!` commands. Default: false. */
  userCommands?: boolean;
};

export type SandboxPolicy = {
  /** Absolute writable roots (deduped, existing). Everything else is read-only. */
  writableRoots: string[];
  network: "allow" | "deny";
};

export type RunnerContext = {
  cwd: string;
  homeDir: string;
  shellPath: string;
  /** landlock runner only: path to the compiled helper binary. */
  helperPath?: string;
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
      !(["auto", "none", ...SANDBOX_RUNNERS] as string[]).includes(obj.runner)
    ) {
      throw new Error(
        `${configPath}: "runner" must be one of: auto, none, ${SANDBOX_RUNNERS.join(", ")}`,
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
  return config;
}

/** Single-quote a string for safe embedding in a shell command line. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
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

/** Build the effective writable-root set from config. Pure: fs injected. */
export function buildWritableRoots(
  config: SandboxConfig,
  ctx: RunnerContext,
  exists: (p: string) => boolean,
): string[] {
  const roots = new Set<string>();
  const add = (p: string) => roots.add(resolveExistingRoot(normalizeSandboxPath(p, ctx), exists));
  add(ctx.cwd); // workspace
  for (const entry of config.writable ?? []) add(entry);
  // DAC-backstopped pseudo-roots that keep common patterns working:
  // `> /dev/null`, /proc/self writes, scratch space.
  for (const systemRoot of ["/tmp", "/dev", "/proc"]) if (exists(systemRoot)) roots.add(systemRoot);
  if (config.home === "rw") add(ctx.homeDir);
  // A root subsuming another is redundant.
  return [...roots].filter(
    (r) => ![...roots].some((other) => other !== r && isInsideRoot(r, other)),
  );
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
 */
export function wrapWithBwrap(command: string, policy: SandboxPolicy, ctx: RunnerContext): string {
  const binds = policy.writableRoots
    .filter((r) => r !== "/dev")
    .map((r) => `--bind ${shellQuote(r)} ${shellQuote(r)}`)
    .join(" ");
  const net = policy.network === "deny" ? "--unshare-net " : "";
  const dev = policy.writableRoots.includes("/dev") ? "--dev /dev " : "";
  return [
    "bwrap",
    "--ro-bind / /",
    binds ? ` ${binds}` : "",
    dev,
    net,
    "--unshare-user --unshare-pid",
    `-- ${ctx.shellPath} -lc ${shellQuote(command)}`,
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
  return `${shellQuote(helper)} ${rwArgs} -- ${ctx.shellPath} -lc ${shellQuote(command)}`;
}

/**
 * Generate a Seatbelt (sandbox-exec) profile: deny-by-default, reads and
 * process ops allowed, writes only under the writable roots, network gated
 * by policy. NOTE: untested on macOS — validate on a real machine before
 * relying on it.
 */
export function buildSeatbeltProfile(policy: SandboxPolicy): string {
  const subpaths = policy.writableRoots.map((r) => `(subpath ${shellQuote(r)})`).join(" ");
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-fork process-exec process-info* mach-lookup sysctl-read)",
    "(allow file-read*)",
    `(allow file-write* ${subpaths})`,
  ];
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
  return `sandbox-exec -p ${shellQuote(profile)} ${ctx.shellPath} -lc ${shellQuote(command)}`;
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
