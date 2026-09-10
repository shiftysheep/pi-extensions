/**
 * Permission Gate + Filesystem Sandbox Extension
 *
 * Two cooperating layers:
 *
 * 1. HEURISTIC GATE (always on) — prompts for confirmation before bash
 *    commands that look dangerous (recursive `rm`, privilege escalation,
 *    world-writable `chmod`, raw device writes, mkfs, power actions).
 *
 * 2. OS SANDBOX (opt-in via sandbox.json `enabled: true`) — wraps the agent's
 *    bash commands in a filesystem sandbox:
 *      - Linux:   bubblewrap (preferred) or a Landlock helper binary
 *      - macOS:   sandbox-exec (Seatbelt)
 *    Everything outside the writable roots becomes read-only, enforced by
 *    the OS. While the sandbox is active, the filesystem category of gate
 *    rules is suppressed (the kernel enforces it); system-category rules
 *    (sudo, dd to raw devices, mkfs, power) stay armed. When no runner is
 *    available the extension falls back to gate-only mode (all rules armed)
 *    and warns.
 *
 * The gate is a heuristic prompt guard, NOT a security boundary: shell
 * expansion, quoting, scripts, and indirect invocation can evade text
 * matching. The sandbox is an OS-level boundary, but it isolates the
 * filesystem only (not the network on landlock) and does not protect
 * against malicious code that exfiltrates or attacks over the network.
 *
 * Config (strictly validated JSON; the two scopes are merged per-key,
 * project wins):
 *   global:  ~/.pi/agent/sandbox.json
 *   project: <cwd>/.pi/sandbox.json   (only honored/written when trusted)
 *   {
 *     "enabled": true,          // default false
 *     "runner": "auto",         // auto | bwrap | landlock | sandbox-exec | none
 *     "writable": ["~/cache"],  // extra writable paths (cwd, /tmp, /dev, /proc are always writable)
 *     "home": "ro",             // ro | rw — access to $HOME (default ro)
 *     "homeCaches": "rw",       // rw | ro — writable $HOME cache dirs (default rw; see HOME_CACHE_ROOTS)
 *     "network": "allow",       // allow | deny (deny is a no-op+warning on landlock)
 *     "userCommands": false     // also sandbox user `!` commands
 *   }
 *
 * Commands:
 *   /sandbox          show live status (runner, writable roots, network policy)
 *   /sandbox on       enable — writes the PROJECT scope, runner defaults to "auto"
 *   /sandbox off      disable — writes the PROJECT scope
 *   /sandbox config   interactive editor for either scope
 *
 * `write`/`edit` tool calls target a path directly (no shell), so they are
 * guarded separately: paths outside the writable roots prompt for
 * confirmation.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExtensionUIContext,
  Theme,
} from "@earendil-works/pi-coding-agent";
import {
  CONFIG_DIR_NAME,
  createLocalBashOperations,
  getAgentDir,
  isToolCallEventType,
} from "@earendil-works/pi-coding-agent";
import { type SelectItem, SelectList, type SelectListTheme, Text } from "@earendil-works/pi-tui";
import {
  applySandboxToggle,
  buildWritableRoots,
  canonicalizeTarget,
  isInsideAnyRoot,
  mergeSandboxConfigs,
  parseSandboxConfig,
  parseWritableList,
  type RunnerContext,
  SANDBOX_RUNNER_CHOICES,
  type SandboxConfig,
  type SandboxPolicy,
  type SandboxRunnerChoice,
  type SandboxScope,
  sandboxConfigPath,
  wrapCommand,
} from "./lib/sandbox-utils.js";
import { findDangerousRule, shouldGate } from "./permission-gate/rules.js";
import { resolveRunner } from "./permission-gate/runner.js";

const SANDBOX_CONFIG_FILE = "sandbox.json";

const USAGE =
  "Usage:\n" +
  "  /sandbox          show live status\n" +
  '  /sandbox on       enable (project scope; runner defaults to "auto"; an explicit runner in either scope is kept)\n' +
  "  /sandbox off      disable (project scope)\n" +
  "  /sandbox config   interactive editor (pick the global or project scope)";

type SandboxState =
  | { active: false; enabled: false }
  | { active: false; enabled: true; reason: string }
  | {
      active: true;
      enabled: true;
      runner: "bwrap" | "landlock" | "sandbox-exec";
      policy: SandboxPolicy;
      helperPath?: string;
      /** false when network=deny is requested but the runner cannot enforce it (landlock). */
      networkEnforced: boolean;
    };

/** Both scope config file paths for a working directory. */
function sandboxConfigFiles(cwd: string): Record<SandboxScope, string> {
  const base = { agentDir: getAgentDir(), projectDir: path.join(cwd, CONFIG_DIR_NAME) };
  return {
    global: sandboxConfigPath("global", base),
    project: sandboxConfigPath("project", base),
  };
}

export type LoadedSandboxConfigs = {
  /** Merged (per-key, project wins) config. Empty on error. */
  config: SandboxConfig;
  /** Per-scope configs as read (project is {} when untrusted or on error). */
  globalConfig: SandboxConfig;
  projectConfig: SandboxConfig;
  files: Record<SandboxScope, string>;
  /** Set when either scope file failed to parse/validate. */
  error?: string;
};

/** Read + strictly validate one scope file. Absent file = empty config. */
function readScopeConfig(file: string): SandboxConfig {
  if (!fs.existsSync(file)) return {};
  return parseSandboxConfig(JSON.parse(fs.readFileSync(file, "utf8")), file);
}

/**
 * Load and merge both scopes: per-key, project wins. An untrusted project
 * contributes nothing (its file is neither read nor honored).
 */
function loadSandboxConfigs(cwd: string, projectTrusted: boolean): LoadedSandboxConfigs {
  const files = sandboxConfigFiles(cwd);
  let globalConfig: SandboxConfig;
  let projectConfig: SandboxConfig;
  try {
    globalConfig = readScopeConfig(files.global);
    projectConfig = projectTrusted ? readScopeConfig(files.project) : {};
  } catch (err) {
    return {
      config: {},
      globalConfig: {},
      projectConfig: {},
      files,
      error: String(err instanceof Error ? err.message : err),
    };
  }
  return {
    config: mergeSandboxConfigs(globalConfig, projectConfig),
    globalConfig,
    projectConfig,
    files,
  };
}

/** Persist one scope's whole config. Written atomically (temp + rename, the
 *  same pattern as the advisor config) so an interrupted write never leaves a
 *  truncated file behind (creates the project .pi dir when needed). */
function writeScopeConfig(file: string, config: SandboxConfig): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  fs.renameSync(tmp, file);
}

// --- select prompts with dim per-option descriptions ---
// ctx.ui.select renders plain strings only; ui.custom + pi-tui's SelectList
// (the component the built-in selectors use) renders {label, description}
// with the description dimmed.

function sandboxSelectTheme(theme: Theme): SelectListTheme {
  return {
    selectedPrefix: (text) => theme.fg("accent", text),
    selectedText: (text) => theme.fg("accent", text),
    description: (text) => theme.fg("dim", text),
    scrollInfo: (text) => theme.fg("dim", text),
    noMatch: (text) => theme.fg("dim", text),
  };
}

class SandboxSelectPrompt {
  onDone: (value: string | undefined) => void = () => {};
  dispose?: () => void;
  private readonly title: Text;
  private readonly list: SelectList;
  private readonly hint: Text;

  constructor(theme: Theme, titleText: string, items: SelectItem[]) {
    this.title = new Text(theme.fg("accent", theme.bold(titleText)), 1, 0);
    this.list = new SelectList(items, Math.min(items.length, 12), sandboxSelectTheme(theme));
    this.list.onSelect = (item) => this.onDone(item.value);
    this.list.onCancel = () => this.onDone(undefined);
    this.hint = new Text(theme.fg("dim", "↑/↓ or j/k: move · enter: select · esc: cancel"), 1, 0);
  }

  render(width: number): string[] {
    return [...this.title.render(width), ...this.list.render(width), ...this.hint.render(width)];
  }

  handleInput(data: string): void {
    this.list.handleInput(data);
  }

  invalidate(): void {
    this.title.invalidate();
    this.list.invalidate();
    this.hint.invalidate();
  }
}

/** Select prompt with a dim description on every option. Returns the chosen
 *  item's value (undefined when cancelled). The custom SelectList path is
 *  TUI-only: RPC mode exposes a callable ui.custom that never invokes the
 *  factory, so gate on ctx.mode (pi's documented guard for terminal-only UI).
 *  Other modes fall back to ctx.ui.select (plain labels, no descriptions),
 *  mapping the returned label back to the item's value. */
async function promptSelect(
  ctx: ExtensionCommandContext,
  title: string,
  items: SelectItem[],
): Promise<string | undefined> {
  if (ctx.mode !== "tui" || typeof ctx.ui.custom !== "function") {
    const label = await ctx.ui.select(
      title,
      items.map((item) => item.label),
      {
        signal: ctx.signal,
      },
    );
    return items.find((item) => item.label === label)?.value;
  }
  return ctx.ui.custom<string | undefined>((_tui, theme, _keybindings, done) => {
    const prompt = new SandboxSelectPrompt(theme, title, items);
    let settled = false;
    let onAbort: (() => void) | undefined;
    const finish = (value: string | undefined) => {
      if (settled) return;
      settled = true;
      if (ctx.signal && onAbort) ctx.signal.removeEventListener("abort", onAbort);
      done(value);
    };
    if (ctx.signal) {
      if (ctx.signal.aborted) {
        finish(undefined);
      } else {
        onAbort = () => finish(undefined);
        ctx.signal.addEventListener("abort", onAbort, { once: true });
      }
    }
    prompt.onDone = (value) => finish(value);
    prompt.dispose = () => {
      if (ctx.signal && onAbort) ctx.signal.removeEventListener("abort", onAbort);
    };
    return prompt;
  });
}

/** Dim hint for each runner choice in the config UI. */
const RUNNER_DESCRIPTIONS: Record<SandboxRunnerChoice, string> = {
  auto: "best available (bwrap → landlock → sandbox-exec)",
  none: "no OS sandbox (gate-only mode)",
  bwrap: "force bubblewrap (Linux)",
  landlock: "force Landlock (Linux 5.13+; network policy not enforced)",
  "sandbox-exec": "force macOS Seatbelt",
};

/** The config menu rows: label = current value, description = dim hint. */
function sandboxOptionItems(draft: SandboxConfig): SelectItem[] {
  return [
    {
      value: "enabled",
      label: `enabled: ${draft.enabled ?? "false"}`,
      description: "master switch — when on, bash runs inside the OS sandbox",
    },
    {
      value: "runner",
      label: `runner: ${draft.runner ?? "auto"}`,
      description: "sandbox backend: auto (best available) or forced",
    },
    {
      value: "network",
      label: `network: ${draft.network ?? "allow"}`,
      description: "outbound network for sandboxed commands",
    },
    {
      value: "home",
      label: `home: ${draft.home ?? "ro"}`,
      description: "access to your $HOME inside the sandbox",
    },
    {
      value: "homeCaches",
      label: `homeCaches: ${draft.homeCaches ?? "rw"}`,
      description: "writable $HOME cache dirs (~/.cache, ~/.npm, ~/.cargo, …); ro = strict",
    },
    {
      value: "userCommands",
      label: `userCommands: ${draft.userCommands ?? "false"}`,
      description: "also sandbox user ! commands",
    },
    {
      value: "writable",
      label: `writable: ${draft.writable?.length ? draft.writable.join(", ") : "(none)"}`,
      description: "extra directories sandboxed commands may write to",
    },
    { value: "save", label: "— save —", description: "write the config file and re-apply" },
    { value: "cancel", label: "— cancel —", description: "discard changes" },
  ];
}

export default function (pi: ExtensionAPI) {
  let config: SandboxConfig = {};
  let state: SandboxState = { active: false, enabled: false };
  let localBashOps: ReturnType<typeof createLocalBashOperations> | undefined;

  const runnerContext = (cwd: string): RunnerContext => ({
    cwd,
    homeDir: os.homedir(),
    shellPath: "/bin/bash",
    helperPath: state.active ? state.helperPath : undefined,
    tmpDir: process.env.TMPDIR,
  });

  /** fs predicates shared by policy building and the write/edit guard. */
  const dirExists = (p: string): boolean => {
    try {
      return fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  };
  const canon = (p: string): string => {
    try {
      return fs.realpathSync(p);
    } catch {
      return p;
    }
  };

  /** Probe runners and build the policy for a merged config. */
  function computeState(
    cwd: string,
    cfg: SandboxConfig,
  ): { state: SandboxState; warnings: string[] } {
    if (!cfg.enabled) return { state: { active: false, enabled: false }, warnings: [] };
    const probe = resolveRunner(cfg.runner ?? "auto");
    if (!probe.ok)
      return {
        state: { active: false, enabled: true, reason: probe.reason },
        warnings: [
          `Sandbox enabled but no runner available (${probe.reason}). Commands run UNSANDBOXED; all permission gates are armed.`,
        ],
      };
    const policy = {
      writableRoots: buildWritableRoots(cfg, runnerContext(cwd), dirExists, canon),
      network: cfg.network ?? "allow",
    };
    const networkEnforced = probe.runner !== "landlock";
    return {
      state: {
        active: true,
        enabled: true,
        runner: probe.runner,
        policy,
        helperPath: probe.helperPath,
        networkEnforced,
      },
      warnings:
        policy.network === "deny" && !networkEnforced
          ? [
              "Sandbox: landlock cannot enforce network policy; network=deny is IGNORED (use bwrap to enforce).",
            ]
          : [],
    };
  }

  /** Set config+state from a merged config. Capability warnings are ALWAYS
   *  surfaced; the verbose "Sandbox active" line only when announce is set. */
  function applySandbox(
    cfg: SandboxConfig,
    ui: ExtensionUIContext,
    cwd: string,
    announce: boolean,
  ): SandboxState {
    config = cfg;
    const next = computeState(cwd, cfg);
    state = next.state;
    for (const warning of next.warnings) ui.notify(warning, "warning");
    if (announce && next.state.active)
      ui.notify(
        `Sandbox active (${next.state.runner}): read-only outside ${next.state.policy.writableRoots.join(", ")}; network ${next.state.policy.network === "deny" ? "DENIED" : "allowed"}.`,
      );
    return next.state;
  }

  pi.on("session_start", (_event, ctx) => {
    // ctx.cwd, not process.cwd(): resumed sessions may run from a different
    // directory than the process started in, and the project config + writable
    // workspace root must key off the session's cwd.
    const loaded = loadSandboxConfigs(ctx.cwd, ctx.isProjectTrusted());
    if (loaded.error) {
      state = { active: false, enabled: true, reason: `invalid config: ${loaded.error}` };
      ctx.ui.notify(`Sandbox disabled: ${loaded.error}`, "warning");
      return;
    }
    applySandbox(loaded.config, ctx.ui, ctx.cwd, true);
  });

  pi.on("tool_call", async (event, ctx) => {
    // --- write/edit path guard (tools write directly, no shell involved) ---
    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      if (!state.active) return undefined;
      const target = path.resolve(ctx.cwd, String((event.input as { path?: string }).path ?? ""));
      // Containment must compare like-with-like: roots are canonicalized in
      // buildWritableRoots, so canonicalize the target the same way (deepest
      // existing ancestor + missing tail) or /tmp/file would miss /private/tmp.
      if (isInsideAnyRoot(canonicalizeTarget(target, dirExists, canon), state.policy.writableRoots))
        return undefined;
      if (!ctx.hasUI) {
        return {
          block: true,
          terminate: true,
          reason: `Sandbox: ${target} is outside the writable roots and there is no UI to confirm`,
        };
      }
      const ok = await ctx.ui.confirm(
        `Sandbox: write outside writable roots`,
        `${target}\n\nAllow this write?`,
        { signal: ctx.signal },
      );
      if (!ok)
        return {
          block: true,
          terminate: true,
          reason: `Sandbox: write outside writable roots (declined): ${target}`,
        };
      return undefined;
    }

    if (!isToolCallEventType("bash", event)) return undefined;
    const command = String(event.input.command ?? "");

    // --- heuristic gate (checked on the ORIGINAL command, before wrapping) ---
    const match = findDangerousRule(command);
    if (match && shouldGate(match, state.active)) {
      if (!ctx.hasUI) {
        return {
          block: true,
          terminate: true,
          reason: `Blocked: "${match.name}" heuristic matched and there is no UI to confirm`,
        };
      }
      const ok = await ctx.ui.confirm(`⚠️ Dangerous command (${match.name})`, command, {
        signal: ctx.signal,
      });
      if (!ok) return { block: true, terminate: true, reason: "Blocked by user" };
    }

    // --- sandbox wrap ---
    if (state.active && command) {
      // Mutate the shared input object IN PLACE: the agent executes the tool with its own
      // args reference (event.input === args), so reassigning event.input would be lost.
      (event.input as { command: string }).command = wrapCommand(
        state.runner,
        command,
        state.policy,
        runnerContext(ctx.cwd),
      );
    }
    return undefined;
  });

  // --- user `!` commands: intercept execution when opted in ---
  pi.on("user_bash", () => {
    if (!state.active || !config.userCommands) return undefined;
    // Snapshot the whole runner context (incl. helperPath) at intercept time so
    // a later /sandbox toggle can't mix generations inside one exec.
    const runner = state.runner;
    const policy = state.policy;
    const helperPath = state.helperPath;
    localBashOps ??= createLocalBashOperations();
    const base = localBashOps;
    return {
      operations: {
        async exec(command: string, cwd: string, options: Parameters<typeof base.exec>[2]) {
          const context: RunnerContext = {
            cwd,
            homeDir: os.homedir(),
            shellPath: "/bin/bash",
            helperPath,
          };
          return base.exec(wrapCommand(runner, command, policy, context), cwd, options);
        },
      },
    };
  });

  // --- /sandbox on|off: toggle the PROJECT scope, re-apply, report (dimmed) ---
  async function toggleSandbox(enabled: boolean, ctx: ExtensionCommandContext): Promise<void> {
    if (!ctx.isProjectTrusted()) {
      ctx.ui.notify(
        `Sandbox unchanged: /sandbox ${enabled ? "on" : "off"} writes the project config (${ctx.cwd}/${CONFIG_DIR_NAME}/${SANDBOX_CONFIG_FILE}), but this project is not trusted. Use /sandbox config (global scope) instead.`,
        "warning",
      );
      return;
    }
    const loaded = loadSandboxConfigs(ctx.cwd, ctx.isProjectTrusted());
    if (loaded.error) {
      ctx.ui.notify(`Sandbox unchanged: ${loaded.error} — fix the file, then retry.`, "error");
      return;
    }
    // inheritedRunner: if the user explicitly chose a runner in EITHER scope,
    // keep it; only default to "auto" when no explicit runner is set anywhere.
    const toggled = applySandboxToggle(loaded.projectConfig, enabled, loaded.config.runner);
    writeScopeConfig(loaded.files.project, toggled);
    // Recompute from the configs we already hold (no re-read of the file we just wrote).
    const next = applySandbox(
      mergeSandboxConfigs(loaded.globalConfig, toggled),
      ctx.ui,
      ctx.cwd,
      false,
    );
    if (!enabled) {
      ctx.ui.notify("Sandbox off", "info");
      return;
    }
    // When no runner is available, applySandbox already warned (announcements
    // are suppressed here, capability warnings are not).
    if (next.active) ctx.ui.notify(`Sandbox on (${next.runner})`, "info");
  }

  // --- one option edit in the config UI; undefined = the user bailed ---
  async function editSandboxOption(
    ctx: ExtensionCommandContext,
    option: string,
    draft: SandboxConfig,
  ): Promise<Partial<SandboxConfig> | undefined> {
    if (option === "enabled") {
      const v = await promptSelect(ctx, "Sandbox enabled", [
        { value: "true", label: "true", description: "wrap bash commands in the OS sandbox" },
        { value: "false", label: "false", description: "gate-only — prompts, no OS isolation" },
      ]);
      return v === undefined ? undefined : { enabled: v === "true" };
    }
    if (option === "runner") {
      const v = await promptSelect(
        ctx,
        "Sandbox runner",
        SANDBOX_RUNNER_CHOICES.map((choice) => ({
          value: choice,
          label: choice,
          description: RUNNER_DESCRIPTIONS[choice],
        })),
      );
      return v === undefined ? undefined : { runner: v as SandboxRunnerChoice };
    }
    if (option === "network") {
      const v = await promptSelect(ctx, "Sandbox network policy", [
        { value: "allow", label: "allow", description: "sandboxed commands can reach the network" },
        { value: "deny", label: "deny", description: "block outbound network (no-op on landlock)" },
      ]);
      return v === undefined ? undefined : { network: v as "allow" | "deny" };
    }
    if (option === "home") {
      const v = await promptSelect(ctx, "$HOME access in the sandbox", [
        { value: "ro", label: "ro", description: "$HOME is read-only (default)" },
        { value: "rw", label: "rw", description: "$HOME is writable" },
      ]);
      return v === undefined ? undefined : { home: v as "ro" | "rw" };
    }
    if (option === "homeCaches") {
      const v = await promptSelect(ctx, "Writable $HOME cache dirs", [
        {
          value: "rw",
          label: "rw",
          description: "~/.cache, ~/.npm, ~/.cargo, … are writable (default)",
        },
        {
          value: "ro",
          label: "ro",
          description: "every $HOME subdir stays read-only (stricter)",
        },
      ]);
      return v === undefined ? undefined : { homeCaches: v as "rw" | "ro" };
    }
    if (option === "userCommands") {
      const v = await promptSelect(ctx, "Sandbox user ! commands", [
        { value: "true", label: "true", description: "user ! commands also run sandboxed" },
        {
          value: "false",
          label: "false",
          description: "user ! commands bypass the sandbox (default)",
        },
      ]);
      return v === undefined ? undefined : { userCommands: v === "true" };
    }
    const v = await ctx.ui.input(
      "Writable paths (comma-separated; empty = none in this scope)",
      draft.writable?.join(", "),
      { signal: ctx.signal },
    );
    if (v === undefined) return undefined;
    // "[]" is a defined value: a project "[]" overrides a non-empty global
    // list (project wins per-key); a global "[]" never overrides a project one.
    return { writable: parseWritableList(v) };
  }

  // --- /sandbox config: pick a scope, edit options, save, re-apply ---
  async function runSandboxConfigUI(ctx: ExtensionCommandContext): Promise<void> {
    const trusted = ctx.isProjectTrusted();
    const files = sandboxConfigFiles(ctx.cwd);
    const scopeLabel = (scope: SandboxScope) =>
      `${scope} — ${files[scope]}${scope === "project" && !trusted ? " (not trusted)" : ""}`;
    const scopeChoice = await promptSelect(ctx, "Sandbox config scope", [
      {
        value: "project",
        label: scopeLabel("project"),
        description: "this repo only — shared with the project (needs trust)",
      },
      {
        value: "global",
        label: scopeLabel("global"),
        description: "applies to all your projects",
      },
    ]);
    if (scopeChoice === undefined) {
      ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
      return;
    }
    const scope: SandboxScope = scopeChoice === "project" ? "project" : "global";
    if (scope === "project" && !trusted) {
      ctx.ui.notify(
        "Project is not trusted; refusing to write its sandbox config. Trust the project or pick the global scope.",
        "warning",
      );
      return;
    }
    const file = files[scope];
    let draft: SandboxConfig;
    try {
      draft = readScopeConfig(file);
    } catch (err) {
      ctx.ui.notify(
        `Cannot edit: ${String(err instanceof Error ? err.message : err)} — fix the file by hand, then retry.`,
        "error",
      );
      return;
    }
    for (;;) {
      const choice = await promptSelect(
        ctx,
        `Sandbox config (${scopeLabel(scope)})`,
        sandboxOptionItems(draft),
      );
      // promptSelect resolves to the item's value in every UI mode.
      if (choice === undefined || choice === "cancel") {
        ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
        return;
      }
      if (choice === "save") break;
      const edited = await editSandboxOption(ctx, choice, draft);
      if (edited === undefined) {
        ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
        return;
      }
      Object.assign(draft, edited);
    }
    writeScopeConfig(file, draft);
    ctx.ui.notify(`sandbox config saved: ${file}`, "info");
    const reloaded = loadSandboxConfigs(ctx.cwd, trusted);
    if (reloaded.error) {
      // The save succeeded, but the OTHER scope file is invalid; keep the live
      // state as-is rather than falling back to an empty config.
      ctx.ui.notify(`Sandbox state unchanged: ${reloaded.error}`, "error");
      return;
    }
    applySandbox(reloaded.config, ctx.ui, ctx.cwd, true);
  }

  pi.registerCommand("sandbox", {
    description:
      "Filesystem sandbox: status; /sandbox on|off (project scope); /sandbox config (interactive editor)",
    getArgumentCompletions: (prefix) =>
      ["on", "off", "config"]
        .filter((a) => a.startsWith(prefix))
        .map((a) => ({ value: a, label: a, description: `sandbox: ${a}` })),
    handler: async (args, ctx) => {
      const sub = args.trim().split(/\s+/).filter(Boolean)[0]?.toLowerCase();
      if (sub === "on") return toggleSandbox(true, ctx);
      if (sub === "off") return toggleSandbox(false, ctx);
      if (sub === "config") return runSandboxConfigUI(ctx);
      if (sub !== undefined) throw new Error(`Unknown sandbox subcommand "${sub}".\n\n${USAGE}`);
      // --- bare /sandbox: live status ---
      const lines: string[] = [];
      if (!state.enabled) {
        lines.push(
          `Sandbox: DISABLED — /sandbox on enables it (project scope); or set "enabled": true in the config`,
        );
      } else if (state.active) {
        lines.push(`Sandbox: ACTIVE (${state.runner})`);
        lines.push(`Writable roots: ${state.policy.writableRoots.join(", ")}`);
        lines.push(
          `Network: ${state.policy.network}${state.policy.network === "deny" && !state.networkEnforced ? " (NOT enforced — landlock)" : ""}`,
        );
        lines.push(`User ! commands: ${config.userCommands ? "sandboxed" : "not sandboxed"}`);
      } else {
        lines.push(`Sandbox: FALLBACK (enabled, but ${state.reason})`);
        lines.push("Commands run unsandboxed; ALL permission gates are armed.");
      }
      const files = sandboxConfigFiles(ctx.cwd);
      const trustNote = ctx.isProjectTrusted() ? "" : " (not trusted)";
      lines.push(
        `Config: ${files.project} (project, wins per-key)${trustNote} / ${files.global} (global)`,
      );
      lines.push(
        "Gate categories: system rules always gated; filesystem rules gated whenever the sandbox is inactive (disabled or fallback).",
      );
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
