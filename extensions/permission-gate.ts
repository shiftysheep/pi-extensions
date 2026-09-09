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
} from "@earendil-works/pi-coding-agent";
import {
  CONFIG_DIR_NAME,
  createLocalBashOperations,
  getAgentDir,
  isToolCallEventType,
} from "@earendil-works/pi-coding-agent";
import {
  applySandboxToggle,
  buildWritableRoots,
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

export default function (pi: ExtensionAPI) {
  let config: SandboxConfig = {};
  let state: SandboxState = { active: false, enabled: false };
  let localBashOps: ReturnType<typeof createLocalBashOperations> | undefined;

  const runnerContext = (cwd: string): RunnerContext => ({
    cwd,
    homeDir: os.homedir(),
    shellPath: "/bin/bash",
    helperPath: state.active ? state.helperPath : undefined,
  });

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
      writableRoots: buildWritableRoots(cfg, runnerContext(cwd), (p) => {
        try {
          return fs.statSync(p).isDirectory();
        } catch {
          return false;
        }
      }),
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
      if (isInsideAnyRoot(target, state.policy.writableRoots)) return undefined;
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
    const select = (title: string, options: string[]) =>
      ctx.ui.select(title, options, { signal: ctx.signal });
    if (option.startsWith("enabled")) {
      const v = await select("Sandbox enabled", ["true", "false"]);
      return v === undefined ? undefined : { enabled: v === "true" };
    }
    if (option.startsWith("runner")) {
      const v = await select("Sandbox runner", [...SANDBOX_RUNNER_CHOICES]);
      return v === undefined ? undefined : { runner: v as SandboxRunnerChoice };
    }
    if (option.startsWith("network")) {
      const v = await select("Sandbox network policy", ["allow", "deny"]);
      return v === undefined ? undefined : { network: v as "allow" | "deny" };
    }
    if (option.startsWith("home")) {
      const v = await select("$HOME access", ["ro", "rw"]);
      return v === undefined ? undefined : { home: v as "ro" | "rw" };
    }
    if (option.startsWith("userCommands")) {
      const v = await select("Sandbox user ! commands", ["true", "false"]);
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
    const scopeChoice = await ctx.ui.select(
      "Sandbox config scope",
      [scopeLabel("project"), scopeLabel("global")],
      { signal: ctx.signal },
    );
    if (scopeChoice === undefined) {
      ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
      return;
    }
    const scope: SandboxScope = scopeChoice.startsWith("project") ? "project" : "global";
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
      const choice = await ctx.ui.select(`Sandbox config (${scopeLabel(scope)})`, [
        `enabled: ${draft.enabled ?? "false"}`,
        `runner: ${draft.runner ?? "auto"}`,
        `network: ${draft.network ?? "allow"}`,
        `home: ${draft.home ?? "ro"}`,
        `userCommands: ${draft.userCommands ?? "false"}`,
        `writable: ${draft.writable?.length ? draft.writable.join(", ") : "(none)"}`,
        "— save —",
        "— cancel —",
      ]);
      if (choice === undefined || choice === "— cancel —") {
        ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
        return;
      }
      if (choice === "— save —") break;
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
