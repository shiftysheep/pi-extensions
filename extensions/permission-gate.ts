/**
 * Permission Gate + Filesystem Sandbox Extension
 *
 * Two cooperating layers:
 *
 * 1. HEURISTIC GATE (always on) — two dispositions:
 *    - CONFIRM (default): prompts before dangerous commands — recursive
 *      `rm`, world-writable `chmod`, privilege escalation, power actions,
 *      destructive Git ops (force push, reset --hard, clean -f, branch -D,
 *      history rewrites), curated remote destruction (IaC destroy —
 *      terraform/cdk/pulumi/vagrant/sam/serverless, az group delete,
 *      gcloud projects delete, docker volume rm/prune, kubectl delete
 *      namespace, aws s3 rm --recursive, repo delete, unpublish, DROP/
 *      TRUNCATE via known DB clients) — and, via a separate
 *      PowerShell rule set, dangerous cmdlets (recursive `Remove-Item`,
 *      elevation, `iex`, ACL changes, machine-wide registry writes).
 *    - DENY (hard block, human-only, NO prompt): raw host-disk destruction
 *      (`dd`/redirect/`tee`/`cp`/`shred` to /dev/*, wipefs, blkdiscard,
 *      partition wipes, LVM/ZFS destroy, mkfs; PowerShell disk wipes). The
 *      agent must never perform these; the human runs them manually.
 *    Every match is gated REGARDLESS of sandbox state: the sandbox answers
 *    "where may this command write?", the gate answers "does this command
 *    require human intent?" — confinement to writable roots does not make
 *    an irreversible action reversible.
 *
 * 2. OS SANDBOX (opt-in via sandbox.json `enabled: true`) — wraps the agent's
 *    bash commands in a filesystem sandbox:
 *      - Linux:   bubblewrap (preferred) or a Landlock helper binary
 *      - macOS:   sandbox-exec (Seatbelt)
 *    Everything outside the writable roots becomes read-only, enforced by
 *    the OS. When no runner is available the extension falls back to
 *    gate-only mode (all rules armed) and warns.
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
 *     "writable": ["~/cache"],  // extra writable paths (cwd, /tmp, /dev, /proc are always writable;
 *                               //   MISSING paths are omitted with a warning, never widened to a parent)
 *     "home": "ro",             // ro | rw — access to $HOME (default ro)
 *     "homeCaches": "ro",       // ro | rw — writable $HOME cache dirs (default ro; some hold
 *                               //   credentials/executables — see HOME_CACHE_ROOTS)
 *     "network": "allow",       // allow | deny (deny is a no-op+warning on landlock)
 *     "userCommands": false,    // also sandbox user `!` commands
 *     "loginShell": true,        // true: bash -lc (login profile sourced); false: bash -c
 *     "landlockHelper": "~/bin/pi-sandbox-landlock",  // prebuilt helper (skip compilation)
 *     "failIfUnavailable": false, // true: block commands when no runner resolves (fail-closed)
 *     "blockTerminates": false    // true: a gate block stops the agent's turn (old behavior);
 *                                 //   default: the block reason is reported to the model as a
 *                                 //   tool error and the turn continues
 *   }
 *
 * A third, highest-precedence MANAGED scope exists for admin/fleet use:
 * /etc/pi/agent/sandbox.json (Windows: %ProgramData%\pi\agent\sandbox.json).
 * Scalar keys there win outright (an admin can pin enabled: true);
 * "writable" can only be narrowed (intersected) by lower scopes.
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
  type BashOperations,
  CONFIG_DIR_NAME,
  createLocalBashOperations,
  getAgentDir,
  isToolCallEventType,
} from "@earendil-works/pi-coding-agent";
import { type SelectItem, SelectList, type SelectListTheme, Text } from "@earendil-works/pi-tui";
import {
  applyManagedSandboxConfig,
  applySandboxToggle,
  buildWritableRoots,
  canonicalizeTarget,
  describeSandboxState,
  isInsideAnyRoot,
  managedSandboxConfigPath,
  mergeSandboxConfigs,
  parseSandboxConfig,
  parseWritableList,
  type RunnerContext,
  SANDBOX_RUNNER_CHOICES,
  type SandboxConfig,
  type SandboxPolicy,
  type SandboxRunnerChoice,
  type SandboxScope,
  type SandboxState,
  sandboxConfigPath,
  sandboxStateSignature,
  wrapCommand,
} from "./lib/sandbox-utils.js";
import { findDangerousPowerShellRule } from "./permission-gate/powershell-rules.js";
import { findDangerousRule } from "./permission-gate/rules.js";
import { resolveRunner } from "./permission-gate/runner.js";

const SANDBOX_CONFIG_FILE = "sandbox.json";

const USAGE =
  "Usage:\n" +
  "  /sandbox          show live status\n" +
  '  /sandbox on       enable (project scope; runner defaults to "auto"; an explicit runner in either scope is kept)\n' +
  "  /sandbox off      disable (project scope)\n" +
  "  /sandbox config   interactive editor (pick the global or project scope)";

/** Both scope config file paths for a working directory. */
function sandboxConfigFiles(cwd: string): Record<SandboxScope, string> {
  const base = { agentDir: getAgentDir(), projectDir: path.join(cwd, CONFIG_DIR_NAME) };
  return {
    global: sandboxConfigPath("global", base),
    project: sandboxConfigPath("project", base),
  };
}

export type LoadedSandboxConfigs = {
  /** Merged config (per-key project wins, then the managed layer). Empty on error. */
  config: SandboxConfig;
  /** Per-scope configs as read (project is {} when untrusted or on error). */
  globalConfig: SandboxConfig;
  projectConfig: SandboxConfig;
  /** Managed (admin) config as read; {} when the file is absent. */
  managedConfig: SandboxConfig;
  files: Record<SandboxScope, string>;
  /** Managed config file path (highest precedence). */
  managedFile: string;
  /** Set when any scope file failed to parse/validate. */
  error?: string;
  /** Advisory warning (e.g. a lower scope was invalid but the managed
   * policy is enforced anyway). */
  warning?: string;
  /** A malformed MANAGED file: fail closed — refuse to run without a
   * verified admin policy. */
  managedFailClosed?: boolean;
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
  const managedFile = managedSandboxConfigPath(process.platform, process.env.PROGRAMDATA);
  // The managed layer is read INDEPENDENTLY: a malformed user file must not
  // drop the admin policy, and vice versa.
  let managedConfig: SandboxConfig | undefined;
  let managedError: string | undefined;
  try {
    managedConfig = readScopeConfig(managedFile);
  } catch (err) {
    managedError = String(err instanceof Error ? err.message : err);
  }
  let globalConfig: SandboxConfig;
  let projectConfig: SandboxConfig;
  try {
    globalConfig = readScopeConfig(files.global);
    projectConfig = projectTrusted ? readScopeConfig(files.project) : {};
  } catch (err) {
    const lowerError = String(err instanceof Error ? err.message : err);
    if (managedError) {
      return {
        config: {},
        globalConfig: {},
        projectConfig: {},
        managedConfig: {},
        files,
        managedFile,
        error: `${lowerError}; managed: ${managedError}`,
        managedFailClosed: true,
      };
    }
    if (managedConfig && Object.keys(managedConfig).length > 0) {
      // A lower-scope error must not defeat managed enforcement: run the
      // managed policy alone (fail-closed if it says so).
      return {
        config: applyManagedSandboxConfig({}, managedConfig),
        globalConfig: {},
        projectConfig: {},
        managedConfig,
        files,
        managedFile,
        warning: `${lowerError} — managed policy enforced instead`,
      };
    }
    return {
      config: {},
      globalConfig: {},
      projectConfig: {},
      managedConfig: {},
      files,
      managedFile,
      error: lowerError,
    };
  }
  if (managedError) {
    // A malformed managed file fails closed: refuse to run without a
    // verified admin policy.
    return {
      config: {},
      globalConfig: {},
      projectConfig: {},
      managedConfig: {},
      files,
      managedFile,
      error: `managed config invalid: ${managedError}`,
      managedFailClosed: true,
    };
  }
  return {
    config: applyManagedSandboxConfig(
      mergeSandboxConfigs(globalConfig, projectConfig),
      managedConfig ?? {},
    ),
    globalConfig,
    projectConfig,
    managedConfig: managedConfig ?? {},
    files,
    managedFile,
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
      label: `homeCaches: ${draft.homeCaches ?? "ro"}`,
      description: "writable $HOME cache dirs (~/.cache, ~/.npm, ~/.cargo, …); ro = strict",
    },
    {
      value: "userCommands",
      label: `userCommands: ${draft.userCommands ?? "false"}`,
      description: "also sandbox user ! commands",
    },
    {
      value: "loginShell",
      label: `loginShell: ${draft.loginShell ?? "true"}`,
      description: "true: bash -lc (sources ~/.bash_profile); false: plain bash -c",
    },
    {
      value: "landlockHelper",
      label: `landlockHelper: ${draft.landlockHelper ?? "(compile on first use)"}`,
      description: "prebuilt Landlock helper path (skips compilation; Linux only)",
    },
    {
      value: "failIfUnavailable",
      label: `failIfUnavailable: ${draft.failIfUnavailable ?? "false"}`,
      description: "block commands instead of running unsandboxed when no runner resolves",
    },
    {
      value: "blockTerminates",
      label: `blockTerminates: ${draft.blockTerminates ?? "false"}`,
      description: "stop the agent's turn on a gate block instead of letting it continue",
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
  let managedConfig: SandboxConfig = {};
  let state: SandboxState = { active: false, enabled: false };
  let localBashOps: ReturnType<typeof createLocalBashOperations> | undefined;

  const runnerContext = (cwd: string): RunnerContext => ({
    cwd,
    homeDir: os.homedir(),
    shellPath: "/bin/bash",
    helperPath: state.active ? state.helperPath : undefined,
    tmpDir: process.env.TMPDIR,
  });

  /** Block result honoring blockTerminates: by default the reason is fed
   *  back to the model as a tool error and the turn CONTINUES (the model
   *  reads the reason and adapts); blockTerminates: true restores the old
   *  behavior of stopping the turn after the current tool batch. */
  const blocked = (reason: string): { block: boolean; reason: string; terminate?: boolean } =>
    config.blockTerminates === true
      ? { block: true, terminate: true, reason }
      : { block: true, reason };

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
    const probe = resolveRunner(cfg.runner ?? "auto", { landlockHelper: cfg.landlockHelper });
    if (!probe.ok) {
      const failClosed = cfg.failIfUnavailable === true;
      return {
        state: { active: false, enabled: true, reason: probe.reason, failClosed },
        warnings: [
          failClosed
            ? `Sandbox enabled with failIfUnavailable: no runner available (${probe.reason}). Bash/PowerShell/write/edit will be BLOCKED rather than run unsandboxed.`
            : `Sandbox enabled but no runner available (${probe.reason}). Commands run UNSANDBOXED; all permission gates are armed.`,
        ],
      };
    }
    const { roots, missingWritable } = buildWritableRoots(
      cfg,
      runnerContext(cwd),
      dirExists,
      canon,
    );
    const policy = {
      writableRoots: roots,
      network: cfg.network ?? "allow",
      loginShell: cfg.loginShell ?? true,
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
      warnings: [
        ...missingWritable.map(
          (p) =>
            `Sandbox: writable path "${p}" does not exist — OMITTED (create it manually; it is never widened to its parent).`,
        ),
        ...(policy.network === "deny" && !networkEnforced
          ? [
              "Sandbox: landlock cannot enforce network policy; network=deny is IGNORED (use bwrap to enforce).",
            ]
          : []),
      ],
    };
  }

  /** Set config+state from a merged config. Capability warnings are ALWAYS
   *  surfaced; the verbose "Sandbox active" line only when announce is set. */
  function applySandbox(
    cfg: SandboxConfig,
    ui: ExtensionUIContext,
    cwd: string,
    announce: boolean,
    managed: SandboxConfig,
  ): SandboxState {
    config = cfg;
    managedConfig = managed;
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
      state = {
        active: false,
        enabled: true,
        reason: `invalid config: ${loaded.error}`,
        failClosed: loaded.managedFailClosed,
      };
      ctx.ui.notify(
        loaded.managedFailClosed
          ? `Sandbox config invalid (${loaded.error}) — fail-closed: commands are BLOCKED until the config is fixed`
          : `Sandbox disabled: ${loaded.error}`,
        "warning",
      );
      return;
    }
    if (loaded.warning) ctx.ui.notify(loaded.warning, "warning");
    applySandbox(loaded.config, ctx.ui, ctx.cwd, true, loaded.managedConfig);
  });

  // --- Tell the MODEL about sandbox state changes -------------------------
  // Toggles (/sandbox on|off, config edits) are only visible to the user in the
  // TUI; without this the model keeps assuming the old restrictions (or their
  // absence) and mistakes an intentional toggle for a transient failure.
  let lastStateSignature: string | undefined;

  pi.on("before_agent_start", (event) => {
    const signature = sandboxStateSignature(state);
    const first = lastStateSignature === undefined;
    const changed = !first && signature !== lastStateSignature;
    lastStateSignature = signature;
    // First turn of an extension instance (session start OR /reload): always
    // state the current sandbox state — including inactive/fail-closed, which
    // the model most needs to know. Afterwards: announce only real changes
    // (the signature covers runner, writable roots, and network enforcement)
    // plus a standing line while active.
    if (!first && !changed && !state.active) return;
    const notes: string[] = [];
    if (changed)
      notes.push(
        `[sandbox] State changed since your last turn — now ${describeSandboxState(state)}. This is an intentional user action, not a transient error: update your assumptions about which paths are writable and whether commands are restricted.`,
      );
    if (first || state.active)
      notes.push(`[sandbox] Current state: ${describeSandboxState(state)}.`);
    return { systemPrompt: `${event.systemPrompt}\n\n${notes.join("\n")}` };
  });

  pi.on("tool_call", async (event, ctx) => {
    // --- write/edit path guard (tools write directly, no shell involved) ---
    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      if (!state.active) {
        if (state.enabled && state.failClosed) {
          return blocked(
            `Sandbox: no runner available (${state.reason}) and failIfUnavailable is set — refusing unsandboxed writes`,
          );
        }
        return undefined;
      }
      const target = path.resolve(ctx.cwd, String((event.input as { path?: string }).path ?? ""));
      // Containment must compare like-with-like: roots are canonicalized in
      // buildWritableRoots, so canonicalize the target the same way (deepest
      // existing ancestor + missing tail) or /tmp/file would miss /private/tmp.
      if (isInsideAnyRoot(canonicalizeTarget(target, dirExists, canon), state.policy.writableRoots))
        return undefined;
      if (!ctx.hasUI) {
        return blocked(
          `Sandbox: ${target} is outside the writable roots and there is no UI to confirm`,
        );
      }
      const ok = await ctx.ui.confirm(
        `Sandbox: write outside writable roots`,
        `${target}\n\nAllow this write?`,
        { signal: ctx.signal },
      );
      if (!ok) return blocked(`Sandbox: write outside writable roots (declined): ${target}`);
      return undefined;
    }

    const isPowerShell = isToolCallEventType("powershell", event);
    if (!isToolCallEventType("bash", event) && !isPowerShell) return undefined;
    // Fail-closed: sandbox enabled + failIfUnavailable but no runner
    // resolved — refuse to run unsandboxed (bash and powershell alike).
    if (!state.active && state.enabled && state.failClosed) {
      return blocked(
        `Sandbox: no runner available (${state.reason}) and failIfUnavailable is set — refusing to run unsandboxed`,
      );
    }
    const command = String(event.input.command ?? "");

    // --- heuristic gate (checked on the ORIGINAL command, before wrapping) ---
    // PowerShell has its own rule set: cmdlets/aliases/parameters differ
    // from bash, so it is NEVER routed through the bash tokenizer.
    const match = isPowerShell ? findDangerousPowerShellRule(command) : findDangerousRule(command);
    if (match) {
      if (match.disposition === "deny") {
        return blocked(
          `Blocked: "${match.name}" is hard-blocked (human-only). Run it manually outside the agent.`,
        );
      }
      if (!ctx.hasUI) {
        return blocked(`Blocked: "${match.name}" heuristic matched and there is no UI to confirm`);
      }
      const ok = await ctx.ui.confirm(`⚠️ Dangerous command (${match.name})`, command, {
        signal: ctx.signal,
      });
      if (!ok) return blocked("Blocked by user");
    }

    // --- sandbox wrap (bash only: the wrappers build a bash command line) ---
    if (!isPowerShell && state.active && command) {
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
    if (!config.userCommands) return undefined;
    if (!state.active) {
      // Fail-closed: user ! commands are blocked too, not run unsandboxed.
      if (state.enabled && state.failClosed) {
        const reason = `Sandbox: no runner available (${state.reason}) and failIfUnavailable is set — user ! commands are blocked`;
        return {
          operations: {
            async exec(
              _command: string,
              _cwd: string,
              options: Parameters<BashOperations["exec"]>[2],
            ) {
              options.onData(Buffer.from(reason));
              return { exitCode: 126 };
            },
          },
        };
      }
      return undefined;
    }
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
      applyManagedSandboxConfig(
        mergeSandboxConfigs(loaded.globalConfig, toggled),
        loaded.managedConfig,
      ),
      ctx.ui,
      ctx.cwd,
      false,
      loaded.managedConfig,
    );
    if (!enabled) {
      if (next.enabled) {
        ctx.ui.notify(
          "Sandbox remains enabled: a managed policy pins enabled: true (lower scopes cannot turn it off)",
          "warning",
        );
      } else {
        ctx.ui.notify("Sandbox off", "info");
      }
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
          value: "ro",
          label: "ro",
          description: "every $HOME subdir stays read-only (default)",
        },
        {
          value: "rw",
          label: "rw",
          description:
            "~/.cache, ~/.npm, ~/.cargo, … are writable (opt-in; some hold credentials/executables)",
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
    if (option === "loginShell") {
      const v = await promptSelect(ctx, "Login shell for sandboxed commands", [
        {
          value: "true",
          label: "true",
          description: "bash -lc — sources /etc/profile + ~/.bash_profile (default)",
        },
        {
          value: "false",
          label: "false",
          description: "bash -c — no login profiles; inherited env and BASH_ENV still apply",
        },
      ]);
      return v === undefined ? undefined : { loginShell: v === "true" };
    }
    if (option === "landlockHelper") {
      const v = await ctx.ui.input(
        "Prebuilt Landlock helper path (empty = compile on first use)",
        draft.landlockHelper ?? "",
        { signal: ctx.signal },
      );
      if (v === undefined) return undefined;
      const trimmed = v.trim();
      return trimmed === "" ? { landlockHelper: undefined } : { landlockHelper: trimmed };
    }
    if (option === "failIfUnavailable") {
      const v = await promptSelect(ctx, "Fail closed when no sandbox runner is available", [
        {
          value: "false",
          label: "false",
          description: "warn and run unsandboxed (default; interactive/dev use)",
        },
        {
          value: "true",
          label: "true",
          description: "BLOCK bash/powershell/write/edit when the boundary can't be established",
        },
      ]);
      return v === undefined ? undefined : { failIfUnavailable: v === "true" };
    }
    if (option === "blockTerminates") {
      const v = await promptSelect(
        ctx,
        "Terminate the agent's turn when the gate blocks a command",
        [
          {
            value: "false",
            label: "false",
            description:
              "report the block reason to the model as a tool error; the turn continues (default)",
          },
          {
            value: "true",
            label: "true",
            description: "stop the turn after the current tool batch (previous behavior)",
          },
        ],
      );
      return v === undefined ? undefined : { blockTerminates: v === "true" };
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
    applySandbox(reloaded.config, ctx.ui, ctx.cwd, true, reloaded.managedConfig);
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
        if (state.failClosed) {
          lines.push("failIfUnavailable: bash/powershell/write/edit are BLOCKED (fail-closed).");
        } else {
          lines.push("Commands run unsandboxed; ALL permission gates are armed.");
        }
      }
      const files = sandboxConfigFiles(ctx.cwd);
      const trustNote = ctx.isProjectTrusted() ? "" : " (not trusted)";
      const managedLine =
        Object.keys(managedConfig).length > 0
          ? ` / ${managedSandboxConfigPath(process.platform, process.env.PROGRAMDATA)} (managed, wins)`
          : "";
      lines.push(
        `Config: ${files.project} (project, wins per-key)${trustNote} / ${files.global} (global)${managedLine}`,
      );
      lines.push(
        "Gate: irreversible-action rules (recursive rm, world-writable chmod, destructive git, remote destruction, …) are ALWAYS gated, sandboxed or not; raw host-disk operations are hard-blocked (human-only).",
      );
      lines.push(
        config.blockTerminates
          ? "Gate blocks stop the agent's turn (blockTerminates: true)."
          : "Gate blocks report the reason to the model as a tool error and the turn continues (blockTerminates: true stops the turn instead).",
      );
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
