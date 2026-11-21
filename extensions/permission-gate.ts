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
 *      TRUNCATE via known DB clients), download-to-shell pipes, service
 *      stops, broad recursive chown, network socket redirects
 *      (/dev/tcp, /dev/udp — incl. the reverse-shell form), and shell
 *      payloads (`bash -c`/`eval` seen through: literal payloads re-gated
 *      recursively, dynamic ones confirmed) — and, via a separate
 *      PowerShell rule set, dangerous cmdlets (recursive `Remove-Item`,
 *      elevation, `iex`, ACL changes, machine-wide registry writes,
 *      `-EncodedCommand` decoded and re-gated).
 *    - DENY (hard block, human-only, NO prompt): raw host-disk destruction
 *      (`dd`/redirect/`tee`/`cp`/`mv`/`shred` to /dev/*, wipefs, blkdiscard,
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
  ExtensionContext,
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
  danglingSymlinkTarget,
  describeSandboxState,
  isInsideAnyRoot,
  MAX_CLASSIFIER_TIMEOUT_MS,
  managedSandboxConfigPath,
  mergeSandboxConfigs,
  parseSandboxConfig,
  parseWritableList,
  type RunnerContext,
  SANDBOX_RUNNER_CHOICES,
  type SandboxConfig,
  type SandboxRunnerChoice,
  type SandboxScope,
  type SandboxState,
  sandboxConfigPath,
  sandboxStateSignature,
  wrapCommand,
} from "./lib/sandbox-utils.js";
import {
  buildClassifierRequest,
  type ClassifierShell,
  DEFAULT_CONFIRM_THRESHOLD,
  DEFAULT_DENY_THRESHOLD,
  DEFAULT_JEV_MODEL,
  decideClassifier,
  effectiveThresholds,
  parseClassifierProbs,
  TYPESAFE_API_KEY_ENV,
} from "./permission-gate/classifier.js";
import { callJev, DEFAULT_CLASSIFIER_TIMEOUT_MS } from "./permission-gate/jev-client.js";
import { findStaticMatch } from "./permission-gate/rules.js";
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
  /** Set when any scope file failed to parse/validate. `config` still holds
   * the merge of the scopes that DID validate (scopes are read
   * independently, so a broken project file cannot discard a valid global
   * failIfUnavailable/enabled policy). Only {} when managed failed closed. */
  error?: string;
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
  // Every scope is read INDEPENDENTLY: a malformed file must not discard the
  // other scopes' validated policy (a broken project file must not drop a
  // valid global failIfUnavailable, and a broken user file must not drop the
  // admin policy).
  let managedConfig: SandboxConfig | undefined;
  let managedError: string | undefined;
  try {
    managedConfig = readScopeConfig(managedFile);
  } catch (err) {
    managedError = String(err instanceof Error ? err.message : err);
  }
  let globalConfig: SandboxConfig = {};
  let projectConfig: SandboxConfig = {};
  const lowerErrors: string[] = [];
  try {
    globalConfig = readScopeConfig(files.global);
  } catch (err) {
    lowerErrors.push(`global: ${String(err instanceof Error ? err.message : err)}`);
  }
  if (projectTrusted) {
    try {
      projectConfig = readScopeConfig(files.project);
    } catch (err) {
      lowerErrors.push(`project: ${String(err instanceof Error ? err.message : err)}`);
    }
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
  // Managed keys still win outright over the surviving lower scopes
  // (applyManagedSandboxConfig), so a lower-scope error cannot defeat managed
  // enforcement; the valid lower scopes simply fill the keys managed omits.
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
    error: lowerErrors.length > 0 ? lowerErrors.join("; ") : undefined,
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

/** The classifier config keys, editable from the config menu. */
const CLASSIFIER_OPTIONS = [
  "classifier",
  "classifierConfirmThreshold",
  "classifierDenyThreshold",
  "classifierModel",
  "classifierTimeoutMs",
] as const;
type ClassifierOption = (typeof CLASSIFIER_OPTIONS)[number];

/** Membership guard so the menu dispatch can't route a typo into the editor. */
function isClassifierOption(option: string): option is ClassifierOption {
  return (CLASSIFIER_OPTIONS as readonly string[]).includes(option);
}

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
    {
      value: "classifier",
      label: `classifier: ${draft.classifier ?? "off"}`,
      description:
        "optional Jev danger classifier for commands the static rules miss (needs TYPESAFE_API_KEY)",
    },
    {
      value: "classifierConfirmThreshold",
      label: `classifierConfirmThreshold: ${draft.classifierConfirmThreshold ?? DEFAULT_CONFIRM_THRESHOLD}`,
      description: `Jev probability at/above which a command prompts for confirmation (default ${DEFAULT_CONFIRM_THRESHOLD})`,
    },
    {
      value: "classifierDenyThreshold",
      label: `classifierDenyThreshold: ${draft.classifierDenyThreshold ?? DEFAULT_DENY_THRESHOLD}`,
      description: `Jev probability at/above which a command is hard-blocked (default ${DEFAULT_DENY_THRESHOLD})`,
    },
    {
      value: "classifierModel",
      label: `classifierModel: ${draft.classifierModel ?? DEFAULT_JEV_MODEL}`,
      description: "Jev model id (default jev-latest)",
    },
    {
      value: "classifierTimeoutMs",
      label: `classifierTimeoutMs: ${draft.classifierTimeoutMs ?? DEFAULT_CLASSIFIER_TIMEOUT_MS}`,
      description: `per-call Jev request timeout in ms (default ${DEFAULT_CLASSIFIER_TIMEOUT_MS})`,
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
  // Warn-once flags for the optional Jev classifier (reset on /reload, which
  // recreates the extension instance — an acceptable re-warn).
  let classifierNoKeyWarned = false;
  let classifierApiWarned = false;

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

  /** One-time classifier warning: TUI/RPC get a notify; headless (print/JSON)
   *  gets a stderr line so stdout stays clean. */
  function warnClassifier(ctx: ExtensionContext, msg: string): void {
    if (ctx.hasUI) {
      ctx.ui.notify(msg, "warning");
    } else {
      process.stderr.write(`[permission-gate] ${msg}\n`);
    }
  }

  /**
   * Optional Jev classifier (third gate tier). Runs only when the static rules
   * did NOT match — it is the semantic safety net for obscured/novel commands,
   * not a re-run of the deterministic rules. Returns a block result when the
   * verdict is deny, a confirm is declined, or there is no UI; undefined to
   * proceed. Fails OPEN (proceed + one-time warning) when the key is missing or
   * the call errors — the static tier still guards the hard cases.
   */
  /** Warn once about a classifier issue (guarded by a module-level flag). */
  function warnClassifierOnce(
    ctx: ExtensionContext,
    flag: () => boolean,
    setFlag: () => void,
    message: string,
  ): void {
    if (flag()) return;
    setFlag();
    warnClassifier(ctx, message);
  }

  async function runJevClassifier(
    command: string,
    ctx: ExtensionContext,
    shell: ClassifierShell,
  ): Promise<{ block: boolean; reason: string; terminate?: boolean } | undefined> {
    if (config.classifier !== "jev" || !command) return undefined;
    const apiKey = process.env[TYPESAFE_API_KEY_ENV];
    if (!apiKey) {
      warnClassifierOnce(
        ctx,
        () => classifierNoKeyWarned,
        () => (classifierNoKeyWarned = true),
        `Classifier enabled (classifier: jev) but ${TYPESAFE_API_KEY_ENV} is not set — Jev classification is skipped.`,
      );
      return undefined;
    }
    const model = config.classifierModel ?? DEFAULT_JEV_MODEL;
    const result = await callJev(buildClassifierRequest(command, model, shell), {
      apiKey,
      timeoutMs: config.classifierTimeoutMs,
      signal: ctx.signal,
    });
    if (!result.ok) {
      if (result.cancelled) return undefined;
      warnClassifierOnce(
        ctx,
        () => classifierApiWarned,
        () => (classifierApiWarned = true),
        `Jev classifier unavailable (${result.error}) — failing open; static rules still apply.`,
      );
      return undefined;
    }
    const probs = parseClassifierProbs(result.body);
    if (!probs) {
      warnClassifierOnce(
        ctx,
        () => classifierApiWarned,
        () => (classifierApiWarned = true),
        "Jev classifier returned a malformed response — failing open; static rules still apply.",
      );
      return undefined;
    }
    return handleClassifierVerdict(
      decideClassifier(probs, effectiveThresholds(config)),
      command,
      ctx,
    );
  }

  async function handleClassifierVerdict(
    verdict: ReturnType<typeof decideClassifier>,
    command: string,
    ctx: ExtensionContext,
  ): Promise<{ block: boolean; reason: string; terminate?: boolean } | undefined> {
    if (verdict.action === "deny") {
      return blocked(
        `Blocked: Jev classified this command as high-risk (${verdict.label}). This is a model judgment, not a static rule — review before running it manually.`,
      );
    }
    if (verdict.action === "confirm") {
      if (!ctx.hasUI)
        return blocked(
          `Blocked: Jev flagged this command (${verdict.label}) and there is no UI to confirm`,
        );
      const ok = await ctx.ui.confirm(`⚠️ Jev flagged this command (${verdict.label})`, command, {
        signal: ctx.signal,
      });
      if (!ok) return blocked("Blocked by user");
    }
    return undefined;
  }

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

  /** Write-guard target predicates: a path "exists" for canonicalization if
   * it stats OR is a dangling symlink (lstat sees the link even when its
   * target is gone). canon resolves a dangling link LEXICALLY via readlink
   * (realpathSync throws on it), so a link inside a writable root pointing
   * outside is judged by its TARGET, not its link path. */
  const targetExists = (p: string): boolean => {
    try {
      fs.statSync(p);
      return true;
    } catch {
      try {
        return fs.lstatSync(p).isSymbolicLink();
      } catch {
        return false;
      }
    }
  };
  const targetCanon = (p: string): string => {
    try {
      return fs.realpathSync(p);
    } catch {
      // realpathSync throws on a dangling symlink: resolve its target
      // lexically instead (danglingSymlinkTarget), or keep the input.
      return (
        danglingSymlinkTarget(
          p,
          (q) => {
            try {
              return fs.lstatSync(q).isSymbolicLink();
            } catch {
              return false;
            }
          },
          (q) => fs.readlinkSync(q),
        ) ?? p
      );
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
    if (loaded.managedFailClosed) {
      state = {
        active: false,
        enabled: true,
        reason: `invalid config: ${loaded.error}`,
        failClosed: true,
      };
      ctx.ui.notify(
        `Sandbox config invalid (${loaded.error}) — fail-closed: commands are BLOCKED until the config is fixed`,
        "warning",
      );
      return;
    }
    // A malformed lower-scope file no longer disables the sandbox: the valid
    // scopes (incl. any managed policy) are applied, with a warning.
    if (loaded.error)
      ctx.ui.notify(
        `Sandbox config error: ${loaded.error} — applying the remaining valid scopes`,
        "warning",
      );
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

  /** Guard the write/edit path: contain within writable roots or confirm. */
  async function guardWriteEdit(
    event: { input: Record<string, unknown> },
    ctx: ExtensionContext,
  ): Promise<{ block: boolean; reason: string; terminate?: boolean } | undefined> {
    if (!state.active) {
      if (state.enabled && state.failClosed) {
        return blocked(
          `Sandbox: no runner available (${state.reason}) and failIfUnavailable is set — refusing unsandboxed writes`,
        );
      }
      return undefined;
    }
    const target = path.resolve(ctx.cwd, String((event.input as { path?: string }).path ?? ""));
    if (
      isInsideAnyRoot(
        canonicalizeTarget(target, targetExists, targetCanon),
        state.policy.writableRoots,
      )
    )
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

  /** Guard the bash/powershell path: static rules, Jev classifier, sandbox wrap. */
  async function guardShell(
    event: { input: Record<string, unknown> },
    command: string,
    isPowerShell: boolean,
    ctx: ExtensionContext,
  ): Promise<{ block: boolean; reason: string; terminate?: boolean } | undefined> {
    if (!state.active && state.enabled && state.failClosed) {
      return blocked(
        `Sandbox: no runner available (${state.reason}) and failIfUnavailable is set — refusing to run unsandboxed`,
      );
    }
    const match = findStaticMatch(isPowerShell ? "powershell" : "bash", command);
    const staticBlock = match ? await confirmStaticMatch(match, command, ctx) : undefined;
    if (staticBlock) return staticBlock;
    if (!match) {
      const jevBlock = await runJevClassifier(command, ctx, isPowerShell ? "powershell" : "bash");
      if (jevBlock) return jevBlock;
    }
    if (!isPowerShell && state.active && command) {
      (event.input as { command: string }).command = wrapCommand(
        state.runner,
        command,
        state.policy,
        runnerContext(ctx.cwd),
      );
    }
    return undefined;
  }

  async function confirmStaticMatch(
    match: NonNullable<ReturnType<typeof findStaticMatch>>,
    command: string,
    ctx: ExtensionContext,
  ): Promise<{ block: boolean; reason: string; terminate?: boolean } | undefined> {
    if (match.disposition === "deny")
      return blocked(
        `Blocked: "${match.name}" is hard-blocked (human-only). Run it manually outside the agent.`,
      );
    if (!ctx.hasUI)
      return blocked(`Blocked: "${match.name}" heuristic matched and there is no UI to confirm`);
    const ok = await ctx.ui.confirm(`⚠️ Dangerous command (${match.name})`, command, {
      signal: ctx.signal,
    });
    return ok ? undefined : blocked("Blocked by user");
  }

  pi.on("tool_call", async (event, ctx) => {
    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      return guardWriteEdit(event, ctx);
    }
    const isPowerShell = isToolCallEventType("powershell", event);
    if (!isToolCallEventType("bash", event) && !isPowerShell) return undefined;
    const command = String(event.input.command ?? "");
    return guardShell(event, command, isPowerShell, ctx);
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

  /** Edit one classifier option; undefined = the user bailed. Kept separate so
   *  editSandboxOption stays under the cognitive-complexity cap. Exhaustive:
   *  a new ClassifierOption member is a compile error until handled here. */
  /** Prompt a 0-1 threshold value and return the partial config (or throw if invalid). */
  async function promptThreshold(
    ctx: ExtensionCommandContext,
    option: "classifierConfirmThreshold" | "classifierDenyThreshold",
    label: string,
    defaultValue: number,
    errorPrefix: string,
  ): Promise<Partial<SandboxConfig>> {
    const v = await ctx.ui.input(label, String(defaultValue), { signal: ctx.signal });
    if (v === undefined) throw new Error("cancelled");
    if (v.trim() === "") throw new Error("enter a number between 0 and 1");
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0 || n > 1)
      throw new Error(`${errorPrefix} must be a number between 0 and 1`);
    return { [option]: n } as Partial<SandboxConfig>;
  }

  async function editClassifierOption(
    ctx: ExtensionCommandContext,
    option: ClassifierOption,
    draft: SandboxConfig,
  ): Promise<Partial<SandboxConfig> | undefined> {
    switch (option) {
      case "classifier": {
        const v = await promptSelect(ctx, "Danger classifier", [
          { value: "off", label: "off", description: "static rules only (default)" },
          {
            value: "jev",
            label: "jev",
            description: "ask TypeSafe Jev when the static rules miss (needs TYPESAFE_API_KEY)",
          },
        ]);
        return v === undefined ? undefined : { classifier: v as "off" | "jev" };
      }
      case "classifierConfirmThreshold":
        return promptThreshold(
          ctx,
          "classifierConfirmThreshold",
          "Classifier confirm threshold (0-1)",
          draft.classifierConfirmThreshold ?? DEFAULT_CONFIRM_THRESHOLD,
          "confirm",
        );
      case "classifierDenyThreshold":
        return promptThreshold(
          ctx,
          "classifierDenyThreshold",
          "Classifier deny threshold (0-1)",
          draft.classifierDenyThreshold ?? DEFAULT_DENY_THRESHOLD,
          "deny",
        );
      case "classifierModel": {
        return promptClassifierModel(ctx, draft);
      }
      case "classifierTimeoutMs": {
        return promptClassifierTimeout(ctx, draft);
      }
    }
    // Unreachable: the switch above is exhaustive over ClassifierOption.
    const exhaustive: never = option;
    return exhaustive;
  }

  async function promptClassifierModel(
    ctx: ExtensionCommandContext,
    draft: SandboxConfig,
  ): Promise<Partial<SandboxConfig> | undefined> {
    const value = await ctx.ui.input(
      "Classifier model id (empty = default jev-latest)",
      draft.classifierModel ?? DEFAULT_JEV_MODEL,
      { signal: ctx.signal },
    );
    if (value === undefined) return undefined;
    const trimmed = value.trim();
    return trimmed === "" ? { classifierModel: undefined } : { classifierModel: trimmed };
  }

  async function promptClassifierTimeout(
    ctx: ExtensionCommandContext,
    draft: SandboxConfig,
  ): Promise<Partial<SandboxConfig> | undefined> {
    const value = await ctx.ui.input(
      "Classifier timeout in ms",
      String(draft.classifierTimeoutMs ?? DEFAULT_CLASSIFIER_TIMEOUT_MS),
      { signal: ctx.signal },
    );
    if (value === undefined) return undefined;
    if (value.trim() === "") throw new Error("enter a positive number of ms");
    const timeout = Number(value);
    if (!Number.isFinite(timeout) || timeout < 1 || timeout > MAX_CLASSIFIER_TIMEOUT_MS)
      throw new Error(`timeout must be a number between 1 and ${MAX_CLASSIFIER_TIMEOUT_MS} ms`);
    return { classifierTimeoutMs: Math.round(timeout) };
  }

  // --- one option edit in the config UI; undefined = the user bailed ---
  /** Prompt a true/false option and return the partial config (or undefined if cancelled). */
  async function promptBoolOption(
    ctx: ExtensionCommandContext,
    option: keyof SandboxConfig,
    label: string,
    trueDesc: string,
    falseDesc: string,
    trueFirst = false,
  ): Promise<Partial<SandboxConfig> | undefined> {
    const choices = trueFirst
      ? [
          { value: "true", label: "true", description: trueDesc },
          { value: "false", label: "false", description: falseDesc },
        ]
      : [
          { value: "false", label: "false", description: falseDesc },
          { value: "true", label: "true", description: trueDesc },
        ];
    const v = await promptSelect(ctx, label, choices);
    if (v === undefined) return undefined;
    return { [option]: v === "true" } as Partial<SandboxConfig>;
  }

  /** Prompt a string-enum option and return the partial config (or undefined if cancelled). */
  async function promptEnumOption<T extends string>(
    ctx: ExtensionCommandContext,
    option: keyof SandboxConfig,
    label: string,
    choices: Array<{ value: T; label: string; description: string }>,
  ): Promise<Partial<SandboxConfig> | undefined> {
    const v = await promptSelect(ctx, label, choices);
    if (v === undefined) return undefined;
    return { [option]: v } as Partial<SandboxConfig>;
  }

  // --- one option edit in the config UI; undefined = the user bailed ---
  async function editSandboxOption(
    ctx: ExtensionCommandContext,
    option: string,
    draft: SandboxConfig,
  ): Promise<Partial<SandboxConfig> | undefined> {
    if (option === "enabled")
      return promptBoolOption(
        ctx,
        "enabled",
        "Sandbox enabled",
        "wrap bash commands in the OS sandbox",
        "gate-only — prompts, no OS isolation",
        true,
      );
    if (option === "runner")
      return promptEnumOption(
        ctx,
        "runner",
        "Sandbox runner",
        SANDBOX_RUNNER_CHOICES.map((choice) => ({
          value: choice,
          label: choice,
          description: RUNNER_DESCRIPTIONS[choice],
        })),
      );
    if (option === "network")
      return promptEnumOption(ctx, "network", "Sandbox network policy", [
        { value: "allow", label: "allow", description: "sandboxed commands can reach the network" },
        { value: "deny", label: "deny", description: "block outbound network (no-op on landlock)" },
      ]);
    if (option === "home" || option === "homeCaches" || option === "userCommands")
      return editSandboxAccessOption(ctx, option);
    if (option === "loginShell" || option === "landlockHelper")
      return editSandboxRuntimeOption(ctx, option, draft);
    if (option === "failIfUnavailable")
      return promptBoolOption(
        ctx,
        "failIfUnavailable",
        "Fail closed when no sandbox runner is available",
        "BLOCK bash/powershell/write/edit when the boundary can't be established",
        "warn and run unsandboxed (default; interactive/dev use)",
      );
    if (option === "blockTerminates")
      return promptBoolOption(
        ctx,
        "blockTerminates",
        "Terminate the agent's turn when the gate blocks a command",
        "stop the turn after the current tool batch (previous behavior)",
        "report the block reason to the model as a tool error; the turn continues (default)",
      );
    if (isClassifierOption(option)) {
      return editClassifierOption(ctx, option, draft);
    }
    return promptWritable(ctx, draft);
  }

  async function editSandboxAccessOption(
    ctx: ExtensionCommandContext,
    option: string,
  ): Promise<Partial<SandboxConfig> | undefined> {
    if (option === "home")
      return promptEnumOption(ctx, "home", "$HOME access in the sandbox", [
        { value: "ro", label: "ro", description: "$HOME is read-only (default)" },
        { value: "rw", label: "rw", description: "$HOME is writable" },
      ]);
    if (option === "homeCaches")
      return promptEnumOption(ctx, "homeCaches", "Writable $HOME cache dirs", [
        { value: "ro", label: "ro", description: "every $HOME subdir stays read-only (default)" },
        {
          value: "rw",
          label: "rw",
          description:
            "~/.cache, ~/.npm, ~/.cargo, … are writable (opt-in; some hold credentials/executables)",
        },
      ]);
    return promptBoolOption(
      ctx,
      "userCommands",
      "Sandbox user ! commands",
      "user ! commands also run sandboxed",
      "user ! commands bypass the sandbox (default)",
      true,
    );
  }

  async function editSandboxRuntimeOption(
    ctx: ExtensionCommandContext,
    option: string,
    draft: SandboxConfig,
  ): Promise<Partial<SandboxConfig> | undefined> {
    if (option === "loginShell")
      return promptBoolOption(
        ctx,
        "loginShell",
        "Login shell for sandboxed commands",
        "bash -lc — sources /etc/profile + ~/.bash_profile (default)",
        "bash -c — no login profiles; inherited env and BASH_ENV still apply",
        true,
      );
    const value = await ctx.ui.input(
      "Prebuilt Landlock helper path (empty = compile on first use)",
      draft.landlockHelper ?? "",
      { signal: ctx.signal },
    );
    if (value === undefined) return undefined;
    const trimmed = value.trim();
    return trimmed === "" ? { landlockHelper: undefined } : { landlockHelper: trimmed };
  }

  /** Prompt for writable paths (comma-separated) and return the partial config. */
  async function promptWritable(
    ctx: ExtensionCommandContext,
    draft: SandboxConfig,
  ): Promise<Partial<SandboxConfig>> {
    const v = await ctx.ui.input(
      "Writable paths (comma-separated; empty = none in this scope)",
      draft.writable?.join(", "),
      { signal: ctx.signal },
    );
    if (v === undefined) throw new Error("cancelled");
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
    const scope = await chooseSandboxScope(ctx, trusted, scopeLabel);
    if (!scope) return;
    const file = files[scope];
    const draft = await editSandboxDraft(ctx, file, scopeLabel(scope));
    if (!draft) return;
    writeScopeConfig(file, draft);
    ctx.ui.notify(`sandbox config saved: ${file}`, "info");
    const reloaded = loadSandboxConfigs(ctx.cwd, trusted);
    if (reloaded.error)
      // The save succeeded, but the OTHER scope file is invalid; apply the
      // merge of the valid scopes (managed still wins) rather than the
      // broken file's absence defeating them.
      ctx.ui.notify(
        `Sandbox config error: ${reloaded.error} — applying the remaining valid scopes`,
        "warning",
      );
    applySandbox(reloaded.config, ctx.ui, ctx.cwd, true, reloaded.managedConfig);
  }

  async function chooseSandboxScope(
    ctx: ExtensionCommandContext,
    trusted: boolean,
    scopeLabel: (scope: SandboxScope) => string,
  ): Promise<SandboxScope | undefined> {
    const choice = await promptSelect(ctx, "Sandbox config scope", [
      {
        value: "project",
        label: scopeLabel("project"),
        description: "this repo only — shared with the project (needs trust)",
      },
      { value: "global", label: scopeLabel("global"), description: "applies to all your projects" },
    ]);
    if (choice === undefined) {
      ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
      return undefined;
    }
    const scope: SandboxScope = choice === "project" ? "project" : "global";
    if (scope === "project" && !trusted) {
      ctx.ui.notify(
        "Project is not trusted; refusing to write its sandbox config. Trust the project or pick the global scope.",
        "warning",
      );
      return undefined;
    }
    return scope;
  }

  async function editSandboxDraft(
    ctx: ExtensionCommandContext,
    file: string,
    label: string,
  ): Promise<SandboxConfig | undefined> {
    let draft: SandboxConfig;
    try {
      draft = readScopeConfig(file);
    } catch (error) {
      ctx.ui.notify(
        `Cannot edit: ${String(error instanceof Error ? error.message : error)} — fix the file by hand, then retry.`,
        "error",
      );
      return undefined;
    }
    for (;;) {
      const choice = await promptSelect(
        ctx,
        `Sandbox config (${label})`,
        sandboxOptionItems(draft),
      );
      if (choice === undefined || choice === "cancel") {
        ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
        return undefined;
      }
      if (choice === "save") return draft;
      const edited = await editSandboxOption(ctx, choice, draft);
      if (edited === undefined) {
        ctx.ui.notify("sandbox config cancelled: no changes saved.", "warning");
        return undefined;
      }
      Object.assign(draft, edited);
    }
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
      ctx.ui.notify(renderSandboxStatus(ctx), "info");
    },
  });

  /** Render the bare /sandbox status display. */
  function renderSandboxStatus(ctx: ExtensionCommandContext): string {
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
    lines.push(`Config: ${files.global}${trustNote}${managedLine}`);
    lines.push(
      `/sandbox config opens the interactive editor; /sandbox on|off toggles (project scope).`,
    );
    lines.push("blockTerminates: true stops the turn instead).");
    return lines.join("\n");
  }
}
