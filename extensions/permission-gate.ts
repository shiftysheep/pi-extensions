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
} from "@earendil-works/pi-coding-agent";
import {
  type BashOperations,
  CONFIG_DIR_NAME,
  createLocalBashOperations,
  isToolCallEventType,
} from "@earendil-works/pi-coding-agent";
import type { SandboxScope } from "./lib/sandbox-utils.js";
import {
  applyManagedSandboxConfig,
  applySandboxToggle,
  buildWritableRoots,
  canonicalizeTarget,
  danglingSymlinkTarget,
  describeSandboxState,
  isInsideAnyRoot,
  MAX_CLASSIFIER_TIMEOUT_MS,
  mergeSandboxConfigs,
  parseWritableList,
  type RunnerContext,
  SANDBOX_RUNNER_CHOICES,
  type SandboxConfig,
  type SandboxState,
  sandboxStateSignature,
  wrapCommand,
} from "./lib/sandbox-utils.js";
import { clearApiKeyCache, resolveApiKey } from "./permission-gate/api-key.js";
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
import {
  loadSandboxConfigs,
  readScopeConfig,
  sandboxConfigFiles,
  writeScopeConfig,
} from "./permission-gate/config.js";
import { callJev, DEFAULT_CLASSIFIER_TIMEOUT_MS } from "./permission-gate/jev-client.js";
import { sandboxOptionItems } from "./permission-gate/menu.js";
import {
  type ClassifierOption,
  isClassifierOption,
  promptSelect,
  RUNNER_DESCRIPTIONS,
} from "./permission-gate/prompts.js";
import { findStaticMatch } from "./permission-gate/rules.js";
import { resolveRunner } from "./permission-gate/runner.js";
import { renderSandboxStatus } from "./permission-gate/status.js";

const SANDBOX_CONFIG_FILE = "sandbox.json";

const USAGE =
  "Usage:\n" +
  "  /sandbox          show live status\n" +
  '  /sandbox on       enable (project scope; runner defaults to "auto"; an explicit runner in either scope is kept)\n' +
  "  /sandbox off      disable (project scope)\n" +
  "  /sandbox config   interactive editor (pick the global or project scope)";

export default function (pi: ExtensionAPI) {
  let config: SandboxConfig = {};
  let managedConfig: SandboxConfig = {};
  let state: SandboxState = { active: false, enabled: false };
  let localBashOps: ReturnType<typeof createLocalBashOperations> | undefined;
  // Warn-once flags for the optional Jev classifier (reset on /reload, which
  // recreates the extension instance — an acceptable re-warn).
  let classifierNoKeyWarned = false;
  let classifierApiWarned = false;
  let powerShellUnsandboxedWarned = false;

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
    const resolved = await resolveApiKey({ useKeychain: config.classifierKeychain });
    if (!resolved) {
      const keychainHint = config.classifierKeychain
        ? "configured keychain entry is unavailable, and "
        : "";
      warnClassifierOnce(
        ctx,
        () => classifierNoKeyWarned,
        () => (classifierNoKeyWarned = true),
        `Classifier enabled (classifier: jev) but no TypeSafe API key found (${TYPESAFE_API_KEY_ENV} is unset, ${keychainHint}and ~/.pi/credentials/typesafe-api-key is absent or unsafe) — Jev classification is skipped.`,
      );
      return undefined;
    }
    const apiKey = resolved.key;
    const model = config.classifierModel ?? DEFAULT_JEV_MODEL;
    const result = await callJev(buildClassifierRequest(command, model, shell), {
      apiKey,
      timeoutMs: config.classifierTimeoutMs,
      signal: ctx.signal,
    });
    if (!result.ok && result.status === 401) clearApiKeyCache();
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

  /** Probe runners and build the policy for a merged config. Supported
   * platforms are Linux and macOS; on anything else the sandbox is treated
   * as disabled (the heuristic gate still applies). */
  function computeState(
    cwd: string,
    cfg: SandboxConfig,
  ): { state: SandboxState; warnings: string[] } {
    if (!cfg.enabled) return { state: { active: false, enabled: false }, warnings: [] };
    if (process.platform !== "linux" && process.platform !== "darwin") {
      return {
        state: { active: false, enabled: false },
        warnings: [
          `Sandbox is not supported on ${process.platform} (Linux/macOS only) — treated as disabled. The heuristic gate still applies.`,
        ],
      };
    }
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

  /** Warn once per session when a PowerShell command runs while the sandbox
   *  is active (PowerShell is never sandboxed — no backend). */
  function warnPowerShellUnsandboxed(ctx: ExtensionContext): void {
    if (!state.active || powerShellUnsandboxedWarned) return;
    powerShellUnsandboxedWarned = true;
    warnClassifier(
      ctx,
      "Sandbox is active but PowerShell is not sandboxed (no backend). Bash commands are confined; PowerShell runs unsandboxed — use bash for sandboxed execution.",
    );
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
    const shell = isPowerShell ? "powershell" : "bash";
    const match = findStaticMatch(shell, command);
    const staticBlock = match ? await confirmStaticMatch(match, command, ctx) : undefined;
    if (staticBlock) return staticBlock;
    if (!match) {
      const jevBlock = await runJevClassifier(command, ctx, shell);
      if (jevBlock) return jevBlock;
    }
    if (isPowerShell) warnPowerShellUnsandboxed(ctx);
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
    if (enabled && process.platform !== "linux" && process.platform !== "darwin") {
      ctx.ui.notify(
        `Sandbox is not supported on ${process.platform} (Linux/macOS only) — leaving it off. The heuristic gate still applies.`,
        "warning",
      );
      return;
    }
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
      case "classifierKeychain": {
        const value = await promptSelect(ctx, "Use OS keychain", [
          { value: "false", label: "off", description: "use env var and private file only" },
          { value: "true", label: "on", description: "try OS keychain, then private file" },
        ]);
        return value === undefined ? undefined : { classifierKeychain: value === "true" };
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
      ctx.ui.notify(
        renderSandboxStatus({
          state,
          config,
          managedConfig,
          files: sandboxConfigFiles(ctx.cwd),
          trusted: ctx.isProjectTrusted(),
        }),
        "info",
      );
    },
  });
}
