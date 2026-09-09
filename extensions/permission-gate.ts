/**
 * Permission Gate + Filesystem Sandbox Extension
 *
 * Two cooperating layers:
 *
 * 1. HEURISTIC GATE (always on) — prompts for confirmation before bash
 *    commands that look dangerous (recursive `rm`, privilege escalation,
 *    world-writable `chmod`, raw device writes, mkfs, power actions).
 *
 * 2. OS SANDBOX (opt-in via ~/.pi/agent/sandbox.json `enabled: true`) —
 *    wraps the agent's bash commands in a filesystem sandbox:
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
 * Config: ~/.pi/agent/sandbox.json
 *   {
 *     "enabled": true,          // default false
 *     "runner": "auto",         // auto | bwrap | landlock | sandbox-exec | none
 *     "writable": ["~/cache"],  // extra writable paths (cwd, /tmp, /dev, /proc are always writable)
 *     "home": "ro",             // ro | rw — access to $HOME (default ro)
 *     "network": "allow",       // allow | deny (deny is a no-op+warning on landlock)
 *     "userCommands": false     // also sandbox user `!` commands
 *   }
 *
 * `write`/`edit` tool calls target a path directly (no shell), so they are
 * guarded separately: paths outside the writable roots prompt for
 * confirmation.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  createLocalBashOperations,
  getAgentDir,
  isToolCallEventType,
} from "@earendil-works/pi-coding-agent";
import {
  buildWritableRoots,
  isInsideAnyRoot,
  parseSandboxConfig,
  type RunnerContext,
  type SandboxConfig,
  type SandboxPolicy,
  wrapCommand,
} from "./lib/sandbox-utils.js";
import { findDangerousRule, shouldGate } from "./permission-gate/rules.js";
import { resolveRunner } from "./permission-gate/runner.js";

const SANDBOX_CONFIG_FILE = "sandbox.json";

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

function loadSandboxConfig(): { config?: SandboxConfig; error?: string } {
  const file = path.join(getAgentDir(), SANDBOX_CONFIG_FILE);
  if (!fs.existsSync(file)) return { config: {} };
  try {
    return { config: parseSandboxConfig(JSON.parse(fs.readFileSync(file, "utf8")), file) };
  } catch (err) {
    return { error: String(err instanceof Error ? err.message : err) };
  }
}

export default function (pi: import("@earendil-works/pi-coding-agent").ExtensionAPI) {
  let config: SandboxConfig = {};
  let state: SandboxState = { active: false, enabled: false };
  let localBashOps: ReturnType<typeof createLocalBashOperations> | undefined;

  const runnerContext = (cwd: string): RunnerContext => ({
    cwd,
    homeDir: os.homedir(),
    shellPath: "/bin/bash",
    helperPath: state.active ? state.helperPath : undefined,
  });

  pi.on("session_start", (_event, ctx) => {
    const loaded = loadSandboxConfig();
    if (loaded.error) {
      state = { active: false, enabled: true, reason: `invalid config: ${loaded.error}` };
      ctx.ui.notify(`Sandbox disabled: ${loaded.error}`, "warning");
      return;
    }
    config = loaded.config ?? {};
    if (!config.enabled) {
      state = { active: false, enabled: false };
      return;
    }

    const probe = resolveRunner(config.runner ?? "auto");
    if (!probe.ok) {
      state = { active: false, enabled: true, reason: probe.reason };
      ctx.ui.notify(
        `Sandbox enabled but no runner available (${probe.reason}). Commands run UNSANDBOXED; all permission gates are armed.`,
        "warning",
      );
      return;
    }

    const cwd = process.cwd();
    const policy = {
      writableRoots: buildWritableRoots(config, runnerContext(cwd), (p) => {
        try {
          return fs.statSync(p).isDirectory();
        } catch {
          return false;
        }
      }),
      network: config.network ?? "allow",
    };
    const networkEnforced = probe.runner !== "landlock";
    state = {
      active: true,
      enabled: true,
      runner: probe.runner,
      policy,
      helperPath: probe.helperPath,
      networkEnforced,
    };

    if (policy.network === "deny" && !networkEnforced) {
      ctx.ui.notify(
        "Sandbox: landlock cannot enforce network policy; network=deny is IGNORED (use bwrap to enforce).",
        "warning",
      );
    }
    ctx.ui.notify(
      `Sandbox active (${probe.runner}): read-only outside ${policy.writableRoots.join(", ")}; network ${policy.network === "deny" ? "DENIED" : "allowed"}.`,
    );
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
    const runner = state.runner;
    const policy = state.policy;
    localBashOps ??= createLocalBashOperations();
    const base = localBashOps;
    return {
      operations: {
        async exec(command: string, cwd: string, options: Parameters<typeof base.exec>[2]) {
          return base.exec(wrapCommand(runner, command, policy, runnerContext(cwd)), cwd, options);
        },
      },
    };
  });

  pi.registerCommand("sandbox", {
    description: "Show sandbox status (runner, writable roots, network policy)",
    handler: async (_args, ctx) => {
      const lines: string[] = [];
      if (!state.enabled) {
        lines.push(
          `Sandbox: DISABLED (${path.join(getAgentDir(), SANDBOX_CONFIG_FILE)} — set "enabled": true to activate)`,
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
      lines.push(
        "Gate categories: system rules always gated; filesystem rules gated only in fallback mode.",
      );
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
