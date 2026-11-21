/**
 * /sandbox status renderer — pure string building over the live state.
 * Kept separate so the wiring file stays inside the complexity budget.
 */

import type { SandboxConfig, SandboxScope, SandboxState } from "../lib/sandbox-utils.js";

export type SandboxStatusInput = {
  state: SandboxState;
  config: SandboxConfig;
  /** Managed config as read (keys present => rendered on the Config line). */
  managedConfig: SandboxConfig;
  /** Resolved managed config path (rendered on the Config line when the
   *  managed scope contributed keys). */
  managedFile: string;
  files: Record<SandboxScope, string>;
  /** Whether the current project is trusted. */
  trusted: boolean;
};

/** Render the bare /sandbox status display. */
export function renderSandboxStatus(input: SandboxStatusInput): string {
  const { state, config, managedConfig, managedFile, files, trusted } = input;
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
  const trustNote = trusted ? "" : " (not trusted)";
  const managedLine =
    Object.keys(managedConfig).length > 0 ? ` / ${managedFile} (managed, wins)` : "";
  lines.push(`Config: ${files.global}${trustNote}${managedLine}`);
  lines.push(
    `/sandbox config opens the interactive editor; /sandbox on|off toggles (project scope).`,
  );
  lines.push(
    "blockTerminates: true stops the agent's turn on gate blocks; default reports the block and lets the turn continue.",
  );
  return lines.join("\n");
}
