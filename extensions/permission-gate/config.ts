/**
 * Sandbox config file IO — scope resolution, loading, and persistence.
 *
 * Pure-ish: no extension-level state lives here; callers pass cwd/trust and
 * get back the merged view plus the per-scope raw configs for editing.
 */

import fs from "node:fs";
import path from "node:path";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";
import {
  applyManagedSandboxConfig,
  managedSandboxConfigPath,
  mergeSandboxConfigs,
  parseSandboxConfig,
  type SandboxConfig,
  type SandboxScope,
  sandboxConfigPath,
} from "../lib/sandbox-utils.js";

/** Both scope config file paths for a working directory. */
export function sandboxConfigFiles(cwd: string): Record<SandboxScope, string> {
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
export function readScopeConfig(file: string): SandboxConfig {
  if (!fs.existsSync(file)) return {};
  return parseSandboxConfig(JSON.parse(fs.readFileSync(file, "utf8")), file);
}

/**
 * Load and merge both scopes: per-key, project wins. An untrusted project
 * contributes nothing (its file is neither read nor honored).
 */
export function loadSandboxConfigs(
  cwd: string,
  projectTrusted: boolean,
  managedFile = managedSandboxConfigPath(process.platform, process.env.PROGRAMDATA),
): LoadedSandboxConfigs {
  const files = sandboxConfigFiles(cwd);
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
export function writeScopeConfig(file: string, config: SandboxConfig): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  fs.renameSync(tmp, file);
}
