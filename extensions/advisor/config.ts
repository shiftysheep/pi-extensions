/**
 * advisor.json config I/O for the advisor extension: load, save, validation,
 * and the human-readable description shown by /advisor.
 */

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { type AdvisorConfig, parseConfig } from "../lib/advisor-utils.js";
import { formatTarget } from "./models.js";

export const CONFIG_PATH = join(getAgentDir(), "advisor.json");

/** Cap on the total redacted transcript characters attached to a request. */
export const MAX_SESSION_CONTEXT_CHARS = 120_000;

export function loadConfig(): AdvisorConfig {
  try {
    return parseConfig(JSON.parse(readFileSync(CONFIG_PATH, "utf8")), CONFIG_PATH);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    if (error instanceof SyntaxError)
      throw new Error(`${CONFIG_PATH}: invalid JSON: ${error.message}`);
    throw error;
  }
}

/** Same as loadConfig, but reports broken-config errors instead of throwing, so /advisor can recover. */
export function loadConfigSafe(): { config: AdvisorConfig; loadError?: string } {
  try {
    return { config: loadConfig() };
  } catch (error: unknown) {
    return { config: {}, loadError: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Validate the mutated config with parseConfig BEFORE touching the file (e.g.
 * `/advisor set a/m,a/m` must not save a same-model pair that the next call
 * would reject), back up a broken previous file, then save.
 * Returns true when a backup was made.
 */
export function saveConfigValidated(config: AdvisorConfig, loadError: string | undefined): boolean {
  try {
    parseConfig(config, CONFIG_PATH);
  } catch (error) {
    throw new Error(
      `Not saved: ${(error as Error).message}\nThe previous configuration is unchanged.`,
    );
  }
  let backedUp = false;
  if (loadError) {
    // Repairing a broken file: keep the previous bytes instead of overwriting them.
    try {
      renameSync(CONFIG_PATH, `${CONFIG_PATH}.bak`);
      backedUp = true;
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT")
        throw new Error(`Could not back up ${CONFIG_PATH}: ${(error as Error).message}`);
    }
  }
  saveConfig(config);
  return backedUp;
}

export function saveConfig(config: AdvisorConfig): void {
  const out: AdvisorConfig = {};
  if (config.primary) out.primary = config.primary;
  if (config.fallback) out.fallback = config.fallback;
  if (config.reasoningEffort) out.reasoningEffort = config.reasoningEffort;
  if (config.activeModelFallback) out.activeModelFallback = config.activeModelFallback;
  if (config.timeoutMs !== undefined) out.timeoutMs = config.timeoutMs;
  if (config.piBinary) out.piBinary = config.piBinary;
  if (config.awsProfile) out.awsProfile = config.awsProfile;
  if (config.awsRegion) out.awsRegion = config.awsRegion;
  if (config.env) out.env = config.env;
  // Write a temp file in the same directory, then rename atomically, so an interrupted
  // write or a concurrent reader never sees a truncated/invalid config.
  const tmpPath = `${CONFIG_PATH}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify(out, null, 2)}\n`);
  renameSync(tmpPath, CONFIG_PATH);
}
export function describeConfig(config: AdvisorConfig, activeModelLabel?: string): string {
  const rows = [
    ["primary", formatTarget(config.primary)],
    ["fallback (secondary)", formatTarget(config.fallback)],
    ["default effort", config.reasoningEffort ?? "(medium)"],
    [
      "active model fallback",
      config.activeModelFallback ? "enabled (self-review, last resort)" : "disabled",
    ],
    [
      "timeout",
      config.timeoutMs !== undefined
        ? `${config.timeoutMs} ms per consultation, fallback chain included (clamped 30 s..30 min)`
        : "5 min review / 10 min explore (defaults)",
    ],
    ["pi binary", config.piBinary ?? '"pi" on PATH (or $PI_BINARY)'],
    ["child AWS profile", config.awsProfile ?? "(host default)"],
    ["child AWS region", config.awsRegion ? config.awsRegion : "(host default)"],
    [
      "child env",
      config.env
        ? Object.entries(config.env)
            .map(([k, v]) => `${k}=${v}`)
            .join(" ")
        : "(none)",
    ],
  ];
  // Retry chain: configured slots in order; no implicit model. The active model is
  // shown only when activeModelFallback is enabled (see buildCandidates).
  const chain: string[] = [];
  if (config.primary) chain.push(formatTarget(config.primary));
  if (config.fallback) chain.push(formatTarget(config.fallback));
  if (chain.length === 0) chain.push("(none configured — run /advisor)");
  if (config.activeModelFallback && activeModelLabel) {
    const already = [config.primary, config.fallback].some(
      (t) => t && `${t.provider ?? "*"}/${t.model}` === activeModelLabel,
    );
    if (!already) chain.push(`${activeModelLabel} (active, last resort)`);
  }
  rows.push(["retry chain", chain.join(" → ")]);
  const width = Math.max(...rows.map(([label]) => label.length)) + 2;
  return [
    `Advisor ${CONFIG_PATH}`,
    ...rows.map(([label, value]) => `  ${label.padEnd(width)}${value}`),
  ].join("\n");
}
