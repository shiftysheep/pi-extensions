/**
 * The /sandbox config menu rows: label = current value, description = dim hint.
 * Pure string building over a draft config — no extension state.
 */

import type { SelectItem } from "@earendil-works/pi-tui";
import type { SandboxConfig } from "../lib/sandbox-utils.js";
import {
  DEFAULT_CONFIRM_THRESHOLD,
  DEFAULT_DENY_THRESHOLD,
  DEFAULT_JEV_MODEL,
} from "./classifier.js";
import { DEFAULT_CLASSIFIER_TIMEOUT_MS } from "./jev-client.js";

/** The config menu rows: label = current value, description = dim hint. */
export function sandboxOptionItems(draft: SandboxConfig): SelectItem[] {
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
    {
      value: "classifierKeychain",
      label: `classifierKeychain: ${draft.classifierKeychain ?? "false"}`,
      description: "read the TypeSafe API key from the OS credential store before the private file",
    },
    { value: "save", label: "— save —", description: "write the config file and re-apply" },
    { value: "cancel", label: "— cancel —", description: "discard changes" },
  ];
}
