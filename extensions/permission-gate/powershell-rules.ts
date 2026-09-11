/**
 * Permission gate rules for the PowerShell tool — pure, unit-testable.
 *
 * pi ships a separate `powershell` tool; on hosts where the agent drives
 * PowerShell, dangerous commands were completely unguarded (the bash rules
 * are bash-syntax-centric and must NOT be reused for PowerShell —
 * cmdlets/aliases/parameters differ).
 *
 * Dispositions mirror rules.ts: "confirm" (default) asks before running;
 * "deny" hard-blocks raw disk destruction (human-only). Every match is
 * gated regardless of sandbox state. Like the bash gate, this is a
 * HEURISTIC prompt guard, not a security boundary: string manipulation,
 * encoding tricks, and indirect invocation can evade text matching.
 *
 * PowerShell quirks handled: alias→cmdlet resolution (rm/del/ri/…),
 * case-insensitivity, parameter PREFIX matching (-Rec == -Recurse),
 * explicit parameter values (-Recurse:$false does NOT count), `;`/newline/
 * pipeline separators, and the `&`/`.` call operators.
 */

import type { GateMatch, RuleDisposition } from "./rules.js";

type PsRule = {
  name: string;
  /** "deny" = hard block (human-only, no prompt). Default: "confirm". */
  disposition?: RuleDisposition;
  test: (command: string) => boolean;
};

/** Common aliases for the cmdlets the rules care about. */
const ALIASES: Record<string, string> = {
  rm: "Remove-Item",
  del: "Remove-Item",
  erase: "Remove-Item",
  ri: "Remove-Item",
  rd: "Remove-Item",
  rmdir: "Remove-Item",
  r: "Remove-Item",
  iex: "Invoke-Expression",
  iwr: "Invoke-WebRequest",
  clc: "Clear-Content",
  kill: "Stop-Process",
};

/** Split into statement segments: `;`, newlines, and pipelines. (`&` and
 * `.` are call OPERATORS, not separators.) */
function psSegments(command: string): string[] {
  return command
    .split(/[;|\n]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** The command word of a segment (call-operator aware, module-qualified
 * names and .exe suffixes normalized, alias-resolved, lowercased). */
function psCommand(segment: string): string | undefined {
  const parts = segment.match(/[\w.$:/\\-]+/g) ?? [];
  let i = 0;
  if (parts[i] === "&" || parts[i] === ".") i++;
  const first = parts[i];
  if (first === undefined) return undefined;
  let raw = first.toLowerCase();
  // Module-qualified: Microsoft.PowerShell.Management\Remove-Item
  const bs = raw.lastIndexOf("\\");
  if (bs !== -1) raw = raw.slice(bs + 1);
  // Executable suffix: icacls.exe, takeown.exe
  raw = raw.replace(/\.exe$/, "");
  return (ALIASES[raw] ?? raw).toLowerCase();
}

/** Args of a segment, minus the command word and call operator. */
function psArgs(segment: string): string[] {
  const parts = segment.match(/[\w.$:/\\-]+/g) ?? [];
  let i = 0;
  if (parts[i] === "&" || parts[i] === ".") i++;
  return parts.slice(i + 1);
}

/**
 * True when any arg is the given parameter, honoring PowerShell prefix
 * matching (-Rec == -Recurse) and explicit values (-Recurse:$false does
 * NOT count).
 */
function hasParam(args: string[], name: string): boolean {
  const target = name.toLowerCase();
  return args.some((a) => {
    if (!a.startsWith("-")) return false;
    let p = a.slice(1);
    let value: string | undefined;
    const colon = p.indexOf(":");
    if (colon !== -1) {
      value = p.slice(colon + 1);
      p = p.slice(0, colon);
    }
    if (p.length === 0) return false;
    const pp = p.toLowerCase();
    if (pp !== target && !target.startsWith(pp)) return false;
    if (value !== undefined && value !== "" && /^(false|\$false|0)$/i.test(value.trim()))
      return false;
    return true;
  });
}

const REGISTRY_HIVE = /^(HKLM|HKCR|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT)([\\:]|$)/i;

/** True when a path argument points at a machine-wide registry hive
 * (provider prefix `Registry::` normalized away). */
function isRegistryPath(token: string): boolean {
  return REGISTRY_HIVE.test(token.replace(/^registry::/i, ""));
}

const PS_RULES: PsRule[] = [
  {
    // Remove-Item (and aliases rm/del/erase/ri/rd/rmdir/r) with -Recurse.
    // Irreversible even inside writable roots — always confirmed.
    name: "recursive Remove-Item",
    test: (command) =>
      psSegments(command).some(
        (seg) => psCommand(seg) === "remove-item" && hasParam(psArgs(seg), "Recurse"),
      ),
  },
  {
    // Clear-Content (alias clc)
    name: "Clear-Content",
    test: (command) => psSegments(command).some((seg) => psCommand(seg) === "clear-content"),
  },
  {
    // Volume/disk wiping — destroys data irreversibly. Hard block.
    name: "disk wipe",
    disposition: "deny",
    test: (command) =>
      psSegments(command).some((seg) =>
        ["format-volume", "clear-disk", "initialize-disk"].includes(psCommand(seg) ?? ""),
      ),
  },
  {
    // Power / shutdown actions
    name: "power action",
    test: (command) =>
      psSegments(command).some((seg) =>
        ["stop-computer", "restart-computer"].includes(psCommand(seg) ?? ""),
      ),
  },
  {
    // Elevation: Start-Process -Verb RunAs (incl. the -Verb:RunAs form)
    name: "privilege escalation",
    test: (command) =>
      psSegments(command).some((seg) => {
        if (psCommand(seg) !== "start-process") return false;
        const args = psArgs(seg);
        const colon = args.find((a) => /^-verb:/i.test(a));
        if (colon && colon.slice(6).toLowerCase() === "runas") return true;
        return hasParam(args, "Verb") && args.some((a) => a.toLowerCase() === "runas");
      }),
  },
  {
    // Arbitrary code execution: Invoke-Expression (alias iex) — also
    // covers the classic `iwr … | iex` download-and-run (the iex segment
    // matches on its own).
    name: "Invoke-Expression",
    test: (command) => psSegments(command).some((seg) => psCommand(seg) === "invoke-expression"),
  },
  {
    // ACL / ownership changes (icacls /grant incl. /grant:r, .exe suffixes)
    name: "ACL/ownership change",
    test: (command) =>
      psSegments(command).some((seg) => {
        const cmd = psCommand(seg);
        if (cmd === "icacls") return psArgs(seg).some((a) => /^\/grant(:|$)/i.test(a));
        return cmd === "takeown" || cmd === "set-acl";
      }),
  },
  {
    // Machine-wide registry modification (HKLM/HKCR; HKCU is user-scoped
    // and left ungated)
    name: "registry modification",
    test: (command) =>
      psSegments(command).some((seg) => {
        const cmd = psCommand(seg);
        if (
          cmd !== "remove-item" &&
          cmd !== "set-itemproperty" &&
          cmd !== "new-item" &&
          cmd !== "remove-itemproperty" &&
          cmd !== "set-item"
        ) {
          return false;
        }
        return psArgs(seg).some((a) => isRegistryPath(a));
      }),
  },
];

/**
 * Returns the matching PowerShell rule to surface: a DENY match wins over a
 * confirm one (same precedence as findDangerousRule). Undefined when nothing
 * matches.
 */
export function findDangerousPowerShellRule(command: string): GateMatch | undefined {
  const matches = PS_RULES.filter((r) => r.test(command));
  const rule = matches.find((r) => r.disposition === "deny") ?? matches[0];
  return rule ? { name: rule.name, disposition: rule.disposition ?? "confirm" } : undefined;
}
