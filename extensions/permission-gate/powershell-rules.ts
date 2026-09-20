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
 * HEURISTIC prompt guard, not a security boundary: string manipulation and
 * indirect invocation can evade text matching. `-EncodedCommand` is decoded
 * and re-gated (and confirmed even when the decoded text is clean), so
 * base64 encoding is not an escape hatch.
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

/**
 * Extract the -EncodedCommand payload from a segment, if present. Returns
 * undefined when no segment carries the parameter, the BASE64 string when
 * parseable, or "" when the parameter is present but its value is not
 * parseable (both present cases must confirm — see findDangerousPowerShellRule).
 * The value token is matched RAW (base64 uses +/=, which the usual PS token
 * regex drops); surrounding single/double quotes are tolerated.
 */
function encodedPayloadOf(command: string): string | undefined {
  for (const seg of psSegments(command)) {
    if (!/-EncodedCommand/i.test(seg)) continue;
    const m = /-EncodedCommand\s*["']?([A-Za-z0-9+/=]+)["']?/.exec(seg);
    return m ? m[1] : "";
  }
  return undefined;
}

/** Decode a PowerShell -EncodedCommand value (UTF-16LE base64). Returns
 * undefined when the value is not valid base64 / not even-length UTF-16LE. */
function decodeEncodedCommand(b64: string): string | undefined {
  if (b64.length === 0 || b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64))
    return undefined;
  const buf = Buffer.from(b64, "base64");
  if (buf.length === 0 || buf.length % 2 !== 0) return undefined;
  return buf.toString("utf16le");
}

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
    // -WhatIf (dry-run) is excluded: it inspects, it does not wipe.
    name: "disk wipe",
    disposition: "deny",
    test: (command) =>
      psSegments(command).some((seg) => {
        if (!["format-volume", "clear-disk", "initialize-disk"].includes(psCommand(seg) ?? ""))
          return false;
        return !hasParam(psArgs(seg), "WhatIf");
      }),
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
 *
 * -EncodedCommand is handled BEFORE the static rules and merged with them
 * (deny still wins overall): the payload is decoded (UTF-16LE base64) and
 * re-gated recursively, but a decoded STATIC MISS still confirms — encoded
 * execution never means "safe". Undecodable values and exhausted nesting
 * budgets confirm as well. `depth` bounds the recursion; callers pass 0.
 */
export function findDangerousPowerShellRule(command: string, depth = 0): GateMatch | undefined {
  const matches = PS_RULES.filter((r) => r.test(command));
  const rule = matches.find((r) => r.disposition === "deny") ?? matches[0];
  const staticMatch: GateMatch | undefined = rule
    ? { name: rule.name, disposition: rule.disposition ?? "confirm" }
    : undefined;
  const enc = encodedPayloadOf(command);
  let encodedMatch: GateMatch | undefined;
  if (enc !== undefined) {
    if (depth < 2 && enc !== "") {
      const decoded = decodeEncodedCommand(enc);
      encodedMatch =
        decoded !== undefined
          ? (findDangerousPowerShellRule(decoded, depth + 1) ?? {
              name: "encoded PowerShell execution",
              disposition: "confirm",
            })
          : { name: "encoded PowerShell execution (undecodable)", disposition: "confirm" };
    } else {
      encodedMatch = { name: "encoded PowerShell execution", disposition: "confirm" };
    }
  }
  const all = [staticMatch, encodedMatch].filter((m): m is GateMatch => m !== undefined);
  return all.find((m) => m.disposition === "deny") ?? all[0];
}
