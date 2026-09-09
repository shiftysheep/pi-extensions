/**
 * Permission gate rules — pure, unit-testable.
 *
 * Each rule has a category:
 *  - "filesystem": the OS sandbox makes this class of mistake impossible
 *    (writes outside the writable roots are denied by the kernel), so the
 *    gate is suppressed while the sandbox is active.
 *  - "system": not preventable by the filesystem sandbox (privilege
 *    escalation, raw block-device writes, mkfs, power actions) — always
 *    gated, sandboxed or not.
 *
 * The gate is a heuristic prompt guard, NOT a security boundary: shell
 * expansion, quoting, scripts, and indirect invocation can evade text
 * matching. Real enforcement comes from the sandbox.
 */

export type RuleCategory = "filesystem" | "system";

export type GateRule = {
  name: string;
  category: RuleCategory;
  test: (command: string) => boolean;
};

/** Split a command line into shell segments (top-level separators only). */
export function segments(command: string): string[] {
  return command
    .split(/&&|\|\||[;&|]|\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Extract the command word (minus env-var prefixes, `env` wrappers, and
 * path) and its args. Known limitation: other wrappers (nice/nohup/time,
 * scripts, quoting) still evade this — the gate is a heuristic, not a
 * security boundary. */
function commandOf(segment: string): { cmd: string; args: string[] } | undefined {
  const parts = segment.match(/\S+/g) ?? [];
  let i = 0;
  while (i < parts.length && /^[A-Za-z_]\w*=\S+$/.test(parts[i])) i++;
  if (i >= parts.length) return undefined;
  let cmd = parts[i].split("/").pop() ?? parts[i];
  if (cmd === "env") {
    // env [FLAGS] [VAR=VALUE]* COMMAND — unwrap to the real command
    i++;
    while (i < parts.length && (/^--?\w/.test(parts[i]) || /^[A-Za-z_]\w*=\S+$/.test(parts[i])))
      i++;
    if (i >= parts.length) return undefined;
    cmd = parts[i].split("/").pop() ?? parts[i];
  }
  return { cmd, args: parts.slice(i + 1) };
}

// Harmless /dev targets that are NOT raw device writes.
const SAFE_DEV_TARGETS = new Set([
  "/dev/null",
  "/dev/stdout",
  "/dev/stderr",
  "/dev/full",
  "/dev/tty",
  "/dev/fd",
]);

const RULES: GateRule[] = [
  {
    // rm with a recursive flag: -r, -R, -rf, -fr, -r -f, --recursive
    name: "recursive rm",
    category: "filesystem",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        if (parsed?.cmd !== "rm") return false;
        return parsed.args.some((a) => /^-/.test(a) && (a === "--recursive" || /[rR]/.test(a)));
      }),
  },
  {
    // chmod making a file world-writable: 777/0777/000777 or a+/o+ ...w
    name: "world-writable chmod",
    category: "filesystem",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        if (parsed?.cmd !== "chmod") return false;
        return parsed.args.some(
          (a) => (Number.isInteger(Number(a)) && Number(a) % 1000 === 777) || /^(a|o)\+.*w/.test(a),
        );
      }),
  },
  {
    // Privilege escalation as the command of any segment
    name: "privilege escalation",
    category: "system",
    test: (command) =>
      segments(command).some((seg) => {
        const { cmd } = commandOf(seg) ?? {};
        return cmd === "sudo" || cmd === "doas" || cmd === "pkexec";
      }),
  },
  {
    // dd writing to a raw device (block devices, disks) — not stopped by
    // filesystem sandboxes, which only mediate filesystem operations.
    name: "raw device write (dd)",
    category: "system",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        if (parsed?.cmd !== "dd") return false;
        return parsed.args.some((a) => {
          const m = /^of=(.+)$/.exec(a);
          return m?.[1].startsWith("/dev/") === true && !SAFE_DEV_TARGETS.has(m[1]);
        });
      }),
  },
  {
    // mkfs (mkfs.ext4, mkfs -t xfs, ...)
    name: "mkfs",
    category: "system",
    test: (command) =>
      segments(command).some((seg) => {
        const { cmd } = commandOf(seg) ?? {};
        return cmd === "mkfs" || cmd?.startsWith("mkfs.") === true;
      }),
  },
  {
    // Power / reboot actions
    name: "power action",
    category: "system",
    test: (command) =>
      segments(command).some((seg) => {
        const { cmd } = commandOf(seg) ?? {};
        return cmd === "shutdown" || cmd === "reboot" || cmd === "poweroff" || cmd === "halt";
      }),
  },
];

export type GateMatch = { name: string; category: RuleCategory };

/** Returns the first matching rule, or undefined. */
export function findDangerousRule(command: string): GateMatch | undefined {
  const rule = RULES.find((r) => r.test(command));
  return rule ? { name: rule.name, category: rule.category } : undefined;
}

/**
 * Whether a matched rule should be gated given sandbox state: system rules
 * are always gated; filesystem rules are gated only when the sandbox is not
 * active (the kernel enforces them instead).
 */
export function shouldGate(match: GateMatch, sandboxActive: boolean): boolean {
  return match.category === "system" || !sandboxActive;
}
