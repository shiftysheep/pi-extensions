/**
 * Permission gate rules — pure, unit-testable.
 *
 * Each rule has a disposition:
 *  - "confirm" (default): the gate asks for confirmation before running.
 *  - "deny": hard block, human-only — refused WITHOUT a prompt. Reserved
 *    for raw host-disk destruction, which the agent must never perform.
 *
 * Every match is gated REGARDLESS of sandbox state: the sandbox answers
 * "where may this command write?", the gate answers "does this command
 * require human intent?". Being confined to writable roots does not make
 * an irreversible action reversible.
 *
 * The gate is a heuristic prompt guard, NOT a security boundary: shell
 * expansion, quoting, scripts, and indirect invocation can evade text
 * matching. Filesystem enforcement comes from the sandbox; remote effects
 * (pushes, cloud, databases) rely on these prompts plus provider-side
 * protections.
 */

export type RuleDisposition = "confirm" | "deny";

export type GateRule = {
  name: string;
  /** "deny" = hard block (human-only, no prompt). Default: "confirm". */
  disposition?: RuleDisposition;
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

/** True for a /dev/* path that is a real device, not a harmless special file. */
function isUnsafeDevTarget(target: string): boolean {
  return target.startsWith("/dev/") && !SAFE_DEV_TARGETS.has(target);
}

/**
 * The command chain of a segment: the outer command plus, when it is a
 * privilege wrapper (sudo/doas/pkexec), the wrapped inner command. Lets the
 * deny tier see through `sudo dd of=/dev/sda` and friends. Heuristic: only
 * simple flag/user forms are unwrapped.
 */
function commandChain(segment: string): Array<{ cmd: string; args: string[] }> {
  const parsed = commandOf(segment);
  if (!parsed) return [];
  const chain = [parsed];
  if (parsed.cmd === "sudo" || parsed.cmd === "doas" || parsed.cmd === "pkexec") {
    const parts = segment.match(/\S+/g) ?? [];
    let i = 0;
    while (i < parts.length && /^[A-Za-z_]\w*=\S+$/.test(parts[i])) i++;
    i++; // the privilege tool itself
    while (i < parts.length) {
      if (parts[i] === "-u" || parts[i] === "--user") i += 2;
      else if (parts[i].startsWith("-")) i++;
      else break;
    }
    if (i < parts.length)
      chain.push({ cmd: parts[i].split("/").pop() ?? parts[i], args: parts.slice(i + 1) });
  }
  return chain;
}

// Redirect targets that are harmless even when written to.
const SAFE_REDIRECT_TARGETS = /^(?:null|stdout|stderr|full|tty|fd|zero|urandom|shm)(?:\/|$)/;

const RULES: GateRule[] = [
  {
    // rm with a recursive flag: -r, -R, -rf, -fr, -r -f, --recursive.
    // Irreversible even inside writable roots — always confirmed.
    name: "recursive rm",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        if (parsed?.cmd !== "rm") return false;
        return parsed.args.some((a) => /^-/.test(a) && (a === "--recursive" || /[rR]/.test(a)));
      }),
  },
  {
    // chmod making a file world-writable: 777/0777/000777 or a+/o+ ...w.
    // Irreversible-ish (permissions are hard to reconstruct) — always confirmed.
    name: "world-writable chmod",
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
    test: (command) =>
      segments(command).some((seg) => {
        const { cmd } = commandOf(seg) ?? {};
        return cmd === "sudo" || cmd === "doas" || cmd === "pkexec";
      }),
  },
  {
    // dd writing to a raw device (block devices, disks) — destroys data
    // irreversibly. Hard block: the human runs this, not the agent.
    name: "raw device write (dd)",
    disposition: "deny",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(
          ({ cmd, args }) =>
            cmd === "dd" &&
            args.some((a) => {
              const m = /^of=(.+)$/.exec(a);
              return m !== null && isUnsafeDevTarget(m[1]);
            }),
        ),
      ),
  },
  {
    // Shell redirection onto a raw device: `cat img > /dev/sda`, `> /dev/nvme0n1`.
    name: "raw device write (redirect)",
    disposition: "deny",
    test: (command) =>
      segments(command).some((seg) => {
        const m = />>?\s*\/dev\/(.+)$/.exec(seg.trim());
        return m !== null && !SAFE_REDIRECT_TARGETS.test(m[1]);
      }),
  },
  {
    // Writers taking a raw device as an argument: tee/shred (any target),
    // cp (destination = last arg).
    name: "raw device write (argument)",
    disposition: "deny",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd, args }) => {
          if (cmd === "tee" || cmd === "shred") return args.some(isUnsafeDevTarget);
          if (cmd === "cp") {
            const last = args[args.length - 1];
            return last !== undefined && isUnsafeDevTarget(last);
          }
          return false;
        }),
      ),
  },
  {
    // Filesystem-signature wipes and media erasure.
    name: "device wipe",
    disposition: "deny",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd, args }) => {
          if (cmd === "wipefs" || cmd === "blkdiscard") return true;
          if (cmd === "sgdisk") return args.includes("--zap-all");
          if (cmd === "parted") return args.includes("rm");
          return false;
        }),
      ),
  },
  {
    // LVM/ZFS volume and pool destruction.
    name: "volume/pool destroy",
    disposition: "deny",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd, args }) => {
          if (cmd === "lvremove" || cmd === "vgremove") return true;
          if (cmd === "zpool" || cmd === "zfs") return args[0] === "destroy";
          return false;
        }),
      ),
  },
  {
    // mkfs (mkfs.ext4, mkfs -t xfs, ...) — filesystem creation destroys
    // whatever was on the device. Hard block.
    name: "mkfs",
    disposition: "deny",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd }) => cmd === "mkfs" || cmd.startsWith("mkfs.")),
      ),
  },
  {
    // Power / reboot actions
    name: "power action",
    test: (command) =>
      segments(command).some((seg) => {
        const { cmd } = commandOf(seg) ?? {};
        return cmd === "shutdown" || cmd === "reboot" || cmd === "poweroff" || cmd === "halt";
      }),
  },
  {
    // Destructive Git operations: force pushes, hard resets, forced cleans,
    // force branch deletion, history rewrites. Remote mutations are not
    // confined by any sandbox — always confirmed.
    name: "destructive git operation",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        if (parsed?.cmd !== "git") return false;
        const [sub, ...rest] = parsed.args;
        if (sub === "push")
          return rest.some(
            (a) =>
              a === "--force" ||
              a === "--force-with-lease" ||
              a === "-f" ||
              a === "--delete" ||
              a.startsWith("+"),
          );
        if (sub === "reset") return rest.includes("--hard");
        if (sub === "clean")
          return rest.some((a) => a === "-f" || a === "--force" || /^-[a-z]*f/.test(a));
        if (sub === "branch")
          return rest.includes("-D") || (rest.includes("--delete") && rest.includes("-f"));
        return sub === "filter-repo" || sub === "filter-branch";
      }),
  },
  {
    // Curated remote-destruction operations (best-effort; the catalog is
    // deliberately narrow — see the file header).
    name: "remote destruction (cloud/IaC)",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        if (!parsed) return false;
        const { cmd, args } = parsed;
        if (cmd === "terraform" || cmd === "terragrunt") return args[0] === "destroy";
        if (cmd === "kubectl")
          return args[0] === "delete" && (args.includes("namespace") || args.includes("ns"));
        if (cmd === "aws")
          return args[0] === "s3" && args[1] === "rm" && args.includes("--recursive");
        if (cmd === "gh") return args[0] === "repo" && args[1] === "delete";
        if (cmd === "npm") return args[0] === "unpublish";
        return false;
      }),
  },
  {
    // Destructive SQL issued through a known database client.
    name: "database destruction",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        const cmd = parsed?.cmd;
        if (!cmd) return false;
        if (cmd === "mysqladmin") return parsed!.args[0] === "drop";
        return (
          ["mysql", "psql", "sqlite3", "mongosh", "sqlplus"].includes(cmd) &&
          /\b(drop\s+(database|table)|truncate\s+table)\b/i.test(seg)
        );
      }),
  },
];

export type GateMatch = { name: string; disposition: RuleDisposition };

/**
 * Returns the matching rule to surface: a DENY match wins over a confirm
 * one, so the hardest rule is surfaced (e.g. `rm -rf build; dd of=/dev/sda`
 * is blocked as a raw device write, not merely confirmed as a recursive rm).
 * First match otherwise; undefined when nothing matches.
 */
export function findDangerousRule(command: string): GateMatch | undefined {
  const matches = RULES.filter((r) => r.test(command));
  const rule = matches.find((r) => r.disposition === "deny") ?? matches[0];
  return rule ? { name: rule.name, disposition: rule.disposition ?? "confirm" } : undefined;
}
