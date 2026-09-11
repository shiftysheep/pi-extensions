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
    // env [FLAGS] [VAR=VALUE]* COMMAND — unwrap to the real command. -u
    // takes an operand that must not be mistaken for the command word.
    i++;
    while (i < parts.length) {
      const p = parts[i];
      if (p === "-u") i += 2;
      else if (/^--?\w/.test(p) || /^[A-Za-z_]\w*=\S+$/.test(p)) i++;
      else break;
    }
    if (i >= parts.length) return undefined;
    cmd = parts[i].split("/").pop() ?? parts[i];
  }
  return { cmd, args: parts.slice(i + 1) };
}

// Harmless /dev targets that are NOT raw device writes. Prefix-aware: /dev/fd/3
// and /dev/shm/file are safe, /dev/sda is not.
const SAFE_DEV_TARGETS = [
  "/dev/null",
  "/dev/stdout",
  "/dev/stderr",
  "/dev/full",
  "/dev/tty",
  "/dev/fd",
  "/dev/shm",
];

/** True for a /dev/* path that is a real device, not a harmless special file. */
function isUnsafeDevTarget(target: string): boolean {
  if (!target.startsWith("/dev/")) return false;
  return !SAFE_DEV_TARGETS.some((s) => target === s || target.startsWith(`${s}/`));
}

/**
 * The command chain of a segment: the outer command plus, when it is a
 * privilege wrapper (sudo/doas/pkexec), the wrapped inner command. Lets the
 * deny tier see through `sudo dd of=/dev/sda` and friends. Unwraps from the
 * already env-normalized args; handles the common operand-taking options.
 */
function commandChain(segment: string): Array<{ cmd: string; args: string[] }> {
  const parsed = commandOf(segment);
  if (!parsed) return [];
  const chain = [parsed];
  if (parsed.cmd === "sudo" || parsed.cmd === "doas" || parsed.cmd === "pkexec") {
    const OPT_WITH_ARG = new Set(["-u", "--user", "-g", "--group", "-C", "--close"]);
    const args = parsed.args;
    let i = 0;
    while (i < args.length && args[i].startsWith("-")) {
      i += OPT_WITH_ARG.has(args[i]) ? 2 : 1;
    }
    if (i < args.length)
      chain.push({ cmd: args[i].split("/").pop() ?? args[i], args: args.slice(i + 1) });
  }
  return chain;
}

// Redirect targets that are harmless even when written to.
const SAFE_REDIRECT_TARGETS = /^(?:null|stdout|stderr|full|tty|fd|zero|urandom|shm)(?:\/|$)/;
/**
 * Declarative command-catalog entry. A segment matches when its (possibly
 * privilege-unwrapped) command word is in `cmds` AND every provided argument
 * constraint holds. Adding a new catalogued command is a data change, not a
 * code change. Bespoke logic (flag parsing, regexes) goes in `test`.
 */
export type CatalogEntry = {
  /** Command words to match (basename, after env/sudo unwrapping). */
  cmds: readonly string[];
  /** args[0] must be one of these (or first non-flag arg when `positional`). */
  sub?: readonly string[];
  /** args[1] must be one of these (or second non-flag arg when `positional`). */
  sub2?: readonly string[];
  /** Match sub/sub2 against the first non-flag argument(s) — tolerates
   * global options like `terraform -chdir=prod destroy`. */
  positional?: boolean;
  /** args must contain at least one of these. */
  has?: readonly string[];
  /** args must contain NONE of these (e.g. dry-run/help forms). */
  notHas?: readonly string[];
  /** Escape hatch for bespoke argument logic. */
  test?: (args: string[], segment: string) => boolean;
};

/** True when any command in the segment's chain satisfies a catalog entry. */
function catalogMatches(entries: readonly CatalogEntry[], segment: string): boolean {
  return commandChain(segment).some(({ cmd, args }) =>
    entries.some((e) => {
      if (!e.cmds.includes(cmd)) return false;
      const a = e.positional ? args.filter((x) => !x.startsWith("-")) : args;
      if (e.sub && !e.sub.includes(a[0] ?? "")) return false;
      if (e.sub2 && !e.sub2.includes(a[1] ?? "")) return false;
      if (e.has && !e.has.some((h) => args.includes(h))) return false;
      if (e.notHas && e.notHas.some((h) => args.includes(h))) return false;
      if (e.test && !e.test(args, segment)) return false;
      return true;
    }),
  );
}

const PRIVILEGE_ESCALATION: readonly CatalogEntry[] = [{ cmds: ["sudo", "doas", "pkexec"] }];

const POWER_ACTIONS: readonly CatalogEntry[] = [
  { cmds: ["shutdown", "reboot", "poweroff", "halt"] },
];

const DEVICE_WIPES: readonly CatalogEntry[] = [
  { cmds: ["wipefs"], notHas: ["--no-act", "--help"] },
  { cmds: ["blkdiscard"], notHas: ["--dry-run"] },
  { cmds: ["sgdisk"], has: ["--zap-all"] },
  { cmds: ["parted"], has: ["rm"] },
];

const VOLUME_DESTROYS: readonly CatalogEntry[] = [
  { cmds: ["lvremove", "vgremove"], notHas: ["--test"] },
  { cmds: ["zpool", "zfs"], sub: ["destroy"] },
];

/**
 * Curated remote-destruction catalog (best-effort; deliberately narrow —
 * see the file header). New entries are data, not code.
 */
const REMOTE_DESTRUCTION: readonly CatalogEntry[] = [
  {
    cmds: ["terraform", "terragrunt", "cdk", "pulumi", "vagrant"],
    sub: ["destroy"],
    positional: true,
  },
  { cmds: ["sam"], sub: ["delete"], positional: true },
  { cmds: ["serverless", "sls"], sub: ["remove"], positional: true },
  {
    cmds: ["az"],
    test: (args) => {
      const gi = args.indexOf("group");
      return gi !== -1 && args[gi + 1] === "delete";
    },
  },
  { cmds: ["gcloud"], sub: ["projects"], sub2: ["delete"], positional: true },
  {
    cmds: ["docker"],
    test: (args) => {
      const vi = args.indexOf("volume");
      return vi !== -1 && (args[vi + 1] === "rm" || args[vi + 1] === "prune");
    },
  },
  {
    // Resource is the arg AFTER `delete`; match namespace forms only —
    // `kubectl delete pod ns` must not prompt.
    cmds: ["kubectl"],
    test: (args) => {
      const di = args.findIndex((a) => a === "delete");
      if (di === -1) return false;
      return /^(namespaces?|ns)(\/|$)/.test(args[di + 1] ?? "");
    },
  },
  {
    cmds: ["aws"],
    test: (args) => {
      const si = args.findIndex((a) => a === "s3");
      return si !== -1 && args[si + 1] === "rm" && args.includes("--recursive");
    },
  },
  {
    cmds: ["gh"],
    test: (args) => {
      const ri = args.indexOf("repo");
      return ri !== -1 && args[ri + 1] === "delete";
    },
  },
  { cmds: ["npm"], sub: ["unpublish"], positional: true },
];

const DB_DESTRUCTION: readonly CatalogEntry[] = [
  { cmds: ["mysqladmin"], sub: ["drop"] },
  { cmds: ["dropdb"] },
  {
    cmds: ["mysql", "psql", "sqlite3", "mongosh", "sqlplus"],
    test: (_args, seg) => /\b(drop\s+(database|table)|truncate\s+table)\b/i.test(seg),
  },
];

const RULES: GateRule[] = [
  {
    // rm with a recursive flag: -r, -R, -rf, -fr, -r -f, --recursive.
    // Irreversible even inside writable roots — always confirmed.
    name: "recursive rm",
    test: (command) =>
      segments(command).some((seg) => {
        const parsed = commandOf(seg);
        if (parsed?.cmd !== "rm") return false;
        return parsed.args.some((a) => a === "--recursive" || /^-(?!-)[A-Za-z]*[rR]/.test(a));
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
    test: (command) => segments(command).some((seg) => catalogMatches(PRIVILEGE_ESCALATION, seg)),
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
        // Target must be a clean path at the segment end: `> /dev/null 2>&1`
        // splits on & and must not be read as a device target.
        const m = />>?\s*(\/dev\/[A-Za-z0-9._\-/]+)$/.exec(seg.trim());
        return m !== null && isUnsafeDevTarget(m[1]);
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
    test: (command) => segments(command).some((seg) => catalogMatches(DEVICE_WIPES, seg)),
  },
  {
    // LVM/ZFS volume and pool destruction.
    name: "volume/pool destroy",
    disposition: "deny",
    test: (command) => segments(command).some((seg) => catalogMatches(VOLUME_DESTROYS, seg)),
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
    test: (command) => segments(command).some((seg) => catalogMatches(POWER_ACTIONS, seg)),
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
        // Skip git GLOBAL options (before the subcommand); -C/-c/-p/
        // --work-tree/--namespace take an operand.
        const GIT_OPT_WITH_ARG = new Set(["-C", "-c", "-p", "--work-tree", "--namespace"]);
        const args = parsed.args;
        let i = 0;
        while (i < args.length && args[i].startsWith("-")) {
          i += GIT_OPT_WITH_ARG.has(args[i]) ? 2 : 1;
        }
        const [sub, ...rest] = args.slice(i);
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
          return (
            rest.includes("-D") ||
            (rest.includes("-d") && rest.includes("-f")) ||
            (rest.includes("--delete") && (rest.includes("-f") || rest.includes("--force")))
          );
        return sub === "filter-repo" || sub === "filter-branch";
      }),
  },
  {
    // Curated remote-destruction operations (best-effort; the catalog is
    // deliberately narrow — see the file header).
    name: "remote destruction (cloud/IaC)",
    test: (command) => segments(command).some((seg) => catalogMatches(REMOTE_DESTRUCTION, seg)),
  },
  {
    // Destructive SQL issued through a known database client.
    name: "database destruction",
    test: (command) => segments(command).some((seg) => catalogMatches(DB_DESTRUCTION, seg)),
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
