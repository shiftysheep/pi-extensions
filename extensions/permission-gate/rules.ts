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

import { findDangerousPowerShellRule } from "./powershell-rules.js";

export type RuleDisposition = "confirm" | "deny";

export type GateRule = {
  name: string;
  /** "deny" = hard block (human-only, no prompt). Default: "confirm". */
  disposition?: RuleDisposition;
  test: (command: string) => boolean;
};

/** Split a command line into shell segments (top-level separators only).
 * Separators inside single/double quotes are literal text, not separators.
 * `>&` and `>|` are REDIRECTION operators, not separators: an unescaped `>`
 * immediately before `&`/`|` keeps it inside the segment (including at the
 * very start of the command). An ESCAPED `>` (`\>`) is a literal, so the
 * following `|`/`&` is a real separator; backslash parity is tracked
 * (`\\>` = escaped backslash + real redirect). */
export function segments(command: string): string[] {
  const out: string[] = [];
  let cur = "";
  let prev: string | null = null; // previous original character
  let prevEscaped = false; // ...and whether it was backslash-escaped
  let quote: string | null = null; // active quote character (' or "), if any
  const flush = (): void => {
    const t = cur.trim();
    if (t) out.push(t);
    cur = "";
  };
  let i = 0;
  while (i < command.length) {
    const ch = command[i];
    if (quote !== null) {
      const consumed = consumeQuotedSegmentChar(command, i, quote, cur);
      cur = consumed.cur;
      if (consumed.closed) quote = null;
      if (consumed.updatePrev) prev = consumed.prev;
      prevEscaped = false;
      i = consumed.next;
      continue;
    }
    if (isQuote(ch)) {
      quote = ch;
      cur += ch;
      prev = ch;
      prevEscaped = false;
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < command.length) {
      cur += ch + command[i + 1];
      prev = command[i + 1];
      prevEscaped = true;
      i += 2;
      continue;
    }
    if (isSegmentSeparator(ch)) {
      const step = consumeSegmentSeparator(command, i, ch, prev, prevEscaped);
      if (step.flush) flush();
      else cur += step.text;
      prev = step.prev;
      prevEscaped = false;
      i = step.next;
      continue;
    }
    cur += ch;
    prev = ch;
    prevEscaped = false;
    i++;
  }
  flush();
  return out;
}

function isSegmentSeparator(ch: string): boolean {
  return ch === "\n" || ch === ";" || ch === "&" || ch === "|";
}

function isQuote(ch: string): boolean {
  return ch === "'" || ch === '"';
}

function consumeSegmentSeparator(
  command: string,
  index: number,
  ch: string,
  previous: string | null,
  previousEscaped: boolean,
): { flush: boolean; text: string; prev: string; next: number } {
  if ((ch === "&" || ch === "|") && command[index + 1] === ch)
    return { flush: true, text: "", prev: ch, next: index + 2 };
  const redirect = (ch === "&" || ch === "|") && previous === ">" && !previousEscaped;
  return { flush: !redirect, text: redirect ? ch : "", prev: ch, next: index + 1 };
}

function consumeQuotedSegmentChar(command: string, i: number, quote: string, cur: string) {
  const ch = command[i];
  if (quote === '"' && ch === "\\" && i + 1 < command.length)
    return {
      cur: cur + ch + command[i + 1],
      closed: false,
      prev: "",
      updatePrev: false,
      next: i + 2,
    };
  return { cur: cur + ch, closed: ch === quote, prev: ch, updatePrev: true, next: i + 1 };
}

/** Extract the command word (minus env-var prefixes, `env` wrappers, and
 * path) and its args. Known limitation: scripts, quoting tricks, and
 * interpreter one-liners still evade this — the gate is a heuristic, not a
 * security boundary. (Benign wrappers nohup/nice/time/exec/command are
 * unwrapped by commandChain, and shell -c/eval payloads by the payload
 * tier in findDangerousRule.) */
function commandOf(segment: string): { cmd: string; args: string[] } | undefined {
  const parts = segment.match(/\S+/g) ?? [];
  let i = 0;
  while (i < parts.length && /^[A-Za-z_]\w*=\S+$/.test(parts[i])) i++;
  if (i >= parts.length) return undefined;
  let cmd = parts[i].split("/").pop() ?? parts[i];
  if (cmd === "env") {
    // env [FLAGS] [VAR=VALUE]* [--] COMMAND — unwrap to the real command.
    // -u/-C/--unset take an operand that must not be mistaken for the
    // command word; `--` terminates options.
    i = envCommandIndex(parts, i + 1);
    if (i >= parts.length) return undefined;
    cmd = parts[i].split("/").pop() ?? parts[i];
  }
  // Note: operands after a `--` terminator are KEPT (they are real targets,
  // e.g. `tee -- /dev/sda`); option-sensitive rules like recursive rm stop
  // interpreting them as flags themselves.
  return { cmd, args: parts.slice(i + 1) };
}

function envCommandIndex(parts: string[], index: number): number {
  let i = index;
  while (i < parts.length) {
    const part = parts[i];
    if (part === "--") return i + 1;
    if (part === "-u" || part === "-C" || part === "--unset") i += 2;
    else if (/^--?\w/.test(part) || /^[A-Za-z_]\w*=\S+$/.test(part)) i++;
    else break;
  }
  return i;
}

// Harmless /dev targets that are NOT raw device writes. Prefix-aware: /dev/fd/3
// and /dev/shm/file are safe, /dev/sda is not. Writing to /dev/zero
// discards data; /dev/urandom is read-only.
const SAFE_DEV_TARGETS = [
  "/dev/null",
  "/dev/stdout",
  "/dev/stderr",
  "/dev/full",
  "/dev/tty",
  "/dev/fd",
  "/dev/shm",
  "/dev/zero",
  "/dev/urandom",
];

/** bash virtual network sockets: /dev/tcp/HOST/PORT, /dev/udp/HOST/PORT. */
const NETSOCKET_RE = /^\/dev\/(tcp|udp)\//;

/** True for a /dev/* path that is a real device, not a harmless special file.
 * bash's virtual network sockets (/dev/tcp, /dev/udp) are NOT devices — a
 * redirect there opens a connection; the "network socket redirect" rule
 * confirms those instead of the raw-device deny tier. */
function isUnsafeDevTarget(target: string): boolean {
  if (!target.startsWith("/dev/")) return false;
  if (NETSOCKET_RE.test(target)) return false;
  return !SAFE_DEV_TARGETS.some((s) => target === s || target.startsWith(`${s}/`));
}

/**
 * Parse a redirection target word starting at `from` (just past the
 * operator): skip whitespace, then read until whitespace or an unquoted
 * redirection/separator operator or parenthesis. Quoted spans fold into the
 * target literally (`>'tmp'/dev/sda` → `tmp/dev/sda`); a backslash escapes
 * the next character outside single quotes. Returns the target text and the
 * index just past it.
 */
function parseRedirectTarget(segment: string, from: number): { target: string; end: number } {
  let j = from;
  while (j < segment.length && /\s/.test(segment[j])) j++;
  let target = "";
  while (j < segment.length) {
    const c = segment[j];
    if (
      /\s/.test(c) ||
      c === ">" ||
      c === "&" ||
      c === "|" ||
      c === ";" ||
      c === "(" ||
      c === ")" ||
      c === "<"
    )
      break;
    if (c === "'" || c === '"') {
      const quoted = readRedirectQuote(segment, j, c);
      target += quoted.text;
      j = quoted.end;
      continue;
    }
    if (c === "\\" && j + 1 < segment.length) {
      j++;
      target += segment[j];
      j++;
      continue;
    }
    target += c;
    j++;
  }
  return { target, end: j };
}

function readRedirectQuote(
  segment: string,
  start: number,
  quote: string,
): { text: string; end: number } {
  let j = start + 1;
  let text = "";
  while (j < segment.length && segment[j] !== quote) {
    if (quote === '"' && segment[j] === "\\" && j + 1 < segment.length) j++;
    text += segment[j] ?? "";
    j++;
  }
  return { text, end: j + 1 };
}

/** A redirection operator and its target word within a segment. */
type Redirect = { op: string; target: string };

/**
 * All redirections in a segment, quote-aware, BOTH directions: `>`, `>>`,
 * `>&`, `>|` (output) and `<`, `<>` (input). `<<` heredocs and `<<<`
 * here-strings are skipped — their "targets" are delimiters or literals, not
 * paths. Escaped characters and quoted spans are not redirections (a quoted
 * EXAMPLE of a redirect is not a redirect). Parentheses matter: in
 * `s=$(cmd 2>/dev/null)` the target is `/dev/null`, NOT `/dev/null)`.
 */
/** Parse a redirect operator (> >> < <> >& >|) starting at index i.
 * Returns the operator string and the index just past it. */
function parseRedirectOp(segment: string, i: number): { op: string; next: number } {
  const ch = segment[i];
  let j = i + 1;
  let op = ch;
  if (ch === "<") {
    if (segment[j] === "<") return { op: "<<", next: j + 1 }; // heredoc: not a path
    if (segment[j] === ">") {
      j++;
      op = "<>";
    }
  } else {
    if (segment[j] === ">") {
      j++;
      op = ">>";
    }
    if (segment[j] === "&" || segment[j] === "|") {
      j++;
      op += segment[j];
    }
  }
  return { op, next: j };
}

function redirects(segment: string): Redirect[] {
  const out: Redirect[] = [];
  let i = 0;
  while (i < segment.length) {
    const ch = segment[i];
    if (ch === "\\" && i + 1 < segment.length) {
      i += 2;
      continue;
    }
    if (ch === "'" || ch === '"') {
      i = skipQuotedText(segment, i, ch);
      continue;
    }
    if (ch === ">" || ch === "<") {
      const { op, next } = parseRedirectOp(segment, i);
      if (op === "<<") {
        i = next;
        continue;
      }
      const { target, end } = parseRedirectTarget(segment, next);
      out.push({ op, target });
      i = end;
      continue;
    }
    i++;
  }
  return out;
}

function skipQuotedText(text: string, start: number, quote: string): number {
  let i = start + 1;
  while (i < text.length && text[i] !== quote) {
    if (quote === '"' && text[i] === "\\" && i + 1 < text.length) i++;
    i++;
  }
  return i + 1;
}

/** Output-redirection targets only (the raw-device deny rule's surface). */
function redirectTargets(segment: string): string[] {
  return redirects(segment)
    .filter((r) => r.op.startsWith(">"))
    .map((r) => r.target);
}

/** Option-sensitive check that ignores operands after a `--` terminator. */
function optionsBeforeTerminator(args: string[]): string[] {
  const dd = args.indexOf("--");
  return dd === -1 ? args : args.slice(0, dd);
}

/** Operand-taking options for sudo/doas (pkexec takes none). -h is HOST for
 * sudo, not help. -A (askpass) and -P (preserve-groups) are BOOLEAN. */
const PRIV_OPTS_WITH_ARG = new Set([
  "-u",
  "--user",
  "-g",
  "--group",
  "-C",
  "--close",
  "-D",
  "--directory",
  "-h",
  "--host",
  "-R",
  "--chroot",
  "-a",
  "--ipv4-addr",
  "--ipv6-addr",
  "-p",
  "--prompt",
  "-T",
  "--timestamp",
]);

/** Operand-taking options for the benign execution wrappers (nice/time). */
const WRAP_OPTS_WITH_ARG = new Set(["-n", "--adjust-cpu-priority", "-p", "--pid", "-g", "--group"]);

/** Benign execution wrappers the rules see through: the inner command is
 * the real subject. `time`/`exec`/`command` are shell keywords as often as
 * binaries; treating them as wrappers is safe either way. */
const BENIGN_WRAPPERS = ["nohup", "nice", "time", "exec", "command"];

/**
 * The command chain of a segment: the outer command plus wrapped inner
 * commands, through privilege wrappers (sudo/doas/pkexec) and benign
 * execution wrappers (nohup/nice/time/exec/command). Lets the deny tier see
 * through `sudo dd of=/dev/sda` and `nohup rm -rf /` and friends. Unwraps
 * from the already env-normalized args; handles the common operand-taking
 * options. Bounded to 3 hops.
 */
function commandChain(segment: string): Array<{ cmd: string; args: string[] }> {
  const parsed = commandOf(segment);
  if (!parsed) return [];
  const chain = [parsed];
  let current = parsed;
  for (let hops = 0; hops < 3; hops++) {
    const { cmd, args } = current;
    const priv = cmd === "sudo" || cmd === "doas" || cmd === "pkexec";
    if (!priv && !BENIGN_WRAPPERS.includes(cmd)) break;
    const optWithArg = priv ? PRIV_OPTS_WITH_ARG : WRAP_OPTS_WITH_ARG;
    let i = 0;
    while (i < args.length && args[i].startsWith("-")) {
      i += optWithArg.has(args[i]) ? 2 : 1;
    }
    if (i >= args.length) break;
    current = { cmd: args[i].split("/").pop() ?? args[i], args: args.slice(i + 1) };
    chain.push(current);
  }
  return chain;
}

/**
 * Positional arguments: flags dropped, and operands of known operand-taking
 * options dropped too (a generic flag filter would leave `--prefix /tmp`'s
 * "/tmp" in a positional slot).
 */
function positionalArgs(args: string[], optsWithArg: readonly string[] = []): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("-")) {
      if (optsWithArg.includes(a)) i++; // skip the option's operand
      continue;
    }
    out.push(a);
  }
  return out;
}
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
  /** Options (with separate operands) to skip when computing positionals. */
  optsWithArg?: readonly string[];
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
    entries.some((entry) => catalogEntryMatches(entry, cmd, args, segment)),
  );
}

function catalogEntryMatches(
  entry: CatalogEntry,
  cmd: string,
  args: string[],
  segment: string,
): boolean {
  if (!entry.cmds.includes(cmd)) return false;
  const values = entry.positional ? positionalArgs(args, entry.optsWithArg) : args;
  if (entry.sub && !entry.sub.includes(values[0] ?? "")) return false;
  if (entry.sub2 && !entry.sub2.includes(values[1] ?? "")) return false;
  if (entry.has && !entry.has.some((has) => args.includes(has))) return false;
  if (entry.notHas && entry.notHas.some((has) => args.includes(has))) return false;
  return !entry.test || entry.test(args, segment);
}

const PRIVILEGE_ESCALATION: readonly CatalogEntry[] = [{ cmds: ["sudo", "doas", "pkexec"] }];

const POWER_ACTIONS: readonly CatalogEntry[] = [
  { cmds: ["shutdown", "reboot", "poweroff", "halt"] },
];

function destructiveGitArgs(args: string[]): boolean {
  const optionsWithArg = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace"]);
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) i += optionsWithArg.has(args[i]) ? 2 : 1;
  const [sub, ...rest] = args.slice(i);
  if (sub === "push")
    return rest.some(
      (arg) =>
        ["--force", "--force-with-lease", "-f", "--delete"].includes(arg) ||
        arg.startsWith("--force-with-lease=") ||
        arg.startsWith("+"),
    );
  if (sub === "reset") return rest.includes("--hard");
  if (sub === "clean")
    return rest.some((arg) => arg === "-f" || arg === "--force" || /^-[a-z]*f/.test(arg));
  if (sub === "branch") return destructiveBranchArgs(rest);
  return sub === "filter-repo" || sub === "filter-branch";
}

function destructiveBranchArgs(args: string[]): boolean {
  return (
    args.includes("-D") ||
    (args.includes("-d") && args.includes("-f")) ||
    args.some((arg) => /^-(?!-)[A-Za-z]+$/.test(arg) && /[dD]/.test(arg) && /f/.test(arg)) ||
    (args.includes("--delete") && (args.includes("-f") || args.includes("--force")))
  );
}

const DEVICE_WIPES: readonly CatalogEntry[] = [
  // -n/--no-act is a dry run: inspect, not wipe. Only OPTIONS (before any
  // `--`) count — an operand named --no-act is not a dry-run flag.
  {
    cmds: ["wipefs"],
    test: (args) =>
      !optionsBeforeTerminator(args).some(
        (a) => a === "--no-act" || a === "--help" || /^-(?!-)[A-Za-z]*n/.test(a),
      ),
  },
  {
    cmds: ["blkdiscard"],
    test: (args) =>
      !optionsBeforeTerminator(args).some((a) => a === "--dry-run" || /^-(?!-)[A-Za-z]*n/.test(a)),
  },
  { cmds: ["sgdisk"], has: ["--zap-all"] },
  { cmds: ["parted"], has: ["rm"] },
];

const VOLUME_DESTROYS: readonly CatalogEntry[] = [
  // -t/--test is a dry run (options only, before any `--`).
  {
    cmds: ["lvremove", "vgremove"],
    test: (args) =>
      !optionsBeforeTerminator(args).some((a) => a === "--test" || /^-(?!-)[A-Za-z]*t/.test(a)),
  },
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
    optsWithArg: ["-chdir", "--chdir", "--cwd"],
  },
  { cmds: ["sam"], sub: ["delete"], positional: true, optsWithArg: ["--region", "-r"] },
  {
    cmds: ["serverless", "sls"],
    sub: ["remove"],
    positional: true,
    optsWithArg: ["-s", "--stage", "-r", "--region"],
  },
  {
    cmds: ["az"],
    test: (args) => {
      const gi = args.indexOf("group");
      return gi !== -1 && args[gi + 1] === "delete";
    },
  },
  {
    cmds: ["gcloud"],
    sub: ["projects"],
    sub2: ["delete"],
    positional: true,
    optsWithArg: ["--project"],
  },
  {
    cmds: ["docker"],
    positional: true,
    optsWithArg: ["--host", "-H"],
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
  {
    cmds: ["npm"],
    sub: ["unpublish"],
    positional: true,
    optsWithArg: [
      "--prefix",
      "-C",
      "--userconfig",
      "--globalconfig",
      "--local-prefix",
      "--call",
      "-c",
      "--loglevel",
      "--registry",
      "-r",
    ],
  },
];

/** Shells whose `-c` payload (or bare stdin) is a new command surface. */
const SHELL_CMDS = new Set(["bash", "sh", "dash", "zsh", "ksh"]);
/** Downloaders whose piped output is code when it feeds a shell. */
const DOWNLOADER_CMDS = new Set(["curl", "wget", "fetch", "axel", "aria2c"]);
/** Recursion budget for the shell-payload tier (guards nested `bash -c`). */
const MAX_PAYLOAD_DEPTH = 3;

/**
 * Drop the first `words` whitespace-delimited words of a segment and return
 * the remainder, minus one layer of matching surrounding quotes. The payload
 * is sliced from the RAW segment (not re-joined tokens) so nested quoting
 * survives for the recursive re-gate.
 */
function payloadAfterWord(segment: string, words: number): string {
  let rest = segment.trimStart();
  for (let i = 0; i < words; i++) {
    const m = /^\S+\s+/.exec(rest);
    if (!m) return "";
    rest = rest.slice(m[0].length);
  }
  const payload = rest.trim();
  if (payload.length >= 2) {
    const q = payload[0];
    if ((q === "'" || q === '"') && payload.endsWith(q)) return payload.slice(1, -1);
  }
  return payload;
}

/**
 * The literal payload of a shell-invocation segment, if any:
 * `bash -c '…'` / `sh -c` / `zsh -lc` (payload = everything after the -c
 * word) or `eval '…'`. commandOf identifies the command (env/path/
 * wrapper-normalized); the payload offset is located on the raw tokens so
 * env prefixes and extra flags are skipped correctly and the payload keeps
 * its internal quoting for the recursive re-gate.
 */
function shellPayloadOf(segment: string): string | undefined {
  const parsed = commandOf(segment);
  if (!parsed) return undefined;
  const { cmd, args } = parsed;
  const parts = segment.match(/\S+/g) ?? [];
  if (cmd === "eval") {
    const wi = parts.findIndex((p) => p === "eval");
    return wi === -1 ? undefined : payloadAfterWord(segment, wi + 1);
  }
  if (!SHELL_CMDS.has(cmd)) return undefined;
  if (!args.some((a) => a === "-c" || a === "-lc")) return undefined;
  const ci = parts.findIndex((p) => p === "-c" || p === "-lc");
  if (ci === -1) return undefined;
  return payloadAfterWord(segment, ci + 1);
}

/** True when a payload contains command substitution or process
 * substitution — its effects cannot be judged from the literal text. */
function payloadIsDynamic(payload: string): boolean {
  return /\$\(|`|<\(/.test(payload);
}

const DB_DESTRUCTION: readonly CatalogEntry[] = [
  { cmds: ["mysqladmin"], sub: ["drop"] },
  { cmds: ["dropdb"] },
  {
    cmds: ["mysql", "psql", "sqlite3", "mongosh", "sqlplus"],
    test: (_args, seg) => /\b(drop\s+(database|table)|truncate\s+table)\b/i.test(seg),
  },
];

/**
 * Service lifecycle stops: stopping/disabling/masking a service is a
 * human-intent operation (outage risk); restarting is left ungated.
 * `service` takes the unit FIRST and the action last (`service nginx stop`).
 */
const SERVICE_STOPS: readonly CatalogEntry[] = [
  {
    cmds: ["systemctl"],
    sub: ["stop", "disable", "mask", "kill"],
    positional: true,
    optsWithArg: ["--root", "-H", "--host", "-M", "--machine"],
  },
  {
    cmds: ["service"],
    test: (args) => ["stop", "shutdown"].includes(args[args.length - 1] ?? ""),
  },
];

/** Paths where a recursive ownership change is a system-wide act. */
const BROAD_OWNERSHIP_PATHS = [
  "/",
  "/etc",
  "/usr",
  "/var",
  "/boot",
  "/home",
  "/root",
  "/opt",
  "~",
  "$HOME",
];

const RULES: GateRule[] = [
  {
    // rm with a recursive flag: -r, -R, -rf, -fr, -r -f, --recursive.
    // Irreversible even inside writable roots — always confirmed.
    name: "recursive rm",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd, args }) => {
          if (cmd !== "rm") return false;
          // After `--`, args are literal operands (`rm -- -r` deletes a file
          // named "-r"), not flags.
          const dd = args.indexOf("--");
          const opts = dd === -1 ? args : args.slice(0, dd);
          return opts.some((a) => a === "--recursive" || /^-(?!-)[A-Za-z]*[rR]/.test(a));
        }),
      ),
  },
  {
    // chmod making a file world-writable: 777/0777/000777 or a+/o+ ...w.
    // Irreversible-ish (permissions are hard to reconstruct) — always confirmed.
    name: "world-writable chmod",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(
          ({ cmd, args }) =>
            cmd === "chmod" &&
            args.some(
              (a) =>
                (Number.isInteger(Number(a)) && Number(a) % 1000 === 777) || /^(a|o)\+.*w/.test(a),
            ),
        ),
      ),
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
      segments(command).some((seg) => redirectTargets(seg).some(isUnsafeDevTarget)),
  },
  {
    // bash virtual network sockets: `> /dev/tcp/H/P` (incl. `>&` and the
    // classic `bash -i >& /dev/tcp/…` reverse shell), `<`/`<>` input forms,
    // and /dev/udp. A NETWORK action requiring human intent — confirmed,
    // not hard-blocked as a disk write (which it is not).
    name: "network socket redirect",
    test: (command) =>
      segments(command).some((seg) => redirects(seg).some((r) => NETSOCKET_RE.test(r.target))),
  },
  {
    // Writers taking a raw device as an argument: tee/shred (any target),
    // cp/mv (destination = last arg).
    name: "raw device write (argument)",
    disposition: "deny",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd, args }) => {
          if (cmd === "tee" || cmd === "shred") return args.some(isUnsafeDevTarget);
          if (cmd === "cp" || cmd === "mv") {
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
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd, args }) => cmd === "git" && destructiveGitArgs(args)),
      ),
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
  {
    // Service lifecycle stops (outage risk — human intent).
    name: "service stop",
    test: (command) => segments(command).some((seg) => catalogMatches(SERVICE_STOPS, seg)),
  },
  {
    // Recursive ownership change on a system-wide path.
    name: "broad recursive chown",
    test: (command) =>
      segments(command).some((seg) =>
        commandChain(seg).some(({ cmd, args }) => {
          if (cmd !== "chown") return false;
          const dd = args.indexOf("--");
          const opts = dd === -1 ? args : args.slice(0, dd);
          const recursive = opts.some(
            (a) => a === "-R" || a === "--recursive" || /^-(?!-)[A-Za-z]*R/.test(a),
          );
          return recursive && args.some((a) => BROAD_OWNERSHIP_PATHS.includes(a));
        }),
      ),
  },
  {
    // Download-and-execute: a downloader's output piped into a shell reading
    // stdin (`curl … | bash`, `wget -qO- … | sh -s`). The payload is remote
    // and unreadable — always confirmed.
    name: "download to shell",
    test: (command) => {
      const segs = segments(command);
      return segs.some((seg, i) => {
        const parsed = commandOf(seg);
        if (!parsed || !SHELL_CMDS.has(parsed.cmd)) return false;
        const stdinOnly = parsed.args.length === 0 || parsed.args.every((a) => a === "-s");
        if (!stdinOnly) return false;
        return segs.slice(0, i).some((prev) => {
          const p = commandOf(prev);
          return p !== undefined && DOWNLOADER_CMDS.has(p.cmd);
        });
      });
    },
  },
];

export type GateMatch = { name: string; disposition: RuleDisposition };

/**
 * Returns the matching rule to surface: a DENY match wins over a confirm
 * one, so the hardest rule is surfaced (e.g. `rm -rf build; dd of=/dev/sda`
 * is blocked as a raw device write, not merely confirmed as a recursive rm).
 * First match otherwise; undefined when nothing matches.
 *
 * When the static rules miss, a SHELL-PAYLOAD TIER sees through
 * `bash -c '…'` / `eval '…'` into the payload: a literal payload is re-gated
 * recursively (an inner deny stays a deny, a harmless payload stays silent),
 * while a dynamic payload (command/process substitution) or an exhausted
 * nesting budget is confirmed. `depth` is the recursion budget, not part of
 * the public contract — callers gate the original command with depth 0.
 */
export function findDangerousRule(command: string, depth = 0): GateMatch | undefined {
  const matches = RULES.filter((r) => r.test(command));
  const rule = matches.find((r) => r.disposition === "deny") ?? matches[0];
  if (rule) return { name: rule.name, disposition: rule.disposition ?? "confirm" };
  for (const seg of segments(command)) {
    const payload = shellPayloadOf(seg);
    if (payload === undefined || payload === "") continue;
    if (depth >= MAX_PAYLOAD_DEPTH) return { name: "nested shell payload", disposition: "confirm" };
    if (payloadIsDynamic(payload)) return { name: "dynamic shell payload", disposition: "confirm" };
    const inner = findDangerousRule(payload, depth + 1);
    if (inner) return inner;
  }
  return undefined;
}

/**
 * Static dispatch by shell: PowerShell has its own rule set (cmdlets/aliases
 * differ from bash), so it is NEVER routed through the bash tokenizer.
 * Single source of truth shared by the production gate and the benchmark,
 * so the two cannot drift apart.
 */
export function findStaticMatch(
  shell: "bash" | "powershell",
  command: string,
): GateMatch | undefined {
  return shell === "powershell" ? findDangerousPowerShellRule(command) : findDangerousRule(command);
}
