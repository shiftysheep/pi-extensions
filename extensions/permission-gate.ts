/**
 * Permission Gate Extension
 *
 * Heuristic guard: prompts for confirmation before bash commands that look
 * dangerous (recursive `rm`, privilege escalation via sudo/doas/pkexec,
 * world-writable `chmod`).
 *
 * This is NOT a security boundary. Shell expansion, quoting, scripts, and
 * indirect invocation can evade text matching, and a later `tool_call`
 * handler can still mutate the command after approval. For real
 * enforcement, sandbox or restrict execution itself.
 */

import { isToolCallEventType } from "@earendil-works/pi-coding-agent";

type Rule = { name: string; test: (command: string) => boolean };

/** Split a command line into shell segments (top-level separators only). */
function segments(command: string): string[] {
	return command
		.split(/&&|\|\||[;&|]|\n/)
		.map((s) => s.trim())
		.filter(Boolean);
}

/** Extract the command word (minus env-var prefixes and path) and its args. */
function commandOf(segment: string): { cmd: string; args: string[] } | undefined {
	const parts = segment.match(/\S+/g) ?? [];
	let i = 0;
	while (i < parts.length && /^[A-Za-z_]\w*=\S+$/.test(parts[i])) i++;
	if (i >= parts.length) return undefined;
	const cmd = parts[i].split("/").pop() ?? parts[i];
	return { cmd, args: parts.slice(i + 1) };
}

const rules: Rule[] = [
	{
		// rm with a recursive flag: -r, -R, -rf, -fr, -r -f, --recursive
		name: "recursive rm",
		test: (command) =>
			segments(command).some((seg) => {
				const { cmd, args } = commandOf(seg) ?? {};
				if (cmd !== "rm") return false;
				return args.some((a) => /^-/.test(a) && (a === "--recursive" || /[rR]/.test(a)));
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
		// chmod making a file world-writable: 777/0777/000777 or a+/o+ ...w
		name: "world-writable chmod",
		test: (command) =>
			segments(command).some((seg) => {
				const { cmd, args } = commandOf(seg) ?? {};
				if (cmd !== "chmod") return false;
				return args.some((a) => (Number.isInteger(Number(a)) && a % 1000 === 777) || /^(a|o)\+.*w/.test(a));
			}),
	},
];

/** Returns the name of the first dangerous rule matched, or undefined. */
export function findDangerousRule(command: string): string | undefined {
	return rules.find((r) => r.test(command))?.name;
}

export default function (pi: import("@earendil-works/pi-coding-agent").ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return undefined;

		const command = event.input.command;
		const rule = findDangerousRule(command);
		if (!rule) return undefined;

		if (!ctx.hasUI) {
			// In non-interactive mode, block by default
			return { block: true, terminate: true, reason: `Blocked: "${rule}" heuristic matched and there is no UI to confirm` };
		}

		const ok = await ctx.ui.confirm(`⚠️ Dangerous command (${rule})`, command, { signal: ctx.signal });
		if (!ok) {
			return { block: true, terminate: true, reason: "Blocked by user" };
		}
	});
}
