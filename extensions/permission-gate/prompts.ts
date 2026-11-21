/**
 * Interactive prompt plumbing for the sandbox config UI: a dimmed-description
 * select list plus the classifier option metadata shared with the menu.
 */

import type { ExtensionCommandContext, Theme } from "@earendil-works/pi-coding-agent";
import { type SelectItem, SelectList, type SelectListTheme, Text } from "@earendil-works/pi-tui";

/** Theme mapping for SelectList: accent selection, dimmed descriptions. */
export function sandboxSelectTheme(theme: Theme): SelectListTheme {
  return {
    selectedPrefix: (text) => theme.fg("accent", text),
    selectedText: (text) => theme.fg("accent", text),
    description: (text) => theme.fg("dim", text),
    scrollInfo: (text) => theme.fg("dim", text),
    noMatch: (text) => theme.fg("dim", text),
  };
}

export class SandboxSelectPrompt {
  onDone: (value: string | undefined) => void = () => {};
  dispose?: () => void;
  private readonly title: Text;
  private readonly list: SelectList;
  private readonly hint: Text;

  constructor(theme: Theme, titleText: string, items: SelectItem[]) {
    this.title = new Text(theme.fg("accent", theme.bold(titleText)), 1, 0);
    this.list = new SelectList(items, Math.min(items.length, 12), sandboxSelectTheme(theme));
    this.list.onSelect = (item) => this.onDone(item.value);
    this.list.onCancel = () => this.onDone(undefined);
    this.hint = new Text(theme.fg("dim", "↑/↓ or j/k: move · enter: select · esc: cancel"), 1, 0);
  }

  render(width: number): string[] {
    return [...this.title.render(width), ...this.list.render(width), ...this.hint.render(width)];
  }

  handleInput(data: string): void {
    this.list.handleInput(data);
  }

  invalidate(): void {
    this.title.invalidate();
    this.list.invalidate();
    this.hint.invalidate();
  }
}

/** Select prompt with a dim description on every option. Returns the chosen
 *  item's value (undefined when cancelled). The custom SelectList path is
 *  TUI-only: RPC mode exposes a callable ui.custom that never invokes the
 *  factory, so gate on ctx.mode (pi's documented guard for terminal-only UI).
 *  Other modes fall back to ctx.ui.select (plain labels, no descriptions),
 *  mapping the returned label back to the item's value. */
export async function promptSelect(
  ctx: ExtensionCommandContext,
  title: string,
  items: SelectItem[],
): Promise<string | undefined> {
  if (ctx.mode !== "tui" || typeof ctx.ui.custom !== "function") {
    const label = await ctx.ui.select(
      title,
      items.map((item) => item.label),
      {
        signal: ctx.signal,
      },
    );
    return items.find((item) => item.label === label)?.value;
  }
  return ctx.ui.custom<string | undefined>((_tui, theme, _keybindings, done) => {
    const prompt = new SandboxSelectPrompt(theme, title, items);
    let settled = false;
    let onAbort: (() => void) | undefined;
    const finish = (value: string | undefined) => {
      if (settled) return;
      settled = true;
      if (ctx.signal && onAbort) ctx.signal.removeEventListener("abort", onAbort);
      done(value);
    };
    if (ctx.signal) {
      if (ctx.signal.aborted) {
        finish(undefined);
      } else {
        onAbort = () => finish(undefined);
        ctx.signal.addEventListener("abort", onAbort, { once: true });
      }
    }
    prompt.onDone = (value) => finish(value);
    prompt.dispose = () => {
      if (ctx.signal && onAbort) ctx.signal.removeEventListener("abort", onAbort);
    };
    return prompt;
  });
}

/** Dim hint for each runner choice in the config UI. */
export const RUNNER_DESCRIPTIONS: Record<string, string> = {
  auto: "best available (bwrap → landlock → sandbox-exec)",
  none: "no OS sandbox (gate-only mode)",
  bwrap: "force bubblewrap (Linux)",
  landlock: "force Landlock (Linux 5.13+; network policy not enforced)",
  "sandbox-exec": "force macOS Seatbelt",
};

/** The classifier config keys, editable from the config menu. */
export const CLASSIFIER_OPTIONS = [
  "classifier",
  "classifierConfirmThreshold",
  "classifierDenyThreshold",
  "classifierModel",
  "classifierTimeoutMs",
  "classifierKeychain",
] as const;
export type ClassifierOption = (typeof CLASSIFIER_OPTIONS)[number];

/** Membership guard so the menu dispatch can't route a typo into the editor. */
export function isClassifierOption(option: string): option is ClassifierOption {
  return (CLASSIFIER_OPTIONS as readonly string[]).includes(option);
}
