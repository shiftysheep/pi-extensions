/**
 * Model resolution for the advisor extension: registry lookups, spec parsing,
 * the interactive picker, and target formatting.
 */

import { setTimeout as delay } from "node:timers/promises";
import type { Model } from "@earendil-works/pi-ai";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  type AdvisorReasoningEffort,
  type AdvisorTarget,
  REASONING_EFFORTS,
  splitEffortSuffix,
} from "../lib/advisor-utils.js";

export type AdvisorSlot = "primary" | "fallback";
export function findModel(ctx: ExtensionContext, target: AdvisorTarget): Model<any> {
  const matches = ctx.modelRegistry
    .getAll()
    .filter(
      (model) =>
        model.id === target.model && (!target.provider || model.provider === target.provider),
    );
  if (matches.length === 1) return matches[0];
  if (matches.length > 1)
    throw new Error(
      `Model "${target.model}" is offered by multiple providers. Specify advisor.provider.`,
    );
  const scope = target.provider ? ` on provider "${target.provider}"` : "";
  throw new Error(
    `Advisor model "${target.model}" is not configured${scope}. Use a provider/model shown by Pi's /model command.`,
  );
}

/** Resolve an input like `provider/model-id` (optionally `@effort`) or bare `model-id`, validating against the registry. */
export function resolveSpec(ctx: ExtensionContext, spec: string): AdvisorTarget {
  const { base: trimmed, effort: suffixEffort } = splitEffortSuffix(spec);
  if (!trimmed) throw new Error("Empty advisor model specification.");
  // Model IDs don't contain "/", so try provider/model first, then a bare whole-modelId match.
  const interpretations: AdvisorTarget[] = [];
  const slash = trimmed.indexOf("/");
  if (slash > 0 && slash < trimmed.length - 1) {
    interpretations.push({
      provider: trimmed.slice(0, slash).trim(),
      model: trimmed.slice(slash + 1).trim(),
    });
  }
  interpretations.push({ model: trimmed });
  let lastError = "";
  for (const target of interpretations) {
    try {
      findModel(ctx, target);
      return suffixEffort ? { ...target, effort: suffixEffort } : target;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
  }
  throw new Error(`Could not resolve "${trimmed}". ${lastError}`);
}
export function formatTarget(target: AdvisorTarget | undefined): string {
  if (!target) return "(unset)";
  const suffix = target.effort ? `@${target.effort}` : "";
  return `${target.provider ?? "*"}/${target.model}${suffix}`;
}
/**
 * Best-effort pre-refresh of a near-expiry OAuth credential in the host's
 * canonical credential store, so a spawned child (which copies auth.json into a
 * throwaway agent dir) is *less likely* to need to refresh on its own copy.
 *
 * Why: the child's auth.json is deleted when it exits, so a refresh the child
 * performs on its own copy would rotate the token in a store that is then
 * discarded — for a rotating/single-use refresh token that invalidates the
 * host's refresh token. Refreshing in the host first means the child copies an
 * already-fresh token and usually never refreshes at all.
 *
 * This is a **mitigation, not a guarantee.** pi only refreshes a token that is
 * within its ~5-minute near-expiry window; a token just *outside* that window
 * at pre-refresh time can still cross into it during the child's run (especially
 * a long explore consultation), at which point the child would rotate it on its
 * disposable copy. Fully eliminating that race requires coordinating refresh and
 * persistence through a single canonical store (or a read-only child store),
 * which is part of the child-credential/environment design deferred to issue #8.
 *
 * `ctx.modelRegistry.getProviderAuth` resolves the provider's auth through pi —
 * which refreshes a near-expiry token and persists the rotated credential into
 * the host's real auth.json — so the child copies the fresh token.
 *
 * Best-effort: never throws. A refresh failure (or a hung refresh that the cap
 * times out) just means the child reports its own auth error and the fallback
 * chain handles it; we must not block a consultation because a proactive
 * refresh could not complete. API-key providers (no OAuth) are a fast no-op.
 */
export async function preRefreshProviderAuth(
  ctx: ExtensionContext,
  providerId: string,
): Promise<void> {
  try {
    const provider = ctx.modelRegistry.getProvider(providerId);
    if (!provider?.auth?.oauth) return; // API-key / env provider: nothing to refresh.
    // Cap the wait: a refresh is a short network call, but a hung refresh must
    // not stall the consultation past its own deadline budget.
    await Promise.race([
      ctx.modelRegistry.getProviderAuth(providerId),
      new Promise((resolve) => delay(15_000).then(() => resolve("timeout"))),
    ]);
  } catch {
    // Intentionally swallowed: the child will surface a real auth error if the
    // token is actually unusable, and the fallback chain already handles that.
  }
}
export async function pickModel(
  ctx: ExtensionContext,
  slot: AdvisorSlot,
): Promise<AdvisorTarget | "unset" | undefined> {
  const models = ctx.modelRegistry.getAvailable();
  if (models.length === 0)
    throw new Error("No available models found; run /login or configure a provider first.");
  const labels = models.map((model) => `${model.provider}/${model.id}`);
  const choice = await ctx.ui.select(
    `Pick ${slot === "primary" ? "the primary" : "the secondary (fallback)"} advisor model`,
    [...labels, "— clear —"],
  );
  if (choice === undefined) return undefined;
  if (choice === "— clear —") return "unset";
  const idx = labels.indexOf(choice);
  const model = models[idx];

  // Per-model reasoning effort: "— default —" means "inherit the global default".
  const effortChoice = await ctx.ui.select(
    `Reasoning effort for ${model.provider}/${model.id} (default: inherit global)`,
    ["— default —", ...REASONING_EFFORTS],
  );
  if (effortChoice === undefined) return undefined;
  const effort =
    effortChoice === "— default —" ? undefined : (effortChoice as AdvisorReasoningEffort);

  return { provider: model.provider, model: model.id, effort };
}
