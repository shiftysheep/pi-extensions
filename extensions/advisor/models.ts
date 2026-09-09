/**
 * Model resolution for the advisor extension: registry lookups, spec parsing,
 * the interactive picker, and target formatting.
 */

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
