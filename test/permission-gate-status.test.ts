import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SANDBOX_RUNNER_CHOICES, type SandboxState } from "../extensions/lib/sandbox-utils.js";
import { sandboxOptionItems } from "../extensions/permission-gate/menu.js";
import { isClassifierOption, RUNNER_DESCRIPTIONS } from "../extensions/permission-gate/prompts.js";
import { renderSandboxStatus } from "../extensions/permission-gate/status.js";

const files = { global: "/tmp/global/sandbox.json", project: "/tmp/project/sandbox.json" };
const managedFile = "/etc/pi/agent/sandbox.json";

describe("renderSandboxStatus", () => {
  it("renders DISABLED when the sandbox is off", () => {
    const text = renderSandboxStatus({
      state: { active: false, enabled: false },
      config: {},
      managedConfig: {},
      files,
      managedFile,
      trusted: true,
    });
    assert.match(text, /DISABLED/);
  });

  it("renders ACTIVE with runner, roots, network and user commands", () => {
    const state: SandboxState = {
      active: true,
      enabled: true,
      runner: "bwrap",
      policy: { writableRoots: ["/tmp/a", "/tmp/b"], network: "deny", loginShell: true },
      networkEnforced: true,
    };
    const text = renderSandboxStatus({
      state,
      config: { userCommands: true },
      managedConfig: {},
      files,
      managedFile,
      trusted: true,
    });
    assert.match(text, /ACTIVE \(bwrap\)/);
    assert.match(text, /Writable roots: \/tmp\/a, \/tmp\/b/);
    assert.match(text, /Network: deny/);
    assert.match(text, /User ! commands: sandboxed/);
  });

  it("marks network=deny as unenforced on landlock", () => {
    const state: SandboxState = {
      active: true,
      enabled: true,
      runner: "landlock",
      policy: { writableRoots: [], network: "deny", loginShell: true },
      networkEnforced: false,
    };
    const text = renderSandboxStatus({
      state,
      config: {},
      managedConfig: {},
      files,
      managedFile,
      trusted: false,
    });
    assert.match(text, /NOT enforced — landlock/);
    assert.match(text, /not trusted/);
  });

  it("renders FALLBACK with fail-closed guidance", () => {
    const state: SandboxState = {
      active: false,
      enabled: true,
      reason: "no runner",
      failClosed: true,
    };
    const text = renderSandboxStatus({
      state,
      config: {},
      managedConfig: {},
      files,
      managedFile,
      trusted: true,
    });
    assert.match(text, /FALLBACK/);
    assert.match(text, /BLOCKED/);
  });
});

describe("sandboxOptionItems", () => {
  it("includes save/cancel rows and classifier rows with defaults", () => {
    const items = sandboxOptionItems({});
    const values = items.map((i) => i.value);
    for (const v of [
      "save",
      "cancel",
      "classifier",
      "classifierConfirmThreshold",
      "classifierDenyThreshold",
      "classifierModel",
      "classifierTimeoutMs",
      "classifierKeychain",
    ]) {
      assert.ok(values.includes(v), `missing menu row: ${v}`);
    }
    assert.match(items.find((i) => i.value === "classifier")!.label, /classifier: off/);
    assert.match(items.find((i) => i.value === "classifierModel")!.label, /jev-latest/);
  });

  it("reflects draft values in labels", () => {
    const items = sandboxOptionItems({ enabled: true, runner: "bwrap", network: "deny" });
    assert.match(items.find((i) => i.value === "enabled")!.label, /enabled: true/);
    assert.match(items.find((i) => i.value === "runner")!.label, /runner: bwrap/);
    assert.match(items.find((i) => i.value === "network")!.label, /network: deny/);
  });
});

describe("isClassifierOption", () => {
  it("accepts only classifier keys", () => {
    assert.equal(isClassifierOption("classifierModel"), true);
    assert.equal(isClassifierOption("runner"), false);
    assert.equal(isClassifierOption("classifier"), true);
  });
});

describe("RUNNER_DESCRIPTIONS", () => {
  it("has a description for every runner choice", () => {
    for (const choice of SANDBOX_RUNNER_CHOICES) {
      assert.ok(RUNNER_DESCRIPTIONS[choice], `missing description for ${choice}`);
    }
  });
});

describe("status footer and managed line", () => {
  it("renders the blockTerminates footer", () => {
    const text = renderSandboxStatus({
      state: { active: false, enabled: false },
      config: {},
      managedConfig: {},
      managedFile,
      files,
      trusted: true,
    });
    assert.match(text, /blockTerminates: true stops the agent's turn/);
  });

  it("renders the managed path and config line when managed scope contributes keys", () => {
    const text = renderSandboxStatus({
      state: { active: false, enabled: false },
      config: {},
      managedConfig: { enabled: true },
      managedFile,
      files,
      trusted: true,
    });
    assert.match(text, new RegExp(`${managedFile.replace(/[/.]/g, "\\$&")} \\(managed, wins\\)`));
    assert.match(text, /Config: \/tmp\/global\/sandbox\.json/);
  });

  it("omits the managed path when the managed scope is empty", () => {
    const text = renderSandboxStatus({
      state: { active: false, enabled: false },
      config: {},
      managedConfig: {},
      managedFile,
      files,
      trusted: true,
    });
    assert.doesNotMatch(text, /managed, wins/);
  });

  it("renders the fail-open display when the sandbox is enabled but unavailable", () => {
    const state: SandboxState = { active: false, enabled: true, reason: "no runner" };
    const text = renderSandboxStatus({
      state,
      config: {},
      managedConfig: {},
      managedFile,
      files,
      trusted: true,
    });
    assert.match(text, /ALL permission gates are armed/);
    assert.doesNotMatch(text, /BLOCKED/);
  });
});
