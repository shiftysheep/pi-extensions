/**
 * Unit tests for the TypeSafe API key resolver: env-var precedence and the
 * private per-user file backend. Run with `npm test`.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
  apiKeyFilePath,
  readApiKeyFile,
  resolveApiKey,
} from "../extensions/permission-gate/api-key.js";
import { TYPESAFE_API_KEY_ENV } from "../extensions/permission-gate/classifier.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-key-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeFile(rel: string, content: string, mode?: number): string {
  const file = path.join(tmpDir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  if (mode !== undefined) fs.chmodSync(file, mode);
  return file;
}

describe("apiKeyFilePath", () => {
  it("points under ~/.pi/credentials", () => {
    assert.equal(
      apiKeyFilePath({ home: "/home/u" }),
      path.join("/home/u", ".pi", "credentials", "typesafe-api-key"),
    );
  });
});

describe("readApiKeyFile", () => {
  it("returns the trimmed token from a 0600 file", () => {
    const file = writeFile("k", "ts-key-123\n", 0o600);
    assert.equal(readApiKeyFile(file), "ts-key-123");
  });

  it("rejects group/other-readable files", () => {
    const file = writeFile("k", "ts-key-123", 0o644);
    assert.equal(readApiKeyFile(file), undefined);
  });

  it("rejects files inside a non-private directory", () => {
    const file = writeFile("open-dir/k", "ts-key-123", 0o600);
    fs.chmodSync(path.dirname(file), 0o755);
    assert.equal(readApiKeyFile(file), undefined);
  });

  it("rejects empty and multiline files", () => {
    const file = writeFile("k", "\n", 0o600);
    assert.equal(readApiKeyFile(file), undefined);
    const file2 = writeFile("k2", "line1\nline2", 0o600);
    assert.equal(readApiKeyFile(file2), undefined);
  });

  it("rejects symlinks and absent files", () => {
    const target = writeFile("real", "ts-key-123", 0o600);
    const link = path.join(tmpDir, "link");
    try {
      fs.symlinkSync(target, link);
      assert.equal(readApiKeyFile(link), undefined);
    } catch {
      // symlink unsupported — skip silently
    }
    assert.equal(readApiKeyFile(path.join(tmpDir, "nope")), undefined);
  });

  it("rejects oversized files", () => {
    const file = writeFile("k", "x".repeat(2000), 0o600);
    assert.equal(readApiKeyFile(file), undefined);
  });
});

describe("resolveApiKey", () => {
  it("prefers the env var over the file", () => {
    const file = writeFile("k", "ts-file-key", 0o600);
    const r = resolveApiKey({
      env: { [TYPESAFE_API_KEY_ENV]: "ts-env-key" },
      filePath: file,
    });
    assert.deepEqual(r, { key: "ts-env-key", source: "env", detail: TYPESAFE_API_KEY_ENV });
  });

  it("falls back to the file", () => {
    const file = writeFile("k", "ts-file-key", 0o600);
    const r = resolveApiKey({ env: {}, filePath: file });
    assert.equal(r?.source, "file");
    assert.equal(r?.key, "ts-file-key");
  });

  it("returns undefined when neither exists", () => {
    const r = resolveApiKey({ env: {}, filePath: path.join(tmpDir, "nope") });
    assert.equal(r, undefined);
  });
});
