/**
 * TypeSafe (Jev) API key resolution — pure, unit-testable.
 *
 * The env var (TYPESAFE_API_KEY) works in normal terminals but is unset when
 * pi is launched from a GUI host (VS Code, T3 Code), so we also support a
 * private per-user file. Resolution order: env var → OS keychain (opt-in)
 * → private file. The key is never copied into
 * process.env, config files, or logs.
 *
 * The file is a single raw token (one line, optional trailing newline) at
 * ~/.pi/credentials/typesafe-api-key. POSIX permissions must be 0600 with a
 * private parent directory; the file must be a regular, non-symlink file owned
 * by the current user. The token is never logged or placed in diagnostics.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { TYPESAFE_API_KEY_ENV } from "./classifier.js";

/** File name of the private key file inside the credentials directory. */
export const TYPESAFE_API_KEY_FILE = "typesafe-api-key";
/** Directory name under $HOME holding the credentials file. */
export const CREDENTIALS_DIR = "credentials";
/** Upper bound for a key file (bytes) — a token is ~50 bytes; anything larger is wrong. */
export const MAX_KEY_FILE_BYTES = 1024;

export type ApiKeySource = "env" | "file" | "keychain";

export type ResolvedApiKey = {
  key: string;
  source: ApiKeySource;
};

const KEYCHAIN_SERVICE = "pi-extensions";
const KEYCHAIN_ACCOUNT = "typesafe-api-key";
const KEYCHAIN_TIMEOUT_MS = 5000;
const KEYCHAIN_CACHE_TTL_MS = 60_000;
const KEYCHAIN_MISS_CACHE_TTL_MS = 5_000;

let keychainCache: { value: string | undefined; expiresAt: number } | undefined;
let keychainLookup: Promise<string | undefined> | undefined;

/** Absolute path of the private key file (outside the workspace). */
export function apiKeyFilePath(opts: { home?: string } = {}): string {
  const home = opts.home ?? os.homedir();
  return path.join(home, ".pi", CREDENTIALS_DIR, TYPESAFE_API_KEY_FILE);
}

function isPrivateOwnedPath(st: fs.Stats): boolean {
  if (process.platform === "win32") return true;
  if (st.mode & 0o077) return false;
  try {
    return st.uid === process.getuid?.();
  } catch {
    return false;
  }
}

function isPrivateDirectory(directory: string): boolean {
  try {
    const st = fs.lstatSync(directory);
    return !st.isSymbolicLink() && st.isDirectory() && isPrivateOwnedPath(st);
  } catch {
    return false;
  }
}

function readPrivateFile(file: string): string | undefined {
  let fd: number;
  const noFollow = fs.constants.O_NOFOLLOW;
  try {
    // O_NONBLOCK keeps opening a FIFO from hanging before fstat can reject it.
    // Windows lacks O_NOFOLLOW, so reject a symlink before opening there.
    if (noFollow === undefined && fs.lstatSync(file).isSymbolicLink()) return undefined;
    fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | (noFollow ?? 0) | (fs.constants.O_NONBLOCK ?? 0),
    );
  } catch {
    return undefined;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > MAX_KEY_FILE_BYTES || !isPrivateOwnedPath(st)) return undefined;
    const buffer = Buffer.alloc(MAX_KEY_FILE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const bytesRead = fs.readSync(fd, buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > MAX_KEY_FILE_BYTES) return undefined;
    return buffer.toString("utf8", 0, length);
  } catch {
    return undefined;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // Ignore close failures; the key is not returned on a read failure.
    }
  }
}

/**
 * Read the key from the private file. Returns undefined when the file is
 * absent, unsafe, or malformed — never throws, never leaks file contents
 * into errors.
 */
export function readApiKeyFile(file: string): string | undefined {
  if (!isPrivateDirectory(path.dirname(file))) return undefined;
  const raw = readPrivateFile(file);
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed.includes("\n") || trimmed.includes("\r")) return undefined;
  return trimmed;
}

async function readKeychain(): Promise<string | undefined> {
  try {
    const { AsyncEntry } = await import("@napi-rs/keyring");
    const entry = new AsyncEntry(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, {
      linux: { store: "secret-service" },
    });
    const key = await entry.getPassword(AbortSignal.timeout(KEYCHAIN_TIMEOUT_MS));
    const trimmed = key?.trim();
    return trimmed ? trimmed : undefined;
  } catch {
    return undefined;
  }
}

async function readKeychainCached(
  loader: () => Promise<string | undefined>,
): Promise<string | undefined> {
  if (keychainCache && keychainCache.expiresAt > Date.now()) return keychainCache.value;
  if (keychainLookup) return keychainLookup;
  keychainLookup = loader()
    .catch(() => undefined)
    .then((value) => {
      const ttl = value ? KEYCHAIN_CACHE_TTL_MS : KEYCHAIN_MISS_CACHE_TTL_MS;
      keychainCache = { value, expiresAt: Date.now() + ttl };
      return value;
    })
    .finally(() => {
      keychainLookup = undefined;
    });
  return keychainLookup;
}

/** Clear the short-lived keychain cache, for example after an authentication failure. */
export function clearApiKeyCache(): void {
  keychainCache = undefined;
}

/**
 * Resolve the API key from the env var, optional OS keychain, or private file.
 * File and keychain readers are injectable for tests.
 */
export async function resolveApiKey(
  opts: {
    env?: NodeJS.ProcessEnv;
    home?: string;
    filePath?: string;
    useKeychain?: boolean;
    readKeychain?: () => Promise<string | undefined>;
  } = {},
): Promise<ResolvedApiKey | undefined> {
  const env = opts.env ?? process.env;
  const fromEnv = env[TYPESAFE_API_KEY_ENV]?.trim();
  if (fromEnv) return { key: fromEnv, source: "env" };
  if (opts.useKeychain) {
    const fromKeychain = await readKeychainCached(opts.readKeychain ?? readKeychain);
    if (fromKeychain) return { key: fromKeychain, source: "keychain" };
  }
  const file = opts.filePath ?? apiKeyFilePath({ home: opts.home });
  const fromFile = readApiKeyFile(file);
  if (fromFile) return { key: fromFile, source: "file" };
  return undefined;
}
