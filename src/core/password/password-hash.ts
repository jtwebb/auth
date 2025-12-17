import { hash as argon2Hash, verify as argon2Verify } from "@node-rs/argon2";
import type { Options as Argon2Options } from "@node-rs/argon2";
import { AuthError } from "../auth-error.js";

// Avoid importing @node-rs/argon2's ambient `const enum` (TS restriction with verbatimModuleSyntax).
// Per their d.ts: Argon2id = 2.
const ARGON2ID = 2;

export type Argon2Params = {
  /**
   * Kibibytes (KiB). Each thread allocates ~memoryCost KiB.
   */
  memoryCost: number;
  /**
   * Iterations.
   */
  timeCost: number;
  /**
   * Threads.
   */
  parallelism: number;
  /**
   * Output hash length in bytes.
   */
  outputLen: number;
};

export const defaultArgon2Params: Argon2Params = {
  // Tuned to be reasonably strong while staying practical for dev/test.
  // Apps can raise these based on their latency/memory budget.
  memoryCost: 19456, // ~19 MiB
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
};

export type HashPasswordOptions = {
  pepper?: string | Uint8Array;
  params?: Partial<Argon2Params>;
};

export type VerifyPasswordResult = {
  ok: boolean;
  /**
   * True when stored params are weaker than desired and should be upgraded.
   */
  needsRehash: boolean;
};

/**
 * Encodes using the PHC string format, e.g.:
 * "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>"
 */
export async function hashPassword(password: string, options: HashPasswordOptions = {}): Promise<string> {
  if (typeof password !== "string" || password.length === 0) {
    throw new AuthError("invalid_input", "password must be a non-empty string");
  }

  const params = normalizeParams(options.params);
  const secret = pepperToSecret(options.pepper);

  return await argon2Hash(password, {
    // The library expects `algorithm?: Algorithm` where Algorithm.Argon2id = 2.
    // We pass the numeric value to avoid depending on the ambient const enum at compile time.
    algorithm: ARGON2ID as unknown as Argon2Options["algorithm"],
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    outputLen: params.outputLen,
    secret,
  });
}

export async function verifyPassword(
  password: string,
  encodedHash: string,
  options: HashPasswordOptions & { desiredParams?: Partial<Argon2Params> } = {},
): Promise<VerifyPasswordResult> {
  if (typeof password !== "string") {
    throw new AuthError("invalid_input", "password must be a string");
  }
  const parsed = parseEncodedHash(encodedHash);
  if (parsed.kind !== "argon2id") {
    throw new AuthError("invalid_input", "unsupported password hash format");
  }

  const secret = pepperToSecret(options.pepper);
  const ok = await argon2Verify(encodedHash, password, { secret });
  const desired = normalizeParams(options.desiredParams);
  const needsRehash = ok && isWeaker(parsed.params, desired);

  return { ok, needsRehash };
}

export function parseEncodedHash(
  encodedHash: string,
):
  | { kind: "argon2id"; params: Argon2Params }
  | { kind: "unknown" } {
  if (typeof encodedHash !== "string") return { kind: "unknown" };
  if (!encodedHash.startsWith("$argon2id$")) return { kind: "unknown" };

  // PHC: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
  const parts = encodedHash.split("$");
  // ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
  if (parts.length !== 6 && parts.length !== 5) return { kind: "unknown" };
  const paramsPart = parts.length === 6 ? parts[3] : parts[2];
  if (!paramsPart) return { kind: "unknown" };

  const parsed = parseArgon2ParamPart(paramsPart);
  if (!parsed) return { kind: "unknown" };

  // outputLen isn't in the param string; keep our current desired default for comparisons.
  const params: Argon2Params = { ...parsed, outputLen: defaultArgon2Params.outputLen };
  return { kind: "argon2id", params };
}

function normalizeParams(override?: Partial<Argon2Params>): Argon2Params {
  const merged: Argon2Params = { ...defaultArgon2Params, ...(override ?? {}) };
  if (!isFiniteInt(merged.memoryCost) || merged.memoryCost < 4096) {
    throw new AuthError("invalid_input", "invalid argon2 memoryCost parameter");
  }
  if (!isFiniteInt(merged.timeCost) || merged.timeCost < 1) {
    throw new AuthError("invalid_input", "invalid argon2 timeCost parameter");
  }
  if (!isFiniteInt(merged.parallelism) || merged.parallelism < 1 || merged.parallelism > 255) {
    throw new AuthError("invalid_input", "invalid argon2 parallelism parameter");
  }
  if (!isFiniteInt(merged.outputLen) || merged.outputLen < 16 || merged.outputLen > 64) {
    throw new AuthError("invalid_input", "invalid argon2 outputLen parameter");
  }
  return merged;
}

function pepperToSecret(pepper: string | Uint8Array | undefined): Uint8Array | undefined {
  if (pepper === undefined) return undefined;
  if (typeof pepper === "string") return Buffer.from(pepper, "utf8");
  return pepper;
}

function parseArgon2ParamPart(paramStr: string): Pick<Argon2Params, "memoryCost" | "timeCost" | "parallelism"> | null {
  // "m=19456,t=2,p=1"
  const pairs = paramStr.split(",").filter(Boolean);
  const map = new Map<string, string>();
  for (const pair of pairs) {
    const [k, v] = pair.split("=");
    if (!k || !v) return null;
    map.set(k, v);
  }
  const memoryCost = toInt(map.get("m"));
  const timeCost = toInt(map.get("t"));
  const parallelism = toInt(map.get("p"));
  if (!isFiniteInt(memoryCost) || !isFiniteInt(timeCost) || !isFiniteInt(parallelism)) return null;
  return { memoryCost, timeCost, parallelism };
}

function isWeaker(stored: Argon2Params, desired: Argon2Params): boolean {
  if (stored.memoryCost < desired.memoryCost) return true;
  if (stored.memoryCost > desired.memoryCost) return false;
  if (stored.timeCost < desired.timeCost) return true;
  if (stored.timeCost > desired.timeCost) return false;
  return stored.parallelism < desired.parallelism;
}

function toInt(v: string | undefined): number {
  if (!v) return Number.NaN;
  return Number.parseInt(v, 10);
}

function isFiniteInt(n: number): boolean {
  return Number.isFinite(n) && Number.isInteger(n);
}


