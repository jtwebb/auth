import { createHash, createHmac } from "node:crypto";
import { AuthError } from "../auth-error.js";
import type { AuthPolicy } from "../auth-policy.js";
import type { UserId } from "../auth-types.js";
import type { RandomBytesFn } from "../create-auth-core.js";
import type { AuthStorage } from "../storage/auth-storage.js";
import type { RotateBackupCodesInput, RotateBackupCodesResult, RedeemBackupCodeInput, RedeemBackupCodeResult } from "./backup-code-types.js";

export type BackupCodeHashSecret = Uint8Array | string | undefined;

export async function rotateBackupCodes(ctx: {
  input: RotateBackupCodesInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  randomBytes: RandomBytesFn;
  backupCodeHashSecret?: BackupCodeHashSecret;
}): Promise<RotateBackupCodesResult> {
  const now = ctx.now();
  const { count, length } = ctx.policy.backupCodes;
  const codes: string[] = [];
  const records = [];

  for (let i = 0; i < count; i++) {
    const code = generateBackupCode(ctx.randomBytes, length);
    codes.push(code);
    records.push({
      userId: ctx.input.userId,
      codeHash: hashBackupCode(ctx.input.userId, code, ctx.backupCodeHashSecret),
      createdAt: now,
    });
  }

  await ctx.storage.backupCodes.replaceCodes(ctx.input.userId, records, now);
  return { userId: ctx.input.userId, codes };
}

export async function redeemBackupCode(ctx: {
  input: RedeemBackupCodeInput;
  storage: AuthStorage;
  now: () => Date;
  backupCodeHashSecret?: BackupCodeHashSecret;
}): Promise<RedeemBackupCodeResult> {
  const now = ctx.now();
  const normalized = normalizeBackupCode(ctx.input.code);
  const codeHash = hashBackupCode(ctx.input.userId, normalized, ctx.backupCodeHashSecret);

  const consumed = await ctx.storage.backupCodes.consumeCode(ctx.input.userId, codeHash, now);
  if (!consumed) {
    throw new AuthError("backup_code_invalid", "Invalid backup code", {
      publicMessage: "Invalid backup code",
      status: 401,
    });
  }

  const remaining = await ctx.storage.backupCodes.countRemaining(ctx.input.userId);
  return { userId: ctx.input.userId, remaining };
}

export function normalizeBackupCode(code: string): string {
  if (typeof code !== "string") throw new AuthError("invalid_input", "code must be a string");
  const trimmed = code.trim();
  if (!trimmed) throw new AuthError("invalid_input", "code is required");
  // Remove common separators/spaces, upper-case for canonical form
  return trimmed.replaceAll("-", "").replaceAll(" ", "").toUpperCase();
}

export function generateBackupCode(randomBytes: RandomBytesFn, length: number): string {
  if (!Number.isInteger(length) || length < 8 || length > 64) {
    throw new AuthError("invalid_input", "backup code length must be between 8 and 64");
  }
  // Crockford Base32 alphabet, omitting I/L/O/U for readability.
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bytes = randomBytes(length);
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new AuthError("internal_error", "randomBytes returned unexpected length");
  }

  let out = "";
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }

  // Group for UX: e.g. ABCDE-FGHIJ-KLMNO
  return out.match(/.{1,5}/g)?.join("-") ?? out;
}

export function hashBackupCode(userId: UserId, code: string, secret?: BackupCodeHashSecret): string {
  const normalized = normalizeBackupCode(code);
  const payload = `backup-code:v1:${userId as unknown as string}:${normalized}`;

  return secret !== undefined
    ? createHmac("sha256", secret).update(payload).digest("hex")
    : createHash("sha256").update(payload).digest("hex");
}


