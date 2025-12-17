import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { AuthError } from "../auth-error.js";
import type { RandomBytesFn } from "../create-auth-core.js";
import type { UserId } from "../auth-types.js";

export type TotpEncryptionKey = string | Uint8Array;

export function encryptTotpSecret(ctx: {
  userId: UserId;
  secretBase32: string;
  key: TotpEncryptionKey;
  randomBytes?: RandomBytesFn;
}): string {
  const iv = (ctx.randomBytes ?? randomBytes)(12);
  const key = deriveKey(ctx.key);
  const aad = Buffer.from(`totp-secret:v1:${ctx.userId as unknown as string}`, "utf8");

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(ctx.secretBase32, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${b64u(iv)}.${b64u(tag)}.${b64u(ciphertext)}`;
}

export function decryptTotpSecret(ctx: { userId: UserId; encryptedSecret: string; key: TotpEncryptionKey }): string {
  const [ivB64u, tagB64u, ctB64u] = ctx.encryptedSecret.split(".");
  if (!ivB64u || !tagB64u || !ctB64u) throw new AuthError("invalid_input", "Invalid encrypted TOTP secret");
  const iv = fromB64u(ivB64u);
  const tag = fromB64u(tagB64u);
  const ct = fromB64u(ctB64u);

  const key = deriveKey(ctx.key);
  const aad = Buffer.from(`totp-secret:v1:${ctx.userId as unknown as string}`, "utf8");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  try {
    const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    return plaintext.toString("utf8");
  } catch (cause) {
    throw new AuthError("internal_error", "Failed to decrypt TOTP secret", { cause });
  }
}

function deriveKey(keyMaterial: TotpEncryptionKey): Buffer {
  // Developer-friendly: accept string or bytes and derive a fixed 32-byte key via SHA-256.
  const buf = typeof keyMaterial === "string" ? Buffer.from(keyMaterial, "utf8") : Buffer.from(keyMaterial);
  return createHash("sha256").update(buf).digest();
}

function b64u(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function fromB64u(s: string): Buffer {
  const padded = s.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((s.length + 3) % 4);
  return Buffer.from(padded, "base64");
}


