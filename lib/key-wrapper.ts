import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import type { WrappedDocumentKey } from "./ecrypt";

export interface DocumentKeyContext {
  documentDigest: string;
  policyDigest: string;
  author: string;
  keyCommitment: string;
}

function encode(value: Buffer | Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function localKeys(): Record<string, Buffer> {
  const keys: Record<string, Buffer> = {};
  const configured = process.env.ECRYPT_WRAPPING_KEYS;
  if (configured) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(configured);
    } catch {
      throw new Error("The versioned wrapping-key configuration is malformed.");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("The versioned wrapping-key configuration is invalid.");
    }
    for (const [keyId, encoded] of Object.entries(parsed)) {
      if (!/^[a-zA-Z0-9_.-]{1,80}$/.test(keyId) || typeof encoded !== "string") {
        throw new Error("A configured wrapping-key version is invalid.");
      }
      const key = Buffer.from(encoded, "base64");
      if (key.length !== 32) throw new Error(`Wrapping key ${keyId} must contain 32 bytes.`);
      keys[keyId] = key;
    }
  }

  const legacyEnvironmentKey = process.env.ECRYPT_MASTER_KEY;
  if (legacyEnvironmentKey) {
    const keyId = process.env.ECRYPT_ACTIVE_KEY_ID || "local-2026-08";
    const key = Buffer.from(legacyEnvironmentKey, "base64");
    if (key.length !== 32) throw new Error("The encryption service key is invalid.");
    keys[keyId] ??= key;
  }
  return keys;
}

function activeLocalKey(): { keyId: string; key: Buffer } {
  const keys = localKeys();
  const keyId = process.env.ECRYPT_ACTIVE_KEY_ID || Object.keys(keys)[0] || "";
  const key = keys[keyId];
  if (!key) throw new Error("The active document-key wrapping version is not configured.");
  return { keyId, key };
}

function localAad(context: DocumentKeyContext, keyId: string): Buffer {
  return Buffer.from(
    JSON.stringify({
      version: 2,
      provider: "local-aes-gcm",
      keyId,
      documentDigest: context.documentDigest,
      policyDigest: context.policyDigest,
      author: context.author.toLowerCase(),
      keyCommitment: context.keyCommitment,
    }),
    "utf8",
  );
}

function localWrap(key: Buffer, context: DocumentKeyContext): WrappedDocumentKey {
  const active = activeLocalKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", active.key, iv);
  cipher.setAAD(localAad(context, active.keyId));
  const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    provider: "local-aes-gcm",
    keyId: active.keyId,
    ciphertext: [encode(iv), encode(ciphertext), encode(tag)].join("."),
  };
}

function localUnwrap(wrapped: WrappedDocumentKey, context: DocumentKeyContext): Buffer {
  const key = localKeys()[wrapped.keyId];
  if (!key) throw new Error("This document uses an unavailable wrapping-key version.");
  const parts = wrapped.ciphertext.split(".");
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) {
    throw new Error("The protected document key is malformed.");
  }
  const [iv, ciphertext, tag] = parts.map((part) => Buffer.from(part, "base64url"));
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length !== 32) {
    throw new Error("The protected document key is invalid.");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(localAad(context, wrapped.keyId));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function kmsEncryptionContext(context: DocumentKeyContext): Record<string, string> {
  return {
    ecryptVersion: "2",
    documentDigest: context.documentDigest,
    policyDigest: context.policyDigest,
    authorDigest: createHash("sha256").update(context.author.toLowerCase()).digest("hex"),
    keyCommitment: context.keyCommitment,
  };
}

async function kmsClient() {
  const region = process.env.AWS_REGION;
  const roleArn = process.env.AWS_ROLE_ARN;
  if (!region || !roleArn) {
    throw new Error("AWS KMS wrapping requires AWS_REGION and AWS_ROLE_ARN.");
  }
  const [{ KMSClient }, { awsCredentialsProvider }] = await Promise.all([
    import("@aws-sdk/client-kms"),
    import("@vercel/oidc-aws-credentials-provider"),
  ]);
  return new KMSClient({
    region,
    credentials: awsCredentialsProvider({ roleArn }),
  });
}

async function kmsWrap(key: Buffer, context: DocumentKeyContext): Promise<WrappedDocumentKey> {
  const keyId = process.env.AWS_KMS_KEY_ID;
  if (!keyId) throw new Error("AWS_KMS_KEY_ID is not configured.");
  const [{ EncryptCommand }, client] = await Promise.all([
    import("@aws-sdk/client-kms"),
    kmsClient(),
  ]);
  const result = await client.send(new EncryptCommand({
    KeyId: keyId,
    Plaintext: key,
    EncryptionContext: kmsEncryptionContext(context),
  }));
  if (!result.CiphertextBlob) throw new Error("AWS KMS did not return a protected document key.");
  return {
    provider: "aws-kms",
    keyId: result.KeyId || keyId,
    ciphertext: encode(result.CiphertextBlob),
  };
}

async function kmsUnwrap(
  wrapped: WrappedDocumentKey,
  context: DocumentKeyContext,
): Promise<Buffer> {
  const [{ DecryptCommand }, client] = await Promise.all([
    import("@aws-sdk/client-kms"),
    kmsClient(),
  ]);
  const result = await client.send(new DecryptCommand({
    KeyId: wrapped.keyId,
    CiphertextBlob: Buffer.from(wrapped.ciphertext, "base64url"),
    EncryptionContext: kmsEncryptionContext(context),
  }));
  if (!result.Plaintext) throw new Error("AWS KMS did not return the document key.");
  return Buffer.from(result.Plaintext);
}

export async function wrapDocumentKey(
  key: Buffer,
  context: DocumentKeyContext,
): Promise<WrappedDocumentKey> {
  if (key.length !== 32) throw new Error("The document key is invalid.");
  return process.env.ECRYPT_KEY_WRAPPER === "aws-kms"
    ? kmsWrap(key, context)
    : localWrap(key, context);
}

export async function unwrapDocumentKey(
  wrapped: WrappedDocumentKey,
  context: DocumentKeyContext,
): Promise<Buffer> {
  const key = wrapped.provider === "aws-kms"
    ? await kmsUnwrap(wrapped, context)
    : localUnwrap(wrapped, context);
  if (key.length !== 32) throw new Error("The unwrapped document key is invalid.");
  const commitment = createHash("sha256").update(key).digest("hex");
  if (commitment !== context.keyCommitment) {
    throw new Error("The document key does not match the signed package.");
  }
  return key;
}
