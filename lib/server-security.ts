import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { getAddress, recoverMessageAddress } from "viem";
import { AccessPolicy, canonicalPolicy } from "./ecrypt";

export type ChallengeAction = "seal" | "unlock";

interface ChallengePayload {
  v: 1;
  action: ChallengeAction;
  host: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
}

function masterKey(): Buffer {
  const encoded = process.env.ECRYPT_MASTER_KEY;
  if (!encoded) {
    throw new Error("The encryption service is not configured yet.");
  }
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32) {
    throw new Error("The encryption service key is invalid.");
  }
  return key;
}

function challengeKey(): Buffer {
  return createHash("sha256")
    .update(masterKey())
    .update("ecrypt:challenge:v1")
    .digest();
}

function wrappingKey(): Buffer {
  return createHash("sha256")
    .update(masterKey())
    .update("ecrypt:wrap:v1")
    .digest();
}

function encode(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

function challengeSignature(payload: string): string {
  return createHmac("sha256", challengeKey()).update(payload).digest("base64url");
}

function challengeToken(message: string): string {
  const match = message.match(/^Token: ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/m);
  if (!match) throw new Error("The wallet authorization message is invalid.");
  return match[1];
}

export function issueChallenge(action: ChallengeAction, host: string) {
  const now = Date.now();
  const payload: ChallengePayload = {
    v: 1,
    action,
    host,
    nonce: encode(randomBytes(18)),
    issuedAt: now,
    expiresAt: now + 5 * 60 * 1000,
  };
  const encodedPayload = encode(JSON.stringify(payload));
  const token = `${encodedPayload}.${challengeSignature(encodedPayload)}`;
  const label = action === "seal" ? "Seal an encrypted document" : "Unlock redactions";
  const message = [
    "eCrypt wallet authorization",
    "",
    `Action: ${label}`,
    `Host: ${host}`,
    `Expires: ${new Date(payload.expiresAt).toISOString()}`,
    "",
    `Token: ${token}`,
    "",
    "This signature does not authorize a blockchain transaction or fee.",
  ].join("\n");

  return { message, expiresAt: new Date(payload.expiresAt).toISOString() };
}

function verifyChallenge(message: string, expectedAction: ChallengeAction, host: string) {
  const token = challengeToken(message);
  const [encodedPayload, suppliedSignature] = token.split(".");
  const expectedSignature = challengeSignature(encodedPayload);
  const supplied = Buffer.from(suppliedSignature);
  const expected = Buffer.from(expectedSignature);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new Error("The wallet authorization message could not be verified.");
  }

  let payload: ChallengePayload;
  try {
    payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
  } catch {
    throw new Error("The wallet authorization message is malformed.");
  }

  if (
    payload.v !== 1 ||
    payload.action !== expectedAction ||
    payload.host !== host ||
    !payload.nonce ||
    payload.expiresAt < Date.now() ||
    payload.issuedAt > Date.now() + 30_000
  ) {
    throw new Error("The wallet authorization message is expired or invalid.");
  }
}

export async function verifyWalletAuthorization(
  message: string,
  signature: `0x${string}`,
  action: ChallengeAction,
  host: string,
) {
  verifyChallenge(message, action, host);
  const address = await recoverMessageAddress({ message, signature });
  return getAddress(address);
}

function wrappingAad(author: string, policy: AccessPolicy): Buffer {
  return Buffer.from(
    JSON.stringify({ version: 1, author: author.toLowerCase(), policy: canonicalPolicy(policy) }),
    "utf8",
  );
}

export function wrapDocumentKey(key: Buffer, author: string, policy: AccessPolicy): string {
  if (key.length !== 32) throw new Error("The document key is invalid.");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", wrappingKey(), iv);
  cipher.setAAD(wrappingAad(author, policy));
  const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [encode(iv), encode(ciphertext), encode(tag)].join(".");
}

export function unwrapDocumentKey(
  wrapped: string,
  author: string,
  policy: AccessPolicy,
): Buffer {
  const parts = wrapped.split(".");
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) {
    throw new Error("The protected document key is malformed.");
  }
  const [iv, ciphertext, tag] = parts.map((part) => Buffer.from(part, "base64url"));
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length !== 32) {
    throw new Error("The protected document key is invalid.");
  }
  const decipher = createDecipheriv("aes-256-gcm", wrappingKey(), iv);
  decipher.setAAD(wrappingAad(author, policy));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function requestHost(request: Request): string {
  return request.headers.get("host") || new URL(request.url).host;
}

export function assertSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return;
  const host = requestHost(request);
  if (new URL(origin).host !== host) {
    throw new Error("This request did not originate from eCrypt.");
  }
}

const requestWindows = new Map<string, { count: number; resetsAt: number }>();

export function assertRateLimit(request: Request, action: string, limit = 30) {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const client = forwarded || request.headers.get("cf-connecting-ip") || "local";
  const key = `${action}:${client}`;
  const now = Date.now();
  const current = requestWindows.get(key);
  if (!current || current.resetsAt <= now) {
    requestWindows.set(key, { count: 1, resetsAt: now + 60_000 });
    return;
  }
  current.count += 1;
  if (current.count > limit) {
    throw new Error("Too many requests. Please wait a moment and try again.");
  }
}

