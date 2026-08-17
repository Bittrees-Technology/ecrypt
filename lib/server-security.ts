import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { getAddress, isAddress, recoverMessageAddress } from "viem";
import {
  AccessPolicy,
  canonicalPolicy,
  ChallengeBinding,
  WrappedDocumentKey,
} from "./ecrypt";
import { assertChallengeStoreConfigured, consumeChallengeNonce } from "./challenge-store";

export type ChallengeAction = "seal" | "unlock";

interface ChallengePayload {
  v: 2;
  action: ChallengeAction;
  host: string;
  uri: string;
  address: string;
  chainId: number;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  binding: ChallengeBinding;
}

function challengeSecret(): Buffer {
  const encoded = process.env.ECRYPT_CHALLENGE_SECRET || process.env.ECRYPT_MASTER_KEY;
  if (!encoded) throw new Error("The wallet authorization service is not configured yet.");
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32) throw new Error("The wallet authorization secret is invalid.");
  return key;
}

function challengeKey(): Buffer {
  return createHash("sha256")
    .update(challengeSecret())
    .update("ecrypt:challenge:v2")
    .digest();
}

function encode(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

export function sha256Hex(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function policyDigest(policy: AccessPolicy): string {
  return sha256Hex(canonicalPolicy(policy));
}

export function wrappedKeyDigest(wrappedKey: WrappedDocumentKey): string {
  return sha256Hex(JSON.stringify({
    provider: wrappedKey.provider,
    keyId: wrappedKey.keyId,
    ciphertext: wrappedKey.ciphertext,
  }));
}

function canonicalBinding(binding: ChallengeBinding): string {
  return JSON.stringify({
    action: binding.action,
    documentId: binding.documentId,
    documentDigest: binding.documentDigest,
    policyDigest: binding.policyDigest,
    keyCommitment: binding.keyCommitment,
    ...(binding.wrappedKeyDigest ? { wrappedKeyDigest: binding.wrappedKeyDigest } : {}),
  });
}

function challengeSignature(payload: string): string {
  return createHmac("sha256", challengeKey()).update(payload).digest("base64url");
}

function challengeToken(message: string): string {
  const match = message.match(/^- urn:ecrypt:challenge:([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/m);
  if (!match) throw new Error("The wallet authorization message is invalid.");
  return match[1];
}

function statement(action: ChallengeAction): string {
  return action === "seal"
    ? "Sign the complete eCrypt document and authorize protection of its random document key."
    : "Authorize one reveal attempt for this exact eCrypt document and protected key.";
}

function challengeMessage(payload: ChallengePayload, token: string): string {
  return [
    `${payload.host} wants you to sign in with your Ethereum account:`,
    payload.address,
    "",
    `${statement(payload.action)} No blockchain transaction or gas fee is requested.`,
    "",
    `URI: ${payload.uri}`,
    "Version: 1",
    `Chain ID: ${payload.chainId}`,
    `Nonce: ${payload.nonce}`,
    `Issued At: ${new Date(payload.issuedAt).toISOString()}`,
    `Expiration Time: ${new Date(payload.expiresAt).toISOString()}`,
    `Request ID: ${payload.binding.documentId}`,
    "Resources:",
    `- urn:ecrypt:action:${payload.action}`,
    `- urn:ecrypt:document-digest:${payload.binding.documentDigest}`,
    `- urn:ecrypt:policy-digest:${payload.binding.policyDigest}`,
    `- urn:ecrypt:key-commitment:${payload.binding.keyCommitment}`,
    ...(payload.binding.wrappedKeyDigest
      ? [`- urn:ecrypt:wrapped-key-digest:${payload.binding.wrappedKeyDigest}`]
      : []),
    `- urn:ecrypt:challenge:${token}`,
  ].join("\n");
}

function validChainId(chainId: number): boolean {
  return Number.isSafeInteger(chainId) && chainId > 0;
}

export function issueChallenge(
  action: ChallengeAction,
  host: string,
  address: string,
  chainId: number,
  binding: ChallengeBinding,
) {
  assertChallengeStoreConfigured();
  if (!isAddress(address)) throw new Error("Connect a valid EVM wallet first.");
  if (!validChainId(chainId)) throw new Error("The wallet reported an invalid EVM network.");
  if (binding.action !== action) throw new Error("The wallet authorization action is invalid.");
  if (action === "unlock" && !binding.wrappedKeyDigest) {
    throw new Error("The unlock authorization is not bound to a protected key.");
  }
  if (action === "seal" && binding.wrappedKeyDigest) {
    throw new Error("The seal authorization contains unexpected protected-key data.");
  }

  const now = Date.now();
  const payload: ChallengePayload = {
    v: 2,
    action,
    host,
    uri: `${host.startsWith("localhost") ? "http" : "https"}://${host}`,
    address: getAddress(address),
    chainId,
    nonce: randomBytes(16).toString("hex"),
    issuedAt: now,
    expiresAt: now + 5 * 60 * 1000,
    binding,
  };
  const encodedPayload = encode(JSON.stringify(payload));
  const token = `${encodedPayload}.${challengeSignature(encodedPayload)}`;
  return {
    message: challengeMessage(payload, token),
    expiresAt: new Date(payload.expiresAt).toISOString(),
  };
}

function verifyChallengeToken(
  message: string,
  expectedAction: ChallengeAction,
  host: string,
  expectedBinding: ChallengeBinding,
  allowExpired = false,
): ChallengePayload {
  const token = challengeToken(message);
  const [encodedPayload, suppliedSignature, extra] = token.split(".");
  if (!encodedPayload || !suppliedSignature || extra) {
    throw new Error("The wallet authorization token is malformed.");
  }
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

  const now = Date.now();
  if (
    payload.v !== 2 ||
    payload.action !== expectedAction ||
    payload.host !== host ||
    !isAddress(payload.address) ||
    !validChainId(payload.chainId) ||
    !/^[a-f0-9]{32}$/.test(payload.nonce) ||
    payload.issuedAt > now + 30_000 ||
    (!allowExpired && payload.expiresAt < now) ||
    payload.expiresAt - payload.issuedAt !== 5 * 60 * 1000 ||
    canonicalBinding(payload.binding) !== canonicalBinding(expectedBinding) ||
    message !== challengeMessage(payload, token)
  ) {
    throw new Error("The wallet authorization message is expired or invalid.");
  }
  return payload;
}

export async function verifyWalletAuthorization(
  message: string,
  signature: `0x${string}`,
  action: ChallengeAction,
  host: string,
  binding: ChallengeBinding,
) {
  const payload = verifyChallengeToken(message, action, host, binding);
  const recovered = getAddress(await recoverMessageAddress({ message, signature }));
  if (recovered !== getAddress(payload.address)) {
    throw new Error("The wallet signature does not match the requested account.");
  }
  await consumeChallengeNonce(payload.nonce, payload.expiresAt);
  return recovered;
}

export async function verifyCreatorProof(
  message: string,
  signature: `0x${string}`,
  host: string,
  binding: ChallengeBinding,
  author: string,
) {
  const payload = verifyChallengeToken(message, "seal", host, binding, true);
  const recovered = getAddress(await recoverMessageAddress({ message, signature }));
  if (recovered !== getAddress(payload.address) || recovered !== getAddress(author)) {
    throw new Error("The package creator signature is invalid.");
  }
  return recovered;
}

export function requestHost(request: Request): string {
  return request.headers.get("host") || new URL(request.url).host;
}

export function assertSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) throw new Error("This request must include its eCrypt origin.");
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
