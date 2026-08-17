import { getAddress, isAddress } from "viem";

export const NETWORKS = {
  ethereum: {
    label: "Ethereum",
    chainId: 1,
    explorer: "https://etherscan.io",
  },
  base: {
    label: "Base",
    chainId: 8453,
    explorer: "https://basescan.org",
  },
  robinhood: {
    label: "Robinhood",
    chainId: 4663,
    explorer: "https://robinhoodchain.blockscout.com",
  },
} as const;

export type NetworkKey = keyof typeof NETWORKS;
export type RuleKind = "wallet" | "erc20" | "erc721" | "erc1155";
export type MatchMode = "any" | "all";

export interface AccessRule {
  id: string;
  kind: RuleKind;
  network?: NetworkKey;
  address?: string;
  contract?: string;
  tokenId?: string;
  minimum?: string;
}

export interface AccessPolicy {
  mode: MatchMode;
  rules: AccessRule[];
}

export interface PublicSegment {
  kind: "public";
  text: string;
}

export interface EncryptedSegment {
  kind: "encrypted";
  ciphertext: string;
  iv: string;
  commitment: string;
}

export type DocumentSegment = PublicSegment | EncryptedSegment;

export interface EcryptDocumentCore {
  version: 2;
  id: string;
  title: string;
  author: string;
  createdAt: string;
  policy: AccessPolicy;
  keyCommitment: string;
  segments: DocumentSegment[];
}

export interface WrappedDocumentKey {
  provider: "local-aes-gcm" | "aws-kms";
  keyId: string;
  ciphertext: string;
}

export interface CreatorProof {
  message: string;
  signature: `0x${string}`;
}

export interface EcryptPackage extends EcryptDocumentCore {
  documentDigest: string;
  policyDigest: string;
  wrappedKey: WrappedDocumentKey;
  creatorProof: CreatorProof;
}

export interface ChallengeBinding {
  action: "seal" | "unlock";
  documentId: string;
  documentDigest: string;
  policyDigest: string;
  keyCommitment: string;
  wrappedKeyDigest?: string;
}

const DECIMAL_VALUE = /^\d+(?:\.\d+)?$/;
const INTEGER_VALUE = /^\d+$/;
const BASE64URL_VALUE = /^[A-Za-z0-9_-]+$/;
const DIGEST_VALUE = /^[a-f0-9]{64}$/;
const DOCUMENT_ID_VALUE = /^doc-[a-zA-Z0-9-]{8,64}$/;

function positiveDecimal(value: string): boolean {
  if (!DECIMAL_VALUE.test(value)) return false;
  const [whole, fraction = ""] = value.split(".");
  return /[1-9]/.test(`${whole}${fraction}`);
}

function positiveInteger(value: string): boolean {
  return INTEGER_VALUE.test(value) && BigInt(value) > 0n;
}

export function normalizePolicy(input: unknown): AccessPolicy {
  if (!input || typeof input !== "object") {
    throw new Error("An access policy is required.");
  }

  const candidate = input as Partial<AccessPolicy>;
  if (candidate.mode !== "any" && candidate.mode !== "all") {
    throw new Error("Choose whether any or all access conditions must match.");
  }
  if (!Array.isArray(candidate.rules) || candidate.rules.length < 1) {
    throw new Error("Add at least one access condition.");
  }
  if (candidate.rules.length > 5) {
    throw new Error("A document can have at most five access conditions.");
  }

  const rules = candidate.rules.map((rule, index): AccessRule => {
    if (!rule || typeof rule !== "object") {
      throw new Error(`Access condition ${index + 1} is invalid.`);
    }

    const id =
      typeof rule.id === "string" && /^[a-zA-Z0-9_-]{1,48}$/.test(rule.id)
        ? rule.id
        : `rule-${index + 1}`;

    if (rule.kind === "wallet") {
      if (!rule.address || !isAddress(rule.address)) {
        throw new Error(`Condition ${index + 1} needs a valid wallet address.`);
      }
      return { id, kind: "wallet", address: getAddress(rule.address) };
    }

    if (
      rule.kind !== "erc20" &&
      rule.kind !== "erc721" &&
      rule.kind !== "erc1155"
    ) {
      throw new Error(`Condition ${index + 1} has an unsupported asset type.`);
    }
    if (!rule.network || !(rule.network in NETWORKS)) {
      throw new Error(`Condition ${index + 1} needs a supported network.`);
    }
    if (!rule.contract || !isAddress(rule.contract)) {
      throw new Error(`Condition ${index + 1} needs a valid contract address.`);
    }

    const base = {
      id,
      kind: rule.kind,
      network: rule.network,
      contract: getAddress(rule.contract),
    } satisfies AccessRule;

    if (rule.kind === "erc721") {
      if (rule.tokenId && !INTEGER_VALUE.test(rule.tokenId)) {
        throw new Error(`Condition ${index + 1} has an invalid token ID.`);
      }
      return { ...base, tokenId: rule.tokenId || undefined };
    }

    if (rule.kind === "erc1155") {
      const minimum = rule.minimum || "1";
      if (rule.tokenId && !INTEGER_VALUE.test(rule.tokenId)) {
        throw new Error(`Condition ${index + 1} has an invalid token ID.`);
      }
      if (!positiveInteger(minimum)) {
        throw new Error(`Condition ${index + 1} needs a whole-number minimum greater than zero.`);
      }
      return {
        ...base,
        tokenId: rule.tokenId || undefined,
        minimum,
      };
    }

    const minimum = rule.minimum || "1";
    if (!positiveDecimal(minimum)) {
      throw new Error(`Condition ${index + 1} needs a minimum balance greater than zero.`);
    }
    return { ...base, minimum };
  });

  return { mode: candidate.mode, rules };
}

export function canonicalPolicy(policy: AccessPolicy): string {
  const normalized = normalizePolicy(policy);
  return JSON.stringify({
    mode: normalized.mode,
    rules: normalized.rules.map((rule) => ({
      id: rule.id,
      kind: rule.kind,
      ...(rule.network ? { network: rule.network } : {}),
      ...(rule.address ? { address: rule.address.toLowerCase() } : {}),
      ...(rule.contract ? { contract: rule.contract.toLowerCase() } : {}),
      ...(rule.tokenId !== undefined ? { tokenId: rule.tokenId } : {}),
      ...(rule.minimum !== undefined ? { minimum: rule.minimum } : {}),
    })),
  });
}

export function canonicalDocumentCore(input: EcryptDocumentCore): string {
  const policy = normalizePolicy(input.policy);
  return JSON.stringify({
    version: 2,
    id: input.id,
    title: input.title,
    author: input.author.toLowerCase(),
    createdAt: input.createdAt,
    policy: JSON.parse(canonicalPolicy(policy)) as AccessPolicy,
    keyCommitment: input.keyCommitment,
    segments: input.segments.map((segment) =>
      segment.kind === "public"
        ? { kind: "public", text: segment.text }
        : {
            kind: "encrypted",
            ciphertext: segment.ciphertext,
            iv: segment.iv,
            commitment: segment.commitment,
          },
    ),
  });
}

export function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_VALUE.test(value);
}

export function isDocumentId(value: unknown): value is string {
  return typeof value === "string" && DOCUMENT_ID_VALUE.test(value);
}

export function isEcryptDocumentCore(value: unknown): value is EcryptDocumentCore {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<EcryptDocumentCore>;
  if (
    item.version !== 2 ||
    !isDocumentId(item.id) ||
    typeof item.title !== "string" ||
    item.title.length > 200 ||
    typeof item.author !== "string" ||
    !isAddress(item.author) ||
    typeof item.createdAt !== "string" ||
    !Number.isFinite(Date.parse(item.createdAt)) ||
    !isDigest(item.keyCommitment) ||
    !Array.isArray(item.segments) ||
    item.segments.length < 1 ||
    item.segments.length > 200
  ) {
    return false;
  }

  try {
    normalizePolicy(item.policy);
  } catch {
    return false;
  }

  return item.segments.every((segment) => {
    if (!segment || typeof segment !== "object") return false;
    if (segment.kind === "public") {
      return typeof segment.text === "string" && segment.text.length <= 1_000_000;
    }
    return (
      segment.kind === "encrypted" &&
      typeof segment.ciphertext === "string" &&
      segment.ciphertext.length > 16 &&
      BASE64URL_VALUE.test(segment.ciphertext) &&
      typeof segment.iv === "string" &&
      BASE64URL_VALUE.test(segment.iv) &&
      typeof segment.commitment === "string" &&
      isDigest(segment.commitment)
    );
  });
}

export function isWrappedDocumentKey(value: unknown): value is WrappedDocumentKey {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<WrappedDocumentKey>;
  return (
    (item.provider === "local-aes-gcm" || item.provider === "aws-kms") &&
    typeof item.keyId === "string" &&
    /^[a-zA-Z0-9_./:@-]{1,300}$/.test(item.keyId) &&
    typeof item.ciphertext === "string" &&
    (item.provider === "local-aes-gcm"
      ? /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(item.ciphertext)
      : BASE64URL_VALUE.test(item.ciphertext))
  );
}

export function isCreatorProof(value: unknown): value is CreatorProof {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<CreatorProof>;
  return (
    typeof item.message === "string" &&
    item.message.length <= 10_000 &&
    typeof item.signature === "string" &&
    /^0x[0-9a-fA-F]{130}$/.test(item.signature)
  );
}

export function isEcryptPackage(value: unknown): value is EcryptPackage {
  if (!isEcryptDocumentCore(value)) return false;
  const item = value as Partial<EcryptPackage>;
  return (
    isDigest(item.documentDigest) &&
    isDigest(item.policyDigest) &&
    isWrappedDocumentKey(item.wrappedKey) &&
    isCreatorProof(item.creatorProof)
  );
}

export function shortAddress(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function describeRule(rule: AccessRule): string {
  if (rule.kind === "wallet" && rule.address) {
    return `Wallet ${shortAddress(rule.address)}`;
  }
  const network = rule.network ? NETWORKS[rule.network].label : "Unknown network";
  const contract = rule.contract ? shortAddress(rule.contract) : "contract";
  if (rule.kind === "erc721") {
    return rule.tokenId
      ? `${network} ERC-721 ${contract} · #${rule.tokenId}`
      : `${network} ERC-721 ${contract} · any token`;
  }
  if (rule.kind === "erc1155") {
    const token = rule.tokenId ? `#${rule.tokenId}` : "any token ID";
    return `${network} ERC-1155 ${contract} · ${token} · ≥ ${rule.minimum || "1"}`;
  }
  return `${network} ERC-20 ${contract} · ≥ ${rule.minimum || "1"}`;
}
