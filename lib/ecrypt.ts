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
  salt: string;
  hash: string;
}

export type DocumentSegment = PublicSegment | EncryptedSegment;

export interface EcryptPackage {
  version: 1;
  id: string;
  title: string;
  author: string;
  createdAt: string;
  policy: AccessPolicy;
  wrappedKey: string;
  segments: DocumentSegment[];
}

const DECIMAL_VALUE = /^\d+(?:\.\d+)?$/;
const INTEGER_VALUE = /^\d+$/;

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
      if (rule.tokenId && !INTEGER_VALUE.test(rule.tokenId)) {
        throw new Error(`Condition ${index + 1} has an invalid token ID.`);
      }
      if (rule.minimum && !INTEGER_VALUE.test(rule.minimum)) {
        throw new Error(`Condition ${index + 1} needs a whole-number minimum.`);
      }
      return {
        ...base,
        tokenId: rule.tokenId || undefined,
        minimum: rule.minimum || "1",
      };
    }

    if (rule.minimum && !DECIMAL_VALUE.test(rule.minimum)) {
      throw new Error(`Condition ${index + 1} has an invalid minimum balance.`);
    }
    return { ...base, minimum: rule.minimum || "1" };
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
      ...(rule.tokenId ? { tokenId: rule.tokenId } : {}),
      ...(rule.minimum ? { minimum: rule.minimum } : {}),
    })),
  });
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
