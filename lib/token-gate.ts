import {
  decodeAbiParameters,
  decodeFunctionResult,
  encodeFunctionData,
  getAddress,
  toEventSelector,
} from "viem";
import type { Hex } from "viem";
import { AccessPolicy, AccessRule, NetworkKey } from "./ecrypt";

const RPC_NETWORKS: Record<NetworkKey, string> = {
  ethereum: "eth-mainnet",
  base: "base-mainnet",
  robinhood: "robinhood-mainnet",
};

const ERC1155_BALANCE_ABI = [
  {
    type: "function",
    name: "balanceOfBatch",
    stateMutability: "view",
    inputs: [
      { name: "accounts", type: "address[]" },
      { name: "ids", type: "uint256[]" },
    ],
    outputs: [{ name: "balances", type: "uint256[]" }],
  },
] as const;

const TRANSFER_SINGLE_TOPIC = toEventSelector(
  "TransferSingle(address,address,address,uint256,uint256)",
);
const TRANSFER_BATCH_TOPIC = toEventSelector(
  "TransferBatch(address,address,address,uint256[],uint256[])",
);

function alchemyKey(): string {
  const key = process.env.ALCHEMY_API_KEY;
  if (!key) throw new Error("Blockchain ownership checks are not configured yet.");
  return key;
}

function rpcUrl(network: NetworkKey): string {
  return `https://${RPC_NETWORKS[network]}.g.alchemy.com/v2/${alchemyKey()}`;
}

function nftUrl(network: NetworkKey): string {
  return `https://${RPC_NETWORKS[network]}.g.alchemy.com/nft/v3/${alchemyKey()}/getNFTsForOwner`;
}

function padAddress(address: string): string {
  return address.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

function padUint(value: string): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

async function rpcRequest<T>(
  network: NetworkKey,
  method: string,
  params: unknown[],
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(rpcUrl(network), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://ecrypt.bittrees.org",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method,
        params,
      }),
      signal: controller.signal,
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`Ownership provider returned ${response.status}.`);
    const payload = (await response.json()) as { result?: T; error?: { message?: string } };
    if (payload.result === undefined || payload.error) {
      throw new Error(payload.error?.message || "The token contract could not be read.");
    }
    return payload.result;
  } finally {
    clearTimeout(timeout);
  }
}

async function ethCall(network: NetworkKey, to: string, data: string): Promise<Hex> {
  return rpcRequest<Hex>(network, "eth_call", [{ to, data }, "latest"]);
}

function resultUint(result: string): bigint {
  if (!/^0x[0-9a-fA-F]+$/.test(result)) throw new Error("The token contract returned invalid data.");
  return BigInt(result);
}

function decimalToUnits(value: string, decimals: number): bigint {
  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > decimals) {
    throw new Error(`The minimum balance has more than ${decimals} decimal places.`);
  }
  return BigInt(`${whole}${fraction.padEnd(decimals, "0")}` || "0");
}

async function erc1155Balances(
  network: NetworkKey,
  contract: string,
  wallet: string,
  tokenIds: string[],
): Promise<readonly bigint[]> {
  if (!tokenIds.length) return [];
  const data = encodeFunctionData({
    abi: ERC1155_BALANCE_ABI,
    functionName: "balanceOfBatch",
    args: [
      tokenIds.map(() => getAddress(wallet)),
      tokenIds.map((tokenId) => BigInt(tokenId)),
    ],
  });
  const result = await ethCall(network, contract, data);
  return decodeFunctionResult({
    abi: ERC1155_BALANCE_ABI,
    functionName: "balanceOfBatch",
    data: result,
  });
}

async function anyBalanceMeets(
  network: NetworkKey,
  contract: string,
  wallet: string,
  tokenIds: string[],
  minimum: bigint,
): Promise<boolean> {
  for (let offset = 0; offset < tokenIds.length; offset += 100) {
    const balances = await erc1155Balances(
      network,
      contract,
      wallet,
      tokenIds.slice(offset, offset + 100),
    );
    if (balances.some((balance) => balance >= minimum)) return true;
  }
  return false;
}

interface OwnedNftPage {
  ownedNfts?: Array<{
    tokenId?: string;
    tokenType?: string;
    contract?: { address?: string; tokenType?: string };
  }>;
  pageKey?: string | null;
  error?: string;
}

async function ownerNftPage(
  network: NetworkKey,
  contract: string,
  wallet: string,
  pageKey?: string,
): Promise<OwnedNftPage> {
  const url = new URL(nftUrl(network));
  url.searchParams.set("owner", wallet);
  url.searchParams.append("contractAddresses[]", contract);
  url.searchParams.set("withMetadata", "false");
  url.searchParams.set("pageSize", "100");
  if (pageKey) url.searchParams.set("pageKey", pageKey);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(url, {
      headers: { accept: "application/json", origin: "https://ecrypt.bittrees.org" },
      signal: controller.signal,
      cache: "no-store",
    });
    const payload = (await response.json()) as OwnedNftPage;
    if (!response.ok || !Array.isArray(payload.ownedNfts)) {
      throw new Error(payload.error || `Ownership provider returned ${response.status}.`);
    }
    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeTokenIds(values: Array<string | undefined>): string[] {
  const tokenIds = new Set<string>();
  for (const value of values) {
    try {
      if (value) tokenIds.add(BigInt(value).toString());
    } catch {
      // Ignore malformed indexer entries; a valid token ID must be an unsigned integer.
    }
  }
  return [...tokenIds];
}

async function indexedErc1155Match(
  network: NetworkKey,
  contract: string,
  wallet: string,
  minimum: bigint,
): Promise<boolean> {
  let pageKey: string | undefined;
  for (let page = 0; page < 20; page += 1) {
    const payload = await ownerNftPage(network, contract, wallet, pageKey);
    const tokenIds = normalizeTokenIds(
      payload.ownedNfts!
        .filter((nft) => {
          const address = nft.contract?.address;
          const tokenType = nft.tokenType || nft.contract?.tokenType;
          return (
            !!address &&
            getAddress(address) === getAddress(contract) &&
            (!tokenType || tokenType.toUpperCase() === "ERC1155")
          );
        })
        .map((nft) => nft.tokenId),
    );
    if (await anyBalanceMeets(network, contract, wallet, tokenIds, minimum)) return true;
    pageKey = payload.pageKey || undefined;
    if (!pageKey) return false;
  }
  throw new Error("This wallet has too many matching ERC-1155 token IDs to check safely.");
}

interface RpcLog {
  data?: Hex;
  topics?: Hex[];
}

async function loggedErc1155TokenIds(
  network: NetworkKey,
  contract: string,
  wallet: string,
): Promise<string[]> {
  const logs = await rpcRequest<RpcLog[]>(network, "eth_getLogs", [
    {
      address: contract,
      fromBlock: "0x0",
      toBlock: "latest",
      topics: [
        [TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC],
        null,
        null,
        `0x${padAddress(wallet)}`,
      ],
    },
  ]);
  const tokenIds: string[] = [];
  for (const log of logs) {
    if (!log.data || !log.topics?.[0]) continue;
    try {
      if (log.topics[0].toLowerCase() === TRANSFER_SINGLE_TOPIC.toLowerCase()) {
        const [tokenId] = decodeAbiParameters(
          [{ type: "uint256" }, { type: "uint256" }],
          log.data,
        );
        tokenIds.push(tokenId.toString());
      } else if (log.topics[0].toLowerCase() === TRANSFER_BATCH_TOPIC.toLowerCase()) {
        const [batchTokenIds] = decodeAbiParameters(
          [{ type: "uint256[]" }, { type: "uint256[]" }],
          log.data,
        );
        tokenIds.push(...batchTokenIds.map((tokenId) => tokenId.toString()));
      }
    } catch {
      // Ignore malformed transfer logs and verify only decodable token IDs onchain.
    }
  }
  return [...new Set(tokenIds)];
}

async function anyErc1155IdMatches(
  network: NetworkKey,
  contract: string,
  wallet: string,
  minimum: bigint,
): Promise<boolean> {
  try {
    return await indexedErc1155Match(network, contract, wallet, minimum);
  } catch (indexerError) {
    try {
      const tokenIds = await loggedErc1155TokenIds(network, contract, wallet);
      return anyBalanceMeets(network, contract, wallet, tokenIds, minimum);
    } catch {
      throw indexerError;
    }
  }
}

async function ruleMatches(rule: AccessRule, wallet: string): Promise<boolean> {
  if (rule.kind === "wallet") {
    return getAddress(rule.address!) === getAddress(wallet);
  }

  const network = rule.network!;
  const contract = rule.contract!;

  if (rule.kind === "erc721" && rule.tokenId) {
    try {
      const result = await ethCall(network, contract, `0x6352211e${padUint(rule.tokenId)}`);
      const owner = `0x${result.slice(-40)}`;
      return getAddress(owner) === getAddress(wallet);
    } catch {
      return false;
    }
  }

  if (rule.kind === "erc1155") {
    if (!rule.tokenId) {
      return anyErc1155IdMatches(
        network,
        contract,
        wallet,
        BigInt(rule.minimum || "1"),
      );
    }
    const data = `0x00fdd58e${padAddress(wallet)}${padUint(rule.tokenId!)}`;
    const balance = resultUint(await ethCall(network, contract, data));
    return balance >= BigInt(rule.minimum || "1");
  }

  const balance = resultUint(
    await ethCall(network, contract, `0x70a08231${padAddress(wallet)}`),
  );
  if (rule.kind === "erc721") return balance > BigInt(0);

  let decimals = 18;
  try {
    decimals = Number(resultUint(await ethCall(network, contract, "0x313ce567")));
  } catch {
    // Eighteen decimals is the ERC-20 convention when a contract omits metadata.
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
    throw new Error("The token contract reported an invalid decimal count.");
  }
  return balance >= decimalToUnits(rule.minimum || "1", decimals);
}

export async function policyAllows(policy: AccessPolicy, wallet: string) {
  if (policy.mode === "all") {
    for (const rule of policy.rules) {
      if (!(await ruleMatches(rule, wallet))) return false;
    }
    return true;
  }

  for (const rule of policy.rules) {
    if (await ruleMatches(rule, wallet)) return true;
  }
  return false;
}
