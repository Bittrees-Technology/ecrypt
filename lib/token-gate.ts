import { getAddress } from "viem";
import { AccessPolicy, AccessRule, NetworkKey } from "./ecrypt";

const RPC_NETWORKS: Record<NetworkKey, string> = {
  ethereum: "eth-mainnet",
  base: "base-mainnet",
  robinhood: "robinhood-mainnet",
};

function rpcUrl(network: NetworkKey): string {
  const key = process.env.ALCHEMY_API_KEY;
  if (!key) throw new Error("Blockchain ownership checks are not configured yet.");
  return `https://${RPC_NETWORKS[network]}.g.alchemy.com/v2/${key}`;
}

function padAddress(address: string): string {
  return address.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

function padUint(value: string): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

async function ethCall(network: NetworkKey, to: string, data: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(rpcUrl(network), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [{ to, data }, "latest"],
      }),
      signal: controller.signal,
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`Ownership provider returned ${response.status}.`);
    const payload = (await response.json()) as { result?: string; error?: { message?: string } };
    if (!payload.result || payload.error) {
      throw new Error(payload.error?.message || "The token contract could not be read.");
    }
    return payload.result;
  } finally {
    clearTimeout(timeout);
  }
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
