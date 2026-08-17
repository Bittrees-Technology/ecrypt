import { NextResponse } from "next/server";
import { getAddress, isAddress } from "viem";
import { normalizePolicy } from "../../../lib/ecrypt";
import {
  assertRateLimit,
  assertSameOrigin,
  requestHost,
  unwrapDocumentKey,
  verifyWalletAuthorization,
} from "../../../lib/server-security";
import { policyAllows } from "../../../lib/token-gate";

export const dynamic = "force-dynamic";

interface UnwrapRequest {
  wrappedKey?: string;
  policy?: unknown;
  author?: string;
  message?: string;
  signature?: `0x${string}`;
}

export async function POST(request: Request) {
  try {
    assertSameOrigin(request);
    assertRateLimit(request, "unwrap", 20);
    const body = (await request.json()) as UnwrapRequest;
    if (
      !body.message ||
      !body.signature ||
      !body.wrappedKey ||
      !body.author ||
      !isAddress(body.author)
    ) {
      return NextResponse.json({ error: "The unlock request is incomplete." }, { status: 400 });
    }

    const policy = normalizePolicy(body.policy);
    const wallet = await verifyWalletAuthorization(
      body.message,
      body.signature,
      "unlock",
      requestHost(request),
    );
    const isCreator = wallet === getAddress(body.author);
    if (!isCreator && !(await policyAllows(policy, wallet))) {
      return NextResponse.json(
        { error: "This wallet does not currently meet the document’s access policy." },
        { status: 403 },
      );
    }

    const key = unwrapDocumentKey(body.wrappedKey, body.author, policy);
    return NextResponse.json(
      { key: key.toString("base64url"), wallet, access: isCreator ? "creator" : "policy" },
      { headers: { "cache-control": "no-store, private" } },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "The document could not be unlocked.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
