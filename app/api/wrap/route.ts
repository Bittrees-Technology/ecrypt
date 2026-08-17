import { NextResponse } from "next/server";
import { normalizePolicy } from "../../../lib/ecrypt";
import {
  assertRateLimit,
  assertSameOrigin,
  requestHost,
  verifyWalletAuthorization,
  wrapDocumentKey,
} from "../../../lib/server-security";

export const dynamic = "force-dynamic";

interface WrapRequest {
  key?: string;
  policy?: unknown;
  message?: string;
  signature?: `0x${string}`;
}

export async function POST(request: Request) {
  try {
    assertSameOrigin(request);
    assertRateLimit(request, "wrap", 20);
    const body = (await request.json()) as WrapRequest;
    if (!body.message || !body.signature || !body.key) {
      return NextResponse.json({ error: "The sealing request is incomplete." }, { status: 400 });
    }

    const policy = normalizePolicy(body.policy);
    const author = await verifyWalletAuthorization(
      body.message,
      body.signature,
      "seal",
      requestHost(request),
    );
    const key = Buffer.from(body.key, "base64url");
    const wrappedKey = wrapDocumentKey(key, author, policy);

    return NextResponse.json(
      { wrappedKey, policy, author },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "The document key could not be protected.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

