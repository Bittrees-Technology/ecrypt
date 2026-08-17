import { NextResponse } from "next/server";
import { getAddress } from "viem";
import { isDigest, isDocumentId, normalizePolicy } from "../../../lib/ecrypt";
import {
  assertRateLimit,
  assertSameOrigin,
  policyDigest,
  requestHost,
  sha256Hex,
  verifyWalletAuthorization,
} from "../../../lib/server-security";
import { wrapDocumentKey } from "../../../lib/key-wrapper";

export const dynamic = "force-dynamic";

interface WrapRequest {
  key?: string;
  documentId?: string;
  documentDigest?: string;
  policyDigest?: string;
  keyCommitment?: string;
  author?: string;
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

    if (
      !isDocumentId(body.documentId) ||
      !isDigest(body.documentDigest) ||
      !isDigest(body.policyDigest) ||
      !isDigest(body.keyCommitment) ||
      !body.author
    ) {
      return NextResponse.json({ error: "The signed document descriptor is invalid." }, { status: 400 });
    }
    const policy = normalizePolicy(body.policy);
    const calculatedPolicyDigest = policyDigest(policy);
    if (calculatedPolicyDigest !== body.policyDigest) {
      return NextResponse.json({ error: "The signed access policy has been altered." }, { status: 400 });
    }
    const binding = {
      action: "seal" as const,
      documentId: body.documentId,
      documentDigest: body.documentDigest,
      policyDigest: calculatedPolicyDigest,
      keyCommitment: body.keyCommitment,
    };
    const author = await verifyWalletAuthorization(
      body.message,
      body.signature,
      "seal",
      requestHost(request),
      binding,
    );
    if (author !== getAddress(body.author)) {
      return NextResponse.json(
        { error: "The signing wallet does not match the document author." },
        { status: 400 },
      );
    }
    const key = Buffer.from(body.key, "base64url");
    if (key.length !== 32 || sha256Hex(key) !== body.keyCommitment) {
      return NextResponse.json(
        { error: "The document key does not match the signed package." },
        { status: 400 },
      );
    }
    const wrappedKey = await wrapDocumentKey(key, {
      documentDigest: body.documentDigest,
      policyDigest: calculatedPolicyDigest,
      author,
      keyCommitment: body.keyCommitment,
    });

    return NextResponse.json(
      {
        wrappedKey,
        policy,
        author,
        documentDigest: body.documentDigest,
        policyDigest: calculatedPolicyDigest,
      },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "The document key could not be protected.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
