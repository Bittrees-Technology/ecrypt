import { NextResponse } from "next/server";
import { getAddress } from "viem";
import {
  CreatorProof,
  isCreatorProof,
  isDigest,
  isDocumentId,
  isWrappedDocumentKey,
  normalizePolicy,
  WrappedDocumentKey,
} from "../../../lib/ecrypt";
import {
  assertRateLimit,
  assertSameOrigin,
  policyDigest,
  requestHost,
  verifyCreatorProof,
  verifyWalletAuthorization,
  wrappedKeyDigest,
} from "../../../lib/server-security";
import { unwrapDocumentKey } from "../../../lib/key-wrapper";
import { policyAllows } from "../../../lib/token-gate";

export const dynamic = "force-dynamic";

interface UnwrapRequest {
  documentId?: string;
  keyCommitment?: string;
  author?: string;
  policy?: unknown;
  wrappedKey?: WrappedDocumentKey;
  documentDigest?: string;
  policyDigest?: string;
  creatorProof?: CreatorProof;
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
      !isWrappedDocumentKey(body.wrappedKey) ||
      !isCreatorProof(body.creatorProof) ||
      !isDocumentId(body.documentId) ||
      !isDigest(body.documentDigest) ||
      !isDigest(body.policyDigest) ||
      !isDigest(body.keyCommitment) ||
      !body.author
    ) {
      return NextResponse.json({ error: "The unlock request is incomplete." }, { status: 400 });
    }

    const policy = normalizePolicy(body.policy);
    const calculatedPolicyDigest = policyDigest(policy);
    if (calculatedPolicyDigest !== body.policyDigest) {
      return NextResponse.json(
        { error: "The document’s signed access policy has been altered." },
        { status: 400 },
      );
    }
    const sealBinding = {
      action: "seal" as const,
      documentId: body.documentId,
      documentDigest: body.documentDigest,
      policyDigest: calculatedPolicyDigest,
      keyCommitment: body.keyCommitment,
    };
    await verifyCreatorProof(
      body.creatorProof.message,
      body.creatorProof.signature,
      requestHost(request),
      sealBinding,
      body.author,
    );
    const unlockBinding = {
      ...sealBinding,
      action: "unlock" as const,
      wrappedKeyDigest: wrappedKeyDigest(body.wrappedKey),
    };
    const wallet = await verifyWalletAuthorization(
      body.message,
      body.signature,
      "unlock",
      requestHost(request),
      unlockBinding,
    );
    const isCreator = wallet === getAddress(body.author);
    if (!isCreator && !(await policyAllows(policy, wallet))) {
      return NextResponse.json(
        { error: "This wallet does not currently meet the document’s access policy." },
        { status: 403 },
      );
    }

    const key = await unwrapDocumentKey(body.wrappedKey, {
      documentDigest: body.documentDigest,
      policyDigest: calculatedPolicyDigest,
      author: body.author,
      keyCommitment: body.keyCommitment,
    });
    return NextResponse.json(
      { key: key.toString("base64url"), wallet, access: isCreator ? "creator" : "policy" },
      { headers: { "cache-control": "no-store, private" } },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "The document could not be unlocked.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
