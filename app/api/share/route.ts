import { NextResponse } from "next/server";
import {
  canonicalDocumentCore,
  EcryptDocumentCore,
  EcryptPackage,
  isEcryptPackage,
} from "../../../lib/ecrypt";
import { createHostedShare } from "../../../lib/share-store";
import {
  assertRateLimit,
  assertSameOrigin,
  policyDigest,
  requestHost,
  sha256Hex,
  verifyCreatorProof,
} from "../../../lib/server-security";

export const dynamic = "force-dynamic";

function documentCore(document: EcryptPackage): EcryptDocumentCore {
  return {
    version: 2,
    id: document.id,
    title: document.title,
    author: document.author,
    createdAt: document.createdAt,
    policy: document.policy,
    keyCommitment: document.keyCommitment,
    segments: document.segments,
  };
}

export async function POST(request: Request) {
  try {
    assertSameOrigin(request);
    assertRateLimit(request, "share-create", 12);
    const body = await request.json() as { document?: unknown };
    if (!isEcryptPackage(body.document)) {
      return NextResponse.json({ error: "Choose a valid signed eCrypt package." }, { status: 400 });
    }
    const document = body.document;
    const serializedLength = Buffer.byteLength(JSON.stringify(document));
    if (serializedLength > 1_500_000) {
      return NextResponse.json({ error: "This package is too large for a hosted short link." }, { status: 413 });
    }

    const calculatedDocumentDigest = sha256Hex(canonicalDocumentCore(documentCore(document)));
    const calculatedPolicyDigest = policyDigest(document.policy);
    if (
      calculatedDocumentDigest !== document.documentDigest ||
      calculatedPolicyDigest !== document.policyDigest
    ) {
      return NextResponse.json(
        { error: "This package was changed after its creator signed it." },
        { status: 400 },
      );
    }
    await verifyCreatorProof(
      document.creatorProof.message,
      document.creatorProof.signature,
      requestHost(request),
      {
        action: "seal",
        documentId: document.id,
        documentDigest: document.documentDigest,
        policyDigest: document.policyDigest,
        keyCommitment: document.keyCommitment,
      },
      document.author,
    );

    const share = await createHostedShare(document);
    return NextResponse.json(share, {
      status: 201,
      headers: { "cache-control": "no-store, private" },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The short link could not be created.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
