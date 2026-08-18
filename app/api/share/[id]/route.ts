import { NextResponse } from "next/server";
import { getAddress } from "viem";
import { isShareId } from "../../../../lib/ecrypt";
import {
  deleteHostedShare,
  deleteHostedShareAsCreator,
  getHostedShare,
} from "../../../../lib/share-store";
import {
  assertRateLimit,
  assertSameOrigin,
  requestHost,
  verifyWalletAuthorization,
  wrappedKeyDigest,
} from "../../../../lib/server-security";

export const dynamic = "force-dynamic";

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function GET(request: Request, context: RouteContext) {
  try {
    assertRateLimit(request, "share-read", 60);
    const { id } = await context.params;
    if (!isShareId(id)) {
      return NextResponse.json({ error: "This short link is invalid." }, { status: 404 });
    }
    const document = await getHostedShare(id);
    if (!document) {
      return NextResponse.json(
        { error: "This short link has expired, was deleted, or does not exist." },
        { status: 404 },
      );
    }
    return NextResponse.json({ document }, {
      headers: { "cache-control": "no-store, private" },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The short link could not be opened.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

export async function DELETE(request: Request, context: RouteContext) {
  try {
    assertSameOrigin(request);
    assertRateLimit(request, "share-delete", 20);
    const { id } = await context.params;
    const body = await request.json() as {
      deleteToken?: unknown;
      message?: unknown;
      signature?: unknown;
    };
    if (!isShareId(id)) {
      return NextResponse.json({ error: "This short-link deletion request is invalid." }, { status: 400 });
    }
    if (typeof body.deleteToken === "string") {
      if (!(await deleteHostedShare(id, body.deleteToken))) {
        return NextResponse.json({ error: "This short link could not be deleted." }, { status: 403 });
      }
    } else {
      const document = await getHostedShare(id);
      if (!document) {
        return NextResponse.json(
          { error: "This short link has expired, was deleted, or does not exist." },
          { status: 404 },
        );
      }
      if (
        typeof body.message !== "string" ||
        typeof body.signature !== "string" ||
        !/^0x[0-9a-fA-F]{130}$/.test(body.signature)
      ) {
        return NextResponse.json({ error: "The creator deletion signature is missing." }, { status: 400 });
      }
      const wallet = await verifyWalletAuthorization(
        body.message,
        body.signature as `0x${string}`,
        "delete",
        requestHost(request),
        {
          action: "delete",
          documentId: document.id,
          documentDigest: document.documentDigest,
          policyDigest: document.policyDigest,
          keyCommitment: document.keyCommitment,
          wrappedKeyDigest: wrappedKeyDigest(document.wrappedKey),
          shareId: id,
        },
      );
      if (wallet !== getAddress(document.author)) {
        return NextResponse.json(
          { error: "Only the document creator wallet can delete this hosted copy." },
          { status: 403 },
        );
      }
      await deleteHostedShareAsCreator(id);
    }
    return NextResponse.json({ deleted: true }, {
      headers: { "cache-control": "no-store, private" },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The short link could not be deleted.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
