import { NextResponse } from "next/server";
import {
  assertRateLimit,
  assertSameOrigin,
  ChallengeAction,
  issueChallenge,
  requestHost,
} from "../../../lib/server-security";
import { ChallengeBinding, isDigest, isDocumentId, isShareId } from "../../../lib/ecrypt";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    assertSameOrigin(request);
    assertRateLimit(request, "challenge", 40);
    const body = (await request.json()) as {
      action?: ChallengeAction;
      address?: string;
      chainId?: number;
      binding?: Partial<ChallengeBinding>;
    };
    if (body.action !== "seal" && body.action !== "unlock" && body.action !== "delete") {
      return NextResponse.json({ error: "Choose a valid wallet action." }, { status: 400 });
    }
    const binding = body.binding;
    if (
      !binding ||
      binding.action !== body.action ||
      !isDocumentId(binding.documentId) ||
      !isDigest(binding.documentDigest) ||
      !isDigest(binding.policyDigest) ||
      !isDigest(binding.keyCommitment) ||
      ((body.action === "unlock" || body.action === "delete") && !isDigest(binding.wrappedKeyDigest)) ||
      (body.action === "delete" && !isShareId(binding.shareId)) ||
      (body.action !== "delete" && binding.shareId !== undefined) ||
      (body.action === "seal" && binding.wrappedKeyDigest !== undefined)
    ) {
      return NextResponse.json(
        { error: "The wallet action is not bound to a valid eCrypt document." },
        { status: 400 },
      );
    }
    if (!body.address || !Number.isSafeInteger(body.chainId)) {
      return NextResponse.json({ error: "Connect a supported wallet network first." }, { status: 400 });
    }
    return NextResponse.json(issueChallenge(
      body.action,
      requestHost(request),
      body.address,
      body.chainId!,
      binding as ChallengeBinding,
    ), {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "A challenge could not be created.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
