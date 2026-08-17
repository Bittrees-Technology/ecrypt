import { NextResponse } from "next/server";
import {
  assertRateLimit,
  assertSameOrigin,
  ChallengeAction,
  issueChallenge,
  requestHost,
} from "../../../lib/server-security";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    assertSameOrigin(request);
    assertRateLimit(request, "challenge", 40);
    const body = (await request.json()) as { action?: ChallengeAction };
    if (body.action !== "seal" && body.action !== "unlock") {
      return NextResponse.json({ error: "Choose a valid wallet action." }, { status: 400 });
    }
    return NextResponse.json(issueChallenge(body.action, requestHost(request)), {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "A challenge could not be created.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

