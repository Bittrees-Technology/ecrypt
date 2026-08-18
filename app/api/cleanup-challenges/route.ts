import { NextResponse } from "next/server";
import { cleanupExpiredChallengeNonces } from "../../../lib/challenge-store";
import { cleanupExpiredHostedShares } from "../../../lib/share-store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  try {
    const [replayMarkers, hostedShares] = await Promise.all([
      cleanupExpiredChallengeNonces(),
      cleanupExpiredHostedShares(),
    ]);
    return NextResponse.json(
      { deleted: { replayMarkers, hostedShares } },
      { headers: { "cache-control": "no-store" } },
    );
  } catch {
    return NextResponse.json({ error: "Temporary-data cleanup failed." }, { status: 500 });
  }
}
