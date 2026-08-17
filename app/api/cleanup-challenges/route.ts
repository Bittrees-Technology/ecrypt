import { NextResponse } from "next/server";
import { cleanupExpiredChallengeNonces } from "../../../lib/challenge-store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  try {
    const deleted = await cleanupExpiredChallengeNonces();
    return NextResponse.json({ deleted }, { headers: { "cache-control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Replay-marker cleanup failed." }, { status: 500 });
  }
}
