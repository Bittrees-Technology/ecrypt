import { BlobError, del, list, put } from "@vercel/blob";

const memoryNonces = new Map<string, number>();

function clearExpiredMemoryNonces(now: number) {
  for (const [nonce, expiresAt] of memoryNonces) {
    if (expiresAt < now) memoryNonces.delete(nonce);
  }
}

function mayUseMemoryStore(): boolean {
  return process.env.NODE_ENV !== "production" || process.env.ECRYPT_ALLOW_MEMORY_NONCE_STORE === "true";
}

export function assertChallengeStoreConfigured() {
  if (!process.env.BLOB_READ_WRITE_TOKEN && !mayUseMemoryStore()) {
    throw new Error("One-time wallet authorization storage is not configured.");
  }
}

export async function consumeChallengeNonce(nonce: string, expiresAt: number): Promise<void> {
  if (process.env.BLOB_READ_WRITE_TOKEN) {
    const bucket = new Date(expiresAt).toISOString().slice(0, 13).replace(/[-T:]/g, "");
    try {
      await put(`ecrypt-challenges/${bucket}/${nonce}.txt`, "used", {
        access: "private",
        addRandomSuffix: false,
        allowOverwrite: false,
        cacheControlMaxAge: 60,
        contentType: "text/plain",
      });
      return;
    } catch (error) {
      if (error instanceof BlobError && /already exists|overwrite|conflict/i.test(error.message)) {
        throw new Error("This wallet authorization has already been used.");
      }
      throw new Error("The one-time wallet authorization could not be recorded. Please try again.");
    }
  }

  if (!mayUseMemoryStore()) {
    throw new Error("One-time wallet authorization storage is not configured.");
  }
  const now = Date.now();
  clearExpiredMemoryNonces(now);
  if (memoryNonces.has(nonce)) {
    throw new Error("This wallet authorization has already been used.");
  }
  memoryNonces.set(nonce, expiresAt);
}

export async function cleanupExpiredChallengeNonces(): Promise<number> {
  if (!process.env.BLOB_READ_WRITE_TOKEN) return 0;
  const cutoffHour = Number(
    new Date(Date.now() - 60 * 60 * 1000).toISOString().slice(0, 13).replace(/[-T:]/g, ""),
  );
  let cursor: string | undefined;
  let deleted = 0;

  for (let page = 0; page < 10; page += 1) {
    const result = await list({ prefix: "ecrypt-challenges/", limit: 1_000, cursor });
    const expired = result.blobs.filter((blob) => {
      const match = blob.pathname.match(/^ecrypt-challenges\/(\d{10})\//);
      return !!match && Number(match[1]) < cutoffHour;
    });
    if (expired.length) {
      await del(expired.map((blob) => blob.url));
      deleted += expired.length;
    }
    if (!result.hasMore || !result.cursor) break;
    cursor = result.cursor;
  }
  return deleted;
}
