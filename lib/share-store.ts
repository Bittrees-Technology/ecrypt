import { del, get, list, put } from "@vercel/blob";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { EcryptPackage, isEcryptPackage, isShareId } from "./ecrypt";

const DAY_MS = 24 * 60 * 60 * 1000;
const RETENTION_DAYS = 30;
const SHARE_ID = /^[A-Za-z0-9_-]{22}$/;
const DELETE_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const memoryShares = new Map<string, StoredShare>();

interface StoredShare {
  version: 1;
  createdAt: string;
  expiresAt: string;
  deleteTokenHash: string;
  document: EcryptPackage;
}

export interface CreatedShare {
  id: string;
  expiresAt: string;
  deleteToken: string;
}

function mayUseMemoryStore(): boolean {
  return process.env.NODE_ENV !== "production" || process.env.ECRYPT_ALLOW_MEMORY_SHARE_STORE === "true";
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function sharePathname(id: string): string | null {
  return SHARE_ID.test(id) ? `ecrypt-shares/${id}.json` : null;
}

function isStoredShare(value: unknown): value is StoredShare {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<StoredShare>;
  return (
    item.version === 1 &&
    typeof item.createdAt === "string" &&
    Number.isFinite(Date.parse(item.createdAt)) &&
    typeof item.expiresAt === "string" &&
    Number.isFinite(Date.parse(item.expiresAt)) &&
    typeof item.deleteTokenHash === "string" &&
    /^[a-f0-9]{64}$/.test(item.deleteTokenHash) &&
    isEcryptPackage(item.document)
  );
}

function assertConfigured() {
  if (!process.env.BLOB_READ_WRITE_TOKEN && !mayUseMemoryStore()) {
    throw new Error("Hosted short-link storage is not configured.");
  }
}

export async function createHostedShare(document: EcryptPackage): Promise<CreatedShare> {
  assertConfigured();
  const createdAt = new Date();
  const id = randomBytes(16).toString("base64url");
  const pathname = sharePathname(id);
  if (!pathname) throw new Error("The short-link identifier could not be created.");

  const deleteToken = randomBytes(32).toString("base64url");
  const stored: StoredShare = {
    version: 1,
    createdAt: createdAt.toISOString(),
    expiresAt: new Date(createdAt.getTime() + RETENTION_DAYS * DAY_MS).toISOString(),
    deleteTokenHash: tokenHash(deleteToken),
    document,
  };
  const serialized = JSON.stringify(stored);

  if (process.env.BLOB_READ_WRITE_TOKEN) {
    await put(pathname, serialized, {
      access: "private",
      addRandomSuffix: false,
      allowOverwrite: false,
      cacheControlMaxAge: 60,
      contentType: "application/json",
    });
  } else {
    memoryShares.set(id, stored);
  }

  return { id, expiresAt: stored.expiresAt, deleteToken };
}

export async function getHostedShare(id: string): Promise<EcryptPackage | null> {
  assertConfigured();
  const pathname = sharePathname(id);
  if (!pathname) return null;

  let stored: StoredShare | null = null;
  if (process.env.BLOB_READ_WRITE_TOKEN) {
    const result = await get(pathname, { access: "private", useCache: false });
    if (!result || result.statusCode !== 200) return null;
    const value = await new Response(result.stream).json() as unknown;
    if (!isStoredShare(value)) throw new Error("The hosted package record is invalid.");
    stored = value;
  } else {
    stored = memoryShares.get(id) || null;
  }

  if (!stored || Date.now() >= Date.parse(stored.expiresAt)) {
    await deleteHostedShareById(id);
    return null;
  }
  return stored.document;
}

async function deleteHostedShareById(id: string): Promise<void> {
  const pathname = sharePathname(id);
  if (!pathname) return;
  if (process.env.BLOB_READ_WRITE_TOKEN) {
    await del(pathname);
  } else {
    memoryShares.delete(id);
  }
}

export async function deleteHostedShareAsCreator(id: string): Promise<void> {
  assertConfigured();
  if (!isShareId(id)) throw new Error("This short link is invalid.");
  await deleteHostedShareById(id);
}

export async function deleteHostedShare(id: string, suppliedToken: string): Promise<boolean> {
  assertConfigured();
  if (!DELETE_TOKEN.test(suppliedToken)) return false;
  const pathname = sharePathname(id);
  if (!pathname) return false;

  let stored: StoredShare | null = null;
  if (process.env.BLOB_READ_WRITE_TOKEN) {
    const result = await get(pathname, { access: "private", useCache: false });
    if (!result || result.statusCode !== 200) return false;
    const value = await new Response(result.stream).json() as unknown;
    if (!isStoredShare(value)) return false;
    stored = value;
  } else {
    stored = memoryShares.get(id) || null;
  }
  if (!stored) return false;

  const expected = Buffer.from(stored.deleteTokenHash, "hex");
  const supplied = Buffer.from(tokenHash(suppliedToken), "hex");
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return false;
  await deleteHostedShareById(id);
  return true;
}

export async function cleanupExpiredHostedShares(): Promise<number> {
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    let deleted = 0;
    for (const [id, stored] of memoryShares) {
      if (Date.parse(stored.expiresAt) <= Date.now()) {
        memoryShares.delete(id);
        deleted += 1;
      }
    }
    return deleted;
  }

  const cutoff = Date.now() - RETENTION_DAYS * DAY_MS;
  let cursor: string | undefined;
  let deleted = 0;
  for (let page = 0; page < 10; page += 1) {
    const result = await list({ prefix: "ecrypt-shares/", limit: 1_000, cursor });
    const expired = result.blobs.filter((blob) => blob.uploadedAt.getTime() <= cutoff);
    if (expired.length) {
      await del(expired.map((blob) => blob.url));
      deleted += expired.length;
    }
    if (!result.hasMore || !result.cursor) break;
    cursor = result.cursor;
  }
  return deleted;
}
