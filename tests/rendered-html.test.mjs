import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";
import { privateKeyToAccount } from "viem/accounts";

process.env.ECRYPT_MASTER_KEY = Buffer.alloc(32, 7).toString("base64");

const projectRoot = new URL("../", import.meta.url);
const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
const stranger = privateKeyToAccount(`0x${"22".repeat(32)}`);

async function worker() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  return (await import(workerUrl.href)).default;
}

function runtime() {
  return {
    ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
  };
}

function context() {
  return { waitUntil() {}, passThroughOnException() {} };
}

async function post(handler, path, body) {
  return handler.fetch(
    new Request(`http://localhost${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost" },
      body: JSON.stringify(body),
    }),
    runtime(),
    context(),
  );
}

async function authorization(handler, action, signer) {
  const challengeResponse = await post(handler, "/api/challenge", { action });
  assert.equal(challengeResponse.status, 200);
  const challenge = await challengeResponse.json();
  return { message: challenge.message, signature: await signer.signMessage({ message: challenge.message }) };
}

test("server-renders the finished eCrypt product", async () => {
  const handler = await worker();
  const response = await handler.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    runtime(),
    context(),
  );
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<title>eCrypt — Wallet-gated document redaction<\/title>/i);
  assert.match(html, /Encrypt the redactions/);
  assert.match(html, /Robinhood Chain/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton/i);
});

test("wallet-only policy wraps and unwraps the same document key", async () => {
  const handler = await worker();
  const policy = {
    mode: "any",
    rules: [{ id: "wallet-owner", kind: "wallet", address: account.address }],
  };
  const documentKey = Buffer.alloc(32, 9).toString("base64url");
  const sealAuthorization = await authorization(handler, "seal", account);
  const wrapResponse = await post(handler, "/api/wrap", {
    key: documentKey,
    policy,
    ...sealAuthorization,
  });
  assert.equal(wrapResponse.status, 200);
  const wrapped = await wrapResponse.json();
  assert.equal(wrapped.author, account.address);

  const unlockAuthorization = await authorization(handler, "unlock", account);
  const unwrapResponse = await post(handler, "/api/unwrap", {
    wrappedKey: wrapped.wrappedKey,
    policy: wrapped.policy,
    author: wrapped.author,
    ...unlockAuthorization,
  });
  assert.equal(unwrapResponse.status, 200);
  const unwrapped = await unwrapResponse.json();
  assert.equal(unwrapped.key, documentKey);
});

test("an unauthorized wallet cannot unwrap the document key", async () => {
  const handler = await worker();
  const policy = {
    mode: "any",
    rules: [{ id: "wallet-owner", kind: "wallet", address: account.address }],
  };
  const sealAuthorization = await authorization(handler, "seal", account);
  const wrapResponse = await post(handler, "/api/wrap", {
    key: Buffer.alloc(32, 4).toString("base64url"),
    policy,
    ...sealAuthorization,
  });
  const wrapped = await wrapResponse.json();

  const unlockAuthorization = await authorization(handler, "unlock", stranger);
  const unwrapResponse = await post(handler, "/api/unwrap", {
    wrappedKey: wrapped.wrappedKey,
    policy: wrapped.policy,
    author: wrapped.author,
    ...unlockAuthorization,
  });
  assert.equal(unwrapResponse.status, 403);
});

test("starter-only assets are gone", async () => {
  const packageJson = await readFile(new URL("package.json", projectRoot), "utf8");
  assert.doesNotMatch(packageJson, /react-loading-skeleton|site-creator-vinext-starter/);
  await assert.rejects(access(new URL("app/_sites-preview", projectRoot)));
});

