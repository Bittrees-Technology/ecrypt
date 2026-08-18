import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import test from "node:test";
import { encodeAbiParameters, getAddress, toEventSelector } from "viem";
import { privateKeyToAccount } from "viem/accounts";

process.env.ECRYPT_MASTER_KEY = Buffer.alloc(32, 7).toString("base64");
process.env.ECRYPT_CHALLENGE_SECRET = Buffer.alloc(32, 6).toString("base64");
process.env.ECRYPT_ACTIVE_KEY_ID = "test-key-2026-08";
process.env.ECRYPT_ALLOW_MEMORY_NONCE_STORE = "true";
process.env.ECRYPT_ALLOW_MEMORY_SHARE_STORE = "true";
process.env.ALCHEMY_API_KEY = "test-key";

const projectRoot = new URL("../", import.meta.url);
const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
const stranger = privateKeyToAccount(`0x${"22".repeat(32)}`);
const holder = privateKeyToAccount(`0x${"33".repeat(32)}`);

async function worker() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${Math.random()}`);
  return (await import(workerUrl.href)).default;
}

function runtime() {
  return { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } };
}

function context() {
  return { waitUntil() {}, passThroughOnException() {} };
}

async function post(handler, path, body) {
  return request(handler, "POST", path, body);
}

async function request(handler, method, path, body) {
  return handler.fetch(
    new Request(`http://localhost${path}`, {
      method,
      headers: {
        origin: "http://localhost",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
    runtime(),
    context(),
  );
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalPolicy(policy) {
  return JSON.stringify({
    mode: policy.mode,
    rules: policy.rules.map((rule) => ({
      id: rule.id,
      kind: rule.kind,
      ...(rule.network ? { network: rule.network } : {}),
      ...(rule.address ? { address: getAddress(rule.address).toLowerCase() } : {}),
      ...(rule.contract ? { contract: getAddress(rule.contract).toLowerCase() } : {}),
      ...(rule.tokenId ? { tokenId: rule.tokenId } : {}),
      ...(rule.minimum ? { minimum: rule.minimum } : {}),
    })),
  });
}

function canonicalDocument(core) {
  return JSON.stringify({
    version: 2,
    id: core.id,
    title: core.title,
    author: getAddress(core.author).toLowerCase(),
    createdAt: core.createdAt,
    policy: JSON.parse(canonicalPolicy(core.policy)),
    keyCommitment: core.keyCommitment,
    segments: core.segments,
  });
}

function descriptor(policy, signer = account, key = Buffer.alloc(32, 9), suffix = "security01") {
  return {
    documentId: `doc-${suffix}`,
    documentDigest: hash(`signed public text:${suffix}`),
    policyDigest: hash(canonicalPolicy(policy)),
    keyCommitment: hash(key),
    author: signer.address,
    policy,
    key,
  };
}

function sealBinding(document) {
  return {
    action: "seal",
    documentId: document.documentId,
    documentDigest: document.documentDigest,
    policyDigest: document.policyDigest,
    keyCommitment: document.keyCommitment,
  };
}

function wrapperDigest(wrappedKey) {
  return hash(JSON.stringify({
    provider: wrappedKey.provider,
    keyId: wrappedKey.keyId,
    ciphertext: wrappedKey.ciphertext,
  }));
}

function unlockBinding(document, wrappedKey) {
  return {
    ...sealBinding(document),
    action: "unlock",
    wrappedKeyDigest: wrapperDigest(wrappedKey),
  };
}

function deleteBinding(document, wrappedKey, shareId) {
  return {
    ...sealBinding(document),
    action: "delete",
    wrappedKeyDigest: wrapperDigest(wrappedKey),
    shareId,
  };
}

async function hostedPackage(handler) {
  const policy = { mode: "any", rules: [{ id: "wallet-owner", kind: "wallet", address: account.address }] };
  const key = Buffer.alloc(32, 12);
  const core = {
    version: 2,
    id: "doc-hosted001",
    title: "Hosted package",
    author: account.address,
    createdAt: "2026-08-18T00:00:00.000Z",
    policy,
    keyCommitment: hash(key),
    segments: [
      { kind: "public", text: "The protected value is " },
      {
        kind: "encrypted",
        ciphertext: Buffer.alloc(32, 3).toString("base64url"),
        iv: Buffer.alloc(12, 4).toString("base64url"),
        commitment: hash("hosted protected value"),
      },
    ],
  };
  const document = {
    documentId: core.id,
    documentDigest: hash(canonicalDocument(core)),
    policyDigest: hash(canonicalPolicy(policy)),
    keyCommitment: core.keyCommitment,
    author: core.author,
    policy,
    key,
  };
  const sealed = await seal(handler, document);
  return {
    package: {
      ...core,
      documentDigest: document.documentDigest,
      policyDigest: document.policyDigest,
      wrappedKey: sealed.wrappedKey,
      creatorProof: sealed.creatorProof,
    },
    document,
    sealed,
  };
}

async function authorization(handler, action, signer, binding) {
  const response = await post(handler, "/api/challenge", {
    action,
    address: signer.address,
    chainId: 1,
    binding,
  });
  assert.equal(response.status, 200, response.status === 200 ? "" : await response.text());
  const challenge = await response.json();
  assert.match(challenge.message, /Version: 1\nChain ID: 1\nNonce: [a-f0-9]{32}/);
  assert.match(challenge.message, new RegExp(`document-digest:${binding.documentDigest}`));
  return {
    message: challenge.message,
    signature: await signer.signMessage({ message: challenge.message }),
  };
}

async function seal(handler, document, signer = account) {
  const creatorProof = await authorization(handler, "seal", signer, sealBinding(document));
  const response = await post(handler, "/api/wrap", {
    key: document.key.toString("base64url"),
    documentId: document.documentId,
    documentDigest: document.documentDigest,
    policyDigest: document.policyDigest,
    keyCommitment: document.keyCommitment,
    author: document.author,
    policy: document.policy,
    ...creatorProof,
  });
  assert.equal(response.status, 200, response.status === 200 ? "" : await response.text());
  return { ...(await response.json()), creatorProof };
}

async function unlock(handler, document, sealed, signer) {
  const proof = await authorization(handler, "unlock", signer, unlockBinding(document, sealed.wrappedKey));
  return post(handler, "/api/unwrap", {
    documentId: document.documentId,
    documentDigest: document.documentDigest,
    policyDigest: document.policyDigest,
    keyCommitment: document.keyCommitment,
    author: document.author,
    policy: sealed.policy,
    wrappedKey: sealed.wrappedKey,
    creatorProof: sealed.creatorProof,
    ...proof,
  });
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
  assert.match(html, /<title>eCrypt — Wallet-Gated Text Encryption &amp; Redaction<\/title>/i);
  assert.match(html, /Encrypt the redactions/);
  assert.match(html, /Robinhood/);
  assert.doesNotMatch(html, /Robinhood Chain/);
  assert.match(html, /Paste &amp; decrypt/);
  assert.match(html, /About/);
});

test("version-2 wallet policy wraps and unwraps the same key", async () => {
  const handler = await worker();
  const policy = { mode: "any", rules: [{ id: "wallet-owner", kind: "wallet", address: account.address }] };
  const document = descriptor(policy, account, Buffer.alloc(32, 9), "wallet001");
  const sealed = await seal(handler, document);
  assert.equal(sealed.author, account.address);
  assert.equal(sealed.wrappedKey.provider, "local-aes-gcm");
  assert.equal(sealed.wrappedKey.keyId, "test-key-2026-08");

  const response = await unlock(handler, document, sealed, account);
  assert.equal(response.status, 200, response.status === 200 ? "" : await response.text());
  const opened = await response.json();
  assert.equal(opened.key, document.key.toString("base64url"));
  assert.equal(opened.access, "creator");
});

test("creator access bypasses the reader policy but strangers cannot", async () => {
  const handler = await worker();
  const policy = { mode: "any", rules: [{ id: "wallet-reader", kind: "wallet", address: holder.address }] };
  const document = descriptor(policy, account, Buffer.alloc(32, 8), "creator01");
  const sealed = await seal(handler, document);
  assert.equal((await unlock(handler, document, sealed, account)).status, 200);
  assert.equal((await unlock(handler, document, sealed, stranger)).status, 403);
});

test("hosted short links retrieve a signed package and the creator can permanently delete it", async () => {
  const handler = await worker();
  const { package: documentPackage, document, sealed } = await hostedPackage(handler);
  const createResponse = await post(handler, "/api/share", { document: documentPackage });
  assert.equal(createResponse.status, 201, createResponse.status === 201 ? "" : await createResponse.text());
  const created = await createResponse.json();
  assert.match(created.id, /^[A-Za-z0-9_-]{22}$/);
  assert.match(created.deleteToken, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(created.expiresAt, undefined);

  const readResponse = await request(handler, "GET", `/api/share/${created.id}`);
  assert.equal(readResponse.status, 200, readResponse.status === 200 ? "" : await readResponse.text());
  assert.deepEqual((await readResponse.json()).document, documentPackage);

  const binding = deleteBinding(document, sealed.wrappedKey, created.id);
  const strangerProof = await authorization(handler, "delete", stranger, binding);
  const strangerDelete = await request(handler, "DELETE", `/api/share/${created.id}`, strangerProof);
  assert.equal(strangerDelete.status, 403);
  assert.match((await strangerDelete.json()).error, /creator wallet/i);

  const creatorProof = await authorization(handler, "delete", account, binding);
  const creatorDelete = await request(handler, "DELETE", `/api/share/${created.id}`, creatorProof);
  assert.equal(creatorDelete.status, 200, creatorDelete.status === 200 ? "" : await creatorDelete.text());
  assert.equal((await creatorDelete.json()).deleted, true);

  const missingResponse = await request(handler, "GET", `/api/share/${created.id}`);
  assert.equal(missingResponse.status, 404);
});

test("the same document-bound wallet authorization cannot be replayed", async () => {
  const handler = await worker();
  const policy = { mode: "any", rules: [{ id: "wallet-owner", kind: "wallet", address: account.address }] };
  const document = descriptor(policy, account, Buffer.alloc(32, 7), "replay001");
  const sealed = await seal(handler, document);
  const proof = await authorization(handler, "unlock", account, unlockBinding(document, sealed.wrappedKey));
  const request = {
    documentId: document.documentId,
    documentDigest: document.documentDigest,
    policyDigest: document.policyDigest,
    keyCommitment: document.keyCommitment,
    author: document.author,
    policy: sealed.policy,
    wrappedKey: sealed.wrappedKey,
    creatorProof: sealed.creatorProof,
    ...proof,
  };
  assert.equal((await post(handler, "/api/unwrap", request)).status, 200);
  const replay = await post(handler, "/api/unwrap", request);
  assert.equal(replay.status, 400);
  assert.match((await replay.json()).error, /already been used/i);
});

test("altered document digests and public-package bindings are rejected", async () => {
  const handler = await worker();
  const policy = { mode: "any", rules: [{ id: "wallet-owner", kind: "wallet", address: account.address }] };
  const document = descriptor(policy, account, Buffer.alloc(32, 5), "tamper001");
  const sealed = await seal(handler, document);
  const altered = { ...document, documentDigest: hash("changed public wording") };
  const response = await unlock(handler, altered, sealed, account);
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /expired or invalid/i);
});

test("zero and negative token minimums are rejected server-side", async () => {
  const handler = await worker();
  for (const [minimum, suffix] of [["0", "zero0001"], ["-1", "negative1"]]) {
    const policy = {
      mode: "any",
      rules: [{ id: `erc20-${suffix}`, kind: "erc20", network: "ethereum", contract: stranger.address, minimum }],
    };
    const document = {
      ...descriptor({ mode: "any", rules: [{ ...policy.rules[0], minimum: "1" }] }, account, Buffer.alloc(32, 4), suffix),
      policy,
    };
    const creatorProof = await authorization(handler, "seal", account, sealBinding(document));
    const response = await post(handler, "/api/wrap", {
      key: document.key.toString("base64url"),
      ...document,
      ...creatorProof,
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error, /greater than zero/i);
  }
});

test("an ERC-1155 policy can authorize ownership of any token ID", async () => {
  const handler = await worker();
  const contract = stranger.address;
  const policy = {
    mode: "any",
    rules: [{ id: "erc1155-any", kind: "erc1155", network: "ethereum", contract, minimum: "2" }],
  };
  const document = descriptor(policy, account, Buffer.alloc(32, 3), "erc115501");
  const sealed = await seal(handler, document);
  assert.equal(sealed.policy.rules[0].tokenId, undefined);

  const originalFetch = globalThis.fetch;
  const ownershipRequests = [];
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    ownershipRequests.push(url.pathname);
    if (url.pathname.endsWith("/getNFTsForOwner")) {
      return Response.json({
        ownedNfts: [{ contract: { address: contract, tokenType: "ERC1155" }, tokenId: "7", tokenType: "ERC1155" }],
        pageKey: null,
      });
    }
    const rpc = JSON.parse(String(init?.body));
    assert.equal(rpc.method, "eth_call");
    return Response.json({ jsonrpc: "2.0", id: 1, result: encodeAbiParameters([{ type: "uint256[]" }], [[3n]]) });
  };
  try {
    assert.equal((await unlock(handler, document, sealed, holder)).status, 200);
    assert.equal(ownershipRequests.length, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("any-ID ERC-1155 falls back to live transfer logs", async () => {
  const handler = await worker();
  const contract = stranger.address;
  const policy = {
    mode: "any",
    rules: [{ id: "erc1155-any-robinhood", kind: "erc1155", network: "robinhood", contract, minimum: "1" }],
  };
  const document = descriptor(policy, account, Buffer.alloc(32, 2), "erc115502");
  const sealed = await seal(handler, document);
  const originalFetch = globalThis.fetch;
  const methods = [];
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/getNFTsForOwner")) return Response.json({ error: "unavailable" }, { status: 404 });
    const rpc = JSON.parse(String(init?.body));
    methods.push(rpc.method);
    if (rpc.method === "eth_getLogs") {
      return Response.json({
        jsonrpc: "2.0",
        id: 1,
        result: [{
          topics: [toEventSelector("TransferSingle(address,address,address,uint256,uint256)")],
          data: encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }], [19n, 1n]),
        }],
      });
    }
    return Response.json({ jsonrpc: "2.0", id: 1, result: encodeAbiParameters([{ type: "uint256[]" }], [[1n]]) });
  };
  try {
    assert.equal((await unlock(handler, document, sealed, holder)).status, 200);
    assert.deepEqual(methods, ["eth_getLogs", "eth_call"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("version-2 client source keeps the commitment nonce inside ciphertext", async () => {
  const appSource = await readFile(new URL("app/EcryptApp.tsx", projectRoot), "utf8");
  const schemaSource = await readFile(new URL("lib/ecrypt.ts", projectRoot), "utf8");
  const serverSource = await readFile(new URL("lib/server-security.ts", projectRoot), "utf8");
  const wrapperSource = await readFile(new URL("lib/key-wrapper.ts", projectRoot), "utf8");
  assert.match(appSource, /\[sha256:\$\{segment\.commitment\}\]/);
  assert.match(appSource, /commitmentNonce: bytesToBase64Url\(commitmentNonce\)/);
  assert.match(appSource, /ecrypt:v2:commitment/);
  assert.doesNotMatch(schemaSource, /\bsalt:/);
  assert.match(schemaSource, /version: 2/);
  assert.match(appSource, /version-1 package is no longer supported/);
  assert.match(appSource, /verifyPackageAuthenticity/);
  assert.match(serverSource, /consumeChallengeNonce/);
  assert.match(serverSource, /document-digest/);
  assert.match(wrapperSource, /EncryptionContext/);
  assert.match(wrapperSource, /keyCommitment/);
});

test("the established copy, JSON, wallet, preview, and About flows remain present", async () => {
  const appSource = await readFile(new URL("app/EcryptApp.tsx", projectRoot), "utf8");
  const stylesheet = await readFile(new URL("app/globals.css", projectRoot), "utf8");
  assert.match(appSource, /BEGIN ECRYPT UNLOCK DATA/);
  assert.match(appSource, /Copy all/);
  assert.match(appSource, /Copy redacted message only/);
  assert.match(appSource, /Copy unlock hash only/);
  assert.match(appSource, /No account history or recovery/);
  assert.match(appSource, /Create short link/);
  assert.match(appSource, /Delete hosted message/);
  assert.match(appSource, /openedShareId && creatorWalletConnected/);
  assert.match(appSource, /accountsChanged/);
  assert.match(appSource, /#share=/);
  assert.match(appSource, /Upload \.ecrypt\.json/);
  assert.match(appSource, /Document title <span>\(optional\)<\/span>/);
  assert.match(appSource, /type Mode = "compose" \| "open" \| "about"/);
  assert.match(appSource, /Creator access is built in/);
  assert.match(appSource, /Gasless by default/);
  assert.match(appSource, /Protocol \/ current build/);
  assert.match(appSource, /Why do deletion controls appear or disappear/);
  assert.match(appSource, /Is eCrypt quantum-safe/);
  assert.match(appSource, /handleWalletAction/);
  assert.match(appSource, /wallet_switchEthereumChain/);
  assert.match(appSource, /explorerAddressUrl/);
  assert.match(appSource, /PREVIEW_PAGE_CHARACTER_LIMIT = 1_800/);
  assert.match(stylesheet, /\.about-panel/);
  assert.match(stylesheet, /grid-template-columns: minmax\(0, 2fr\) minmax\(0, 1fr\)/);
  assert.doesNotMatch(appSource, /SAMPLE_DOCUMENT|Untitled private document|Untitled encrypted message|always eligible/);
  await assert.rejects(access(new URL("app/_sites-preview", projectRoot)));
});

test("SEO metadata, crawler files, and branded icons are present", async () => {
  const layoutSource = await readFile(new URL("app/layout.tsx", projectRoot), "utf8");
  const pageSource = await readFile(new URL("app/page.tsx", projectRoot), "utf8");
  const robots = await readFile(new URL("public/robots.txt", projectRoot), "utf8");
  const sitemap = await readFile(new URL("public/sitemap.xml", projectRoot), "utf8");
  const manifest = JSON.parse(await readFile(new URL("public/site.webmanifest", projectRoot), "utf8"));
  assert.match(layoutSource, /https:\/\/ecrypt\.bittrees\.org/);
  assert.match(layoutSource, /Wallet-Gated Text Encryption & Redaction/);
  assert.match(pageSource, /"@type": "WebApplication"/);
  assert.match(robots, /Sitemap: https:\/\/ecrypt\.bittrees\.org\/sitemap\.xml/);
  assert.match(sitemap, /<loc>https:\/\/ecrypt\.bittrees\.org\/<\/loc>/);
  assert.equal(manifest.short_name, "eCrypt");
  await Promise.all([
    "public/favicon.ico",
    "public/favicon-32x32.png",
    "public/apple-touch-icon.png",
    "public/icon-192.png",
    "public/icon.png",
    "public/og.png",
  ].map((asset) => access(new URL(asset, projectRoot))));
});

test("repository documentation declares version 2, MIT, and private reporting", async () => {
  const readme = await readFile(new URL("README.md", projectRoot), "utf8");
  const license = await readFile(new URL("LICENSE", projectRoot), "utf8");
  const security = await readFile(new URL("SECURITY.md", projectRoot), "utf8");
  const envExample = await readFile(new URL(".env.example", projectRoot), "utf8");
  const packageJson = JSON.parse(await readFile(new URL("package.json", projectRoot), "utf8"));
  assert.match(readme, /https:\/\/ecrypt\.bittrees\.org/);
  assert.match(readme, /Version 2|version 2/);
  assert.match(readme, /nonce-protected/i);
  assert.match(readme, /Hosted short link/);
  assert.match(readme, /creator-authorized.*deletion|creator-deletion/i);
  assert.match(readme, /Current production build/);
  assert.match(readme, /no automatic expiration/i);
  assert.match(readme, /deletion controls appear only/i);
  assert.match(readme, /AWS KMS/);
  assert.match(license, /^MIT License/);
  assert.match(security, /private vulnerability reporting/);
  assert.match(security, /one-time/i);
  assert.match(security, /hosted short-link/i);
  assert.match(envExample, /ECRYPT_CHALLENGE_SECRET=/);
  assert.match(envExample, /BLOB_READ_WRITE_TOKEN=/);
  assert.equal(packageJson.license, "MIT");
});
