import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";
import { encodeAbiParameters, toEventSelector } from "viem";
import { privateKeyToAccount } from "viem/accounts";

process.env.ECRYPT_MASTER_KEY = Buffer.alloc(32, 7).toString("base64");
process.env.ALCHEMY_API_KEY = "test-key";

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
  assert.match(html, /Robinhood/);
  assert.doesNotMatch(html, /Robinhood Chain/);
  assert.match(html, /Paste &amp; decrypt/);
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

test("an ERC-1155 policy can authorize ownership of any token ID", async () => {
  const handler = await worker();
  const contract = stranger.address;
  const policy = {
    mode: "any",
    rules: [
      {
        id: "erc1155-any",
        kind: "erc1155",
        network: "ethereum",
        contract,
        tokenId: "",
        minimum: "2",
      },
    ],
  };
  const sealAuthorization = await authorization(handler, "seal", account);
  const wrapResponse = await post(handler, "/api/wrap", {
    key: Buffer.alloc(32, 5).toString("base64url"),
    policy,
    ...sealAuthorization,
  });
  assert.equal(wrapResponse.status, 200);
  const wrapped = await wrapResponse.json();
  assert.equal(wrapped.policy.rules[0].tokenId, undefined);

  const originalFetch = globalThis.fetch;
  const ownershipRequests = [];
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    ownershipRequests.push(url.pathname);
    if (url.pathname.endsWith("/getNFTsForOwner")) {
      assert.equal(url.searchParams.get("owner"), account.address);
      assert.equal(url.searchParams.get("contractAddresses[]"), contract);
      return Response.json({
        ownedNfts: [
          {
            contract: { address: contract, tokenType: "ERC1155" },
            tokenId: "7",
            tokenType: "ERC1155",
          },
        ],
        pageKey: null,
      });
    }
    const rpc = JSON.parse(String(init?.body));
    assert.equal(rpc.method, "eth_call");
    return Response.json({
      jsonrpc: "2.0",
      id: 1,
      result: encodeAbiParameters([{ type: "uint256[]" }], [[3n]]),
    });
  };

  try {
    const unlockAuthorization = await authorization(handler, "unlock", account);
    const unwrapResponse = await post(handler, "/api/unwrap", {
      wrappedKey: wrapped.wrappedKey,
      policy: wrapped.policy,
      author: wrapped.author,
      ...unlockAuthorization,
    });
    assert.equal(unwrapResponse.status, 200);
    assert.equal(ownershipRequests.length, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("an any-ID ERC-1155 policy falls back to live transfer logs", async () => {
  const handler = await worker();
  const contract = stranger.address;
  const policy = {
    mode: "any",
    rules: [
      {
        id: "erc1155-any-robinhood",
        kind: "erc1155",
        network: "robinhood",
        contract,
        minimum: "1",
      },
    ],
  };
  const sealAuthorization = await authorization(handler, "seal", account);
  const wrapResponse = await post(handler, "/api/wrap", {
    key: Buffer.alloc(32, 6).toString("base64url"),
    policy,
    ...sealAuthorization,
  });
  const wrapped = await wrapResponse.json();

  const originalFetch = globalThis.fetch;
  const rpcMethods = [];
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/getNFTsForOwner")) {
      return Response.json({ error: "NFT index unavailable" }, { status: 404 });
    }
    const rpc = JSON.parse(String(init?.body));
    rpcMethods.push(rpc.method);
    if (rpc.method === "eth_getLogs") {
      return Response.json({
        jsonrpc: "2.0",
        id: 1,
        result: [
          {
            topics: [
              toEventSelector("TransferSingle(address,address,address,uint256,uint256)"),
            ],
            data: encodeAbiParameters(
              [{ type: "uint256" }, { type: "uint256" }],
              [19n, 1n],
            ),
          },
        ],
      });
    }
    assert.equal(rpc.method, "eth_call");
    return Response.json({
      jsonrpc: "2.0",
      id: 1,
      result: encodeAbiParameters([{ type: "uint256[]" }], [[1n]]),
    });
  };

  try {
    const unlockAuthorization = await authorization(handler, "unlock", account);
    const unwrapResponse = await post(handler, "/api/unwrap", {
      wrappedKey: wrapped.wrappedKey,
      policy: wrapped.policy,
      author: wrapped.author,
      ...unlockAuthorization,
    });
    assert.equal(unwrapResponse.status, 200);
    assert.deepEqual(rpcMethods, ["eth_getLogs", "eth_call"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("starter-only assets are gone", async () => {
  const packageJson = await readFile(new URL("package.json", projectRoot), "utf8");
  const appSource = await readFile(new URL("app/EcryptApp.tsx", projectRoot), "utf8");
  assert.doesNotMatch(packageJson, /react-loading-skeleton|site-creator-vinext-starter/);
  assert.match(appSource, /\[sha256:\$\{segment\.hash\}\]/);
  assert.match(appSource, /BEGIN ECRYPT UNLOCK DATA/);
  assert.match(appSource, /Copy unlockable text/);
  assert.match(appSource, /handleWalletAction/);
  assert.match(appSource, /network-picker/);
  await assert.rejects(access(new URL("app/_sites-preview", projectRoot)));
});
