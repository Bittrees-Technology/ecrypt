# eCrypt

eCrypt creates portable documents with public text and encrypted inline redactions. A reader connects an EVM wallet, signs a fee-free message, and must satisfy the document's current access policy before the protected passages can be decrypted.

The primary result is copyable plain text: the original public text remains unchanged while every protected passage is replaced inline with its full salted `sha256:…` hash. “Copy all” includes that redacted message and its encrypted unlock-data block; “Copy redacted message only” creates a public document that cannot be decrypted by itself; and “Copy unlock hash only” copies the compact encrypted package without the readable duplicate. Share links and `.ecrypt.json` packages remain available too.

Document titles are optional. Decryption defaults to copy/paste and also accepts downloaded `.ecrypt.json` packages. eCrypt keeps no document history: if every copy containing the unlock data is lost, the protected passages cannot be recovered from their SHA-256 hashes.

Supported access conditions:

- a specific wallet address
- an ERC-20 minimum balance
- ownership of any token, or one token ID, from an ERC-721 collection
- ownership of any token ID, or one specific token ID, from an ERC-1155 contract, with a minimum balance per ID
- up to five conditions combined with `ANY` or `ALL`
- the wallet that creates a document always retains decrypt access

Supported networks:

- Ethereum mainnet (chain ID `1`)
- Base mainnet (chain ID `8453`)
- Robinhood mainnet (chain ID `4663`)

## How it protects a document

1. The browser generates a random AES-256-GCM document key.
2. Each `[[marked passage]]` is encrypted locally with a unique nonce.
3. A random salt is combined with the plaintext to produce the visible SHA-256 integrity hash.
4. The service wraps the document key with `ECRYPT_MASTER_KEY`, binding it to the author and normalized access policy.
5. On unlock, the service verifies the wallet signature. The creator wallet is always eligible; other wallets must satisfy the live onchain policy before the document key is unwrapped.
6. The browser decrypts the passages and verifies each salted hash locally.

The document itself is not stored in a database. The share URL or downloaded `.ecrypt.json` package carries the public text, ciphertext, protected key, and policy.

## Local setup

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
npm run build
npm run build:vercel
```

Create these server-only environment variables:

```text
ECRYPT_MASTER_KEY=<32 random bytes encoded as base64>
ALCHEMY_API_KEY=<Alchemy application key>
```

Generate a master key with a cryptographically secure random-number generator. Never expose either value through a `NEXT_PUBLIC_` variable or commit it to the repository.

## Verification

```bash
npm test
npm run lint
```

The integration test exercises server rendering, challenge signing, key wrapping, an authorized wallet unlock, and rejection of an unauthorized wallet.

## Security boundary

eCrypt is an MVP, not an independently audited cryptographic product. The deployed service can unwrap document keys after policy verification, so control of `ECRYPT_MASTER_KEY` is security-critical. Rotating that key invalidates previously sealed documents unless a key-version migration is implemented. In-memory request limiting is best-effort in serverless environments; production abuse protection should also be configured at the hosting edge.
