# eCrypt

Wallet-gated encryption for inline text redactions on Ethereum, Base, and Robinhood.

[Live app](https://ecrypt.bittrees.org) · [Security policy](SECURITY.md) · [MIT license](LICENSE)

eCrypt keeps the readable parts of a message intact while replacing selected private passages with salted SHA-256 integrity hashes. Eligible readers connect an EVM wallet, sign a fee-free authorization message, and satisfy the document’s current wallet or token policy before the protected passages are decrypted in their browser.

The service does not store document history or decrypted plaintext. Encrypted packages are portable through copy/paste, share links, and `.ecrypt.json` downloads.

## Key capabilities

- Encrypt only the passages wrapped in `[[double brackets]]` or marked with **Redact selection**.
- Keep all other text readable and copyable in its original position.
- Gate decryption by wallet address, ERC-20 balance, ERC-721 ownership, or ERC-1155 balance.
- Combine up to five access conditions with `ANY` or `ALL` logic.
- Let the creator wallet decrypt its own package regardless of the reader policy.
- Use an optional title; blank titles remain absent from previews and decrypted output.
- Paste an encrypted package to decrypt by default, or upload a saved `.ecrypt.json` file.
- Connect or switch the wallet directly from the Ethereum, Base, and Robinhood shortcuts.
- Link protected and policy addresses to the appropriate block explorer.

## Basic workflow

1. Open [ecrypt.bittrees.org](https://ecrypt.bittrees.org) and choose **Create & redact**.
2. Write or paste a message. Select sensitive text and choose **Redact selection**, or add markers manually:

   ```text
   Transfer [[1,250 USDC]] to [[0x1234…abcd]] after approval.
   ```

3. Add one or more reveal conditions and choose whether `ANY` or `ALL` must pass.
4. Choose **Create redacted text**, connect the creator wallet, and sign the authorization message.
5. Preserve or share one of the output formats below.
6. A reader opens **Paste & decrypt**, pastes the unlock data or uploads the JSON package, connects an eligible wallet, and signs a new authorization message.

Wallet signatures authorize only the named eCrypt action. They do not submit a blockchain transaction and require no gas.

## Copy and storage formats

| Option | Contains | Can start decryption? | Intended use |
| --- | --- | --- | --- |
| **Copy all** | Public message with inline hashes plus the encrypted unlock-data block | Yes | Send one self-contained copy |
| **Copy redacted message only** | Public message with inline hashes | No | Publish a clean, non-decryptable public copy |
| **Copy unlock hash only** | The complete encoded encrypted package, despite the compact UI label | Yes | Send or store the unlock data separately |
| **Share link** | The encrypted package in the URL fragment | Yes | Open eCrypt with the package preloaded |
| **Download `.ecrypt.json`** | Structured encrypted package and policy | Yes | Durable local backup and later upload |

The inline SHA-256 values cannot reconstruct the protected text. If every copy containing the encrypted unlock data is lost, recovery is impossible—even for the creator or eCrypt.

## Access policies

| Credential | Supported rule |
| --- | --- |
| Wallet | One specific EVM address |
| ERC-20 | Minimum token balance |
| ERC-721 | Any token in a collection or one optional token ID |
| ERC-1155 | Any token ID or one optional token ID, with a minimum balance for one qualifying ID |

An ERC-1155 minimum is evaluated per token ID rather than as a sum across IDs. Policies accept up to five conditions. `ANY` allows the first matching condition; `ALL` requires every condition.

The wallet that creates a package is recorded as its author and always remains eligible to decrypt that package.

## Supported networks

| Network | Chain ID | Explorer |
| --- | ---: | --- |
| Ethereum mainnet | `1` | [Etherscan](https://etherscan.io) |
| Base mainnet | `8453` | [Basescan](https://basescan.org) |
| Robinhood mainnet | `4663` | [Blockscout](https://robinhoodchain.blockscout.com) |

The three network shortcuts connect the wallet when necessary and request a switch to the selected chain. Selecting a network inside a token condition uses the same switch flow. If the provider reports that Base or Robinhood is missing, eCrypt requests permission to add it before retrying. The wallet can require confirmation or reject any connection, addition, or switch request.

## Cryptographic and authorization flow

1. The browser creates a random 256-bit AES-GCM document key.
2. Each marked passage is encrypted locally with a unique 96-bit nonce.
3. A random salt and the plaintext produce the visible SHA-256 integrity value.
4. The creator signs a five-minute, host-bound eCrypt challenge.
5. The server protects the document key with a key derived from `ECRYPT_MASTER_KEY` and binds it to the creator address and normalized policy.
6. During unlock, the server verifies a fresh wallet signature. The creator is accepted directly; another wallet must pass the live onchain policy.
7. The server returns the document key, and the browser decrypts each passage and verifies its salted hash.

The package contains public text, ciphertext, nonces, salts, hashes, the wrapped document key, author, and access policy. Possessing it is necessary for recovery but is not sufficient for decryption without an eligible wallet.

## Local development

Requirements:

- Node.js `22.13.0` or newer
- an Alchemy application key with access to Ethereum, Base, and Robinhood
- an EVM wallet extension or compatible injected provider for interactive use

Install and configure:

```bash
npm install
cp .env.example .env.local
```

Generate a 32-byte base64 master key:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

Add that value and the Alchemy key to `.env.local`:

```text
ECRYPT_MASTER_KEY=<32 random bytes encoded as base64>
ALCHEMY_API_KEY=<server-only Alchemy application key>
```

Never use a `NEXT_PUBLIC_` prefix for either value, expose them to client code, or commit real credentials.

Start the local development server:

```bash
npm run dev
```

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the vinext development server |
| `npm run build` | Build the Cloudflare Worker-compatible vinext output |
| `npm run build:vercel` | Build the production Next.js/Vercel output |
| `npm start` | Start the built vinext application |
| `npm test` | Build and run the server, policy, ERC-1155, UI-source, SEO, and repository tests |
| `npm run lint` | Run ESLint |

## Deployment

The public deployment uses Vercel and `npm run build:vercel`. Configure `ECRYPT_MASTER_KEY` and `ALCHEMY_API_KEY` as encrypted server-side environment variables in the hosting platform.

Keep the same `ECRYPT_MASTER_KEY` for the lifetime of packages created by a deployment. Changing or losing it makes existing wrapped document keys unrecoverable unless a versioned key-migration system is added first.

## Security and operational boundary

eCrypt is experimental cryptographic software and has not been independently audited. Do not use it for regulated, safety-critical, or high-value data without an independent security review.

- Plaintext passages are encrypted and decrypted in the browser; the server receives the random document key for wrapping and returns it only after authorization.
- The deployed service can derive the wrapping key and unwrap document keys. Protecting `ECRYPT_MASTER_KEY`, the hosting account, and the server runtime is critical.
- The application stores no document vault or wallet history. Share links and local packages may still be retained by browsers, clipboard managers, messaging services, recipients, and user backups.
- Live eligibility depends on wallet providers, supported chains, token-contract behavior, and Alchemy availability.
- In-memory request limiting is best-effort in serverless environments; production edge protection should provide additional abuse controls.

Report suspected vulnerabilities privately by following [SECURITY.md](SECURITY.md). Do not disclose secrets or real encrypted documents in a public issue.

## Contributing

Issues and pull requests are welcome for reproducible bugs, accessibility improvements, documentation, and narrowly scoped features. Use synthetic documents and test wallets in examples. Security findings must use the private reporting process rather than GitHub Issues.

## License

eCrypt is available under the [MIT License](LICENSE).
