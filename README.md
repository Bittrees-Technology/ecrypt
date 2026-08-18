# eCrypt

Authenticated, wallet-gated encryption for inline text redactions on Ethereum, Base, and Robinhood.

[Live app](https://ecrypt.bittrees.org) · [Security policy](SECURITY.md) · [MIT license](LICENSE)

eCrypt keeps ordinary text readable while encrypting only the passages a writer marks. The output remains an easy-to-copy document with inline SHA-256 commitments and a portable unlock-data block. The creator or an eligible reader connects an EVM wallet and signs a gasless authorization before the protected passages are decrypted in the browser.

Version 2 signs the complete readable document and metadata, uses nonce-protected commitments whose verification nonces stay inside authenticated ciphertext, rejects non-positive token minimums, consumes document-bound wallet challenges once, and binds each wrapped document key to a named wrapping-key version.

The service does not operate a wallet-synced history or recovery vault. A user can explicitly create a hosted short link, which stores the complete signed encrypted package without an automatic expiration until the creator deletes it. All other formats remain user-held, and losing every remaining copy of the unlock data makes recovery impossible.

## Current production build

| Surface | Current behavior |
| --- | --- |
| Package format | Version 2 only; complete public wording, metadata, policy, ciphertext, commitments, and key binding are authenticated by the creator signature |
| Reveal authority | The creator wallet or a wallet satisfying up to five `ANY`/`ALL` conditions |
| Networks | Ethereum, Base, and Robinhood mainnets |
| Input | Manual copy/paste is the default; `.ecrypt.json`, self-contained full links, and hosted short links are also supported |
| Hosted short links | Opt-in private storage with no automatic expiration; the link contains only a random 128-bit identifier |
| Hosted deletion | Creator-authorized and gasless; the deletion controls appear only while the signed creator wallet is connected |
| Account behavior | Wallet account changes are detected immediately, and revealed text is hidden when the account changes or disconnects |
| Onchain writes | None; the current build does not publish documents or hashes to a blockchain |

## Key capabilities

- Encrypt passages wrapped in `[[double brackets]]` or marked with **Redact selection**.
- Preserve all public text in its original, copyable position.
- Detect changes to the title, public wording, metadata, policy, ciphertext, commitments, creator, or document-key commitment before reveal.
- Gate reveal by wallet address, ERC-20 balance, ERC-721 ownership, or ERC-1155 balance.
- Accept an optional ERC-721 or ERC-1155 token ID; an omitted ERC-1155 ID means any qualifying ID from the contract.
- Combine up to five access conditions with `ANY` or `ALL` logic.
- Let the creator wallet decrypt its package regardless of the reader policy.
- Use an optional title; a blank title remains absent.
- Paste a package by default, upload `.ecrypt.json`, open a self-contained URL-fragment link, or retrieve an opt-in hosted short link.
- Let the creator wallet permanently delete eCrypt’s hosted copy through a gasless, one-time signature; creator-deletion controls stay hidden from every other connected wallet.
- Connect or switch wallets through the Ethereum, Base, and Robinhood shortcuts.
- Detect wallet account changes and hide revealed plaintext when the account changes or disconnects.
- Link creator and policy addresses to their respective block explorers.

## Basic workflow

1. Open [ecrypt.bittrees.org](https://ecrypt.bittrees.org) and choose **Create & redact**.
2. Write or paste a message. Select private text and choose **Redact selection**, or mark it directly:

   ```text
   Transfer [[1,250 USDC]] to [[0x1234…abcd]] after approval.
   ```

3. Add one or more reveal conditions and choose whether `ANY` or `ALL` must pass.
4. Choose **Create redacted text** and sign the document-bound wallet message.
5. Preserve or share one of the output formats below.
6. The creator or a reader opens **Paste & decrypt**, pastes or uploads the package (or opens either link type), connects a wallet, and signs a fresh one-time reveal authorization.

The wallet messages do not submit blockchain transactions and require no gas.

## Copy and storage formats

| Option | Contains | Can start decryption? | Intended use |
| --- | --- | --- | --- |
| **Copy all** | Public message with inline commitments plus the complete unlock-data block | Yes | One self-contained copy |
| **Copy redacted message only** | Public wording with inline commitments, but no ciphertext package or creator proof | No | A clean public display copy |
| **Copy unlock hash only** | The complete encoded package, despite the compact button label | Yes | Send or store unlock data separately |
| **Self-contained full link** | The same package in the URL fragment | Yes | Open eCrypt without server-side document storage; long packages may be truncated by other applications |
| **Hosted short link** | A random identifier; eCrypt privately stores the complete signed encrypted package until creator deletion | Yes | Easier link sharing with explicit persistent storage |
| **Download `.ecrypt.json`** | The structured version-2 package and policy | Yes | A durable local backup and later upload |

An inline commitment cannot reconstruct a protected passage. The commitment’s random nonce is encrypted with the passage, so holding the package does not allow offline testing of predictable guesses. The complete package is still required for authorized reveal.

### Hosted short links

Creating a hosted short link is an explicit storage action. The URL contains a cryptographically random 128-bit identifier, not document text, wallet addresses, ciphertext, or a document hash. The private store record contains the complete signed package: readable public text, metadata, wallet policy, ciphertext, commitments, creator proof, and protected-key envelope. It does not contain revealed plaintext or commitment nonces outside their authenticated ciphertext.

Hosted records have no automatic expiration. The browser that creates a link receives a separate random deletion capability for immediate removal. Later, the creator can open the hosted link from another device and connect the signed creator wallet; only that wallet sees the Creator deletion section. Deletion uses a one-time gasless signature bound to the exact package, protected key, and short-link identifier. It makes the identifier unavailable through eCrypt, but cannot recall packages that recipients, applications, caches, or backups already copied.

## Access policies

| Credential | Supported rule |
| --- | --- |
| Wallet | One specific EVM address |
| ERC-20 | A minimum balance greater than zero |
| ERC-721 | Any token in a collection or one optional token ID |
| ERC-1155 | Any token ID or one optional token ID, with a positive whole-number minimum for one qualifying ID |

An ERC-1155 minimum is evaluated per token ID, not as a sum across IDs. Browser validation improves feedback, while the server independently normalizes and validates every policy before wrapping or unwrapping a key.

The creator address is part of the signed package and always remains eligible to reveal it.

## Supported networks

| Network | Chain ID | Explorer |
| --- | ---: | --- |
| Ethereum mainnet | `1` | [Etherscan](https://etherscan.io) |
| Base mainnet | `8453` | [Basescan](https://basescan.org) |
| Robinhood mainnet | `4663` | [Blockscout](https://robinhoodchain.blockscout.com) |

Network shortcuts request connection and switching through the wallet provider. If Base or Robinhood is missing, eCrypt requests permission to add it. A wallet can require confirmation or reject any request. eCrypt listens for account changes: switching accounts immediately updates creator-only controls and clears revealed text, while **Disconnect wallet** clears eCrypt’s connected-account state even if the wallet application still lists the site as approved.

## Version-2 security design

### Protected passages and inline commitments

1. The browser creates a random 256-bit AES-GCM document key.
2. Every private passage receives a separate random 256-bit commitment nonce.
3. eCrypt computes `SHA-256(domain || commitment nonce || plaintext)` for the visible inline commitment.
4. The plaintext and commitment nonce are serialized together and encrypted with AES-256-GCM under a unique 96-bit IV.
5. The package exposes the commitment, IV, and ciphertext, but never the commitment nonce.
6. After authorized decryption, the browser recomputes the commitment before showing the passage.

AES-GCM additional authenticated data binds each ciphertext to its version, ordered segment position, and commitment.

### Whole-document authentication

The browser constructs a deterministic representation containing:

- version, document ID, optional title, author, and creation time;
- normalized access policy;
- document-key commitment;
- every ordered public segment;
- every ordered ciphertext, IV, and inline commitment.

It hashes that representation into the `documentDigest`. The creator signs an ERC-4361-formatted message containing the document digest, policy digest, key commitment, document ID, action, domain, issue time, expiration, and nonce. When a package is opened, eCrypt recomputes the digests and verifies the creator signature before treating the content as authentic.

The protected-key envelope is separately authenticated by its wrapping provider using the same document digest, policy digest, creator, and key commitment. Replacing the envelope therefore fails unwrap or the final key-commitment check.

### One-time reveal authorization

Every reveal signature is bound to:

- the exact document and policy digests;
- the document-key commitment;
- a digest of the exact protected-key envelope;
- the `unlock` action, origin, wallet, chain ID, issue time, and five-minute expiration;
- a cryptographically random nonce.

Production records each used nonce as an opaque private replay marker with Vercel Blob’s create-once behavior. Reusing the same authorization fails. A daily authenticated cleanup removes markers after the signed challenge can no longer be valid. These markers contain no wallet address, document digest, public wording, ciphertext, or plaintext.

Creator deletion uses the same one-time challenge protections. Its signature names the `delete` action, exact document and policy digests, key commitment, protected-key digest, and hosted short-link identifier. The server retrieves the stored package, verifies that the signing wallet is its creator, consumes the challenge nonce once, and deletes the private record.

### Versioned key wrapping

All protected keys carry a provider and `keyId`. The wrapping context binds the document digest, policy digest, author, and SHA-256 commitment of the raw AES key.

The included providers are:

- `local-aes-gcm`: versioned 256-bit environment keys for local development and self-hosting. `ECRYPT_ACTIVE_KEY_ID` selects the current version and `ECRYPT_WRAPPING_KEYS` can retain older decrypt-only versions during rotation.
- `aws-kms`: an HSM-backed AWS KMS adapter using an authenticated KMS encryption context. On Vercel it obtains short-lived AWS credentials through OIDC and an environment-scoped IAM role instead of a permanent AWS access key.

For sensitive production use, configure `aws-kms`, restrict the IAM role to the exact KMS key, retain retired key versions until every package using them has been deleted or migrated, and monitor CloudTrail for unusual encrypt/decrypt activity. The default local provider is operationally simpler but does not provide the isolation or audit guarantees of an external HSM-backed KMS.

## Package boundary and data exposure

Protected plaintext and commitment nonces remain in the browser. During ordinary sealing and reveal, the service receives only the random document key, signed digests and identifiers, creator address, normalized policy, protected-key envelope, and wallet authorization. Public document wording and encrypted segments do not need to be sent to the key service.

When a user chooses **Hosted short link**, the complete signed encrypted package—including readable public wording, metadata, creator address, policy, ciphertext, commitments, and protected-key envelope—is sent to eCrypt’s private storage without an automatic expiration. Anyone with the unguessable short URL can retrieve that package until the creator deletes it, although creator or policy eligibility is still required to receive the document key.

The policy necessarily reveals wallet and contract addresses to the eCrypt service and its blockchain data provider during live eligibility checks. Clipboard managers, browsers, extensions, messaging services, recipients, and device backups may retain anything a user copies or reveals.

## Local development

Requirements:

- Node.js 22.13 or newer
- an Alchemy application key
- a 32-byte wrapping key and a separate 32-byte challenge secret

Install dependencies and prepare local environment values:

```bash
npm install
cp .env.example .env.local
openssl rand -base64 32
openssl rand -base64 32
```

Set `ECRYPT_MASTER_KEY`, `ECRYPT_CHALLENGE_SECRET`, `ECRYPT_ACTIVE_KEY_ID`, and `ALCHEMY_API_KEY`. Local development automatically uses in-process nonce and short-link stores; production fails closed unless durable private Blob storage is configured.

```bash
npm run dev
```

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the vinext development server |
| `npm run build` | Build the Cloudflare Worker-compatible output |
| `npm run build:vercel` | Build the production Next.js/Vercel output |
| `npm start` | Start the built vinext application |
| `npm test` | Build and run security, policy, UI-source, SEO, and repository checks |
| `npm run lint` | Run ESLint |

## Deployment

The public deployment uses Vercel and `npm run build:vercel`. Configure these encrypted server-side values:

- `ALCHEMY_API_KEY`
- `ECRYPT_CHALLENGE_SECRET`
- `BLOB_READ_WRITE_TOKEN`
- `CRON_SECRET`
- a wrapping provider and its key configuration

For the local wrapping provider, configure `ECRYPT_MASTER_KEY` and `ECRYPT_ACTIVE_KEY_ID`. For AWS KMS, configure `ECRYPT_KEY_WRAPPER=aws-kms`, `AWS_REGION`, `AWS_ROLE_ARN`, and `AWS_KMS_KEY_ID`, then establish the corresponding Vercel OIDC trust and least-privilege IAM policy.

Never expose server secrets through `NEXT_PUBLIC_` variables, client code, copied packages, or repository commits.

## Security and operational boundary

eCrypt is experimental cryptographic software and has not been independently audited. Do not use it for regulated, safety-critical, or high-value data without independent review.

- eCrypt is service-assisted rather than decentralized or zero-knowledge. The authorization service can unwrap document keys when its policy checks succeed.
- Compromise of the hosting account, wrapping provider, wallet, browser, extension, device, blockchain data provider, or recipient can affect confidentiality or availability.
- There is no recovery vault. Losing every complete package is permanent.
- Live eligibility depends on wallet providers, supported chains, token-contract behavior, and Alchemy availability.
- In-memory request throttling is best-effort; production should retain platform firewall and abuse controls.
- Version 2 deliberately provides no version-1 compatibility because the application had not yet been used when the security transition was made.

Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md). Do not disclose secrets or real encrypted documents in a public issue.

## Contributing

Issues and pull requests are welcome for reproducible bugs, accessibility improvements, documentation, and narrowly scoped features. Use synthetic documents and test wallets. Security findings must follow the private reporting process.

## License

eCrypt is available under the [MIT License](LICENSE).
