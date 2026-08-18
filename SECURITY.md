# Security Policy

## Supported versions

Security fixes are applied to the latest `main` branch and the production service at [ecrypt.bittrees.org](https://ecrypt.bittrees.org). Older commits, forks, and modified self-hosted deployments are not maintained by Bittrees Technology.

| Surface | Supported |
| --- | --- |
| Current production deployment | Yes |
| Latest `main` branch | Yes |
| Older commits or releases | No |
| Third-party forks or modified deployments | No |

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Use [GitHub private vulnerability reporting](https://github.com/Bittrees-Technology/ecrypt/security/advisories/new) so details remain confidential while they are investigated.

Please include:

- the affected URL, API route, commit, or component;
- the security impact and who could be affected;
- clear reproduction steps using synthetic data;
- a minimal proof of concept, if one is necessary;
- the wallet, browser, network, and token standard involved;
- any suggested remediation;
- confirmation that no unrelated user data was accessed or retained.

Do not include real decrypted documents, active unlock packages, wallet recovery phrases, private keys, API keys, or other secrets. Bittrees Technology aims to acknowledge a complete report within five business days. Investigation and remediation timelines depend on severity and reproducibility.

## In scope

- client-side encryption, decryption, integrity verification, and package parsing;
- whole-document creator signatures, canonical digests, and package-tampering detection;
- document-bound wallet challenges, one-time nonce consumption, and creator authorization;
- hosted short-link creation, private retrieval, persistent retention, and creator-authorized deletion;
- nonce-protected inline commitments and offline-guess resistance;
- versioned document-key wrapping, KMS encryption contexts, rotation, and unwrapping;
- wallet, ERC-20, ERC-721, and ERC-1155 eligibility checks;
- authorization bypasses, cross-origin request flaws, and policy tampering;
- secret exposure caused by the eCrypt application or its deployment configuration;
- the production service at `https://ecrypt.bittrees.org` and the code in this repository.

## Out of scope

- vulnerabilities in wallets, blockchains, token contracts, Alchemy, Vercel, or other third-party services that are not caused by eCrypt;
- reports that only identify an outdated dependency without a working impact path;
- loss of unlock data after every user-held copy and opt-in hosted short link has been deleted;
- social engineering, phishing, physical attacks, or compromised user devices;
- denial-of-service testing, automated high-volume scanning, or actions that degrade the production service;
- accessing, modifying, decrypting, or retaining data that does not belong to the researcher.

## Safe testing and disclosure

Use accounts, token contracts, and encrypted documents you control. Keep requests low volume, do not perform blockchain transactions on behalf of another person, and stop immediately if testing exposes unexpected data. Give Bittrees Technology a reasonable opportunity to investigate and remediate a confirmed issue before public disclosure.

This policy does not authorize access to another person’s data, disruption of the service, or activity against third-party systems.

## Important security boundary

eCrypt is experimental software and has not undergone an independent security audit. Version 2 encrypts protected plaintext and its commitment nonce in the browser, authenticates the complete readable document through the creator’s wallet signature, and rejects altered packages. Production wallet challenges are tied to one document and protected-key digest, expire after five minutes, and use an opaque create-once replay marker so their nonce cannot be accepted twice.

The service remains part of the trust boundary: it receives each random document key for wrapping and returns it after creator or live-policy authorization. When a user opts into a hosted short link, private Blob storage also receives the complete signed encrypted package, including readable public text and wallet policy. The deployed local provider uses a versioned `ECRYPT_MASTER_KEY`; the optional AWS KMS provider uses an HSM-backed key and authenticated encryption context through Vercel OIDC. Compromise of the hosting account, Blob store, active wrapping provider, authorization service, wallet, browser, extension, device, or recipient can affect confidentiality or availability.

Hosted short links do not expire automatically, so their complete signed encrypted packages remain in eCrypt’s private storage until creator-authorized deletion. Hosted-copy deletion removes eCrypt’s active private record and makes its identifier unavailable through the application. It cannot revoke copies already downloaded, cached, backed up, copied, or forwarded outside eCrypt. Do not describe hosted deletion as remote erasure of recipient-controlled copies.

Never delete a wrapping-key version while packages using its `keyId` may still need to open. Never place plaintext, raw wallet addresses, or raw policies in an AWS KMS encryption context or replay-marker pathname; KMS contexts are audit-logged. eCrypt uses only document, policy, author, and key commitments in that context. Review the [README](README.md#security-and-operational-boundary) before operating a deployment with sensitive data.

Version-1 packages are intentionally unsupported. This avoids preserving the former public-text authentication and offline-guessing weaknesses in a compatibility path.
