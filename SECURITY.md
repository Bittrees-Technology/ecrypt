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
- wallet-signature challenges and creator authorization;
- document-key wrapping and unwrapping;
- wallet, ERC-20, ERC-721, and ERC-1155 eligibility checks;
- authorization bypasses, cross-origin request flaws, and policy tampering;
- secret exposure caused by the eCrypt application or its deployment configuration;
- the production service at `https://ecrypt.bittrees.org` and the code in this repository.

## Out of scope

- vulnerabilities in wallets, blockchains, token contracts, Alchemy, Vercel, or other third-party services that are not caused by eCrypt;
- reports that only identify an outdated dependency without a working impact path;
- loss of unlock data, which is an intentional no-history/no-recovery design constraint;
- social engineering, phishing, physical attacks, or compromised user devices;
- denial-of-service testing, automated high-volume scanning, or actions that degrade the production service;
- accessing, modifying, decrypting, or retaining data that does not belong to the researcher.

## Safe testing and disclosure

Use accounts, token contracts, and encrypted documents you control. Keep requests low volume, do not perform blockchain transactions on behalf of another person, and stop immediately if testing exposes unexpected data. Give Bittrees Technology a reasonable opportunity to investigate and remediate a confirmed issue before public disclosure.

This policy does not authorize access to another person’s data, disruption of the service, or activity against third-party systems.

## Important security boundary

eCrypt is experimental software and has not undergone an independent security audit. Plaintext redactions are encrypted and decrypted in the browser, but the deployed service holds the server-side master key used to protect document keys. A compromise or rotation of `ECRYPT_MASTER_KEY` can affect the confidentiality or recoverability of encrypted packages. Review the [README](README.md#security-and-operational-boundary) before operating a deployment with sensitive data.
