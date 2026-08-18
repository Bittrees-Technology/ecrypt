"use client";

import {
  ArrowRight,
  BookOpen,
  Braces,
  Check,
  Copy,
  Download,
  Eye,
  ExternalLink,
  FileLock2,
  KeyRound,
  LogOut,
  LockKeyhole,
  Network,
  Plus,
  ShieldCheck,
  TriangleAlert,
  Trash2,
  Upload,
  Wallet,
} from "lucide-react";
import { type ChangeEvent, type ClipboardEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { getAddress, recoverMessageAddress } from "viem";
import {
  AccessPolicy,
  AccessRule,
  canonicalDocumentCore,
  canonicalPolicy,
  ChallengeBinding,
  DocumentSegment,
  EcryptDocumentCore,
  EcryptPackage,
  EncryptedSegment,
  isEcryptPackage,
  MatchMode,
  NETWORKS,
  NetworkKey,
  normalizePolicy,
  RuleKind,
  shortAddress,
  WrappedDocumentKey,
} from "../lib/ecrypt";

interface EthereumProvider {
  request<T = unknown>(request: { method: string; params?: unknown[] }): Promise<T>;
  on?(event: "chainChanged", listener: (chainId: unknown) => void): void;
  on?(event: "accountsChanged", listener: (accounts: unknown) => void): void;
  removeListener?(event: "chainChanged", listener: (chainId: unknown) => void): void;
  removeListener?(event: "accountsChanged", listener: (accounts: unknown) => void): void;
}

declare global {
  interface Window {
    ethereum?: EthereumProvider;
  }
}

type Mode = "compose" | "open" | "about";
type Notice = { tone: "error" | "success" | "info"; text: string } | null;
type PreviewMode = "continuous" | "pages";
type HostedShare = {
  id: string;
  url: string;
  deleteToken: string;
};
type PreviewPiece =
  | { key: string; kind: "public"; text: string }
  | { key: string; kind: "revealed"; text: string }
  | { key: string; kind: "redaction"; label: string; preview?: boolean };

const PREVIEW_PAGE_CHARACTER_LIMIT = 1_800;

const ADDABLE_WALLET_NETWORKS: Partial<Record<NetworkKey, {
  chainName: string;
  rpcUrls: string[];
  nativeCurrency: { name: string; symbol: string; decimals: number };
  blockExplorerUrls: string[];
}>> = {
  base: {
    chainName: "Base Mainnet",
    rpcUrls: ["https://mainnet.base.org"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://basescan.org"],
  },
  robinhood: {
    chainName: "Robinhood Chain",
    rpcUrls: ["https://rpc.mainnet.chain.robinhood.com"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://robinhoodchain.blockscout.com"],
  },
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const ECRYPT_DATA_BEGIN = "-----BEGIN ECRYPT UNLOCK DATA-----";
const ECRYPT_DATA_END = "-----END ECRYPT UNLOCK DATA-----";

function randomId(prefix: string) {
  return `${prefix}-${crypto.randomUUID().slice(0, 12)}`;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function concatBytes(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((length, value) => length + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

async function sha256Hex(value: Uint8Array | string): Promise<string> {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function documentCore(documentPackage: EcryptPackage): EcryptDocumentCore {
  return {
    version: 2,
    id: documentPackage.id,
    title: documentPackage.title,
    author: documentPackage.author,
    createdAt: documentPackage.createdAt,
    policy: documentPackage.policy,
    keyCommitment: documentPackage.keyCommitment,
    segments: documentPackage.segments,
  };
}

async function documentDigest(core: EcryptDocumentCore): Promise<string> {
  return sha256Hex(canonicalDocumentCore(core));
}

async function policyDigest(policy: AccessPolicy): Promise<string> {
  return sha256Hex(canonicalPolicy(policy));
}

async function wrappedKeyDigest(documentPackage: EcryptPackage): Promise<string> {
  return sha256Hex(JSON.stringify({
    provider: documentPackage.wrappedKey.provider,
    keyId: documentPackage.wrappedKey.keyId,
    ciphertext: documentPackage.wrappedKey.ciphertext,
  }));
}

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function textToHex(value: string): `0x${string}` {
  return `0x${Array.from(encoder.encode(value), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function providerErrorCode(error: unknown): number | undefined {
  if (!error || typeof error !== "object") return undefined;
  const direct = (error as { code?: unknown }).code;
  if (typeof direct === "number") return direct;
  const nested = (error as { data?: { originalError?: { code?: unknown } } }).data?.originalError?.code;
  return typeof nested === "number" ? nested : undefined;
}

function networkKeyFromChainId(value: unknown): NetworkKey | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const chainId = typeof value === "number"
    ? value
    : value.toLowerCase().startsWith("0x")
      ? Number.parseInt(value, 16)
      : Number.parseInt(value, 10);
  const match = (Object.entries(NETWORKS) as [NetworkKey, (typeof NETWORKS)[NetworkKey]][])
    .find(([, network]) => network.chainId === chainId);
  return match?.[0] ?? null;
}

function markedSegments(value: string) {
  const segments: Array<{ kind: "public" | "secret"; text: string }> = [];
  const pattern = /\[\[([\s\S]*?)\]\]/g;
  let cursor = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value))) {
    if (match.index > cursor) segments.push({ kind: "public", text: value.slice(cursor, match.index) });
    segments.push({ kind: "secret", text: match[1] });
    cursor = match.index + match[0].length;
  }
  if (cursor < value.length) segments.push({ kind: "public", text: value.slice(cursor) });
  return segments;
}

function takePreviewChunk(value: string, limit: number): [string, string] {
  const characters = Array.from(value);
  if (characters.length <= limit) return [value, ""];

  let cut = limit;
  const preferredFloor = Math.floor(limit * 0.6);
  for (let index = limit - 1; index >= preferredFloor; index -= 1) {
    if (/\s/.test(characters[index])) {
      cut = index + 1;
      break;
    }
  }
  return [characters.slice(0, cut).join(""), characters.slice(cut).join("")];
}

function paginatePreviewPieces(pieces: PreviewPiece[]): PreviewPiece[][] {
  const pages: PreviewPiece[][] = [[]];
  let usedCharacters = 0;

  function startPage() {
    pages.push([]);
    usedCharacters = 0;
  }

  for (const piece of pieces) {
    if (piece.kind === "redaction") {
      const displayLength = Math.max(24, Array.from(piece.label).length);
      if (usedCharacters > 0 && usedCharacters + displayLength > PREVIEW_PAGE_CHARACTER_LIMIT) {
        startPage();
      }
      pages[pages.length - 1].push(piece);
      usedCharacters += displayLength;
      continue;
    }

    let remaining = piece.text;
    let offset = 0;
    while (remaining) {
      let available = PREVIEW_PAGE_CHARACTER_LIMIT - usedCharacters;
      if (available < 160 && usedCharacters > 0) {
        startPage();
        available = PREVIEW_PAGE_CHARACTER_LIMIT;
      }
      const [chunk, rest] = takePreviewChunk(remaining, available);
      pages[pages.length - 1].push({
        ...piece,
        key: `${piece.key}-${offset}`,
        text: chunk,
      });
      usedCharacters += Array.from(chunk).length;
      offset += Array.from(chunk).length;
      remaining = rest;
      if (remaining) startPage();
    }
  }

  return pages;
}

function encodedPackage(documentPackage: EcryptPackage): string {
  return bytesToBase64Url(encoder.encode(JSON.stringify(documentPackage)));
}

function redactedPackageText(documentPackage: EcryptPackage): string {
  return documentPackage.segments
    .map((segment) =>
      segment.kind === "public" ? segment.text : `[sha256:${segment.commitment}]`,
    )
    .join("");
}

function unlockDataPackageText(documentPackage: EcryptPackage): string {
  return `${ECRYPT_DATA_BEGIN}\n${encodedPackage(documentPackage)}\n${ECRYPT_DATA_END}`;
}

function unlockablePackageText(documentPackage: EcryptPackage): string {
  return `${redactedPackageText(documentPackage)}\n\n${unlockDataPackageText(documentPackage)}`;
}

function decodePackage(input: string): EcryptPackage {
  if (input.length > 2_000_000) {
    throw new Error("This eCrypt text is too large to open safely.");
  }
  const trimmed = input.trim();
  let serialized = trimmed;
  const unlockDataStart = trimmed.indexOf(ECRYPT_DATA_BEGIN);
  if (unlockDataStart >= 0) {
    const dataStart = unlockDataStart + ECRYPT_DATA_BEGIN.length;
    const dataEnd = trimmed.indexOf(ECRYPT_DATA_END, dataStart);
    if (dataEnd < 0) throw new Error("The pasted unlock data is incomplete.");
    serialized = trimmed
      .slice(dataStart, dataEnd)
      .replace(/[\s\u00ad\u200b-\u200d\u2060\ufeff]/g, "");
  } else if (trimmed.includes("#ecrypt=")) {
    serialized = trimmed.split("#ecrypt=")[1];
  } else if (trimmed.includes("[sha256:")) {
    throw new Error("This is only the redacted message. Ask the sender to use “Copy all” or “Copy unlock hash only” so the encrypted passages travel with it.");
  }
  if (!serialized.startsWith("{")) {
    serialized = decoder.decode(base64UrlToBytes(serialized));
  }
  const parsed = JSON.parse(serialized) as unknown;
  if (!isEcryptPackage(parsed)) {
    if (parsed && typeof parsed === "object" && (parsed as { version?: unknown }).version === 1) {
      throw new Error("This version-1 package is no longer supported. Create a new version-2 document.");
    }
    throw new Error("This is not a valid eCrypt document package.");
  }
  parsed.policy = normalizePolicy(parsed.policy);
  return parsed;
}

async function verifyPackageAuthenticity(documentPackage: EcryptPackage): Promise<void> {
  const calculatedDocumentDigest = await documentDigest(documentCore(documentPackage));
  const calculatedPolicyDigest = await policyDigest(documentPackage.policy);
  if (
    calculatedDocumentDigest !== documentPackage.documentDigest ||
    calculatedPolicyDigest !== documentPackage.policyDigest
  ) {
    throw new Error("This package’s public text, metadata, or policy was changed after signing.");
  }
  const signedMessage = documentPackage.creatorProof.message;
  const requiredResources = [
    `Request ID: ${documentPackage.id}`,
    "- urn:ecrypt:action:seal",
    `- urn:ecrypt:document-digest:${documentPackage.documentDigest}`,
    `- urn:ecrypt:policy-digest:${documentPackage.policyDigest}`,
    `- urn:ecrypt:key-commitment:${documentPackage.keyCommitment}`,
  ];
  if (!requiredResources.every((resource) => signedMessage.includes(resource))) {
    throw new Error("This package is not bound to its creator’s document signature.");
  }
  const recovered = getAddress(await recoverMessageAddress({
    message: signedMessage,
    signature: documentPackage.creatorProof.signature,
  }));
  if (recovered !== getAddress(documentPackage.author)) {
    throw new Error("This package’s creator signature is invalid.");
  }
}

async function api<T>(path: string, body: unknown): Promise<T> {
  return requestJson<T>(path, "POST", body);
}

async function apiGet<T>(path: string): Promise<T> {
  return requestJson<T>(path, "GET");
}

async function apiDelete<T>(path: string, body: unknown): Promise<T> {
  return requestJson<T>(path, "DELETE", body);
}

async function requestJson<T>(path: string, method: "GET" | "POST" | "DELETE", body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    ...(body === undefined ? {} : {
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  });
  const raw = await response.text();
  if (!raw) {
    throw new Error("eCrypt received an empty server response. Please try again.");
  }
  let payload: T & { error?: string };
  try {
    payload = JSON.parse(raw) as T & { error?: string };
  } catch {
    throw new Error("eCrypt received an incomplete server response. Please try again.");
  }
  if (!response.ok) throw new Error(payload.error || "The request could not be completed.");
  return payload;
}

async function connectWallet(): Promise<string> {
  if (!window.ethereum) {
    throw new Error("Install or open an EVM-compatible wallet to continue.");
  }
  const accounts = await window.ethereum.request<string[]>({ method: "eth_requestAccounts" });
  if (!accounts[0]) throw new Error("No wallet account was selected.");
  return accounts[0];
}

async function signMessage(address: string, message: string): Promise<`0x${string}`> {
  if (!window.ethereum) throw new Error("A wallet connection is required.");
  try {
    return await window.ethereum.request<`0x${string}`>({
      method: "personal_sign",
      params: [textToHex(message), address],
    });
  } catch (error) {
    if (error instanceof Error && /reject|denied|cancel/i.test(error.message)) throw error;
    return window.ethereum.request<`0x${string}`>({
      method: "personal_sign",
      params: [message, address],
    });
  }
}

async function walletAuthorization(
  action: "seal" | "unlock" | "delete",
  wallet: string,
  binding: ChallengeBinding,
) {
  if (!window.ethereum) throw new Error("A wallet connection is required.");
  const chainValue = await window.ethereum.request<string>({ method: "eth_chainId" });
  const chainId = Number.parseInt(chainValue, 16);
  if (!Number.isSafeInteger(chainId) || chainId < 1) {
    throw new Error("The wallet reported an invalid network.");
  }
  const challenge = await api<{ message: string }>("/api/challenge", {
    action,
    address: wallet,
    chainId,
    binding,
  });
  const signature = await signMessage(wallet, challenge.message);
  return { message: challenge.message, signature };
}

async function encryptSecret(text: string, key: CryptoKey, index: number): Promise<EncryptedSegment> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const commitmentNonce = crypto.getRandomValues(new Uint8Array(32));
  const plaintext = encoder.encode(text);
  const commitment = await sha256Hex(concatBytes(
    encoder.encode("ecrypt:v2:commitment\0"),
    commitmentNonce,
    plaintext,
  ));
  const envelope = encoder.encode(JSON.stringify({
    text,
    commitmentNonce: bytesToBase64Url(commitmentNonce),
  }));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(iv),
        additionalData: asArrayBuffer(encoder.encode(`ecrypt:v2:${index}:${commitment}`)),
      },
      key,
      asArrayBuffer(envelope),
    ),
  );
  return {
    kind: "encrypted",
    ciphertext: bytesToBase64Url(ciphertext),
    iv: bytesToBase64Url(iv),
    commitment,
  };
}

async function decryptSecret(segment: EncryptedSegment, key: CryptoKey, index: number) {
  const plaintextEnvelope = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(base64UrlToBytes(segment.iv)),
        additionalData: asArrayBuffer(encoder.encode(`ecrypt:v2:${index}:${segment.commitment}`)),
      },
      key,
      asArrayBuffer(base64UrlToBytes(segment.ciphertext)),
    ),
  );
  let envelope: { text?: unknown; commitmentNonce?: unknown };
  try {
    envelope = JSON.parse(decoder.decode(plaintextEnvelope));
  } catch {
    throw new Error("A redacted passage contained invalid encrypted data.");
  }
  if (typeof envelope.text !== "string" || typeof envelope.commitmentNonce !== "string") {
    throw new Error("A redacted passage contained invalid encrypted data.");
  }
  const nonce = base64UrlToBytes(envelope.commitmentNonce);
  if (nonce.length !== 32) throw new Error("A redacted passage contained an invalid commitment nonce.");
  const commitment = await sha256Hex(concatBytes(
    encoder.encode("ecrypt:v2:commitment\0"),
    nonce,
    encoder.encode(envelope.text),
  ));
  if (commitment !== segment.commitment) {
    throw new Error("A redacted passage did not pass its integrity check.");
  }
  return envelope.text;
}

function downloadPackage(documentPackage: EcryptPackage) {
  const blob = new Blob([JSON.stringify(documentPackage, null, 2)], {
    type: "application/ecrypt+json",
  });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${documentPackage.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "document"}.ecrypt.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function explorerAddressUrl(address: string, network: NetworkKey = "ethereum") {
  return `${NETWORKS[network].explorer}/address/${address}`;
}

function ExplorerAddress({
  address,
  network = "ethereum",
  prefix = "",
  suffix = "",
}: {
  address: string;
  network?: NetworkKey;
  prefix?: string;
  suffix?: string;
}) {
  return (
    <a
      className="explorer-address"
      href={explorerAddressUrl(address, network)}
      target="_blank"
      rel="noreferrer"
      aria-label={`View ${address} on the ${NETWORKS[network].label} block explorer`}
      title={`View on ${NETWORKS[network].label} explorer`}
    >
      <code>{prefix}{shortAddress(address)}{suffix}</code>
      <ExternalLink size={11} aria-hidden="true" />
    </a>
  );
}

function PreviewPieces({ pieces }: { pieces: PreviewPiece[] }) {
  return pieces.map((piece) => {
    if (piece.kind === "public") return <span key={piece.key}>{piece.text}</span>;
    if (piece.kind === "revealed") {
      return <mark className="revealed-passage" key={piece.key}>{piece.text}</mark>;
    }
    return (
      <span
        className={`redaction${piece.preview ? " preview-redaction" : ""}`}
        key={piece.key}
        title={piece.preview ? "Passage marked for encryption" : "Encrypted redaction"}
      >
        <LockKeyhole size={12} aria-hidden="true" /> {piece.label}
      </span>
    );
  });
}

function DocumentPreview({
  ariaLabel,
  metaLeft,
  metaRight,
  title,
  pieces,
  emptyMessage,
  signature,
}: {
  ariaLabel: string;
  metaLeft: string;
  metaRight: string;
  title?: string;
  pieces: PreviewPiece[];
  emptyMessage?: string;
  signature?: ReactNode;
}) {
  const previewRef = useRef<HTMLDivElement>(null);
  const [previewMode, setPreviewMode] = useState<PreviewMode>("continuous");
  const [page, setPage] = useState(0);
  const pages = paginatePreviewPieces(pieces);
  const hasMultiplePages = pages.length > 1;
  const safePage = Math.min(page, pages.length - 1);
  const pagePieces = previewMode === "pages" && hasMultiplePages ? pages[safePage] : pieces;

  function selectPage(nextPage: number) {
    setPage(Math.max(0, Math.min(nextPage, pages.length - 1)));
    requestAnimationFrame(() => previewRef.current?.scrollIntoView({ block: "start" }));
  }

  return (
    <div className="document-preview" ref={previewRef}>
      {hasMultiplePages && (
        <div className="preview-mode-bar">
          <span>Preview view</span>
          <div role="group" aria-label="Preview display mode">
            <button
              className={previewMode === "continuous" ? "active" : ""}
              type="button"
              aria-pressed={previewMode === "continuous"}
              onClick={() => setPreviewMode("continuous")}
            >
              Continuous
            </button>
            <button
              className={previewMode === "pages" ? "active" : ""}
              type="button"
              aria-pressed={previewMode === "pages"}
              onClick={() => { setPreviewMode("pages"); setPage(0); }}
            >
              Pages
            </button>
          </div>
        </div>
      )}

      <article
        className={`document-paper${previewMode === "pages" && hasMultiplePages ? " document-paper-paged" : ""}`}
        aria-label={ariaLabel}
      >
        <div className="paper-meta">
          <span>{metaLeft}</span>
          <span>{metaRight}</span>
        </div>
        {title?.trim() && <h3>{title}</h3>}
        <div className="document-copy">
          {pieces.length ? <PreviewPieces pieces={pagePieces} /> : <span className="empty-copy">{emptyMessage}</span>}
        </div>
        {signature}
        {previewMode === "pages" && hasMultiplePages && (
          <span className="paper-page-number">Page {safePage + 1} of {pages.length}</span>
        )}
      </article>

      {previewMode === "pages" && hasMultiplePages && (
        <nav className="preview-pagination" aria-label="Document preview pages">
          <button type="button" onClick={() => selectPage(0)} disabled={safePage === 0}>First</button>
          <button type="button" onClick={() => selectPage(safePage - 1)} disabled={safePage === 0}>Previous</button>
          <span aria-live="polite">Page {safePage + 1} of {pages.length}</span>
          <button type="button" onClick={() => selectPage(safePage + 1)} disabled={safePage === pages.length - 1}>Next</button>
          <button type="button" onClick={() => selectPage(pages.length - 1)} disabled={safePage === pages.length - 1}>Last</button>
        </nav>
      )}
    </div>
  );
}

function RedactedDocument({
  documentPackage,
  revealed,
}: {
  documentPackage: EcryptPackage;
  revealed: Record<number, string>;
}) {
  const pieces: PreviewPiece[] = documentPackage.segments.map((segment, index) => {
    if (segment.kind === "public") {
      return { key: `${index}-public`, kind: "public", text: segment.text };
    }
    const plaintext = revealed[index];
    return plaintext
      ? { key: `${index}-revealed`, kind: "revealed", text: plaintext }
      : { key: `${index}-redacted`, kind: "redaction", label: `sha256:${segment.commitment.slice(0, 12)}` };
  });
  return (
    <DocumentPreview
      ariaLabel={documentPackage.title ? `${documentPackage.title} encrypted document` : "Encrypted document"}
      metaLeft="eCrypt protected text"
      metaRight={new Date(documentPackage.createdAt).toLocaleDateString()}
      title={documentPackage.title}
      pieces={pieces}
      signature={<div className="paper-signature">
        <span>Protected by</span>
        <ExplorerAddress address={documentPackage.author} />
      </div>}
    />
  );
}

function DraftPreview({ value, title }: { value: string; title: string }) {
  const segments = markedSegments(value);
  const pieces: PreviewPiece[] = segments.map((segment, index) =>
    segment.kind === "secret"
      ? { key: `${index}-secret`, kind: "redaction", label: "encrypt on seal", preview: true }
      : { key: `${index}-public`, kind: "public", text: segment.text },
  );
  return (
    <DocumentPreview
      ariaLabel="Redaction preview"
      metaLeft="Live redaction preview"
      metaRight="Draft"
      title={title}
      pieces={pieces}
      emptyMessage="Write something, then select text to redact it."
    />
  );
}

function AboutPanel() {
  return (
    <section
      className="about-panel"
      id="about-panel"
      role="tabpanel"
      aria-labelledby="about-tab"
      tabIndex={0}
    >
      <header className="about-intro">
        <div>
          <span className="eyebrow">Protocol / current build</span>
          <h2>A readable document with encrypted holes.</h2>
        </div>
        <p>
          eCrypt leaves ordinary text readable and encrypts only the passages you mark. The result can travel through email, chat, a document, a share link, or a saved package. The creator wallet or a wallet that satisfies the signed access policy can reveal the protected passages later without writing a transaction to a blockchain.
        </p>
        <div className="about-facts" aria-label="eCrypt at a glance">
          <div><strong>03</strong><span>supported networks</span></div>
          <div><strong>04</strong><span>access-rule types</span></div>
          <div><strong>00</strong><span>onchain writes</span></div>
        </div>
      </header>

      <section className="about-flow" aria-labelledby="about-flow-title">
        <div className="about-section-heading">
          <span className="eyebrow">Create to reveal</span>
          <h3 id="about-flow-title">How one message moves through eCrypt</h3>
        </div>
        <div className="about-flow-grid">
          <article>
            <span>01 / Mark</span>
            <h4>Choose the private passages</h4>
            <p>Write or paste the document, then select text or wrap it in <code>[[double brackets]]</code>. Everything outside those markers remains public.</p>
          </article>
          <article>
            <span>02 / Encrypt</span>
            <h4>Seal them in the browser</h4>
            <p>Your browser creates a random 256-bit document key. Each passage receives a secret commitment nonce that is encrypted with the text, while a nonce-protected SHA-256 commitment replaces it inline.</p>
          </article>
          <article>
            <span>03 / Carry</span>
            <h4>Keep the complete package</h4>
            <p>The portable version-2 package carries the signed public text and metadata, ciphertext, commitments, creator proof, access policy, and a versioned protected key. Copy all, unlock data, JSON, and either link type carry this package; redacted-message-only text does not.</p>
          </article>
          <article>
            <span>04 / Reveal</span>
            <h4>Prove access, then decrypt</h4>
            <p>The connected wallet signs a five-minute authorization bound to this exact package. Its nonce is accepted once; eCrypt recognizes the creator or checks the live policy, returns the key when authorized, and the browser verifies every passage.</p>
          </article>
        </div>
      </section>

      <div className="about-detail-grid">
        <section className="about-card" aria-labelledby="about-crypto-title">
          <span className="eyebrow">Protection layers</span>
          <h3 id="about-crypto-title">What each technology does</h3>
          <dl className="about-definition-list">
            <div><dt>AES-256-GCM</dt><dd>Encrypts each private passage and detects ciphertext tampering. This is what provides confidentiality.</dd></div>
            <div><dt>Nonce-protected SHA-256</dt><dd>Creates the public inline commitment. Its random verification nonce stays inside the ciphertext, preventing package holders from testing predictable guesses offline.</dd></div>
            <div><dt>Wallet signatures</dt><dd>The creator signature remains the package’s authenticity proof. Separate reveal and hosted-copy deletion authorizations last five minutes, name the exact target, and cannot be replayed after use.</dd></div>
            <div><dt>Authenticated key wrapping</dt><dd>Binds the protected document key to the signed document, policy, creator, and key commitment under an identified wrapping-key version.</dd></div>
            <div><dt>Live chain reads</dt><dd>Check the wallet’s current token or NFT eligibility on Ethereum, Base, or Robinhood when the reader asks to reveal.</dd></div>
          </dl>
        </section>

        <section className="about-card" aria-labelledby="about-policy-title">
          <span className="eyebrow">Access policy</span>
          <h3 id="about-policy-title">Who can reveal a message</h3>
          <p>Up to five rules can be combined so that <strong>any</strong> rule or <strong>all</strong> rules must match. Eligibility is evaluated when the document is opened, so transferring a token can change access.</p>
          <ul className="about-rule-list">
            <li><strong>Specific wallet</strong><span>One named EVM address.</span></li>
            <li><strong>ERC-20</strong><span>A minimum token balance.</span></li>
            <li><strong>ERC-721</strong><span>Any NFT from a contract, or one optional token ID.</span></li>
            <li><strong>ERC-1155</strong><span>One optional token ID or any single qualifying ID from a contract. The whole-number minimum is checked per ID, not summed across IDs.</span></li>
          </ul>
          <div className="about-callout"><Wallet size={17} aria-hidden="true" /><p><strong>Creator access is built in.</strong> The wallet that creates the package can decrypt it without satisfying the reader policy. On a hosted link, creator-deletion controls appear only while that creator wallet is connected.</p></div>
        </section>
      </div>

      <section className="about-formats" aria-labelledby="about-formats-title">
        <div className="about-section-heading">
          <span className="eyebrow">Portable formats</span>
          <h3 id="about-formats-title">What to copy or save</h3>
        </div>
        <div className="about-format-grid">
          <article><span>Recommended</span><h4>Copy all</h4><p>The readable redacted message and complete unlock-data block together. Manual copy and paste works across applications when the full block stays intact.</p></article>
          <article><span>Public display</span><h4>Redacted message only</h4><p>Public text and inline SHA-256 commitments. It is easy to share, but contains no ciphertext or protected key and cannot be decrypted by itself.</p></article>
          <article><span>Compact carrier</span><h4>Unlock data only</h4><p>Despite the button’s “unlock hash” label, this is the complete encoded encrypted package—not merely a hash. It is enough to begin an authorized reveal.</p></article>
          <article><span>Files and links</span><h4>JSON, full link, or short link</h4><p>JSON can be uploaded later. The full link keeps data in its URL but can be truncated by other apps. An opt-in short link stores the package with no automatic expiration until creator deletion.</p></article>
        </div>
      </section>

      <div className="about-detail-grid about-privacy-grid">
        <section className="about-card" aria-labelledby="about-data-title">
          <span className="eyebrow">Data boundaries</span>
          <h3 id="about-data-title">What reaches the eCrypt service</h3>
          <ul className="about-bullet-list">
            <li><strong>Redacted plaintext does not.</strong> Protected passages and their commitment nonces are encrypted and decrypted in the browser.</li>
            <li><strong>A random document key does.</strong> eCrypt receives it over HTTPS to bind it to the creator and policy, then returns it only after an authorized reveal.</li>
            <li><strong>Policy checks disclose context.</strong> Wallet, contract, network, and balance queries are sent to eCrypt’s blockchain data provider when eligibility is checked.</li>
            <li><strong>The package is visible to its holder.</strong> It exposes signed public text, ciphertext, commitments, metadata, creator, and policy—but not redacted text or commitment nonces.</li>
            <li><strong>Hosted short links are opt-in persistent storage.</strong> Creating one sends that complete package to eCrypt’s private storage with no automatic expiration. Anyone with the random link can retrieve the package and attempt wallet-gated reveal until the creator deletes it.</li>
            <li><strong>Replay markers are temporary security data.</strong> eCrypt records random one-time challenge identifiers without document or wallet contents so the same authorization cannot be reused.</li>
          </ul>
        </section>

        <section className="about-card" aria-labelledby="about-cost-title">
          <span className="eyebrow">Networks / cost</span>
          <h3 id="about-cost-title">Gasless by default</h3>
          <p>Creating, revealing, and creator deletion use wallet signatures and read-only blockchain calls. The current build does not publish the document or its hash onchain, so these flows have no gas fee. Your wallet may still ask permission to connect, sign, add a network, or switch networks.</p>
          <div className="about-network-row" aria-label="Supported networks">
            <span>Ethereum</span><span>Base</span><span>Robinhood</span>
          </div>
          <p className="about-small-copy">eCrypt is service-assisted rather than fully decentralized: protected keys use versioned server-side wrapping and still depend on eCrypt’s authorization service being available.</p>
        </section>
      </div>

      <section className="about-warning" aria-labelledby="about-warning-title">
        <TriangleAlert size={24} aria-hidden="true" />
        <div>
          <span className="eyebrow">Important limits</span>
          <h3 id="about-warning-title">Encryption cannot correct an unsafe sharing decision.</h3>
          <ul>
            <li>Anyone with the complete package can attempt the unlock process, but only the creator or a currently eligible wallet should receive the key.</li>
            <li>There is no account history or recovery vault. A hosted short link is an opt-in persistent copy, not a wallet-synced archive; it has no automatic expiration, and once it is deleted eCrypt cannot recover it.</li>
            <li>Creator deletion removes eCrypt’s hosted copy, but cannot recall packages another person already copied, downloaded, cached, or forwarded.</li>
            <li>The secret commitment nonce is encrypted with each passage, so a package holder cannot test predictable plaintext guesses against the visible SHA-256 commitment.</li>
            <li>Changing the title, public wording, metadata, policy, ciphertext, or commitments invalidates the signed document and eCrypt rejects it before reveal.</li>
            <li>A compromised wallet, browser, extension, clipboard, device, or recipient can expose revealed text.</li>
            <li>This is experimental software and has not been presented as independently audited or post-quantum secure.</li>
          </ul>
        </div>
      </section>

      <section className="about-faq" aria-labelledby="about-faq-title">
        <div className="about-section-heading">
          <span className="eyebrow">Quick answers</span>
          <h3 id="about-faq-title">Common questions</h3>
        </div>
        <div className="about-faq-list">
          <details><summary>Can someone decrypt just because they have the unlock data?</summary><p>No. The unlock data lets them begin the process. They still need the creator wallet or a wallet that currently satisfies the package’s policy.</p></details>
          <details><summary>Does eCrypt save my document or a history?</summary><p>eCrypt does not create an account history or recovery vault. It stores a complete signed encrypted package only when someone explicitly chooses Hosted short link. That copy has no automatic expiration and remains until its creator deletes it; all other formats remain user-held.</p></details>
          <details><summary>Can the creator delete a hosted message?</summary><p>Yes. Open the hosted short link and connect its creator wallet. Only then does eCrypt show the Creator deletion section. Its gasless signature is bound to the exact document and short-link identifier. Deletion removes eCrypt’s hosted copy, but cannot erase copies already saved or forwarded elsewhere.</p></details>
          <details><summary>Why do deletion controls appear or disappear?</summary><p>They are shown only when the connected account matches the signed creator address. Switching wallet accounts updates the controls immediately. Disconnecting or changing accounts also hides any revealed plaintext from the current view.</p></details>
          <details><summary>Does a reader need to pay gas?</summary><p>No. The wallet signs a message and eCrypt makes read-only ownership checks. There is no blockchain transaction in the standard create or reveal flow.</p></details>
          <details><summary>Is the visible SHA-256 value the encrypted text?</summary><p>No. It is a nonce-protected commitment. The protected text and the random nonce required to test that commitment are both inside authenticated AES ciphertext.</p></details>
          <details><summary>Can someone change the readable public wording?</summary><p>They can edit a copied string, but eCrypt recomputes the complete document digest and verifies the creator’s wallet signature. An altered package is rejected before reveal.</p></details>
          <details><summary>Is eCrypt quantum-safe?</summary><p>No post-quantum claim is made. AES-256 has a substantial security margin, but ordinary EVM wallet signatures are not post-quantum cryptography.</p></details>
        </div>
      </section>
    </section>
  );
}

export default function EcryptApp() {
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const packageFileRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<Mode>("compose");
  const [wallet, setWallet] = useState("");
  const [walletNetwork, setWalletNetwork] = useState<NetworkKey | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [matchMode, setMatchMode] = useState<MatchMode>("any");
  const [rules, setRules] = useState<AccessRule[]>([
    { id: "rule-wallet", kind: "wallet", address: "" },
  ]);
  const [busy, setBusy] = useState<"seal" | "unlock" | "delete" | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [sealedPackage, setSealedPackage] = useState<EcryptPackage | null>(null);
  const [openedPackage, setOpenedPackage] = useState<EcryptPackage | null>(null);
  const [openedShareId, setOpenedShareId] = useState<string | null>(null);
  const [packageInput, setPackageInput] = useState("");
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const [copied, setCopied] = useState<"all" | "redacted" | "unlock" | "link" | "short" | null>(null);
  const [hostedShare, setHostedShare] = useState<HostedShare | null>(null);
  const [shareBusy, setShareBusy] = useState<"create" | "delete" | null>(null);
  const creatorWalletConnected = Boolean(
    wallet && openedPackage && wallet.toLowerCase() === openedPackage.author.toLowerCase(),
  );

  const selfContainedShareUrl = useMemo(() => {
    if (!sealedPackage || typeof window === "undefined") return "";
    return `${window.location.origin}/#ecrypt=${encodedPackage(sealedPackage)}`;
  }, [sealedPackage]);

  const redactedText = useMemo(() => {
    return sealedPackage ? redactedPackageText(sealedPackage) : "";
  }, [sealedPackage]);

  const unlockableText = useMemo(() => {
    return sealedPackage ? unlockablePackageText(sealedPackage) : "";
  }, [sealedPackage]);

  const unlockDataText = useMemo(() => {
    return sealedPackage ? unlockDataPackageText(sealedPackage) : "";
  }, [sealedPackage]);

  useEffect(() => {
    const encoded = window.location.hash.startsWith("#ecrypt=")
      ? window.location.hash.slice("#ecrypt=".length)
      : "";
    const shareId = window.location.hash.startsWith("#share=")
      ? window.location.hash.slice("#share=".length)
      : "";
    if (!encoded && !shareId) return;
    const timer = window.setTimeout(() => void (async () => {
      try {
        const loaded = shareId
          ? (await apiGet<{ document: EcryptPackage }>(`/api/share/${encodeURIComponent(shareId)}`)).document
          : decodePackage(encoded);
        await verifyPackageAuthenticity(loaded);
        setOpenedPackage(loaded);
        setOpenedShareId(shareId || null);
        setMode("open");
        setNotice({
          tone: "info",
          text: shareId
            ? "Hosted package retrieved and creator signature verified. Connect an eligible wallet to reveal the redactions."
            : "Signed package verified. Connect an eligible wallet to reveal the redactions.",
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "The encrypted document link is incomplete or invalid.";
        setNotice({
          tone: "error",
          text: /Unexpected (?:end|EOF)|JSON Parse/i.test(message)
            ? "This self-contained link was truncated. Ask the sender for a short link, Copy all, the unlock-data block, or the saved package."
            : message,
        });
      }
    })(), 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    const provider = window.ethereum;
    if (!wallet || !provider) return;

    const handleChainChanged = (chainId: unknown) => {
      setWalletNetwork(networkKeyFromChainId(chainId));
    };
    const handleAccountsChanged = (accounts: unknown) => {
      const nextWallet = Array.isArray(accounts) && typeof accounts[0] === "string" ? accounts[0] : "";
      setWallet(nextWallet);
      setRevealed({});
      if (!nextWallet) setWalletNetwork(null);
    };

    void provider.request<string>({ method: "eth_chainId" })
      .then(handleChainChanged)
      .catch(() => setWalletNetwork(null));
    provider.on?.("chainChanged", handleChainChanged);
    provider.on?.("accountsChanged", handleAccountsChanged);
    return () => {
      provider.removeListener?.("chainChanged", handleChainChanged);
      provider.removeListener?.("accountsChanged", handleAccountsChanged);
    };
  }, [wallet]);

  async function ensureWallet() {
    if (wallet) return wallet;
    const address = await connectWallet();
    setWallet(address);
    setRules((current) =>
      current.map((rule, index) =>
        index === 0 && rule.kind === "wallet" && !rule.address
          ? { ...rule, address }
          : rule,
      ),
    );
    return address;
  }

  async function handleConnect() {
    try {
      const address = await ensureWallet();
      setNotice({ tone: "success", text: `Wallet ${shortAddress(address)} connected.` });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "Wallet connection failed." });
    }
  }

  async function handleWalletAction() {
    if (!wallet) {
      await handleConnect();
      return;
    }
    setWallet("");
    setWalletNetwork(null);
    setRevealed({});
    setNotice({ tone: "info", text: "Wallet disconnected from eCrypt and revealed text was hidden. Your wallet app may still list this site as approved." });
  }

  function redactSelection() {
    const editor = editorRef.current;
    if (!editor || editor.selectionStart === editor.selectionEnd) {
      setNotice({ tone: "info", text: "Select a passage in the document first, then choose Redact selection." });
      editor?.focus();
      return;
    }
    const start = editor.selectionStart;
    const end = editor.selectionEnd;
    const selected = body.slice(start, end);
    if (selected.includes("[[") || selected.includes("]]")) {
      setNotice({ tone: "error", text: "That selection already contains a redaction marker." });
      return;
    }
    const next = `${body.slice(0, start)}[[${selected}]]${body.slice(end)}`;
    setBody(next);
    setNotice({ tone: "success", text: "Passage marked for encryption." });
    requestAnimationFrame(() => {
      editor.focus();
      editor.setSelectionRange(start + 2, end + 2);
    });
  }

  function updateRule(id: string, update: Partial<AccessRule>) {
    setRules((current) => current.map((rule) => (rule.id === id ? { ...rule, ...update } : rule)));
  }

  async function switchWalletNetwork(networkKey: NetworkKey, selectedForCondition = false) {
    const network = NETWORKS[networkKey];
    try {
      await ensureWallet();
    } catch (error) {
      setNotice({
        tone: "error",
        text: error instanceof Error ? error.message : `Connect a wallet to switch to ${network.label}.`,
      });
      return false;
    }
    if (!window.ethereum) {
      setNotice({ tone: "error", text: `The connected wallet could not switch to ${network.label}.` });
      return false;
    }

    const chainId = `0x${network.chainId.toString(16)}`;
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId }],
      });
      setWalletNetwork(networkKey);
      setNotice({ tone: "success", text: `Wallet switched to ${network.label}.` });
      return true;
    } catch (switchError) {
      const addableNetwork = ADDABLE_WALLET_NETWORKS[networkKey];
      if (providerErrorCode(switchError) === 4902 && addableNetwork) {
        try {
          await window.ethereum.request({
            method: "wallet_addEthereumChain",
            params: [{ chainId, ...addableNetwork }],
          });
          await window.ethereum.request({
            method: "wallet_switchEthereumChain",
            params: [{ chainId }],
          });
          setWalletNetwork(networkKey);
          setNotice({ tone: "success", text: `${network.label} was added and selected in your wallet.` });
          return true;
        } catch (addError) {
          const rejected = providerErrorCode(addError) === 4001 || (addError instanceof Error && /reject|denied|cancel/i.test(addError.message));
          setNotice({
            tone: rejected ? "info" : "error",
            text: rejected
              ? `${selectedForCondition ? `${network.label} is selected for this condition, but ` : ""}the wallet network change was canceled.`
              : `${selectedForCondition ? `${network.label} is selected for this condition, but ` : ""}the wallet could not add or switch to ${network.label}.`,
          });
          return false;
        }
      }

      const rejected = providerErrorCode(switchError) === 4001 || (switchError instanceof Error && /reject|denied|cancel/i.test(switchError.message));
      setNotice({
        tone: rejected ? "info" : "error",
        text: rejected
          ? `${selectedForCondition ? `${network.label} is selected for this condition, but ` : ""}the wallet network change was canceled.`
          : `${selectedForCondition ? `${network.label} is selected for this condition, but ` : ""}this wallet could not switch to ${network.label} automatically.`,
      });
      return false;
    }
  }

  async function selectRuleNetwork(id: string, networkKey: NetworkKey) {
    updateRule(id, { network: networkKey });
    await switchWalletNetwork(networkKey, true);
  }

  function changeRuleKind(id: string, kind: RuleKind) {
    setRules((current) =>
      current.map((rule) => {
        if (rule.id !== id) return rule;
        if (kind === "wallet") return { id, kind, address: wallet || "" };
        if (kind === "erc721") return { id, kind, network: "ethereum", contract: "", tokenId: "" };
        if (kind === "erc1155") {
          return { id, kind, network: "ethereum", contract: "", tokenId: "", minimum: "1" };
        }
        return { id, kind, network: "ethereum", contract: "", minimum: "1" };
      }),
    );
  }

  function addRule() {
    if (rules.length >= 5) {
      setNotice({ tone: "info", text: "A document can have up to five access conditions." });
      return;
    }
    setRules((current) => [
      ...current,
      { id: randomId("rule"), kind: "erc20", network: "ethereum", contract: "", minimum: "1" },
    ]);
  }

  async function sealDocument() {
    setNotice(null);
    const marked = markedSegments(body);
    if (!marked.some((segment) => segment.kind === "secret")) {
      setNotice({ tone: "error", text: "Mark at least one passage for encryption." });
      return;
    }

    let policy: AccessPolicy;
    try {
      policy = normalizePolicy({ mode: matchMode, rules });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The access policy is invalid." });
      return;
    }

    setBusy("seal");
    try {
      const address = getAddress(await ensureWallet());
      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      const key = await crypto.subtle.importKey(
        "raw",
        asArrayBuffer(rawKey),
        "AES-GCM",
        false,
        ["encrypt"],
      );
      const segments: DocumentSegment[] = [];
      for (const segment of marked) {
        const index = segments.length;
        segments.push(
          segment.kind === "secret"
            ? await encryptSecret(segment.text, key, index)
            : { kind: "public", text: segment.text },
        );
      }
      const core: EcryptDocumentCore = {
        version: 2,
        id: randomId("doc"),
        title: title.trim().slice(0, 160),
        author: address,
        createdAt: new Date().toISOString(),
        policy,
        keyCommitment: await sha256Hex(rawKey),
        segments,
      };
      const calculatedDocumentDigest = await documentDigest(core);
      const calculatedPolicyDigest = await policyDigest(policy);
      const binding: ChallengeBinding = {
        action: "seal",
        documentId: core.id,
        documentDigest: calculatedDocumentDigest,
        policyDigest: calculatedPolicyDigest,
        keyCommitment: core.keyCommitment,
      };
      const authorization = await walletAuthorization("seal", address, binding);
      const wrapped = await api<{
        wrappedKey: WrappedDocumentKey;
        policy: AccessPolicy;
        author: string;
        documentDigest: string;
        policyDigest: string;
      }>("/api/wrap", {
        key: bytesToBase64Url(rawKey),
        documentId: core.id,
        documentDigest: calculatedDocumentDigest,
        policyDigest: calculatedPolicyDigest,
        keyCommitment: core.keyCommitment,
        author: core.author,
        policy: core.policy,
        ...authorization,
      });
      const documentPackage: EcryptPackage = {
        ...core,
        author: wrapped.author,
        policy: wrapped.policy,
        documentDigest: wrapped.documentDigest,
        policyDigest: wrapped.policyDigest,
        wrappedKey: wrapped.wrappedKey,
        creatorProof: authorization,
      };
      await verifyPackageAuthenticity(documentPackage);
      setSealedPackage(documentPackage);
      setHostedShare(null);
      setRevealed({});
      setNotice({ tone: "success", text: "Redacted text is ready. Use Copy all for a self-contained message, or choose one of the separate formats below." });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The document could not be sealed." });
    } finally {
      setBusy(null);
    }
  }

  async function copyShareLink() {
    try {
      await navigator.clipboard.writeText(selfContainedShareUrl);
      setCopied("link");
      window.setTimeout(() => setCopied((current) => (current === "link" ? null : current)), 1800);
    } catch {
      setNotice({ tone: "error", text: "The share link could not be copied. You can select it manually." });
    }
  }

  async function createShortLink() {
    if (!sealedPackage) return;
    setShareBusy("create");
    setNotice(null);
    try {
      const created = await api<{ id: string; deleteToken: string }>("/api/share", {
        document: sealedPackage,
      });
      const next: HostedShare = {
        ...created,
        url: `${window.location.origin}/#share=${created.id}`,
      };
      window.localStorage.setItem(`ecrypt:share-delete:${created.id}`, created.deleteToken);
      setHostedShare(next);
      setNotice({
        tone: "success",
        text: "Short link created. It will remain available until the document creator deletes the hosted copy.",
      });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The short link could not be created." });
    } finally {
      setShareBusy(null);
    }
  }

  async function copyShortLink() {
    if (!hostedShare) return;
    try {
      await navigator.clipboard.writeText(hostedShare.url);
      setCopied("short");
      window.setTimeout(() => setCopied((current) => (current === "short" ? null : current)), 1800);
    } catch {
      setNotice({ tone: "error", text: "The short link could not be copied automatically. You can select it manually." });
    }
  }

  async function deleteShortLink() {
    if (!hostedShare) return;
    setShareBusy("delete");
    setNotice(null);
    try {
      await apiDelete<{ deleted: true }>(`/api/share/${encodeURIComponent(hostedShare.id)}`, {
        deleteToken: hostedShare.deleteToken,
      });
      window.localStorage.removeItem(`ecrypt:share-delete:${hostedShare.id}`);
      setHostedShare(null);
      setNotice({ tone: "success", text: "The hosted package was deleted. Its short link no longer works." });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The short link could not be deleted." });
    } finally {
      setShareBusy(null);
    }
  }

  async function creatorDeleteHostedMessage() {
    if (!openedPackage || !openedShareId) return;
    setBusy("delete");
    setNotice(null);
    try {
      const address = getAddress(await ensureWallet());
      if (address !== getAddress(openedPackage.author)) {
        throw new Error("Connect the document creator wallet to delete this hosted copy.");
      }
      const binding: ChallengeBinding = {
        action: "delete",
        documentId: openedPackage.id,
        documentDigest: openedPackage.documentDigest,
        policyDigest: openedPackage.policyDigest,
        keyCommitment: openedPackage.keyCommitment,
        wrappedKeyDigest: await wrappedKeyDigest(openedPackage),
        shareId: openedShareId,
      };
      const authorization = await walletAuthorization("delete", address, binding);
      await apiDelete<{ deleted: true }>(`/api/share/${encodeURIComponent(openedShareId)}`, authorization);
      window.localStorage.removeItem(`ecrypt:share-delete:${openedShareId}`);
      setOpenedPackage(null);
      setOpenedShareId(null);
      setRevealed({});
      window.history.replaceState(null, "", window.location.pathname);
      setNotice({
        tone: "success",
        text: "Creator verified. The hosted package was deleted and its short link no longer works. Copies already saved or sent cannot be recalled.",
      });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The hosted package could not be deleted." });
    } finally {
      setBusy(null);
    }
  }

  async function copyRedactedText() {
    try {
      await navigator.clipboard.writeText(redactedText);
      setCopied("redacted");
      window.setTimeout(() => setCopied((current) => (current === "redacted" ? null : current)), 1800);
    } catch {
      setNotice({ tone: "error", text: "The redacted text could not be copied automatically. You can select it manually." });
    }
  }

  async function copyAllText() {
    try {
      await navigator.clipboard.writeText(unlockableText);
      setCopied("all");
      window.setTimeout(() => setCopied((current) => (current === "all" ? null : current)), 1800);
    } catch {
      setNotice({ tone: "error", text: "The complete text could not be copied automatically. Select everything in the output box instead." });
    }
  }

  async function copyUnlockDataText() {
    try {
      await navigator.clipboard.writeText(unlockDataText);
      setCopied("unlock");
      window.setTimeout(() => setCopied((current) => (current === "unlock" ? null : current)), 1800);
    } catch {
      setNotice({ tone: "error", text: "The unlock-data block could not be copied automatically. Use Copy all or download the package instead." });
    }
  }

  async function openPackageText(value: string) {
    const loaded = decodePackage(value);
    await verifyPackageAuthenticity(loaded);
    setOpenedPackage(loaded);
    setOpenedShareId(null);
    setRevealed({});
    setNotice({ tone: "success", text: "Creator signature verified. Connect an eligible wallet to reveal the redactions." });
  }

  async function loadPackage() {
    try {
      await openPackageText(packageInput);
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The pasted text could not be opened." });
    }
  }

  async function handlePackagePaste(event: ClipboardEvent<HTMLTextAreaElement>) {
    const pasted = event.clipboardData.getData("text/plain");
    if (!pasted) return;
    event.preventDefault();
    setPackageInput(pasted);
    try {
      await openPackageText(pasted);
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The pasted text could not be opened." });
    }
  }

  async function handlePackageFile(event: ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;
    try {
      if (file.size > 2_000_000) {
        throw new Error("This eCrypt package is too large to open safely.");
      }
      const contents = await file.text();
      setPackageInput(contents);
      await openPackageText(contents);
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The selected package could not be opened." });
    } finally {
      input.value = "";
    }
  }

  async function unlockDocument() {
    if (!openedPackage) return;
    setBusy("unlock");
    setNotice(null);
    try {
      const address = await ensureWallet();
      const binding: ChallengeBinding = {
        action: "unlock",
        documentId: openedPackage.id,
        documentDigest: openedPackage.documentDigest,
        policyDigest: openedPackage.policyDigest,
        keyCommitment: openedPackage.keyCommitment,
        wrappedKeyDigest: await wrappedKeyDigest(openedPackage),
      };
      const authorization = await walletAuthorization("unlock", address, binding);
      const response = await api<{ key: string; access: "creator" | "policy" }>("/api/unwrap", {
        documentId: openedPackage.id,
        keyCommitment: openedPackage.keyCommitment,
        author: openedPackage.author,
        policy: openedPackage.policy,
        wrappedKey: openedPackage.wrappedKey,
        documentDigest: openedPackage.documentDigest,
        policyDigest: openedPackage.policyDigest,
        creatorProof: openedPackage.creatorProof,
        ...authorization,
      });
      const rawKey = base64UrlToBytes(response.key);
      if (await sha256Hex(rawKey) !== openedPackage.keyCommitment) {
        throw new Error("The revealed document key does not match the signed package.");
      }
      const key = await crypto.subtle.importKey(
        "raw",
        asArrayBuffer(rawKey),
        "AES-GCM",
        false,
        ["decrypt"],
      );
      const plaintext: Record<number, string> = {};
      for (let index = 0; index < openedPackage.segments.length; index += 1) {
        const segment = openedPackage.segments[index];
        if (segment.kind === "encrypted") plaintext[index] = await decryptSecret(segment, key, index);
      }
      setRevealed(plaintext);
      setNotice({
        tone: "success",
        text: response.access === "creator"
          ? "Creator wallet verified. All redactions passed their integrity checks."
          : "Access verified. All redactions passed their integrity checks.",
      });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The document could not be unlocked." });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="site-shell">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="eCrypt home">
          <span className="brand-mark">e/</span>
          <span>CRYPT</span>
        </a>
        <div className="header-note"><span className="status-dot" /> Client-side encryption</div>
        <button
          className={`wallet-button${wallet ? " wallet-connected" : ""}`}
          onClick={handleWalletAction}
          type="button"
          aria-label={wallet ? `Disconnect wallet ${wallet}` : "Connect wallet"}
          title={wallet ? "Disconnect wallet from eCrypt" : "Connect wallet"}
        >
          {wallet ? <LogOut size={16} aria-hidden="true" /> : <Wallet size={16} aria-hidden="true" />}
          {wallet ? `Disconnect ${shortAddress(wallet)}` : "Connect wallet"}
        </button>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero-kicker"><Braces size={16} /> Wallet-gated redaction protocol</div>
          <h1>Encrypt the redactions.<br /><em>Keep the proof public.</em></h1>
          <p className="hero-copy">
            Seal sensitive passages inside an otherwise readable document. A wallet signature and live onchain access policy decide who can reveal them.
          </p>
          <div className="network-strip" aria-label="Switch connected wallet network">
            {(Object.entries(NETWORKS) as [NetworkKey, (typeof NETWORKS)[NetworkKey]][]).map(([key, network], index) => (
              <button
                className={`network-chip network-${key}${walletNetwork === key ? " active" : ""}`}
                type="button"
                aria-label={`Switch wallet to ${network.label}`}
                aria-pressed={walletNetwork === key}
                title={`Switch wallet to ${network.label}`}
                onClick={() => void switchWalletNetwork(key)}
                key={key}
              >
                <span>{String(index + 1).padStart(2, "0")}</span>{network.label}
              </button>
            ))}
          </div>
        </section>

        <section className="tool-section" aria-label="eCrypt document tool">
          <div className="mode-switch" role="tablist" aria-label="Document action">
            <button
              id="compose-tab"
              role="tab"
              aria-selected={mode === "compose"}
              aria-controls="compose-panel"
              className={mode === "compose" ? "active" : ""}
              onClick={() => setMode("compose")}
              type="button"
            >
              <FileLock2 size={17} /> Create &amp; redact <span>01</span>
            </button>
            <button
              id="open-tab"
              role="tab"
              aria-selected={mode === "open"}
              aria-controls="open-panel"
              className={mode === "open" ? "active" : ""}
              onClick={() => setMode("open")}
              type="button"
            >
              <KeyRound size={17} /> Paste &amp; decrypt <span>02</span>
            </button>
            <button
              id="about-tab"
              role="tab"
              aria-selected={mode === "about"}
              aria-controls="about-panel"
              className={mode === "about" ? "active" : ""}
              onClick={() => setMode("about")}
              type="button"
            >
              <BookOpen size={17} /> About <span>03</span>
            </button>
          </div>

          {notice && (
            <div className={`notice notice-${notice.tone}`} role="status">
              {notice.tone === "success" ? <Check size={16} /> : <ShieldCheck size={16} />}
              <span>{notice.text}</span>
              <button type="button" onClick={() => setNotice(null)} aria-label="Dismiss message">×</button>
            </div>
          )}

          {mode === "compose" ? (
            <div className="workspace-grid" id="compose-panel" role="tabpanel" aria-labelledby="compose-tab" tabIndex={0}>
              <div className="workspace-main">
                <div className="panel-heading">
                  <div>
                    <span className="eyebrow">Document / plaintext</span>
                    <h2>Choose what stays private</h2>
                  </div>
                  <button className="compact-action" type="button" onClick={redactSelection}>
                    <Eye size={15} /> Redact selection
                  </button>
                </div>
                <label className="field-label" htmlFor="document-title">Document title <span>(optional)</span></label>
                <input
                  id="document-title"
                  className="title-input"
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                  maxLength={160}
                  placeholder="Optional title"
                />
                <label className="field-label editor-label" htmlFor="document-body">
                  Body <span>Select text and use “Redact selection,” or wrap it in [[double brackets]].</span>
                </label>
                <textarea
                  id="document-body"
                  ref={editorRef}
                  className="document-editor"
                  value={body}
                  onChange={(event) => setBody(event.target.value)}
                  placeholder="Write or paste your text here…"
                  spellCheck
                />
                <DraftPreview value={body} title={title} />
              </div>

              <aside className="policy-panel">
                <div className="panel-heading policy-heading">
                  <div>
                    <span className="eyebrow">Access / onchain</span>
                    <h2>Set the reveal policy</h2>
                  </div>
                  <Network size={20} aria-hidden="true" />
                </div>
                <p className="policy-intro">Choose where each token is checked. Selecting a network also asks a connected wallet to switch; your wallet may request confirmation. The wallet that creates the document can always decrypt it.</p>

                {rules.length > 1 && (
                  <div className="match-toggle" aria-label="Access condition mode">
                    <span>Require</span>
                    <button className={matchMode === "any" ? "active" : ""} onClick={() => setMatchMode("any")} type="button">Any</button>
                    <button className={matchMode === "all" ? "active" : ""} onClick={() => setMatchMode("all")} type="button">All</button>
                  </div>
                )}

                <div className="rule-list">
                  {rules.map((rule, index) => (
                    <div className="rule-card" key={rule.id}>
                      <div className="rule-topline">
                        <span>Condition {String(index + 1).padStart(2, "0")}</span>
                        {rules.length > 1 && (
                          <button type="button" onClick={() => setRules((current) => current.filter((item) => item.id !== rule.id))} aria-label={`Remove condition ${index + 1}`}>
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                      <label className="field-label" htmlFor={`${rule.id}-kind`}>Credential</label>
                      <select id={`${rule.id}-kind`} value={rule.kind} onChange={(event) => changeRuleKind(rule.id, event.target.value as RuleKind)}>
                        <option value="wallet">Specific wallet</option>
                        <option value="erc20">ERC-20 balance</option>
                        <option value="erc721">ERC-721 / NFT</option>
                        <option value="erc1155">ERC-1155 token</option>
                      </select>

                      {rule.kind === "wallet" ? (
                        <>
                          <label className="field-label" htmlFor={`${rule.id}-address`}>Allowed address</label>
                          <input id={`${rule.id}-address`} value={rule.address || ""} onChange={(event) => updateRule(rule.id, { address: event.target.value })} placeholder="0x…" autoComplete="off" />
                          {wallet && !rule.address && <button type="button" className="text-action" onClick={() => updateRule(rule.id, { address: wallet })}>Use connected wallet</button>}
                        </>
                      ) : (
                        <>
                          <span className="field-label" id={`${rule.id}-network-label`}>Network</span>
                          <div className="network-picker" role="group" aria-labelledby={`${rule.id}-network-label`}>
                            {(Object.entries(NETWORKS) as [NetworkKey, (typeof NETWORKS)[NetworkKey]][]).map(([key, network]) => (
                              <button
                                className={rule.network === key ? "active" : ""}
                                type="button"
                                aria-pressed={rule.network === key}
                                onClick={() => void selectRuleNetwork(rule.id, key)}
                                key={key}
                              >
                                {network.label}
                              </button>
                            ))}
                          </div>
                          <label className="field-label" htmlFor={`${rule.id}-contract`}>Contract address</label>
                          <input id={`${rule.id}-contract`} value={rule.contract || ""} onChange={(event) => updateRule(rule.id, { contract: event.target.value })} placeholder="0x…" autoComplete="off" />
                          {(rule.kind === "erc721" || rule.kind === "erc1155") && (
                            <>
                              <label className="field-label" htmlFor={`${rule.id}-token`}>Token ID <span>(optional)</span></label>
                              <input id={`${rule.id}-token`} inputMode="numeric" value={rule.tokenId || ""} onChange={(event) => updateRule(rule.id, { tokenId: event.target.value })} placeholder="Any token ID" />
                            </>
                          )}
                          {(rule.kind === "erc20" || rule.kind === "erc1155") && (
                            <>
                              <label className="field-label" htmlFor={`${rule.id}-minimum`}>Minimum balance {rule.kind === "erc1155" && <span>(for one ID)</span>}</label>
                              <input id={`${rule.id}-minimum`} inputMode="decimal" value={rule.minimum || "1"} onChange={(event) => updateRule(rule.id, { minimum: event.target.value })} />
                            </>
                          )}
                        </>
                      )}
                    </div>
                  ))}
                </div>

                <button className="add-condition" type="button" onClick={addRule}><Plus size={15} /> Add condition</button>
                <button className="seal-button" type="button" onClick={sealDocument} disabled={busy !== null}>
                  <LockKeyhole size={18} />
                  {busy === "seal" ? "Encrypting redactions…" : "Create redacted text"}
                  {busy !== "seal" && <ArrowRight size={18} />}
                </button>
                <div className="security-footnote"><ShieldCheck size={16} /><span>AES-256-GCM runs in your browser. The service receives only a random document key, never your plaintext.</span></div>
              </aside>

              {sealedPackage && (
                <section className="sealed-result copyable-result">
                  <div className="result-copy">
                    <span className="eyebrow">Redacted text / ready to paste</span>
                    <h2>Original text, inline hashes.</h2>
                    <p>Every public character stays in place and is covered by the creator signature. Each protected passage becomes a nonce-protected SHA-256 commitment.</p>
                    <label className="field-label" htmlFor="redacted-output">Complete output — select all and copy</label>
                    <textarea id="redacted-output" className="redacted-output" readOnly value={unlockableText} spellCheck={false} />
                    <div className="output-actions">
                      <button className="copy-output-button" type="button" onClick={copyAllText}>
                        {copied === "all" ? <Check size={16} /> : <Copy size={16} />}
                        {copied === "all" ? "Copied all" : "Copy all"}
                      </button>
                      <button className="copy-hash-button" type="button" onClick={copyRedactedText}>
                        {copied === "redacted" ? <Check size={16} /> : <Copy size={16} />}
                        {copied === "redacted" ? "Copied redacted message" : "Copy redacted message only"}
                      </button>
                      <button className="copy-hash-button" type="button" onClick={copyUnlockDataText}>
                        {copied === "unlock" ? <Check size={16} /> : <Copy size={16} />}
                        {copied === "unlock" ? "Copied unlock hash" : "Copy unlock hash only"}
                      </button>
                    </div>
                    <div className="copy-options-footer" aria-label="Copy option guide">
                      <p><strong>Copy all</strong><span>The complete redacted message plus its unlock-data block. Best for sending one self-contained copy.</span></p>
                      <p><strong>Redacted message only</strong><span>Readable public text with inline SHA-256 redactions. It cannot be decrypted by itself.</span></p>
                      <p><strong>Unlock hash only</strong><span>The compact encrypted package. Paste it into eCrypt and satisfy the wallet policy to reveal the message.</span></p>
                    </div>
                    <div className="recovery-warning" role="note">
                      <TriangleAlert size={20} aria-hidden="true" />
                      <p><strong>No account history or recovery</strong><span>eCrypt stores a package only if you explicitly create a hosted short link. That copy remains available until the creator deletes it. If every user-held copy is lost and no hosted copy remains, recovery is impossible—even for eCrypt.</span></p>
                    </div>

                    <details className="package-options">
                      <summary>More ways to keep the unlockable version</summary>
                      <p>The complete output above, either link option, and the downloaded package can start wallet-gated reveal. The redacted-message-only format cannot.</p>
                      <div className="hosted-share-option">
                        <span className="field-label">Hosted short link</span>
                        <p>Opt in to storing the signed encrypted package—including its readable text, wallet policy, and ciphertext—in eCrypt’s private storage until the creator deletes it. The URL contains only a random identifier. Anyone with it can retrieve the package, but reveal still requires an eligible wallet.</p>
                        {hostedShare ? (
                          <>
                            <div className="share-field">
                              <input aria-label="Hosted short link" readOnly value={hostedShare.url} />
                              <button type="button" onClick={copyShortLink}>{copied === "short" ? <Check size={16} /> : <Copy size={16} />}{copied === "short" ? "Copied" : "Copy"}</button>
                            </div>
                            <p className="share-expiry">No expiration. This link remains available until the creator deletes the hosted copy.</p>
                            <button className="delete-share-button" type="button" onClick={deleteShortLink} disabled={shareBusy !== null}>
                              <Trash2 size={16} /> {shareBusy === "delete" ? "Deleting…" : "Delete hosted copy now"}
                            </button>
                          </>
                        ) : (
                          <button className="create-share-button" type="button" onClick={createShortLink} disabled={shareBusy !== null}>
                            <ExternalLink size={16} /> {shareBusy === "create" ? "Creating…" : "Create short link"}
                          </button>
                        )}
                      </div>
                      <label className="field-label" htmlFor="share-url">Self-contained full link</label>
                      <p>This link stores nothing on eCrypt, but long documents may produce URLs that messaging applications truncate.</p>
                      <div className="share-field">
                        <input id="share-url" readOnly value={selfContainedShareUrl} />
                        <button type="button" onClick={copyShareLink}>{copied === "link" ? <Check size={16} /> : <Copy size={16} />}{copied === "link" ? "Copied" : "Copy"}</button>
                      </div>
                      <button className="download-button" type="button" onClick={() => downloadPackage(sealedPackage)}><Download size={16} /> Download .ecrypt.json</button>
                    </details>
                  </div>
                </section>
              )}
            </div>
          ) : mode === "open" ? (
            <div className="open-workspace" id="open-panel" role="tabpanel" aria-labelledby="open-tab" tabIndex={0}>
              {!openedPackage ? (
                <div className="open-empty">
                  <div className="open-icon"><Upload size={26} /></div>
                  <span className="eyebrow">Copy / paste unlock</span>
                  <h2>Paste redacted text to decrypt</h2>
                  <p>Paste text created with “Copy all” or “Copy unlock hash only.” eCrypt detects the unlock-data block automatically. Share links and <code>.ecrypt.json</code> packages still work too.</p>
                  <textarea value={packageInput} onChange={(event) => setPackageInput(event.target.value)} onPaste={handlePackagePaste} placeholder={`Public text [sha256:…]\n\n${ECRYPT_DATA_BEGIN}\n…`} aria-label="Unlockable redacted text" />
                  <button className="seal-button open-button" type="button" onClick={loadPackage} disabled={!packageInput.trim()}><FileLock2 size={18} /> Open pasted text <ArrowRight size={18} /></button>
                  <div className="upload-package-option">
                    <span>Or use a saved package</span>
                    <input
                      ref={packageFileRef}
                      type="file"
                      accept=".json,application/json,application/ecrypt+json"
                      onChange={handlePackageFile}
                      hidden
                    />
                    <button className="download-button upload-json-button" type="button" onClick={() => packageFileRef.current?.click()}>
                      <Upload size={16} /> Upload .ecrypt.json
                    </button>
                  </div>
                </div>
              ) : (
                <div className="unlock-grid">
                  <div>
                    <div className="panel-heading">
                      <div><span className="eyebrow">Document / ciphertext</span><h2>Public until proven eligible</h2></div>
                      <button className="compact-action" type="button" onClick={() => { setOpenedPackage(null); setOpenedShareId(null); setRevealed({}); window.history.replaceState(null, "", window.location.pathname); }}><Upload size={15} /> Paste another</button>
                    </div>
                    <RedactedDocument documentPackage={openedPackage} revealed={revealed} />
                  </div>
                  <aside className="unlock-panel">
                    <div className="unlock-seal"><ShieldCheck size={27} /></div>
                    <span className="eyebrow">Live access check</span>
                    <h2>{Object.keys(revealed).length ? "Redactions revealed" : "Prove access to unlock"}</h2>
                    <p>{Object.keys(revealed).length ? "The plaintext was decrypted locally and every hidden-nonce commitment matched." : "Your wallet signs a one-time message bound to this exact package. No transaction or gas fee is required."}</p>
                    <div className="policy-summary">
                      <div><span>Policy</span><strong>{openedPackage.policy.mode === "any" ? "Any condition" : "All conditions"}</strong></div>
                      <div className="summary-rule">
                        <span className="summary-kind">CREATOR</span>
                        <ExplorerAddress address={openedPackage.author} />
                      </div>
                      {openedPackage.policy.rules.map((rule) => (
                        <div className="summary-rule" key={rule.id}>
                          <span className="summary-kind">{rule.kind.toUpperCase()}</span>
                          {rule.kind === "wallet" ? (
                            <ExplorerAddress address={rule.address!} />
                          ) : (
                            <ExplorerAddress
                              address={rule.contract!}
                              network={rule.network!}
                              prefix={`${NETWORKS[rule.network!].label} · `}
                            />
                          )}
                        </div>
                      ))}
                    </div>
                    {!Object.keys(revealed).length && (
                      <button className="seal-button" type="button" onClick={unlockDocument} disabled={busy !== null}>
                        <KeyRound size={18} /> {busy === "unlock" ? "Checking access…" : "Verify & reveal redactions"} {busy !== "unlock" && <ArrowRight size={18} />}
                      </button>
                    )}
                    {openedShareId && creatorWalletConnected && (
                      <div className="creator-delete-option">
                        <strong>Creator deletion</strong>
                        <p>The creator wallet can permanently remove this hosted package. Copies already downloaded, copied, or forwarded cannot be recalled.</p>
                        <button type="button" onClick={creatorDeleteHostedMessage} disabled={busy !== null}>
                          <Trash2 size={16} /> {busy === "delete" ? "Deleting…" : "Delete hosted message"}
                        </button>
                      </div>
                    )}
                    <div className="security-footnote"><Wallet size={16} /><span>{wallet ? `Connected as ${shortAddress(wallet)}` : "Connect an EVM wallet when prompted."}</span></div>
                  </aside>
                </div>
              )}
            </div>
          ) : (
            <AboutPanel />
          )}
        </section>

        <section className="principles">
          <div><span>01</span><h3>Local by default</h3><p>Plaintext and decrypted passages stay in the browser.</p></div>
          <div><span>02</span><h3>Portable proof</h3><p>Signed public text and nonce-protected commitments expose tampering.</p></div>
          <div><span>03</span><h3>Live eligibility</h3><p>Wallet and token conditions are checked at reveal time.</p></div>
        </section>
      </main>

      <footer>
        <div className="brand footer-brand"><span className="brand-mark">e/</span><span>CRYPT</span></div>
        <p>Experimental cryptographic software by Bittrees. Do not use for regulated or mission-critical data without an independent security review.</p>
        <a href="https://bittrees.org" target="_blank" rel="noreferrer">bittrees.org <ArrowRight size={14} /></a>
      </footer>
    </div>
  );
}
