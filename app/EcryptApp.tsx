"use client";

import {
  ArrowRight,
  Braces,
  Check,
  Copy,
  Download,
  Eye,
  FileLock2,
  KeyRound,
  LockKeyhole,
  Network,
  Plus,
  ShieldCheck,
  Trash2,
  Upload,
  Wallet,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  AccessPolicy,
  AccessRule,
  DocumentSegment,
  EcryptPackage,
  EncryptedSegment,
  MatchMode,
  NETWORKS,
  NetworkKey,
  normalizePolicy,
  RuleKind,
  shortAddress,
} from "../lib/ecrypt";

interface EthereumProvider {
  request<T = unknown>(request: { method: string; params?: unknown[] }): Promise<T>;
}

declare global {
  interface Window {
    ethereum?: EthereumProvider;
  }
}

type Mode = "compose" | "open";
type Notice = { tone: "error" | "success" | "info"; text: string } | null;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SAMPLE_DOCUMENT = `BOARD AUTHORIZATION · 08/17/2026

The undersigned approves the transfer of [[1,250,000 USDC]] from the treasury to [[0x7A4b…91F2]] upon completion of the transaction review.

This authorization remains valid until [[September 30, 2026 at 17:00 UTC]]. All other terms remain public and verifiable.`;

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

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function textToHex(value: string): `0x${string}` {
  return `0x${Array.from(encoder.encode(value), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
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

function isEcryptPackage(value: unknown): value is EcryptPackage {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<EcryptPackage>;
  return (
    item.version === 1 &&
    typeof item.id === "string" &&
    typeof item.title === "string" &&
    typeof item.author === "string" &&
    typeof item.createdAt === "string" &&
    typeof item.wrappedKey === "string" &&
    Array.isArray(item.segments) &&
    item.segments.length > 0 &&
    item.segments.length <= 200 &&
    item.segments.every(
      (segment) =>
        segment &&
        typeof segment === "object" &&
        ((segment.kind === "public" && typeof segment.text === "string") ||
          (segment.kind === "encrypted" &&
            typeof segment.ciphertext === "string" &&
            typeof segment.iv === "string" &&
            typeof segment.salt === "string" &&
            typeof segment.hash === "string")),
    )
  );
}

function decodePackage(input: string): EcryptPackage {
  const trimmed = input.trim();
  let serialized = trimmed;
  if (trimmed.includes("#ecrypt=")) serialized = trimmed.split("#ecrypt=")[1];
  if (!serialized.startsWith("{")) {
    serialized = decoder.decode(base64UrlToBytes(serialized));
  }
  const parsed = JSON.parse(serialized) as unknown;
  if (!isEcryptPackage(parsed)) throw new Error("This is not a valid eCrypt document package.");
  parsed.policy = normalizePolicy(parsed.policy);
  return parsed;
}

async function api<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = (await response.json()) as T & { error?: string };
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

async function walletAuthorization(action: "seal" | "unlock", wallet: string) {
  const challenge = await api<{ message: string }>("/api/challenge", { action });
  const signature = await signMessage(wallet, challenge.message);
  return { message: challenge.message, signature };
}

async function encryptSecret(text: string, key: CryptoKey, index: number): Promise<EncryptedSegment> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const plaintext = encoder.encode(text);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", asArrayBuffer(concatBytes(salt, plaintext))),
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(iv),
        additionalData: asArrayBuffer(encoder.encode(`ecrypt:v1:${index}`)),
      },
      key,
      asArrayBuffer(plaintext),
    ),
  );
  return {
    kind: "encrypted",
    ciphertext: bytesToBase64Url(ciphertext),
    iv: bytesToBase64Url(iv),
    salt: bytesToBase64Url(salt),
    hash: bytesToBase64Url(digest),
  };
}

async function decryptSecret(segment: EncryptedSegment, key: CryptoKey, index: number) {
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(base64UrlToBytes(segment.iv)),
        additionalData: asArrayBuffer(encoder.encode(`ecrypt:v1:${index}`)),
      },
      key,
      asArrayBuffer(base64UrlToBytes(segment.ciphertext)),
    ),
  );
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      asArrayBuffer(concatBytes(base64UrlToBytes(segment.salt), plaintext)),
    ),
  );
  if (bytesToBase64Url(digest) !== segment.hash) {
    throw new Error("A redacted passage did not pass its integrity check.");
  }
  return decoder.decode(plaintext);
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

function RedactedDocument({
  documentPackage,
  revealed,
}: {
  documentPackage: EcryptPackage;
  revealed: Record<number, string>;
}) {
  return (
    <article className="document-paper" aria-label={`${documentPackage.title} encrypted document`}>
      <div className="paper-meta">
        <span>eCrypt sealed document</span>
        <span>{new Date(documentPackage.createdAt).toLocaleDateString()}</span>
      </div>
      <h3>{documentPackage.title}</h3>
      <div className="document-copy">
        {documentPackage.segments.map((segment, index) => {
          if (segment.kind === "public") return <span key={`${index}-public`}>{segment.text}</span>;
          const plaintext = revealed[index];
          return plaintext ? (
            <mark className="revealed-passage" key={`${index}-revealed`}>
              {plaintext}
            </mark>
          ) : (
            <span className="redaction" key={`${index}-redacted`} title="Encrypted redaction">
              <LockKeyhole size={12} aria-hidden="true" /> sha256:{segment.hash.slice(0, 12)}
            </span>
          );
        })}
      </div>
      <div className="paper-signature">
        <span>Sealed by</span>
        <code>{shortAddress(documentPackage.author)}</code>
      </div>
    </article>
  );
}

function DraftPreview({ value, title }: { value: string; title: string }) {
  const segments = markedSegments(value);
  return (
    <article className="document-paper draft-paper" aria-label="Redaction preview">
      <div className="paper-meta">
        <span>Live redaction preview</span>
        <span>Draft</span>
      </div>
      <h3>{title || "Untitled private document"}</h3>
      <div className="document-copy">
        {segments.length ? (
          segments.map((segment, index) =>
            segment.kind === "secret" ? (
              <span className="redaction preview-redaction" key={`${index}-secret`}>
                <LockKeyhole size={12} aria-hidden="true" /> encrypt on seal
              </span>
            ) : (
              <span key={`${index}-public`}>{segment.text}</span>
            ),
          )
        ) : (
          <span className="empty-copy">Write something, then select text to redact it.</span>
        )}
      </div>
    </article>
  );
}

export default function EcryptApp() {
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const [mode, setMode] = useState<Mode>("compose");
  const [wallet, setWallet] = useState("");
  const [title, setTitle] = useState("Treasury authorization — Q3");
  const [body, setBody] = useState(SAMPLE_DOCUMENT);
  const [matchMode, setMatchMode] = useState<MatchMode>("any");
  const [rules, setRules] = useState<AccessRule[]>([
    { id: "rule-wallet", kind: "wallet", address: "" },
  ]);
  const [busy, setBusy] = useState<"seal" | "unlock" | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [sealedPackage, setSealedPackage] = useState<EcryptPackage | null>(null);
  const [openedPackage, setOpenedPackage] = useState<EcryptPackage | null>(null);
  const [packageInput, setPackageInput] = useState("");
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const [copied, setCopied] = useState(false);

  const shareUrl = useMemo(() => {
    if (!sealedPackage || typeof window === "undefined") return "";
    const encoded = bytesToBase64Url(encoder.encode(JSON.stringify(sealedPackage)));
    return `${window.location.origin}/#ecrypt=${encoded}`;
  }, [sealedPackage]);

  useEffect(() => {
    const encoded = window.location.hash.startsWith("#ecrypt=")
      ? window.location.hash.slice("#ecrypt=".length)
      : "";
    if (!encoded) return;
    const timer = window.setTimeout(() => {
      try {
        const loaded = decodePackage(encoded);
        setOpenedPackage(loaded);
        setMode("open");
        setNotice({ tone: "info", text: "Encrypted package loaded. Connect an eligible wallet to reveal the redactions." });
      } catch {
        setNotice({ tone: "error", text: "The encrypted document link is incomplete or invalid." });
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

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
    if (!title.trim()) {
      setNotice({ tone: "error", text: "Give the document a title before sealing it." });
      return;
    }
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
      const address = await ensureWallet();
      const authorization = await walletAuthorization("seal", address);
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
      const wrapped = await api<{ wrappedKey: string; policy: AccessPolicy; author: string }>("/api/wrap", {
        key: bytesToBase64Url(rawKey),
        policy,
        ...authorization,
      });
      const documentPackage: EcryptPackage = {
        version: 1,
        id: randomId("doc"),
        title: title.trim().slice(0, 160),
        author: wrapped.author,
        createdAt: new Date().toISOString(),
        policy: wrapped.policy,
        wrappedKey: wrapped.wrappedKey,
        segments,
      };
      setSealedPackage(documentPackage);
      setRevealed({});
      setNotice({ tone: "success", text: "Document sealed. Share the link or download its portable package." });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The document could not be sealed." });
    } finally {
      setBusy(null);
    }
  }

  async function copyShareLink() {
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setNotice({ tone: "error", text: "The share link could not be copied. You can select it manually." });
    }
  }

  function loadPackage() {
    try {
      const loaded = decodePackage(packageInput);
      setOpenedPackage(loaded);
      setRevealed({});
      setNotice({ tone: "success", text: "Encrypted document loaded." });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The package could not be opened." });
    }
  }

  async function unlockDocument() {
    if (!openedPackage) return;
    setBusy("unlock");
    setNotice(null);
    try {
      const address = await ensureWallet();
      const authorization = await walletAuthorization("unlock", address);
      const response = await api<{ key: string }>("/api/unwrap", {
        wrappedKey: openedPackage.wrappedKey,
        policy: openedPackage.policy,
        author: openedPackage.author,
        ...authorization,
      });
      const key = await crypto.subtle.importKey(
        "raw",
        asArrayBuffer(base64UrlToBytes(response.key)),
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
      setNotice({ tone: "success", text: "Access verified. All redactions passed their integrity checks." });
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
        <button className="wallet-button" onClick={handleConnect} type="button">
          <Wallet size={16} aria-hidden="true" />
          {wallet ? shortAddress(wallet) : "Connect wallet"}
        </button>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero-kicker"><Braces size={16} /> Wallet-gated redaction protocol</div>
          <h1>Encrypt the redactions.<br /><em>Keep the proof public.</em></h1>
          <p className="hero-copy">
            Seal sensitive passages inside an otherwise readable document. A wallet signature and live onchain access policy decide who can reveal them.
          </p>
          <div className="network-strip" aria-label="Supported networks">
            {(Object.entries(NETWORKS) as [NetworkKey, (typeof NETWORKS)[NetworkKey]][]).map(([key, network], index) => (
              <div className={`network-chip network-${key}`} key={key}>
                <span>{String(index + 1).padStart(2, "0")}</span>{network.label}
              </div>
            ))}
          </div>
        </section>

        <section className="tool-section" aria-label="eCrypt document tool">
          <div className="mode-switch" role="tablist" aria-label="Document action">
            <button
              role="tab"
              aria-selected={mode === "compose"}
              className={mode === "compose" ? "active" : ""}
              onClick={() => setMode("compose")}
              type="button"
            >
              <FileLock2 size={17} /> Create &amp; seal <span>01</span>
            </button>
            <button
              role="tab"
              aria-selected={mode === "open"}
              className={mode === "open" ? "active" : ""}
              onClick={() => setMode("open")}
              type="button"
            >
              <KeyRound size={17} /> Open &amp; unlock <span>02</span>
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
            <div className="workspace-grid">
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
                <label className="field-label" htmlFor="document-title">Document title</label>
                <input
                  id="document-title"
                  className="title-input"
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                  maxLength={160}
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
                <p className="policy-intro">Ownership is checked live each time someone asks to decrypt.</p>

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
                          <label className="field-label" htmlFor={`${rule.id}-network`}>Network</label>
                          <select id={`${rule.id}-network`} value={rule.network} onChange={(event) => updateRule(rule.id, { network: event.target.value as NetworkKey })}>
                            {(Object.entries(NETWORKS) as [NetworkKey, (typeof NETWORKS)[NetworkKey]][]).map(([key, network]) => <option value={key} key={key}>{network.label}</option>)}
                          </select>
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
                  {busy === "seal" ? "Sealing document…" : "Seal encrypted document"}
                  {busy !== "seal" && <ArrowRight size={18} />}
                </button>
                <div className="security-footnote"><ShieldCheck size={16} /><span>AES-256-GCM runs in your browser. The service receives only a random document key, never your plaintext.</span></div>
              </aside>

              {sealedPackage && (
                <section className="sealed-result">
                  <div className="result-copy">
                    <span className="eyebrow">Sealed / ready to share</span>
                    <h2>Your private passages are now ciphertext.</h2>
                    <p>The URL carries the public text, encrypted redactions, policy, and protected key. No document database is required.</p>
                    <label className="field-label" htmlFor="share-url">Portable share link</label>
                    <div className="share-field">
                      <input id="share-url" readOnly value={shareUrl} />
                      <button type="button" onClick={copyShareLink}>{copied ? <Check size={16} /> : <Copy size={16} />}{copied ? "Copied" : "Copy"}</button>
                    </div>
                    <button className="download-button" type="button" onClick={() => downloadPackage(sealedPackage)}><Download size={16} /> Download .ecrypt.json</button>
                  </div>
                  <RedactedDocument documentPackage={sealedPackage} revealed={{}} />
                </section>
              )}
            </div>
          ) : (
            <div className="open-workspace">
              {!openedPackage ? (
                <div className="open-empty">
                  <div className="open-icon"><Upload size={26} /></div>
                  <span className="eyebrow">Portable ciphertext</span>
                  <h2>Open an encrypted document</h2>
                  <p>Paste an eCrypt share link, encoded package, or the contents of a downloaded <code>.ecrypt.json</code> file.</p>
                  <textarea value={packageInput} onChange={(event) => setPackageInput(event.target.value)} placeholder="https://ecrypt.bittrees.org/#ecrypt=…" aria-label="Encrypted document package" />
                  <button className="seal-button open-button" type="button" onClick={loadPackage} disabled={!packageInput.trim()}><FileLock2 size={18} /> Load encrypted document <ArrowRight size={18} /></button>
                </div>
              ) : (
                <div className="unlock-grid">
                  <div>
                    <div className="panel-heading">
                      <div><span className="eyebrow">Document / ciphertext</span><h2>Public until proven eligible</h2></div>
                      <button className="compact-action" type="button" onClick={() => { setOpenedPackage(null); setRevealed({}); window.history.replaceState(null, "", window.location.pathname); }}><Upload size={15} /> Open another</button>
                    </div>
                    <RedactedDocument documentPackage={openedPackage} revealed={revealed} />
                  </div>
                  <aside className="unlock-panel">
                    <div className="unlock-seal"><ShieldCheck size={27} /></div>
                    <span className="eyebrow">Live access check</span>
                    <h2>{Object.keys(revealed).length ? "Redactions revealed" : "Prove access to unlock"}</h2>
                    <p>{Object.keys(revealed).length ? "The plaintext was decrypted locally and every salted hash matched." : "Your wallet signs a message. No transaction or gas fee is required."}</p>
                    <div className="policy-summary">
                      <div><span>Policy</span><strong>{openedPackage.policy.mode === "any" ? "Any condition" : "All conditions"}</strong></div>
                      {openedPackage.policy.rules.map((rule) => (
                        <div className="summary-rule" key={rule.id}>
                          <span className="summary-kind">{rule.kind.toUpperCase()}</span>
                          <code>{rule.kind === "wallet" ? shortAddress(rule.address!) : `${NETWORKS[rule.network!].label} · ${shortAddress(rule.contract!)}`}</code>
                        </div>
                      ))}
                    </div>
                    {!Object.keys(revealed).length && (
                      <button className="seal-button" type="button" onClick={unlockDocument} disabled={busy !== null}>
                        <KeyRound size={18} /> {busy === "unlock" ? "Checking access…" : "Verify & reveal redactions"} {busy !== "unlock" && <ArrowRight size={18} />}
                      </button>
                    )}
                    <div className="security-footnote"><Wallet size={16} /><span>{wallet ? `Connected as ${shortAddress(wallet)}` : "Connect an EVM wallet when prompted."}</span></div>
                  </aside>
                </div>
              )}
            </div>
          )}
        </section>

        <section className="principles">
          <div><span>01</span><h3>Local by default</h3><p>Plaintext and decrypted passages stay in the browser.</p></div>
          <div><span>02</span><h3>Portable proof</h3><p>Each redaction carries a salted SHA-256 integrity hash.</p></div>
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
