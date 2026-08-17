"use client";

import {
  ArrowRight,
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
import { type ChangeEvent, type ClipboardEvent, useEffect, useMemo, useRef, useState } from "react";
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

function encodedPackage(documentPackage: EcryptPackage): string {
  return bytesToBase64Url(encoder.encode(JSON.stringify(documentPackage)));
}

function redactedPackageText(documentPackage: EcryptPackage): string {
  return documentPackage.segments
    .map((segment) =>
      segment.kind === "public" ? segment.text : `[sha256:${segment.hash}]`,
    )
    .join("");
}

function unlockDataPackageText(documentPackage: EcryptPackage): string {
  return `${ECRYPT_DATA_BEGIN}\n${encodedPackage(documentPackage)}\n${ECRYPT_DATA_END}`;
}

function unlockablePackageText(documentPackage: EcryptPackage): string {
  return `${redactedPackageText(documentPackage)}\n\n${unlockDataPackageText(documentPackage)}`;
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

function RedactedDocument({
  documentPackage,
  revealed,
}: {
  documentPackage: EcryptPackage;
  revealed: Record<number, string>;
}) {
  return (
    <article className="document-paper" aria-label={documentPackage.title ? `${documentPackage.title} encrypted document` : "Encrypted document"}>
      <div className="paper-meta">
        <span>eCrypt protected text</span>
        <span>{new Date(documentPackage.createdAt).toLocaleDateString()}</span>
      </div>
      {documentPackage.title && <h3>{documentPackage.title}</h3>}
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
        <span>Protected by</span>
        <ExplorerAddress address={documentPackage.author} />
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
      {title.trim() && <h3>{title}</h3>}
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
  const packageFileRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<Mode>("compose");
  const [wallet, setWallet] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
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
  const [copied, setCopied] = useState<"all" | "redacted" | "unlock" | "link" | null>(null);

  const shareUrl = useMemo(() => {
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

  async function handleWalletAction() {
    if (!wallet) {
      await handleConnect();
      return;
    }
    setWallet("");
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

  async function selectRuleNetwork(id: string, networkKey: NetworkKey) {
    updateRule(id, { network: networkKey });
    const network = NETWORKS[networkKey];
    if (!wallet) {
      setNotice({ tone: "info", text: `${network.label} selected. Connect a wallet when you are ready to create the document.` });
      return;
    }
    if (!window.ethereum) {
      setNotice({ tone: "error", text: `${network.label} was selected, but the connected wallet could not be reached.` });
      return;
    }

    const chainId = `0x${network.chainId.toString(16)}`;
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId }],
      });
      setNotice({ tone: "success", text: `Wallet switched to ${network.label}.` });
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
          setNotice({ tone: "success", text: `${network.label} was added and selected in your wallet.` });
          return;
        } catch (addError) {
          const rejected = providerErrorCode(addError) === 4001 || (addError instanceof Error && /reject|denied|cancel/i.test(addError.message));
          setNotice({
            tone: rejected ? "info" : "error",
            text: rejected
              ? `${network.label} is selected for this condition, but the wallet network change was canceled.`
              : `${network.label} is selected for this condition, but the wallet could not add or switch to it.`,
          });
          return;
        }
      }

      const rejected = providerErrorCode(switchError) === 4001 || (switchError instanceof Error && /reject|denied|cancel/i.test(switchError.message));
      setNotice({
        tone: rejected ? "info" : "error",
        text: rejected
          ? `${network.label} is selected for this condition, but the wallet network change was canceled.`
          : `${network.label} is selected for this condition, but this wallet could not switch networks automatically.`,
      });
    }
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
      setNotice({ tone: "success", text: "Redacted text is ready. Use Copy all for a self-contained message, or choose one of the separate formats below." });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The document could not be sealed." });
    } finally {
      setBusy(null);
    }
  }

  async function copyShareLink() {
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopied("link");
      window.setTimeout(() => setCopied((current) => (current === "link" ? null : current)), 1800);
    } catch {
      setNotice({ tone: "error", text: "The share link could not be copied. You can select it manually." });
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

  function openPackageText(value: string) {
    const loaded = decodePackage(value);
    setOpenedPackage(loaded);
    setRevealed({});
    setNotice({ tone: "success", text: "Unlock data found. Connect an eligible wallet to reveal the redactions." });
  }

  function loadPackage() {
    try {
      openPackageText(packageInput);
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "The pasted text could not be opened." });
    }
  }

  function handlePackagePaste(event: ClipboardEvent<HTMLTextAreaElement>) {
    const pasted = event.clipboardData.getData("text/plain");
    if (!pasted) return;
    event.preventDefault();
    setPackageInput(pasted);
    try {
      openPackageText(pasted);
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
      openPackageText(contents);
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
      const authorization = await walletAuthorization("unlock", address);
      const response = await api<{ key: string; access: "creator" | "policy" }>("/api/unwrap", {
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
              <FileLock2 size={17} /> Create &amp; redact <span>01</span>
            </button>
            <button
              role="tab"
              aria-selected={mode === "open"}
              className={mode === "open" ? "active" : ""}
              onClick={() => setMode("open")}
              type="button"
            >
              <KeyRound size={17} /> Paste &amp; decrypt <span>02</span>
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
                    <p>Every public character stays in place. Each protected passage is replaced with its full salted SHA-256 hash.</p>
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
                      <p><strong>No history or recovery</strong><span>eCrypt does not store your documents. If every copy of the unlock data is lost—including Copy all, the unlock hash, share link, and downloaded package—recovery is impossible, even for eCrypt.</span></p>
                    </div>

                    <details className="package-options">
                      <summary>More ways to keep the unlockable version</summary>
                      <p>The complete output above, this share link, and the downloaded package all contain the encrypted passages and access policy. The redacted-message-only format does not.</p>
                      <label className="field-label" htmlFor="share-url">Private share link</label>
                      <div className="share-field">
                        <input id="share-url" readOnly value={shareUrl} />
                        <button type="button" onClick={copyShareLink}>{copied === "link" ? <Check size={16} /> : <Copy size={16} />}{copied === "link" ? "Copied" : "Copy"}</button>
                      </div>
                      <button className="download-button" type="button" onClick={() => downloadPackage(sealedPackage)}><Download size={16} /> Download .ecrypt.json</button>
                    </details>
                  </div>
                </section>
              )}
            </div>
          ) : (
            <div className="open-workspace">
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
                      <button className="compact-action" type="button" onClick={() => { setOpenedPackage(null); setRevealed({}); window.history.replaceState(null, "", window.location.pathname); }}><Upload size={15} /> Paste another</button>
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
                      <div className="summary-rule">
                        <span className="summary-kind">CREATOR</span>
                        <ExplorerAddress address={openedPackage.author} suffix=" · always eligible" />
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
