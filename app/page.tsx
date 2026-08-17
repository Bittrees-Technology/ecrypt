import EcryptApp from "./EcryptApp";

const structuredData = {
  "@context": "https://schema.org",
  "@type": "WebApplication",
  name: "eCrypt",
  url: "https://ecrypt.bittrees.org",
  description: "Browser-based text encryption and inline document redaction with wallet and token-gated decryption.",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Any",
  browserRequirements: "Requires JavaScript and an EVM-compatible wallet for encryption and decryption.",
  isAccessibleForFree: true,
  offers: {
    "@type": "Offer",
    price: "0",
    priceCurrency: "USD",
  },
  creator: {
    "@type": "Organization",
    name: "Bittrees",
    url: "https://bittrees.org",
  },
  featureList: [
    "Client-side AES-256-GCM encryption for inline text redactions",
    "Wallet and token-gated decryption without an onchain transaction",
    "ERC-20, ERC-721, and ERC-1155 access conditions",
    "Ethereum, Base, and Robinhood network support",
    "Portable copy-and-paste encrypted packages",
  ],
};

export default function Home() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData).replace(/</g, "\\u003c") }}
      />
      <EcryptApp />
    </>
  );
}
