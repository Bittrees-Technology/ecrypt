import EcryptApp from "./EcryptApp";

const siteUrl = "https://ecrypt.bittrees.org";
const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": `${siteUrl}/#organization`,
      name: "Bittrees",
      url: "https://bittrees.org",
      logo: {
        "@type": "ImageObject",
        url: `${siteUrl}/icon.png`,
        width: 512,
        height: 512,
      },
    },
    {
      "@type": "WebSite",
      "@id": `${siteUrl}/#website`,
      url: `${siteUrl}/`,
      name: "eCrypt",
      description: "Wallet-gated text encryption and inline document redaction.",
      inLanguage: "en-US",
      publisher: { "@id": `${siteUrl}/#organization` },
    },
    {
      "@type": "WebApplication",
      "@id": `${siteUrl}/#application`,
      name: "eCrypt",
      url: `${siteUrl}/`,
      description: "Browser-based AES-256-GCM text encryption with wallet and token-gated inline redactions.",
      applicationCategory: "SecurityApplication",
      applicationSubCategory: "Document encryption and redaction",
      operatingSystem: "Any",
      browserRequirements: "Requires JavaScript and an EVM-compatible wallet for encryption and decryption.",
      softwareVersion: "2.0.0",
      inLanguage: "en-US",
      isAccessibleForFree: true,
      image: {
        "@type": "ImageObject",
        url: `${siteUrl}/og.png`,
        width: 1200,
        height: 630,
      },
      offers: {
        "@type": "Offer",
        price: "0",
        priceCurrency: "USD",
      },
      creator: { "@id": `${siteUrl}/#organization` },
      isPartOf: { "@id": `${siteUrl}/#website` },
      featureList: [
        "Client-side AES-256-GCM encryption for inline text redactions",
        "Creator-authenticated public text and metadata",
        "Wallet and token-gated decryption without an onchain transaction",
        "ERC-20, ERC-721, and ERC-1155 access conditions",
        "Ethereum, Base, and Robinhood network support",
        "Portable copy-and-paste and JSON encrypted packages",
        "Optional persistent short links with creator-authorized deletion",
      ],
    },
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
