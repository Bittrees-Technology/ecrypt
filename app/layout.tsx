import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const siteUrl = "https://ecrypt.bittrees.org";
const title = "eCrypt — Wallet-Gated Text Encryption & Redaction";
const description = "Encrypt sensitive text as inline SHA-256 redactions, then let eligible Ethereum, Base, or Robinhood wallets and token holders decrypt it without a transaction.";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const viewport: Viewport = {
  themeColor: "#f3f0e8",
  colorScheme: "light",
};

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title,
  description,
  applicationName: "eCrypt",
  authors: [{ name: "Bittrees", url: "https://bittrees.org" }],
  creator: "Bittrees",
  publisher: "Bittrees",
  category: "Security",
  keywords: [
    "wallet-gated encryption",
    "document redaction",
    "text encryption",
    "token-gated access",
    "ERC-20",
    "ERC-721",
    "ERC-1155",
    "Ethereum",
    "Base",
    "Robinhood",
  ],
  referrer: "strict-origin-when-cross-origin",
  alternates: { canonical: siteUrl },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
  manifest: "/site.webmanifest",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "32x32" },
      { url: "/favicon-32x32.png", type: "image/png", sizes: "32x32" },
      { url: "/icon.png", type: "image/png", sizes: "512x512" },
    ],
    shortcut: "/favicon.ico",
    apple: [{ url: "/apple-touch-icon.png", type: "image/png", sizes: "180x180" }],
  },
  appleWebApp: {
    capable: true,
    title: "eCrypt",
    statusBarStyle: "black-translucent",
  },
  openGraph: {
    type: "website",
    url: siteUrl,
    siteName: "eCrypt",
    locale: "en_US",
    title,
    description,
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "eCrypt — Encrypt the redactions. Keep the proof public." }],
  },
  twitter: {
    card: "summary_large_image",
    title,
    description,
    images: [{ url: "/og.png", alt: "eCrypt — Encrypt the redactions. Keep the proof public." }],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}
