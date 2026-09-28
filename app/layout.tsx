import InsightsScript from "next/script";
import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const siteUrl = "https://ecrypt.bittrees.org";
const title = "eCrypt — Wallet-Gated Text Encryption & Redaction";
const socialTitle = "eCrypt — Encrypt the redactions. Keep the proof public.";
const description = "Encrypt selected text in your browser with AES-256-GCM, then reveal it to eligible wallets or token holders across Ethereum, Base, and Robinhood.";

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
  title: {
    default: title,
    template: "%s | eCrypt",
  },
  description,
  applicationName: "eCrypt",
  authors: [{ name: "Bittrees", url: "https://bittrees.org" }],
  creator: "Bittrees",
  publisher: "Bittrees",
  category: "Security",
  keywords: [
    "wallet-gated encryption",
    "document redaction",
    "encrypted documents",
    "text encryption",
    "AES-256-GCM",
    "SHA-256 commitments",
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
  formatDetection: {
    address: false,
    email: false,
    telephone: false,
  },
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml", sizes: "any" },
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
    title: socialTitle,
    description,
    images: [{ url: "/og.png", width: 1200, height: 630, type: "image/png", alt: socialTitle }],
  },
  twitter: {
    card: "summary_large_image",
    title: socialTitle,
    description,
    images: [{ url: "/og.png", alt: socialTitle }],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}<InsightsScript src="https://insights.bittrees.org/consent.js" data-insights-site="ecrypt" strategy="afterInteractive" />
      </body>
    </html>
  );
}
