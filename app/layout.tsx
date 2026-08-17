import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

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

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") || requestHeaders.get("host") || "ecrypt.bittrees.org";
  const protocol = requestHeaders.get("x-forwarded-proto") || (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;
  const title = "eCrypt — Wallet-gated document redaction";
  const description = "Encrypt inline document redactions and reveal them only to eligible wallets or ERC-20, ERC-721, and ERC-1155 holders.";
  return {
    metadataBase: new URL(origin),
    title,
    description,
    applicationName: "eCrypt",
    alternates: { canonical: "/" },
    openGraph: {
      type: "website",
      url: "/",
      siteName: "eCrypt",
      title,
      description,
      images: [{ url: `${origin}/og.png`, width: 1536, height: 1024, alt: "eCrypt — Encrypt the redactions. Keep the proof public." }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [`${origin}/og.png`],
    },
  };
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}

