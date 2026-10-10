import type { Metadata } from "next";
import { Bricolage_Grotesque, IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Link from "next/link";
import { GuardSwitch } from "@/components/GuardSwitch";
import { Nav } from "@/components/Nav";
import "./globals.css";

const display = Bricolage_Grotesque({ subsets: ["latin"], variable: "--font-bricolage" });
const sans = IBM_Plex_Sans({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-plex-sans" });
const mono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "600"], variable: "--font-plex-mono" });

export const metadata: Metadata = {
  title: "AgentBreak",
  description: "Autonomous red team for AI agents: what broke, whether the guard held, and what it cost.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${display.variable} ${sans.variable} ${mono.variable}`}>
      <body>
        <div className="shell">
          <header className="topbar">
            <Link href="/" className="brand"><i aria-hidden="true" />AgentBreak</Link>
            <Nav />
            <GuardSwitch />
          </header>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
