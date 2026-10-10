import type { Metadata, Viewport } from "next";
import { Figtree, JetBrains_Mono, Orbitron } from "next/font/google";
import localFont from "next/font/local";
import "./globals.css";

const airstrike = localFont({
  src: [
    { path: "./fonts/airstrike.ttf", weight: "400", style: "normal" },
    { path: "./fonts/airstrikebold.ttf", weight: "700", style: "normal" },
  ],
  variable: "--font-airstrike", display: "swap", fallback: ["Orbitron", "Segoe UI", "sans-serif"],
});
const logoFont = localFont({ src: "./fonts/airstrikechrome.ttf", weight: "400", variable: "--font-logo-face", display: "swap", fallback: ["Orbitron", "sans-serif"] });
const fallbackDisplay = Orbitron({ subsets: ["latin"], weight: ["500", "700"], variable: "--font-orbitron", display: "swap" });
const sans = Figtree({ subsets: ["latin"], weight: ["400", "500", "600", "700"], variable: "--font-figtree", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-jetbrains", display: "swap" });

export const metadata: Metadata = {
  title: { default: "AVHSOL: Agentic Vulnerability Hunter with Simulated Offensive Layers", template: "%s · AVHSOL" },
  description:
    "AVHSOL is an autonomous red team for AI agents. It hunts for ways to hijack an agent, proves each one with a replayable trace, tests whether a guard stops it, and remembers everything in a bitemporal knowledge graph.",
};

export const viewport: Viewport = { themeColor: "#050912", colorScheme: "dark" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${airstrike.variable} ${logoFont.variable} ${fallbackDisplay.variable} ${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
