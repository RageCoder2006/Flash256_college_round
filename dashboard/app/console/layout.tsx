import Link from "next/link";
import { AuthGate } from "@/components/AuthGate";
import { ConsoleShell } from "@/components/ConsoleShell";
import { GuardSwitch } from "@/components/GuardSwitch";
import { Logo } from "@/components/Logo";
import { Nav } from "@/components/Nav";

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  return (
    <ConsoleShell
      side={
        <>
          <Link href="/" className="brandmark" aria-label="AVHSOL overview">
            <Logo />
            <span>
              <b>AVHSOL</b>
              <small>Agentic Vulnerability Hunter with Simulated Offensive Layers</small>
            </span>
          </Link>
          <Nav />
          <div className="side-foot">
            <GuardSwitch />
            <span>Made by David Porathur and Rishit Baitule</span>
          </div>
        </>
      }
    >
      <AuthGate>{children}</AuthGate>
    </ConsoleShell>
  );
}
