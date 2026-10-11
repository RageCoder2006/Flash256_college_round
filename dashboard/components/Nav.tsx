"use client";
import { Activity, ChevronLeft, FileText, Info, LayoutDashboard, ListTree, Network, Play, Settings, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/console", label: "Status", icon: Activity },
  { href: "/console/verdict", label: "Verdict", icon: LayoutDashboard },
  { href: "/console/graph", label: "Neural graph", icon: Network },
  { href: "/console/intel", label: "Threat intel", icon: ShieldAlert },
  { href: "/console/traces", label: "Traces", icon: ListTree },
  { href: "/console/reports", label: "Reports", icon: FileText },
  { href: "/console/run", label: "Run", icon: Play },
  { href: "/console/settings", label: "Settings", icon: Settings },
  { href: "/console/about", label: "About", icon: Info },
];

export function Nav() {
  const path = usePathname();
  return (
    <nav className="navlist" aria-label="Console">
      {LINKS.map(({ href, label, icon: Icon }) => {
        const active = href === "/console" ? path === "/console" : path.startsWith(href);
        return (
          <Link key={href} href={href} className="navlink" aria-current={active ? "page" : undefined}>
            <Icon size={18} aria-hidden="true" />
            {label}
          </Link>
        );
      })}
      <Link href="/" className="navlink" style={{ marginTop: 10, opacity: 0.8 }}>
        <ChevronLeft size={18} aria-hidden="true" />
        Project overview
      </Link>
    </nav>
  );
}
