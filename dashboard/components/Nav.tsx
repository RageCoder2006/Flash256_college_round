"use client";
import { ChevronLeft, LayoutDashboard, ListTree, Network, Play } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/console", label: "Verdict", icon: LayoutDashboard },
  { href: "/console/graph", label: "Neural graph", icon: Network },
  { href: "/console/traces", label: "Traces", icon: ListTree },
  { href: "/console/run", label: "Run", icon: Play },
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
