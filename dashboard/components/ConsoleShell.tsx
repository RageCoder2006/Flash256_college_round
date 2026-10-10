"use client";
import { useEffect, useState } from "react";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";

const KEY = "avhsol.side";

/** Console frame with a sidebar the user can hide (remembered per browser). */
export function ConsoleShell({ side, children }: { side: React.ReactNode; children: React.ReactNode }) {
  const [hidden, setHidden] = useState(false);
  useEffect(() => {
    try { setHidden(localStorage.getItem(KEY) === "1"); } catch { /* storage unavailable */ }
  }, []);
  const toggle = () => {
    setHidden((h) => {
      try { localStorage.setItem(KEY, h ? "0" : "1"); } catch { /* ignore */ }
      return !h;
    });
  };
  return (
    <div className={`app${hidden ? " side-hidden" : ""}`}>
      <aside className="side" aria-hidden={hidden}>{side}</aside>
      <button className="side-toggle" onClick={toggle} aria-label={hidden ? "Show sidebar" : "Hide sidebar"} aria-expanded={!hidden} title={hidden ? "Show sidebar" : "Hide sidebar"}>
        {hidden ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
      </button>
      <main className="main">{children}</main>
    </div>
  );
}
