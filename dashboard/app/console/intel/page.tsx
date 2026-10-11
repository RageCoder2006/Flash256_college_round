"use client";
import { useState } from "react";
import { Database, Network, Search } from "lucide-react";
import { BrowseTab } from "@/components/intel/BrowseTab";
import { GraphTab } from "@/components/intel/GraphTab";
import { SourcesTab } from "@/components/intel/SourcesTab";
import type { IntelSources } from "@/lib/api";
import { useFetch } from "@/lib/use";

type Tab = "sources" | "browse" | "graph";

export default function IntelPage() {
  const [tab, setTab] = useState<Tab>("sources");
  const meta = useFetch<IntelSources>("/api/intel/sources", 30000);
  const who = useFetch<{ role: string }>("/api/whoami");
  const tabs: [Tab, string, React.ReactNode][] = [
    ["sources", "Data sources", <Database key="d" size={15} />],
    ["browse", "Search & browse", <Search key="s" size={15} />],
    ["graph", "Knowledge graph", <Network key="g" size={15} />],
  ];
  return (
    <div>
      <div className="page-head">
        <h1>Threat intelligence</h1>
        <p className="muted">Public advisories, exploited-vulnerability lists and research about attacks on AI agents. AVHSOL uses them to write attack seeds, to give findings context, and to link what is happening in the world to what it tests.</p>
      </div>
      <div className="seg ti-tabs" role="tablist" aria-label="Threat intelligence views">
        {tabs.map(([k, l, ic]) => (
          <button key={k} role="tab" aria-selected={tab === k} aria-pressed={tab === k} onClick={() => setTab(k)}>{ic} {l}</button>
        ))}
      </div>
      <div style={{ marginTop: 16 }}>
        {tab === "sources" && <SourcesTab data={meta.data} role={who.data?.role} reload={meta.reload} />}
        {tab === "browse" && <BrowseTab meta={meta.data} />}
        {tab === "graph" && <GraphTab meta={meta.data} />}
      </div>
      {meta.error && <div className="ti-msg bad" style={{ marginTop: 12 }}>{meta.error}</div>}
    </div>
  );
}
