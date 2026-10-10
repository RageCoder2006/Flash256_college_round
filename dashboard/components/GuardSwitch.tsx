"use client";
import { useState } from "react";
import { post, type GuardStatus } from "@/lib/api";
import { useFetch } from "@/lib/use";

const MODES = ["off", "monitor", "enforce"] as const;

export function GuardSwitch() {
  const { data, reload } = useFetch<GuardStatus>("/api/guard", 4000);
  const [busy, setBusy] = useState(false);
  const reachable = !!data?.reachable;
  async function set(mode: string) {
    setBusy(true);
    try {
      await post("/api/guard/mode", { mode });
      await reload();
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="guardwrap">
      <span id="guard-label">Guard</span>
      <div className="seg" role="group" aria-labelledby="guard-label">
        {MODES.map((m) => (
          <button key={m} className={m} aria-pressed={data?.mode === m} disabled={!reachable || busy} onClick={() => set(m)}>
            {m}
          </button>
        ))}
      </div>
      {!reachable && data && <span title={data.reason}>not running</span>}
    </div>
  );
}
