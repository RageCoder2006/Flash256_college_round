"use client";
import { useEffect, useState } from "react";
import { getToken, post, type GuardStatus } from "@/lib/api";
import { useFetch } from "@/lib/use";

const MODES = ["off", "monitor", "enforce"] as const;

export function GuardSwitch() {
  // Don't poll while signed out: an unauthenticated poll is just noise (and a 401 every few seconds).
  const [signedIn, setSignedIn] = useState(false);
  useEffect(() => {
    const on = () => setSignedIn(!!getToken());
    const off = () => setSignedIn(false);
    on();
    window.addEventListener("ab-signed-in", on);
    window.addEventListener("ab-auth-required", off);
    return () => {
      window.removeEventListener("ab-signed-in", on);
      window.removeEventListener("ab-auth-required", off);
    };
  }, []);
  const { data, reload } = useFetch<GuardStatus>(signedIn ? "/api/guard" : null, signedIn ? 4000 : 0);
  const [busy, setBusy] = useState(false);
  const reachable = signedIn && !!data?.reachable;
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
