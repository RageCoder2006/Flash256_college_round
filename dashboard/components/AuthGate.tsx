"use client";
import { useCallback, useEffect, useState } from "react";
import { API, getToken, setToken } from "@/lib/api";

/** Asks for an API token before showing anything, and shows who you are signed in as. */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const [role, setRole] = useState<string | null>(null);
  const [needs, setNeeds] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);

  const probe = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/whoami`, { cache: "no-store", headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {} });
      if (r.status === 401) {
        setNeeds(true);
        setRole(null);
        return;
      }
      if (r.status === 429) {
        setError("Too many failed attempts. Wait a minute and try again.");
        setNeeds(true);
        return;
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setRole((await r.json()).role);
      setNeeds(false);
      setError(null);
      window.dispatchEvent(new Event("ab-signed-in"));
    } catch {
      setError("The API isn’t reachable. Start it with avhsol serve.");
      setNeeds(true);
    }
  }, []);

  useEffect(() => {
    void probe();
    const on = () => {
      setNeeds(true);
      setRole(null);
    };
    window.addEventListener("ab-auth-required", on);
    return () => window.removeEventListener("ab-auth-required", on);
  }, [probe]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setToken(value.trim());
    setValue("");
    await probe();
    if (!getToken()) setError("Enter a token.");
    setBusy(false);
  }

  if (needs || role === null) {
    return (
      <section className="verdict" style={{ maxWidth: 520 }}>
        <h1 style={{ fontSize: 30 }}>Sign in</h1>
        <p>AVHSOL controls agent runs and holds attack evidence, so the API needs a token. Tokens are in <span className="mono">deploy/stack/.env</span> (viewer, analyst, operator, admin).</p>
        <form onSubmit={submit} className="form" style={{ marginTop: 16 }}>
          <label style={{ flex: 1, minWidth: 260 }}>
            API token
            <input type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} style={{ font: "inherit", padding: "8px 10px", borderRadius: 8, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)" }} />
          </label>
          <button className="btn" disabled={busy || !value.trim()}>Sign in</button>
        </form>
        {error && <p className="err" style={{ marginTop: 12 }}>{error}</p>}
      </section>
    );
  }
  return (
    <>
      <div className="statusbar">
        <span className="who"><span className="dot" aria-hidden="true" />Signed in as <b style={{ color: "var(--ink)" }}>{role}</b></span>
        <button className="btn ghost" style={{ padding: "3px 12px", fontSize: 13 }} onClick={() => { setToken(""); setNeeds(true); setRole(null); }}>Sign out</button>
      </div>
      {children}
    </>
  );
}
