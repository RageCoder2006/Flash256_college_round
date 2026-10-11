"use client";
import { useEffect, useState } from "react";
import { get, getActiveRun, setActiveRun } from "@/lib/api";

interface RunRow { id: string; traces: number; modified: string; simulated: boolean }

/** Chooses which run the Traces, Verdict and summary pages show, so an audit started from the command line can be opened here. */
export function RunPicker() {
  const [runs, setRuns] = useState<RunRow[]>([]);
  const [cur, setCur] = useState("");
  useEffect(() => {
    setCur(getActiveRun());
    get<{ runs: RunRow[] }>("/api/reports/runs").then((r) => setRuns(r.runs)).catch(() => undefined);
  }, []);
  if (runs.length === 0) return null;
  return (
    <label className="runpick">
      <span>Viewing run</span>
      <select value={cur} aria-label="Run shown on the Traces and Verdict pages" onChange={(e) => { setActiveRun(e.target.value); setCur(e.target.value); window.location.reload(); }}>
        <option value="">Server default</option>
        {runs.map((r) => <option key={r.id} value={r.id}>{r.id} ({r.traces}){r.simulated ? " · simulated" : ""}</option>)}
      </select>
    </label>
  );
}
