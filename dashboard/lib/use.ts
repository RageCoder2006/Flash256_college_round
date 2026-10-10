"use client";
import { useCallback, useEffect, useState } from "react";
import { AuthError, get } from "./api";

/** path = null disables the request (e.g. while signed out). */
export function useFetch<T>(path: string | null, refreshMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    if (!path) {
      setLoading(false);
      return;
    }
    try {
      setData(await get<T>(path));
      setError(null);
    } catch (e) {
      if (e instanceof AuthError) return; // the sign-in gate takes over
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    const again = () => void load();
    window.addEventListener("ab-signed-in", again);
    return () => window.removeEventListener("ab-signed-in", again);
  }, [load]);
  useEffect(() => {
    void load();
    if (!refreshMs) return;
    const t = setInterval(load, refreshMs);
    return () => clearInterval(t);
  }, [load, refreshMs]);
  return { data, error, loading, reload: load };
}
