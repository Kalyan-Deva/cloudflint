"use client";

import { useCallback, useEffect, useState } from "react";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  return body as T;
}

/** Fetch on mount, and again whenever `deps` change or `reload` is called. */
export function useApi<T>(path: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!path) return;
    let live = true;
    setLoading(true);
    api<T>(path)
      .then((d) => live && (setData(d), setError(null)))
      .catch((e) => live && setError(e.message))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, nonce, ...deps]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, error, loading, reload };
}

export function Panel({
  title,
  aside,
  children,
  className = "",
  info,
}: {
  title?: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  info?: string;
}) {
  return (
    <section className={`border hair rounded-sm bg-panel ${className}`}>
      {title && (
        <header className="flex items-center justify-between gap-4 px-4 h-10 border-b hair">
          <h2 className="cap flex items-center gap-1.5">
            {title}
            {info && (
              <span className="text-dim cursor-help" title={info}>
                ⓘ
              </span>
            )}
          </h2>
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}

/** The label-over-value pair this design uses everywhere. */
export function Cell({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: React.ReactNode;
  tone?: "accent" | "good" | "bad" | "warn";
  hint?: string;
}) {
  const colour = tone
    ? { accent: "text-accent", good: "text-good", bad: "text-bad", warn: "text-warn" }[tone]
    : "text-text";
  return (
    <div>
      <div className="cap">{label}</div>
      <div className={`text-[15px] leading-tight tabular mt-0.5 ${colour}`}>{value}</div>
      {hint && <div className="text-[11px] text-dim tabular mt-0.5">{hint}</div>}
    </div>
  );
}

export function Row({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 text-[12.5px] py-[3px]">
      <span className="text-dim shrink-0">{k}</span>
      <span className={`text-right truncate ${mono ? "text-[12px]" : ""}`}>{v}</span>
    </div>
  );
}

export function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span className="border hair rounded-sm px-2 py-0.5 text-[11px] text-muted">{children}</span>
  );
}

export function Problem({ error }: { error: string }) {
  return (
    <div className="border hair rounded-sm bg-panel px-4 py-3 text-[12.5px]">
      <span className="text-bad">Not available.</span> <span className="text-muted">{error}</span>
    </div>
  );
}

export function Button({
  children,
  onClick,
  tone = "plain",
  disabled,
  size = "md",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  tone?: "plain" | "accent" | "bad" | "solid";
  disabled?: boolean;
  size?: "sm" | "md";
}) {
  const tones = {
    plain: "border-line hover:border-muted text-text",
    accent: "border-accent/60 text-accent hover:bg-accent/10",
    bad: "border-bad/60 text-bad hover:bg-bad/10",
    solid: "border-accent bg-accent text-black hover:bg-accent/90 font-semibold",
  }[tone];

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`border rounded-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
        size === "sm" ? "px-2.5 h-7 text-[11.5px]" : "px-3 h-8 text-[12.5px]"
      } ${tones}`}
    >
      {children}
    </button>
  );
}

/** A row of mutually exclusive buttons, as used for timeframes and filters. */
export function Segmented<T extends string | number>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex border hair rounded-sm overflow-hidden">
      {options.map((o) => (
        <button
          key={String(o.value)}
          onClick={() => onChange(o.value)}
          className={`px-2.5 h-7 text-[11.5px] border-r hair last:border-r-0 transition-colors ${
            value === o.value ? "bg-raised text-accent" : "text-dim hover:text-text"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function statusTone(status: number) {
  if (status >= 500) return "text-bad";
  if (status === 403) return "text-bad";
  if (status === 429) return "text-warn";
  if (status >= 400) return "text-warn";
  return "text-good";
}

export function cacheTone(cache: string | null) {
  if (!cache) return "text-dim";
  if (cache === "HIT") return "text-good";
  if (cache.startsWith("STALE")) return "text-warn";
  return "text-dim";
}

export function ms(us: number) {
  if (us < 1000) return `${us}µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)}ms`;
  return `${(us / 1_000_000).toFixed(2)}s`;
}

export function clock(atMs: number) {
  return new Date(atMs).toLocaleTimeString("en-GB", { hour12: false });
}

export function ago(atMs: number) {
  const s = Math.max(0, Math.round((Date.now() - atMs) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function bytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
