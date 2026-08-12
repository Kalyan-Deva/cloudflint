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
}: {
  title?: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`border hair rounded bg-surface ${className}`}>
      {title && (
        <header className="flex items-center justify-between gap-4 px-4 h-10 border-b hair">
          <h2 className="text-[13px] font-medium tracking-tight">{title}</h2>
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone = "plain",
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "plain" | "accent" | "danger" | "good";
}) {
  const colour = {
    plain: "text-text",
    accent: "text-accent",
    danger: "text-danger",
    good: "text-good",
  }[tone];

  return (
    <div className="border hair rounded bg-surface px-4 py-3">
      <div className="text-[11px] uppercase tracking-wider text-muted">{label}</div>
      <div className={`mt-1 text-[22px] leading-none tabular ${colour}`}>{value}</div>
      {hint && <div className="mt-1.5 text-[12px] text-muted tabular">{hint}</div>}
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="px-4 py-8 text-center text-[13px] text-muted">{children}</div>;
}

export function Problem({ error }: { error: string }) {
  return (
    <div className="border hair rounded bg-surface px-4 py-3 text-[13px]">
      <span className="text-danger">Not available.</span>{" "}
      <span className="text-muted">{error}</span>
    </div>
  );
}

export function Button({
  children,
  onClick,
  tone = "plain",
  disabled,
  type = "button",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  tone?: "plain" | "accent" | "danger";
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  const tones = {
    plain: "border-line hover:border-muted text-text",
    accent: "border-accent/60 text-accent hover:bg-accent/10",
    danger: "border-danger/60 text-danger hover:bg-danger/10",
  }[tone];

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`border rounded px-3 h-8 text-[13px] transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${tones}`}
    >
      {children}
    </button>
  );
}

export function statusTone(status: number) {
  if (status >= 500) return "text-danger";
  if (status === 429) return "text-warn";
  if (status === 403) return "text-danger";
  if (status >= 400) return "text-warn";
  return "text-good";
}

export function cacheTone(cache: string | null) {
  if (!cache) return "text-muted";
  if (cache === "HIT") return "text-good";
  if (cache.startsWith("STALE")) return "text-warn";
  return "text-muted";
}

export function ms(us: number) {
  if (us < 1000) return `${us}µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)}ms`;
  return `${(us / 1_000_000).toFixed(2)}s`;
}

export function clock(atMs: number) {
  const d = new Date(atMs);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

/** A flat proportion bar. Colour means something; it is never decoration. */
export function Meter({ parts }: { parts: { label: string; value: number; colour: string }[] }) {
  const total = parts.reduce((sum, p) => sum + p.value, 0);
  if (total === 0) return <div className="h-1.5 rounded-sm bg-raised" />;

  return (
    <div className="flex h-1.5 rounded-sm overflow-hidden bg-raised">
      {parts.map((p) => (
        <div
          key={p.label}
          title={`${p.label}: ${p.value}`}
          style={{ width: `${(p.value / total) * 100}%`, background: p.colour }}
        />
      ))}
    </div>
  );
}
