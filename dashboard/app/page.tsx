"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Cell,
  Panel,
  Problem,
  Row,
  Segmented,
  Tag,
  ago,
  api,
  bytes,
  cacheTone,
  clock,
  ms,
  statusTone,
  useApi,
} from "@/lib/ui";

type Zone = {
  name: string;
  hostnames: string[];
  origin: string;
  preserve_host: boolean;
  origin_timeout_ms: number;
  waf_rules: string[];
  waf_reads_body: boolean;
  cache_enabled: boolean;
  cache_vary_on: string[];
  cache_overrides: string[];
  rate_limits: string[];
  adaptive: boolean;
};

type Summary = {
  requests: number;
  errors: number;
  blocked: number;
  rate_limited: number;
  cache_hits: number;
  cache_eligible: number;
  p50_us: number;
  p95_us: number;
  by_stage: [string, number][];
  top_paths: [string, number][];
  top_ips: [string, number][];
};

type Bucket = {
  at_ms: number;
  requests: number;
  blocked: number;
  limited: number;
  errors: number;
  cache_hits: number;
  p95_us: number;
};

type Event = {
  at_ms: number;
  zone: string;
  host: string;
  method: string;
  path: string;
  status: number;
  duration_us: number;
  decided_by: string;
  cache: string | null;
  client_ip: string;
};

type EdgeStats = {
  zones: number;
  cache: { entries: number; bytes: number };
  events: { seen: number; dropped: number };
  uptime_s: number;
};

const WINDOWS = [
  { value: 15, label: "15m" },
  { value: 60, label: "1H" },
  { value: 360, label: "6H" },
  { value: 1440, label: "24H" },
  { value: 10080, label: "7D" },
];

export default function Dashboard() {
  const zones = useApi<{ revision: number; zones: Zone[] }>("/api/cp/v1/zones");
  const [zone, setZone] = useState("");
  const [mins, setMins] = useState(60);

  useEffect(() => {
    if (!zone && zones.data?.zones.length) setZone(zones.data.zones[0].name);
  }, [zones.data, zone]);

  const scope = zone ? `zone=${encodeURIComponent(zone)}&` : "";
  const summary = useApi<Summary>(`/api/cp/v1/analytics/summary?${scope}since_mins=${mins}`, [zone, mins]);
  const series = useApi<{ buckets: Bucket[] }>(
    `/api/cp/v1/analytics/timeseries?${scope}since_mins=${mins}&buckets=64`,
    [zone, mins],
  );
  const edge = useApi<EdgeStats>("/api/edge/stats");

  if (zones.error) return <Problem error={zones.error} />;
  const current = zones.data?.zones.find((z) => z.name === zone);

  return (
    <div className="space-y-4">
      <Hero
        zone={current}
        revision={zones.data?.revision}
        zones={zones.data?.zones ?? []}
        selected={zone}
        onSelect={setZone}
        summary={summary.data}
      />

      <div className="grid lg:grid-cols-3 gap-4">
        <Panel title="security" info="What the WAF and the rate limiter turned away.">
          <div className="p-4 grid grid-cols-2 gap-y-3.5">
            <Cell
              label="blocked"
              value={summary.data?.blocked ?? 0}
              tone={summary.data && summary.data.blocked > 0 ? "bad" : undefined}
              hint="by the waf"
            />
            <Cell
              label="rate limited"
              value={summary.data?.rate_limited ?? 0}
              tone={summary.data && summary.data.rate_limited > 0 ? "warn" : undefined}
              hint="429s"
            />
            <Cell label="rules active" value={current?.waf_rules.length ?? 0} />
            <Cell
              label="body inspection"
              value={current?.waf_reads_body ? "on" : "off"}
              hint={current?.waf_reads_body ? "bodies buffered" : "head only"}
            />
          </div>
        </Panel>

        <Panel title="cache" info="Hits never reached your origin.">
          <div className="p-4 grid grid-cols-2 gap-y-3.5">
            <Cell
              label="hit ratio"
              value={`${hitRate(summary.data)}%`}
              tone={hitRate(summary.data) >= 50 ? "good" : undefined}
              hint={`${summary.data?.cache_hits ?? 0} of ${summary.data?.cache_eligible ?? 0}`}
            />
            <Cell label="entries" value={edge.data?.cache.entries ?? 0} hint="on this edge" />
            <Cell label="held" value={bytes(edge.data?.cache.bytes ?? 0)} />
            <Cell label="varies on" value={current?.cache_vary_on.join(", ") || "—"} />
          </div>
        </Panel>

        <Panel title="latency & origin" info="Time to answer, measured at the edge.">
          <div className="p-4 grid grid-cols-2 gap-y-3.5">
            <Cell label="p50" value={ms(summary.data?.p50_us ?? 0)} />
            <Cell label="p95" value={ms(summary.data?.p95_us ?? 0)} />
            <Cell
              label="errors"
              value={summary.data?.errors ?? 0}
              tone={summary.data && summary.data.errors > 0 ? "bad" : undefined}
              hint="5xx"
            />
            <Cell
              label="events dropped"
              value={edge.data?.events.dropped ?? 0}
              hint={`${edge.data?.events.seen ?? 0} seen`}
            />
          </div>
        </Panel>
      </div>

      <div className="grid xl:grid-cols-[1fr_330px] gap-4 items-start">
        <div className="space-y-4">
          <Panel
            title="traffic"
            aside={<Segmented options={WINDOWS} value={mins} onChange={setMins} />}
          >
            <Chart buckets={series.data?.buckets ?? []} loading={series.loading} />
          </Panel>

          <Tabs summary={summary.data} zone={current} />
        </div>

        <div className="space-y-4">
          <Purge zones={zones.data?.zones ?? []} />
          <Feed />
        </div>
      </div>
    </div>
  );
}

function hitRate(s: Summary | null | undefined) {
  return s && s.cache_eligible > 0 ? Math.round((s.cache_hits / s.cache_eligible) * 100) : 0;
}

function Hero({
  zone,
  zones,
  selected,
  onSelect,
  revision,
  summary,
}: {
  zone?: Zone;
  zones: Zone[];
  selected: string;
  onSelect: (z: string) => void;
  revision?: number;
  summary?: Summary | null;
}) {
  return (
    <section className="border hair rounded-sm bg-panel">
      <div className="p-5 flex flex-wrap gap-6 items-start">
        <div className="w-11 h-11 rounded-full bg-accent flex items-center justify-center text-black text-[17px] font-bold shrink-0">
          {(zone?.name ?? "?")[0].toUpperCase()}
        </div>

        <div className="flex-1 min-w-[280px]">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-[21px] leading-none">{zone?.name ?? "no zones"}</h1>
            <span className="border border-accent/50 text-accent rounded-sm px-1.5 py-0.5 text-[10px] tracking-wider uppercase">
              {zone?.cache_enabled ? "active" : "cache off"}
            </span>
            {zones.length > 1 && (
              <select
                value={selected}
                onChange={(e) => onSelect(e.target.value)}
                className="w-auto h-6 py-0 text-[11.5px]"
              >
                {zones.map((z) => (
                  <option key={z.name}>{z.name}</option>
                ))}
              </select>
            )}
          </div>

          <p className="text-[12.5px] text-muted mt-1.5">
            Zone on Cloudveil {revision !== undefined && `· config revision ${revision}`}
          </p>
          <p className="text-[12.5px] text-muted mt-2 max-w-[560px]">
            Fronting <span className="text-text">{zone?.origin ?? "—"}</span>. Requests are rate
            limited, inspected by the WAF, then served from cache where allowed — the origin only
            sees what none of those could answer.
          </p>

          <div className="flex gap-1.5 mt-3 flex-wrap">
            {(zone?.hostnames ?? []).map((h) => (
              <Tag key={h}>{h}</Tag>
            ))}
          </div>
        </div>

        <div className="border-l hair pl-6 min-w-[190px]">
          <div className="cap">requests served</div>
          <div className="text-[26px] leading-tight tabular text-accent">
            {(summary?.requests ?? 0).toLocaleString()}
          </div>
          <div className="text-[11.5px] text-dim tabular">
            {(summary?.blocked ?? 0) + (summary?.rate_limited ?? 0)} turned away
          </div>
        </div>

        <div className="min-w-[210px] space-y-0.5">
          <Row k="ORIGIN" v={zone?.origin ?? "—"} mono />
          <Row k="HOST HEADER" v={zone?.preserve_host ? "passed through" : "rewritten"} />
          <Row k="TIMEOUT" v={`${zone?.origin_timeout_ms ?? 0} ms`} mono />
          <Row k="ADAPTIVE" v={zone?.adaptive ? "on" : "off"} />
        </div>
      </div>
    </section>
  );
}

/* Stacked bars per bucket, with the slowest request in each drawn underneath -
   the same shape as a price chart with volume, for the same reason: one glance
   should show both how much happened and how bad it was. */
function Chart({ buckets, loading }: { buckets: Bucket[]; loading: boolean }) {
  const [hover, setHover] = useState<number | null>(null);

  const { peak, slowest } = useMemo(() => {
    let peak = 1;
    let slowest = 1;
    for (const b of buckets) {
      peak = Math.max(peak, b.requests);
      slowest = Math.max(slowest, b.p95_us);
    }
    return { peak, slowest };
  }, [buckets]);

  if (loading && buckets.length === 0) {
    return <div className="h-[260px] grid place-items-center text-[12px] text-dim">loading…</div>;
  }
  if (buckets.length === 0) {
    return (
      <div className="h-[260px] grid place-items-center text-[12px] text-dim">
        No traffic in this window. Send some through the edge.
      </div>
    );
  }

  const shown = hover !== null ? buckets[hover] : buckets[buckets.length - 1];
  const width = 100 / buckets.length;

  return (
    <div className="p-4">
      <div className="flex items-baseline gap-5 text-[11.5px] mb-3 flex-wrap">
        <span className="text-muted">
          {hover !== null ? clock(shown.at_ms) : "latest"}
        </span>
        <Legend colour="var(--color-accent)" label="ok" value={okOf(shown)} />
        <Legend colour="var(--color-bad)" label="blocked" value={shown.blocked} />
        <Legend colour="var(--color-warn)" label="limited" value={shown.limited} />
        <Legend colour="var(--color-bad)" label="errors" value={shown.errors} />
        <span className="ml-auto text-dim tabular">peak {peak}/bucket</span>
      </div>

      <svg
        viewBox="0 0 100 46"
        preserveAspectRatio="none"
        className="w-full h-[200px]"
        onMouseLeave={() => setHover(null)}
      >
        {[0.25, 0.5, 0.75].map((g) => (
          <line
            key={g}
            x1="0"
            x2="100"
            y1={34 * g}
            y2={34 * g}
            stroke="var(--color-line-soft)"
            strokeWidth="0.15"
          />
        ))}

        {buckets.map((b, i) => {
          const x = i * width;
          const scale = (n: number) => (n / peak) * 32;
          const ok = okOf(b);
          const parts = [
            { h: scale(ok), fill: "var(--color-accent)" },
            { h: scale(b.limited), fill: "var(--color-warn)" },
            { h: scale(b.blocked), fill: "var(--color-bad)" },
            { h: scale(b.errors), fill: "#8a2f2a" },
          ];
          let y = 34;
          return (
            <g key={b.at_ms} onMouseEnter={() => setHover(i)}>
              <rect x={x} y={0} width={width} height={46} fill="transparent" />
              {parts.map((p, n) => {
                y -= p.h;
                return (
                  <rect
                    key={n}
                    x={x + width * 0.15}
                    y={y}
                    width={width * 0.7}
                    height={Math.max(p.h, p.h > 0 ? 0.35 : 0)}
                    fill={p.fill}
                    opacity={hover === null || hover === i ? 1 : 0.45}
                  />
                );
              })}
              {/* slowest request in the bucket, the "volume" row */}
              <rect
                x={x + width * 0.15}
                y={46 - (b.p95_us / slowest) * 9}
                width={width * 0.7}
                height={(b.p95_us / slowest) * 9}
                fill="var(--color-dim)"
                opacity={hover === null || hover === i ? 0.5 : 0.22}
              />
            </g>
          );
        })}
        <line x1="0" x2="100" y1="34" y2="34" stroke="var(--color-line)" strokeWidth="0.2" />
      </svg>

      <div className="flex justify-between text-[10.5px] text-dim tabular mt-1.5">
        <span>{clock(buckets[0].at_ms)}</span>
        <span>slowest in view {ms(slowest)}</span>
        <span>{clock(buckets[buckets.length - 1].at_ms)}</span>
      </div>
    </div>
  );
}

function okOf(b: Bucket) {
  return Math.max(0, b.requests - b.blocked - b.limited - b.errors);
}

function Legend({ colour, label, value }: { colour: string; label: string; value: number }) {
  return (
    <span className="flex items-center gap-1.5">
      <i className="w-2 h-2 rounded-[1px] inline-block" style={{ background: colour }} />
      <span className="text-dim">{label}</span>
      <span className="tabular">{value}</span>
    </span>
  );
}

const TABS = ["top paths", "top clients", "answered by", "zone"] as const;

function Tabs({ summary, zone }: { summary?: Summary | null; zone?: Zone }) {
  const [tab, setTab] = useState<(typeof TABS)[number]>("top paths");

  return (
    <section className="border hair rounded-sm bg-panel">
      <div className="flex border-b hair overflow-x-auto">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 h-10 cap border-b-2 -mb-px transition-colors whitespace-nowrap ${
              tab === t ? "border-accent text-accent" : "border-transparent hover:text-text"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "top paths" && <Ranked rows={summary?.top_paths ?? []} />}
      {tab === "top clients" && <Ranked rows={summary?.top_ips ?? []} />}
      {tab === "answered by" && <Ranked rows={summary?.by_stage ?? []} />}
      {tab === "zone" && (
        <div className="p-4 grid md:grid-cols-2 gap-x-8 gap-y-1">
          <Row k="ORIGIN" v={zone?.origin ?? "—"} mono />
          <Row k="HOSTNAMES" v={zone?.hostnames.join(", ") ?? "—"} mono />
          <Row k="WAF RULES" v={zone?.waf_rules.length ?? 0} />
          <Row k="READS BODIES" v={zone?.waf_reads_body ? "yes" : "no"} />
          <Row k="CACHE" v={zone?.cache_enabled ? "on" : "off"} />
          <Row k="VARIES ON" v={zone?.cache_vary_on.join(", ") || "—"} />
          <Row k="OVERRIDES" v={zone?.cache_overrides.join(" · ") || "none"} mono />
          <Row k="RATE LIMITS" v={zone?.rate_limits.join(" · ") || "none"} mono />
        </div>
      )}
    </section>
  );
}

function Ranked({ rows }: { rows: [string, number][] }) {
  const most = rows.reduce((m, r) => Math.max(m, r[1]), 0);
  if (rows.length === 0) {
    return <div className="px-4 py-8 text-center text-[12px] text-dim">Nothing yet.</div>;
  }
  return (
    <ul>
      {rows.map(([label, n]) => (
        <li
          key={label}
          className="relative flex items-center justify-between gap-4 px-4 h-8 border-b hair last:border-b-0"
        >
          <span
            className="absolute inset-y-0 left-0 bg-accent/10"
            style={{ width: `${(n / most) * 100}%` }}
          />
          <span className="relative truncate text-[12px]" title={label}>
            {label}
          </span>
          <span className="relative text-[12px] text-muted tabular shrink-0">{n}</span>
        </li>
      ))}
    </ul>
  );
}

function Purge({ zones }: { zones: Zone[] }) {
  const [kind, setKind] = useState<"url" | "tag" | "zone" | "all">("url");
  const [value, setValue] = useState("");
  const [said, setSaid] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setSaid(null);
    try {
      const body = kind === "all" ? { all: true } : { [kind]: value };
      const out = await api<{ edges: { edge: string; ok: boolean; detail: string }[] }>(
        "/api/cp/v1/purge",
        { method: "POST", body: JSON.stringify(body) },
      );
      setSaid(out.edges.map((e) => `${e.ok ? "ok" : "failed"} — ${e.detail}`).join("\n"));
    } catch (e) {
      setSaid((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="purge cache">
      <div className="p-4 space-y-3">
        <Segmented
          options={[
            { value: "url", label: "url" },
            { value: "tag", label: "tag" },
            { value: "zone", label: "zone" },
            { value: "all", label: "all" },
          ]}
          value={kind}
          onChange={(k) => {
            setKind(k);
            setValue(k === "zone" ? (zones[0]?.name ?? "") : "");
          }}
        />

        {kind !== "all" && (
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={
              kind === "url" ? "http://demo.local/page" : kind === "tag" ? "nav" : "demo"
            }
          />
        )}

        <Button onClick={run} tone={kind === "all" ? "bad" : "accent"} disabled={busy}>
          {busy ? "purging…" : kind === "all" ? "Purge everything" : `Purge by ${kind}`}
        </Button>

        {said && (
          <pre className="border hair rounded-sm bg-base px-2.5 py-2 text-[11px] whitespace-pre-wrap">
            {said}
          </pre>
        )}

        <p className="text-[11px] text-dim">
          Purges go to the edges — that is where the cache is. Each reports back separately.
        </p>
      </div>
    </Panel>
  );
}

/* The alert feed. Only the interesting requests: anything the edge turned away,
   newest first, refreshed on a timer rather than streamed - this is a summary,
   the Logs page is the tail. */
function Feed() {
  const [events, setEvents] = useState<Event[]>([]);

  useEffect(() => {
    let live = true;
    const tick = () =>
      api<Event[]>("/api/edge/recent?limit=120")
        .then((all) => live && setEvents(all))
        .catch(() => {});
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, []);

  const notable = events.filter((e) => e.status >= 400).slice(0, 6);

  return (
    <Panel
      title="recent alerts"
      aside={
        <a href="/logs" className="text-[11px] text-accent hover:underline">
          view all →
        </a>
      }
    >
      {notable.length === 0 ? (
        <div className="px-4 py-8 text-center text-[12px] text-dim">
          Nothing has been turned away yet.
        </div>
      ) : (
        <ul>
          {notable.map((e, i) => (
            <li key={`${e.at_ms}-${i}`} className="px-4 py-2.5 border-b hair last:border-b-0">
              <div className="flex items-center gap-2">
                <span
                  className={`border rounded-sm px-1.5 text-[10px] uppercase tracking-wider ${badge(
                    e.status,
                  )}`}
                >
                  {word(e.status)}
                </span>
                <span className="text-[11px] text-dim">{ago(e.at_ms)}</span>
                <span className="ml-auto text-[11px] text-dim tabular">{ms(e.duration_us)}</span>
              </div>
              <div className="text-[12px] mt-1 truncate" title={e.path}>
                {e.method} {e.path}
              </div>
              <div className="text-[11px] text-dim mt-0.5">
                {e.client_ip} · turned away by {e.decided_by}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function word(status: number) {
  if (status === 403) return "blocked";
  if (status === 429) return "limited";
  if (status >= 500) return "error";
  return "warn";
}

function badge(status: number) {
  if (status === 403 || status >= 500) return "border-bad/50 text-bad";
  if (status === 429) return "border-warn/50 text-warn";
  return "border-line text-muted";
}
