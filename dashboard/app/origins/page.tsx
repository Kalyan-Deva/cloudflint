"use client";

import { useEffect, useState } from "react";
import { Cell, Panel, Problem, Row, Tag, ago, clock, useApi } from "@/lib/ui";

type Backend = {
  origin: string;
  authority: string;
  healthy: boolean;
  weight: number;
  in_flight: number;
  requests: number;
  errors: number;
  traffic_share: number;
  error_rate: number;
  p50_ms: number | null;
  p95_ms: number | null;
  probes_ok: number;
  probes_failed: number;
};

type ZoneOrigins = {
  zone: string;
  strategy: string;
  probe: { path: string; every_secs: number } | null;
  unhealthy_after: number;
  retry_after_secs: number;
  requests: number;
  failovers: number;
  origins: Backend[];
};

type Failover = { at_ms: number; zone: string; from: string; to: string };

type Report = { zones: ZoneOrigins[]; recent_failovers: Failover[] };

const STRATEGY: Record<string, string> = {
  first_healthy: "Earlier origins are preferred — a primary with backups behind it.",
  round_robin: "One request each in turn, among the healthy origins.",
  weighted: "In proportion to each origin's weight, interleaved rather than in runs.",
  least_connections: "Whichever healthy origin has the fewest requests in flight.",
};

export default function Origins() {
  /* origin health is the edge's own view - the control plane only knows what the config
     says, not which backend answered a minute ago */
  const { data, error, reload } = useApi<Report>("/api/edge/origins");
  const [live, setLive] = useState(true);

  useEffect(() => {
    if (!live) return;
    const t = setInterval(reload, 3000);
    return () => clearInterval(t);
  }, [live, reload]);

  if (error) return <Problem error={error} />;

  const zones = data?.zones ?? [];
  const failovers = data?.recent_failovers ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-[17px] tracking-tight">Origins</h1>
          <p className="text-[13px] text-muted">
            What this edge thinks of each backend, and how it is sharing traffic between
            them. Counts are since the node started.
          </p>
        </div>
        <button
          onClick={() => setLive((v) => !v)}
          className={`border hair rounded-sm px-2.5 h-7 text-[11.5px] transition-colors ${
            live ? "text-accent border-accent/60" : "text-dim"
          }`}
        >
          {live ? "live" : "paused"}
        </button>
      </div>

      {zones.map((zone) => (
        <Panel
          key={zone.zone}
          title={zone.zone}
          info={STRATEGY[zone.strategy] ?? zone.strategy}
          aside={
            <div className="flex items-center gap-2">
              <Tag>{zone.strategy.replace(/_/g, " ")}</Tag>
              {zone.probe ? (
                <Tag>
                  probing {zone.probe.path} · {zone.probe.every_secs}s
                </Tag>
              ) : (
                <Tag>passive health only</Tag>
              )}
            </div>
          }
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 px-4 py-3 border-b hair">
            <Cell label="Requests" value={zone.requests.toLocaleString()} hint="to origins" />
            <Cell
              label="Origins up"
              value={`${zone.origins.filter((o) => o.healthy).length} of ${zone.origins.length}`}
              tone={zone.origins.every((o) => o.healthy) ? "good" : "bad"}
            />
            <Cell
              label="Failovers"
              value={zone.failovers.toLocaleString()}
              tone={zone.failovers > 0 ? "warn" : undefined}
              hint="requests moved on"
            />
            <Cell
              label="Out after"
              value={`${zone.unhealthy_after} fails`}
              hint={`back in ${zone.retry_after_secs}s`}
            />
          </div>

          <div className="divide-y divide-[var(--color-line)]">
            {zone.origins.map((o) => (
              <Backend key={o.authority} o={o} strategy={zone.strategy} />
            ))}
          </div>
        </Panel>
      ))}

      <Panel
        title="Failover events"
        info="A request that could not reach its first choice and was sent to another origin. Only the last 32 are kept."
      >
        {failovers.length === 0 ? (
          <div className="px-4 py-6 text-[13px] text-muted">
            Nothing has failed over. That is the number you want.
          </div>
        ) : (
          <div className="divide-y divide-[var(--color-line)]">
            {failovers.map((f, i) => (
              <div
                key={`${f.at_ms}-${i}`}
                className="flex items-baseline gap-3 px-4 py-2 text-[12.5px]"
              >
                <span className="text-dim tabular w-[68px] shrink-0">{clock(f.at_ms)}</span>
                <span className="text-warn w-[64px] shrink-0">MOVED</span>
                <span className="truncate">
                  <span className="text-bad">{f.from}</span>
                  <span className="text-dim"> → </span>
                  <span className="text-good">{f.to}</span>
                </span>
                <span className="ml-auto text-dim shrink-0">
                  {f.zone} · {ago(f.at_ms)}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {zones.length === 0 && (
        <Panel>
          <div className="px-4 py-6 text-[13px] text-muted">
            The active config has no zones.
          </div>
        </Panel>
      )}
    </div>
  );
}

function Backend({ o, strategy }: { o: Backend; strategy: string }) {
  const latency = (v: number | null) => (v === null ? "—" : `${v} ms`);

  return (
    <div className="px-4 py-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${
              o.healthy ? "bg-good" : "bg-bad"
            }`}
            title={o.healthy ? "in rotation" : "taken out"}
          />
          <span className="text-[13px] truncate" title={o.origin}>
            {o.origin}
          </span>
          {!o.healthy && <span className="text-[11px] text-bad shrink-0">OUT</span>}
          {strategy === "weighted" && (
            <span className="text-[11px] text-dim shrink-0">weight {o.weight}</span>
          )}
        </div>
        <div className="text-[11.5px] text-dim tabular shrink-0">
          {o.in_flight} in flight
        </div>
      </div>

      {/* traffic share, drawn rather than written: the point is the comparison */}
      <div className="mt-2 h-[3px] bg-raised rounded-sm overflow-hidden">
        <div
          className={o.healthy ? "h-full bg-accent" : "h-full bg-bad"}
          style={{ width: `${Math.max(o.traffic_share, o.requests > 0 ? 1 : 0)}%` }}
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-x-4 mt-2">
        <Row k="Traffic" v={`${o.traffic_share}%`} />
        <Row k="Requests" v={o.requests.toLocaleString()} />
        <Row
          k="Errors"
          v={
            <span className={o.errors > 0 ? "text-bad" : undefined}>
              {o.errors} · {o.error_rate}%
            </span>
          }
        />
        <Row
          k="Probes"
          v={
            o.probes_ok + o.probes_failed === 0 ? (
              "none"
            ) : (
              <>
                <span className="text-good">{o.probes_ok}</span>
                <span className="text-dim"> / </span>
                <span className={o.probes_failed > 0 ? "text-bad" : "text-dim"}>
                  {o.probes_failed}
                </span>
              </>
            )
          }
        />
        <Row k="p50" v={latency(o.p50_ms)} />
        <Row k="p95" v={latency(o.p95_ms)} />
      </div>
    </div>
  );
}
