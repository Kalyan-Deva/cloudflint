"use client";

import { useEffect, useState } from "react";
import { Button, Cell, Panel, Problem, Row, Tag, ago, bytes, clock, useApi } from "@/lib/ui";

type Cert = {
  zone: string;
  mode: string;
  status: string;
  deployed: boolean;
  not_after_ms: number | null;
};

type Node = {
  edge_id: string;
  region: string | null;
  label: string | null;
  version: string;
  started_at_ms: number;
  first_seen_ms: number;
  last_seen_ms: number;
  last_seen_age_s: number;
  uptime_s: number;
  active_revision: number;
  acked_at_ms: number | null;
  up_to_date: boolean;
  draining: boolean;
  status: string;
  note: string | null;
  cpu_percent: number;
  memory_bytes: number;
  memory_total_bytes: number;
  connections_active: number;
  requests_total: number;
  requests_per_sec: number;
  cache_entries: number;
  cache_bytes: number;
  zones: number;
  origins_total: number;
  origins_healthy: number;
  certificates: Cert[];
};

type Fleet = {
  desired_revision: number | null;
  offline_after_s: number;
  counts: {
    total: number;
    online: number;
    degraded: number;
    offline: number;
    up_to_date: number;
  };
  regions: { region: string; total: number; online: number }[];
  edges: Node[];
};

/* -1 is the edge saying it follows a local file rather than this control plane */
const NO_REVISION = -1;

const DOT: Record<string, string> = {
  online: "bg-good",
  degraded: "bg-warn",
  offline: "bg-bad",
};

export default function FleetPage() {
  const { data, error, reload } = useApi<Fleet>("/api/cp/v1/edges");
  const [live, setLive] = useState(true);

  useEffect(() => {
    if (!live) return;
    const t = setInterval(reload, 5000);
    return () => clearInterval(t);
  }, [live, reload]);

  if (error) return <Problem error={error} />;

  const counts = data?.counts;
  const nodes = data?.edges ?? [];
  const desired = data?.desired_revision ?? null;
  /* a node we cannot hear from contributes nothing to either number - it is not
     serving traffic we know about, and its config revision is only a memory */
  const reachable = nodes.filter((n) => n.status !== "offline");
  const rps = reachable.reduce((sum, n) => sum + n.requests_per_sec, 0);
  const onRevision = reachable.filter((n) => n.up_to_date).length;

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-[17px] tracking-tight">Fleet</h1>
          <p className="text-[13px] text-muted">
            Every node that has reported in. Nodes register themselves by heartbeating, so
            this is what is actually running — not what anyone was told to deploy.
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

      <Panel
        title="Fleet"
        info={`A node is called offline once it has not been heard from for ${
          data?.offline_after_s ?? 45
        } seconds — three missed heartbeats rather than one, so a lost packet is not an outage.`}
        aside={
          desired !== null ? <Tag>fleet config revision {desired}</Tag> : <Tag>no config yet</Tag>
        }
      >
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 px-4 py-3">
          <Cell label="Nodes" value={counts?.total ?? 0} hint="known here" />
          <Cell
            label="Online"
            value={counts?.online ?? 0}
            tone={counts && counts.online > 0 ? "good" : undefined}
          />
          <Cell
            label="Degraded"
            value={counts?.degraded ?? 0}
            tone={counts && counts.degraded > 0 ? "warn" : undefined}
          />
          <Cell
            label="Offline"
            value={counts?.offline ?? 0}
            tone={counts && counts.offline > 0 ? "bad" : undefined}
          />
          <Cell
            label="Requests/s"
            value={rps.toFixed(1)}
            hint="across the fleet"
            tone="accent"
          />
        </div>

        {/* the rollout, drawn. counted over nodes we can still hear from: an offline
            node's revision is the last thing it said, not a fact about now, and
            counting it would report a rollout as complete while part of the fleet is
            dark. the offline count above is where those nodes are accounted for */}
        {desired !== null && reachable.length > 0 && (
          <div className="px-4 pb-3">
            <div className="flex items-baseline justify-between text-[11.5px] mb-1">
              <span className="cap">Config rollout</span>
              <span className="text-dim tabular">
                {onRevision} of {reachable.length} reachable on revision {desired}
                {(counts?.offline ?? 0) > 0 && (
                  <span className="text-bad"> · {counts?.offline} not answering</span>
                )}
              </span>
            </div>
            <div className="h-[3px] bg-raised rounded-sm overflow-hidden">
              <div
                className={
                  onRevision === reachable.length ? "h-full bg-good" : "h-full bg-warn"
                }
                style={{ width: `${(onRevision / reachable.length) * 100}%` }}
              />
            </div>
          </div>
        )}
      </Panel>

      {(data?.regions.length ?? 0) > 1 && (
        <Panel
          title="Regions"
          info="Grouped by the region each node reports. A whole POP going dark is the thing this is for."
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 px-4 py-3">
            {data?.regions.map((r) => (
              <Cell
                key={r.region}
                label={r.region}
                value={`${r.online} of ${r.total}`}
                hint="online"
                tone={r.online === 0 ? "bad" : r.online < r.total ? "warn" : "good"}
              />
            ))}
          </div>
        </Panel>
      )}

      {nodes.map((n) => (
        <NodePanel key={n.edge_id} n={n} desired={desired} onForget={reload} />
      ))}

      {nodes.length === 0 && (
        <Panel>
          <div className="px-4 py-6 text-[13px] text-muted">
            No node has reported in yet. An edge registers itself once it has a{" "}
            <span className="text-text">control_plane</span> to report to — set{" "}
            <span className="text-text">CLOUDFLINT_EDGE_ID</span> and{" "}
            <span className="text-text">CLOUDFLINT_REGION</span> on each one so they can be
            told apart.
          </div>
        </Panel>
      )}
    </div>
  );
}

function NodePanel({
  n,
  desired,
  onForget,
}: {
  n: Node;
  desired: number | null;
  onForget: () => void;
}) {
  const [forgetting, setForgetting] = useState(false);
  const memPct =
    n.memory_total_bytes > 0 ? (n.memory_bytes / n.memory_total_bytes) * 100 : 0;

  async function forget() {
    setForgetting(true);
    try {
      await fetch(`/api/cp/v1/edges/${encodeURIComponent(n.edge_id)}`, { method: "DELETE" });
      onForget();
    } finally {
      setForgetting(false);
    }
  }

  return (
    <Panel
      title={n.edge_id}
      info={n.label ?? undefined}
      aside={
        <div className="flex items-center gap-2">
          {n.region && <Tag>{n.region}</Tag>}
          <Tag>v{n.version}</Tag>
          <span
            className={`inline-block w-1.5 h-1.5 rounded-full ${DOT[n.status] ?? "bg-dim"}`}
            title={n.status}
          />
          <span
            className={`text-[11px] ${
              n.status === "online"
                ? "text-good"
                : n.status === "degraded"
                  ? "text-warn"
                  : "text-bad"
            }`}
          >
            {n.status.toUpperCase()}
          </span>
        </div>
      }
    >
      {n.note && (
        <div className="px-4 py-2 border-b hair text-[12.5px] text-warn">{n.note}</div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 px-4 py-3 border-b hair">
        <Cell
          label="Last heartbeat"
          value={n.last_seen_age_s < 1 ? "just now" : `${n.last_seen_age_s}s ago`}
          hint={clock(n.last_seen_ms)}
          tone={n.status === "offline" ? "bad" : undefined}
        />
        <Cell label="Requests/s" value={n.requests_per_sec.toFixed(1)} tone="accent" />
        <Cell
          label="Connections"
          value={n.connections_active.toLocaleString()}
          hint="in flight"
        />
        <Cell label="CPU" value={`${n.cpu_percent.toFixed(1)}%`} />
        <Cell label="Memory" value={bytes(n.memory_bytes)} hint={`${memPct.toFixed(1)}% of host`} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-1 px-4 py-3">
        <Row
          k="Config revision"
          v={
            n.active_revision === NO_REVISION ? (
              <span className="text-dim">local file</span>
            ) : n.up_to_date ? (
              <span className="text-good">{n.active_revision} · current</span>
            ) : (
              <span className="text-warn">
                {n.active_revision} · fleet on {desired}
              </span>
            )
          }
        />
        <Row
          k="Acknowledged"
          v={n.acked_at_ms ? ago(n.acked_at_ms) : <span className="text-dim">—</span>}
        />
        <Row k="Up for" v={uptime(n.uptime_s)} />
        <Row k="Started" v={clock(n.started_at_ms)} />
        <Row k="First seen" v={ago(n.first_seen_ms)} />
        <Row k="Zones" v={n.zones} />
        <Row
          k="Origins"
          v={
            n.origins_total === 0 ? (
              <span className="text-dim">none</span>
            ) : (
              <span className={n.origins_healthy < n.origins_total ? "text-bad" : "text-good"}>
                {n.origins_healthy} of {n.origins_total} healthy
              </span>
            )
          }
        />
        <Row k="Cache" v={`${n.cache_entries.toLocaleString()} · ${bytes(n.cache_bytes)}`} />
        <Row k="Requests total" v={n.requests_total.toLocaleString()} />
      </div>

      {n.certificates.length > 0 && (
        <div className="px-4 py-3 border-t hair">
          <div className="cap mb-1.5">Certificates</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
            {n.certificates.map((c) => (
              <Row
                key={c.zone}
                k={c.zone}
                v={
                  <span className="flex items-center gap-1.5 justify-end">
                    <span className="text-dim text-[11px]">{c.mode}</span>
                    <span
                      className={
                        !c.deployed || c.status === "expired"
                          ? "text-bad"
                          : c.status === "expiring"
                            ? "text-warn"
                            : "text-good"
                      }
                    >
                      {c.deployed ? c.status : "not deployed"}
                    </span>
                    {c.not_after_ms && (
                      <span className="text-dim text-[11px]">
                        · {daysLeft(c.not_after_ms)}
                      </span>
                    )}
                  </span>
                }
              />
            ))}
          </div>
        </div>
      )}

      {/* only worth offering for a node that is gone: forgetting a live one just means
          it reappears on its next heartbeat */}
      {n.status === "offline" && (
        <div className="px-4 py-2.5 border-t hair flex items-center justify-between gap-4">
          <span className="text-[12px] text-muted">
            Decommissioned? Forgetting it clears it from the fleet. A node that is merely
            unreachable will come back on its next heartbeat.
          </span>
          <Button tone="bad" size="sm" onClick={forget} disabled={forgetting}>
            {forgetting ? "forgetting…" : "forget"}
          </Button>
        </div>
      )}
    </Panel>
  );
}

function uptime(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

function daysLeft(atMs: number) {
  const days = Math.round((atMs - Date.now()) / 86_400_000);
  if (days < 0) return "expired";
  if (days === 0) return "today";
  return `${days}d left`;
}
