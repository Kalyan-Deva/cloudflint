"use client";

import { useState } from "react";
import { Meter, Panel, Problem, Stat, ms, useApi } from "@/lib/ui";

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

const WINDOWS = [
  { label: "5m", mins: 5 },
  { label: "1h", mins: 60 },
  { label: "24h", mins: 1440 },
  { label: "7d", mins: 10080 },
];

const STAGE_COLOUR: Record<string, string> = {
  origin: "#7d9471",
  cache: "#c9784a",
  waf: "#b8574d",
  ratelimit: "#b8974d",
  route: "#8b9099",
};

export default function Overview() {
  const [mins, setMins] = useState(60);
  const { data, error } = useApi<Summary>(`/api/cp/v1/analytics/summary?since_mins=${mins}`, [mins]);

  if (error) return <Problem error={error} />;

  const s = data;
  const hitRate =
    s && s.cache_eligible > 0 ? Math.round((s.cache_hits / s.cache_eligible) * 100) : 0;

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-[17px] font-semibold tracking-tight">Overview</h1>
          <p className="text-[13px] text-muted">
            What the edge has been doing, as reported to the control plane.
          </p>
        </div>
        <div className="flex border hair rounded overflow-hidden shrink-0">
          {WINDOWS.map((w) => (
            <button
              key={w.mins}
              onClick={() => setMins(w.mins)}
              className={`px-3 h-8 text-[12px] border-r hair last:border-r-0 transition-colors ${
                mins === w.mins ? "bg-raised text-text" : "text-muted hover:text-text"
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Stat label="Requests" value={(s?.requests ?? 0).toLocaleString()} />
        <Stat
          label="Blocked"
          value={s?.blocked ?? 0}
          tone={s && s.blocked > 0 ? "danger" : "plain"}
          hint="by the waf"
        />
        <Stat
          label="Limited"
          value={s?.rate_limited ?? 0}
          tone={s && s.rate_limited > 0 ? "accent" : "plain"}
          hint="429s"
        />
        <Stat
          label="Errors"
          value={s?.errors ?? 0}
          tone={s && s.errors > 0 ? "danger" : "plain"}
          hint="5xx"
        />
        <Stat
          label="Cache"
          value={`${hitRate}%`}
          tone={hitRate >= 50 ? "good" : "plain"}
          hint={`${s?.cache_hits ?? 0} of ${s?.cache_eligible ?? 0} cacheable`}
        />
        <Stat
          label="Latency"
          value={ms(s?.p50_us ?? 0)}
          hint={`p95 ${ms(s?.p95_us ?? 0)}`}
        />
      </div>

      <Panel title="Answered by">
        <div className="p-4 space-y-3">
          <Meter
            parts={(s?.by_stage ?? []).map(([stage, n]) => ({
              label: stage,
              value: n,
              colour: STAGE_COLOUR[stage] ?? "#8b9099",
            }))}
          />
          <div className="flex flex-wrap gap-x-6 gap-y-1.5 text-[12px]">
            {(s?.by_stage ?? []).map(([stage, n]) => (
              <span key={stage} className="flex items-center gap-2">
                <i
                  className="w-2 h-2 rounded-[1px] inline-block"
                  style={{ background: STAGE_COLOUR[stage] ?? "#8b9099" }}
                />
                <span>{stage}</span>
                <span className="text-muted tabular">{n}</span>
              </span>
            ))}
            {(s?.by_stage ?? []).length === 0 && (
              <span className="text-muted">No traffic in this window.</span>
            )}
          </div>
          <p className="text-[12px] text-muted pt-1">
            A request answered by the cache or the waf never reached your origin at all.
          </p>
        </div>
      </Panel>

      <div className="grid md:grid-cols-2 gap-5">
        <Ranked title="Top paths" rows={s?.top_paths ?? []} />
        <Ranked title="Top clients" rows={s?.top_ips ?? []} mono />
      </div>
    </div>
  );
}

function Ranked({
  title,
  rows,
  mono,
}: {
  title: string;
  rows: [string, number][];
  mono?: boolean;
}) {
  const most = rows.reduce((m, r) => Math.max(m, r[1]), 0);

  return (
    <Panel title={title}>
      {rows.length === 0 ? (
        <div className="px-4 py-6 text-[13px] text-muted">Nothing yet.</div>
      ) : (
        <ul>
          {rows.map(([label, n]) => (
            <li
              key={label}
              className="relative flex items-center justify-between gap-4 px-4 h-8 border-b hair last:border-b-0"
            >
              <span
                className="absolute inset-y-0 left-0 bg-accent/8"
                style={{ width: `${(n / most) * 100}%` }}
              />
              <span
                className={`relative truncate text-[12.5px] ${mono ? "font-mono" : ""}`}
                title={label}
              >
                {label}
              </span>
              <span className="relative text-[12.5px] text-muted tabular shrink-0">{n}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
