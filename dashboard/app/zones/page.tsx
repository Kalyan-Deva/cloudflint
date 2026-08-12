"use client";

import { Panel, Problem, useApi } from "@/lib/ui";

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

export default function Zones() {
  const { data, error } = useApi<{ revision: number; zones: Zone[] }>("/api/cp/v1/zones");
  if (error) return <Problem error={error} />;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[17px] font-semibold tracking-tight">Zones</h1>
        <p className="text-[13px] text-muted">
          Read back from the active config by the edge&apos;s own parser
          {data ? ` — revision ${data.revision}` : ""}.
        </p>
      </div>

      {(data?.zones ?? []).map((zone) => (
        <Panel
          key={zone.name}
          title={zone.name}
          aside={
            <span className="font-mono text-[12px] text-muted">{zone.origin}</span>
          }
        >
          <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-[var(--color-line)]">
            <Field label="Hostnames">
              <div className="flex flex-wrap gap-1.5">
                {zone.hostnames.map((h) => (
                  <code
                    key={h}
                    className="border hair rounded px-1.5 py-0.5 text-[12px] font-mono"
                  >
                    {h}
                  </code>
                ))}
              </div>
              <Note>Exact hostnames win over wildcards.</Note>
            </Field>

            <Field label="Origin">
              <Row k="Address" v={zone.origin} mono />
              <Row k="Host header" v={zone.preserve_host ? "passed through" : "rewritten"} />
              <Row k="Timeout" v={`${zone.origin_timeout_ms} ms`} />
            </Field>

            <Field label={`WAF · ${zone.waf_rules.length} rules`}>
              {zone.waf_rules.length === 0 ? (
                <span className="text-muted text-[13px]">Off for this zone.</span>
              ) : (
                <>
                  <div className="flex flex-wrap gap-1.5 max-h-24 overflow-auto">
                    {zone.waf_rules.map((r) => (
                      <code
                        key={r}
                        className="border hair rounded px-1.5 py-0.5 text-[11.5px] font-mono text-muted"
                      >
                        {r}
                      </code>
                    ))}
                  </div>
                  <Note>
                    {zone.waf_reads_body
                      ? "Reads request bodies, so uploads to this zone get buffered."
                      : "Head-only — no request body is ever buffered for this zone."}
                  </Note>
                </>
              )}
            </Field>

            <Field label="Cache and limits">
              <Row k="Cache" v={zone.cache_enabled ? "on" : "off"} />
              <Row k="Varies on" v={zone.cache_vary_on.join(", ") || "nothing"} />
              {zone.cache_overrides.map((o) => (
                <Row key={o} k="Override" v={o} mono />
              ))}
              {zone.rate_limits.length === 0 ? (
                <Row k="Rate limits" v="none" />
              ) : (
                zone.rate_limits.map((r) => <Row key={r} k="Limit" v={r} mono />)
              )}
              <Row k="Adaptive" v={zone.adaptive ? "on" : "off"} />
            </Field>
          </div>
        </Panel>
      ))}

      {data?.zones.length === 0 && (
        <Panel>
          <div className="px-4 py-6 text-[13px] text-muted">
            The active config has no zones.
          </div>
        </Panel>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="p-4 space-y-2">
      <div className="text-[11px] uppercase tracking-wider text-muted">{label}</div>
      {children}
    </div>
  );
}

function Row({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 text-[13px]">
      <span className="text-muted shrink-0">{k}</span>
      <span className={`text-right truncate ${mono ? "font-mono text-[12px]" : ""}`} title={v}>
        {v}
      </span>
    </div>
  );
}

function Note({ children }: { children: React.ReactNode }) {
  return <p className="text-[12px] text-muted pt-1">{children}</p>;
}
