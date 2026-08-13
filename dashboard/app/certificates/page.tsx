"use client";

import { Cell, Panel, Problem, Row, Tag, useApi } from "@/lib/ui";

type ZoneCert = {
  zone: string;
  hostnames: string[];
  mode: string;
  configured: string | null;
  deployed: boolean;
  status: string;
  subject: string | null;
  issuer: string | null;
  self_signed: boolean | null;
  dns_names: string[];
  not_before_ms: number | null;
  not_after_ms: number | null;
  days_left: number | null;
  renews_at_ms: number | null;
  renewal: string;
  origin: {
    https: boolean;
    verify: boolean;
    ca: string | null;
    mtls: boolean;
    mode: string;
  };
};

type Report = {
  listener: { listen: string; redirect_http: boolean } | null;
  zones: ZoneCert[];
};

/** What each status means, in words, since a colour on its own is a guess. */
const STATUS: Record<string, { label: string; tone: "good" | "warn" | "bad" | undefined }> = {
  ok: { label: "valid", tone: "good" },
  expiring: { label: "expiring soon", tone: "warn" },
  expired: { label: "expired", tone: "bad" },
  not_yet_valid: { label: "not valid yet", tone: "bad" },
  not_loaded: { label: "configured but not loaded", tone: "bad" },
  none: { label: "no certificate", tone: undefined },
};

function date(ms: number | null) {
  if (!ms) return "—";
  return new Date(ms).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

export default function Certificates() {
  const { data, error } = useApi<Report>("/api/edge/certificates");
  if (error) return <Problem error={error} />;

  const zones = data?.zones ?? [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[17px] tracking-tight">Certificates</h1>
        <p className="text-[13px] text-muted">
          What this edge is serving to clients, and how it talks to origins. Read from the
          certificates actually loaded — not from what the config asks for.
        </p>
      </div>

      {data?.listener ? (
        <Panel title="HTTPS listener">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 px-4 py-3">
            <Cell label="Listening on" value={data.listener.listen} />
            <Cell
              label="Plaintext"
              value={data.listener.redirect_http ? "redirects to https" : "served as-is"}
              tone={data.listener.redirect_http ? "good" : undefined}
            />
            <Cell label="Zones with a certificate" value={zones.filter((z) => z.deployed).length} />
          </div>
        </Panel>
      ) : (
        <Panel title="HTTPS listener">
          <div className="px-4 py-6 text-[13px] text-muted">
            No <code>tls</code> block in the config, so this edge is plaintext only.
          </div>
        </Panel>
      )}

      {zones.map((z) => {
        const status = STATUS[z.status] ?? { label: z.status, tone: undefined };
        return (
          <Panel
            key={z.zone}
            title={z.zone}
            aside={
              <div className="flex items-center gap-2">
                {z.self_signed && <Tag>self-signed</Tag>}
                <Tag>
                  {{ acme: "acme", manual: "manual certificate", off: "no tls" }[z.mode] ??
                    z.mode}
                </Tag>
              </div>
            }
          >
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 px-4 py-3 border-b hair">
              <Cell label="Status" value={status.label} tone={status.tone} />
              <Cell
                label="Expires"
                value={date(z.not_after_ms)}
                tone={
                  z.days_left === null
                    ? undefined
                    : z.days_left < 0
                      ? "bad"
                      : z.days_left < 14
                        ? "warn"
                        : "good"
                }
                hint={z.days_left === null ? undefined : `${z.days_left} days left`}
              />
              <Cell
                label="Renewal"
                value={z.renews_at_ms ? date(z.renews_at_ms) : "manual"}
                hint={z.renews_at_ms ? undefined : "nothing renews this yet"}
              />
              <Cell
                label="To the origin"
                value={z.origin.mode}
                tone={
                  !z.origin.https
                    ? undefined
                    : z.origin.verify
                      ? "good"
                      : "bad"
                }
              />
            </div>

            <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-[var(--color-line)]">
              <div className="p-4 space-y-1">
                <div className="cap pb-1">Presented to clients</div>
                <Row k="Subject" v={z.subject ?? "—"} />
                <Row k="Issuer" v={z.issuer ?? "—"} />
                <Row k="Valid from" v={date(z.not_before_ms)} />
                <Row k="Deployed" v={z.deployed ? "yes" : "no"} />
                {z.configured && <Row k="File" v={z.configured} mono />}
                <div className="pt-2">
                  <div className="cap pb-1">Valid for</div>
                  {z.dns_names.length === 0 ? (
                    <span className="text-[12.5px] text-dim">—</span>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {z.dns_names.map((n) => {
                        /* a name the certificate covers but the zone does not serve, or
                           the other way round, is worth seeing at a glance */
                        const served = z.hostnames.some(
                          (h) => h === n || (h.startsWith("*.") && n.endsWith(h.slice(1))),
                        );
                        return (
                          <code
                            key={n}
                            className={`border hair rounded px-1.5 py-0.5 text-[11.5px] ${
                              served ? "" : "text-warn"
                            }`}
                            title={served ? "served by this zone" : "not a hostname of this zone"}
                          >
                            {n}
                          </code>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              <div className="p-4 space-y-1">
                <div className="cap pb-1">Origin connection</div>
                <Row k="Scheme" v={z.origin.https ? "https" : "http"} />
                <Row
                  k="Certificate checked"
                  v={
                    !z.origin.https ? (
                      "n/a"
                    ) : z.origin.verify ? (
                      <span className="text-good">yes</span>
                    ) : (
                      <span className="text-bad">no — verify is off</span>
                    )
                  }
                />
                <Row k="Extra CA trusted" v={z.origin.ca ?? "none"} mono />
                <Row
                  k="Client certificate"
                  v={z.origin.mtls ? "presented (mTLS)" : "none"}
                />
                {z.origin.https && !z.origin.verify && (
                  <p className="text-[12px] text-warn pt-2">
                    Traffic to this origin is encrypted but unauthenticated — anything on
                    the path can read and rewrite it.
                  </p>
                )}
              </div>
            </div>
          </Panel>
        );
      })}

      {zones.length === 0 && (
        <Panel>
          <div className="px-4 py-6 text-[13px] text-muted">The active config has no zones.</div>
        </Panel>
      )}
    </div>
  );
}
