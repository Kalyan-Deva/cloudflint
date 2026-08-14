"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api, ms } from "@/lib/ui";

type Summary = {
  requests: number;
  errors: number;
  blocked: number;
  rate_limited: number;
  cache_hits: number;
  cache_eligible: number;
  p50_us: number;
  p95_us: number;
};

type EdgeStats = {
  zones: number;
  cache: { entries: number; bytes: number };
  events: { seen: number; dropped: number };
  uptime_s: number;
};

const NAV = [
  {
    section: "overview",
    items: [
      { href: "/", label: "Dashboard", icon: Grid },
      { href: "/zones", label: "Zones", icon: Globe },
      { href: "/origins", label: "Origins", icon: Stack },
    ],
  },
  {
    section: "traffic",
    items: [{ href: "/logs", label: "Live logs", icon: Pulse }],
  },
  {
    section: "security",
    items: [
      { href: "/waf", label: "WAF rules", icon: Shield },
      { href: "/certificates", label: "Certificates", icon: Lock },
    ],
  },
  {
    section: "control",
    items: [
      { href: "/fleet", label: "Fleet", icon: Nodes },
      { href: "/config", label: "Config", icon: Doc },
      { href: "/tokens", label: "Tokens", icon: Key },
    ],
  },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [edge, setEdge] = useState<EdgeStats | null>(null);
  const [reachable, setReachable] = useState(true);

  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const [s, e] = await Promise.all([
          api<Summary>("/api/cp/v1/analytics/summary?since_mins=60"),
          api<EdgeStats>("/api/edge/stats"),
        ]);
        if (!live) return;
        setSummary(s);
        setEdge(e);
        setReachable(true);
      } catch {
        if (live) setReachable(false);
      }
    };
    tick();
    const id = setInterval(tick, 10_000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, []);

  const hitRate =
    summary && summary.cache_eligible > 0
      ? Math.round((summary.cache_hits / summary.cache_eligible) * 100)
      : 0;

  return (
    <div className="min-h-screen flex">
      <aside className="w-[230px] shrink-0 border-r hair bg-base fixed inset-y-0 left-0 flex flex-col">
        <div className="h-[62px] flex items-center gap-2.5 px-5 border-b hair">
          <Flint />
          <span className="text-[15px] tracking-[0.14em] font-semibold">CLOUDFLINT</span>
        </div>

        <nav className="flex-1 overflow-y-auto py-4">
          {NAV.map((group) => (
            <div key={group.section} className="mb-5">
              <div className="cap px-5 pb-2">{group.section}</div>
              {group.items.map((item) => {
                const on = path === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`flex items-center gap-3 h-9 px-5 border-l-2 transition-colors ${
                      on
                        ? "border-accent bg-raised text-accent"
                        : "border-transparent text-muted hover:text-text hover:bg-panel"
                    }`}
                  >
                    <item.icon />
                    <span className="text-[13px]">{item.label}</span>
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="m-3 border hair rounded-sm bg-panel px-3 py-2.5">
          <div className="cap">edge status</div>
          <div className="flex items-center justify-between mt-1.5">
            <span className="flex items-center gap-2 text-[12px]">
              <i
                className={`w-1.5 h-1.5 rounded-full ${
                  reachable ? "bg-good pulse" : "bg-bad"
                }`}
              />
              {reachable ? "Healthy" : "Unreachable"}
            </span>
            <span className="text-[11px] text-dim tabular">
              {edge ? uptime(edge.uptime_s) : "—"}
            </span>
          </div>
          {edge && (
            <div className="mt-2 pt-2 border-t hair flex justify-between text-[11px] text-dim tabular">
              <span>{edge.zones} zones</span>
              <span>{edge.cache.entries} cached</span>
            </div>
          )}
        </div>
      </aside>

      <div className="ml-[230px] flex-1 min-w-0">
        <header className="h-[62px] border-b hair flex items-stretch overflow-x-auto sticky top-0 bg-base z-10">
          <Strip label="requests 1h" value={(summary?.requests ?? 0).toLocaleString()} />
          <Strip
            label="blocked"
            value={summary?.blocked ?? 0}
            tone={summary && summary.blocked > 0 ? "bad" : undefined}
          />
          <Strip
            label="rate limited"
            value={summary?.rate_limited ?? 0}
            tone={summary && summary.rate_limited > 0 ? "warn" : undefined}
          />
          <Strip
            label="cache hit"
            value={`${hitRate}%`}
            tone={hitRate >= 50 ? "good" : undefined}
          />
          <Strip label="p50 / p95" value={`${ms(summary?.p50_us ?? 0)} / ${ms(summary?.p95_us ?? 0)}`} />
          <Strip
            label="errors"
            value={summary?.errors ?? 0}
            tone={summary && summary.errors > 0 ? "bad" : undefined}
          />
          <div className="flex items-center gap-2 px-5 ml-auto shrink-0">
            <i className={`w-1.5 h-1.5 rounded-full ${reachable ? "bg-accent pulse" : "bg-bad"}`} />
            <span className="text-[12px] text-muted">{reachable ? "Live" : "No edge"}</span>
          </div>
        </header>

        <main className="p-5">{children}</main>
      </div>
    </div>
  );
}

function Strip({
  label,
  value,
  tone,
}: {
  label: string;
  value: string | number;
  tone?: "good" | "bad" | "warn";
}) {
  const colour = tone ? { good: "text-good", bad: "text-bad", warn: "text-warn" }[tone] : "";
  return (
    <div className="px-5 flex flex-col justify-center border-r hair shrink-0">
      <div className="cap">{label}</div>
      <div className={`text-[14px] tabular ${colour}`}>{value}</div>
    </div>
  );
}

function uptime(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

/* A struck flint: the stone, and the sparks coming off it. The old mark was three
   drawn-across curves for a veil, which stopped meaning anything when the name changed. */
function Flint() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none" aria-hidden>
      {/* the stone: angular, struck, not a tidy shape */}
      <path
        d="M3.1 9.6L5.4 4.3l4.3-1.1 1.5 3.4-2.2 5.1-4.6 0.6z"
        stroke="var(--color-accent)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      {/* sparks, thrown off the struck edge and fading as they go */}
      <path d="M12.1 3.4l1.9-1.6" stroke="var(--color-accent)" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M13 6.2l1.9-0.5" stroke="var(--color-accent)" strokeWidth="1.3" strokeLinecap="round" opacity="0.62" />
      <path d="M11.9 1.2l0.4 1.5" stroke="var(--color-accent)" strokeWidth="1.2" strokeLinecap="round" opacity="0.38" />
    </svg>
  );
}

const ico = { width: 14, height: 14, viewBox: "0 0 16 16", fill: "none" } as const;
const line = { stroke: "currentColor", strokeWidth: 1.3, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

function Grid() {
  return (
    <svg {...ico}>
      <rect x="2" y="2" width="5" height="5" rx="1" {...line} />
      <rect x="9" y="2" width="5" height="5" rx="1" {...line} />
      <rect x="2" y="9" width="5" height="5" rx="1" {...line} />
      <rect x="9" y="9" width="5" height="5" rx="1" {...line} />
    </svg>
  );
}
function Globe() {
  return (
    <svg {...ico}>
      <circle cx="8" cy="8" r="6" {...line} />
      <path d="M2 8h12M8 2c1.7 2 1.7 10 0 12M8 2c-1.7 2-1.7 10 0 12" {...line} />
    </svg>
  );
}
function Pulse() {
  return (
    <svg {...ico}>
      <path d="M1.5 8h3l1.5-4 2.5 8 1.5-4h3.5" {...line} />
    </svg>
  );
}
function Lock() {
  return (
    <svg {...ico}>
      <rect x="3" y="7" width="10" height="7" rx="1.5" {...line} />
      <path d="M5.5 7V5a2.5 2.5 0 015 0v2" {...line} />
    </svg>
  );
}
/** Backends, stacked. */
function Stack() {
  return (
    <svg {...ico}>
      <rect x="2" y="2.5" width="12" height="3.5" rx="1" {...line} />
      <rect x="2" y="10" width="12" height="3.5" rx="1" {...line} />
      <path d="M8 6v4" {...line} />
    </svg>
  );
}
function Shield() {
  return (
    <svg {...ico}>
      <path d="M8 1.6l5 2v4.2c0 3-2.1 5.3-5 6.6-2.9-1.3-5-3.6-5-6.6V3.6l5-2z" {...line} />
    </svg>
  );
}
/* several nodes reporting to one place - the fleet, drawn as what it is */
function Nodes() {
  return (
    <svg {...ico}>
      <circle cx="8" cy="3.2" r="1.7" {...line} />
      <circle cx="3.2" cy="12.4" r="1.7" {...line} />
      <circle cx="12.8" cy="12.4" r="1.7" {...line} />
      <path d="M6.9 4.6L4.2 10.9M9.1 4.6l2.7 6.3M4.9 12.4h6.2" {...line} />
    </svg>
  );
}
function Doc() {
  return (
    <svg {...ico}>
      <path d="M4 1.8h5l3 3v9.4H4z" {...line} />
      <path d="M9 1.8v3h3" {...line} />
    </svg>
  );
}
function Key() {
  return (
    <svg {...ico}>
      <circle cx="5" cy="8" r="3" {...line} />
      <path d="M8 8h6M12 8v2.5M14 8v2" {...line} />
    </svg>
  );
}
