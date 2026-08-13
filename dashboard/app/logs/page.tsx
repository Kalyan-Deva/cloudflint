"use client";

import { useEffect, useRef, useState } from "react";
import { Panel, cacheTone, clock, ms, statusTone } from "@/lib/ui";

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

const FILTERS = {
  all: () => true,
  blocked: (e: Event) => e.status === 403,
  limited: (e: Event) => e.status === 429,
  errors: (e: Event) => e.status >= 500,
  cached: (e: Event) => e.cache === "HIT" || (e.cache ?? "").startsWith("STALE"),
} as const;

const KEEP = 400;

export default function Logs() {
  const [events, setEvents] = useState<Event[]>([]);
  const [filter, setFilter] = useState<keyof typeof FILTERS>("all");
  const [live, setLive] = useState(true);
  const [state, setState] = useState<"connecting" | "live" | "lost">("connecting");
  const paused = useRef(false);

  useEffect(() => {
    paused.current = !live;
  }, [live]);

  /* seed with what the edge already has, so the table isn't empty until the next
     request happens to arrive */
  useEffect(() => {
    fetch("/api/edge/recent?limit=100", { cache: "no-store" })
      .then((r) => r.json())
      .then((seed) => Array.isArray(seed) && setEvents(seed))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const source = new EventSource("/api/edge/stream");
    source.onopen = () => setState("live");
    source.onerror = () => setState("lost");
    source.onmessage = (msg) => {
      if (paused.current) return;
      try {
        const event = JSON.parse(msg.data) as Event;
        setEvents((prev) => [event, ...prev].slice(0, KEEP));
      } catch {
        /* a malformed frame is not worth tearing the stream down over */
      }
    };
    return () => source.close();
  }, []);

  const shown = events.filter(FILTERS[filter]);

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-[17px] tracking-tight">Logs</h1>
          <p className="text-[13px] text-muted">
            Streamed from the edge as requests happen, not from the control plane.
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="flex items-center gap-1.5 text-[12px] text-muted">
            <i
              className={`w-1.5 h-1.5 rounded-full ${
                state === "live" ? "bg-good" : state === "lost" ? "bg-bad" : "bg-warn"
              }`}
            />
            {state === "live" ? "connected" : state === "lost" ? "disconnected" : "connecting"}
          </span>
          <button
            onClick={() => setLive((v) => !v)}
            className={`border rounded px-3 h-8 text-[12px] transition-colors ${
              live ? "border-line text-muted hover:text-text" : "border-accent/60 text-accent"
            }`}
          >
            {live ? "Pause" : "Paused"}
          </button>
        </div>
      </div>

      <Panel
        title={`${shown.length} of ${events.length} shown`}
        aside={
          <div className="flex border hair rounded overflow-hidden">
            {(Object.keys(FILTERS) as (keyof typeof FILTERS)[]).map((key) => (
              <button
                key={key}
                onClick={() => setFilter(key)}
                className={`px-2.5 h-6 text-[11.5px] border-r hair last:border-r-0 transition-colors ${
                  filter === key ? "bg-raised text-text" : "text-muted hover:text-text"
                }`}
              >
                {key}
              </button>
            ))}
          </div>
        }
      >
        <div className="max-h-[62vh] overflow-auto">
          <table className="w-full text-[12.5px] font-mono">
            <thead className="sticky top-0 bg-panel">
              <tr className="text-muted text-left border-b hair">
                <Th className="w-20">time</Th>
                <Th className="w-14">status</Th>
                <Th className="w-14">method</Th>
                <Th>path</Th>
                <Th className="w-24">answered</Th>
                <Th className="w-20">cache</Th>
                <Th className="w-20 text-right">took</Th>
                <Th className="w-28">client</Th>
              </tr>
            </thead>
            <tbody>
              {shown.map((e, i) => (
                <tr key={`${e.at_ms}-${i}`} className="border-b hair last:border-b-0">
                  <Td className="text-muted">{clock(e.at_ms)}</Td>
                  <Td className={`tabular ${statusTone(e.status)}`}>{e.status}</Td>
                  <Td className="text-muted">{e.method}</Td>
                  <Td className="truncate max-w-0" title={`${e.host}${e.path}`}>
                    {e.path}
                  </Td>
                  <Td className="text-muted">{e.decided_by}</Td>
                  <Td className={cacheTone(e.cache)}>{e.cache ?? "—"}</Td>
                  <Td className="text-right tabular text-muted">{ms(e.duration_us)}</Td>
                  <Td className="text-muted truncate">{e.client_ip}</Td>
                </tr>
              ))}
            </tbody>
          </table>

          {shown.length === 0 && (
            <div className="px-4 py-10 text-center text-[13px] text-muted">
              {events.length === 0
                ? "Nothing yet. Send some traffic through the edge."
                : `No ${filter} requests in the last ${events.length}.`}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <th className={`font-normal px-3 h-8 ${className}`}>{children}</th>;
}

function Td({
  children,
  className = "",
  title,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <td className={`px-3 h-7 ${className}`} title={title}>
      {children}
    </td>
  );
}
