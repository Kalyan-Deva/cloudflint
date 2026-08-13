"use client";

import { useEffect, useState } from "react";
import { Button, Panel, Problem, api, useApi } from "@/lib/ui";

type Zone = { name: string; waf_rules: string[]; waf_reads_body: boolean };

type Explained = {
  matched: { rule: string; action: string; severity: string }[];
  outcome: "allow" | "block" | "skip";
  decided_by: string | null;
  skipped_needing_body: string[];
};

export default function Waf() {
  const { data, error } = useApi<{ zones: Zone[] }>("/api/cp/v1/zones");
  const [zone, setZone] = useState("");

  useEffect(() => {
    if (!zone && data?.zones.length) setZone(data.zones[0].name);
  }, [data, zone]);

  if (error) return <Problem error={error} />;
  const current = data?.zones.find((z) => z.name === zone);

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-[17px] tracking-tight">WAF</h1>
          <p className="text-[13px] text-muted">
            Try a request against the rules before you trust them.
          </p>
        </div>
        <select
          value={zone}
          onChange={(e) => setZone(e.target.value)}
          className="w-auto min-w-40 h-8 py-0"
        >
          {(data?.zones ?? []).map((z) => (
            <option key={z.name} value={z.name}>
              {z.name}
            </option>
          ))}
        </select>
      </div>

      <div className="grid lg:grid-cols-[1fr_1.15fr] gap-5 items-start">
        <Panel
          title={`Rules · ${current?.waf_rules.length ?? 0}`}
          aside={
            current?.waf_reads_body ? (
              <span className="text-[11.5px] text-warn">reads bodies</span>
            ) : (
              <span className="text-[11.5px] text-muted">head only</span>
            )
          }
        >
          {!current || current.waf_rules.length === 0 ? (
            <div className="px-4 py-6 text-[13px] text-muted">
              The WAF is off for this zone.
            </div>
          ) : (
            <ul className="max-h-[420px] overflow-auto">
              {current.waf_rules.map((rule) => (
                <li
                  key={rule}
                  className="px-4 h-8 flex items-center border-b hair last:border-b-0 font-mono text-[12.5px]"
                >
                  {rule}
                </li>
              ))}
            </ul>
          )}
        </Panel>

        {zone && <Tester zone={zone} />}
      </div>
    </div>
  );
}

const SAMPLES: [string, { path: string; query: string; ua?: string; body?: string }][] = [
  ["Ordinary", { path: "/search", query: "q=how+to+bake+bread" }],
  ["SQL injection", { path: "/search", query: "id=1%20union%20select%20password" }],
  ["Traversal", { path: "/files/%2e%2e%2f%2e%2e%2fetc/passwd", query: "" }],
  ["Scanner", { path: "/", query: "", ua: "sqlmap/1.7.2#stable" }],
];

function Tester({ zone }: { zone: string }) {
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/search");
  const [query, setQuery] = useState("id=1%20union%20select%20password");
  const [headers, setHeaders] = useState("user-agent: Mozilla/5.0");
  const [body, setBody] = useState("");
  const [ip, setIp] = useState("203.0.113.9");

  const [result, setResult] = useState<Explained | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const parsed: Record<string, string> = {};
      for (const line of headers.split("\n")) {
        const at = line.indexOf(":");
        if (at > 0) parsed[line.slice(0, at).trim()] = line.slice(at + 1).trim();
      }
      setResult(
        await api<Explained>("/api/cp/v1/waf/test", {
          method: "POST",
          body: JSON.stringify({ zone, method, path, query, body, ip, headers: parsed }),
        }),
      );
    } catch (e) {
      setResult(null);
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      title="Test a request"
      aside={
        <div className="flex gap-3 text-[11.5px]">
          {SAMPLES.map(([label, s]) => (
            <button
              key={label}
              className="text-muted hover:text-accent transition-colors"
              onClick={() => {
                setPath(s.path);
                setQuery(s.query);
                setHeaders(`user-agent: ${s.ua ?? "Mozilla/5.0"}`);
                setBody(s.body ?? "");
                setResult(null);
              }}
            >
              {label}
            </button>
          ))}
        </div>
      }
    >
      <div className="p-4 space-y-3">
        <div className="grid grid-cols-[5.5rem_1fr] gap-2">
          <select value={method} onChange={(e) => setMethod(e.target.value)} className="h-8 py-0">
            {["GET", "POST", "PUT", "DELETE", "HEAD"].map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
          <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/path" />
        </div>

        <Labelled label="Query string">
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="a=1&b=2" />
        </Labelled>

        <div className="grid grid-cols-2 gap-3">
          <Labelled label="Headers">
            <textarea
              rows={3}
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              placeholder="user-agent: curl/8.4.0"
            />
          </Labelled>
          <Labelled label="Body">
            <textarea
              rows={3}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="leave empty to skip body rules"
            />
          </Labelled>
        </div>

        <div className="flex items-end gap-3">
          <Labelled label="Client IP">
            <input value={ip} onChange={(e) => setIp(e.target.value)} />
          </Labelled>
          <Button onClick={run} tone="accent" disabled={busy}>
            {busy ? "Running…" : "Run"}
          </Button>
        </div>
      </div>

      {error && (
        <div className="border-t hair px-4 py-3 text-[13px]">
          <span className="text-bad">Could not run it.</span>{" "}
          <span className="text-muted">{error}</span>
        </div>
      )}

      {result && <Verdict result={result} />}
    </Panel>
  );
}

function Verdict({ result }: { result: Explained }) {
  const tone = {
    block: "text-bad border-bad/50",
    skip: "text-accent border-accent/50",
    allow: "text-good border-good/50",
  }[result.outcome];

  const says = {
    block: "This request would be blocked.",
    skip: "This request would skip the rest of the WAF.",
    allow: "This request would be allowed through.",
  }[result.outcome];

  return (
    <div className="border-t hair">
      <div className="px-4 py-3 flex items-center gap-3">
        <span className={`border rounded px-2 py-0.5 text-[11px] uppercase tracking-wider ${tone}`}>
          {result.outcome}
        </span>
        <span className="text-[13px]">{says}</span>
        {result.decided_by && (
          <code className="ml-auto font-mono text-[12px] text-muted">{result.decided_by}</code>
        )}
      </div>

      {result.matched.length > 0 && (
        <ul className="border-t hair">
          {result.matched.map((m) => (
            <li
              key={m.rule}
              className="px-4 h-8 flex items-center gap-3 border-b hair last:border-b-0"
            >
              <code className="font-mono text-[12.5px] flex-1 truncate">{m.rule}</code>
              <span className="text-[11.5px] text-muted">{m.severity}</span>
              <span
                className={`text-[11.5px] w-12 text-right ${
                  m.action === "block"
                    ? "text-bad"
                    : m.action === "skip"
                      ? "text-accent"
                      : "text-warn"
                }`}
              >
                {m.action}
              </span>
            </li>
          ))}
        </ul>
      )}

      <p className="px-4 py-2.5 text-[12px] text-muted border-t hair">
        {result.matched.length === 0
          ? "No rule matched."
          : "Every matching rule is listed, including ones a block in front of them would normally hide."}
        {result.skipped_needing_body.length > 0 &&
          ` ${result.skipped_needing_body.length} body rule(s) were skipped — add a body to test them.`}
      </p>
    </div>
  );
}

function Labelled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block flex-1">
      <span className="text-[11px] uppercase tracking-wider text-muted">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}
