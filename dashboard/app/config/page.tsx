"use client";

import { useEffect, useState } from "react";
import { Button, Panel, Problem, api, useApi } from "@/lib/ui";

type Active = { revision: number; yaml: string; note: string; created_at: number };
type Revision = { id: number; note: string; created_at: number; active: boolean };

export default function Config() {
  const active = useApi<Active>("/api/cp/v1/config");
  const revisions = useApi<Revision[]>("/api/cp/v1/config/revisions");

  const [yaml, setYaml] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [said, setSaid] = useState<{ good: boolean; text: string } | null>(null);

  useEffect(() => {
    if (active.data) setYaml(active.data.yaml);
  }, [active.data]);

  const dirty = !!active.data && yaml !== active.data.yaml;

  async function save() {
    setSaving(true);
    setSaid(null);
    try {
      const out = await api<{ revision: number }>("/api/cp/v1/config", {
        method: "PUT",
        body: JSON.stringify({ yaml, note }),
      });
      setSaid({ good: true, text: `Saved as revision ${out.revision} and made active.` });
      setNote("");
      active.reload();
      revisions.reload();
    } catch (e) {
      setSaid({ good: false, text: (e as Error).message });
    } finally {
      setSaving(false);
    }
  }

  async function activate(id: number) {
    setSaid(null);
    try {
      await api(`/api/cp/v1/config/revisions/${id}/activate`, { method: "POST" });
      setSaid({ good: true, text: `Rolled back to revision ${id}.` });
      active.reload();
      revisions.reload();
    } catch (e) {
      setSaid({ good: false, text: (e as Error).message });
    }
  }

  if (active.error && !active.data) return <Problem error={active.error} />;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[17px] font-semibold tracking-tight">Config</h1>
        <p className="text-[13px] text-muted">
          Checked with the edge&apos;s own parser on save, so a config that would break
          the data plane never gets stored.
        </p>
      </div>

      {said && (
        <div
          className={`border rounded px-4 py-2.5 text-[13px] ${
            said.good ? "border-good/40 text-good" : "border-danger/40 text-danger"
          }`}
        >
          {said.text}
        </div>
      )}

      <Panel
        title={`Active config${active.data ? ` · revision ${active.data.revision}` : ""}`}
        aside={
          dirty ? (
            <span className="text-[11.5px] text-accent">unsaved changes</span>
          ) : (
            <span className="text-[11.5px] text-muted">{active.data?.note || "no note"}</span>
          )
        }
      >
        <div className="p-4 space-y-3">
          <textarea
            rows={24}
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
            spellCheck={false}
          />
          <div className="flex items-center gap-3">
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="What changed, and why"
            />
            <Button onClick={save} tone="accent" disabled={saving || !dirty}>
              {saving ? "Saving…" : "Save as new revision"}
            </Button>
          </div>
          <p className="text-[12px] text-muted">
            Edges pick this up within a few seconds. They keep serving the last good
            config if the control plane is unreachable.
          </p>
        </div>
      </Panel>

      <div className="grid lg:grid-cols-2 gap-5 items-start">
        <Panel title="Revisions">
          <ul className="max-h-80 overflow-auto">
            {(revisions.data ?? []).map((r) => (
              <li
                key={r.id}
                className="flex items-center gap-3 px-4 h-10 border-b hair last:border-b-0"
              >
                <span className="font-mono text-[12.5px] w-8 tabular">{r.id}</span>
                <span className="flex-1 truncate text-[13px]" title={r.note}>
                  {r.note || <span className="text-muted">no note</span>}
                </span>
                <span className="text-[11.5px] text-muted shrink-0">
                  {new Date(r.created_at).toLocaleString("en-GB")}
                </span>
                {r.active ? (
                  <span className="text-[11.5px] text-good w-16 text-right">active</span>
                ) : (
                  <button
                    onClick={() => activate(r.id)}
                    className="text-[11.5px] text-muted hover:text-accent w-16 text-right transition-colors"
                  >
                    roll back
                  </button>
                )}
              </li>
            ))}
            {(revisions.data ?? []).length === 0 && (
              <li className="px-4 py-6 text-[13px] text-muted">No revisions yet.</li>
            )}
          </ul>
        </Panel>

        <Purge />
      </div>
    </div>
  );
}

function Purge() {
  const [kind, setKind] = useState<"url" | "tag" | "zone" | "all">("url");
  const [value, setValue] = useState("http://demo.local/page");
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
      setSaid(
        out.edges
          .map((e) => `${e.edge}: ${e.ok ? e.detail : `failed — ${e.detail}`}`)
          .join("\n"),
      );
    } catch (e) {
      setSaid((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Purge">
      <div className="p-4 space-y-3">
        <div className="flex border hair rounded overflow-hidden w-fit">
          {(["url", "tag", "zone", "all"] as const).map((k) => (
            <button
              key={k}
              onClick={() => setKind(k)}
              className={`px-3 h-7 text-[12px] border-r hair last:border-r-0 transition-colors ${
                kind === k ? "bg-raised text-text" : "text-muted hover:text-text"
              }`}
            >
              {k}
            </button>
          ))}
        </div>

        {kind !== "all" && (
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={
              kind === "url" ? "http://demo.local/page" : kind === "tag" ? "nav" : "demo"
            }
          />
        )}

        <Button onClick={run} tone="danger" disabled={busy}>
          {busy ? "Purging…" : kind === "all" ? "Purge everything" : `Purge by ${kind}`}
        </Button>

        {said && (
          <pre className="border hair rounded bg-base px-3 py-2 text-[12px] font-mono whitespace-pre-wrap">
            {said}
          </pre>
        )}

        <p className="text-[12px] text-muted">
          Purges go to the edges, because that is where the cache is. Each one reports
          back separately — a purge can succeed on some nodes and not others.
        </p>
      </div>
    </Panel>
  );
}
