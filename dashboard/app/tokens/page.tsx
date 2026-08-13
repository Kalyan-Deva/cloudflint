"use client";

import { useState } from "react";
import { Button, Panel, Problem, api, useApi } from "@/lib/ui";

type Token = {
  id: number;
  name: string;
  created_at: number;
  last_used_at: number | null;
};

export default function Tokens() {
  const tokens = useApi<Token[]>("/api/cp/v1/tokens");
  const [name, setName] = useState("");
  const [minted, setMinted] = useState<{ name: string; token: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function mint() {
    setBusy(true);
    setError(null);
    try {
      const out = await api<{ name: string; token: string }>("/api/cp/v1/tokens", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setMinted(out);
      setName("");
      tokens.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: number) {
    setError(null);
    try {
      await api(`/api/cp/v1/tokens/${id}`, { method: "DELETE" });
      tokens.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (tokens.error && !tokens.data) return <Problem error={tokens.error} />;

  return (
    <div className="space-y-4 max-w-[900px]">
      <div>
        <h1 className="text-[17px] tracking-tight">Tokens</h1>
        <p className="text-[12.5px] text-muted mt-1">
          Every control plane endpoint except <code className="text-text">/health</code> needs one.
          Only the hash is stored, so a token is shown once and never again.
        </p>
      </div>

      {error && (
        <div className="border border-bad/40 rounded-sm px-4 py-2.5 text-[12.5px] text-bad">
          {error}
        </div>
      )}

      {minted && (
        <Panel title="new token">
          <div className="p-4 space-y-2.5">
            <p className="text-[12.5px]">
              <span className="text-accent">Copy this now.</span>{" "}
              <span className="text-muted">
                It is not stored anywhere and cannot be shown again.
              </span>
            </p>
            <div className="flex gap-2">
              <input readOnly value={minted.token} className="text-accent" />
              <Button onClick={() => navigator.clipboard?.writeText(minted.token)}>copy</Button>
            </div>
            <p className="text-[11px] text-dim">
              For an edge: <code>CLOUDVEIL_CP_TOKEN</code>. For the dashboard:{" "}
              <code>CLOUDVEIL_API_TOKEN</code>.
            </p>
            <Button size="sm" onClick={() => setMinted(null)}>
              done
            </Button>
          </div>
        </Panel>
      )}

      <Panel title="mint a token">
        <div className="p-4 flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="what will hold it — edge-01, dashboard, ci"
          />
          <Button onClick={mint} tone="accent" disabled={busy || !name.trim()}>
            {busy ? "minting…" : "mint"}
          </Button>
        </div>
      </Panel>

      <Panel title={`issued · ${tokens.data?.length ?? 0}`}>
        <table className="w-full text-[12px]">
          <thead>
            <tr className="cap border-b hair text-left">
              <th className="font-normal px-4 h-8 w-10">id</th>
              <th className="font-normal px-4 h-8">name</th>
              <th className="font-normal px-4 h-8 w-44">created</th>
              <th className="font-normal px-4 h-8 w-44">last used</th>
              <th className="font-normal px-4 h-8 w-20" />
            </tr>
          </thead>
          <tbody>
            {(tokens.data ?? []).map((t) => (
              <tr key={t.id} className="border-b hair last:border-b-0">
                <td className="px-4 h-9 tabular text-dim">{t.id}</td>
                <td className="px-4 h-9">{t.name}</td>
                <td className="px-4 h-9 text-muted tabular">{when(t.created_at)}</td>
                <td className="px-4 h-9 text-muted tabular">
                  {t.last_used_at ? when(t.last_used_at) : <span className="text-dim">never</span>}
                </td>
                <td className="px-4 h-9 text-right">
                  <button
                    onClick={() => revoke(t.id)}
                    className="text-[11.5px] text-dim hover:text-bad transition-colors"
                  >
                    revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {(tokens.data ?? []).length === 0 && (
          <div className="px-4 py-8 text-center text-[12px] text-dim">No tokens issued.</div>
        )}
      </Panel>

      <p className="text-[11.5px] text-dim">
        Revoking takes effect on the next request. The edge admin API has its own token, set as{" "}
        <code>CLOUDVEIL_ADMIN_TOKEN</code> on the edge itself — secrets never travel in config,
        because config travels between nodes and is editable right here.
      </p>
    </div>
  );
}

function when(atMs: number) {
  if (!atMs) return "—";
  return new Date(atMs).toLocaleString("en-GB");
}
