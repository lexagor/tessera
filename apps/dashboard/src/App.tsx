import { useCallback, useEffect, useState } from "react";
import type { CSSProperties, ReactNode } from "react";

const LS_KEY = "tessera.apiKey";

type Policy = {
  id: string;
  version: number;
  name: string;
  grants: { resource: string; condition?: string }[];
  fail_open: boolean;
};

type ChainEntry = {
  payload_hash: string;
  receipt: {
    v: number;
    agent: string;
    ts: string;
    authorization: { decision: string; policy: string; policyVersion: number; resource: string };
    call: { tool: string; argsHash: string; resultHash?: string | null };
    grant: { provider: string; ttlS: number; status: string };
  };
};

type AnchorBatch = { root: string; count: number; calldata: string };

type ApiKey = {
  id: string;
  tenant: string;
  name: string;
  prefix: string;
  createdAt: string;
  revokedAt?: string | null;
};

type Tab = "chain" | "policies" | "keys" | "verify";

export function App() {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem(LS_KEY) ?? "tsk_demo_local");
  const [tab, setTab] = useState<Tab>("chain");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    localStorage.setItem(LS_KEY, apiKey);
  }, [apiKey]);

  const api = useCallback(
    async (path: string, init: RequestInit = {}) => {
      const res = await fetch(path, {
        ...init,
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiKey}`,
          ...(init.headers ?? {}),
        },
      });
      const text = await res.text();
      const body = text ? JSON.parse(text) : {};
      if (!res.ok) throw new Error(body.error ?? `${res.status} ${res.statusText}`);
      return body;
    },
    [apiKey],
  );

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", margin: "0 auto", maxWidth: 980, padding: 24 }}>
      <header style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
        <h1 style={{ margin: 0 }}>Tessera</h1>
        <span style={{ color: "#666" }}>governance &amp; trust plane for autonomous agents</span>
      </header>

      <div style={{ display: "flex", gap: 8, margin: "16px 0" }}>
        <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: "#666" }}>API key</span>
          <input
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            style={{ width: 240, padding: 6, fontFamily: "monospace" }}
          />
        </label>
        <span style={{ color: "#999", alignSelf: "center" }}>stored locally</span>
      </div>

      <nav style={{ display: "flex", gap: 8, borderBottom: "1px solid #ddd", paddingBottom: 8 }}>
        {(["chain", "policies", "keys", "verify"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: "6px 12px",
              border: "1px solid #ccc",
              borderRadius: 6,
              background: tab === t ? "#111" : "#fff",
              color: tab === t ? "#fff" : "#111",
              cursor: "pointer",
            }}
          >
            {t}
          </button>
        ))}
      </nav>

      {error && (
        <pre style={{ background: "#fee", color: "#900", padding: 12, borderRadius: 6, marginTop: 12 }}>
          {error}
        </pre>
      )}

      <div style={{ marginTop: 16 }}>
        {tab === "chain" && <ChainTab api={api} setError={setError} />}
        {tab === "policies" && <PoliciesTab api={api} setError={setError} />}
        {tab === "keys" && <KeysTab api={api} setError={setError} />}
        {tab === "verify" && <VerifyTab setError={setError} />}
      </div>
    </main>
  );
}

function ChainTab({ api, setError }: { api: Api; setError: (e: string | null) => void }) {
  const [agent, setAgent] = useState("governed-agent");
  const [chain, setChain] = useState<{ length: number; verified: boolean; signer: string; entries: ChainEntry[] } | null>(null);
  const [anchor, setAnchor] = useState<AnchorBatch | null>(null);
  const [anchors, setAnchors] = useState<{ id: string; agent: string; merkleRoot: string; count: number; txHash: string }[]>([]);

  const load = async () => {
    setError(null);
    setAnchor(null);
    try {
      setChain(await api(`/v1/chain/${encodeURIComponent(agent)}`));
      setAnchors((await api("/v1/anchors")).items);
    } catch (e) {
      setChain(null);
      setError(String(e));
    }
  };

  const anchorChain = async () => {
    setError(null);
    try {
      setAnchor(await api(`/v1/chain/${encodeURIComponent(agent)}/anchor`));
    } catch (e) {
      setError(String(e));
    }
  };

  const [txHash, setTxHash] = useState<string | null>(null);

  const submitOnChain = async () => {
    setError(null);
    setTxHash(null);
    try {
      const res = await api(`/v1/chain/${encodeURIComponent(agent)}/anchor/submit`, { method: "POST" });
      setTxHash(res.txHash);
    } catch (e) {
      setError(String(e));
    }
  };

  const revokeAgent = async () => {
    setError(null);
    try {
      await api("/v1/revoke", {
        method: "POST",
        body: JSON.stringify({ target: agent, kind: "agent", reason: "manual" }),
      });
      await load();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <input value={agent} onChange={(e) => setAgent(e.target.value)} style={{ padding: 6, width: 240 }} />
        <button onClick={load} style={btn}>Load chain</button>
        <button onClick={anchorChain} style={btn}>Anchor batch</button>
        <button onClick={submitOnChain} style={btn}>Submit on-chain</button>
        <button onClick={revokeAgent} style={btn}>Revoke agent</button>
      </div>

      {chain && (
        <>
          <p style={{ marginTop: 12 }}>
            <Badge ok={chain.verified}>{chain.verified ? "verified" : "NOT verified"}</Badge>{" "}
            {chain.length} receipts · signer <code>{chain.signer}</code>
          </p>
          <table style={table}>
            <thead>
              <tr>
                <Th>tool</Th>
                <Th>status</Th>
                <Th>decision</Th>
                <Th>policy</Th>
                <Th>argsHash</Th>
                <Th>ts</Th>
              </tr>
            </thead>
            <tbody>
              {chain.entries.map((e) => (
                <tr key={e.payload_hash}>
                  <Td>{e.receipt.call.tool}</Td>
                  <Td>{e.receipt.grant.status}</Td>
                  <Td>{e.receipt.authorization.decision}</Td>
                  <Td>{e.receipt.authorization.policy}</Td>
                  <Td mono>{short(e.receipt.call.argsHash)}</Td>
                  <Td>{e.receipt.ts}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {anchor && (
        <pre style={pre}>
          count: {anchor.count}
          {"\n"}root: {anchor.root}
          {"\n"}calldata: {anchor.calldata}
        </pre>
      )}

      {txHash && (
        <p>
          on-chain tx: <code style={{ wordBreak: "break-all" }}>{txHash}</code>
        </p>
      )}

      {anchors.length > 0 && (
        <>
          <h3 style={{ marginTop: 20 }}>Recent anchors</h3>
          <table style={table}>
            <thead>
              <tr>
                <Th>agent</Th>
                <Th>count</Th>
                <Th>root</Th>
                <Th>tx</Th>
              </tr>
            </thead>
            <tbody>
              {anchors.map((a) => (
                <tr key={a.id}>
                  <Td>{a.agent}</Td>
                  <Td>{a.count}</Td>
                  <Td mono>{short(a.merkleRoot)}</Td>
                  <Td mono>{short(a.txHash)}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}

function PoliciesTab({ api, setError }: { api: Api; setError: (e: string | null) => void }) {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [id, setId] = useState("refunds");
  const [draft, setDraft] = useState(
    JSON.stringify(
      {
        version: 1,
        name: "Refunds under $50",
        grants: [{ resource: "stripe:refunds.create", constraints: [{ type: "max_number", field: "amount", value: 5000 }] }],
        fail_open: false,
      },
      null,
      2,
    ),
  );

  const load = useCallback(async () => {
    setError(null);
    try {
      const body = await api("/v1/policies");
      setPolicies(body.items);
    } catch (e) {
      setError(String(e));
    }
  }, [api, setError]);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    setError(null);
    try {
      const policy = JSON.parse(draft);
      await api(`/v1/policies/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(policy) });
      await load();
    } catch (e) {
      setError(String(e));
    }
  };

  const remove = async (policyId: string) => {
    setError(null);
    try {
      await api(`/v1/policies/${encodeURIComponent(policyId)}`, { method: "DELETE" });
      await load();
    } catch (e) {
      setError(String(e));
    }
  };

  const [notes, setNotes] = useState<string[]>([]);

  const propose = async () => {
    setError(null);
    try {
      const proposal = await api("/v1/policies/propose");
      setDraft(JSON.stringify(proposal.policy, null, 2));
      setId(String(proposal.policy.id ?? "proposed"));
      setNotes(proposal.notes ?? []);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
      <div>
        <h3>Policies</h3>
        {policies.length === 0 && <p style={{ color: "#888" }}>none</p>}
        <ul style={{ listStyle: "none", padding: 0 }}>
          {policies.map((p) => (
            <li key={p.id} style={{ border: "1px solid #ddd", borderRadius: 6, padding: 10, marginBottom: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <strong>{p.id}</strong>
                <button onClick={() => remove(p.id)} style={{ ...btn, padding: "2px 8px" }}>
                  delete
                </button>
              </div>
              <div style={{ color: "#666", fontSize: 13 }}>
                v{p.version} · {p.name} · {p.grants.length} grant(s)
                {p.fail_open ? " · fail-open" : ""}
              </div>
              {p.grants.map((g, i) => (
                <div key={i} style={{ fontFamily: "monospace", fontSize: 12, marginTop: 4 }}>
                  {g.resource}
                  {g.condition ? ` when ${g.condition}` : ""}
                </div>
              ))}
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h3>Upsert policy</h3>
        <input value={id} onChange={(e) => setId(e.target.value)} style={{ padding: 6, width: "100%" }} />
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={16}
          style={{ width: "100%", fontFamily: "monospace", fontSize: 12, marginTop: 8 }}
        />
        <button onClick={save} style={{ ...btn, marginTop: 8 }}>
          Save policy
        </button>
        <button onClick={propose} style={{ ...btn, marginTop: 8, marginLeft: 8 }}>
          Propose from telemetry
        </button>
        {notes.length > 0 && (
          <ul style={{ color: "#666", fontSize: 13 }}>
            {notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function KeysTab({ api, setError }: { api: Api; setError: (e: string | null) => void }) {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [name, setName] = useState("ci");
  const [created, setCreated] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const body = await api("/v1/keys");
      setKeys(body.items);
    } catch (e) {
      setError(String(e));
    }
  }, [api, setError]);

  useEffect(() => {
    void load();
  }, [load]);

  const create = async () => {
    setError(null);
    setCreated(null);
    try {
      const body = await api("/v1/keys", { method: "POST", body: JSON.stringify({ name }) });
      setCreated(body.key);
      await load();
    } catch (e) {
      setError(String(e));
    }
  };

  const revoke = async (id: string) => {
    setError(null);
    try {
      await api(`/v1/keys/${encodeURIComponent(id)}`, { method: "DELETE" });
      await load();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section>
      <h3>API keys</h3>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input value={name} onChange={(e) => setName(e.target.value)} style={{ padding: 6 }} />
        <button onClick={create} style={btn}>Create key</button>
      </div>

      {created && (
        <pre style={{ background: "#efe", padding: 12, borderRadius: 6, marginTop: 12, wordBreak: "break-all" }}>
          One-time key (store it now):{"\n"}
          {created}
        </pre>
      )}

      <table style={{ ...table, marginTop: 12 }}>
        <thead>
          <tr>
            <Th>name</Th>
            <Th>prefix</Th>
            <Th>created</Th>
            <Th>status</Th>
            <Th> </Th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.id}>
              <Td>{k.name}</Td>
              <Td mono>{k.prefix}…</Td>
              <Td>{k.createdAt}</Td>
              <Td>{k.revokedAt ? "revoked" : "active"}</Td>
              <Td>
                {!k.revokedAt && (
                  <button onClick={() => revoke(k.id)} style={{ ...btn, padding: "2px 8px" }}>
                    revoke
                  </button>
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function VerifyTab({ setError }: { setError: (e: string | null) => void }) {
  const [payload, setPayload] = useState('{\n  "entries": []\n}');
  const [result, setResult] = useState<string | null>(null);

  const run = async (path: string, body: unknown) => {
    setError(null);
    setResult(null);
    try {
      const res = await fetch(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? `${res.status}`);
      setResult(JSON.stringify(json, null, 2));
    } catch (e) {
      setError(String(e));
    }
  };

  const parse = (fn: (body: any) => void) => {
    try {
      fn(JSON.parse(payload));
    } catch (e) {
      setError(`invalid JSON: ${String(e)}`);
    }
  };

  return (
    <section>
      <h3>Independent verification</h3>
      <p style={{ color: "#666" }}>
        Paste a receipt object, or <code>{'{ "entries": [ ... ] }'}</code> for a chain. These
        endpoints require no API key.
      </p>
      <textarea
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        rows={14}
        style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
      />
      <div style={{ marginTop: 8 }}>
        <button style={btn} onClick={() => parse((b) => run("/v1/verify/receipt", b))}>
          Verify receipt
        </button>
        <button style={{ ...btn, marginLeft: 8 }} onClick={() => parse((b) => run("/v1/verify/chain", b))}>
          Verify chain
        </button>
      </div>
      {result && <pre style={pre}>{result}</pre>}
    </section>
  );
}

type Api = (path: string, init?: RequestInit) => Promise<any>;

const btn: CSSProperties = {
  padding: "6px 12px",
  border: "1px solid #ccc",
  borderRadius: 6,
  background: "#fff",
  cursor: "pointer",
};
const table: CSSProperties = { borderCollapse: "collapse", width: "100%", fontSize: 13 };
const pre: CSSProperties = {
  background: "#f6f6f6",
  padding: 12,
  borderRadius: 6,
  marginTop: 12,
  whiteSpace: "pre-wrap",
  wordBreak: "break-all",
  fontSize: 12,
};

function Th({ children }: { children: ReactNode }) {
  return <th style={{ textAlign: "left", borderBottom: "1px solid #ddd", padding: "6px 8px" }}>{children}</th>;
}
function Td({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return (
    <td style={{ borderBottom: "1px solid #eee", padding: "6px 8px", fontFamily: mono ? "monospace" : undefined }}>
      {children}
    </td>
  );
}
function Badge({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span
      style={{
        background: ok ? "#e6f7e6" : "#fde8e8",
        color: ok ? "#1a7f1a" : "#a00",
        padding: "2px 8px",
        borderRadius: 999,
        fontSize: 12,
        fontWeight: 600,
      }}
    >
      {children}
    </span>
  );
}
function short(hex: string): string {
  return hex.length > 14 ? `${hex.slice(0, 10)}…${hex.slice(-4)}` : hex;
}
