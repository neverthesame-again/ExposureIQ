import { useState } from 'react';
import { RefreshCw, CheckCircle2, ChevronDown, ChevronUp, Loader2, Sparkles, UploadCloud, PlugZap, XCircle, KeyRound } from 'lucide-react';
import { useApi, usePoll, api, fmt, agoShort } from '../lib.jsx';
import { Card, LoadingGrid, ErrorState, useToast } from '../components/ui.jsx';

const VENDOR_COLOR = { Microsoft: 'var(--mde)', Rapid7: 'var(--r7)', ServiceNow: 'var(--both)', 'Public threat intel': 'var(--p1)' };

export default function Sources() {
  const { data, error, loading, reload } = useApi('/integrations');
  const [syncing, setSyncing] = useState(null);
  const [open, setOpen] = useState(null);
  const [local, setLocal] = useState({});
  const toast = useToast();
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <LoadingGrid />;

  const LIVE_SOURCE = { mdvm: 'MDE', mde: 'MDE', r7: 'R7', cmdb: 'CMDB', kev: 'INTEL' };
  const sync = async (id, name) => {
    setSyncing(id);
    try {
      if (LIVE_SOURCE[id]) {
        await api('/live/trigger', { method: 'POST', body: { source: LIVE_SOURCE[id] } });
        toast(`${name} sync started: watch it on the Command Center`);
        setTimeout(reload, 2500);
      } else {
        const r = await api(`/integrations/${id}/sync`, { method: 'POST' });
        setLocal((l) => ({ ...l, [id]: r }));
        toast(`${name} synced: ${fmt.n(r.records)} ${r.recordLabel}`);
      }
    } catch (e) {
      toast(`${name}: ${e.message}`, 'ai');
    } finally { setSyncing(null); }
  };

  return (
    <div className="col" style={{ gap: 16 }}>
      <Connections />
      <Card title="Data pipeline" sub="Rapid7 stays a source · MDVM is the exposure layer · Power BI and GenAI sit on top">
        <Pipeline />
      </Card>
      <div className="grid g-2">
        {data.map((raw) => {
          const i = local[raw.id] || raw;
          return (
            <Card key={i.id}>
              <div className="row" style={{ alignItems: 'flex-start' }}>
                <div style={{ width: 38, height: 38, borderRadius: 10, display: 'grid', placeItems: 'center', background: `color-mix(in srgb, ${VENDOR_COLOR[i.vendor] || 'var(--ai)'} 16%, transparent)`, color: VENDOR_COLOR[i.vendor] || 'var(--ai)', fontWeight: 800, fontSize: 13, flex: 'none' }}>
                  {i.id === 'aoai' ? <Sparkles size={17} /> : i.id === 'pbi' ? <UploadCloud size={17} /> : i.name.split(' ').map((w) => w[0]).slice(0, 2).join('')}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="row wrap" style={{ gap: 6 }}>
                    <b style={{ fontSize: 14 }}>{i.name}</b>
                    <span className={`badge ${i.status === 'Connected' ? 'badge-good' : i.status === 'Simulated' ? 'badge-ai' : ''}`}>{i.status === 'Connected' && <CheckCircle2 size={11} />}{i.status}</span>
                    {i.badge && <span className="badge badge-ai">{i.badge}</span>}
                  </div>
                  <div className="muted" style={{ fontSize: 12 }}>{i.role}</div>
                </div>
                {i.syncAgoMin != null && (
                  <button className="btn btn-sm" onClick={() => sync(i.id, i.name)} disabled={syncing === i.id}>
                    {syncing === i.id ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />}{syncing === i.id ? 'Syncing…' : 'Sync now'}
                  </button>
                )}
              </div>
              <div className="grid g-3 mt" style={{ gap: 10 }}>
                <Mini label="Records" value={i.records ? fmt.n(i.records) : '—'} sub={i.recordLabel} />
                <Mini label="Last sync" value={i.lastSync ? fmt.ago(i.lastSync) : '—'} sub={i.frequency} />
                <Mini label="Method" value={i.method.split('·')[0]} sub={i.method.split('·')[1] || ''} />
              </div>
              <button className="link-btn mt-s" onClick={() => setOpen(open === i.id ? null : i.id)}>{open === i.id ? <ChevronUp size={13} /> : <ChevronDown size={13} />}Field mapping</button>
              {open === i.id && <div className="row wrap mt-s" style={{ gap: 5 }}>{i.fields.map((f) => <span key={f} className="cite mono">{f}</span>)}</div>}
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function Mini({ label, value, sub }) {
  return (
    <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 10, padding: '8px 10px', minWidth: 0 }}>
      <div className="muted" style={{ fontSize: 11 }}>{label}</div>
      <div style={{ fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{value}</div>
      <div className="muted" style={{ fontSize: 11, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{sub}</div>
    </div>
  );
}

function Pipeline() {
  const src = [['Rapid7 InsightVM', 'var(--r7)', 'network & appliance scans'], ['Defender for Endpoint', 'var(--mde)', 'agent telemetry'], ['ServiceNow CMDB', 'var(--both)', 'criticality & owners'], ['CISA KEV · EPSS', 'var(--p1)', 'threat intelligence']];
  const out = [['ExposureIQ dashboards', 'var(--accent)', 'security teams'], ['Power BI', 'var(--p3)', 'leadership reporting'], ['AI agents', 'var(--ai)', 'Google Gemini'], ['ServiceNow VR', 'var(--both)', 'remediation tickets']];
  const W = 1000, H = 280, nw = 200, nh = 50;
  const ys = (i) => 12 + i * 66;
  const core = { x: 400, y: 40, w: 200, h: 200 };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxHeight: 300 }} role="img" aria-label="Data pipeline diagram">
      <style>{`.flow{stroke-dasharray:6 6;animation:dash 1.2s linear infinite}@keyframes dash{to{stroke-dashoffset:-12}}`}</style>
      {src.map(([, c], i) => <path key={i} className="flow" d={`M${nw + 10},${ys(i) + nh / 2} C${330},${ys(i) + nh / 2} ${330},${core.y + core.h / 2} ${core.x},${core.y + core.h / 2}`} stroke={c} strokeWidth="2" fill="none" opacity="0.8" />)}
      {out.map(([, c], i) => <path key={i} className="flow" d={`M${core.x + core.w},${core.y + core.h / 2} C${670},${core.y + core.h / 2} ${670},${ys(i) + nh / 2} ${W - nw - 10},${ys(i) + nh / 2}`} stroke={c} strokeWidth="2" fill="none" opacity="0.8" />)}
      {src.map(([t, c, s], i) => <Node key={t} x={10} y={ys(i)} w={nw} h={nh} title={t} sub={s} color={c} />)}
      {out.map(([t, c, s], i) => <Node key={t} x={W - nw - 10} y={ys(i)} w={nw} h={nh} title={t} sub={s} color={c} />)}
      <rect x={core.x} y={core.y} width={core.w} height={core.h} rx="18" fill="var(--surface-2)" stroke="var(--ai)" strokeWidth="1.5" />
      <text x={core.x + core.w / 2} y={core.y + 30} textAnchor="middle" style={{ fontSize: 15, fontWeight: 800, fill: 'var(--text)' }}>MDVM + ExposureIQ</text>
      {['Normalise assets & CVEs', 'Correlate & de-duplicate', 'Unified risk score', 'SLA & accountability'].map((s, i) => (
        <g key={s} transform={`translate(${core.x + 18}, ${core.y + 50 + i * 36})`}>
          <rect width={core.w - 36} height="28" rx="8" fill="var(--surface)" stroke="var(--border-strong)" />
          <text x={(core.w - 36) / 2} y="18" textAnchor="middle" style={{ fontSize: 12, fontWeight: 600, fill: 'var(--text-2)' }}>{s}</text>
        </g>
      ))}
    </svg>
  );
}

function Node({ x, y, w, h, title, sub, color }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="12" fill="var(--surface-2)" stroke="var(--border-strong)" />
      <rect x={x} y={y + 10} width="4" height={h - 20} rx="2" fill={color} />
      <text x={x + 16} y={y + 21} style={{ fontSize: 13, fontWeight: 700, fill: 'var(--text)' }}>{title}</text>
      <text x={x + 16} y={y + 38} style={{ fontSize: 11.5, fill: 'var(--muted)' }}>{sub}</text>
    </g>
  );
}

const MODE_TEXT = {
  mock: 'Running on the built-in mock tenant: realistic Defender, Rapid7 and ServiceNow API responses. Add credentials to backend/.env and restart to switch to your real systems.',
  live: 'Live: syncing from your real systems. Sources without credentials are switched off.',
};

function Connections() {
  const { data } = usePoll('/connectors', 5000);
  const [tests, setTests] = useState({});
  const [testing, setTesting] = useState(null);
  const [setup, setSetup] = useState(false);
  if (!data) return null;
  const test = async (id) => {
    setTesting(id);
    try { const r = await api(`/connectors/${id}/test`, { method: 'POST' }); setTests((t) => ({ ...t, [id]: r })); } finally { setTesting(null); }
  };
  return (
    <Card title="Connections" sub={MODE_TEXT[data.mode]} icon={<PlugZap size={16} />} flush
      action={<span className={`mode-badge ${data.mode}`} style={{ fontSize: 12, padding: '4px 10px' }}>{data.mode === 'mock' ? 'Mock tenant' : 'Live'}</span>}>
      <div className="conn-row" style={{ borderTop: 0, paddingTop: 0, color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
        <span>Connector</span><span>Mode</span><span>Status</span><span>Last sync</span><span />
      </div>
      {data.connectors.map((c) => {
        const t = tests[c.id];
        return (
          <div key={c.id} className="conn-row">
            <b>{c.name}</b>
            <span className={`mode-badge ${c.mode}`}>{c.mode}</span>
            <span style={{ minWidth: 0 }}>
              {t ? <span className="row" style={{ gap: 6, color: t.ok ? 'var(--good-text)' : 'var(--bad)' }}>{t.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}{t.detail}</span>
                : c.lastError ? <span style={{ color: 'var(--bad)' }}>{c.lastError}</span>
                  : c.mode === 'off' ? <span className="muted">Not configured</span>
                    : c.id === 'soc' ? <span className="text-2">{c.mode === 'live' ? 'Webhook ready' : 'Ready: escalations are logged (no webhook set)'}{c.calls ? ` · ${fmt.n(c.calls)} sent` : ''}</span>
                    : <span className="text-2">{c.lastCount != null ? `${fmt.n(c.lastCount)} records in last sync` : 'Waiting for first sync'}{c.calls ? ` · ${fmt.n(c.calls)} API calls` : ''}</span>}
            </span>
            <span className="muted">{c.lastSync ? agoShort(c.lastSync) : '—'}</span>
            <button className="btn btn-sm" onClick={() => test(c.id)} disabled={testing === c.id}>{testing === c.id ? <Loader2 size={12} className="spin" /> : <PlugZap size={12} />}Test</button>
          </div>
        );
      })}
      <div className="conn-row">
        <b>Gemini (AI agents)</b>
        <span className={`mode-badge ${data.ai.enabled ? 'live' : 'off'}`}>{data.ai.enabled ? 'live' : 'off'}</span>
        <span style={{ minWidth: 0 }}>
          {data.ai.lastError ? <span style={{ color: 'var(--bad)' }}>{data.ai.lastError}</span>
            : data.ai.enabled ? <span className="text-2">{data.ai.model} · {fmt.n(data.ai.runs)} agent runs · {fmt.n(data.ai.calls)} model calls · {fmt.n(data.ai.inputTokens + data.ai.outputTokens)} tokens</span>
              : <span className="muted">No GEMINI_API_KEY: agents use the rules engine</span>}
        </span>
        <span />
        <span />
      </div>
      <div style={{ padding: '10px 18px 14px', borderTop: '1px solid var(--border)' }}>
        <button className="link-btn" onClick={() => setSetup(!setup)}><KeyRound size={13} />{setup ? 'Hide' : 'How to connect your systems'}</button>
        {setup && (
          <div className="setup text-2" style={{ fontSize: 12.5, marginTop: 8 }}>
            Fill in <span className="mono">backend/.env</span> (template: <span className="mono">backend/.env.example</span>) and restart the backend. Credentials stay on the server and are never sent to the browser.
            <pre>{`GEMINI_API_KEY=...                  # AI agents
DEFENDER_TENANT_ID=...              # Entra app: Machine.Read.All, Vulnerability.Read.All
DEFENDER_CLIENT_ID=...
DEFENDER_CLIENT_SECRET=...
RAPID7_CONSOLE_URL=https://insightvm.example.com:3780
RAPID7_USERNAME=...
RAPID7_PASSWORD=...
SERVICENOW_INSTANCE=https://yourco.service-now.com
SERVICENOW_USERNAME=...
SERVICENOW_PASSWORD=...
SOC_WEBHOOK_URL=...                 # optional: Teams/Slack incoming webhook`}</pre>
          </div>
        )}
      </div>
    </Card>
  );
}
