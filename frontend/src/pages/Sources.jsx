import { useState } from 'react';
import { RefreshCw, CheckCircle2, ChevronDown, ChevronUp, Loader2, Sparkles, UploadCloud } from 'lucide-react';
import { useApi, api, fmt } from '../lib.jsx';
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

  const sync = async (id, name) => {
    setSyncing(id);
    try {
      const r = await api(`/integrations/${id}/sync`, { method: 'POST' });
      setLocal((l) => ({ ...l, [id]: r }));
      toast(`${name} synced — ${fmt.n(r.records)} ${r.recordLabel}`);
    } finally { setSyncing(null); }
  };

  return (
    <div className="col" style={{ gap: 16 }}>
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
  const out = [['ExposureIQ dashboards', 'var(--accent)', 'security teams'], ['Power BI', 'var(--p3)', 'leadership reporting'], ['GenAI copilot', 'var(--ai)', 'Azure OpenAI'], ['ServiceNow VR', 'var(--both)', 'remediation tickets']];
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
