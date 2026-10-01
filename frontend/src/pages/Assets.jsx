import { useState } from 'react';
import { Search, Globe, EyeOff, Radar, Download, Check, Minus } from 'lucide-react';
import { useApi, fmt, downloadCsv } from '../lib.jsx';
import { Card, RiskPill, SourceBadges, SlaBadge, KevBadge, Drawer, ErrorState, Skeleton } from '../components/ui.jsx';
import { Donut, SegBar, Legend } from '../components/charts.jsx';

const COV = [
  { key: 'both', label: 'Both tools', color: 'var(--both)' },
  { key: 'mdeOnly', label: 'Defender only', color: 'var(--mde)' },
  { key: 'r7Only', label: 'Rapid7 only', color: 'var(--r7)' },
  { key: 'none', label: 'Not assessed', color: 'var(--none)' },
];
const TYPES = ['Workstation', 'Server', 'Cloud VM', 'Network Device', 'OT / IoT'];

export default function Assets({ company, params, navigate }) {
  const [q, setQ] = useState('');
  const [type, setType] = useState('');
  const [coverage, setCoverage] = useState(params.coverage || '');
  const [internet, setInternet] = useState(false);
  const [limit, setLimit] = useState(50);
  const { data, loading, error, reload } = useApi('/assets', { company, q, type, coverage, internet: internet ? 'true' : '' });
  const open = (id) => navigate('assets', { ...params, asset: id });

  if (error) return <ErrorState error={error} onRetry={reload} />;
  const c = data?.coverage;

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="grid g-main-r">
        <Card title="Scanner coverage" sub="Share of known assets assessed by at least one tool">
          {!c ? <Skeleton h={180} /> : (
            <div className="row" style={{ gap: 22, alignItems: 'center' }}>
              <Donut segments={COV.map((s) => ({ label: s.label, value: c[s.key], color: s.color }))} center={`${c.pct}%`} sub="covered" size={160} />
              <div className="col" style={{ gap: 8, flex: 1 }}>
                {COV.map((s) => (
                  <button key={s.key} className={`task ${coverage === ({ both: 'both', mdeOnly: 'mde', r7Only: 'r7', none: 'none' })[s.key] ? 'sel' : ''}`} style={{ alignItems: 'center', padding: '4px 6px' }}
                    onClick={() => setCoverage(({ both: 'both', mdeOnly: 'mde', r7Only: 'r7', none: 'none' })[s.key])}>
                    <span style={{ width: 10, height: 10, borderRadius: 3, background: s.color }} /><span style={{ flex: 1 }}>{s.label}</span><b className="num" style={{ color: 'var(--text)' }}>{fmt.n(c[s.key])}</b>
                  </button>
                ))}
              </div>
            </div>
          )}
          {data && (
            <div className="hero-band mt" style={{ marginBottom: 0 }}>
              <EyeOff size={16} style={{ color: 'var(--warn)', flex: 'none' }} />
              <span><b>{c.none} blind spots.</b> {data.discovery.mdeDiscovered} were spotted by Defender device discovery but aren't onboarded; {data.discovery.cmdbOnly} exist only in the CMDB. <button className="link-btn" onClick={() => setCoverage('none')}>Show them</button></span>
            </div>
          )}
        </Card>

        <Card title="Who sees what" sub="Each tool is blind somewhere — together they cover the estate" icon={<Radar size={16} />}>
          {!data ? <Skeleton h={200} /> : (
            <>
              <div className="col" style={{ gap: 14 }}>
                {data.byType.map((t) => (
                  <button key={t.type} className="task" style={{ display: 'block', padding: 6 }} onClick={() => setType(type === t.type ? '' : t.type)}>
                    <div className="row" style={{ marginBottom: 6 }}>
                      <b style={{ color: 'var(--text)' }}>{t.type}</b>
                      <span className="muted" style={{ fontSize: 12 }}>{fmt.n(t.total)} assets</span>
                      <span className="sp" />
                      <span style={{ fontSize: 12, color: t.pct < 90 ? 'var(--warn)' : 'var(--text-2)', fontWeight: 600 }}>{t.pct}% covered</span>
                    </div>
                    <SegBar segments={COV.map((s) => ({ label: s.label, value: t[s.key], color: s.color }))} height={12} />
                  </button>
                ))}
              </div>
              <div className="mt"><Legend items={COV} /></div>
            </>
          )}
        </Card>
      </div>

      <div>
        <div className="filters">
          <div className="searchbox" style={{ minWidth: 260 }}>
            <Search size={14} />
            <input className="input" style={{ border: 0, padding: 0, background: 'transparent', outline: 'none', flex: 1 }} placeholder="Hostname, IP, OS or service…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="select" value={type} onChange={(e) => setType(e.target.value)} aria-label="Asset type">
            <option value="">All asset types</option>
            {TYPES.map((t) => <option key={t}>{t}</option>)}
          </select>
          <div className="seg">
            {[['', 'Any coverage'], ['both', 'Both'], ['mde', 'Defender only'], ['r7', 'Rapid7 only'], ['none', 'Not assessed']].map(([v, l]) => <button key={v} className={coverage === v ? 'on' : ''} onClick={() => setCoverage(v)}>{l}</button>)}
          </div>
          <button className={`chip ${internet ? 'on' : ''}`} onClick={() => setInternet(!internet)}><Globe size={13} />Internet-facing</button>
          <span className="sp" />
          {data && <span className="muted" style={{ fontSize: 12 }}><b style={{ color: 'var(--text)' }}>{fmt.n(data.total)}</b> assets</span>}
          <button className="btn btn-sm" disabled={!data} onClick={() => downloadCsv(`exposureiq-assets-${company}.csv`,
            ['Hostname', 'Company', 'Type', 'OS', 'IP', 'Site', 'Service', 'Criticality', 'Internet-facing', 'Defender', 'Rapid7', 'Open findings', 'Max risk', 'Owner'],
            data.rows.map((r) => [r.hostname, r.companyName, r.type, r.os, r.ip, r.site, r.service, r.criticality, r.internetFacing ? 'Yes' : 'No', r.mde ? 'Yes' : 'No', r.r7 ? 'Yes' : 'No', r.openFindings, r.maxRisk, r.owner]))}><Download size={13} />CSV</button>
        </div>
        <Card flush>
          <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1 }}>
            <table className="t">
              <thead><tr><th>Asset</th><th>Company</th><th>Type / OS</th><th>Business service</th><th>Defender</th><th>Rapid7</th><th>Matched by</th><th className="r">Open</th><th>Top risk</th></tr></thead>
              <tbody>
                {!data && [0, 1, 2, 3, 4].map((i) => <tr key={i}><td colSpan={9}><Skeleton h={26} /></td></tr>)}
                {data?.rows.slice(0, limit).map((a) => (
                  <tr key={a.id} className={`click ${params.asset === a.id ? 'sel' : ''}`} onClick={() => open(a.id)}>
                    <td><div className="row" style={{ gap: 6 }}><span className="mono" style={{ fontWeight: 600 }}>{a.hostname}</span>{a.internetFacing && <Globe size={12} style={{ color: 'var(--p2)' }} />}</div><div className="muted mono" style={{ fontSize: 11 }}>{a.ip} · {a.site}</div></td>
                    <td>{a.companyName}</td>
                    <td><div>{a.type}</div><div className="muted" style={{ fontSize: 11 }}>{a.os}</div></td>
                    <td><div>{a.service}</div><div className="muted" style={{ fontSize: 11 }}>{a.criticality}</div></td>
                    <td><Tick on={a.mde} /></td>
                    <td><Tick on={a.r7} /></td>
                    <td style={{ fontSize: 12 }}>{a.matchMethod ? <span className={a.matchConfidence < 80 ? 'badge badge-warn' : 'text-2'}>{a.matchMethod}{a.matchConfidence < 100 && ` · ${a.matchConfidence}%`}</span> : a.discovery ? <span className="badge">{a.discovery}</span> : <span className="muted">single source</span>}</td>
                    <td className="r num" style={{ fontWeight: 700 }}>{a.openFindings || <span className="muted">0</span>}</td>
                    <td>{a.maxRisk ? <span className="row" style={{ gap: 6 }}><RiskPill risk={a.maxRisk} showPriority={false} /><span className="mono muted" style={{ fontSize: 11 }}>{a.topCve}</span></span> : <span className="muted">—</span>}</td>
                  </tr>
                ))}
                {data && !data.rows.length && <tr><td colSpan={9} className="empty">No assets match.</td></tr>}
              </tbody>
            </table>
          </div>
          {data && data.rows.length > limit && <div style={{ padding: 12, textAlign: 'center', borderTop: '1px solid var(--border)' }}><button className="btn btn-sm" onClick={() => setLimit(limit + 50)}>Show more ({data.rows.length - limit} remaining)</button></div>}
        </Card>
      </div>

      {params.asset && <AssetDrawer id={params.asset} navigate={navigate} onClose={() => navigate('assets', { ...params, asset: undefined })} />}
    </div>
  );
}

function Tick({ on }) {
  return on ? <span className="badge badge-good" style={{ padding: '2px 6px' }}><Check size={11} /></span> : <span className="badge" style={{ padding: '2px 6px', opacity: 0.6 }}><Minus size={11} /></span>;
}

function AssetDrawer({ id, onClose, navigate }) {
  const { data: a } = useApi(`/assets/${id}`);
  const open = a?.findings.filter((f) => f.status !== 'Remediated') || [];
  return (
    <Drawer open onClose={onClose} title={a ? <span className="mono">{a.hostname}</span> : 'Loading…'}
      sub={a && `${a.companyName} · ${a.type} · ${a.os}`}
      badges={a && <>{a.internetFacing && <span className="badge badge-warn"><Globe size={11} />Internet-facing</span>}<span className="badge">{a.criticality}</span></>}>
      {!a ? <Skeleton h={300} /> : (
        <>
          <div className="grid g-2" style={{ gap: 10 }}>
            {[['Business service', a.service], ['Owner', a.owner], ['IP address', a.ip], ['Site', a.site], ['Defender for Endpoint', a.mde ? 'Onboarded' : 'Not onboarded'], ['Rapid7 InsightVM', a.r7 ? 'Scanned' : 'Not scanned'], ['Identity match', a.matchMethod ? `${a.matchMethod} (${a.matchConfidence}%)` : a.discovery || 'Single source'], ['Last seen', fmt.ago(a.lastSeen)]].map(([k, v]) => (
              <div key={k} className="card" style={{ padding: '10px 12px', boxShadow: 'none' }}><div className="muted" style={{ fontSize: 11 }}>{k}</div><div style={{ fontWeight: 600 }}>{v}</div></div>
            ))}
          </div>
          <div className="section-t">Findings on this asset ({open.length} open)</div>
          {!a.findings.length && <div className="empty">{a.mde || a.r7 ? 'No findings — clean asset.' : 'Not assessed by any scanner — findings unknown.'}</div>}
          <table className="t">
            <tbody>
              {a.findings.map((f) => (
                <tr key={f.id} className="click" style={{ opacity: f.status === 'Remediated' ? 0.5 : 1 }} onClick={() => navigate('vulnerabilities', { cve: f.cve, status: f.status === 'Remediated' ? 'all' : undefined })}>
                  <td><RiskPill risk={f.risk} /></td>
                  <td><div className="row" style={{ gap: 6 }}><span className="mono" style={{ fontWeight: 600 }}>{f.cve}</span>{f.kev && <KevBadge />}</div><div className="text-2" style={{ fontSize: 12 }}>{f.title}</div></td>
                  <td><SourceBadges sources={f.sources.length === 2 ? ['Both'] : f.sources} /></td>
                  <td>{f.status === 'Remediated' ? <span className="badge">Fixed</span> : <SlaBadge state={f.sla} />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Drawer>
  );
}
