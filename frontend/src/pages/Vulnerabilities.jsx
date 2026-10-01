import { useMemo, useState } from 'react';
import { Search, Flame, Globe, Download, ArrowDown, Ticket, X } from 'lucide-react';
import { useApi, fmt, downloadCsv } from '../lib.jsx';
import { Card, RiskPill, SourceBadges, KevBadge, ErrorState, Skeleton } from '../components/ui.jsx';
import VulnDrawer from '../components/VulnDrawer.jsx';

const PRIOS = ['P1', 'P2', 'P3', 'P4'];
const COLS = [
  { id: 'risk', label: 'Risk', sort: 'risk' },
  { id: 'cve', label: 'Vulnerability' },
  { id: 'src', label: 'Seen by' },
  { id: 'assets', label: 'Assets', sort: 'assets', r: true },
  { id: 'co', label: 'Companies' },
  { id: 'age', label: 'Oldest', sort: 'age', r: true },
  { id: 'sla', label: 'SLA', sort: 'breached' },
  { id: 'ticket', label: 'Ticket' },
];

export default function Vulnerabilities({ company, params, navigate, companies }) {
  const [q, setQ] = useState(params.q || '');
  const [prio, setPrio] = useState(params.priority ? params.priority.split(',') : []);
  const [source, setSource] = useState(params.source || '');
  const [kev, setKev] = useState(params.kev === 'true');
  const [internet, setInternet] = useState(params.internet === 'true');
  const [sla, setSla] = useState(params.sla || '');
  const [status, setStatus] = useState(params.status || 'open');
  const [sort, setSort] = useState('risk');
  const [limit, setLimit] = useState(40);
  const selected = params.cve;

  const query = { company, q, priority: prio.join(','), source, kev: kev ? 'true' : '', internet: internet ? 'true' : '', sla, status, sort };
  const { data, loading, error, reload } = useApi('/vulnerabilities', query);
  const short = useMemo(() => Object.fromEntries(companies.map((c) => [c.id, c.short])), [companies]);

  const setParam = (cve) => navigate('vulnerabilities', { ...params, cve });
  const togglePrio = (p) => setPrio((cur) => (cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p]));
  const activeFilters = prio.length + (source ? 1 : 0) + (kev ? 1 : 0) + (internet ? 1 : 0) + (sla ? 1 : 0) + (q ? 1 : 0);
  const clear = () => { setQ(''); setPrio([]); setSource(''); setKev(false); setInternet(false); setSla(''); };

  const exportCsv = () => downloadCsv(`exposureiq-vulnerabilities-${company}.csv`,
    ['CVE', 'Title', 'Product', 'Unified risk', 'Priority', 'CVSS', 'EPSS', 'KEV', 'Open assets', 'Companies', 'Seen by', 'Oldest (days)', 'Breached', 'Tickets'],
    data.rows.map((r) => [r.cve, r.title, r.product, r.maxRisk, r.priority, r.cvss, r.epss, r.kev ? 'Yes' : 'No', r.assets, r.companies.map((c) => short[c]).join('; '), r.sources.join('; '), r.oldestDays, r.breached, r.tickets.join('; ')]));

  return (
    <>
      <div className="filters">
        <div className="searchbox" style={{ minWidth: 260 }}>
          <Search size={14} />
          <input className="input" style={{ border: 0, padding: 0, background: 'transparent', outline: 'none', flex: 1 }} placeholder="CVE, product or title…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="seg" role="group" aria-label="Priority">
          {PRIOS.map((p) => <button key={p} className={prio.includes(p) ? 'on' : ''} onClick={() => togglePrio(p)}><span className="dot" style={{ width: 7, height: 7, borderRadius: 9, background: `var(--${p.toLowerCase()})` }} />{p}</button>)}
        </div>
        <div className="seg" role="group" aria-label="Source">
          {[['', 'All sources'], ['Both', 'Both'], ['MDE', 'Defender only'], ['R7', 'Rapid7 only']].map(([v, l]) => <button key={v} className={source === v ? 'on' : ''} onClick={() => setSource(v)}>{l}</button>)}
        </div>
        <button className={`chip ${kev ? 'on' : ''}`} onClick={() => setKev(!kev)}><Flame size={13} />Actively exploited</button>
        <button className={`chip ${internet ? 'on' : ''}`} onClick={() => setInternet(!internet)}><Globe size={13} />Internet-facing</button>
        <select className="select" value={sla} onChange={(e) => setSla(e.target.value)} aria-label="SLA state">
          <option value="">Any SLA state</option>
          <option>Breached</option><option>Due soon</option><option>On track</option><option>Exception</option>
        </select>
        <select className="select" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="open">Open</option><option value="remediated">Remediated</option><option value="all">All statuses</option>
        </select>
        {activeFilters > 0 && <button className="btn btn-ghost btn-sm" onClick={clear}><X size={13} />Clear {activeFilters}</button>}
        <span className="sp" />
        {data && <span className="muted" style={{ fontSize: 12 }}><b style={{ color: 'var(--text)' }}>{fmt.n(data.total)}</b> vulnerabilities · {fmt.n(data.findings)} findings</span>}
        <button className="btn btn-sm" onClick={exportCsv} disabled={!data}><Download size={13} />CSV</button>
      </div>

      {error ? <ErrorState error={error} onRetry={reload} /> : (
        <Card flush>
          <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: 'opacity .15s' }}>
            <table className="t">
              <thead>
                <tr>
                  {COLS.map((c) => (
                    <th key={c.id} className={`${c.sort ? 'sortable' : ''} ${c.r ? 'r' : ''}`} onClick={() => c.sort && setSort(c.sort)}>
                      {c.label}{sort === c.sort && <ArrowDown size={11} style={{ marginLeft: 3, verticalAlign: -1 }} />}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {!data && [0, 1, 2, 3, 4, 5].map((i) => <tr key={i}><td colSpan={8}><Skeleton h={28} /></td></tr>)}
                {data?.rows.slice(0, limit).map((r) => (
                  <tr key={r.cve} className={`click ${selected === r.cve ? 'sel' : ''}`} onClick={() => setParam(r.cve)}>
                    <td><RiskPill risk={r.maxRisk} /></td>
                    <td className="title-cell">
                      <div className="row" style={{ gap: 6 }}><span className="mono" style={{ fontWeight: 600 }}>{r.cve}</span>{r.kev && <KevBadge />}{r.internetFacing > 0 && <span className="badge" title="Internet-facing instances"><Globe size={11} />{r.internetFacing}</span>}</div>
                      <div className="ttl" title={r.title}>{r.title}</div>
                      <div className="muted" style={{ fontSize: 11 }}>{r.product} · CVSS {r.cvss.toFixed(1)} · EPSS {Math.round(r.epss * 100)}%</div>
                    </td>
                    <td><SourceBadges sources={r.sources} /></td>
                    <td className="r num" style={{ fontWeight: 700 }}>{r.assets}</td>
                    <td><div className="row wrap" style={{ gap: 4 }}>{r.companies.map((c) => <span key={c} className="badge">{short[c] || c}</span>)}</div></td>
                    <td className="r num">{status === 'remediated' ? '—' : `${r.oldestDays} d`}</td>
                    <td>{r.breached > 0 ? <span className="badge badge-bad">{r.breached} breached</span> : r.dueSoon > 0 ? <span className="badge badge-warn">{r.dueSoon} due soon</span> : <span className="badge badge-good">On track</span>}</td>
                    <td>{r.tickets.length ? <span className="badge"><Ticket size={11} />{r.tickets.length}</span> : <span className="muted">—</span>}</td>
                  </tr>
                ))}
                {data && !data.rows.length && <tr><td colSpan={8} className="empty">No vulnerabilities match these filters.</td></tr>}
              </tbody>
            </table>
          </div>
          {data && data.rows.length > limit && (
            <div style={{ padding: 12, textAlign: 'center', borderTop: '1px solid var(--border)' }}>
              <button className="btn btn-sm" onClick={() => setLimit(limit + 40)}>Show more ({data.rows.length - limit} remaining)</button>
            </div>
          )}
        </Card>
      )}

      {selected && <VulnDrawer cve={selected} company={company} navigate={navigate} onClose={() => setParam(undefined)} />}
    </>
  );
}
