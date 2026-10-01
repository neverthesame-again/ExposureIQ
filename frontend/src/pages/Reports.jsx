import { useEffect, useState } from 'react';
import { FileText, Presentation, ClipboardCheck, Printer, ArrowLeft, Loader2, CalendarClock, Sparkles, Mail } from 'lucide-react';
import { api, fmt, md, storage } from '../lib.jsx';
import { Card, useToast } from '../components/ui.jsx';

const TYPES = [
  { id: 'weekly', icon: FileText, title: 'Weekly operations report', audience: 'SOC, vulnerability analysts, remediation owners', cadence: 'Every Monday 07:00', recipients: 'secops-dl, OpCo IT leads', replaces: 'Manual Rapid7 + Defender export merge (~6 h / week)' },
  { id: 'monthly', icon: Presentation, title: 'Monthly executive report', audience: 'Group CISO, CIO, Executive Committee', cadence: '1st business day of the month', recipients: 'group-ciso, exco-office', replaces: 'Hand-built PowerPoint (~3 days / month)' },
  { id: 'audit', icon: ClipboardCheck, title: 'Audit & compliance evidence pack', audience: 'Internal audit, ISO 27001 / NIS2 assessors', cadence: 'Quarterly · on demand', recipients: 'internal-audit', replaces: 'Evidence collection from 3 systems (~2 weeks)' },
];

export default function Reports({ company, params, companies }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(null);
  const [sched, setSched] = useState(() => storage.get('eiq-schedules', { weekly: true, monthly: true, audit: false }));
  const toast = useToast();
  const scopeName = company === 'all' ? 'SHV Group' : companies.find((c) => c.id === company)?.short;

  const generate = async (type) => {
    setLoading(type);
    try { setReport(await api(`/reports/${type}`, { params: { company } })); window.scrollTo({ top: 0 }); }
    finally { setLoading(null); }
  };
  useEffect(() => { if (params.open) generate(params.open); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const toggle = (id) => {
    const next = { ...sched, [id]: !sched[id] };
    setSched(next); storage.set('eiq-schedules', next);
    toast(next[id] ? `Scheduled: ${TYPES.find((t) => t.id === id).title}` : 'Schedule paused');
  };

  if (report) return (
    <div>
      <div className="row no-print" style={{ marginBottom: 14 }}>
        <button className="btn" onClick={() => setReport(null)}><ArrowLeft size={14} />All reports</button>
        <span className="sp" />
        <span className="badge badge-ai"><Sparkles size={11} />Narrative generated from live data</span>
        <button className="btn" onClick={() => toast('Draft email prepared for the distribution list (simulated)', 'ai')}><Mail size={14} />Email</button>
        <button className="btn btn-primary" onClick={() => window.print()}><Printer size={14} />Print / Save PDF</button>
      </div>
      <article className="doc">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#6b7280', fontSize: 12, marginBottom: 18 }}>
          <b style={{ color: '#4f46e5' }}>ExposureIQ</b> · {report.company} · {report.period} · Generated {fmt.dateY(report.generatedAt)}
        </div>
        <h1>{report.title}</h1>
        <div style={{ color: '#6b7280' }}>Audience: {report.audience}</div>
        <div className="kpis">
          <div><b>{report.kpis.exposureScore}</b><span>Exposure score (Δ {report.kpis.exposureScore - report.kpis.exposureScorePrev})</span></div>
          <div><b>{report.kpis.openP1 + report.kpis.openP2}</b><span>Open P1 + P2</span></div>
          <div><b>{report.kpis.slaCompliance}%</b><span>SLA compliance</span></div>
          <div><b>{report.kpis.coverage.pct}%</b><span>Asset coverage</span></div>
        </div>
        <h2>Summary</h2>
        {report.narrative.map((p, i) => <p key={i} style={i === 0 && report.type === 'monthly' ? { fontSize: 16, fontWeight: 600, color: '#111827' } : undefined}>{md(p)}</p>)}
        {report.actions && (<><h2>Decisions & actions requested</h2><ol>{report.actions.map((a) => <li key={a} style={{ marginBottom: 6, color: '#374151' }}>{a}</li>)}</ol></>)}
        {report.sections.map((s) => (
          <section key={s.title}>
            <h2>{s.title}</h2>
            <table>
              <thead><tr>{s.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
              <tbody>{s.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>)}</tbody>
            </table>
          </section>
        ))}
        <p style={{ marginTop: 30, fontSize: 11, color: '#9ca3af' }}>Sources: Microsoft Defender Vulnerability Management, Microsoft Defender for Endpoint, Rapid7 InsightVM, ServiceNow CMDB, CISA KEV. POC — simulated data.</p>
      </article>
    </div>
  );

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="hero-band"><Sparkles size={16} style={{ color: 'var(--ai)' }} /><span>Reports are generated from the same correlated dataset as the dashboards, scoped to <b>{scopeName}</b>. The narrative is written by the GenAI layer and every number is traceable.</span></div>
      <div className="grid g-3">
        {TYPES.map((t) => (
          <Card key={t.id}>
            <div style={{ width: 42, height: 42, borderRadius: 12, display: 'grid', placeItems: 'center', background: 'var(--accent-soft)', color: 'var(--accent)' }}><t.icon size={20} /></div>
            <h3 className="card-t" style={{ marginTop: 14, fontSize: 16 }}>{t.title}</h3>
            <div className="text-2" style={{ fontSize: 12.5, margin: '4px 0 14px' }}>{t.audience}</div>
            <div className="col" style={{ gap: 6, fontSize: 12 }}>
              <div className="row"><CalendarClock size={14} className="muted" />{t.cadence}</div>
              <div className="row"><Mail size={14} className="muted" />{t.recipients}</div>
              <div className="muted" style={{ marginTop: 4 }}>Replaces: {t.replaces}</div>
            </div>
            <div className="row mt" style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}>
              <label className="row" style={{ gap: 8, fontSize: 12.5, cursor: 'pointer' }}>
                <span onClick={() => toggle(t.id)} role="switch" aria-checked={sched[t.id]} style={{ width: 34, height: 20, borderRadius: 20, background: sched[t.id] ? 'var(--good)' : 'var(--surface-3)', position: 'relative', transition: 'background .2s', border: '1px solid var(--border)' }}>
                  <span style={{ position: 'absolute', top: 2, left: sched[t.id] ? 16 : 2, width: 14, height: 14, borderRadius: 10, background: '#fff', transition: 'left .2s' }} />
                </span>
                {sched[t.id] ? 'Scheduled' : 'Paused'}
              </label>
              <span className="sp" />
              <button className="btn btn-primary" onClick={() => generate(t.id)} disabled={!!loading}>{loading === t.id ? <Loader2 size={14} /> : <FileText size={14} />}{loading === t.id ? 'Generating…' : 'Generate'}</button>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
