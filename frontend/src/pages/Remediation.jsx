import { useState } from 'react';
import { ShieldCheck, AlertTriangle, Clock, FileWarning, Timer, Ticket, Loader2, Check, Flame } from 'lucide-react';
import { useApi, api, fmt, PRIORITY_COLOR, complianceTone } from '../lib.jsx';
import { Card, Kpi, RiskPill, ComplianceCell, KevBadge, LoadingGrid, ErrorState, useToast } from '../components/ui.jsx';
import { StackedColumns, LineChart, Legend } from '../components/charts.jsx';

const PKEYS = [
  { key: 'P4', label: 'P4', color: 'var(--p4)' },
  { key: 'P3', label: 'P3', color: 'var(--p3)' },
  { key: 'P2', label: 'P2', color: 'var(--p2)' },
  { key: 'P1', label: 'P1', color: 'var(--p1)' },
];
const toneColor = (v) => ({ good: 'var(--good)', warn: 'var(--warn)', bad: 'var(--bad)' })[complianceTone(v)];

export default function Remediation({ company, navigate }) {
  const { data, loading, error, reload } = useApi('/remediation', { company });
  const [busy, setBusy] = useState(null);
  const toast = useToast();
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <LoadingGrid />;
  const d = data;
  const mttrAll = d.mttrByPriority;

  const ticket = async (o) => {
    setBusy(`${o.cve}|${o.company}`);
    try {
      const r = await api('/tickets', { method: 'POST', body: { cve: o.cve, company: o.company } });
      toast(r.created[0] ? `${r.created[0].id} raised for ${o.owner}` : 'Ticket already exists');
      reload();
    } finally { setBusy(null); }
  };

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="grid g-4">
        <Kpi label="SLA compliance" icon={<ShieldCheck size={14} />} value={d.compliance} unit="%" foot="target ≥ 85%" tone={toneColor(d.compliance)} />
        <Kpi label="Past due" icon={<AlertTriangle size={14} />} value={fmt.n(d.breached)} foot="open findings beyond SLA" tone="var(--bad)" />
        <Kpi label="Due in the next days" icon={<Clock size={14} />} value={fmt.n(d.dueSoon)} foot="within 20% of the SLA window" />
        <Kpi label="Risk exceptions" icon={<FileWarning size={14} />} value={fmt.n(d.exceptions)} foot="accepted, with expiry" />
      </div>

      <Card title="SHV unified SLA policy" sub="One policy for every group company, driven by the unified risk score — not by any single tool's label">
        <div className="grid g-4">
          {d.policy.map((p) => (
            <div key={p.priority} style={{ borderRadius: 12, border: '1px solid var(--border)', padding: 14, background: 'var(--surface-2)', borderTop: `3px solid ${PRIORITY_COLOR[p.priority]}` }}>
              <div className="row"><b style={{ fontSize: 15 }}>{p.priority}</b><span className="muted">{p.label}</span><span className="sp" /><span style={{ fontSize: 20, fontWeight: 800 }}>{p.days}<small className="muted" style={{ fontSize: 12 }}> days</small></span></div>
              <div className="muted" style={{ fontSize: 11.5, margin: '2px 0 6px' }}>Risk ≥ {p.minRisk}</div>
              <div className="text-2" style={{ fontSize: 12 }}>{p.description}</div>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid g-main">
        <Card title="SLA compliance heatmap" sub="Share of findings fixed (or still open) within SLA, last 90 days">
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Company</th><th>Overall</th>{['P1', 'P2', 'P3', 'P4'].map((p) => <th key={p} style={{ textAlign: 'center' }}>{p}</th>)}</tr></thead>
              <tbody>
                {d.slaMatrix.map((r) => (
                  <tr key={r.id}>
                    <td style={{ fontWeight: 600 }}>{r.name}</td>
                    <td><ComplianceCell value={r.overall} /></td>
                    {['P1', 'P2', 'P3', 'P4'].map((p) => (
                      <td key={p} style={{ padding: 4 }}>
                        <div style={{ textAlign: 'center', padding: '9px 4px', borderRadius: 8, fontWeight: 700, background: `color-mix(in srgb, ${toneColor(r[p])} ${Math.round(12 + (100 - r[p]) * 0.35)}%, transparent)` }} title={`${r.name} ${p}: ${r[p]}%`}>
                          {r[p]}%
                        </div>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="legend mt-s"><span><i style={{ background: 'var(--good)' }} />≥ 85% on target</span><span><i style={{ background: 'var(--warn)' }} />70–85% at risk</span><span><i style={{ background: 'var(--bad)' }} />&lt; 70% off track</span></div>
        </Card>
        <Card title="Time to remediate vs SLA" sub="Mean days to fix, last 90 days" icon={<Timer size={16} />}>
          <div className="col" style={{ gap: 16, marginTop: 6 }}>
            {mttrAll.map((m) => {
              const max = Math.max(...mttrAll.map((x) => Math.max(x.mttr, x.target))) * 1.1;
              const over = m.mttr > m.target;
              return (
                <div key={m.priority}>
                  <div className="row" style={{ marginBottom: 5, fontSize: 12.5 }}>
                    <b style={{ color: PRIORITY_COLOR[m.priority] }}>{m.priority}</b>
                    <span className="sp" />
                    <b className="num">{m.mttr} d</b><span className="muted">/ target {m.target} d</span>
                    {over ? <span className="badge badge-bad">over</span> : <span className="badge badge-good">within</span>}
                  </div>
                  <div style={{ position: 'relative', height: 10, borderRadius: 10, background: 'var(--surface-3)' }}>
                    <div style={{ width: `${(m.mttr / max) * 100}%`, height: '100%', borderRadius: 10, background: PRIORITY_COLOR[m.priority] }} />
                    <div title={`SLA target ${m.target} d`} style={{ position: 'absolute', left: `${(m.target / max) * 100}%`, top: -4, bottom: -4, width: 2, background: 'var(--text)' }} />
                  </div>
                </div>
              );
            })}
          </div>
          <div className="muted mt" style={{ fontSize: 11.5 }}>Black tick = SLA target. P1 findings wait for emergency change windows — the biggest lever for improvement.</div>
        </Card>
      </div>

      <div className="grid g-2">
        <Card title="Open backlog by age" sub="How long open findings have been waiting">
          <StackedColumns rows={d.buckets} keys={PKEYS} height={220} />
          <div className="mt-s"><Legend items={[...PKEYS].reverse()} /></div>
        </Card>
        <Card title="Inflow vs outflow" sub="Findings detected vs remediated per week">
          <LineChart data={d.flow} series={[{ key: 'detected', label: 'Detected', color: 'var(--r7)' }, { key: 'remediated', label: 'Remediated', color: 'var(--both)' }]} height={220} />
          <div className="mt-s"><Legend items={[{ label: 'Detected', color: 'var(--r7)' }, { label: 'Remediated', color: 'var(--both)' }]} /></div>
        </Card>
      </div>

      <Card title="Overdue work" sub={`${d.overdue.length} campaigns past SLA, grouped by vulnerability and company`} flush>
        <div className="table-wrap" style={{ maxHeight: 460, overflowY: 'auto' }}>
          <table className="t">
            <thead><tr><th>Risk</th><th>Vulnerability</th><th>Company</th><th className="r">Assets</th><th className="r">Overdue</th><th>Owner</th><th>ServiceNow</th></tr></thead>
            <tbody>
              {d.overdue.slice(0, 60).map((o) => (
                <tr key={`${o.cve}|${o.company}`} className="click" onClick={() => navigate('vulnerabilities', { cve: o.cve })}>
                  <td><RiskPill risk={o.maxRisk} /></td>
                  <td className="title-cell"><div className="row" style={{ gap: 6 }}><span className="mono" style={{ fontWeight: 600 }}>{o.cve}</span>{o.kev && <KevBadge />}</div><div className="ttl text-2" style={{ fontWeight: 400 }}>{o.title}</div></td>
                  <td>{o.companyName}</td>
                  <td className="r num">{o.assets}</td>
                  <td className="r num" style={{ color: 'var(--bad)', fontWeight: 700 }}>{o.daysOverdue} d</td>
                  <td style={{ fontSize: 12 }}>{o.owner}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {o.ticket ? <span className="badge badge-good"><Check size={11} />{o.ticket.id}</span>
                      : <button className="btn btn-sm" disabled={!!busy} onClick={() => ticket(o)}>{busy === `${o.cve}|${o.company}` ? <Loader2 size={12} /> : <Ticket size={12} />}Raise</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Accountability by team" sub="Remediation owners from the CMDB, sorted by SLA compliance (worst first)" flush>
        <div className="table-wrap">
          <table className="t">
            <thead><tr><th>Owner</th><th className="r">Open</th><th className="r">Past due</th><th>SLA compliance</th><th className="r">MTTR</th></tr></thead>
            <tbody>
              {d.leaderboard.map((l) => (
                <tr key={l.owner}>
                  <td style={{ fontWeight: 600 }}>{l.owner}</td>
                  <td className="r num">{l.open}</td>
                  <td className="r num" style={{ color: l.breached ? 'var(--bad)' : undefined }}>{l.breached}</td>
                  <td><ComplianceCell value={l.compliance} /></td>
                  <td className="r num">{l.mttr} d</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
