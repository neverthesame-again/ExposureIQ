import { useState } from 'react';
import { Sparkles, Ticket, Globe, Loader2, AlertTriangle, MessageSquareText, Check, ExternalLink } from 'lucide-react';
import { useApi, api, fmt, md, PRIORITY_COLOR, PRIORITY_LABEL, riskColor } from '../lib.jsx';
import { Drawer, KevBadge, RiskPill, SourceBadges, SlaBadge, Skeleton, useToast } from './ui.jsx';

export default function VulnDrawer({ cve, company, onClose, navigate }) {
  const { data: d, loading, reload } = useApi(`/vulnerabilities/${cve}`, { company });
  const [showAll, setShowAll] = useState(false);
  const [creating, setCreating] = useState(null);
  const toast = useToast();

  const createTicket = async (co) => {
    setCreating(co);
    try {
      const r = await api('/tickets', { method: 'POST', body: { cve, company: co } });
      toast(r.created.length ? `Created ${r.created.map((t) => t.id).join(', ')} in ServiceNow for ${r.created.length} compan${r.created.length > 1 ? 'ies' : 'y'}` : 'Tickets already exist for every affected company');
      reload();
    } finally { setCreating(null); }
  };

  const open = d?.instances.filter((i) => i.status !== 'Remediated') || [];
  const rows = showAll ? d?.instances || [] : (d?.instances || []).slice(0, 12);
  const priority = d?.risk ? (d.risk.total >= 85 ? 'P1' : d.risk.total >= 70 ? 'P2' : d.risk.total >= 50 ? 'P3' : 'P4') : null;

  return (
    <Drawer open onClose={onClose}
      title={loading && !d ? cve : <><span className="mono">{d.cve}</span> · {d.title}</>}
      sub={d ? `${d.product} · published ${fmt.dateY(d.published)} · ${d.category}` : 'Loading…'}
      badges={d && <>{d.kev && <KevBadge />}{priority && <span className="badge"><span className="dot" style={{ background: PRIORITY_COLOR[priority] }} />{priority} · {PRIORITY_LABEL[priority]}</span>}<span className="badge">{d.exploit} exploit</span></>}
      actions={d && <button className="btn btn-primary" onClick={() => createTicket(company)} disabled={!!creating || !open.length}>{creating ? <Loader2 size={14} className="spin" /> : <Ticket size={14} />}Create tickets</button>}>
      {!d ? <><Skeleton h={90} /><div className="mt" /><Skeleton h={220} /></> : (
        <>
          <div className="grid g-4">
            <Stat label="Unified risk" value={d.risk ? d.risk.total : '—'} color={d.risk ? riskColor(d.risk.total) : undefined} note={d.riskAsset ? `on ${d.riskAsset}` : ''} />
            <Stat label="CVSS" value={d.cvss.toFixed(1)} note="technical severity" />
            <Stat label="EPSS" value={`${Math.round(d.epss * 100)}%`} note="exploit probability" />
            <Stat label="Open instances" value={open.length} note={`${d.instances.length - open.length} remediated`} />
          </div>

          {d.risk && (
            <>
              <div className="section-t">Why this score</div>
              <div className="col" style={{ gap: 9 }}>
                {d.risk.breakdown.map((b) => (
                  <div key={b.factor} style={{ display: 'grid', gridTemplateColumns: '170px 1fr 54px', gap: 12, alignItems: 'center' }}>
                    <div><div style={{ fontWeight: 600, fontSize: 12.5 }}>{b.factor}</div><div className="muted" style={{ fontSize: 11 }}>{b.detail}</div></div>
                    <div className="bar-track" style={{ height: 8 }}><div style={{ width: `${(b.points / b.max) * 100}%`, background: 'var(--accent)' }} /></div>
                    <div className="num" style={{ textAlign: 'right', fontWeight: 700 }}>{b.points}<span className="muted" style={{ fontWeight: 500 }}>/{b.max}</span></div>
                  </div>
                ))}
              </div>
            </>
          )}

          <div className="section-t">Two tools, one truth</div>
          <div className="grid g-3">
            <ToolCard name="Rapid7 InsightVM" color="var(--r7)" data={d.sourceView.r7} lines={(r) => [`Severity: ${r.label}`, `Risk score: ${fmt.n(r.riskScore)}`, `${r.instances} instances`]} />
            <ToolCard name="Defender VM" color="var(--mde)" data={d.sourceView.mde} lines={(m) => [`Severity: ${m.label}`, `Exposure impact: ${m.exposureImpact}`, `${m.instances} instances`]} />
            <div className="card" style={{ padding: 14, borderColor: 'var(--both)', boxShadow: 'none' }}>
              <div className="row" style={{ gap: 6, fontWeight: 700, fontSize: 12.5 }}><span className="src src-Both">EIQ</span>ExposureIQ unified</div>
              <div className="col" style={{ gap: 2, marginTop: 8, fontSize: 12.5 }}>
                <span>Priority: <b style={{ color: priority ? PRIORITY_COLOR[priority] : undefined }}>{priority || '—'}</b></span>
                <span>SLA: {priority ? { P1: 7, P2: 30, P3: 60, P4: 90 }[priority] : '—'} days</span>
                <span>{d.instances.length} unique instances ({d.sourceView.overlap} seen by both)</span>
              </div>
            </div>
          </div>
          {d.sourceView.disagreement && (
            <div className="hero-band mt-s" style={{ marginBottom: 0 }}>
              <AlertTriangle size={16} style={{ color: 'var(--warn)', flex: 'none' }} />
              <span>The tools disagree: Rapid7 says <b>{d.sourceView.r7.label}</b>, Defender says <b>{d.sourceView.mde.label}</b>. ExposureIQ resolves this per asset using business context, so every company gets the same answer.</span>
            </div>
          )}

          <div className="section-t">AI remediation guidance</div>
          <div className="card ai-card" style={{ boxShadow: 'none' }}>
            <div className="ai-head"><Sparkles size={14} className="sparkle" />{d.ai.model}</div>
            <div className="mt-s">{d.ai.summary.map((s, i) => <p key={i} className="ai-p">{md(s)}</p>)}</div>
            <ol style={{ margin: '6px 0 8px', paddingLeft: 18, color: 'var(--text-2)' }}>
              {d.ai.steps.map((s, i) => <li key={i} style={{ marginBottom: 4 }}>{s}</li>)}
            </ol>
            <div className="text-2" style={{ fontSize: 12.5 }}><b style={{ color: 'var(--text)' }}>Compensating control:</b> {d.ai.compensating}</div>
            <div className="row mt">
              <button className="btn btn-ai btn-sm" onClick={() => navigate('copilot', { q: `Explain ${d.cve}` })}><MessageSquareText size={13} />Ask ExposureIQ</button>
              <a className="btn btn-sm" href={`https://nvd.nist.gov/vuln/detail/${d.cve}`} target="_blank" rel="noreferrer" style={{ display: d.cve.startsWith('CVE') ? undefined : 'none' }}><ExternalLink size={13} />NVD</a>
            </div>
          </div>

          {d.byCompany.length > 0 && (
            <>
              <div className="section-t">Accountability by company</div>
              <table className="t">
                <thead><tr><th>Company</th><th className="r">Open</th><th className="r">Breached</th><th>ServiceNow</th><th /></tr></thead>
                <tbody>
                  {d.byCompany.map((c) => (
                    <tr key={c.id}>
                      <td style={{ fontWeight: 600 }}>{c.name}</td>
                      <td className="r num">{c.open}</td>
                      <td className="r num" style={{ color: c.breached ? 'var(--bad)' : undefined }}>{c.breached}</td>
                      <td>{c.ticket ? <span className="badge badge-good"><Check size={11} />{c.ticket.id} · {c.ticket.state}</span> : <span className="muted">No ticket</span>}</td>
                      <td className="r">{!c.ticket && <button className="btn btn-sm" disabled={!!creating} onClick={() => createTicket(c.id)}>{creating === c.id ? <Loader2 size={12} /> : <Ticket size={12} />}Create</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          <div className="section-t">Affected instances ({d.instances.length})</div>
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Host</th><th>Company</th><th>Asset</th><th>Seen by</th><th className="r">Risk</th><th className="r">Age</th><th>SLA</th></tr></thead>
              <tbody>
                {rows.map((i) => (
                  <tr key={i.id} className="click" onClick={() => navigate('assets', { asset: i.assetId })} style={{ opacity: i.status === 'Remediated' ? 0.55 : 1 }}>
                    <td><span className="mono" style={{ fontWeight: 600 }}>{i.hostname}</span>{i.internetFacing && <Globe size={12} style={{ marginLeft: 6, color: 'var(--p2)' }} title="Internet-facing" />}</td>
                    <td>{i.companyName}</td>
                    <td><div>{i.type}</div><div className="muted" style={{ fontSize: 11 }}>{i.criticality} · {i.service}</div></td>
                    <td><SourceBadges sources={i.sources.length === 2 ? ['Both'] : i.sources} /></td>
                    <td className="r"><RiskPill risk={i.risk} showPriority={false} /></td>
                    <td className="r num">{i.ageDays} d</td>
                    <td>{i.status === 'Remediated' ? <span className="badge">Fixed {fmt.date(i.remediatedAt)}</span> : <SlaBadge state={i.sla} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {d.instances.length > 12 && !showAll && <button className="btn btn-sm mt-s" onClick={() => setShowAll(true)}>Show all {d.instances.length}</button>}
        </>
      )}
    </Drawer>
  );
}

function Stat({ label, value, note, color }) {
  return (
    <div className="card" style={{ padding: 12, boxShadow: 'none' }}>
      <div className="muted" style={{ fontSize: 11.5 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 800, color, letterSpacing: '-0.02em' }}>{value}</div>
      <div className="muted" style={{ fontSize: 11, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{note}</div>
    </div>
  );
}

function ToolCard({ name, color, data, lines }) {
  return (
    <div className="card" style={{ padding: 14, boxShadow: 'none', opacity: data ? 1 : 0.6 }}>
      <div className="row" style={{ gap: 6, fontWeight: 700, fontSize: 12.5 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: color }} />{name}</div>
      <div className="col" style={{ gap: 2, marginTop: 8, fontSize: 12.5, color: 'var(--text-2)' }}>
        {data ? lines(data).map((l) => <span key={l}>{l}</span>) : <span>Not assessed by this tool</span>}
      </div>
    </div>
  );
}
