import { useEffect, useState } from 'react';
import { Download, ScanLine, GitMerge, Gauge, Bot, Send, Ticket, BarChart3, LayoutDashboard, Loader2 } from 'lucide-react';
import { fmt } from '../lib.jsx';

export const SOURCE_META = {
  MDE: { label: 'Defender for Endpoint', short: 'Defender', color: 'var(--mde)' },
  R7: { label: 'Rapid7 InsightVM', short: 'Rapid7', color: 'var(--r7)' },
  CMDB: { label: 'ServiceNow CMDB', short: 'CMDB', color: 'var(--both)' },
  INTEL: { label: 'CISA KEV · EPSS', short: 'Threat intel', color: 'var(--p1)' },
};

const STAGES = [
  { title: 'Collect', what: 'Pull new records from each security tool', icon: Download, total: (t) => [t.received, 'records received'], extra: (t) => `${fmt.n(t.batches)} batches` },
  { title: 'Normalise', what: 'Match devices to CMDB assets; standardise CVE IDs and severity', icon: ScanLine, total: (t) => [t.normalised, 'records normalised'], extra: (t) => `${fmt.n(t.filtered)} noise dropped` },
  { title: 'Correlate', what: 'Same issue seen by both tools becomes one finding', icon: GitMerge, total: (t) => [t.merged, 'duplicates merged'], extra: (t) => `${fmt.n(t.newFindings)} new · ${fmt.n(t.remediated)} fixed` },
  { title: 'Score & prioritise', what: 'Risk 0–100 from severity, exploitation and business impact → P1–P4 with an SLA', icon: Gauge, total: (t) => [t.scored, 'findings scored'], extra: (t) => `${fmt.n(t.p1p2)} P1/P2 · ${fmt.n(t.kev)} exploited` },
  { title: 'AI agent triage', what: 'Agents check context, then ticket, escalate, merge or ask a person', icon: Bot, total: (t) => [t.agentDecisions, 'agent decisions'], extra: () => 'Triage + Asset-Match agents', ai: true },
  { title: 'Deliver', what: 'Tickets to owners, data to Power BI and dashboards', icon: Send, total: (t) => [t.tickets, 'tickets raised'], extra: (t) => `${fmt.n(t.published)} rows published` },
];
const STEP_MS = 650;

export default function LivePipeline({ batch, totals }) {
  const [step, setStep] = useState(-1);

  useEffect(() => {
    if (!batch) return;
    setStep(0);
    let s = 0;
    const id = setInterval(() => {
      s += 1;
      setStep(s);
      if (s >= STAGES.length) clearInterval(id);
    }, STEP_MS);
    return () => clearInterval(id);
  }, [batch?.id]);

  const color = batch ? SOURCE_META[batch.source].color : 'var(--accent)';
  const running = batch && step >= 0 && step < STAGES.length;
  const outputs = [
    { label: 'ServiceNow tickets', icon: Ticket, on: batch?.counts.tickets > 0 },
    { label: 'Power BI', icon: BarChart3, on: !!batch },
    { label: 'Dashboards', icon: LayoutDashboard, on: !!batch },
  ];

  return (
    <div>
      <div className="lp" style={{ '--flow': color }}>
        {STAGES.map((st, i) => {
          const state = !batch ? '' : i === step ? 'active' : i < step ? 'done' : 'todo';
          const [n, label] = st.total(totals);
          return (
            <div key={st.title} className="lp-cell">
              <div className={`lp-stage ${state} ${st.ai ? 'ai' : ''}`}>
                <div className="lp-head">
                  <span className="lp-num">{i + 1}</span>
                  <st.icon size={15} />
                  <b>{st.title}</b>
                </div>
                <div className="lp-what">{st.what}</div>

                {i === 0 && (
                  <div className="lp-chips">
                    {Object.entries(SOURCE_META).map(([k, m]) => {
                      const on = batch?.source === k && step >= 0;
                      return (
                        <span key={k} className={`lp-chip ${on ? 'on' : ''}`} style={{ '--c': m.color }}>
                          <i />{m.short}{on && <em>+{batch.counts.received}</em>}
                        </span>
                      );
                    })}
                  </div>
                )}
                {st.ai && (
                  <div className="lp-chips">
                    {[['triage', 'Triage Agent'], ['match', 'Asset-Match Agent']].map(([id, name]) => {
                      const mine = batch?.agentRuns?.filter((r) => r.agent === id) || [];
                      const working = mine.some((r) => r.action === 'running');
                      return (
                        <span key={id} className={`lp-chip ${mine.length && step >= i ? 'on' : ''}`} style={{ '--c': 'var(--ai)' }}>
                          {working && step >= i ? <Loader2 size={12} className="spin" /> : <Bot size={12} />}{name}{mine.length > 0 && step >= i && <em>{mine.length}</em>}
                        </span>
                      );
                    })}
                  </div>
                )}
                {i === STAGES.length - 1 && (
                  <div className="lp-chips">
                    {outputs.map((o) => (
                      <span key={o.label} className={`lp-chip ${o.on && step >= i ? 'on' : ''}`} style={{ '--c': 'var(--good)' }}>
                        <o.icon size={12} />{o.label}
                      </span>
                    ))}
                  </div>
                )}

                <div className="lp-total">
                  <span key={n} className="flash num">{fmt.n(n)}</span>
                  <small>{label}</small>
                </div>
                <div className="lp-extra">{st.extra(totals)}</div>
                <div className={`lp-say ${batch && step >= i ? 'show' : ''}`}>
                  {batch && step >= i ? batch.steps[i] : batch ? 'Up next…' : 'Waiting for data…'}
                </div>
              </div>
              {i < STAGES.length - 1 && (
                <div className={`lp-link ${batch && step > i ? 'lit' : ''}`}>
                  {batch && step === i + 1 && [0, 1, 2].map((d) => <span key={`${batch.id}-${d}`} className="lp-dot" style={{ animationDelay: `${d * 0.12}s` }} />)}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="lp-caption" style={{ '--flow': color }}>
        {batch ? (
          <>
            <span className="lp-src" style={{ background: color }}>{SOURCE_META[batch.source].short}</span>
            <span className="lp-cap-step">{running ? `Step ${step + 1} of ${STAGES.length} · ${STAGES[step].title}` : 'Batch complete'}</span>
            <span className="lp-cap-text">{running ? batch.steps[step] : batch.summary}</span>
          </>
        ) : (
          <span className="lp-cap-text muted">Waiting for the next batch from a connected source…</span>
        )}
      </div>
    </div>
  );
}
