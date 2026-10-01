import { useEffect, useState } from 'react';
import { Bot, Hand, Flame, ShieldCheck, Gauge as GaugeIcon, Crosshair, ArrowRight, Pause, Play, Zap, Activity, CheckCircle2, Ticket } from 'lucide-react';
import { useLive, usePoll, api, fmt, agoShort, PRIORITY_COLOR } from '../lib.jsx';
import { AGENT_META } from '../components/AgentTrace.jsx';
import { Card, Kpi, RiskPill, SourceBadges, KevBadge, LoadingGrid, useToast } from '../components/ui.jsx';
import { Sparkline } from '../components/charts.jsx';
import LivePipeline, { SOURCE_META } from '../components/LivePipeline.jsx';

const time = (iso) => new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

export default function Overview({ company, navigate, companies }) {
  const [paused, setPaused] = useState(false);
  const live = useLive(company, paused);
  const toast = useToast();
  const now = useNow();
  const agents = usePoll('/agents', 4000);
  const v = live.view;
  if (!v) return <LoadingGrid />;

  const k = v.kpis, base = live.baseline || k, hist = live.history;
  const nextIn = Math.max(0, Math.ceil((v.nextAt - now) / 1000));
  const trigger = async (source) => {
    await api('/live/trigger', { method: 'POST', body: { source } });
    if (paused) toast('Batch queued — resume to watch it flow');
  };
  const flash = (val) => <span key={val} className="flash">{val}</span>;

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="live-bar">
        <span className={`live-pill ${live.status !== 'live' ? 'off' : paused ? 'paused' : ''}`}>
          <span className="pulse" />{live.status !== 'live' ? 'Reconnecting…' : paused ? 'Paused' : 'Live'}
        </span>
        <span className="muted">
          {paused
            ? `${live.queued || 0} batch${live.queued === 1 ? '' : 'es'} waiting`
            : `Next batch in ${nextIn}s · ${fmt.n(v.totals.batches)} batches processed since ${time(v.startedAt)}`}
        </span>
        <span className="sp" />
        <span className="muted" style={{ fontSize: 12 }}>Run now:</span>
        <button className="btn btn-sm" onClick={() => trigger('MDE')}><Zap size={12} style={{ color: 'var(--mde)' }} />Defender sync</button>
        <button className="btn btn-sm" onClick={() => trigger('R7')}><Zap size={12} style={{ color: 'var(--r7)' }} />Rapid7 scan</button>
        <button className="btn btn-sm" onClick={() => setPaused((p) => !p)}>{paused ? <Play size={12} /> : <Pause size={12} />}{paused ? 'Resume' : 'Pause'}</button>
      </div>

      <div className="grid g-4">
        <Kpi label="Exposure score" icon={<GaugeIcon size={14} />} value={flash(k.exposureScore)} unit=" / 100" delta={k.exposureScore - base.exposureScore} foot="since you opened"
          spark={hist.length > 1 && <Sparkline values={hist.map((h) => h.exposureScore)} color="var(--accent)" />} />
        <Kpi label="Open P1 + P2" icon={<Crosshair size={14} />} value={flash(fmt.n(k.openP1 + k.openP2))} delta={k.openP1 + k.openP2 - base.openP1 - base.openP2} foot="since you opened"
          spark={hist.length > 1 && <Sparkline values={hist.map((h) => h.openP1 + h.openP2)} color="var(--p2)" />} onClick={() => navigate('vulnerabilities', { priority: 'P1,P2' })} />
        <Kpi label="Actively exploited (KEV)" icon={<Flame size={14} />} value={flash(fmt.n(k.kevOpen))} delta={k.kevOpen - base.kevOpen} foot="since you opened"
          spark={hist.length > 1 && <Sparkline values={hist.map((h) => h.kevOpen)} color="var(--p1)" />} onClick={() => navigate('vulnerabilities', { kev: 'true' })} />
        <Kpi label="SLA compliance" icon={<ShieldCheck size={14} />} value={flash(k.slaCompliance)} unit="%" better="higher" delta={k.slaCompliance - base.slaCompliance} deltaUnit=" pts" foot="since you opened"
          spark={hist.length > 1 && <Sparkline values={hist.map((h) => h.slaCompliance)} color="var(--good)" />} onClick={() => navigate('remediation')} />
      </div>

      <Card title="How your data flows, live" sub="Each batch from a security tool passes through six steps before it reaches a dashboard or a ticket. Counters show totals since monitoring started."
        icon={<Activity size={16} />}>
        <LivePipeline batch={live.batch} totals={v.totals} />
      </Card>

      <div className="grid g-main">
        <Card title="Live activity" sub="Newest first · click a finding to open it" flush>
          <div className="feed">
            {live.recent.length === 0 && <div className="empty">No batches yet — the first one arrives within a few seconds.</div>}
            {live.recent.slice(0, 10).map((b) => (
              <div key={b.id} className={`feed-row ${b.id === live.batch?.id ? 'new' : ''}`}>
                <span className="feed-time mono">{time(b.at)}</span>
                <span className="feed-src" style={{ background: SOURCE_META[b.source].color }}>{SOURCE_META[b.source].short}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="feed-sum">{b.summary}{b.company && <span className="muted"> · {companies.find((c) => c.id === b.company)?.short}</span>}</div>
                  {(b.newFindings.length > 0 || b.tickets.length > 0 || b.fixed.length > 0 || b.agentRuns?.length > 0) && (
                    <div className="row wrap" style={{ gap: 6, marginTop: 5 }}>
                      {b.newFindings.map((f) => (
                        <button key={f.id} className="feed-chip" style={{ '--c': PRIORITY_COLOR[f.priority] }} onClick={() => navigate('vulnerabilities', { cve: f.cve })} title={`${f.title} · ${f.companyName}`}>
                          <b>{f.priority}</b>{f.cve}<span className="muted">{f.hostname}</span>{f.kev && <Flame size={11} style={{ color: 'var(--p1)' }} />}
                        </button>
                      ))}
                      {b.fixed.map((f) => (
                        <span key={`${f.cve}-${f.hostname}`} className="feed-chip" style={{ '--c': 'var(--good)' }}><CheckCircle2 size={11} style={{ color: 'var(--good)' }} />Fixed {f.cve}<span className="muted">{f.hostname}</span></span>
                      ))}
                      {(b.agentRuns || []).map((r) => (
                        <button key={r.id} className="feed-chip" style={{ '--c': 'var(--ai)' }} onClick={() => navigate('agents', { run: r.id })} title="Open the agent's reasoning">
                          <Bot size={11} style={{ color: 'var(--ai)' }} />{AGENT_META[r.agent].short}: {r.label}
                        </button>
                      ))}
                      {b.tickets.map((t) => (
                        <span key={t.id} className="feed-chip" style={{ '--c': 'var(--accent)' }}><Ticket size={11} style={{ color: 'var(--accent)' }} />{t.id}<span className="muted">{t.assignee}</span></span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>

        <div className="col" style={{ gap: 16 }}>
          <AgentsPanel data={agents.data} navigate={navigate} />
          <Card title="Fix these first" sub="Updates as new findings arrive" action={<button className="link-btn" onClick={() => navigate('vulnerabilities')}>All <ArrowRight size={13} /></button>}>
            <div className="col" style={{ gap: 2 }}>
              {v.topRisks.map((t) => (
                <button key={t.cve} className="task" style={{ alignItems: 'center', padding: '7px 6px' }} onClick={() => navigate('vulnerabilities', { cve: t.cve })}>
                  <RiskPill risk={t.maxRisk} showPriority={false} />
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span className="row" style={{ gap: 6 }}><span className="mono" style={{ fontWeight: 600, color: 'var(--text)' }}>{t.cve}</span>{t.kev && <KevBadge />}</span>
                    <span style={{ display: 'block', fontSize: 12, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.title}</span>
                  </span>
                  <span style={{ textAlign: 'right' }}>
                    <span key={t.assets} className="flash" style={{ display: 'block', fontWeight: 700, color: 'var(--text)' }}>{t.assets} assets</span>
                    <SourceBadges sources={t.sources} />
                  </span>
                </button>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function AgentsPanel({ data, navigate }) {
  if (!data) return null;
  return (
    <Card className="ai-card" title="AI agents at work" sub="Simulated reasoning in this POC" icon={<Bot size={16} style={{ color: 'var(--ai)' }} />}
      action={<button className="link-btn" onClick={() => navigate('agents')}>Open <ArrowRight size={13} /></button>}>
      <div className="col" style={{ gap: 2 }}>
        {data.agents.map((a) => {
          const M = AGENT_META[a.id];
          const last = data.runs.find((r) => r.agent === a.id);
          return (
            <button key={a.id} className="task" style={{ alignItems: 'center', padding: '6px' }} onClick={() => navigate('agents', last ? { run: last.id } : {})}>
              <span className={`agent-pulse ${a.working ? 'on' : ''}`} style={{ '--c': M.color }}><M.icon size={14} /></span>
              <span style={{ flex: 1, minWidth: 0 }}>
                <span style={{ display: 'block', fontWeight: 600, color: 'var(--text)', fontSize: 12.5 }}>{a.name}</span>
                <span style={{ display: 'block', fontSize: 11.5, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {a.working ? 'Working…' : last ? `${last.decision.label} · ${agoShort(last.at)}` : 'Waiting for work'}
                </span>
              </span>
              <span className="muted num" style={{ fontSize: 11.5 }}>{a.stats.runs}</span>
            </button>
          );
        })}
      </div>
      {data.totals.pending > 0 && (
        <button className="btn btn-sm mt-s" style={{ width: '100%', justifyContent: 'center' }} onClick={() => navigate('agents')}>
          <Hand size={12} style={{ color: 'var(--warn)' }} />{data.totals.pending} proposal{data.totals.pending === 1 ? '' : 's'} waiting for your approval
        </button>
      )}
    </Card>
  );
}

function useNow() {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}
