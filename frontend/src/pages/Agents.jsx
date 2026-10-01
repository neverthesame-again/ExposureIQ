import { useEffect, useRef, useState } from 'react';
import { Bot, Play, ShieldCheck, Wrench, Check, X, Loader2, Sparkles, Hand, Clock } from 'lucide-react';
import { usePoll, api, agoShort, fmt, PRIORITY_COLOR } from '../lib.jsx';
import { Card, LoadingGrid, ErrorState, useToast } from '../components/ui.jsx';
import AgentTrace, { AGENT_META } from '../components/AgentTrace.jsx';

const STATUS = {
  done: ['Done', 'badge-good'],
  awaiting: ['Awaiting approval', 'badge-warn'],
  approved: ['Approved by a person', 'badge-good'],
  rejected: ['Rejected by a person', 'badge-bad'],
};

export default function Agents({ params, navigate, company }) {
  const { data, error, loading, reload } = usePoll('/agents', 2500);
  const [filter, setFilter] = useState('all');
  const [sel, setSel] = useState(params.run || null);
  const [follow, setFollow] = useState(!params.run);
  const [running, setRunning] = useState(null);
  const [busyAp, setBusyAp] = useState(null);
  const seen = useRef(null);
  const [fresh, setFresh] = useState(null);
  const toast = useToast();

  const runs = data?.runs || [];
  // Follow the newest run until the person picks one; animate runs that arrive while the page is open.
  useEffect(() => {
    if (!data) return;
    if (!seen.current) { seen.current = new Set(runs.map((r) => r.id)); if (!sel && runs[0]) setSel(runs[0].id); return; }
    const newest = runs[0];
    if (newest && !seen.current.has(newest.id)) {
      runs.forEach((r) => seen.current.add(r.id));
      if (follow) { setSel(newest.id); setFresh(newest.id); }
    }
  }, [data]); // eslint-disable-line react-hooks/exhaustive-deps

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <LoadingGrid />;

  const { agents, approvals, totals, model } = data;
  const pending = approvals.filter((a) => a.status === 'pending');
  const decided = approvals.filter((a) => a.status !== 'pending');
  const list = runs.filter((r) => filter === 'all' || r.agent === filter);
  const current = runs.find((r) => r.id === sel) || runs[0];

  const runAgent = async (id) => {
    if (id === 'copilot') return navigate('copilot');
    setRunning(id);
    try {
      const r = await api(`/agents/${id}/run`, { method: 'POST', body: { company } });
      if (!r.run) toast(r.message, 'ai');
      else { seen.current?.add(r.run.id); setSel(r.run.id); setFresh(r.run.id); setFollow(false); }
      reload();
    } finally { setRunning(null); }
  };
  const decide = async (ap, decision) => {
    setBusyAp(ap.id);
    try {
      const r = await api(`/approvals/${ap.id}`, { method: 'POST', body: { decision } });
      toast(r.outcome, decision === 'approve' ? 'good' : 'ai');
      reload();
    } finally { setBusyAp(null); }
  };
  const pick = (id) => { setSel(id); setFollow(false); setFresh(null); };

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="hero-band" style={{ marginBottom: 0 }}>
        <div className="brand-mark" style={{ width: 38, height: 38, flex: 'none' }}><Bot size={19} /></div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <b>{agents.length} AI agents work on the live feed.</b> Each has a goal, a fixed set of tools and guardrails on what it may do alone. Every thought, tool call and decision is recorded below.
          <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>Reasoning engine: {model}</div>
        </div>
        <Stat v={totals.runs} l="decisions" />
        <Stat v={totals.toolCalls} l="tool calls" />
        <Stat v={totals.autoActions} l="acted alone" />
        <Stat v={totals.pending} l="awaiting you" tone={totals.pending ? 'var(--warn)' : undefined} />
        <Stat v={totals.overrides} l="overruled" />
      </div>

      <div className="grid g-4">
        {agents.map((a) => {
          const M = AGENT_META[a.id];
          return (
            <div key={a.id} className={`card agent-card ${a.working ? 'working' : ''}`} style={{ '--c': M.color }}>
              <div className="row" style={{ alignItems: 'flex-start' }}>
                <div className="agent-ico"><M.icon size={18} /></div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <b style={{ fontSize: 14 }}>{a.name}</b>
                  <div className="agent-status">
                    <span className="dot" />{a.working ? 'Working…' : a.stats.lastRun ? `Idle · last run ${agoShort(a.stats.lastRun)}` : 'Idle · waiting for a trigger'}
                  </div>
                </div>
              </div>
              <div className="text-2" style={{ fontSize: 12.5, marginTop: 10 }}>{a.goal}</div>
              <div className="agent-tools">
                {a.tools.map((t) => <span key={t} className="mono">{t}</span>)}
              </div>
              <div className="agent-line"><ShieldCheck size={13} />{a.autonomy}</div>
              <div className="agent-line"><Clock size={13} />{a.trigger}</div>
              <div className="agent-stats">
                <span><b>{fmt.n(a.stats.runs)}</b> runs</span>
                <span><b>{fmt.n(a.stats.toolCalls)}</b> tool calls</span>
                <span style={a.pending ? { color: 'var(--warn)' } : undefined}><b>{a.pending}</b> pending</span>
              </div>
              <button className="btn btn-sm" style={{ marginTop: 10, alignSelf: 'flex-start' }} onClick={() => runAgent(a.id)} disabled={running === a.id}>
                {running === a.id ? <Loader2 size={12} className="spin" /> : a.id === 'copilot' ? <Sparkles size={12} /> : <Play size={12} />}
                {a.id === 'copilot' ? 'Ask a question' : 'Run now'}
              </button>
            </div>
          );
        })}
      </div>

      {(pending.length > 0 || decided.length > 0) && (
        <Card title="Waiting for you" sub="Agents propose; people decide anything that accepts risk, merges uncertain data or changes ServiceNow" icon={<Hand size={16} />} flush>
          {pending.length === 0 && <div className="muted" style={{ padding: '4px 18px 14px', fontSize: 12.5 }}>Nothing waiting. Recent decisions are below.</div>}
          {[...pending, ...decided.slice(0, pending.length ? 3 : 5)].map((ap) => {
            const M = AGENT_META[ap.agent];
            return (
              <div key={ap.id} className={`approval ${ap.status}`}>
                <span className="agent-chip" style={{ '--c': M.color }}><M.icon size={12} />{M.short}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600 }}>{ap.title}</div>
                  <div className="muted" style={{ fontSize: 12 }}>{ap.reason} · confidence {Math.round(ap.confidence * 100)}%{ap.outcome ? ` · ${ap.outcome}` : ''}</div>
                </div>
                <button className="link-btn" onClick={() => pick(ap.runId)}>View reasoning</button>
                {ap.status === 'pending' ? (
                  <>
                    <button className="btn btn-sm" onClick={() => decide(ap, 'reject')} disabled={busyAp === ap.id}><X size={12} />Reject</button>
                    <button className="btn btn-sm btn-primary" onClick={() => decide(ap, 'approve')} disabled={busyAp === ap.id}><Check size={12} />Approve</button>
                  </>
                ) : <span className={`badge ${ap.status === 'approved' ? 'badge-good' : 'badge-bad'}`}>{ap.status === 'approved' ? 'Approved' : 'Rejected'}</span>}
              </div>
            );
          })}
        </Card>
      )}

      <div className="grid g-main-r">
        <Card title="Agent activity" sub="Newest first · click to see the reasoning" flush>
          <div className="seg" style={{ margin: '0 18px 10px' }}>
            {['all', 'triage', 'match', 'planner', 'copilot'].map((f) => <button key={f} className={filter === f ? 'on' : ''} onClick={() => setFilter(f)}>{f === 'all' ? 'All' : AGENT_META[f].short}</button>)}
          </div>
          <div className="run-list">
            {list.length === 0 && <div className="empty">No runs yet for this agent.</div>}
            {list.slice(0, 30).map((r) => {
              const M = AGENT_META[r.agent];
              return (
                <button key={r.id} className={`run-row ${current?.id === r.id ? 'sel' : ''}`} onClick={() => pick(r.id)}>
                  <span className="agent-dot" style={{ background: M.color }} />
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span className="run-title">{r.title}</span>
                    <span className="muted" style={{ fontSize: 11.5 }}>{M.short} · {r.decision.label} · {agoShort(r.at)}</span>
                  </span>
                  {r.status === 'awaiting' && <span className="badge badge-warn">Needs you</span>}
                </button>
              );
            })}
          </div>
        </Card>

        <Card>
          {!current ? <div className="empty">Agents haven't run yet. They start as soon as the live feed sends work.</div> : (
            <RunView run={current} animate={fresh === current.id} approval={approvals.find((a) => a.id === current.approvalId)} onDecide={decide} busy={busyAp} navigate={navigate} />
          )}
        </Card>
      </div>
    </div>
  );
}

function RunView({ run, animate, approval, onDecide, busy, navigate }) {
  const M = AGENT_META[run.agent];
  const [done, setDone] = useState(!animate);
  useEffect(() => setDone(!animate), [run.id, animate]);
  const [label, cls] = STATUS[run.status] || STATUS.done;
  return (
    <div>
      <div className="row" style={{ alignItems: 'flex-start', marginBottom: 12 }}>
        <span className="agent-chip lg" style={{ '--c': M.color }}><M.icon size={14} />{M.short} agent</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 15 }}>{run.title}</div>
          <div className="muted" style={{ fontSize: 12 }}>{run.id} · {new Date(run.at).toLocaleTimeString('en-GB')} · {run.toolCalls} tool calls{run.subject?.priority && <> · <b style={{ color: PRIORITY_COLOR[run.subject.priority] }}>{run.subject.priority}</b> risk {run.subject.risk}</>}</div>
        </div>
        <span className={`badge ${cls}`}>{label}</span>
      </div>
      <AgentTrace key={run.id} steps={run.steps} animate={animate} onDone={() => setDone(true)} />
      {done && run.plan && (
        <div className="table-wrap card" style={{ padding: 0, boxShadow: 'none', marginTop: 12 }}>
          <table className="t">
            <thead><tr><th>Campaign</th><th>Owner team</th><th>Fix</th><th className="r">Assets</th><th>Change window</th></tr></thead>
            <tbody>
              {run.plan.map((c) => (
                <tr key={c.id} className="click" onClick={() => navigate('vulnerabilities', { cve: c.cve })}>
                  <td><b style={{ color: PRIORITY_COLOR[c.priority] }}>{c.priority}</b> {c.id}</td>
                  <td>{c.team}</td>
                  <td><span className="mono">{c.cve}</span><div className="muted" style={{ fontSize: 11.5 }}>{c.title}</div></td>
                  <td className="r num">{c.assets}</td>
                  <td style={{ fontSize: 12 }}>{c.window}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {done && (
        <div className="row mt" style={{ gap: 8 }}>
          <span className="muted" style={{ fontSize: 12 }}><Wrench size={12} style={{ verticalAlign: -2 }} /> Confidence {Math.round(run.decision.confidence * 100)}%</span>
          <span className="sp" />
          {run.subject?.cve && <button className="btn btn-sm" onClick={() => navigate('vulnerabilities', { cve: run.subject.cve })}>Open {run.subject.cve}</button>}
          {approval?.status === 'pending' && (
            <>
              <button className="btn btn-sm" onClick={() => onDecide(approval, 'reject')} disabled={busy === approval.id}><X size={12} />Reject</button>
              <button className="btn btn-sm btn-primary" onClick={() => onDecide(approval, 'approve')} disabled={busy === approval.id}><Check size={12} />Approve</button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({ v, l, tone }) {
  return (
    <div className="stat-inline" style={{ minWidth: 70, textAlign: 'right' }}>
      <span className="v num" style={tone ? { color: tone } : undefined}>{fmt.n(v)}</span>
      <span className="l">{l}</span>
    </div>
  );
}
