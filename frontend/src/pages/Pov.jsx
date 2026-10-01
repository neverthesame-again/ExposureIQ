import { useState } from 'react';
import { Check, CircleDashed, CircleDot, Target, Layers, ListChecks, Compass } from 'lucide-react';
import { useApi, api, fmt } from '../lib.jsx';
import { Card, LoadingGrid, ErrorState } from '../components/ui.jsx';

export default function Pov() {
  const { data, error, loading, reload } = useApi('/pov');
  const [tasks, setTasks] = useState(null);
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <LoadingGrid />;
  const list = tasks || data.tasks;
  const toggle = async (id) => {
    setTasks(list.map((t) => (t.id === id ? { ...t, done: !t.done } : t)));
    await api(`/pov/tasks/${id}/toggle`, { method: 'POST' });
  };
  const { trial } = data;
  const done = list.filter((t) => t.done).length;
  const currentPhase = Math.min(4, Math.floor(trial.day / 23) + 1);
  const r = 52, C = 2 * Math.PI * r;
  const metricsByGroup = data.metrics.reduce((m, x) => ({ ...m, [x.group]: [...(m[x.group] || []), x] }), {});

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="grid g-main-r">
        <Card title="Microsoft Defender Vulnerability Management trial" sub="Standalone trial, up to 90 days — our proof of value window">
          <div className="row" style={{ gap: 22 }}>
            <svg width="130" height="130" role="img" aria-label={`Day ${trial.day} of ${trial.length}`}>
              <circle cx="65" cy="65" r={r} fill="none" stroke="var(--surface-3)" strokeWidth="12" />
              <circle cx="65" cy="65" r={r} fill="none" stroke="url(#tg)" strokeWidth="12" strokeLinecap="round" strokeDasharray={`${(trial.day / trial.length) * C} ${C}`} transform="rotate(-90 65 65)" />
              <defs><linearGradient id="tg"><stop offset="0" stopColor="#38bdf8" /><stop offset="1" stopColor="#8b5cf6" /></linearGradient></defs>
              <text x="65" y="64" textAnchor="middle" style={{ fontSize: 28, fontWeight: 800, fill: 'var(--text)' }}>{trial.day}</text>
              <text x="65" y="82" textAnchor="middle" style={{ fontSize: 11, fill: 'var(--muted)' }}>of {trial.length} days</text>
            </svg>
            <div className="col" style={{ gap: 8, flex: 1 }}>
              <div className="stat-inline"><span className="v">{trial.length - trial.day} days left</span><span className="l">Started {fmt.dateY(trial.startedAt)} · ends {fmt.dateY(trial.endsAt)}</span></div>
              <div className="stat-inline"><span className="v">{done} / {list.length}</span><span className="l">PoV tasks complete</span></div>
              <div className="bar-track"><div style={{ width: `${(done / list.length) * 100}%`, background: 'var(--good)' }} /></div>
            </div>
          </div>
        </Card>
        <Card title="Positioning for the steering discussion" sub="Not a Defender replacement — an enterprise vulnerability intelligence & exposure management use case" icon={<Compass size={16} />}>
          <div className="grid g-4" style={{ gap: 10 }}>
            {[['Rapid7 InsightVM', 'Remains a vulnerability source for appliances, OT and network scanning', 'var(--r7)'],
              ['Defender VM', 'Becomes the risk-prioritisation and exposure-management layer', 'var(--mde)'],
              ['Power BI', 'Executive reporting layer for leadership and OpCo boards', 'var(--p3)'],
              ['GenAI', 'Intelligent summaries, patch plans and Q&A on top of the data', 'var(--ai)']].map(([t, d, c]) => (
              <div key={t} style={{ borderTop: `3px solid ${c}`, background: 'var(--surface-2)', borderRadius: 10, padding: 12 }}>
                <b>{t}</b>
                <div className="text-2" style={{ fontSize: 12, marginTop: 4 }}>{d}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="90-day plan" sub="Click a task to update its status" icon={<Layers size={16} />}>
        <div className="grid g-4">
          {data.phases.map((p) => {
            const pt = list.filter((t) => t.phase === p.n);
            const state = p.n < currentPhase ? 'done' : p.n === currentPhase ? 'active' : 'next';
            return (
              <div key={p.n} style={{ border: `1px solid ${state === 'active' ? 'var(--accent)' : 'var(--border)'}`, borderRadius: 12, padding: 14, background: state === 'active' ? 'var(--accent-soft)' : 'var(--surface-2)' }}>
                <div className="row" style={{ gap: 8 }}>
                  {state === 'done' ? <Check size={16} style={{ color: 'var(--good)' }} /> : state === 'active' ? <CircleDot size={16} style={{ color: 'var(--accent)' }} /> : <CircleDashed size={16} className="muted" />}
                  <b>Phase {p.n} · {p.name}</b>
                </div>
                <div className="muted" style={{ fontSize: 11.5, margin: '2px 0 6px 24px' }}>{p.weeks}</div>
                <div className="text-2" style={{ fontSize: 12, marginBottom: 8 }}>{p.goal}</div>
                {pt.map((t) => (
                  <button key={t.id} className={`task ${t.done ? 'done' : ''}`} onClick={() => toggle(t.id)}>
                    <span className={`check ${t.done ? 'on' : ''}`}>{t.done && <Check size={12} />}</span>
                    <span className="tx" style={{ fontSize: 12.5 }}>{t.text}</span>
                  </button>
                ))}
              </div>
            );
          })}
        </div>
      </Card>

      <div className="grid g-main">
        <Card title="Success criteria" sub="Baseline (before) vs measured today, from the business case" icon={<Target size={16} />} flush>
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Metric</th><th className="r">Baseline</th><th className="r">Today</th><th>Target</th><th>Status</th></tr></thead>
              <tbody>
                {Object.entries(metricsByGroup).map(([g, ms]) => [
                  <tr key={g}><td colSpan={5} style={{ background: 'var(--surface-2)', fontWeight: 700, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--muted)' }}>{g}</td></tr>,
                  ...ms.map((m) => (
                    <tr key={m.name}>
                      <td style={{ fontWeight: 600 }}>{m.name}</td>
                      <td className="r num muted">{m.baseline}{typeof m.baseline === 'number' && m.unit ? ` ${m.unit}` : ''}</td>
                      <td className="r num" style={{ fontWeight: 700 }}>{m.current}{typeof m.current === 'number' && m.unit ? ` ${m.unit}` : ''}</td>
                      <td className="text-2">{m.target}</td>
                      <td>{m.status === 'met' ? <span className="badge badge-good"><Check size={11} />On target</span> : <span className="badge badge-warn">In progress</span>}</td>
                    </tr>
                  )),
                ])}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="What it takes to run the trial" sub="Prerequisites and owners" icon={<ListChecks size={16} />}>
          <div className="col" style={{ gap: 4 }}>
            {data.prerequisites.map((p) => (
              <div key={p.item} className="row" style={{ alignItems: 'flex-start', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                <span className={`check ${p.status === 'done' ? 'on' : ''}`} style={p.status === 'progress' ? { borderColor: 'var(--warn)' } : undefined}>{p.status === 'done' && <Check size={12} />}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 600 }}>{p.item}</div>
                  <div className="muted" style={{ fontSize: 11.5 }}>{p.owner}</div>
                </div>
                <span className={`badge ${p.status === 'done' ? 'badge-good' : p.status === 'progress' ? 'badge-warn' : ''}`}>{p.status === 'done' ? 'Done' : p.status === 'progress' ? 'In progress' : 'To do'}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
