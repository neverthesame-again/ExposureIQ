import { useEffect, useState } from 'react';
import { Brain, Wrench, CheckCircle2, CornerDownRight, Bot, ScanSearch, CalendarClock, MessageSquareText, ShieldAlert } from 'lucide-react';

export const AGENT_META = {
  triage: { icon: ScanSearch, color: 'var(--p2)', short: 'Triage' },
  match: { icon: Bot, color: 'var(--both)', short: 'Asset-Match' },
  planner: { icon: CalendarClock, color: 'var(--accent)', short: 'Planner' },
  copilot: { icon: MessageSquareText, color: 'var(--ai)', short: 'Copilot' },
};

const argVal = (v) => (Array.isArray(v) ? (v.some((x) => x && typeof x === 'object') ? `[${v.length} items]` : `[${v.join(', ')}]`) : typeof v === 'string' && v.length > 80 ? JSON.stringify(`${v.slice(0, 77)}…`) : JSON.stringify(v));
const argText = (args) => Object.entries(args || {}).map(([k, v]) => `${k}=${argVal(v)}`).join(', ');

// Renders an agent's trace. With `animate`, steps appear one by one, as if the agent were working live.
export default function AgentTrace({ steps, animate = false, compact = false, running = false, onDone }) {
  const [shown, setShown] = useState(animate ? 0 : steps.length);

  useEffect(() => {
    if (!animate) { setShown(steps.length); return; }
    setShown(0);
    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setShown(i);
      if (i >= steps.length) { clearInterval(id); onDone?.(); }
    }, 420);
    return () => clearInterval(id);
    // Polling hands us a new array every few seconds; only a different run (remount) or step count restarts it.
  }, [steps.length, animate]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <ol className={`trace ${compact ? 'compact' : ''}`}>
      {steps.slice(0, shown).map((s, i) => (
        <li key={i} className={`trace-step ${s.type}`}>
          <span className="trace-ico">
            {s.type === 'thought' ? <Brain size={13} /> : s.type === 'tool' ? <Wrench size={13} /> : s.type === 'guardrail' ? <ShieldAlert size={13} /> : <CheckCircle2 size={13} />}
          </span>
          <div className="trace-body">
            {s.type === 'tool' ? (
              <>
                <div className="trace-call mono"><b>{s.tool}</b>({argText(s.args)})</div>
                <div className="trace-result"><CornerDownRight size={12} />{s.result}</div>
              </>
            ) : (
              <div>{s.type === 'thought' ? <span className="trace-tag">Thinking</span> : s.type === 'guardrail' ? <span className="trace-tag guard">Guardrail</span> : <span className="trace-tag dec">Decision</span>}{s.text}</div>
            )}
          </div>
        </li>
      ))}
      {(shown < steps.length || running) && <li className="trace-step pending"><span className="trace-ico"><span className="typing"><span /><span /><span /></span></span></li>}
    </ol>
  );
}
