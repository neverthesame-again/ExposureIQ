import { useEffect, useRef, useState } from 'react';
import { Sparkles, Send, ShieldCheck, Database, Lock, RotateCcw, ArrowRight, Copy } from 'lucide-react';
import { api, md } from '../lib.jsx';
import AgentTrace from '../components/AgentTrace.jsx';
import { Card, useToast } from '../components/ui.jsx';

const LIBRARY = [
  { group: 'Leadership', items: ['Summarise for the board', 'Compare all group companies', 'How has exposure trended?'] },
  { group: 'Operations', items: ["Build this week's patch plan", 'Show actively exploited vulnerabilities', 'What is internet-facing and vulnerable?', 'Which companies are breaching SLA?'] },
  { group: 'Data trust', items: ['How much duplication did correlation remove?', 'What are the coverage gaps?', 'How is the unified risk score calculated?'] },
  { group: 'Deep dives', items: ['Why is Mammoet behind?', 'Explain CVE-2024-3400', 'Explain CVE-2021-44228'] },
];

export default function Copilot({ company, params, companies, navigate }) {
  const [msgs, setMsgs] = useState([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const log = useRef(null);
  const asked = useRef(false);
  const toast = useToast();
  const scopeName = company === 'all' ? 'SHV Group' : companies.find((c) => c.id === company)?.short || company;

  const ask = async (q) => {
    const question = q.trim();
    if (!question || busy) return;
    setInput('');
    setMsgs((m) => [...m, { role: 'user', text: question }, { role: 'bot', pending: true }]);
    setBusy(true);
    try {
      const res = await api('/copilot', { method: 'POST', body: { question, company } });
      setMsgs((m) => [...m.slice(0, -1), { role: 'bot', res, shown: 0, live: true }]);
      await new Promise((r) => setTimeout(r, (res.trace?.length || 0) * 420 + 250));
      for (let i = 1; i <= res.blocks.length; i++) {
        await new Promise((r) => setTimeout(r, 260));
        setMsgs((m) => m.map((x, idx) => (idx === m.length - 1 ? { ...x, shown: i } : x)));
      }
    } catch (e) {
      setMsgs((m) => [...m.slice(0, -1), { role: 'bot', res: { blocks: [{ type: 'text', text: `Sorry — the API didn't respond (${e.message}).` }], citations: [], followUps: [] }, shown: 1 }]);
    } finally { setBusy(false); }
  };

  useEffect(() => { if (params.q && !asked.current) { asked.current = true; ask(params.q); } }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { log.current?.scrollTo({ top: log.current.scrollHeight, behavior: 'smooth' }); }, [msgs]);

  const copy = (res) => {
    const text = res.blocks.map((b) => b.type === 'text' ? b.text.replace(/\*\*/g, '') : b.type === 'list' ? b.items.map((i) => `• ${i}`).join('\n') : b.type === 'table' ? [b.columns.join(' | '), ...b.rows.map((r) => r.join(' | '))].join('\n') : '').join('\n\n');
    navigator.clipboard?.writeText(text).then(() => toast('Answer copied — ready to paste into email or Teams', 'ai'));
  };

  return (
    <div className="chat">
      <div className="chat-side col" style={{ gap: 12 }}>
        <Card>
          <div className="ai-head"><Sparkles size={14} />Prompt library</div>
          {LIBRARY.map((g) => (
            <div key={g.group}>
              <div className="section-t" style={{ margin: '14px 0 6px' }}>{g.group}</div>
              {g.items.map((p) => <button key={p} className="prompt-btn" onClick={() => ask(p)} disabled={busy}>{p}</button>)}
            </div>
          ))}
        </Card>
        <Card>
          <div className="section-t" style={{ marginTop: 0 }}>How answers are grounded</div>
          <div className="col text-2" style={{ gap: 10, fontSize: 12 }}>
            <div className="row" style={{ alignItems: 'flex-start' }}><Database size={15} style={{ flex: 'none', marginTop: 2 }} />Every number comes from the correlated Rapid7 + Defender dataset, with sources cited.</div>
            <div className="row" style={{ alignItems: 'flex-start' }}><Lock size={15} style={{ flex: 'none', marginTop: 2 }} />Only aggregated metrics reach the model — no raw host data leaves the EU tenant.</div>
            <div className="row" style={{ alignItems: 'flex-start' }}><ShieldCheck size={15} style={{ flex: 'none', marginTop: 2 }} />Scope follows the company selector: <b style={{ color: 'var(--text)' }}>{scopeName}</b>.</div>
          </div>
        </Card>
      </div>

      <div className="card chat-main">
        <div className="chat-log" ref={log}>
          {!msgs.length && (
            <div style={{ margin: 'auto', textAlign: 'center', maxWidth: 560 }}>
              <div className="brand-mark" style={{ width: 54, height: 54, margin: '0 auto 14px', borderRadius: 16 }}><Sparkles size={26} /></div>
              <div style={{ fontSize: 22, fontWeight: 800, letterSpacing: '-0.02em' }}>Ask ExposureIQ anything about {scopeName}'s exposure</div>
              <div className="text-2" style={{ margin: '8px 0 18px' }}>A security analyst that has already read every Rapid7 scan, every Defender finding and the CMDB — and answers in seconds instead of days.</div>
              <div className="row wrap" style={{ justifyContent: 'center', gap: 8 }}>
                {['Summarise for the board', "Build this week's patch plan", 'Why is Mammoet behind?', 'Show actively exploited vulnerabilities'].map((p) => <button key={p} className="follow" onClick={() => ask(p)}>{p}</button>)}
              </div>
            </div>
          )}
          {msgs.map((m, i) => m.role === 'user' ? (
            <div key={i} className="msg user"><div className="bubble">{m.text}</div></div>
          ) : (
            <div key={i} className="msg bot">
              <div className="avatar"><Sparkles size={15} /></div>
              <div className="bubble">
                {m.pending ? <div className="typing" style={{ padding: '8px 0' }}><span /><span /><span /><span className="muted" style={{ width: 'auto', height: 'auto', background: 'none', animation: 'none', marginLeft: 6, fontSize: 12 }}>Copilot agent is querying the data…</span></div> : (
                  <>
                    {m.res.trace && (
                      <details className="trace-box" open>
                        <summary>Agent trace · {m.res.trace.filter((s) => s.type === 'tool').length} tool calls · {m.res.engine && m.res.engine !== 'rules' ? `Gemini ${m.res.engine}` : 'rules engine (template answer)'}</summary>
                        <AgentTrace steps={m.res.trace} animate={!!m.live} compact />
                      </details>
                    )}
                    {m.res.blocks.slice(0, m.shown).map((b, j) => <Block key={j} b={b} />)}
                    {m.shown >= m.res.blocks.length && (
                      <>
                        {m.res.citations?.length > 0 && (
                          <div className="row wrap" style={{ gap: 5, marginTop: 4 }}>
                            <span className="muted" style={{ fontSize: 11 }}>Sources:</span>
                            {m.res.citations.map((c) => <span key={c} className="cite">{c}</span>)}
                          </div>
                        )}
                        <div className="row wrap" style={{ gap: 6, marginTop: 12 }}>
                          {m.res.followUps?.map((f) => <button key={f} className="follow" onClick={() => ask(f)} disabled={busy}>{f}</button>)}
                          <span className="sp" />
                          {m.res.link && <button className="btn btn-sm" onClick={() => navigate(m.res.link.page, { cve: m.res.link.cve })}>Open details <ArrowRight size={12} /></button>}
                          <button className="btn btn-sm btn-ghost" onClick={() => copy(m.res)} title="Copy answer"><Copy size={12} />Copy</button>
                        </div>
                      </>
                    )}
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
        <form className="chat-input" onSubmit={(e) => { e.preventDefault(); ask(input); }}>
          {msgs.length > 0 && <button type="button" className="icon-btn" title="New conversation" onClick={() => setMsgs([])}><RotateCcw size={15} /></button>}
          <textarea rows={1} value={input} placeholder={`Ask about ${scopeName} — e.g. "Which KEV vulnerabilities are internet-facing?"`}
            onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(input); } }} />
          <button className="btn btn-ai" style={{ height: 44 }} disabled={busy || !input.trim()}><Send size={15} />Ask</button>
        </form>
      </div>
    </div>
  );
}

function Block({ b }) {
  if (b.type === 'text') return <p>{md(b.text)}</p>;
  if (b.type === 'list') return (
    <div style={{ marginBottom: 10 }}>
      {b.title && <div style={{ fontWeight: 700, marginBottom: 4 }}>{b.title}</div>}
      <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--text-2)' }}>{b.items.map((it, i) => <li key={i} style={{ marginBottom: 3 }}>{md(it)}</li>)}</ul>
    </div>
  );
  if (b.type === 'kpis') return (
    <div className="grid g-3" style={{ gap: 8, marginBottom: 10 }}>
      {b.items.map((k) => <div key={k.label} className="card" style={{ padding: 10, boxShadow: 'none' }}><div className="muted" style={{ fontSize: 11 }}>{k.label}</div><div style={{ fontSize: 20, fontWeight: 800 }}>{k.value}</div><div className="muted" style={{ fontSize: 11 }}>{k.hint}</div></div>)}
    </div>
  );
  if (b.type === 'table') return (
    <div style={{ marginBottom: 12 }}>
      {b.title && <div style={{ fontWeight: 700, marginBottom: 4 }}>{b.title}</div>}
      <div className="table-wrap card" style={{ padding: 0, boxShadow: 'none' }}>
        <table className="t">
          <thead><tr>{b.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>{b.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} className={j === 0 && String(c).startsWith('CVE') ? 'mono' : ''}>{c}</td>)}</tr>)}</tbody>
        </table>
      </div>
    </div>
  );
  return null;
}
