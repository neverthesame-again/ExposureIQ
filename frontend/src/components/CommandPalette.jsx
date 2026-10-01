import { useEffect, useMemo, useRef, useState } from 'react';
import { Search, Bug, Server, Sparkles, CornerDownLeft, ArrowRight } from 'lucide-react';
import { api } from '../lib.jsx';
import { NAV } from '../nav.js';
import { KevBadge } from './ui.jsx';

export default function CommandPalette({ open, onClose, navigate }) {
  const [q, setQ] = useState('');
  const [res, setRes] = useState({ vulns: [], assets: [] });
  const [hl, setHl] = useState(0);
  const input = useRef(null);

  useEffect(() => { if (open) { setQ(''); setHl(0); setTimeout(() => input.current?.focus(), 10); } }, [open]);
  useEffect(() => {
    if (!q.trim()) { setRes({ vulns: [], assets: [] }); return; }
    const t = setTimeout(() => api('/search', { params: { q } }).then(setRes).catch(() => {}), 120);
    return () => clearTimeout(t);
  }, [q]);

  const items = useMemo(() => {
    const out = [];
    if (q.trim()) out.push({ kind: 'ai', label: `Ask ExposureIQ: “${q}”`, go: () => navigate('copilot', { q }) });
    res.vulns.forEach((v) => out.push({ kind: 'vuln', v, label: v.cve, go: () => navigate('vulnerabilities', { cve: v.cve, status: v.open ? undefined : 'all' }) }));
    res.assets.forEach((a) => out.push({ kind: 'asset', a, label: a.hostname, go: () => navigate('assets', { asset: a.id }) }));
    NAV.flatMap((g) => g.items).filter((n) => !q || n.label.toLowerCase().includes(q.toLowerCase())).forEach((n) => out.push({ kind: 'page', n, label: n.label, go: () => navigate(n.id) }));
    return out;
  }, [q, res, navigate]);

  if (!open) return null;
  const choose = (it) => { it.go(); onClose(); };
  const onKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setHl((h) => Math.min(items.length - 1, h + 1)); }
    if (e.key === 'ArrowUp') { e.preventDefault(); setHl((h) => Math.max(0, h - 1)); }
    if (e.key === 'Enter' && items[hl]) choose(items[hl]);
    if (e.key === 'Escape') onClose();
  };
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal" role="dialog" aria-label="Search">
        <div style={{ position: 'relative' }}>
          <Search size={18} style={{ position: 'absolute', left: 16, top: 17, color: 'var(--muted)' }} />
          <input ref={input} className="palette-input" placeholder="Search CVEs, hosts, services — or ask a question…" value={q} onChange={(e) => { setQ(e.target.value); setHl(0); }} onKeyDown={onKey} />
        </div>
        <div className="palette-list">
          {items.map((it, i) => (
            <button key={it.kind + it.label} className={`palette-item ${i === hl ? 'hl' : ''}`} onMouseEnter={() => setHl(i)} onClick={() => choose(it)}>
              {it.kind === 'ai' && <><Sparkles size={16} style={{ color: 'var(--ai)' }} /><span style={{ color: 'var(--ai)', fontWeight: 600 }}>{it.label}</span></>}
              {it.kind === 'vuln' && <><Bug size={16} className="muted" /><span className="mono" style={{ fontWeight: 600 }}>{it.v.cve}</span><span className="text-2" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{it.v.title}</span>{it.v.kev && <KevBadge />}<span className="muted" style={{ fontSize: 11.5 }}>{it.v.open} open</span></>}
              {it.kind === 'asset' && <><Server size={16} className="muted" /><span className="mono" style={{ fontWeight: 600 }}>{it.a.hostname}</span><span className="text-2" style={{ flex: 1 }}>{it.a.company} · {it.a.type} · {it.a.service}</span></>}
              {it.kind === 'page' && <><it.n.icon size={16} className="muted" /><span style={{ flex: 1 }}>{it.label}</span><ArrowRight size={14} className="muted" /></>}
              {i === hl && <CornerDownLeft size={13} className="muted" />}
            </button>
          ))}
          {!items.length && <div className="empty">No matches</div>}
        </div>
      </div>
    </>
  );
}
