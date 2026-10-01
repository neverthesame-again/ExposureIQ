import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { ArrowDownRight, ArrowUpRight, Minus, X, CheckCircle2, AlertTriangle, Flame, Sparkles } from 'lucide-react';
import { PRIORITY_COLOR, PRIORITY_LABEL, SOURCE_LABEL, riskColor, priorityOf, complianceTone } from '../lib.jsx';

export function Card({ title, sub, action, children, className = '', flush, icon }) {
  return (
    <section className={`card ${flush ? 'flush' : ''} ${className}`}>
      {(title || action) && (
        <div className="card-h">
          {icon && <div style={{ color: 'var(--muted)', marginTop: 1 }}>{icon}</div>}
          <div style={{ flex: 1, minWidth: 0 }}>
            {title && <h3 className="card-t">{title}</h3>}
            {sub && <div className="card-s">{sub}</div>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

// better: 'lower' means a negative delta is good
export function Delta({ value, better = 'lower', unit = '', digits = 0 }) {
  if (value == null || Number.isNaN(value)) return null;
  const v = Math.round(value * 10 ** digits) / 10 ** digits;
  if (v === 0) return <span className="delta flat"><Minus size={11} />0{unit}</span>;
  const good = better === 'lower' ? v < 0 : v > 0;
  return (
    <span className={`delta ${good ? 'good' : 'bad'}`}>
      {v > 0 ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}
      {Math.abs(v)}{unit}
    </span>
  );
}

export function Kpi({ label, value, unit, delta, better, deltaUnit, foot, icon, spark, onClick, tone }) {
  return (
    <div className="card kpi" onClick={onClick} style={{ cursor: onClick ? 'pointer' : 'default' }}>
      <div className="kpi-label">{icon}{label}</div>
      <div className="kpi-value" style={tone ? { color: tone } : undefined}>{value}{unit && <small>{unit}</small>}</div>
      <div className="kpi-foot">
        {delta != null && <Delta value={delta} better={better} unit={deltaUnit} digits={1} />}
        <span>{foot}</span>
      </div>
      {spark && <div className="spark">{spark}</div>}
    </div>
  );
}

export function RiskPill({ risk, showPriority = true }) {
  const p = priorityOf(risk);
  return (
    <span className="risk" title={`Unified risk ${risk} · ${p} ${PRIORITY_LABEL[p]}`}>
      <span className="risk-num" style={{ background: riskColor(risk) }}>{risk}</span>
      {showPriority && <span className="prio" style={{ color: PRIORITY_COLOR[p] }}>{p}</span>}
    </span>
  );
}

export function PriorityBadge({ p }) {
  return <span className="badge"><span className="dot" style={{ background: PRIORITY_COLOR[p] }} />{p} · {PRIORITY_LABEL[p]}</span>;
}

export function SourceBadges({ sources }) {
  return (
    <span className="row" style={{ gap: 4 }}>
      {sources.map((s) => <span key={s} className={`src src-${s}`} title={SOURCE_LABEL[s]}>{s === 'Both' ? 'R7+MDE' : s}</span>)}
    </span>
  );
}

export function KevBadge() {
  return <span className="badge badge-kev" title="Listed in the CISA Known Exploited Vulnerabilities catalogue"><Flame size={11} />KEV</span>;
}

export function SlaBadge({ state }) {
  const map = {
    Breached: ['badge-bad', AlertTriangle], 'Due soon': ['badge-warn', AlertTriangle], 'On track': ['badge-good', CheckCircle2],
    Met: ['badge-good', CheckCircle2], Missed: ['badge-bad', AlertTriangle], Exception: ['', null],
  };
  const [cls, Icon] = map[state] || ['', null];
  return <span className={`badge ${cls}`}>{Icon && <Icon size={11} />}{state}</span>;
}

export function ComplianceCell({ value }) {
  const tone = complianceTone(value);
  const color = tone === 'good' ? 'var(--good)' : tone === 'warn' ? 'var(--warn)' : 'var(--bad)';
  return (
    <span className="row" style={{ gap: 8 }}>
      <span style={{ width: 44, height: 6, borderRadius: 6, background: 'var(--surface-3)', overflow: 'hidden', display: 'inline-block' }}>
        <span style={{ display: 'block', height: '100%', width: `${value}%`, background: color, borderRadius: 6 }} />
      </span>
      <span className="num" style={{ fontWeight: 600 }}>{value}%</span>
    </span>
  );
}

export function AiTag({ children = 'AI generated' }) {
  return <span className="badge badge-ai"><Sparkles size={11} />{children}</span>;
}

export function Drawer({ open, onClose, title, sub, badges, children, actions }) {
  useEffect(() => {
    if (!open) return;
    const h = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={typeof title === 'string' ? title : 'Details'}>
        <div className="drawer-h">
          <div style={{ flex: 1, minWidth: 0 }}>
            {badges && <div className="row wrap" style={{ gap: 6, marginBottom: 6 }}>{badges}</div>}
            <div style={{ fontSize: 17, fontWeight: 700, letterSpacing: '-0.015em' }}>{title}</div>
            {sub && <div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>{sub}</div>}
          </div>
          {actions}
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        <div className="drawer-b">{children}</div>
      </aside>
    </>
  );
}

export function Skeleton({ h = 120, className = '' }) {
  return <div className={`skeleton ${className}`} style={{ height: h }} />;
}

export function LoadingGrid() {
  return (
    <div className="grid g-3">
      {[0, 1, 2, 3, 4, 5].map((i) => <Skeleton key={i} h={i < 3 ? 110 : 260} />)}
    </div>
  );
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="card empty">
      <AlertTriangle size={22} style={{ color: 'var(--bad)' }} />
      <div style={{ fontWeight: 700, color: 'var(--text)', marginTop: 8 }}>Couldn't reach the ExposureIQ API</div>
      <div style={{ margin: '4px 0 12px' }}>{String(error?.message || error)} — is the backend running on port 4100?</div>
      {onRetry && <button className="btn" onClick={onRetry}>Retry</button>}
    </div>
  );
}

// ---------- Toasts ----------
const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const push = useCallback((text, tone = 'good') => {
    const id = Math.random();
    setToasts((t) => [...t, { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-wrap">
        {toasts.map((t) => (
          <div className="toast" key={t.id}>
            {t.tone === 'good' ? <CheckCircle2 size={17} style={{ color: 'var(--good)' }} /> : <Sparkles size={17} style={{ color: 'var(--ai)' }} />}
            <span>{t.text}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
