import { useCallback, useEffect, useRef, useState } from 'react';

export async function api(path, { method = 'GET', body, params } = {}) {
  const qs = params ? '?' + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== null && v !== false)).toString() : '';
  const res = await fetch(`/api${path}${qs}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export function useApi(path, params, deps = []) {
  const [state, setState] = useState({ data: null, loading: true, error: null });
  const key = JSON.stringify(params || {});
  const seq = useRef(0);
  const load = useCallback(() => {
    const id = ++seq.current;
    setState((s) => ({ ...s, loading: true, error: null }));
    api(path, { params })
      .then((data) => { if (id === seq.current) setState({ data, loading: false, error: null }); })
      .catch((error) => { if (id === seq.current) setState({ data: null, loading: false, error }); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, key, ...deps]);
  useEffect(() => { load(); }, [load]);
  return { ...state, reload: load };
}

export function usePoll(path, ms, params) {
  const r = useApi(path, params);
  useEffect(() => {
    const id = setInterval(r.reload, ms);
    return () => clearInterval(id);
  }, [r.reload, ms]);
  return r;
}

export const agoShort = (iso) => {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
};

// Subscribes to the backend's live stream (Server-Sent Events). While paused, batches are
// queued and applied on resume, so the activity feed never has gaps.
export function useLive(company, paused) {
  const [s, setS] = useState({ status: 'connecting', view: null, baseline: null, history: [], recent: [], batch: null });
  const pausedRef = useRef(paused);
  const queue = useRef([]);
  const applyBatch = (prev, d) => ({
    ...prev,
    view: d,
    batch: d.batch,
    recent: [d.batch, ...prev.recent.filter((b) => b.id !== d.batch.id)].slice(0, 20),
    history: [...prev.history, d.kpis].slice(-40),
  });

  useEffect(() => {
    pausedRef.current = paused;
    if (!paused && queue.current.length) {
      const q = queue.current;
      queue.current = [];
      setS((prev) => ({ ...q.reduce(applyBatch, prev), queued: 0 }));
    }
  }, [paused]);

  useEffect(() => {
    setS({ status: 'connecting', view: null, baseline: null, history: [], recent: [], batch: null });
    queue.current = [];
    const es = new EventSource(`/api/live/stream?company=${encodeURIComponent(company)}`);
    es.onopen = () => setS((p) => ({ ...p, status: 'live' }));
    es.onerror = () => setS((p) => ({ ...p, status: 'reconnecting' }));
    es.addEventListener('snapshot', (e) => {
      const d = JSON.parse(e.data);
      setS((p) => ({ ...p, status: 'live', view: d, baseline: p.baseline || d.kpis, recent: d.recent, history: [d.kpis], batch: d.recent[0] || null }));
    });
    // Agents finish after the batch: replace the batch in place (same id, so animations don't restart).
    es.addEventListener('batchUpdate', (e) => {
      const d = JSON.parse(e.data);
      const swap = (b) => (b.id === d.batch.id ? d.batch : b);
      queue.current = queue.current.map((q) => (q.batch.id === d.batch.id ? d : q));
      setS((p) => ({ ...p, view: d, recent: p.recent.map(swap), batch: p.batch && p.batch.id === d.batch.id ? d.batch : p.batch }));
    });
    es.addEventListener('batch', (e) => {
      const d = JSON.parse(e.data);
      if (pausedRef.current) { queue.current.push(d); setS((p) => ({ ...p, queued: queue.current.length })); }
      else setS((p) => applyBatch(p, d));
    });
    return () => es.close();
  }, [company]);

  return s;
}

export const fmt = {
  n: (v) => (v == null ? '—' : Number(v).toLocaleString('en-GB')),
  pct: (v) => (v == null ? '—' : `${v}%`),
  d: (v) => (v == null ? '—' : `${v} d`),
  date: (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }),
  dateY: (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }),
  ago: (iso) => {
    if (!iso) return 'never';
    const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m} min ago`;
    if (m < 1440) return `${Math.round(m / 60)} h ago`;
    return `${Math.round(m / 1440)} d ago`;
  },
};

export const PRIORITY_COLOR = { P1: 'var(--p1)', P2: 'var(--p2)', P3: 'var(--p3)', P4: 'var(--p4)' };
export const PRIORITY_LABEL = { P1: 'Act now', P2: 'Urgent', P3: 'Planned', P4: 'Routine' };
export const SOURCE_LABEL = { MDE: 'Defender', R7: 'Rapid7', Both: 'Both tools' };
export const riskColor = (r) => (r >= 85 ? 'var(--p1)' : r >= 70 ? 'var(--p2)' : r >= 50 ? 'var(--p3)' : 'var(--p4)');
export const priorityOf = (r) => (r >= 85 ? 'P1' : r >= 70 ? 'P2' : r >= 50 ? 'P3' : 'P4');
export const complianceTone = (v) => (v >= 85 ? 'good' : v >= 70 ? 'warn' : 'bad');

// Tiny markdown: **bold** only — enough for the GenAI narratives.
export function md(text) {
  return String(text).split(/(\*\*[^*]+\*\*)/g).map((part, i) =>
    part.startsWith('**') ? <strong key={i}>{part.slice(2, -2)}</strong> : part,
  );
}

export function downloadCsv(filename, columns, rows) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = [columns.map(esc).join(','), ...rows.map((r) => r.map(esc).join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function useElementWidth() {
  const ref = useRef(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

export const storage = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
};
