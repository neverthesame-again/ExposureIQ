// Hand-built SVG charts: thin marks, recessive axes, hover tooltips on every chart.
import { useState } from 'react';
import { useElementWidth, fmt } from '../lib.jsx';

function Tooltip({ tip }) {
  if (!tip) return null;
  return (
    <div className="tooltip" style={{ left: tip.x, top: tip.y }}>
      {tip.title && <div className="tt-h">{tip.title}</div>}
      {tip.rows.map((r) => (
        <div className="tt-r" key={r.label}>
          {r.color && <span style={{ width: 8, height: 8, borderRadius: 2, background: r.color }} />}
          {r.label}<b>{r.value}</b>
        </div>
      ))}
    </div>
  );
}

const niceMax = (v) => {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
};

export function Sparkline({ values, color = 'var(--accent)', width = 84, height = 26, className }) {
  if (!values?.length) return null;
  const min = Math.min(...values), max = Math.max(...values);
  const span = max - min || 1;
  const pts = values.map((v, i) => [(i / (values.length - 1)) * (width - 4) + 2, height - 3 - ((v - min) / span) * (height - 6)]);
  const d = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join('');
  const last = pts[pts.length - 1];
  return (
    <svg width={width} height={height} className={className} aria-hidden>
      <path d={d} fill="none" stroke={color} strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="2.6" fill={color} />
    </svg>
  );
}

export function LineChart({ data, xKey = 'date', series, height = 220, yFormat = fmt.n, xFormat = fmt.date, yMax, area = true, annotations = [] }) {
  const [ref, width] = useElementWidth();
  const [hover, setHover] = useState(null);
  const pad = { l: 36, r: 12, t: 12, b: 26 };
  const w = Math.max(0, width - pad.l - pad.r), h = height - pad.t - pad.b;
  const max = yMax ?? niceMax(Math.max(...data.flatMap((d) => series.map((s) => d[s.key]))) * 1.1);
  const x = (i) => pad.l + (data.length === 1 ? w / 2 : (i / (data.length - 1)) * w);
  const y = (v) => pad.t + h - (v / max) * h;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((t) => t * max);
  const onMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const i = Math.round(((e.clientX - rect.left - pad.l) / w) * (data.length - 1));
    setHover(Math.max(0, Math.min(data.length - 1, i)));
  };
  const tip = hover != null && width ? {
    x: x(hover), y: Math.min(...series.map((s) => y(data[hover][s.key]))),
    title: xFormat(data[hover][xKey]),
    rows: series.map((s) => ({ label: s.label, value: yFormat(data[hover][s.key]), color: s.color })),
  } : null;
  return (
    <div className="chart" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height} onMouseMove={onMove} onMouseLeave={() => setHover(null)} role="img">
          <defs>
            {series.map((s) => (
              <linearGradient key={s.key} id={`g-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor={s.color} stopOpacity="0.22" />
                <stop offset="1" stopColor={s.color} stopOpacity="0" />
              </linearGradient>
            ))}
          </defs>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={pad.l + w} y1={y(t)} y2={y(t)} stroke="var(--grid)" strokeDasharray={t ? '2 4' : undefined} />
              <text x={pad.l - 8} y={y(t) + 4} textAnchor="end">{yFormat(Math.round(t))}</text>
            </g>
          ))}
          {data.map((d, i) => (i % Math.ceil(data.length / 7) === 0 || i === data.length - 1) && (
            <text key={i} x={x(i)} y={height - 6} textAnchor="middle">{xFormat(d[xKey])}</text>
          ))}
          {annotations.map((a) => (
            <g key={a.label}>
              <line x1={x(a.index)} x2={x(a.index)} y1={pad.t} y2={pad.t + h} stroke="var(--ai)" strokeDasharray="3 3" />
              <text x={x(a.index) + 5} y={pad.t + 10} style={{ fill: 'var(--ai)', fontWeight: 600 }}>{a.label}</text>
            </g>
          ))}
          {series.map((s) => {
            const line = data.map((d, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(d[s.key]).toFixed(1)}`).join('');
            return (
              <g key={s.key}>
                {area && series.length === 1 && <path d={`${line}L${x(data.length - 1)},${y(0)}L${x(0)},${y(0)}Z`} fill={`url(#g-${s.key})`} />}
                <path d={line} fill="none" stroke={s.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" strokeDasharray={s.dashed ? '5 4' : undefined} />
              </g>
            );
          })}
          {hover != null && (
            <g>
              <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={pad.t + h} stroke="var(--axis)" />
              {series.map((s) => <circle key={s.key} cx={x(hover)} cy={y(data[hover][s.key])} r="4.5" fill={s.color} stroke="var(--surface)" strokeWidth="2" />)}
            </g>
          )}
        </svg>
      )}
      <Tooltip tip={tip} />
    </div>
  );
}

export function StackedColumns({ rows, labelKey = 'label', keys, height = 220, onClick, yFormat = fmt.n }) {
  const [ref, width] = useElementWidth();
  const [hover, setHover] = useState(null);
  const pad = { l: 34, r: 8, t: 10, b: 28 };
  const w = Math.max(0, width - pad.l - pad.r), h = height - pad.t - pad.b;
  const totals = rows.map((r) => keys.reduce((s, k) => s + r[k.key], 0));
  const max = niceMax(Math.max(...totals, 1));
  const band = w / rows.length;
  const bw = Math.min(46, band * 0.56);
  const y = (v) => (v / max) * h;
  const tip = hover != null && width ? {
    x: pad.l + band * hover + band / 2,
    y: pad.t + h - y(totals[hover]),
    title: `${rows[hover][labelKey]} · ${fmt.n(totals[hover])}`,
    rows: [...keys].reverse().map((k) => ({ label: k.label, value: yFormat(rows[hover][k.key]), color: k.color })),
  } : null;
  return (
    <div className="chart" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height}>
          {[0, 0.5, 1].map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={pad.l + w} y1={pad.t + h - t * h} y2={pad.t + h - t * h} stroke="var(--grid)" strokeDasharray={t ? '2 4' : undefined} />
              <text x={pad.l - 8} y={pad.t + h - t * h + 4} textAnchor="end">{yFormat(Math.round(t * max))}</text>
            </g>
          ))}
          {rows.map((r, i) => {
            let acc = 0;
            const cx = pad.l + band * i + band / 2;
            const segs = keys.filter((k) => r[k.key] > 0);
            return (
              <g key={r[labelKey]} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} onClick={() => onClick?.(r)} style={{ cursor: onClick ? 'pointer' : 'default' }}>
                <rect x={pad.l + band * i} y={pad.t} width={band} height={h} fill={hover === i ? 'var(--surface-2)' : 'transparent'} rx="6" />
                {segs.map((k, si) => {
                  const hh = y(r[k.key]);
                  const yy = pad.t + h - acc - hh;
                  acc += hh;
                  const top = si === segs.length - 1;
                  const gap = si > 0 ? 2 : 0;
                  return top
                    ? <path key={k.key} d={roundedTop(cx - bw / 2, yy, bw, Math.max(0, hh - gap), 4)} fill={k.color} />
                    : <rect key={k.key} x={cx - bw / 2} y={yy} width={bw} height={Math.max(0, hh - gap)} fill={k.color} />;
                })}
                <text x={cx} y={height - 8} textAnchor="middle" style={{ fill: 'var(--text-2)', fontWeight: 500 }}>{r[labelKey]}</text>
              </g>
            );
          })}
        </svg>
      )}
      <Tooltip tip={tip} />
    </div>
  );
}
function roundedTop(x, y, w, h, r) {
  r = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

export function Legend({ items }) {
  return (
    <div className="legend">
      {items.map((i) => <span key={i.label}><i style={{ background: i.color }} />{i.label}</span>)}
    </div>
  );
}

export function Donut({ segments, size = 150, thickness = 18, center, sub }) {
  const [hover, setHover] = useState(null);
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const r = size / 2 - thickness / 2 - 2;
  const C = 2 * Math.PI * r;
  let acc = 0;
  const gap = 3;
  return (
    <div className="chart" style={{ width: size }}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={thickness} />
        {segments.map((s, i) => {
          const len = (s.value / total) * C;
          const dash = Math.max(0, len - gap);
          const el = (
            <circle key={s.label} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color} strokeWidth={hover === i ? thickness + 4 : thickness}
              strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={-acc} transform={`rotate(-90 ${size / 2} ${size / 2})`}
              onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} style={{ transition: 'stroke-width .15s' }} />
          );
          acc += len;
          return el;
        })}
        <text x={size / 2} y={size / 2 + 2} textAnchor="middle" style={{ fontSize: 24, fontWeight: 800, fill: 'var(--text)' }}>
          {hover != null ? fmt.n(segments[hover].value) : center}
        </text>
        <text x={size / 2} y={size / 2 + 20} textAnchor="middle" style={{ fontSize: 11 }}>
          {hover != null ? segments[hover].label : sub}
        </text>
      </svg>
    </div>
  );
}

export function Gauge({ value, prev, size = 220 }) {
  const r = size / 2 - 18;
  const cx = size / 2, cy = size / 2 + 4;
  const angle = (v) => Math.PI + (v / 100) * Math.PI;
  const pt = (v, rr = r) => [cx + rr * Math.cos(angle(v)), cy + rr * Math.sin(angle(v))];
  const arc = (a, b, rr = r) => {
    const [x1, y1] = pt(a, rr), [x2, y2] = pt(b, rr);
    return `M${x1},${y1}A${rr},${rr} 0 ${b - a > 50 ? 1 : 0} 1 ${x2},${y2}`;
  };
  const bands = [[0, 30, 'var(--good)', 'Low'], [30, 60, 'var(--warn)', 'Medium'], [60, 100, 'var(--bad)', 'High']];
  const band = bands.find(([a, b]) => value >= a && value < b) || bands[2];
  const [nx, ny] = pt(value, r - 26);
  return (
    <svg width={size} height={size / 2 + 34} role="img" aria-label={`Exposure score ${value} of 100`}>
      {bands.map(([a, b, c]) => <path key={a} d={arc(a + 0.8, b - 0.8)} stroke={c} strokeOpacity="0.22" strokeWidth="14" fill="none" strokeLinecap="butt" />)}
      <path d={arc(0.5, Math.max(1, value))} stroke={band[2]} strokeWidth="14" fill="none" strokeLinecap="round" />
      {prev != null && (() => { const [px, py] = pt(prev, r + 12); return <circle cx={px} cy={py} r="3.5" fill="var(--muted)"><title>4 weeks ago: {prev}</title></circle>; })()}
      <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="var(--text)" strokeWidth="3" strokeLinecap="round" />
      <circle cx={cx} cy={cy} r="7" fill="var(--surface)" stroke="var(--text)" strokeWidth="3" />
      <text x={cx - r} y={cy + 20} textAnchor="middle" style={{ fontSize: 10 }}>0</text>
      <text x={cx + r} y={cy + 20} textAnchor="middle" style={{ fontSize: 10 }}>100</text>
    </svg>
  );
}

export function Venn({ a, b, both, labelA, labelB, colorA = 'var(--mde)', colorB = 'var(--r7)', height = 190 }) {
  const [ref, width] = useElementWidth();
  const [hover, setHover] = useState(null);
  const total = a + b - both;
  const ra = Math.sqrt(a / total) * 80, rb = Math.sqrt(b / total) * 80;
  const overlapRatio = both / Math.min(a, b);
  const dist = (ra + rb) * (1 - overlapRatio * 0.55);
  const cx = width / 2, cy = height / 2;
  const xa = cx - dist / 2 + (ra - rb) * 0.1, xb = xa + dist;
  const regions = { a: { label: `Only ${labelA}`, value: a - both }, both: { label: 'Seen by both (de-duplicated)', value: both }, b: { label: `Only ${labelB}`, value: b - both } };
  return (
    <div className="chart" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height}>
          <circle cx={xa} cy={cy} r={ra} fill={colorA} fillOpacity={hover === 'a' ? 0.42 : 0.26} stroke={colorA} strokeWidth="2" onMouseEnter={() => setHover('a')} onMouseLeave={() => setHover(null)} />
          <circle cx={xb} cy={cy} r={rb} fill={colorB} fillOpacity={hover === 'b' ? 0.42 : 0.26} stroke={colorB} strokeWidth="2" onMouseEnter={() => setHover('b')} onMouseLeave={() => setHover(null)} />
          <text x={xa - ra * 0.45} y={cy} textAnchor="middle" style={{ fontSize: 20, fontWeight: 800, fill: 'var(--text)', pointerEvents: 'none' }}>{fmt.n(a - both)}</text>
          <text x={xa - ra * 0.45} y={cy + 16} textAnchor="middle" style={{ pointerEvents: 'none' }}>{labelA} only</text>
          <text x={(xa + ra + xb - rb) / 2} y={cy} textAnchor="middle" style={{ fontSize: 17, fontWeight: 800, fill: 'var(--text)' }} onMouseEnter={() => setHover('both')} onMouseLeave={() => setHover(null)}>{fmt.n(both)}</text>
          <text x={(xa + ra + xb - rb) / 2} y={cy + 15} textAnchor="middle" style={{ pointerEvents: 'none' }}>both</text>
          <text x={xb + rb * 0.4} y={cy} textAnchor="middle" style={{ fontSize: 20, fontWeight: 800, fill: 'var(--text)', pointerEvents: 'none' }}>{fmt.n(b - both)}</text>
          <text x={xb + rb * 0.4} y={cy + 16} textAnchor="middle" style={{ pointerEvents: 'none' }}>{labelB} only</text>
        </svg>
      )}
      {hover && <Tooltip tip={{ x: width / 2, y: 14, title: regions[hover].label, rows: [{ label: 'Unified findings', value: fmt.n(regions[hover].value) }] }} />}
    </div>
  );
}

// Horizontal proportional bar made of labelled segments (2px surface gaps)
export function SegBar({ segments, height = 10 }) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  return (
    <div className="bar-track" style={{ height }}>
      {segments.filter((s) => s.value > 0).map((s) => (
        <div key={s.label} title={`${s.label}: ${fmt.n(s.value)}`} style={{ width: `${(s.value / total) * 100}%`, background: s.color }} />
      ))}
    </div>
  );
}
