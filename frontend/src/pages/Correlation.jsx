import { useState } from 'react';
import { Fingerprint, Scale, Radar, Check, X, ArrowRight, Info } from 'lucide-react';
import { useApi, fmt, useElementWidth, PRIORITY_COLOR } from '../lib.jsx';
import { Card, LoadingGrid, ErrorState, useToast } from '../components/ui.jsx';
import { Venn, StackedColumns, Legend } from '../components/charts.jsx';

const SEV_COLOR = { Critical: 'var(--p1)', Severe: 'var(--p2)', High: 'var(--p2)', Moderate: 'var(--p3)', Medium: 'var(--p3)', Low: 'var(--p4)' };

export default function Correlation({ company, navigate }) {
  const { data, loading, error, reload } = useApi('/reconciliation', { company });
  const [decided, setDecided] = useState({});
  const toast = useToast();
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading && !data) return <LoadingGrid />;
  const { raw, uniqueByType, disagreements, matching, mtti } = data;
  const decide = (id, v) => { setDecided((d) => ({ ...d, [id]: v })); toast(v === 'merge' ? 'Match confirmed — findings merged into one asset' : 'Kept as two separate assets'); };
  const pending = matching.review.filter((r) => !decided[r.assetId]);
  const maxMtti = Math.max(mtti.r7, mtti.mde, mtti.unified) * 1.15;

  return (
    <div className="col" style={{ gap: 16 }}>
      <Card title="From two noisy feeds to one source of truth" sub={`${fmt.n(raw.total)} raw findings → ${fmt.n(raw.unified)} unified findings · ${raw.duplicateRate}% of raw volume was duplication`}>
        <Flow raw={raw} />
      </Card>

      <div className="grid g-3">
        <Card title="Overlap" sub="Unified findings by the tool(s) that reported them">
          <Venn a={raw.mde} b={raw.r7} both={raw.both} labelA="Defender" labelB="Rapid7" />
          <div className="text-2" style={{ fontSize: 12 }}>Neither tool alone sees the full picture: dropping either would hide <b style={{ color: 'var(--text)' }}>{fmt.n(Math.min(raw.mdeOnly, raw.r7Only))}+</b> real findings.</div>
        </Card>
        <Card title="Who uniquely sees what" sub="Findings by asset type and source">
          <StackedColumns rows={uniqueByType.map((t) => ({ ...t, label: t.type.replace('Network Device', 'Network').replace('Workstation', 'Endpoints') }))}
            keys={[{ key: 'r7Only', label: 'Rapid7 only', color: 'var(--r7)' }, { key: 'both', label: 'Both', color: 'var(--both)' }, { key: 'mdeOnly', label: 'Defender only', color: 'var(--mde)' }]} height={200} />
          <div className="mt-s"><Legend items={[{ label: 'Defender only', color: 'var(--mde)' }, { label: 'Both', color: 'var(--both)' }, { label: 'Rapid7 only', color: 'var(--r7)' }]} /></div>
        </Card>
        <Card title="Mean time to identify" sub="Exposure start → first detection" icon={<Radar size={16} />}>
          <div className="col" style={{ gap: 14, marginTop: 8 }}>
            {[['Rapid7 alone', mtti.r7, 'var(--r7)', 'scheduled scan cycle'], ['Defender alone', mtti.mde, 'var(--mde)', 'continuous agent telemetry'], ['ExposureIQ unified', mtti.unified, 'var(--both)', 'earliest signal from either tool, all assets']].map(([l, v, c, n]) => (
              <div key={l}>
                <div className="row" style={{ fontSize: 12.5, marginBottom: 5 }}><b>{l}</b><span className="muted" style={{ fontSize: 11 }}>{n}</span><span className="sp" /><b className="num">{v} d</b></div>
                <div className="bar-track" style={{ height: 10 }}><div style={{ width: `${(v / maxMtti) * 100}%`, background: c }} /></div>
              </div>
            ))}
          </div>
          <div className="hero-band mt" style={{ marginBottom: 0, fontSize: 12 }}><Info size={15} style={{ flex: 'none', color: 'var(--accent)' }} /><span>Unified MTTI is slightly above Defender's because it also covers appliances and OT that only Rapid7 can see.</span></div>
        </Card>
      </div>

      <div className="grid g-main">
        <Card title="Severity disagreements, resolved" sub={`${disagreements.length} vulnerabilities (${fmt.n(data.disagreementInstances)} instances) where Rapid7 and Defender label severity differently`} icon={<Scale size={16} />} flush>
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Vulnerability</th><th>Rapid7 says</th><th>Defender says</th><th>ExposureIQ decides (per asset)</th><th className="r">Instances</th></tr></thead>
              <tbody>
                {disagreements.map((d) => (
                  <tr key={d.cve} className="click" onClick={() => navigate('vulnerabilities', { cve: d.cve, status: 'all' })}>
                    <td className="title-cell"><div className="mono" style={{ fontWeight: 600 }}>{d.cve}</div><div className="ttl text-2" style={{ fontWeight: 400 }}>{d.title}</div></td>
                    <td><Sev s={d.r7} /></td>
                    <td><Sev s={d.mde} /></td>
                    <td>
                      <div className="row" style={{ gap: 4 }}>
                        {['P1', 'P2', 'P3', 'P4'].filter((p) => d.unified[p]).map((p) => <span key={p} className="badge"><span className="dot" style={{ background: PRIORITY_COLOR[p] }} />{p} × {d.unified[p]}</span>)}
                      </div>
                    </td>
                    <td className="r num" style={{ fontWeight: 700 }}>{d.instances}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="muted" style={{ fontSize: 11.5, padding: '10px 18px 14px' }}>Same CVE, different answers depending on the asset: a crown-jewel internet-facing server gets P1, a standard laptop gets P3.</div>
        </Card>

        <Card title="Asset identity matching" sub={`${fmt.n(matching.matchedAssets)} assets seen by both tools, matched automatically`} icon={<Fingerprint size={16} />}>
          <div className="col" style={{ gap: 9 }}>
            {matching.methods.map((m) => (
              <div key={m.method}>
                <div className="row" style={{ fontSize: 12.5, marginBottom: 4 }}><span>{m.method}</span><span className="sp" /><b className="num">{m.count}</b></div>
                <div className="bar-track" style={{ height: 7 }}><div style={{ width: `${(m.count / matching.matchedAssets) * 100}%`, background: m.method === 'Fuzzy hostname' ? 'var(--warn)' : 'var(--accent)' }} /></div>
              </div>
            ))}
          </div>
          <div className="section-t">Needs a human ({pending.length})</div>
          {!pending.length && <div className="empty" style={{ padding: 20 }}><Check size={18} style={{ color: 'var(--good)' }} /><div>Review queue is empty</div></div>}
          <div className="col" style={{ gap: 8, maxHeight: 320, overflowY: 'auto' }}>
            {pending.map((r) => (
              <div key={r.assetId} className="card" style={{ padding: 10, boxShadow: 'none' }}>
                <div className="row" style={{ gap: 6, fontSize: 12 }}>
                  <span className="src src-MDE">MDE</span><span className="mono">{r.mdeName}</span>
                  <ArrowRight size={12} className="muted" />
                  <span className="src src-R7">R7</span><span className="mono">{r.r7Name}</span>
                </div>
                <div className="row mt-s" style={{ fontSize: 11.5 }}>
                  <span className="badge badge-warn">{r.confidence}% confidence</span>
                  <span className="muted" style={{ flex: 1 }}>{r.companyName} · {r.reason}</span>
                  <button className="btn btn-sm" onClick={() => decide(r.assetId, 'merge')}><Check size={12} />Same</button>
                  <button className="btn btn-sm btn-ghost" onClick={() => decide(r.assetId, 'split')}><X size={12} />Different</button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

function Sev({ s }) {
  return <span className="badge"><span className="dot" style={{ background: SEV_COLOR[s] }} />{s}</span>;
}

// Sankey-style flow: two raw feeds merge into three unified buckets.
function Flow({ raw }) {
  const [ref, width] = useElementWidth();
  const [hover, setHover] = useState(null);
  const H = 250, nodeW = 14, gap = 16;
  const k = (H - gap) / (raw.r7 + raw.mde);
  const x0 = 150, x1 = Math.max(x0 + 200, width - 190);
  const r7h = raw.r7 * k, mdeh = raw.mde * k;
  const L = { r7: [0, r7h], mde: [r7h + gap, r7h + gap + mdeh] };
  const rightTotal = (raw.r7Only + raw.both + raw.mdeOnly) * k + gap * 2;
  const top = (H - rightTotal) / 2;
  const R = {};
  let y = top;
  R.r7Only = [y, y += raw.r7Only * k]; y += gap;
  R.both = [y, y += raw.both * k]; y += gap;
  R.mdeOnly = [y, y += raw.mdeOnly * k];
  const bothMid = (R.both[0] + R.both[1]) / 2;
  const ribbon = (a0, a1, b0, b1) => {
    const xa = x0 + nodeW, xb = x1, xm = (xa + xb) / 2;
    return `M${xa},${a0}C${xm},${a0} ${xm},${b0} ${xb},${b0}L${xb},${b1}C${xm},${b1} ${xm},${a1} ${xa},${a1}Z`;
  };
  const ribbons = [
    { id: 'r7o', d: ribbon(L.r7[0], L.r7[0] + raw.r7Only * k, R.r7Only[0], R.r7Only[1]), color: 'var(--r7)', tip: `${fmt.n(raw.r7Only)} findings only Rapid7 sees` },
    { id: 'r7b', d: ribbon(L.r7[0] + raw.r7Only * k, L.r7[1], R.both[0], bothMid), color: 'var(--r7)', tip: `${fmt.n(raw.both)} Rapid7 findings also seen by Defender` },
    { id: 'mdeb', d: ribbon(L.mde[0], L.mde[0] + raw.both * k, bothMid, R.both[1]), color: 'var(--mde)', tip: `${fmt.n(raw.both)} Defender findings also seen by Rapid7` },
    { id: 'mdeo', d: ribbon(L.mde[0] + raw.both * k, L.mde[1], R.mdeOnly[0], R.mdeOnly[1]), color: 'var(--mde)', tip: `${fmt.n(raw.mdeOnly)} findings only Defender sees` },
  ];
  const label = (x, yy, anchor, title, value, sub) => (
    <g>
      <text x={x} y={yy - 4} textAnchor={anchor} style={{ fontSize: 12.5, fontWeight: 700, fill: 'var(--text)' }}>{title}</text>
      <text x={x} y={yy + 12} textAnchor={anchor} style={{ fontSize: 12 }}>{value}{sub ? ` · ${sub}` : ''}</text>
    </g>
  );
  const midX = (x0 + x1) / 2;
  return (
    <div className="chart" ref={ref}>
      {width > 0 && (
        <svg width={width} height={H + 10}>
          {ribbons.map((r) => (
            <path key={r.id} d={r.d} fill={r.color} fillOpacity={hover === r.id ? 0.45 : 0.2} stroke={r.color} strokeOpacity="0.35"
              onMouseEnter={() => setHover(r.id)} onMouseLeave={() => setHover(null)} style={{ transition: 'fill-opacity .15s' }}>
              <title>{r.tip}</title>
            </path>
          ))}
          <rect x={x0} y={L.r7[0]} width={nodeW} height={r7h} rx="3" fill="var(--r7)" />
          <rect x={x0} y={L.mde[0]} width={nodeW} height={mdeh} rx="3" fill="var(--mde)" />
          {label(x0 - 12, (L.r7[0] + L.r7[1]) / 2, 'end', 'Rapid7 InsightVM', fmt.n(raw.r7), 'raw')}
          {label(x0 - 12, (L.mde[0] + L.mde[1]) / 2, 'end', 'Defender VM', fmt.n(raw.mde), 'raw')}
          <rect x={x1} y={R.r7Only[0]} width={nodeW} height={R.r7Only[1] - R.r7Only[0]} rx="3" fill="var(--r7)" />
          <rect x={x1} y={R.both[0]} width={nodeW} height={R.both[1] - R.both[0]} rx="3" fill="var(--both)" />
          <rect x={x1} y={R.mdeOnly[0]} width={nodeW} height={R.mdeOnly[1] - R.mdeOnly[0]} rx="3" fill="var(--mde)" />
          {label(x1 + nodeW + 12, (R.r7Only[0] + R.r7Only[1]) / 2, 'start', 'Rapid7 only', fmt.n(raw.r7Only), 'appliances, OT')}
          {label(x1 + nodeW + 12, (R.both[0] + R.both[1]) / 2, 'start', 'Merged', fmt.n(raw.both), `${fmt.n(raw.both * 2)} rows → ${fmt.n(raw.both)}`)}
          {label(x1 + nodeW + 12, (R.mdeOnly[0] + R.mdeOnly[1]) / 2, 'start', 'Defender only', fmt.n(raw.mdeOnly), 'installed software')}
          {width > 700 && ['1 · Match assets', '2 · Normalise CVE', '3 · Score risk'].map((s, i) => (
            <g key={s} transform={`translate(${midX - 180 + i * 125}, ${H / 2 - 13})`}>
              <rect width="112" height="26" rx="13" fill="var(--surface)" stroke="var(--border-strong)" />
              <text x="56" y="17" textAnchor="middle" style={{ fontSize: 11.5, fontWeight: 600, fill: 'var(--text-2)' }}>{s}</text>
            </g>
          ))}
        </svg>
      )}
    </div>
  );
}
