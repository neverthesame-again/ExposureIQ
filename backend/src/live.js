// Live feed simulation. Every few seconds one source delivers a batch of records, and the batch
// goes through the same steps a production connector would: collect → normalise → correlate →
// score → prioritise → deliver. Batches change the shared store, so every screen moves with them.
import { COMPANIES, SLA_POLICY } from './data/companies.js';
import { CATALOG, catalogById } from './data/catalog.js';
import { store, computeRisk, priorityFor, slaState } from './data/generator.js';
import { kpis, topRisks, isOpen } from './analytics.js';
import { briefing, runSync } from './insights.js';
import { triage, runAssetMatch } from './agents.js';

const TICK_MS = 6000;
const SOURCES = {
  MDE: { label: 'Defender for Endpoint', flag: 'mde', syncs: ['mde', 'mdvm'] },
  R7: { label: 'Rapid7 InsightVM', flag: 'r7', syncs: ['r7'] },
  CMDB: { label: 'ServiceNow CMDB', syncs: ['cmdb'] },
  INTEL: { label: 'CISA KEV · EPSS', syncs: ['kev'] },
};
const WEIGHTS = [['MDE', 0.45], ['R7', 0.25], ['CMDB', 0.15], ['INTEL', 0.15]];
const coShort = Object.fromEntries(COMPANIES.map((c) => [c.id, c.short]));

const rnd = Math.random;
const int = (a, b) => a + Math.floor(rnd() * (b - a + 1));
const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
const weighted = (pairs) => {
  let x = rnd() * pairs.reduce((s, [, w]) => s + w, 0);
  for (const [v, w] of pairs) if ((x -= w) <= 0) return v;
  return pairs[pairs.length - 1][0];
};
const sample = (arr, n) => {
  const a = [...arr];
  for (let i = 0; i < Math.min(n, a.length); i++) {
    const j = i + Math.floor(rnd() * (a.length - i));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, n);
};
const lc = (t) => t.charAt(0).toLowerCase() + t.slice(1);
const plural = (n, one, many = `${one}s`) => `${n.toLocaleString('en-GB')} ${n === 1 ? one : many}`;

let seq = 0;
let nextFinding = store.findings.length + 1;
const startedAt = new Date().toISOString();
let nextAt = Date.now() + TICK_MS;
const recent = [];
const totals = { batches: 0, received: 0, filtered: 0, normalised: 0, merged: 0, newFindings: 0, scored: 0, kev: 0, p1p2: 0, agentDecisions: 0, remediated: 0, tickets: 0, published: 0 };

const seenBy = (f, flag) => store.assetById[f.assetId][flag] && catalogById[f.cve].detect[flag];

function scannerBatch(src) {
  const { flag, label } = SOURCES[src];
  // A Rapid7 scan job covers one company's sites; Defender agents report from everywhere.
  const company = src === 'R7' ? pick(COMPANIES).id : null;
  const inScope = (x) => !company || x.company === company;
  const open = store.findings.filter((f) => f.status === 'Open' && inScope(f) && seenBy(f, flag));
  const openKeys = new Set(store.findings.filter(isOpen).map((f) => `${f.assetId}|${f.cve}`));

  // 1. Records describing issues we already know about → merged into the existing finding.
  const known = sample(open, src === 'R7' ? int(18, 50) : int(6, 20));
  let nowBoth = 0;
  for (const f of known) {
    if (!f.sources.includes(src)) { f.sources.push(src); nowBoth++; }
    f.detected[src] = 0;
  }

  // 2. Fixes the tool can now confirm (the vulnerable software / config is gone).
  const fixed = sample(open.filter((f) => !known.includes(f)), src === 'R7' ? int(0, 2) : int(0, 3));
  for (const f of fixed) {
    f.status = 'Remediated';
    f.remediatedAgo = 0;
    f.sla = slaState(f);
    openKeys.delete(`${f.assetId}|${f.cve}`);
    const t = store.tickets.find((x) => x.cve === f.cve && x.company === f.company && x.state !== 'Resolved');
    if (t && !store.findings.some((o) => o.cve === f.cve && o.company === f.company && isOpen(o))) t.state = 'Resolved';
  }

  // 3. Genuinely new weaknesses.
  const want = weighted([[0, 0.25], [1, 0.4], [2, 0.25], [3, 0.1]]);
  const assets = store.assets.filter((a) => a[flag] && inScope(a));
  const created = [];
  for (let tries = 0; created.length < want && tries < 60; tries++) {
    const a = pick(assets);
    const cats = CATALOG.filter((c) => c.detect[flag] && c.category !== 'End of Life' && c.tags.some((t) => a.tags.includes(t)) && !openKeys.has(`${a.id}|${c.id}`));
    if (!cats.length) continue;
    const cat = weighted(cats.map((c) => [c, c.prob]));
    const risk = computeRisk(cat, a).total;
    const p = priorityFor(risk);
    const f = {
      id: `F-${String(nextFinding++).padStart(6, '0')}`,
      cve: cat.id, assetId: a.id, company: a.company,
      sources: [src], detected: { [src]: 0 },
      exposureAgo: +(rnd() * (src === 'R7' ? 3 : 0.5)).toFixed(2), detectedAgo: 0,
      status: 'Open', remediatedAgo: null, risk, priority: p.priority, slaDays: p.days, live: true,
    };
    f.sla = slaState(f);
    store.findings.push(f);
    openKeys.add(`${a.id}|${cat.id}`);
    created.push(f);
  }

  // 4. The triage agent decides what happens to each urgent or actively exploited finding.
  const triaged = created.filter((f) => f.priority === 'P1' || f.priority === 'P2' || catalogById[f.cve].kev).slice(0, 3).map(triage);
  const tickets = triaged.filter((x) => x.ticket).map((x) => x.ticket);
  const agentRuns = triaged.map((x) => x.run);

  const filtered = src === 'R7' ? int(4, 18) : int(0, 4);
  const normalised = known.length + fixed.length + created.length;
  const received = normalised + filtered;
  const byP = ['P1', 'P2', 'P3', 'P4'].map((p) => [p, created.filter((f) => f.priority === p).length]).filter(([, n]) => n);
  const top = [...created].sort((a, b) => b.risk - a.risk)[0];
  const kevNew = created.filter((f) => catalogById[f.cve].kev).length;
  const p1p2 = created.filter((f) => f.priority === 'P1' || f.priority === 'P2').length;
  const host = (f) => store.assetById[f.assetId].hostname;
  const sla = (p) => `${p} ${SLA_POLICY.find((x) => x.priority === p).days} d`;

  return {
    company,
    counts: { received, filtered, normalised, merged: known.length, nowBoth, newFindings: created.length, scored: created.length, kev: kevNew, p1p2, agentDecisions: agentRuns.length, remediated: fixed.length, tickets: tickets.length, published: normalised },
    steps: [
      `${plural(received, 'record')} received from ${label}${company ? ` (${coShort[company]} scan job)` : ' agents'}.`,
      `${filtered ? `${plural(filtered, 'informational check')} dropped. ` : ''}${plural(normalised, 'record')} matched to CMDB assets with standard CVE IDs and severity.`,
      `${known.length} already known → merged${nowBoth ? ` (${nowBoth} now confirmed by both tools)` : ''}. ${plural(created.length, 'new finding')}${fixed.length ? `, ${plural(fixed.length, 'fix', 'fixes')} confirmed` : ''}.`,
      top ? `${top.cve} on ${host(top)} scored ${top.risk}/100${catalogById[top.cve].kev ? ' (actively exploited)' : ''}. ${byP.map(([p, n]) => `${n} × ${p}`).join(', ')}; SLA clock started (${byP.map(([p]) => sla(p)).join(', ')}).` : 'Nothing new to score in this batch.',
      agentRuns.length ? `Triage agent reviewed ${plural(agentRuns.length, 'finding')}: ${agentRuns.map((r) => `${r.subject.cve} → ${lc(r.decision.label)}`).join('; ')}.` : 'Nothing urgent, so the triage agent was not needed.',
      `${tickets.length ? `${tickets.map((t) => t.id).join(', ')} raised by the agent. ` : ''}Power BI and dashboards refreshed.`,
    ],
    summary: `${plural(received, 'record')} → ${known.length} merged, ${created.length} new${p1p2 ? ` (${p1p2} urgent)` : ''}${fixed.length ? `, ${fixed.length} fixed` : ''}`,
    newFindings: created.map((f) => ({ id: f.id, cve: f.cve, title: catalogById[f.cve].title, hostname: host(f), company: f.company, companyName: coShort[f.company], risk: f.risk, priority: f.priority, kev: catalogById[f.cve].kev })),
    fixed: fixed.map((f) => ({ cve: f.cve, hostname: host(f), companyName: coShort[f.company] })),
    tickets: tickets.map((t) => ({ id: t.id, cve: t.cve, assignee: t.assignee })),
    agentRuns: agentRuns.map((r) => ({ id: r.id, agent: r.agent, cve: r.subject.cve, label: r.decision.label, action: r.decision.action })),
  };
}

function enrichmentBatch(src) {
  const open = store.findings.filter(isOpen);
  if (src === 'CMDB') {
    const cis = int(12, 40);
    // A CMDB refresh is when uncertain device matches can be settled, so the asset-match agent runs here.
    const run = runAssetMatch();
    return {
      company: null,
      counts: { received: cis, filtered: 0, normalised: cis, merged: 0, nowBoth: 0, newFindings: 0, scored: 0, kev: 0, p1p2: 0, agentDecisions: run ? 1 : 0, remediated: 0, tickets: 0, published: cis },
      steps: [
        `${cis} configuration items received from ServiceNow CMDB.`,
        `All ${cis} matched to known assets by Entra device ID or hostname.`,
        'Enrichment only: owners and business services checked, no conflicts.',
        `Business criticality re-applied to ${plural(open.length, 'open finding')}; no priority changes.`,
        run ? `Asset-Match agent checked ${run.title}: ${lc(run.decision.label)}.` : 'No uncertain device matches left for the Asset-Match agent.',
        'Owner routing for tickets updated.',
      ],
      summary: `${cis} CIs refreshed; owners and criticality confirmed`,
      newFindings: [], fixed: [], tickets: [],
      agentRuns: run ? [{ id: run.id, agent: run.agent, cve: null, label: `${run.subject.hostname}: ${run.decision.label}`, action: run.decision.action }] : [],
    };
  }
  const updates = int(3, 12);
  const hit = sample([...new Set(open.map((f) => f.cve))], int(1, 5));
  const matched = hit.length;
  const touched = open.filter((f) => hit.includes(f.cve)).length;
  return {
    company: null,
    counts: { received: updates, filtered: updates - matched, normalised: matched, merged: 0, nowBoth: 0, newFindings: 0, scored: 0, kev: 0, p1p2: 0, agentDecisions: 0, remediated: 0, tickets: 0, published: matched },
    steps: [
      `${updates} KEV / EPSS updates received from public threat intelligence.`,
      `${plural(matched, 'CVE')} present in the SHV estate; ${updates - matched} not relevant, dropped.`,
      'Enrichment only: no new findings.',
      `No priority changes. Exploit likelihood refreshed for ${plural(touched, 'open finding')} (${hit.slice(0, 2).join(', ')}${matched > 2 ? '…' : ''}).`,
      'No new findings, so no agent decisions needed.',
      'Threat-intel fields updated in Power BI.',
    ],
    summary: `${updates} threat-intel updates, ${matched} relevant to the estate`,
    newFindings: [], fixed: [], tickets: [], agentRuns: [],
  };
}

export function runBatch(forced) {
  const source = SOURCES[forced] ? forced : weighted(WEIGHTS);
  const b = SOURCES[source].flag ? scannerBatch(source) : enrichmentBatch(source);
  Object.assign(b, { id: ++seq, at: new Date().toISOString(), source, sourceLabel: SOURCES[source].label });
  for (const k of Object.keys(totals)) if (k in b.counts) totals[k] += b.counts[k];
  totals.batches++;
  recent.unshift(b);
  recent.length = Math.min(recent.length, 20);
  [...SOURCES[source].syncs, 'pbi', ...(b.counts.tickets ? ['snow'] : [])].forEach(runSync);
  return b;
}

function view(company) {
  const b = briefing(company);
  return {
    kpis: kpis(company),
    topRisks: topRisks(company, 5),
    briefing: { headline: b.headline },
    totals, startedAt, tickMs: TICK_MS, nextAt,
  };
}

export function attachLive(app) {
  const clients = new Set();
  const send = (c, event, data) => c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  const broadcast = (batch) => {
    const views = {};
    for (const c of clients) send(c, 'batch', { batch, ...(views[c.company] ||= view(c.company)) });
  };

  app.get('/api/live', (req, res) => res.json({ ...view(req.query.company || 'all'), recent }));
  app.get('/api/live/stream', (req, res) => {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.flushHeaders();
    const c = { res, company: req.query.company || 'all' };
    clients.add(c);
    send(c, 'snapshot', { ...view(c.company), recent });
    req.on('close', () => clients.delete(c));
  });
  app.post('/api/live/trigger', (req, res) => {
    const b = runBatch(req.body?.source);
    broadcast(b);
    res.json({ id: b.id });
  });

  setInterval(() => {
    nextAt = Date.now() + TICK_MS;
    broadcast(runBatch());
  }, TICK_MS);
  setInterval(() => { for (const c of clients) c.res.write(': ping\n\n'); }, 20000);
}
