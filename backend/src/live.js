// Sync engine. Each source is pulled through its connector, normalised and correlated into the
// store, and the result is streamed to the UI as a "batch" that walks the six pipeline steps.
//   mock mode: a batch every DEMO_TICK_MS from a random source, against the mock tenant
//   live mode: each configured source on its own schedule (DEFENDER_SYNC_MINUTES etc.)
// Agents run after ingestion; their decisions arrive later as a batch update.
import { COMPANIES, SLA_POLICY } from './data/companies.js';
import { catalogById } from './data/catalog.js';
import { store } from './data/generator.js';
import { config } from './config.js';
import { defender, rapid7, servicenow, intel, connectorStatus } from './connectors/index.js';
import * as C from './ingest/correlate.js';
import * as mock from './mock/tenant.js';
import { kpis, topRisks, isOpen } from './analytics.js';
import { briefing, runSync } from './insights.js';
import { triage, runAssetMatch } from './agents.js';
import { saveState } from './state.js';

const SOURCES = {
  MDE: { label: 'Defender for Endpoint', connector: defender, syncs: ['mde', 'mdvm'], minutes: config.defender.syncMinutes },
  R7: { label: 'Rapid7 InsightVM', connector: rapid7, syncs: ['r7'], minutes: config.rapid7.syncMinutes },
  CMDB: { label: 'ServiceNow CMDB', connector: servicenow, syncs: ['cmdb'], minutes: config.servicenow.syncMinutes },
  INTEL: { label: 'CISA KEV · EPSS', connector: intel, syncs: ['kev'], minutes: config.intel.syncMinutes },
};
const WEIGHTS = [['MDE', 0.45], ['R7', 0.25], ['CMDB', 0.15], ['INTEL', 0.15]];
const enabled = (src) => SOURCES[src].connector.status.mode !== 'off';
const coShort = Object.fromEntries(COMPANIES.map((c) => [c.id, c.short]));
const plural = (n, one, many = `${one}s`) => `${Number(n).toLocaleString('en-GB')} ${n === 1 ? one : many}`;
const lc = (t) => t.charAt(0).toLowerCase() + t.slice(1);
const urgent = (f) => f.priority === 'P1' || f.priority === 'P2';
const host = (f) => store.assetById[f.assetId]?.hostname || f.assetId;

let seq = 0;
let r7Cursor = 0;
const startedAt = new Date().toISOString();
const nextRun = {};
const busy = {};
const recent = [];
const totals = { batches: 0, received: 0, filtered: 0, normalised: 0, merged: 0, newFindings: 0, scored: 0, kev: 0, p1p2: 0, agentDecisions: 0, remediated: 0, tickets: 0, published: 0 };
let broadcast = () => {};

async function pool(items, n, fn) {
  const queue = [...items];
  await Promise.all(Array.from({ length: Math.min(n, queue.length) }, async () => { while (queue.length) await fn(queue.shift()); }));
}

// ---------------- per-source pulls ----------------
async function pullDefender() {
  const since = defender.status.lastSync;
  if (config.mode === 'mock') mock.worldStep();
  if (!since && config.mode === 'live') {
    for (const m of await defender.machines()) C.upsertDefenderMachine(m);
    return { st: C.ingestDefenderVulns(await defender.vulnerabilitiesFull(), { full: true }), scope: 'full snapshot' };
  }
  const rows = await defender.vulnerabilityChanges(since || new Date(Date.now() - 120000).toISOString());
  return { st: C.ingestDefenderVulns(rows), scope: 'changes since last sync' };
}

async function pullRapid7() {
  const sites = await rapid7.sites();
  if (!sites.length) throw new Error('No Rapid7 sites visible to this user');
  const site = config.mode === 'mock' ? sites[Math.floor(Math.random() * sites.length)] : sites[r7Cursor++ % sites.length];
  if (config.mode === 'mock') mock.worldStep({ companyId: mock.mockSites.find((s) => s.id === site.id)?.company, add: [0, 1, 1, 2], fix: [0, 0, 1, 1] });
  const assets = await rapid7.siteAssets(site.id);
  const vulns = new Map();
  const defs = new Map();
  await pool(assets, 4, async (a) => vulns.set(a.id, await rapid7.assetVulnerabilities(a.id)));
  const keys = [...new Set([...vulns.values()].flat().map((v) => v.id))];
  await pool(keys, 4, async (k) => defs.set(k, await rapid7.vulnerability(k)));
  const st = C.ingestRapid7Site(site, assets, vulns, defs);
  return { st, scope: `${site.name} scan`, assets: assets.length, company: C.companyFor({ site: site.name }) };
}

async function pullCmdb() {
  const change = config.mode === 'mock' ? mock.servicenow.maybeChangeCi() : null;
  return { st: C.ingestCmdb(await servicenow.cmdb()), change };
}

async function pullIntel() {
  if (config.mode === 'mock') mock.intel.maybeAddToKev();
  const kev = await intel.kev();
  const open = [...new Set(store.findings.filter(isOpen).map((f) => f.cve))];
  const epss = await intel.epss(open);
  const st = C.ingestThreatIntel(kev, epss);
  return { st, kevCount: kev.length, epssCount: epss.length, kevInEstate: kev.filter((k) => catalogById[k.cveID]).length };
}

// ---------------- one batch ----------------
function counts(st, extra = {}) {
  return {
    received: st.received, filtered: st.filtered, normalised: st.normalised, merged: st.merged, nowBoth: st.nowBoth,
    newFindings: st.created.length, scored: st.created.length + st.rescored, kev: st.created.filter((f) => catalogById[f.cve].kev).length + st.newlyKev.length,
    p1p2: st.created.filter(urgent).length + st.priorityChanges.filter((c) => urgent(c.finding)).length,
    agentDecisions: 0, remediated: st.fixed.length, tickets: 0, published: st.normalised, ...extra,
  };
}

function scoreLine(st) {
  const top = [...st.created].sort((a, b) => b.risk - a.risk)[0];
  if (!top) return st.rescored ? `${plural(st.rescored, 'open finding')} re-scored${st.priorityChanges.length ? `; ${plural(st.priorityChanges.length, 'priority change')}` : '; no priority changes'}.` : 'Nothing new to score in this batch.';
  const byP = ['P1', 'P2', 'P3', 'P4'].map((p) => [p, st.created.filter((f) => f.priority === p).length]).filter(([, n]) => n);
  return `${top.cve} on ${host(top)} scored ${top.risk}/100${catalogById[top.cve].kev ? ' (actively exploited)' : ''}. ${byP.map(([p, n]) => `${n} × ${p}`).join(', ')}; SLA clock started (${byP.map(([p]) => `${p} ${SLA_POLICY.find((x) => x.priority === p).days} d`).join(', ')}).`;
}

async function runSource(src) {
  if (busy[src] || !enabled(src)) return null;
  busy[src] = true;
  const S = SOURCES[src];
  const syncStart = new Date().toISOString();
  const b = { id: ++seq, at: syncStart, source: src, sourceLabel: S.label, mode: S.connector.status.mode, company: null, newFindings: [], fixed: [], tickets: [], agentRuns: [] };
  try {
    let st;
    if (src === 'MDE') {
      const r = await pullDefender();
      st = r.st;
      b.counts = counts(st);
      b.steps = [
        `${plural(st.received, 'record')} received from Defender (${r.scope}).`,
        `${st.filtered ? `${plural(st.filtered, 'software-inventory row')} without a CVE dropped. ` : ''}${plural(st.normalised, 'record')} mapped to ExposureIQ assets and vulnerability ids.`,
        `${st.merged} already known → merged${st.nowBoth ? ` (${st.nowBoth} now confirmed by both tools)` : ''}. ${plural(st.created.length, 'new finding')}${st.fixed.length ? `, ${plural(st.fixed.length, 'fix', 'fixes')} confirmed by Defender` : ''}${st.newAssets ? `, ${plural(st.newAssets, 'new device')}` : ''}.`,
        scoreLine(st), '', '',
      ];
      b.summary = `${plural(st.received, 'record')} → ${st.merged} merged, ${st.created.length} new${st.created.filter(urgent).length ? ` (${st.created.filter(urgent).length} urgent)` : ''}${st.fixed.length ? `, ${st.fixed.length} fixed` : ''}`;
    } else if (src === 'R7') {
      const r = await pullRapid7();
      st = r.st;
      b.company = r.company;
      b.counts = counts(st);
      b.steps = [
        `${plural(r.assets, 'asset')} and ${plural(st.received, 'vulnerability record')} from Rapid7 (${r.scope}).`,
        `${st.filtered ? `${plural(st.filtered, 'unconfirmed ("potential") check')} dropped. ` : ''}${plural(st.normalised, 'record')} mapped to ExposureIQ assets and vulnerability ids.`,
        `${st.merged} already known → merged${st.nowBoth ? ` (${st.nowBoth} now confirmed by both tools)` : ''}. ${plural(st.created.length, 'new finding')}${st.fixed.length ? `, ${plural(st.fixed.length, 'fix', 'fixes')} confirmed by the rescan` : ''}.`,
        scoreLine(st), '', '',
      ];
      b.summary = `${plural(st.received, 'record')} → ${st.merged} merged, ${st.created.length} new${st.fixed.length ? `, ${st.fixed.length} fixed` : ''}`;
    } else if (src === 'CMDB') {
      const r = await pullCmdb();
      st = r.st;
      b.counts = counts(st);
      b.steps = [
        `${plural(st.received, 'configuration item')} received from ServiceNow.`,
        `${plural(st.normalised, 'CI')} matched to assets${st.newAssets ? `; ${plural(st.newAssets, 'new asset')} added` : ''}.`,
        'Enrichment only: owners, services and criticality checked.',
        r.change ? `${r.change.hostname} now supports ${r.change.service} (Crown Jewel): ${plural(st.rescored, 'finding')} re-scored, ${plural(st.priorityChanges.length, 'priority change')}.` : `Business context confirmed${st.rescored ? `; ${plural(st.rescored, 'finding')} re-scored` : ''}.`,
        '', 'Owner routing for tickets updated.',
      ];
      b.summary = r.change ? `${r.change.hostname} re-classified as Crown Jewel; ${st.priorityChanges.length} priority changes` : `${plural(st.received, 'CI')} refreshed; context confirmed`;
    } else {
      const r = await pullIntel();
      st = r.st;
      b.counts = counts(st, { received: r.kevCount + r.epssCount, filtered: r.kevCount - r.kevInEstate, normalised: r.kevInEstate + r.epssCount });
      b.steps = [
        `${plural(r.kevCount, 'KEV entry', 'KEV entries')} and ${plural(r.epssCount, 'EPSS score')} received.`,
        `${plural(r.kevCount - r.kevInEstate, 'KEV entry', 'KEV entries')} not present in the estate dropped; ${r.kevInEstate} matched.`,
        'Enrichment only: no new findings.',
        st.newlyKev.length ? `CISA added ${st.newlyKev.join(', ')} to KEV: ${plural(st.rescored, 'finding')} re-scored, ${plural(st.priorityChanges.length, 'priority change')}.` : `Exploit likelihood refreshed; ${plural(st.rescored, 'finding')} re-scored, ${plural(st.priorityChanges.length, 'priority change')}.`,
        '', 'Threat-intel fields updated in Power BI.',
      ];
      b.summary = st.newlyKev.length ? `${st.newlyKev.join(', ')} added to CISA KEV` : `EPSS refreshed for ${plural(r.epssCount, 'CVE')}`;
    }
    b.newFindings = st.created.map((f) => ({ id: f.id, cve: f.cve, title: catalogById[f.cve].title, hostname: host(f), company: f.company, companyName: coShort[f.company], risk: f.risk, priority: f.priority, kev: catalogById[f.cve].kev }));
    b.fixed = st.fixed.map((f) => ({ cve: f.cve, hostname: host(f), companyName: coShort[f.company] }));
    S.connector.status.lastSync = syncStart;
    S.connector.status.lastError = null;
    S.connector.status.lastCount = st.received;
    [...S.syncs, 'pbi'].forEach(runSync);

    // ---- AI agents ----
    const forTriage = [
      ...st.created.filter((f) => urgent(f) || catalogById[f.cve].kev),
      ...st.priorityChanges.filter((c) => urgent(c.finding) && !urgent({ priority: c.from })).map((c) => c.finding),
      ...store.findings.filter((f) => st.newlyKev.includes(f.cve) && f.status === 'Open'),
    ].filter((f, i, arr) => !f.triaged && arr.indexOf(f) === i).slice(0, 3);
    const jobs = forTriage.map((f) => { const promise = triage(f); return { cve: f.cve, promise, runId: f.triageRunId }; });
    if (src === 'CMDB') {
      const a = store.assets.find((x) => x.matchMethod === 'Fuzzy hostname' && !x.agentReviewed && x.mde && x.r7);
      if (a) { const promise = runAssetMatch(a.id); jobs.push({ cve: null, hostname: a.hostname, promise, runId: a.matchRunId, agent: 'match' }); }
    }
    b.agentRuns = jobs.map((j) => ({ id: j.runId, agent: j.agent || 'triage', cve: j.cve, hostname: j.hostname, label: 'Working…', action: 'running' }));
    b.steps[4] = jobs.length ? `${jobs.length === 1 ? 'Agent' : `${jobs.length} agents`} working on ${b.agentRuns.map((r) => r.cve || `${r.hostname} (device match)`).join(', ')}…` : 'Nothing urgent, so no agent was needed.';
    b.steps[5] ||= 'Dashboards and Power BI dataset refreshed.';
    if (jobs.length) Promise.allSettled(jobs.map((j) => j.promise)).then((results) => agentsDone(b, results));
  } catch (e) {
    S.connector.status.lastError = `${e.message}${e.body ? ` · ${e.body.slice(0, 160)}` : ''}`;
    b.error = S.connector.status.lastError;
    b.counts = { received: 0, filtered: 0, normalised: 0, merged: 0, newFindings: 0, scored: 0, kev: 0, p1p2: 0, agentDecisions: 0, remediated: 0, tickets: 0, published: 0 };
    b.steps = [`${S.label} sync failed: ${b.error}`, 'Skipped.', 'Skipped.', 'Skipped.', 'Skipped.', 'Nothing published.'];
    b.summary = `Sync failed: ${e.message}`;
  } finally {
    busy[src] = false;
  }
  for (const k of Object.keys(totals)) if (k in b.counts) totals[k] += b.counts[k];
  totals.batches++;
  recent.unshift(b);
  recent.length = Math.min(recent.length, 25);
  broadcast('batch', b);
  saveState();
  return b;
}

function agentsDone(b, results) {
  let decisions = 0;
  let tickets = 0;
  results.forEach((r, i) => {
    const out = r.value;
    const run = out?.run || out; // triage returns { run, ticket }; asset-match returns the run
    const entry = b.agentRuns[i];
    if (!run?.decision) { entry.label = 'No decision'; entry.action = 'error'; return; }
    decisions++;
    Object.assign(entry, { id: run.id, label: run.decision.label, action: run.decision.action, engine: run.engine });
    if (out?.ticket) { tickets++; b.tickets.push({ id: out.ticket.id, cve: out.ticket.cve, assignee: out.ticket.assignee }); }
  });
  b.counts.agentDecisions = decisions;
  b.counts.tickets = tickets;
  totals.agentDecisions += decisions;
  totals.tickets += tickets;
  const engines = [...new Set(b.agentRuns.map((r) => r.engine).filter(Boolean))].map((e) => (e === 'rules' ? 'rules engine' : `Gemini ${e}`));
  b.steps[4] = `${b.agentRuns.map((r) => `${r.agent === 'match' ? 'Asset-Match' : 'Triage'}: ${r.cve ? `${r.cve} → ` : `${r.hostname} → `}${lc(r.label)}`).join('; ')}${engines.length ? ` (${engines.join(', ')})` : ''}.`;
  b.steps[5] = `${b.tickets.length ? `${b.tickets.map((t) => t.id).join(', ')} raised in ServiceNow. ` : ''}Dashboards and Power BI dataset refreshed.`;
  broadcast('batchUpdate', b);
  saveState();
}

// ---------------- scheduling ----------------
function pickMock() {
  let x = Math.random();
  for (const [s, w] of WEIGHTS) if ((x -= w) <= 0) return s;
  return 'MDE';
}

function schedule(src, delayMs) {
  nextRun[src] = Date.now() + delayMs;
  setTimeout(async () => {
    await runSource(src);
    let next = SOURCES[src].minutes * 60000;
    if (src === 'R7') {
      const n = Math.max(1, (await rapid7.sites().catch(() => [])).length);
      next = Math.max(60000, next / n); // every site is re-read once per RAPID7_SYNC_MINUTES
    }
    schedule(src, next);
  }, delayMs);
}

const nextAt = () => (config.mode === 'mock' ? nextRun.mock : Math.min(...Object.values(nextRun).filter(Boolean), Date.now() + 3600000));

function view(company) {
  return {
    kpis: kpis(company), topRisks: topRisks(company, 5), briefing: { headline: briefing(company).headline },
    totals, startedAt, tickMs: config.demoTickMs, nextAt: nextAt(), mode: config.mode, sources: connectorStatus(),
  };
}

export function attachLive(app) {
  const clients = new Set();
  const send = (c, event, data) => c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  broadcast = (event, batch) => {
    const views = {};
    for (const c of clients) send(c, event, { batch, ...(views[c.company] ||= view(c.company)) });
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
    const src = SOURCES[req.body?.source] ? req.body.source : 'MDE';
    if (!enabled(src)) return res.status(400).json({ error: `${SOURCES[src].label} is not configured` });
    runSource(src);
    res.json({ started: src });
  });
  setInterval(() => { for (const c of clients) c.res.write(': ping\n\n'); }, 20000);

  if (config.mode === 'mock') {
    const tick = () => { nextRun.mock = Date.now() + config.demoTickMs; setTimeout(async () => { await runSource(pickMock()); tick(); }, config.demoTickMs); };
    tick();
  } else {
    // First pass in a sensible order: context (CMDB) first, then findings, then enrichment.
    let delay = 2000;
    for (const src of ['CMDB', 'MDE', 'INTEL', 'R7']) if (enabled(src)) { schedule(src, delay); delay += 15000; }
  }
}
