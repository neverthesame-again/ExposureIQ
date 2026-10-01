import express from 'express';
import cors from 'cors';
import { COMPANIES, SLA_POLICY } from './src/data/companies.js';
import { store } from './src/data/generator.js';
import { catalogById } from './src/data/catalog.js';
import {
  kpis, trend, scorecard, priorityByCompany, topRisks, vulnerabilities, vulnDetail,
  assetsList, assetDetail, reconciliation, remediation, searchAll, isOpen, needsReview,
} from './src/analytics.js';
import { briefing, copilot, integrations, runSync, pov, toggleTask, report } from './src/insights.js';
import { attachLive } from './src/live.js';
import { attachAgents, copilotRun, pendingApprovals } from './src/agents.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4100;
const wait = (ms) => new Promise((res) => setTimeout(res, ms));

app.get('/api/health', (_req, res) => res.json({ ok: true, findings: store.findings.length, assets: store.assets.length }));

app.get('/api/meta', (_req, res) => res.json({
  companies: COMPANIES.map(({ id, name, short, hq, sector, owner, scanDays }) => ({ id, name, short, hq, sector, owner, scanDays })),
  slaPolicy: SLA_POLICY,
  generatedAt: new Date().toISOString(),
  dataMode: 'Simulated',
  counts: {
    p1: new Set(store.findings.filter((f) => isOpen(f) && f.priority === 'P1').map((f) => f.cve)).size,
    breached: store.findings.filter((f) => isOpen(f) && f.sla === 'Breached').length,
    review: store.assets.filter(needsReview).length,
    approvals: pendingApprovals(),
  },
  trial: { day: 23, length: 90 },
}));

app.get('/api/overview', (req, res) => {
  const c = req.query.company;
  res.json({
    kpis: kpis(c),
    trend: trend(c),
    scorecard: scorecard(),
    priorityByCompany: priorityByCompany(),
    topRisks: topRisks(c, 6),
    briefing: briefing(c),
  });
});

app.get('/api/vulnerabilities', (req, res) => res.json(vulnerabilities(req.query)));
app.get('/api/vulnerabilities/:cve', (req, res) => {
  const d = vulnDetail(req.params.cve, req.query.company);
  if (!d) return res.status(404).json({ error: 'Unknown vulnerability' });
  res.json(d);
});

app.get('/api/assets', (req, res) => res.json(assetsList(req.query)));
app.get('/api/assets/:id', (req, res) => {
  const d = assetDetail(req.params.id);
  if (!d) return res.status(404).json({ error: 'Unknown asset' });
  res.json(d);
});

app.get('/api/reconciliation', (req, res) => res.json(reconciliation(req.query.company)));
app.get('/api/remediation', (req, res) => res.json(remediation(req.query.company)));
app.get('/api/search', (req, res) => res.json(searchAll(req.query.q)));

app.get('/api/tickets', (_req, res) => res.json(store.tickets));
app.post('/api/tickets', async (req, res) => {
  const { cve, company } = req.body || {};
  if (!catalogById[cve]) return res.status(400).json({ error: 'Unknown vulnerability' });
  const targets = company && company !== 'all' ? [company] : COMPANIES.map((c) => c.id);
  const created = [];
  for (const co of targets) {
    const open = store.findings.filter((f) => f.cve === cve && f.company === co && isOpen(f));
    if (!open.length || store.tickets.some((t) => t.cve === cve && t.company === co)) continue;
    const t = {
      id: store.nextTicket(), cve, company: co, createdAgo: 0, state: 'New',
      assignee: store.assetById[open.sort((a, b) => b.risk - a.risk)[0].assetId].owner,
      createdBy: 'You (via ExposureIQ)', assets: open.length,
    };
    store.tickets.push(t);
    created.push(t);
  }
  await wait(700);
  res.json({ created });
});

app.post('/api/copilot', async (req, res) => {
  const { question = '', company } = req.body || {};
  await wait(500 + Math.random() * 600);
  const answer = copilot(question, company);
  const run = copilotRun(question, company, answer);
  res.json({ ...answer, trace: run.steps, runId: run.id });
});

app.get('/api/integrations', (_req, res) => res.json(integrations()));
app.post('/api/integrations/:id/sync', async (req, res) => {
  await wait(1400);
  res.json(runSync(req.params.id));
});

app.get('/api/pov', (_req, res) => res.json(pov()));
app.post('/api/pov/tasks/:id/toggle', (req, res) => res.json(toggleTask(req.params.id)));

app.get('/api/reports/:type', async (req, res) => {
  await wait(900);
  res.json(report(req.params.type, req.query.company));
});

attachAgents(app);
attachLive(app);

app.listen(PORT, () => {
  console.log(`ExposureIQ mock API on http://localhost:${PORT}  (${store.assets.length} assets, ${store.findings.length} unified findings)`);
});
