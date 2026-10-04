import { config, configured } from './src/config.js';
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
import { attachAgents, askCopilot, pendingApprovals } from './src/agents.js';
import { connectorStatus, testConnector, soc } from './src/connectors/index.js';
import { createTicket } from './src/agents/tools.js';
import { ai } from './src/ai/gemini.js';
import { restoreState } from './src/state.js';

const restored = restoreState();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = config.port;
const wait = (ms) => new Promise((res) => setTimeout(res, ms));

app.get('/api/health', (_req, res) => res.json({ ok: true, findings: store.findings.length, assets: store.assets.length }));

app.get('/api/meta', (_req, res) => res.json({
  companies: COMPANIES.map(({ id, name, short, hq, sector, owner, scanDays }) => ({ id, name, short, hq, sector, owner, scanDays })),
  slaPolicy: SLA_POLICY,
  generatedAt: new Date().toISOString(),
  dataMode: config.mode === 'mock' ? 'Mock tenant' : 'Live connectors',
  ai: { enabled: ai.enabled, model: ai.model },
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
    const t = await createTicket(open.sort((a, b) => b.risk - a.risk)[0], { by: 'Analyst' });
    Object.assign(t, { createdBy: 'You (via ExposureIQ)', assets: open.length });
    created.push(t);
  }
  res.json({ created });
});

app.post('/api/copilot', async (req, res) => {
  const { question = '', company } = req.body || {};
  res.json(await askCopilot(String(question).slice(0, 1000), company || 'all'));
});

app.get('/api/integrations', (_req, res) => res.json(integrations()));
app.post('/api/integrations/:id/sync', async (req, res) => {
  await wait(1400);
  res.json(runSync(req.params.id));
});

// Connector status and connection tests (no secrets are ever returned)
app.get('/api/connectors', (_req, res) => res.json({
  mode: config.mode,
  connectors: connectorStatus(),
  configured,
  ai: { enabled: ai.enabled, model: ai.models.join(' → '), calls: ai.calls, runs: ai.runs, lastError: ai.lastError, inputTokens: ai.inputTokens, outputTokens: ai.outputTokens },
  socLog: soc.sent.slice(0, 10),
}));
app.post('/api/connectors/:id/test', async (req, res) => res.json(await testConnector(req.params.id)));

app.get('/api/pov', (_req, res) => res.json(pov()));
app.post('/api/pov/tasks/:id/toggle', (req, res) => res.json(toggleTask(req.params.id)));

app.get('/api/reports/:type', async (req, res) => {
  await wait(900);
  res.json(report(req.params.type, req.query.company));
});

attachAgents(app);
attachLive(app);

app.listen(PORT, () => {
  const on = Object.entries(configured).filter(([, v]) => v).map(([k]) => k);
  console.log(`ExposureIQ API on http://localhost:${PORT}`);
  console.log(`  data mode: ${config.mode}${config.mode === 'live' ? ` (configured: ${on.join(', ') || 'none'})` : ' (built-in mock tenant)'}${restored ? ` · restored ${restored.findings} findings from ${restored.savedAt}` : ''}`);
  console.log(`  agents:    ${ai.enabled ? `Gemini ${ai.model}` : 'rules engine (set GEMINI_API_KEY to use Gemini)'}`);
  console.log(`  estate:    ${store.assets.length} assets, ${store.findings.length} unified findings`);
});
