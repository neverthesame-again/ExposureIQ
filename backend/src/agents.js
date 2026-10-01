// AI agents (simulated reasoning). Each agent has a goal, a fixed set of tools and guardrails, and
// every run is recorded as a trace: thought → tool call → observation → decision. In this POC the
// reasoning is scripted over the real store; in production each agent would be an LLM (Azure OpenAI)
// calling these same tools, with the same guardrails enforced outside the model.
import { COMPANIES } from './data/companies.js';
import { catalogById } from './data/catalog.js';
import { store } from './data/generator.js';
import { isOpen, kpis, r7NameFor, needsReview } from './analytics.js';

export const AGENTS = [
  {
    id: 'triage', name: 'Triage Agent', role: 'Decides what happens to every new urgent finding',
    goal: 'For each new P1/P2 or actively exploited finding, check real-world exploitability and business impact, then raise a ticket, escalate to the SOC, propose risk acceptance or monitor.',
    tools: ['get_asset', 'lookup_threat_intel', 'check_compensating_controls', 'search_tickets', 'create_ticket', 'update_ticket', 'notify_soc', 'propose_risk_acceptance'],
    autonomy: 'Raises tickets and escalates on its own; risk acceptance needs a human',
    trigger: 'Every new P1/P2 or KEV finding in the live feed',
  },
  {
    id: 'match', name: 'Asset-Match Agent', role: 'Resolves uncertain device matches between tools',
    goal: 'When Defender and Rapid7 report what may be the same device under different names, compare every identifier across CMDB, Defender and Rapid7 and merge or keep them apart.',
    tools: ['get_cmdb_record', 'get_defender_device', 'get_rapid7_asset', 'compare_identities', 'merge_assets', 'request_review'],
    autonomy: 'Merges on its own at 90% confidence or more; below that asks an analyst',
    trigger: 'Every CMDB sync, or on demand',
  },
  {
    id: 'planner', name: 'Remediation Planner', role: 'Turns open findings into patch campaigns',
    goal: 'Group open P1/P2 findings into one campaign per fix and owner team, fit each into the right change window, and draft the change requests.',
    tools: ['get_open_findings', 'get_change_calendar', 'group_by_fix', 'draft_change_requests', 'submit_to_servicenow'],
    autonomy: 'Drafts plans on its own; submitting to ServiceNow needs a human',
    trigger: 'Daily at 07:00 CET, or on demand',
  },
  {
    id: 'copilot', name: 'Analyst Copilot', role: 'Answers questions by querying the data itself',
    goal: 'Work out what a question needs, call the right ExposureIQ tools, and answer with numbers and sources.',
    tools: ['get_kpis', 'query_findings', 'get_top_risks', 'get_scorecard', 'get_remediation', 'get_reconciliation', 'get_assets', 'get_trend', 'get_vulnerability', 'get_change_calendar'],
    autonomy: 'Read-only: never changes data',
    trigger: 'When someone asks a question',
  },
];
export const MODEL = 'Simulated reasoning (Azure OpenAI in production)';

const coShort = Object.fromEntries(COMPANIES.map((c) => [c.id, c.short]));
const runs = [];
const approvals = [];
const stats = Object.fromEntries(AGENTS.map((a) => [a.id, { runs: 0, toolCalls: 0, autoActions: 0, proposals: 0, approved: 0, rejected: 0, lastRun: null }]));
let runSeq = 0;
let apprSeq = 0;

const hash = (s) => [...String(s)].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) >>> 0, 7);
const hex = (s, n) => hash(s).toString(16).padStart(8, '0').slice(0, n);
const pct = (x) => `${Math.round(x * 100)}%`;
const isUrgent = (f) => f.priority === 'P1' || f.priority === 'P2';

function trace() {
  const steps = [];
  return {
    steps,
    think: (text) => steps.push({ type: 'thought', text }),
    tool: (tool, args, result) => steps.push({ type: 'tool', tool, args, result }),
    decide: (text) => steps.push({ type: 'decision', text }),
  };
}

function record(agent, { title, subject, t, decision, auto = false, approval = null, extra = {} }) {
  const s = stats[agent];
  const run = {
    id: `R-${String(++runSeq).padStart(4, '0')}`, agent, at: new Date().toISOString(), title, subject,
    steps: t.steps, decision, status: approval ? 'awaiting' : 'done', approvalId: approval?.id || null,
    toolCalls: t.steps.filter((x) => x.type === 'tool').length, ...extra,
  };
  s.runs++;
  s.toolCalls += run.toolCalls;
  s.lastRun = run.at;
  if (auto) s.autoActions++;
  if (approval) { s.proposals++; approval.runId = run.id; approvals.unshift(approval); }
  runs.unshift(run);
  runs.length = Math.min(runs.length, 80);
  return run;
}

function openTicket(f, by = 'Triage Agent') {
  const t = { id: store.nextTicket(), cve: f.cve, company: f.company, createdAgo: 0, state: 'New', assignee: store.assetById[f.assetId].owner, createdBy: `${by} (AI)`, assets: 1 };
  store.tickets.push(t);
  return t;
}

// ---------------- Triage agent ----------------
const CONTROLS = {
  Workstation: 'Defender attack surface reduction rule blocks the exploit technique on this device',
  Server: 'Host firewall only allows the vulnerable service from the application subnet',
  'Cloud VM': 'Azure NSG limits inbound traffic to the load balancer',
  'Network Device': 'Management interface reachable only from the admin jump hosts',
  'OT / IoT': 'Device sits in an isolated OT segment with no route to the office network',
};

export function triage(f) {
  const a = store.assetById[f.assetId];
  const c = catalogById[f.cve];
  const t = trace();
  t.think(`New ${f.priority} finding: ${f.cve} (${c.title}) on ${a.hostname}. Before routing it I need the asset's business context, the threat picture and whether anything already mitigates it.`);
  t.tool('get_asset', { hostname: a.hostname }, `${a.type} · ${a.os} · ${a.criticality} asset (${a.service}) · ${a.internetFacing ? 'internet-facing' : 'internal only'} · owner: ${a.owner}`);
  t.tool('lookup_threat_intel', { cve: f.cve }, `CVSS ${c.cvss.toFixed(1)} · EPSS ${pct(c.epss)} · ${c.kev ? 'in CISA KEV, exploited in the wild' : 'not in CISA KEV'} · exploit: ${c.exploit}`);
  const control = !c.kev && !(a.internetFacing && a.type !== 'Workstation') && hash(f.id) % 100 < 40 ? CONTROLS[a.type] : null;
  t.tool('check_compensating_controls', { hostname: a.hostname, cve: f.cve }, control ? `Found: ${control}` : 'No compensating control found');
  const existing = store.tickets.find((x) => x.cve === f.cve && x.company === f.company && x.state !== 'Resolved');
  t.tool('search_tickets', { cve: f.cve, company: f.company }, existing ? `${existing.id} (${existing.state}) already tracks ${f.cve} at ${coShort[f.company]}` : `No open ticket for ${f.cve} at ${coShort[f.company]}`);

  let decision, ticket = null, approval = null, auto = true;
  if (c.kev && (a.internetFacing || a.tier === 1)) {
    t.think(`Actively exploited and ${a.internetFacing ? 'reachable from the internet' : `on a ${a.criticality} asset`}. This cannot wait in the normal queue: emergency ticket plus a SOC heads-up to hunt for exploitation.`);
    if (existing) t.tool('update_ticket', { id: existing.id, priority: 'Emergency' }, `${existing.id} raised to emergency, ${a.hostname} added`);
    else { ticket = openTicket(f); t.tool('create_ticket', { cve: f.cve, assignee: a.owner, priority: 'Emergency' }, `${ticket.id} created for ${a.owner}`); }
    t.tool('notify_soc', { severity: 'High', host: a.hostname }, 'SOC on-call paged; hunt query for exploitation attempts started');
    decision = { action: 'escalate', label: 'Escalated to SOC', confidence: 0.96 };
    t.decide(`Escalated: emergency fix tracked in ${existing ? existing.id : ticket.id}, SOC hunting for signs of exploitation.`);
  } else if (existing) {
    t.think('A ticket for this vulnerability already exists at this company. Adding the asset keeps one change per fix instead of a duplicate ticket.');
    t.tool('update_ticket', { id: existing.id, add_asset: a.hostname }, `${a.hostname} added to ${existing.id}`);
    existing.assets = (existing.assets || 1) + 1;
    decision = { action: 'merge', label: `Added to ${existing.id}`, confidence: 0.93 };
    t.decide(`Added to the existing ticket ${existing.id}; no duplicate work created.`);
  } else if (control && f.priority !== 'P1') {
    t.think(`A compensating control makes exploitation unlikely here (${control.toLowerCase()}). A ticket would add noise; I'll propose a 30-day risk acceptance, which policy says a person must approve.`);
    approval = { id: `A-${++apprSeq}`, agent: 'triage', kind: 'risk', findingId: f.id, title: `Accept risk for ${f.cve} on ${a.hostname} for 30 days`, reason: control, confidence: 0.81, status: 'pending', at: new Date().toISOString() };
    t.tool('propose_risk_acceptance', { finding: f.id, days: 30 }, `Proposal ${approval.id} sent to the approvals queue`);
    decision = { action: 'propose', label: 'Risk acceptance proposed', confidence: 0.81 };
    t.decide('Waiting for a person: risk acceptance proposed for 30 days with the control as justification.');
    auto = false;
  } else if (isUrgent(f)) {
    t.think(`No mitigation and no existing ticket. ${f.priority} means a ${f.slaDays}-day deadline, so the owner needs a ticket now.`);
    ticket = openTicket(f);
    t.tool('create_ticket', { cve: f.cve, assignee: a.owner, due_in_days: f.slaDays }, `${ticket.id} created for ${a.owner}`);
    decision = { action: 'ticket', label: `Ticket ${ticket.id}`, confidence: 0.94 };
    t.decide(`Ticket ${ticket.id} raised for ${a.owner}, due in ${f.slaDays} days.`);
  } else {
    t.think(`It is in KEV, but on a ${a.criticality.toLowerCase()} internal asset the unified score is only ${f.risk}. The ${f.priority} SLA (${f.slaDays} days) already covers it; a ticket now would jump the queue.`);
    decision = { action: 'monitor', label: `Monitor under ${f.priority} SLA`, confidence: 0.88 };
    t.decide(`Monitoring under the ${f.priority} SLA; I'll re-check if the asset's exposure changes.`);
  }
  f.triaged = true;
  const run = record('triage', { title: `${f.cve} on ${a.hostname}`, subject: { cve: f.cve, hostname: a.hostname, company: f.company, priority: f.priority, risk: f.risk }, t, decision, auto, approval });
  return { run, ticket };
}

// ---------------- Asset-match agent ----------------
export function runAssetMatch() {
  const a = store.assets.find((x) => needsReview(x) && !x.agentReviewed);
  if (!a) return null;
  const r7Name = r7NameFor(a);
  const h = hash(a.id);
  const sameMac = h % 100 < 60;
  const sameIp = a.matchConfidence >= 70;
  const renamed = r7Name.endsWith('-OLD');
  const mac = (s) => hex(s, 12).match(/../g).join(':').toUpperCase();
  const t = trace();
  t.think(`Defender's ${a.hostname} and Rapid7's "${r7Name}" were linked by a fuzzy hostname match at only ${a.matchConfidence}%. I'll compare every identifier the three systems hold before deciding.`);
  t.tool('get_cmdb_record', { name: a.hostname }, `CI ${a.hostname} · ${a.service} · ${a.site} · serial ${hex(a.id + 's', 8).toUpperCase()}`);
  t.tool('get_defender_device', { name: a.hostname }, `Entra ID ${hex(a.id + 'e', 8)}… · IP ${a.ip} · MAC ${mac(a.id)} · ${a.os}`);
  const r7Ip = sameIp ? a.ip : a.ip.replace(/\.\d+$/, `.${(h % 200) + 20}`);
  t.tool('get_rapid7_asset', { name: r7Name }, `IP ${r7Ip} · MAC ${sameMac ? mac(a.id) : mac(a.id + 'x')} · ${a.os} · last scanned ${(h % 9) + 1} days ago`);
  const conf = Math.min(99, 52 + (renamed ? 2 : 12) + (sameMac ? 22 : 0) + (sameIp ? 8 : 0) + 3);
  t.tool('compare_identities', { defender: a.hostname, rapid7: r7Name }, `Name: ${renamed ? 'same base name with "-OLD" suffix' : 'same after normalising case/domain/hyphens'} · MAC: ${sameMac ? 'identical' : 'different'} · IP: ${sameIp ? 'identical' : 'different (DHCP)'} · OS: identical → confidence ${conf}%`);
  let decision, approval = null, auto = false;
  if (conf >= 90) {
    t.think(`Same hardware address and a matching name: this is one device. ${conf}% is above my 90% threshold, so I can merge without asking.`);
    t.tool('merge_assets', { keep: a.hostname, alias: r7Name }, 'Merged: findings from both tools now attach to one asset');
    a.matchMethod = 'Agent-verified match';
    a.matchConfidence = conf;
    a.agentReviewed = 'auto';
    decision = { action: 'merge', label: `Merged at ${conf}%`, confidence: conf / 100 };
    t.decide(`Merged ${r7Name} into ${a.hostname}; removed from the analyst review queue.`);
    auto = true;
  } else {
    t.think(`${sameMac ? 'The MAC matches' : 'The MAC differs'}${renamed ? ' and the "-OLD" suffix suggests a re-imaged device' : ''}. ${conf}% is below my 90% threshold, so an analyst should decide.`);
    approval = { id: `A-${++apprSeq}`, agent: 'match', kind: 'match', assetId: a.id, title: `Confirm ${a.hostname} (Defender) = ${r7Name} (Rapid7)`, reason: `${sameMac ? 'Same MAC' : 'Different MAC'}, ${sameIp ? 'same IP' : 'IP changed'}${renamed ? ', renamed "-OLD"' : ''}`, confidence: conf / 100, status: 'pending', at: new Date().toISOString() };
    t.tool('request_review', { assets: [a.hostname, r7Name], confidence: conf }, `Review ${approval.id} sent to the approvals queue`);
    a.agentReviewed = 'pending';
    decision = { action: 'propose', label: `Needs review (${conf}%)`, confidence: conf / 100 };
    t.decide(`Asked an analyst to confirm: ${conf}% is not enough to merge on my own.`);
  }
  return record('match', { title: `${a.hostname} ↔ ${r7Name}`, subject: { hostname: a.hostname, company: a.company }, t, decision, auto, approval });
}

// ---------------- Remediation planner ----------------
const WINDOW = {
  Workstation: 'Wed 20:00 · workstation ring 1',
  Server: 'Thu 22:00–02:00 CET · server window',
  'Cloud VM': 'Thu 22:00–02:00 CET · server window',
  'Network Device': 'Sun 01:00 · network window',
  'OT / IoT': 'Next planned stop · OT change board',
};

export function runPlanner(company = 'all') {
  const open = store.findings.filter((f) => f.status === 'Open' && isUrgent(f) && (company === 'all' || f.company === company));
  const groups = new Map();
  for (const f of open) {
    const a = store.assetById[f.assetId];
    const key = `${a.owner}|${f.cve}`;
    const g = groups.get(key) || { team: a.owner, company: f.company, cve: f.cve, title: catalogById[f.cve].title, findings: [], weight: 0, p1: 0, type: a.type };
    g.findings.push(f);
    g.weight += (f.risk / 100) ** 3;
    if (f.priority === 'P1') g.p1++;
    groups.set(key, g);
  }
  const all = [...groups.values()].sort((x, y) => y.weight - x.weight);
  const total = all.reduce((s, g) => s + g.weight, 0) || 1;
  const top = all.slice(0, 6);
  const campaigns = top.map((g, i) => ({
    id: `C-${i + 1}`, team: g.team, companyName: coShort[g.company], cve: g.cve, title: g.title, assets: g.findings.length,
    window: g.p1 ? 'Emergency CAB · within 48 h' : WINDOW[g.type], priority: g.p1 ? 'P1' : 'P2',
  }));
  const share = top.reduce((s, g) => s + g.weight, 0) / total;
  const t = trace();
  t.think(`Goal: turn ${company === 'all' ? 'the group\'s' : `${coShort[company]}'s`} open urgent findings into as few changes as possible, so each owner team patches once per fix in its normal window.`);
  t.tool('get_open_findings', { priority: ['P1', 'P2'], company }, `${open.length} open P1/P2 findings across ${new Set(open.map((f) => store.assetById[f.assetId].owner)).size} owner teams`);
  t.tool('get_change_calendar', { next_days: 14 }, 'Wed 20:00 workstations · Thu 22:00 servers · Sun 01:00 network · emergency CAB daily 09:00');
  t.tool('group_by_fix', { by: ['owner_team', 'cve'] }, `${all.length} distinct (team, fix) pairs; the top ${top.length} hold ${pct(share)} of urgent risk`);
  t.think(`Planning the top ${top.length}: anything with a P1 goes to the emergency CAB, the rest into each team's next standard window.`);
  t.tool('draft_change_requests', { campaigns: top.length }, `${top.length} change requests drafted, each with the asset list, fix steps and rollback plan`);
  const approval = { id: `A-${++apprSeq}`, agent: 'planner', kind: 'plan', company, campaigns, title: `Submit ${top.length} patch campaigns to ServiceNow`, reason: `Covers ${top.reduce((s, g) => s + g.findings.length, 0)} findings, ${pct(share)} of urgent risk`, confidence: 0.9, status: 'pending', at: new Date().toISOString() };
  t.decide(`Plan ready: ${top.length} campaigns covering ${pct(share)} of urgent risk. Waiting for approval before submitting to ServiceNow.`);
  return record('planner', { title: `Patch plan · ${company === 'all' ? 'SHV Group' : coShort[company]}`, subject: { company }, t, decision: { action: 'propose', label: `${top.length} campaigns drafted`, confidence: 0.9 }, approval, extra: { plan: campaigns } });
}

// ---------------- Analyst copilot ----------------
export function copilotRun(question, company, res) {
  const k = kpis(company);
  const scope = company && company !== 'all' ? coShort[company] : 'SHV Group';
  const t = trace();
  const cve = res.link?.cve;
  const T = {
    executive: [['get_kpis', { scope }, `exposure ${k.exposureScore}/100, ${k.openP1 + k.openP2} open P1/P2, SLA ${k.slaCompliance}%`], ['get_trend', { weeks: 13 }, `exposure ${k.exposureScorePrev} → ${k.exposureScore} over 4 weeks`], ['get_top_risks', { n: 3 }, '3 vulnerabilities ranked by risk contribution']],
    kev: [['query_findings', { kev: true, status: 'open', scope }, `${k.kevOpen} open actively-exploited instances`], ['get_scorecard', {}, 'KEV exposure per company']],
    plan: [['get_open_findings', { priority: ['P1', 'P2'], scope }, `${k.openP1 + k.openP2} open urgent findings`], ['get_change_calendar', { next_days: 7 }, 'next standard and emergency windows'], ['get_top_risks', { n: 5 }, 'fixes ranked by risk removed']],
    sla: [['get_remediation', { scope }, `${k.breached} findings past SLA · compliance ${k.slaCompliance}%`]],
    compare: [['get_scorecard', {}, `${COMPANIES.length} companies scored on one model`]],
    duplication: [['get_reconciliation', { scope }, `${k.rawFindings} raw records → ${k.unifiedFindings} unique findings`]],
    coverage: [['get_assets', { coverage: 'none', scope }, `${k.coverage.none} assets with no scanner · coverage ${k.coverage.pct}%`]],
    internet: [['query_findings', { internet_facing: true, status: 'open', scope }, 'open findings on internet-facing assets']],
    trend: [['get_trend', { weeks: 13, scope }, `MTTR ${k.mttr} d (was ${k.mttrPrev} d)`]],
    score: [['get_scoring_model', {}, '5 factors: severity 50, exploitation 20, EPSS 8, criticality 15, exposure 10']],
    company: [['get_kpis', { scope: res.scope }, 'company KPIs'], ['get_scorecard', {}, 'peer comparison']],
    cve: [['get_vulnerability', { id: cve }, `${store.findings.filter((f) => f.cve === cve && isOpen(f)).length} open instances`], ['lookup_threat_intel', { cve }, 'CVSS, EPSS, KEV status, fix']],
  }[res.intent] || [];
  t.think(T.length ? `The question is about ${res.intent === 'cve' ? cve : res.intent} for ${res.scope}. I'll fetch only the data that answers it.` : 'The question does not match anything I can look up; I will suggest questions I can answer.');
  for (const [tool, args, result] of T) t.tool(tool, args, result);
  if (T.length) t.think('Writing the answer from these results only, citing each source. Raw host data never goes to the model.');
  t.decide(`Answered with ${res.blocks.length} part${res.blocks.length === 1 ? '' : 's'}${res.citations?.length ? ` and ${res.citations.length} sources` : ''}.`);
  return record('copilot', { title: question.length > 60 ? `${question.slice(0, 57)}…` : question, subject: { company }, t, decision: { action: 'answer', label: 'Answered', confidence: 0.9 } });
}

// ---------------- Approvals ----------------
export function decide(id, verdict) {
  const ap = approvals.find((x) => x.id === id);
  if (!ap || ap.status !== 'pending') return null;
  const ok = verdict === 'approve';
  ap.status = ok ? 'approved' : 'rejected';
  ap.decidedAt = new Date().toISOString();
  stats[ap.agent][ok ? 'approved' : 'rejected']++;
  const run = runs.find((r) => r.id === ap.runId);
  if (run) run.status = ap.status;
  let outcome = ok ? 'Approved' : 'Rejected — nothing changed';
  if (ap.kind === 'risk') {
    const f = store.findings.find((x) => x.id === ap.findingId);
    if (ok && f && f.status === 'Open') { f.status = 'Risk Accepted'; f.sla = 'Exception'; outcome = `${f.cve} accepted for 30 days`; }
  } else if (ap.kind === 'match') {
    const a = store.assetById[ap.assetId];
    if (ok) { a.matchMethod = 'Agent-verified match'; a.matchConfidence = Math.round(ap.confidence * 100); a.agentReviewed = 'approved'; outcome = `${a.hostname} merged`; }
    else { a.agentReviewed = 'rejected'; outcome = `${a.hostname} kept as separate devices`; }
  } else if (ap.kind === 'plan' && ok) {
    let created = 0;
    for (const c of ap.campaigns) {
      const f = store.findings.find((x) => x.cve === c.cve && store.assetById[x.assetId].owner === c.team && x.status === 'Open');
      if (f && !store.tickets.some((x) => x.cve === f.cve && x.company === f.company && x.state !== 'Resolved')) { openTicket(f, 'Remediation Planner'); created++; }
    }
    outcome = `${ap.campaigns.length} campaigns submitted · ${created} new ServiceNow changes`;
  }
  ap.outcome = outcome;
  return ap;
}

export function agentsView() {
  const now = Date.now();
  return {
    model: MODEL,
    agents: AGENTS.map((a) => ({ ...a, stats: stats[a.id], pending: approvals.filter((x) => x.agent === a.id && x.status === 'pending').length, working: !!stats[a.id].lastRun && now - new Date(stats[a.id].lastRun).getTime() < 7000 })),
    approvals: approvals.filter((x) => x.status === 'pending').concat(approvals.filter((x) => x.status !== 'pending').slice(0, 8)),
    runs,
    totals: {
      runs: Object.values(stats).reduce((s, x) => s + x.runs, 0),
      toolCalls: Object.values(stats).reduce((s, x) => s + x.toolCalls, 0),
      autoActions: Object.values(stats).reduce((s, x) => s + x.autoActions, 0),
      pending: approvals.filter((x) => x.status === 'pending').length,
      overrides: Object.values(stats).reduce((s, x) => s + x.rejected, 0),
    },
  };
}

export const pendingApprovals = () => approvals.filter((x) => x.status === 'pending').length;

export function attachAgents(app) {
  app.get('/api/agents', (_req, res) => res.json(agentsView()));
  app.get('/api/agents/runs/:id', (req, res) => {
    const r = runs.find((x) => x.id === req.params.id);
    return r ? res.json(r) : res.status(404).json({ error: 'Unknown run' });
  });
  app.post('/api/agents/:id/run', (req, res) => {
    const id = req.params.id;
    let run = null;
    if (id === 'triage') {
      const f = store.findings.filter((x) => x.status === 'Open' && isUrgent(x) && !x.triaged).sort((x, y) => y.risk - x.risk)[0];
      if (f) run = triage(f).run;
    } else if (id === 'match') run = runAssetMatch();
    else if (id === 'planner') run = runPlanner(req.body?.company || 'all');
    if (!run) return res.json({ run: null, message: 'Nothing for this agent to do right now' });
    res.json({ run });
  });
  app.post('/api/approvals/:id', (req, res) => {
    const ap = decide(req.params.id, req.body?.decision);
    return ap ? res.json(ap) : res.status(400).json({ error: 'Unknown or already decided' });
  });
  // The planner's daily run, so the approvals queue has something in it from the start.
  runPlanner('all');
}
