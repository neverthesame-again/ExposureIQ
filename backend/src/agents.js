// The four ExposureIQ agents. Each one runs on Gemini (function calling) when GEMINI_API_KEY is set,
// and on a deterministic rules engine otherwise (or when the per-minute budget is used up, or Gemini
// fails). Either way:
//   - the agent may only use its own tools,
//   - actions are executed by this file after guardrail checks, never by the model directly,
//   - anything that accepts risk, merges uncertain data or changes ServiceNow in bulk needs a person,
//   - every step is recorded as a trace the UI shows live.
import { COMPANIES } from './data/companies.js';
import { catalogById } from './data/catalog.js';
import { store } from './data/generator.js';
import { isOpen, needsReview } from './analytics.js';
import { copilot as templateCopilot } from './insights.js';
import { ai, runAgent, tryAcquireBackgroundRun, acquireInteractiveRun, runsThisMinute, coolingDownFor, quotaView, headroom } from './ai/gemini.js';
import { config } from './config.js';
import * as T from './agents/tools.js';

const coShort = T.coShort;
const COMPANY_IDS = COMPANIES.map((c) => c.id);

export const AGENTS = [
  {
    id: 'triage', name: 'Triage Agent', role: 'Decides what happens to every new urgent finding',
    goal: 'For each new P1/P2 or actively exploited finding, investigate the asset, threat intel, compensating controls and open tickets, then raise a ticket, add to an existing one, escalate to the SOC, propose risk acceptance or monitor.',
    tools: ['get_asset', 'lookup_threat_intel', 'check_compensating_controls', 'search_tickets', 'submit_triage'],
    autonomy: 'Raises tickets and escalates on its own; risk acceptance needs a human',
    trigger: 'Every new P1/P2 or KEV finding, and findings whose priority rises',
  },
  {
    id: 'match', name: 'Asset-Match Agent', role: 'Resolves uncertain device matches between tools',
    goal: 'When Defender and Rapid7 may be reporting the same device under different names, pull the device records from ServiceNow, Defender and Rapid7, compare every identifier and decide: merge, keep separate, or ask an analyst.',
    tools: ['get_cmdb_record', 'get_defender_device', 'get_rapid7_asset', 'compare_identities', 'submit_match'],
    autonomy: 'Merges on its own only at ≥ 90% confidence with an identical MAC; otherwise asks an analyst',
    trigger: 'Every CMDB sync, or on demand',
  },
  {
    id: 'planner', name: 'Remediation Planner', role: 'Turns open findings into patch campaigns',
    goal: 'Group open P1/P2 findings into one campaign per fix and owner team, pick the right change window for each, and propose the plan.',
    tools: ['get_open_findings', 'get_change_calendar', 'submit_plan'],
    autonomy: 'Drafts plans on its own; submitting to ServiceNow needs a human',
    trigger: 'Once at start-up, then on demand',
  },
  {
    id: 'copilot', name: 'Analyst Copilot', role: 'Answers questions by querying the data itself',
    goal: 'Work out what a question needs, call the right ExposureIQ tools, and answer with numbers from the data.',
    tools: Object.keys(T.READ),
    autonomy: 'Read-only: never changes data',
    trigger: 'When someone asks a question',
  },
];

const runs = [];
const approvals = [];
const stats = Object.fromEntries(AGENTS.map((a) => [a.id, { runs: 0, toolCalls: 0, autoActions: 0, proposals: 0, approved: 0, rejected: 0, lastRun: null, llmRuns: 0, rulesRuns: 0 }]));
let runSeq = 0;
let apprSeq = 0;
const listeners = new Set();
export const onRunFinished = (fn) => listeners.add(fn);

// ---------------- engine choice ----------------
// Synchronous on purpose: a run is registered the moment an agent starts, so the UI can follow it.
//   background: work the live feed started; it only gets Gemini when there is spare capacity
//   lowValue:   low-priority work that the rules engine handles well; Gemini is kept for urgent findings
// Synchronous on purpose: a run is registered the moment an agent starts, so the UI can follow it.
function engineFor({ background = false, lowValue = false } = {}) {
  if (!ai.enabled) return { llm: false, note: 'Rules engine (no GEMINI_API_KEY configured)' };
  if (!background) return { llm: true }; // people's requests go through engineForPerson
  if (lowValue) return { llm: false, note: 'Rules engine (low-priority finding; Gemini kept for urgent work)' };
  return tryAcquireBackgroundRun() ? { llm: true } : { llm: false, note: 'Rules engine (Gemini capacity kept free for your questions)' };
}
// A person is waiting: wait for Gemini capacity rather than falling back.
async function engineForPerson() {
  if (!ai.enabled) return { llm: false, note: 'Rules engine (no GEMINI_API_KEY configured)' };
  return (await acquireInteractiveRun(60000)) ? { llm: true } : { llm: false, note: `Rules engine (Gemini quota exhausted for ${coolingDownFor()}s)` };
}

function startRun(agent, { title, subject, engine }) {
  const run = {
    id: `R-${String(++runSeq).padStart(4, '0')}`, agent, at: new Date().toISOString(), title, subject,
    steps: [], decision: null, status: 'running', approvalId: null, toolCalls: 0,
    engine: engine.llm ? ai.model : 'rules', engineNote: engine.note || null,
  };
  runs.unshift(run);
  runs.length = Math.min(runs.length, 120);
  return run;
}

function finishRun(run, { decision, approval = null, auto = false, extra = {} }) {
  const s = stats[run.agent];
  Object.assign(run, extra, { decision, status: approval ? 'awaiting' : 'done', approvalId: approval?.id || null, toolCalls: run.steps.filter((x) => x.type === 'tool').length, finishedAt: new Date().toISOString() });
  s.runs++;
  s.toolCalls += run.toolCalls;
  s.lastRun = run.at;
  s[run.engine === 'rules' ? 'rulesRuns' : 'llmRuns']++;
  if (auto) s.autoActions++;
  if (approval) { s.proposals++; approval.runId = run.id; approvals.unshift(approval); }
  for (const fn of listeners) fn(run);
  return run;
}

function failRun(run, e) {
  run.steps.push({ type: 'guardrail', text: `Stopped: ${e.message}` });
  return finishRun(run, { decision: { action: 'error', label: 'Failed', confidence: 0 } });
}

const step = (run) => ({
  think: (text) => run.steps.push({ type: 'thought', text }),
  tool: (tool, args, result) => run.steps.push({ type: 'tool', tool, args, result: typeof result === 'string' ? result : result?.summary || result?.error || '' }),
  guard: (text) => run.steps.push({ type: 'guardrail', text }),
  decide: (text) => run.steps.push({ type: 'decision', text }),
});

const S = (props, required = Object.keys(props)) => ({ type: 'OBJECT', properties: props, required });
const str = (description, extra = {}) => ({ type: 'STRING', description, ...extra });
const companyParam = str(`Company id, or "all" for the whole group. One of: all, ${COMPANY_IDS.join(', ')}`);

// =====================================================================================
// Triage agent
// =====================================================================================
const TRIAGE_ACTIONS = ['escalate', 'ticket', 'add_to_ticket', 'propose_risk_acceptance', 'monitor'];
const TRIAGE_SYSTEM = `You are the Triage Agent in ExposureIQ, the vulnerability-management platform for SHV Group (group companies: ${COMPANIES.map((c) => c.short).join(', ')}).
A new urgent or actively exploited finding has arrived. Investigate it with your tools, then decide exactly one action and call submit_triage.

Actions:
- escalate: actively exploited (in CISA KEV) and the asset is internet-facing or Crown Jewel, or the finding is P1. Opens an emergency ticket and pages the SOC.
- ticket: the owner team must fix it within the SLA and no ticket exists yet.
- add_to_ticket: an open ticket already tracks this vulnerability at this company.
- propose_risk_acceptance: a registered compensating control makes exploitation unlikely. Never for P1 or KEV findings. A person must approve it.
- monitor: low business impact and the SLA already covers it. Never for P1 or P2.

Always check the asset, the threat intel, compensating controls and existing tickets before deciding.
Think briefly. Base the rationale only on facts the tools returned, in two sentences at most. Confidence is between 0 and 1.`;

function triageTools() {
  const id = S({ asset_id: str('ExposureIQ asset id') });
  return {
    get_asset: { description: 'Business context of an asset: type, OS, service, criticality tier, internet exposure, owner team, which tools see it.', parameters: id, run: T.getAsset },
    lookup_threat_intel: { description: 'CVSS, EPSS, CISA KEV status, exploit maturity, vendor fix, and how many open instances exist in the estate.', parameters: S({ cve: str('Vulnerability id, e.g. CVE-2024-3400') }), run: T.threatIntel },
    check_compensating_controls: { description: 'Compensating controls registered against the asset in the ServiceNow CMDB.', parameters: id, run: T.compensatingControls },
    search_tickets: { description: 'Open ServiceNow tickets for a vulnerability at a company.', parameters: S({ cve: str('Vulnerability id'), company: str('Company id') }), run: T.searchTickets },
    submit_triage: {
      description: 'Submit your decision. Ends the run.',
      parameters: S({ action: str('The action', { enum: TRIAGE_ACTIONS }), rationale: str('Why, in at most two sentences'), confidence: { type: 'NUMBER', description: '0 to 1' } }),
    },
  };
}

// The policy, enforced in code whatever the model decided.
function triagePolicy(f, action) {
  const a = store.assetById[f.assetId];
  const c = catalogById[f.cve];
  const urgent = f.priority === 'P1' || f.priority === 'P2';
  const open = store.tickets.find((x) => x.cve === f.cve && x.company === f.company && x.state !== 'Resolved');
  const mustEscalate = f.priority === 'P1' || (c.kev && (a.internetFacing || a.tier === 1));
  let final = TRIAGE_ACTIONS.includes(action) ? action : urgent ? 'ticket' : 'monitor';
  const notes = [];
  if (final === 'escalate' && !mustEscalate && !c.kev) { final = open ? 'add_to_ticket' : 'ticket'; notes.push('escalation is reserved for P1 or actively exploited findings'); }
  if (final === 'propose_risk_acceptance' && (f.priority === 'P1' || c.kev)) { final = mustEscalate ? 'escalate' : open ? 'add_to_ticket' : 'ticket'; notes.push('risk acceptance is not allowed for P1 or KEV findings'); }
  if (final === 'propose_risk_acceptance' && !a.controls) { final = urgent ? (open ? 'add_to_ticket' : 'ticket') : 'monitor'; notes.push('no compensating control is registered in the CMDB'); }
  if (final === 'monitor' && urgent) { final = open ? 'add_to_ticket' : 'ticket'; notes.push('P1/P2 findings cannot be left to monitoring'); }
  if (final === 'ticket' && open) { final = 'add_to_ticket'; notes.push(`${open.id} already tracks it`); }
  if (final === 'add_to_ticket' && !open) { final = 'ticket'; notes.push('there is no open ticket to add to'); }
  if (mustEscalate && final !== 'escalate' && f.priority === 'P1') { final = 'escalate'; notes.push('P1 findings are always escalated'); }
  return { action: final, notes, open };
}

function rulesTriage(f, run) {
  const a = store.assetById[f.assetId];
  const c = catalogById[f.cve];
  const s = step(run);
  s.think(`New ${f.priority} finding: ${f.cve} on ${a.hostname}. Checking business context, threat intel, controls and tickets.`);
  s.tool('get_asset', { asset_id: a.id }, T.getAsset({ asset_id: a.id }));
  s.tool('lookup_threat_intel', { cve: f.cve }, T.threatIntel({ cve: f.cve }));
  s.tool('check_compensating_controls', { asset_id: a.id }, T.compensatingControls({ asset_id: a.id }));
  s.tool('search_tickets', { cve: f.cve, company: f.company }, T.searchTickets({ cve: f.cve, company: f.company }));
  const urgent = f.priority === 'P1' || f.priority === 'P2';
  const action = f.priority === 'P1' || (c.kev && (a.internetFacing || a.tier === 1)) ? 'escalate'
    : a.controls && !c.kev && f.priority !== 'P1' ? 'propose_risk_acceptance'
      : urgent ? 'ticket' : 'monitor';
  return { action, rationale: { escalate: 'Actively exploited or P1 on an exposed or crown-jewel asset.', propose_risk_acceptance: `Registered control: ${a.controls}.`, ticket: `No mitigation; ${f.priority} needs a fix within ${f.slaDays} days.`, monitor: `Low business impact; the ${f.priority} SLA covers it.` }[action], confidence: 0.85 };
}

export async function triage(f, { interactive = false } = {}) {
  if (!f || f.triaged || !isOpen(f)) return null;
  f.triaged = true;
  const a = store.assetById[f.assetId];
  const engine = engineFor({ background: !interactive, lowValue: f.priority === 'P3' || f.priority === 'P4' });
  const run = startRun('triage', { title: `${f.cve} on ${a.hostname}`, subject: { cve: f.cve, hostname: a.hostname, company: f.company, priority: f.priority, risk: f.risk, findingId: f.id }, engine });
  f.triageRunId = run.id;
  if (interactive && engine.llm && !(await acquireInteractiveRun(60000))) { engine.llm = false; run.engine = 'rules'; run.engineNote = 'Rules engine (Gemini quota exhausted)'; }
  try {
    let decision;
    if (engine.llm) {
      try {
        const res = await runAgent({
          system: TRIAGE_SYSTEM,
          prompt: `New finding ${f.id}: ${f.cve} on asset_id "${a.id}" (${a.hostname}) at company "${f.company}". Priority ${f.priority}, unified risk ${f.risk}/100, SLA ${f.slaDays} days. Reported by: ${f.sources.join(' and ')}.`,
          tools: triageTools(), finalTool: 'submit_triage', trace: run.steps, onModel: (m) => { run.engine = m; },
        });
        decision = res.final;
      } catch (e) {
        run.steps.push({ type: 'guardrail', text: `Gemini unavailable (${e.message}); finishing with the rules engine.` });
        run.engine = 'rules';
        decision = rulesTriage(f, run);
      }
    } else decision = rulesTriage(f, run);
    return await applyTriage(f, decision, run);
  } catch (e) {
    failRun(run, e);
    return { run, ticket: null };
  }
}

async function applyTriage(f, decision, run) {
  const s = step(run);
  const a = store.assetById[f.assetId];
  const { action, notes, open } = triagePolicy(f, decision.action);
  if (action !== decision.action) s.guard(`Policy changed "${decision.action}" to "${action}": ${notes.join('; ')}.`);
  const conf = Math.max(0, Math.min(1, Number(decision.confidence) || 0.8));
  let ticket = null;
  let approval = null;
  let label;
  if (action === 'escalate') {
    if (open) { open.priority = 'Emergency'; open.assets = (open.assets || 1) + 1; s.tool('update_ticket', { id: open.id, priority: 'Emergency' }, `${open.id} raised to emergency, ${a.hostname} added`); }
    else { ticket = await T.createTicket(f, { priority: 'Emergency', note: decision.rationale }); s.tool('create_ticket', { cve: f.cve, assignee: a.owner, priority: 'Emergency' }, `${ticket.id} created for ${a.owner}`); }
    const n = await T.notifySoc(`ExposureIQ: ${f.cve} (${catalogById[f.cve].title}) on ${a.hostname} [${coShort[f.company]}] needs urgent attention. ${decision.rationale}`);
    s.tool('notify_soc', { host: a.hostname, severity: 'High' }, `SOC notified (${n.delivered})`);
    label = 'Escalated to SOC';
  } else if (action === 'add_to_ticket') {
    open.assets = (open.assets || 1) + 1;
    s.tool('update_ticket', { id: open.id, add_asset: a.hostname }, `${a.hostname} added to ${open.id}`);
    label = `Added to ${open.id}`;
  } else if (action === 'ticket') {
    ticket = await T.createTicket(f, { note: decision.rationale });
    s.tool('create_ticket', { cve: f.cve, assignee: a.owner, due_in_days: f.slaDays }, `${ticket.id} created for ${a.owner}`);
    label = `Ticket ${ticket.id}`;
  } else if (action === 'propose_risk_acceptance') {
    approval = { id: `A-${++apprSeq}`, agent: 'triage', kind: 'risk', findingId: f.id, title: `Accept risk for ${f.cve} on ${a.hostname} for 30 days`, reason: a.controls, confidence: conf, status: 'pending', at: new Date().toISOString() };
    s.tool('propose_risk_acceptance', { finding: f.id, days: 30 }, `Proposal ${approval.id} sent to the approvals queue`);
    label = 'Risk acceptance proposed';
  } else label = `Monitor under ${f.priority} SLA`;
  s.decide(`${label}. ${decision.rationale || ''}`.trim());
  finishRun(run, { decision: { action, label, confidence: conf }, approval, auto: !approval });
  return { run, ticket };
}

// =====================================================================================
// Asset-match agent
// =====================================================================================
const MATCH_SYSTEM = `You are the Asset-Match Agent in ExposureIQ. Microsoft Defender and Rapid7 sometimes report the same physical device under different names, which splits its vulnerabilities across two records.
Pull the device records from the ServiceNow CMDB, Defender and Rapid7, compare them, and call submit_match with one decision:
- merge: the same device.
- separate: two different devices.
- needs_review: the evidence is not strong enough either way.
Strong evidence: identical MAC address, Entra device ID, serial number. Weak evidence: a similar hostname, or the same IP (DHCP re-assigns IPs). A "-OLD" suffix often means a re-imaged device that kept its name.
Confidence is 0 to 100. Keep the rationale to two sentences.`;

function matchTools() {
  const id = S({ asset_id: str('ExposureIQ asset id') });
  return {
    get_cmdb_record: { description: 'The ServiceNow CMDB record for the asset.', parameters: id, run: T.cmdbRecord },
    get_defender_device: { description: 'The device as Microsoft Defender for Endpoint reports it.', parameters: id, run: T.defenderDevice },
    get_rapid7_asset: { description: 'The asset as Rapid7 InsightVM reports it.', parameters: id, run: T.rapid7Asset },
    compare_identities: { description: 'Side-by-side comparison of hostname, MAC, IP and OS across the three systems.', parameters: id, run: T.compareIdentities },
    submit_match: { description: 'Submit your decision. Ends the run.', parameters: S({ decision: str('The decision', { enum: ['merge', 'separate', 'needs_review'] }), confidence: { type: 'NUMBER', description: '0 to 100' }, rationale: str('Why, in at most two sentences') }) },
  };
}

async function rulesMatch(a, run) {
  const s = step(run);
  s.think(`${a.hostname} was linked to a Rapid7 record by a fuzzy hostname match (${a.matchConfidence}%). Comparing identifiers across the three systems.`);
  s.tool('get_cmdb_record', { asset_id: a.id }, await T.cmdbRecord({ asset_id: a.id }));
  s.tool('get_defender_device', { asset_id: a.id }, await T.defenderDevice({ asset_id: a.id }));
  s.tool('get_rapid7_asset', { asset_id: a.id }, await T.rapid7Asset({ asset_id: a.id }));
  const cmp = await T.compareIdentities({ asset_id: a.id });
  s.tool('compare_identities', { asset_id: a.id }, cmp);
  const conf = Math.min(99, 52 + (cmp.hostname.startsWith('same base') ? 2 : cmp.hostname === 'different' ? 0 : 12) + (cmp.mac === 'identical' ? 22 : 0) + (cmp.ip === 'identical' ? 8 : 0) + 3);
  return { decision: conf >= 90 ? 'merge' : 'needs_review', confidence: conf, rationale: `${cmp.mac === 'identical' ? 'Identical MAC' : 'MAC differs'}, IP ${cmp.ip}, hostname ${cmp.hostname}.` };
}

export async function runAssetMatch(assetId, { interactive = false } = {}) {
  const a = assetId ? store.assetById[assetId] : store.assets.find((x) => needsReview(x) && !x.agentReviewed);
  if (!a || !a.mde || !a.r7) return null;
  a.agentReviewed = 'running';
  const engine = engineFor({ background: !interactive });
  const run = startRun('match', { title: `${a.hostname}: Defender ↔ Rapid7`, subject: { hostname: a.hostname, company: a.company, assetId: a.id }, engine });
  a.matchRunId = run.id;
  if (interactive && engine.llm && !(await acquireInteractiveRun(60000))) { engine.llm = false; run.engine = 'rules'; run.engineNote = 'Rules engine (Gemini quota exhausted)'; }
  try {
    let d;
    if (engine.llm) {
      try {
        const res = await runAgent({ system: MATCH_SYSTEM, prompt: `Asset ${a.id} (${a.hostname}, ${coShort[a.company]}) was linked between Defender and Rapid7 by a fuzzy hostname match at ${a.matchConfidence}%. Decide whether they are the same device.`, tools: matchTools(), finalTool: 'submit_match', trace: run.steps, onModel: (m) => { run.engine = m; } });
        d = res.final;
      } catch (e) {
        run.steps.push({ type: 'guardrail', text: `Gemini unavailable (${e.message}); finishing with the rules engine.` });
        run.engine = 'rules';
        d = await rulesMatch(a, run);
      }
    } else d = await rulesMatch(a, run);

    const s = step(run);
    const conf = Math.round(Math.max(0, Math.min(100, Number(d.confidence) || 0)));
    const cmp = await T.compareIdentities({ asset_id: a.id });
    let approval = null;
    let label;
    let auto = false;
    if (d.decision === 'merge' && conf >= 90 && cmp.mac === 'identical') {
      a.matchMethod = 'Agent-verified match'; a.matchConfidence = conf; a.agentReviewed = 'auto';
      s.tool('merge_assets', { asset_id: a.id }, 'Merged: findings from both tools now attach to one asset');
      label = `Merged at ${conf}%`; auto = true;
    } else if (d.decision === 'separate' && conf >= 90) {
      a.agentReviewed = 'separate';
      s.tool('keep_separate', { asset_id: a.id }, 'Marked as two different devices');
      label = `Kept separate (${conf}%)`; auto = true;
    } else {
      if (d.decision === 'merge') s.guard(`Merge needs ≥ 90% confidence and an identical MAC (got ${conf}%, MAC ${cmp.mac}); asking an analyst instead.`);
      approval = { id: `A-${++apprSeq}`, agent: 'match', kind: 'match', assetId: a.id, title: `Confirm ${a.hostname} in Defender and Rapid7 is one device`, reason: d.rationale || cmp.summary, confidence: conf / 100, status: 'pending', at: new Date().toISOString() };
      s.tool('request_review', { asset_id: a.id, confidence: conf }, `Review ${approval.id} sent to the approvals queue`);
      a.agentReviewed = 'pending';
      label = `Needs review (${conf}%)`;
    }
    s.decide(`${label}. ${d.rationale || ''}`.trim());
    return finishRun(run, { decision: { action: d.decision, label, confidence: conf / 100 }, approval, auto });
  } catch (e) {
    a.agentReviewed = null;
    return failRun(run, e);
  }
}

// =====================================================================================
// Remediation planner
// =====================================================================================
const PLAN_SYSTEM = `You are the Remediation Planner in ExposureIQ. Turn open P1/P2 findings into patch campaigns so each owner team patches once per fix, in the right change window.
Get the open findings and the change calendar, then call submit_plan with at most 6 campaigns, highest share of urgent risk first.
Each campaign is one (owner team, vulnerability) group from get_open_findings. Use window "emergency-cab" for groups with P1 findings or actively exploited (KEV) issues on exposed assets; otherwise the team's normal window for its asset type.
Give each campaign a one-sentence rationale and the plan a one-sentence summary.`;

function planTools() {
  return {
    get_open_findings: { description: 'Open P1/P2 findings grouped by (owner team, vulnerability), with counts, P1s, KEV, asset types and share of urgent risk.', parameters: S({ company: companyParam }), run: (x) => T.openFindingsSummary({ company: x.company === 'all' ? null : x.company }) },
    get_change_calendar: { description: 'The change windows available in the next 14 days.', parameters: S({}, []), run: T.changeCalendar },
    submit_plan: {
      description: 'Submit the plan for human approval. Ends the run.',
      parameters: S({
        summary: str('One sentence'),
        campaigns: { type: 'ARRAY', items: S({ team: str('Owner team, exactly as returned'), cve: str('Vulnerability id'), window_id: str('Change window id', { enum: T.CHANGE_WINDOWS.map((w) => w.id) }), rationale: str('One sentence') }) },
      }),
    },
  };
}

function rulesPlan(company, run) {
  const s = step(run);
  s.think('Grouping open urgent findings by owner team and fix, then fitting each group into its change window.');
  const sum = T.openFindingsSummary({ company: company === 'all' ? null : company, limit: 6 });
  s.tool('get_open_findings', { company }, sum);
  s.tool('get_change_calendar', {}, T.changeCalendar());
  const windowFor = (g) => (g.p1 || (g.kev && g.asset_types.includes('Network Device')) ? 'emergency-cab' : g.asset_types.includes('Network Device') ? 'net-sun' : g.asset_types.includes('OT / IoT') ? 'ot-board' : g.asset_types.includes('Workstation') && g.asset_types.length === 1 ? 'ws-ring1' : 'srv-thu');
  return { summary: `${sum.groups.length} campaigns covering the largest share of urgent risk.`, campaigns: sum.groups.map((g) => ({ team: g.team, cve: g.cve, window_id: windowFor(g), rationale: `${g.findings} findings, ${g.share_of_urgent_risk} of urgent risk.` })) };
}

export async function runPlanner(company = 'all', { interactive = false } = {}) {
  const engine = engineFor({ background: !interactive });
  const run = startRun('planner', { title: `Patch plan · ${company === 'all' ? 'SHV Group' : coShort[company]}`, subject: { company }, engine });
  if (interactive && engine.llm && !(await acquireInteractiveRun(60000))) { engine.llm = false; run.engine = 'rules'; run.engineNote = 'Rules engine (Gemini quota exhausted)'; }
  try {
    let plan;
    if (engine.llm) {
      try {
        plan = (await runAgent({ system: PLAN_SYSTEM, prompt: `Plan this week's patch campaigns for company "${company}".`, tools: planTools(), finalTool: 'submit_plan', trace: run.steps, onModel: (m) => { run.engine = m; } })).final;
      } catch (e) {
        run.steps.push({ type: 'guardrail', text: `Gemini unavailable (${e.message}); finishing with the rules engine.` });
        run.engine = 'rules';
        plan = rulesPlan(company, run);
      }
    } else plan = rulesPlan(company, run);

    // Validate every campaign against the data before a person sees it.
    const s = step(run);
    const groups = T.openFindingsSummary({ company: company === 'all' ? null : company, limit: 200 }).groups;
    const windows = Object.fromEntries(T.CHANGE_WINDOWS.map((w) => [w.id, w.name]));
    const campaigns = [];
    const dropped = [];
    for (const c of (plan.campaigns || []).slice(0, 6)) {
      const g = groups.find((x) => x.team === c.team && x.cve === c.cve);
      if (!g) { dropped.push(`${c.team} / ${c.cve}`); continue; }
      campaigns.push({ id: `C-${campaigns.length + 1}`, team: g.team, companyName: g.company, cve: g.cve, title: g.title, assets: g.findings, priority: g.p1 ? 'P1' : 'P2', window: windows[c.window_id] || windows['srv-thu'], rationale: c.rationale || '' });
    }
    if (dropped.length) s.guard(`Dropped ${dropped.length} campaign(s) that don't match any open findings: ${dropped.join(', ')}.`);
    if (!campaigns.length) throw new Error('The plan contained no valid campaigns');
    const covered = campaigns.reduce((n, c) => n + c.assets, 0);
    const approval = { id: `A-${++apprSeq}`, agent: 'planner', kind: 'plan', company, campaigns, title: `Submit ${campaigns.length} patch campaigns to ServiceNow`, reason: plan.summary || `Covers ${covered} findings`, confidence: 0.9, status: 'pending', at: new Date().toISOString() };
    s.decide(`Plan ready: ${campaigns.length} campaigns covering ${covered} findings. ${plan.summary || ''} Waiting for approval before anything goes to ServiceNow.`);
    return finishRun(run, { decision: { action: 'propose', label: `${campaigns.length} campaigns drafted`, confidence: 0.9 }, approval, extra: { plan: campaigns } });
  } catch (e) {
    return failRun(run, e);
  }
}

// =====================================================================================
// Analyst copilot
// =====================================================================================
const COPILOT_SYSTEM = `You are the ExposureIQ Analyst Copilot for SHV Group's security team. ExposureIQ correlates Microsoft Defender and Rapid7 vulnerability data into one de-duplicated, risk-ranked view.
Answer the question using only data from your tools; call them before answering. Company ids: ${COMPANIES.map((c) => `${c.id} (${c.short})`).join(', ')}.
Answer format: lead with the direct answer and its key number in bold, then the supporting detail. Use a markdown table for lists of more than three items. Keep it under 220 words.
If the data cannot answer the question, say so plainly. If asked what you are or which model you run on: you are the ExposureIQ Analyst Copilot, an AI agent powered by Google Gemini (${ai.models.join(', falling back to ')}); answer that without calling tools. Finish with one line starting "Next questions:" listing two or three short follow-up questions separated by " | ".`;

const READ_DECLS = {
  get_kpis: ['Headline KPIs: exposure score, open P1/P2, KEV instances, SLA compliance, MTTR, MTTI, coverage, duplicates removed.', S({ company: companyParam })],
  get_top_risks: ['Vulnerabilities ranked by their share of exposure.', S({ company: companyParam, n: { type: 'INTEGER', description: 'How many, default 8' } }, ['company'])],
  query_findings: ['Search open vulnerabilities with filters. Returns totals and the top rows.', S({ company: companyParam, priority: str('Comma-separated priorities, e.g. "P1,P2"'), kev: { type: 'BOOLEAN', description: 'Only actively exploited' }, internet_facing: { type: 'BOOLEAN', description: 'Only on internet-facing assets' }, text: str('Free-text search on title or CVE') }, ['company'])],
  get_vulnerability: ['One vulnerability: details, fix and per-company impact.', S({ cve: str('Vulnerability id') })],
  get_scorecard: ['Every group company scored on the same model: grade, exposure, P1/P2, KEV, SLA, MTTR, coverage.', S({}, [])],
  get_remediation: ['SLA compliance, MTTR by priority and the most overdue work.', S({ company: companyParam })],
  get_reconciliation: ['Raw records from both tools versus unified findings, and tool overlap.', S({ company: companyParam })],
  get_assets: ['Assets with coverage and exposure filters.', S({ company: companyParam, coverage: str('one of: both, mde, r7, none'), internet_facing: { type: 'BOOLEAN', description: 'Only internet-facing' }, text: str('Search hostname, OS or service') }, ['company'])],
  get_trend: ['13-week trend of exposure, open, urgent and KEV counts.', S({ company: companyParam })],
};
const CITE = { get_reconciliation: 'Rapid7 InsightVM + Defender (correlated)', get_assets: 'ServiceNow CMDB', get_vulnerability: 'CISA KEV · FIRST EPSS', query_findings: 'Microsoft Defender VM · Rapid7 InsightVM' };

export function mdToBlocks(md) {
  const blocks = [];
  const lines = md.replace(/\r/g, '').split('\n');
  let para = [];
  const flush = () => { if (para.length) { blocks.push({ type: 'text', text: para.join(' ') }); para = []; } };
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].trim();
    if (!l) { flush(); continue; }
    if (l.startsWith('|')) {
      flush();
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) rows.push(lines[i++].trim());
      i--;
      const cells = (r) => r.replace(/^\||\|$/g, '').split('|').map((c) => c.trim().replace(/\*\*/g, ''));
      const body = rows.filter((r, j) => j > 0 && !/^\|?\s*:?-{2,}/.test(r));
      blocks.push({ type: 'table', columns: cells(rows[0]), rows: body.map(cells) });
      continue;
    }
    if (/^([-*•]|\d+\.)\s+/.test(l)) {
      flush();
      const items = [];
      while (i < lines.length && /^([-*•]|\d+\.)\s+/.test(lines[i].trim())) items.push(lines[i++].trim().replace(/^([-*•]|\d+\.)\s+/, ''));
      i--;
      blocks.push({ type: 'list', items });
      continue;
    }
    para.push(l.replace(/^#+\s*/, '**').replace(/^(\*\*[^*]+)$/, '$1**'));
  }
  flush();
  return blocks;
}

export async function askCopilot(question, company = 'all') {
  const engine = await engineForPerson();
  const run = startRun('copilot', { title: question.length > 60 ? `${question.slice(0, 57)}…` : question, subject: { company }, engine });
  if (engine.llm) {
    try {
      const tools = Object.fromEntries(Object.entries(READ_DECLS).map(([name, [description, parameters]]) => [name, { description, parameters, run: (args) => T.READ[name]({ ...args, company: args.company === 'all' ? undefined : args.company }) }]));
      const res = await runAgent({ system: COPILOT_SYSTEM, prompt: `Scope: company "${company}". Question: ${question}`, tools, finalTool: null, trace: run.steps, onModel: (m) => { run.engine = m; } });
      let text = res.answer || 'I could not find an answer in the data.';
      let followUps = [];
      const m = text.match(/\n?\s*\**Next questions:?\**\s*(.+)$/i);
      if (m) { followUps = m[1].split('|').map((q) => q.trim().replace(/^[-*]\s*/, '').replace(/\*\*/g, '')).filter(Boolean).slice(0, 3); text = text.slice(0, m.index).trim(); }
      const used = [...new Set(run.steps.filter((x) => x.type === 'tool').map((x) => x.tool))];
      const cve = (question.match(/CVE-\d{4}-\d{4,7}/i) || text.match(/CVE-\d{4}-\d{4,7}/))?.[0]?.toUpperCase();
      run.steps.push({ type: 'decision', text: `Answered from ${used.length} tool${used.length === 1 ? '' : 's'}: ${used.join(', ') || 'none'}.` });
      finishRun(run, { decision: { action: 'answer', label: 'Answered', confidence: 0.9 } });
      return {
        blocks: mdToBlocks(text), citations: ['ExposureIQ unified dataset', ...new Set(used.map((u) => CITE[u]).filter(Boolean))], followUps,
        link: cve ? { page: 'vulnerabilities', cve } : undefined, trace: run.steps, runId: run.id, engine: run.engine, scope: company,
      };
    } catch (e) {
      run.steps.push({ type: 'guardrail', text: `Gemini unavailable (${e.message}); answering from templates.` });
      run.engine = 'rules';
    }
  }
  // Rules engine: template answers, with the same trace format.
  const res = templateCopilot(question, company);
  const s = step(run);
  s.think(`Matched the question to the "${res.intent}" answer template.`);
  for (const [tool, args] of TEMPLATE_TOOLS[res.intent] || []) s.tool(tool, { ...args, company }, T.READ[tool]?.({ company: company === 'all' ? undefined : company, ...args })?.summary || '');
  s.decide(`Answered from template with ${res.blocks.length} parts.`);
  finishRun(run, { decision: { action: 'answer', label: 'Answered (template)', confidence: 0.7 } });
  return { ...res, trace: run.steps, runId: run.id, engine: run.engine };
}
const TEMPLATE_TOOLS = {
  executive: [['get_kpis', {}], ['get_trend', {}], ['get_top_risks', { n: 3 }]], kev: [['query_findings', { kev: true }], ['get_scorecard', {}]],
  plan: [['query_findings', { priority: 'P1,P2' }], ['get_top_risks', { n: 5 }]], sla: [['get_remediation', {}]], compare: [['get_scorecard', {}]],
  duplication: [['get_reconciliation', {}]], coverage: [['get_assets', { coverage: 'none' }]], internet: [['query_findings', { internet_facing: true }]],
  trend: [['get_trend', {}]], company: [['get_kpis', {}], ['get_scorecard', {}]], cve: [], score: [],
};

// =====================================================================================
// Approvals
// =====================================================================================
export async function decide(id, verdict) {
  const ap = approvals.find((x) => x.id === id);
  if (!ap || ap.status !== 'pending') return null;
  const ok = verdict === 'approve';
  ap.status = ok ? 'approved' : 'rejected';
  ap.decidedAt = new Date().toISOString();
  stats[ap.agent][ok ? 'approved' : 'rejected']++;
  const run = runs.find((r) => r.id === ap.runId);
  if (run) run.status = ap.status;
  let outcome = ok ? 'Approved' : 'Rejected: nothing changed';
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
      const f = store.findings.find((x) => x.cve === c.cve && store.assetById[x.assetId]?.owner === c.team && x.status === 'Open');
      if (!f || store.tickets.some((x) => x.cve === f.cve && x.company === f.company && x.state !== 'Resolved')) continue;
      const t = await T.createTicket(f, { priority: c.priority === 'P1' ? 'Emergency' : 'Normal', by: 'Remediation Planner', note: `Campaign ${c.id}: ${c.assets} assets · window ${c.window}` });
      t.assets = c.assets;
      created++;
    }
    outcome = `${ap.campaigns.length} campaigns submitted · ${created} new ServiceNow tickets`;
  }
  ap.outcome = outcome;
  return ap;
}

export function agentsView() {
  const now = Date.now();
  return {
    model: ai.enabled ? `Gemini ${ai.models.join(' → ')}` : 'Rules engine: add GEMINI_API_KEY to backend/.env to switch agents to Gemini',
    ai: { enabled: ai.enabled, model: ai.model, models: quotaView(), coolingDownSec: coolingDownFor(), calls: ai.calls, runs: ai.runs, inputTokens: ai.inputTokens, outputTokens: ai.outputTokens, lastError: ai.lastError, runsThisMinute: runsThisMinute(), budgetPerMinute: config.gemini.maxRunsPerMinute },
    agents: AGENTS.map((a) => ({
      ...a, stats: stats[a.id], pending: approvals.filter((x) => x.agent === a.id && x.status === 'pending').length,
      working: runs.some((r) => r.agent === a.id && r.status === 'running') || (!!stats[a.id].lastRun && now - new Date(stats[a.id].lastRun).getTime() < 5000),
    })),
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
  app.post('/api/agents/:id/run', async (req, res) => {
    const id = req.params.id;
    let run = null;
    if (id === 'triage') {
      const f = store.findings.filter((x) => x.status === 'Open' && (x.priority === 'P1' || x.priority === 'P2') && !x.triaged).sort((x, y) => y.risk - x.risk)[0];
      if (f) { triage(f, { interactive: true }); run = runs[0]; }
    } else if (id === 'match') {
      const a = store.assets.find((x) => needsReview(x) && !x.agentReviewed);
      if (a) { runAssetMatch(a.id, { interactive: true }); run = runs[0]; }
    } else if (id === 'planner') { runPlanner(req.body?.company || 'all', { interactive: true }); run = runs[0]; }
    if (!run) return res.json({ run: null, message: 'Nothing for this agent to do right now' });
    res.json({ run }); // the run continues in the background; the UI polls it
  });
  app.post('/api/approvals/:id', async (req, res) => {
    const ap = await decide(req.params.id, req.body?.decision);
    return ap ? res.json(ap) : res.status(400).json({ error: 'Unknown or already decided' });
  });
  if (store.findings.some((f) => f.status === 'Open' && (f.priority === 'P1' || f.priority === 'P2'))) runPlanner('all');
}
