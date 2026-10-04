// "GenAI" layer (simulated). In production these narratives would be produced by an LLM
// (e.g. Azure OpenAI) grounded on the same computed metrics. Here they are templated from
// live numbers, so the text always matches the dashboards.
import { ai } from './ai/gemini.js';
import { COMPANIES, SLA_POLICY } from './data/companies.js';
import { catalogById } from './data/catalog.js';
import { store, isoAgo } from './data/generator.js';
import { kpis, scorecard, topRisks, reconciliation, remediation, scope, isOpen, vulnDetail, assetsList, trend } from './analytics.js';

const coName = (id) => (!id || id === 'all' ? 'SHV Group' : COMPANIES.find((c) => c.id === id)?.short || id);
const n = (v) => Number(v).toLocaleString('en-GB');
const signed = (n, unit = '') => `${n > 0 ? '+' : ''}${n}${unit}`;

export function briefing(company) {
  const k = kpis(company);
  const sc = scorecard();
  const top = topRisks(company, 3);
  const concentration = topRisks(company, 40).sort((a, b) => b.contribution - a.contribution).slice(0, 3);
  const rec = reconciliation(company);
  const d = k.exposureScore - k.exposureScorePrev;
  const worst = [...sc].sort((a, b) => b.exposureScore - a.exposureScore)[0];
  const best = [...sc].sort((a, b) => a.exposureScore - b.exposureScore)[0];
  const scoped = company && company !== 'all';
  const urgentOpen = scope(company).findings.filter((f) => isOpen(f) && (f.priority === 'P1' || f.priority === 'P2'));
  const topIds = new Set(concentration.map((t) => t.cve));
  const urgentShare = urgentOpen.length ? Math.round((urgentOpen.filter((f) => topIds.has(f.cve)).length / urgentOpen.length) * 100) : 0;
  const headline = d === 0
    ? `Exposure is stable: ${coName(company)} holds at ${k.exposureScore}/100, with ${k.openP1 + k.openP2} urgent items open.`
    : d < 0
    ? `Exposure is improving: ${coName(company)} risk fell ${Math.abs(d)} points in 4 weeks, but ${k.openP1 + k.openP2} urgent items still need action.`
    : `Exposure is rising: ${coName(company)} risk is up ${d} points in 4 weeks, driven by ${top[0] ? top[0].product : 'new findings'}.`;
  const paragraphs = [
    `${coName(company)} currently has an **exposure score of ${k.exposureScore}/100** (${signed(d)} vs 4 weeks ago) across ${k.assets} assets. There are **${k.openP1} P1** and **${k.openP2} P2** open items, of which **${k.kevOpen} instances** are vulnerabilities known to be actively exploited (CISA KEV).`,
    [
      top.filter((t) => t.priority === 'P1').length ? `**Act now:** ${top.filter((t) => t.priority === 'P1').map((t) => `${t.cve} (${t.product}, ${t.assets} asset${t.assets > 1 ? 's' : ''})`).join(', ')} — P1 exposures on critical or internet-facing systems.` : '',
      concentration.length ? `The largest risk concentrations are **${concentration.map((t) => `${t.cve} (${t.product}, ${t.assets} assets)`).join('**, **')}** — together **${urgentShare}%** of open P1/P2 instances, fixable with ${concentration.length} patch campaigns.` : '',
    ].filter(Boolean).join(' ') || 'There are no open high-risk concentrations.',
    `SLA compliance stands at **${k.slaCompliance}%** with **${k.breached}** findings past due. Mean time to remediate is **${k.mttr} days** (${signed(Math.round((k.mttr - k.mttrPrev) * 10) / 10, ' d')} vs the previous quarter).`,
    scoped ? `Tool coverage is **${k.coverage.pct}%** of known assets; ${k.coverage.none} asset${k.coverage.none === 1 ? ' is' : 's are'} not assessed by any scanner.`
      : `Across companies, **${best.short}** leads (score ${best.exposureScore}) while **${worst.short}** carries the highest exposure (score ${worst.exposureScore}, ${worst.breached} SLA breaches, ${worst.scanCadence}-day Rapid7 scan cadence).`,
    `Correlating Rapid7 and Defender removed **${k.duplicatesRemoved} duplicate findings** (${rec.raw.duplicateRate}% of raw volume) and cut mean time to identify from **${rec.mtti.r7} days (Rapid7 alone)** to **${rec.mtti.unified} days**.`,
  ];
  const actions = [];
  if (top[0]) actions.push({ text: `Emergency patch campaign for ${top[0].cve} (${top[0].product}) — ${top[0].assets} assets, risk ${top[0].maxRisk}.`, cve: top[0].cve });
  if (!scoped && worst.breached > 10) actions.push({ text: `Escalate ${worst.short}'s SLA backlog (${worst.breached} breaches) to the BU CIO and move Rapid7 scans from ${worst.scanCadence}-day to 7-day cadence.` });
  if (k.coverage.none > 0) actions.push({ text: `Onboard ${k.coverage.none} unassessed assets (MDE device discovery already sees ${assetsList({ company }).discovery.mdeDiscovered}).`, link: 'assets' });
  if (rec.matching.review.length) actions.push({ text: `Resolve ${rec.matching.review.length} low-confidence asset matches in the correlation queue.`, link: 'correlation' });
  return { headline, paragraphs, actions, generatedAt: new Date().toISOString(), model: 'Simulated GenAI · grounded on ExposureIQ data' };
}

// ---------------- Copilot ----------------
const CITE = {
  mdvm: 'MDVM · DeviceTvmSoftwareVulnerabilities',
  r7: 'Rapid7 InsightVM · /api/3/vulnerabilities',
  cmdb: 'ServiceNow CMDB · cmdb_ci',
  kev: 'CISA KEV catalogue',
  snow: 'ServiceNow · Vulnerability Response',
};

function answerExecutive(company) {
  const b = briefing(company);
  return {
    blocks: [
      { type: 'text', text: `**${b.headline}**` },
      ...b.paragraphs.map((p) => ({ type: 'text', text: p })),
      { type: 'list', title: 'Recommended actions', items: b.actions.map((a) => a.text) },
    ],
    citations: [CITE.mdvm, CITE.r7, CITE.cmdb, CITE.kev],
    followUps: ['Which companies are breaching SLA?', 'Build this week\'s patch plan', 'How much duplication did correlation remove?'],
  };
}

function answerKev(company) {
  const open = scope(company).findings.filter((f) => isOpen(f) && catalogById[f.cve].kev);
  const map = new Map();
  for (const f of open) {
    const key = `${f.cve}|${f.company}`;
    const g = map.get(key) || { cve: f.cve, company: COMPANIES.find((c) => c.id === f.company).short, assets: 0, internet: 0, maxRisk: 0 };
    g.assets++; if (store.assetById[f.assetId].internetFacing) g.internet++; g.maxRisk = Math.max(g.maxRisk, f.risk);
    map.set(key, g);
  }
  const rows = [...map.values()].sort((a, b) => b.maxRisk - a.maxRisk).slice(0, 10);
  return {
    blocks: [
      { type: 'text', text: `There are **${open.length} open instances** of actively exploited (KEV) vulnerabilities in ${coName(company)}, spread over **${new Set(open.map((f) => f.cve)).size} CVEs**. ${rows.filter((r) => r.internet).length ? `**${rows.filter((r) => r.internet).length}** of the top groups include internet-facing assets — these are your most likely breach paths.` : ''}` },
      { type: 'table', columns: ['CVE', 'Company', 'Assets', 'Internet-facing', 'Max risk'], rows: rows.map((r) => [r.cve, r.company, r.assets, r.internet, r.maxRisk]) },
    ],
    citations: [CITE.kev, CITE.mdvm, CITE.r7],
    followUps: ['Build this week\'s patch plan', `Explain ${rows[0]?.cve || 'CVE-2024-3400'}`, 'What is internet-facing and vulnerable?'],
  };
}

function answerSla(company) {
  const rem = remediation(company);
  const rows = rem.slaMatrix.sort((a, b) => a.overall - b.overall);
  const worst = rem.leaderboard.slice(0, 5);
  return {
    blocks: [
      { type: 'text', text: `SLA compliance for ${coName(company)} is **${rem.compliance}%** with **${rem.breached} breached** and **${rem.dueSoon} due within days**. The SHV policy is P1 ≤ 7d, P2 ≤ 30d, P3 ≤ 60d, P4 ≤ 90d, applied to the unified risk priority.` },
      { type: 'table', title: 'Compliance by company', columns: ['Company', 'Overall', 'P1', 'P2', 'P3', 'P4'], rows: rows.map((r) => [r.name, `${r.overall}%`, `${r.P1}%`, `${r.P2}%`, `${r.P3}%`, `${r.P4}%`]) },
      { type: 'table', title: 'Teams most behind', columns: ['Owner', 'Open', 'Breached', 'Compliance', 'MTTR'], rows: worst.map((w) => [w.owner, w.open, w.breached, `${w.compliance}%`, `${w.mttr} d`]) },
    ],
    citations: [CITE.mdvm, CITE.r7, CITE.snow],
    followUps: ['Why is Mammoet behind?', 'Build this week\'s patch plan', 'Summarise for the board'],
  };
}

function answerCompare() {
  const sc = scorecard().sort((a, b) => b.exposureScore - a.exposureScore);
  return {
    blocks: [
      { type: 'text', text: `Ranked by exposure score (higher = more risk). **${sc[0].short}** needs the most attention; **${sc[sc.length - 1].short}** is the benchmark to replicate.` },
      { type: 'table', columns: ['Company', 'Grade', 'Exposure', '4-wk Δ', 'P1+P2', 'SLA', 'MTTR', 'Coverage'], rows: sc.map((s) => [s.short, s.grade, s.exposureScore, signed(s.exposureDelta), s.openP1 + s.openP2, `${s.slaCompliance}%`, `${s.mttr} d`, `${s.coverage}%`]) },
      { type: 'text', text: `The spread is mostly explained by **scan cadence and remediation discipline**: ${sc[0].short} scans every ${sc[0].scanCadence} days vs ${sc[sc.length - 1].scanCadence} days at ${sc[sc.length - 1].short}.` },
    ],
    citations: [CITE.mdvm, CITE.r7, CITE.cmdb],
    followUps: [`Why is ${sc[0].short} behind?`, 'Which companies are breaching SLA?', 'Summarise for the board'],
  };
}

function answerCompany(id) {
  const k = kpis(id);
  const top = topRisks(id, 5);
  const co = COMPANIES.find((c) => c.id === id);
  const rec = reconciliation(id);
  return {
    blocks: [
      { type: 'text', text: `**${co.name}** has an exposure score of **${k.exposureScore}** with **${k.breached} SLA breaches** and MTTR of **${k.mttr} days**. Three root causes stand out:` },
      { type: 'list', items: [
        `Rapid7 scans run every **${co.scanDays} days**, so issues are identified after **${rec.mtti.r7} days** on average via Rapid7 vs ${rec.mtti.mde} days via Defender.`,
        `Tool coverage is **${k.coverage.pct}%**; ${k.coverage.none} assets are not assessed by any scanner.`,
        `The backlog is concentrated in: ${top.slice(0, 3).map((t) => `${t.cve} (${t.assets})`).join(', ')}.`,
      ] },
      { type: 'text', text: 'Recommendation: move to weekly authenticated scans, onboard unmanaged devices into Defender, and run a single consolidated patch campaign for the top three CVEs.' },
    ],
    citations: [CITE.mdvm, CITE.r7, CITE.cmdb],
    followUps: [`Build this week's patch plan for ${co.short}`, 'Compare all group companies', 'What are the coverage gaps?'],
  };
}

function answerDuplication(company) {
  const rec = reconciliation(company);
  return {
    blocks: [
      { type: 'text', text: `Rapid7 reported **${n(rec.raw.r7)}** findings and Defender **${n(rec.raw.mde)}** — **${n(rec.raw.total)}** raw rows. After asset matching and CVE correlation these collapse into **${n(rec.raw.unified)} unified findings**: ${n(rec.raw.both)} were seen by both tools (${rec.raw.duplicateRate}% of raw volume was duplication).` },
      { type: 'kpis', items: [
        { label: 'Only Defender sees', value: rec.raw.mdeOnly, hint: 'installed software, off-network laptops' },
        { label: 'Seen by both', value: rec.raw.both, hint: 'de-duplicated' },
        { label: 'Only Rapid7 sees', value: rec.raw.r7Only, hint: 'appliances, OT, un-agented hosts' },
      ] },
      { type: 'text', text: `**${rec.disagreements.length} CVEs** are labelled differently by the two tools (${rec.disagreementInstances} instances) — e.g. ${rec.disagreements[0] ? `${rec.disagreements[0].cve}: Rapid7 "${rec.disagreements[0].r7}" vs Defender "${rec.disagreements[0].mde}"` : 'none'}. ExposureIQ resolves these with one unified risk score instead of either vendor label.` },
    ],
    citations: [CITE.mdvm, CITE.r7],
    followUps: ['How is the unified risk score calculated?', 'What are the coverage gaps?', 'Summarise for the board'],
  };
}

function answerCoverage(company) {
  const a = assetsList({ company });
  return {
    blocks: [
      { type: 'text', text: `**${a.coverage.pct}%** of known assets in ${coName(company)} are assessed by at least one scanner. ${a.coverage.none} assets are blind spots — ${a.discovery.mdeDiscovered} were found by Defender device discovery and ${a.discovery.cmdbOnly} exist only in the CMDB.` },
      { type: 'table', columns: ['Asset type', 'Total', 'Both tools', 'Defender only', 'Rapid7 only', 'None'], rows: a.byType.map((t) => [t.type, t.total, t.both, t.mdeOnly, t.r7Only, t.none]) },
      { type: 'text', text: 'Network appliances and OT cannot run the Defender agent, so Rapid7 (or a network-based OT sensor) remains essential there. Workstations are the reverse — Defender sees them wherever they are.' },
    ],
    citations: [CITE.mdvm, CITE.r7, CITE.cmdb],
    followUps: ['What is internet-facing and vulnerable?', 'How much duplication did correlation remove?'],
  };
}

function answerInternet(company) {
  const all = assetsList({ company, internet: 'true' }).rows.filter((r) => r.openFindings > 0);
  const rows = all.slice(0, 10);
  return {
    blocks: [
      { type: 'text', text: `**${all.length} internet-facing assets** currently carry open findings${all.length > 10 ? ' (top 10 by risk below)' : ''}. These are prioritised automatically because attack surface adds +10 to the unified risk score.` },
      { type: 'table', columns: ['Host', 'Company', 'Type', 'Top CVE', 'Max risk', 'Open'], rows: rows.map((r) => [r.hostname, r.companyName, r.type, r.topCve, r.maxRisk, r.openFindings]) },
    ],
    citations: [CITE.r7, CITE.mdvm, CITE.cmdb],
    followUps: ['Show actively exploited vulnerabilities', 'Build this week\'s patch plan'],
  };
}

function answerPlan(company) {
  const top = topRisks(company, 6);
  return {
    blocks: [
      { type: 'text', text: `Here is a risk-ranked patch plan for ${coName(company)} this week. It groups findings into campaigns so each team gets one change, not dozens of tickets.` },
      { type: 'table', columns: ['#', 'Campaign', 'Assets', 'Companies', 'Risk', 'Ticket'], rows: top.map((t, i) => [i + 1, `${t.cve} — ${t.product}`, t.assets, t.companies.length, t.maxRisk, t.tickets[0] || 'Create']) },
      { type: 'text', text: `Completing campaigns 1–3 would close **${top.slice(0, 3).reduce((s, t) => s + t.assets, 0)} high-risk instances** and is estimated to lower the exposure score by roughly ${Math.max(3, Math.round(top.slice(0, 3).reduce((s, t) => s + t.maxRisk * t.assets, 0) / 400))} points.` },
    ],
    citations: [CITE.mdvm, CITE.r7, CITE.kev, CITE.snow],
    followUps: [`Explain ${top[0]?.cve || 'CVE-2024-3400'}`, 'Which companies are breaching SLA?'],
  };
}

function answerTrend(company) {
  const t = trend(company);
  const first = t[0], last = t[t.length - 1];
  const k = kpis(company);
  return {
    blocks: [
      { type: 'text', text: `Over the last 12 weeks ${coName(company)}'s exposure score moved from **${first.exposure} to ${last.exposure}** and open findings from **${first.open} to ${last.open}**. MTTR is **${k.mttr} days** vs ${k.mttrPrev} days the quarter before.` },
      { type: 'table', columns: ['Week of', 'Exposure', 'Open', 'P1+P2', 'New', 'Closed'], rows: t.filter((_, i) => i % 2 === 0 || i === t.length - 1).map((p) => [p.date.slice(0, 10), p.exposure, p.open, p.urgent, p.detected, p.remediated]) },
    ],
    citations: [CITE.mdvm, CITE.r7],
    followUps: ['Summarise for the board', 'Which companies are breaching SLA?'],
  };
}

function answerScore() {
  return {
    blocks: [
      { type: 'text', text: 'The **unified risk score (0–100)** replaces the separate Rapid7 and Defender severity labels with one transparent formula applied to every finding:' },
      { type: 'table', columns: ['Factor', 'Source', 'Max points'], rows: [
        ['Technical severity (CVSS × 5)', 'NVD via both tools', 50],
        ['Threat intelligence (KEV / exploit maturity)', 'CISA KEV, MDVM threat insights', 20],
        ['Exploit likelihood (EPSS)', 'FIRST EPSS', 8],
        ['Business criticality (crown jewel / high / standard)', 'ServiceNow CMDB', 15],
        ['Attack surface (internet-facing)', 'Rapid7 external scan + MDVM', 10],
      ] },
      { type: 'text', text: `The score maps to the SHV SLA: ${SLA_POLICY.map((p) => `**${p.priority}** ≥ ${p.minRisk} → ${p.days} days`).join(', ')}.` },
    ],
    citations: ['ExposureIQ scoring policy v0.3'],
    followUps: ['How much duplication did correlation remove?', 'Show actively exploited vulnerabilities'],
  };
}

function answerCve(id, company) {
  const d = vulnDetail(id, company);
  if (!d) return { blocks: [{ type: 'text', text: `${id} is not present in the SHV estate (neither Rapid7 nor Defender has reported it).` }], citations: [CITE.mdvm, CITE.r7], followUps: ['Show actively exploited vulnerabilities'] };
  return {
    blocks: [
      { type: 'text', text: `**${d.cve} — ${d.title}** (CVSS ${d.cvss}${d.kev ? ', CISA KEV' : ''}, ${d.exploit} exploit).` },
      ...d.ai.summary.map((t) => ({ type: 'text', text: t })),
      { type: 'list', title: 'Remediation', items: [...d.ai.steps, `Compensating control: ${d.compensating}`] },
      d.byCompany.length ? { type: 'table', columns: ['Company', 'Open', 'Breached', 'Ticket'], rows: d.byCompany.map((c) => [c.name, c.open, c.breached, c.ticket ? c.ticket.id : '—']) } : null,
    ].filter(Boolean),
    citations: [CITE.mdvm, CITE.r7, CITE.kev],
    followUps: ['Build this week\'s patch plan', 'Show actively exploited vulnerabilities'],
    link: { page: 'vulnerabilities', cve: d.cve },
  };
}

export function copilot(question, company) {
  const q = (question || '').toLowerCase();
  const cve = question.match(/(CVE-\d{4}-\d{4,7}|EOL-[A-Z0-9]+|R7-[A-Z-]+)/i);
  const mentioned = COMPANIES.find((c) => q.includes(c.short.toLowerCase()) || q.includes(c.id));
  let res, intent;
  if (cve) { intent = 'cve'; res = answerCve(cve[1].toUpperCase(), company); }
  else if (/why .*(behind|worse|bad|high)|deep dive|tell me about/.test(q) && mentioned) { intent = 'company'; res = answerCompany(mentioned.id); }
  else if (/score|calculat|formula|how.*risk/.test(q) && !/board|summar/.test(q)) { intent = 'score'; res = answerScore(); }
  else if (/board|executive|summar|brief|leadership|ciso/.test(q)) { intent = 'executive'; res = answerExecutive(mentioned ? mentioned.id : company); }
  else if (/kev|actively|exploited|in the wild/.test(q)) { intent = 'kev'; res = answerKev(mentioned ? mentioned.id : company); }
  else if (/plan|this week|priorit|what should|fix first|campaign/.test(q)) { intent = 'plan'; res = answerPlan(mentioned ? mentioned.id : company); }
  else if (/sla|overdue|breach|late|30 days/.test(q)) { intent = 'sla'; res = answerSla(mentioned ? mentioned.id : company); }
  else if (/compare|rank|worst|best|which compan|league/.test(q)) { intent = 'compare'; res = answerCompare(); }
  else if (/duplic|overlap|correlat|rapid7 vs|vs rapid7|both tools|disagree/.test(q)) { intent = 'duplication'; res = answerDuplication(mentioned ? mentioned.id : company); }
  else if (/coverage|blind|unmanaged|gap|not scanned|missing/.test(q)) { intent = 'coverage'; res = answerCoverage(mentioned ? mentioned.id : company); }
  else if (/internet|external|perimeter|exposed/.test(q)) { intent = 'internet'; res = answerInternet(mentioned ? mentioned.id : company); }
  else if (/trend|improv|progress|mttr|over time|last quarter/.test(q)) { intent = 'trend'; res = answerTrend(mentioned ? mentioned.id : company); }
  else if (/score|calculat|formula|how.*risk/.test(q)) { intent = 'score'; res = answerScore(); }
  else if (mentioned) { intent = 'company'; res = answerCompany(mentioned.id); }
  else {
    intent = 'help';
    res = {
      blocks: [{ type: 'text', text: 'I can answer questions about exposure, SLAs, specific CVEs, group-company comparisons, coverage gaps and tool overlap — all grounded on the correlated Rapid7 + Defender data. Try one of these:' }],
      citations: [],
      followUps: ['Summarise for the board', 'Show actively exploited vulnerabilities', 'Compare all group companies', 'Build this week\'s patch plan', 'How is the unified risk score calculated?'],
    };
  }
  return { ...res, intent, scope: coName(mentioned ? mentioned.id : company), answeredAt: new Date().toISOString() };
}

// ---------------- Data sources ----------------
const syncState = {};
export function integrations() {
  const mdeFindings = store.findings.filter((f) => f.sources.includes('MDE')).length;
  const r7Findings = store.findings.filter((f) => f.sources.includes('R7')).length;
  const base = [
    { id: 'mdvm', name: 'Microsoft Defender Vulnerability Management', vendor: 'Microsoft', role: 'Exposure management layer', status: 'Connected', badge: 'Trial · day 23 of 90', method: 'Defender XDR API · Advanced Hunting (DeviceTvm* tables)', frequency: 'Every 4 h', records: mdeFindings, recordLabel: 'software vulnerabilities', syncAgoMin: 38, fields: ['DeviceId', 'DeviceName', 'CveId', 'VulnerabilitySeverityLevel', 'RecommendedSecurityUpdate', 'ExposureScore'] },
    { id: 'mde', name: 'Microsoft Defender for Endpoint', vendor: 'Microsoft', role: 'Endpoint agent & device inventory', status: 'Connected', method: 'Defender XDR API · /api/machines', frequency: 'Every 4 h', records: store.assets.filter((a) => a.mde).length, recordLabel: 'onboarded devices', syncAgoMin: 38, fields: ['id', 'computerDnsName', 'osPlatform', 'aadDeviceId', 'lastIpAddress', 'onboardingStatus'] },
    { id: 'r7', name: 'Rapid7 InsightVM', vendor: 'Rapid7', role: 'Network & authenticated scanning', status: 'Connected', method: 'InsightVM API v3 · /api/3/assets, /vulnerabilities', frequency: 'Daily 02:00 CET', records: r7Findings, recordLabel: 'vulnerability instances', syncAgoMin: 412, fields: ['asset.id', 'hostName', 'ip', 'vulnerability.id', 'severity', 'riskScore'] },
    { id: 'cmdb', name: 'ServiceNow CMDB', vendor: 'ServiceNow', role: 'Business criticality & ownership', status: 'Connected', method: 'Table API · cmdb_ci_computer, cmdb_ci_service', frequency: 'Daily', records: store.assets.length, recordLabel: 'configuration items', syncAgoMin: 610, fields: ['name', 'business_service', 'u_criticality_tier', 'support_group', 'company'] },
    { id: 'snow', name: 'ServiceNow Vulnerability Response', vendor: 'ServiceNow', role: 'Remediation ticketing (optional)', status: 'Connected', method: 'REST · sn_vul_vulnerable_item', frequency: 'On demand', records: store.tickets.length, recordLabel: 'remediation tasks', syncAgoMin: 5, fields: ['number', 'state', 'assignment_group', 'due_date'] },
    { id: 'kev', name: 'CISA KEV & FIRST EPSS', vendor: 'Public threat intel', role: 'Exploitation enrichment', status: 'Connected', method: 'JSON feeds', frequency: 'Daily', records: 1340, recordLabel: 'KEV entries', syncAgoMin: 190, fields: ['cveID', 'dateAdded', 'epss', 'percentile'] },
    { id: 'pbi', name: 'Power BI', vendor: 'Microsoft', role: 'Executive reporting layer', status: 'Publishing', method: 'Semantic model push · Fabric workspace "Group Security"', frequency: 'Every 4 h', records: 6, recordLabel: 'report pages', syncAgoMin: 36, fields: ['FactFinding', 'DimAsset', 'DimCompany', 'DimDate', 'FactExposureDaily'] },
    { id: 'aoai', name: 'Google Gemini', vendor: 'Google', role: 'Reasoning model behind the 4 AI agents', status: ai.enabled ? 'Connected' : 'Not configured', method: `${ai.model} · function calling over ExposureIQ tools`, frequency: 'On demand', records: 0, recordLabel: 'no data stored', syncAgoMin: null, fields: ['metrics context only — no raw host data sent'] },
  ];
  return base.map((b) => ({ ...b, ...(syncState[b.id] || {}), lastSync: b.syncAgoMin == null ? null : new Date(Date.now() - (syncState[b.id]?.syncAgoMin ?? b.syncAgoMin) * 60000).toISOString() }));
}
export function runSync(id) {
  syncState[id] = { syncAgoMin: 0 };
  return integrations().find((i) => i.id === id);
}

// ---------------- Proof of value tracker ----------------
const povTasks = [
  { id: 't1', phase: 1, text: 'Global Administrator activates MDVM trial in Microsoft 365 admin center', done: true },
  { id: 't2', phase: 1, text: 'Confirm Defender for Endpoint P2 / Defender for Servers onboarding per company', done: true },
  { id: 't3', phase: 1, text: 'Review Exposure Score and Secure Score baseline', done: true },
  { id: 't4', phase: 1, text: 'Enable device discovery to surface unmanaged assets', done: false },
  { id: 't5', phase: 2, text: 'Read-only API key for Rapid7 InsightVM (per console)', done: true },
  { id: 't6', phase: 2, text: 'Compare MDVM vs Rapid7 findings on a 50-host sample', done: false },
  { id: 't7', phase: 2, text: 'Agree unified risk scoring formula with Group CISO', done: false },
  { id: 't8', phase: 3, text: 'Publish Power BI semantic model and executive report', done: false },
  { id: 't9', phase: 3, text: 'Agree SHV SLA policy (P1 7d / P2 30d / P3 60d / P4 90d)', done: false },
  { id: 't10', phase: 3, text: 'First automated monthly executive report', done: false },
  { id: 't11', phase: 4, text: 'Assess Rapid7 → MDVM integration pattern (API vs Sentinel vs Fabric)', done: false },
  { id: 't12', phase: 4, text: 'DPIA / data-processing review for GenAI layer', done: false },
  { id: 't13', phase: 4, text: 'Go / no-go: MDVM as strategic exposure platform', done: false },
];
export function toggleTask(id) {
  const t = povTasks.find((x) => x.id === id);
  if (t) t.done = !t.done;
  return t;
}
export function pov() {
  const k = kpis('all');
  const rec = reconciliation('all');
  const monthly = remediation('all').monthly;
  const open = store.findings.filter(isOpen);
  const crit30 = open.filter((f) => (f.priority === 'P1' || f.priority === 'P2') && f.detectedAgo > 30).length;
  const crit30Prev = store.findings.filter((f) => f.detectedAgo >= 28 && !(f.status === 'Remediated' && f.remediatedAgo >= 28) && (f.priority === 'P1' || f.priority === 'P2') && f.detectedAgo - 28 > 30).length;
  const r7View = Math.round((store.assets.filter((a) => a.r7).length / store.assets.length) * 1000) / 10;
  return {
    trial: { day: 23, length: 90, startedAt: isoAgo(23), endsAt: isoAgo(-67) },
    phases: [
      { n: 1, name: 'Asset discovery', weeks: 'Weeks 1–3', goal: 'Onboard Defender-managed endpoints, build the exposure inventory, baseline Exposure & Secure Score.' },
      { n: 2, name: 'Vulnerability analysis', weeks: 'Weeks 4–7', goal: 'Compare MDVM with Rapid7 findings and validate risk-based prioritisation.' },
      { n: 3, name: 'Reporting & governance', weeks: 'Weeks 8–10', goal: 'Power BI dashboards, SLA measurement, executive reporting.' },
      { n: 4, name: 'Integration assessment', weeks: 'Weeks 11–13', goal: 'Decide the integration pattern and whether MDVM becomes the strategic platform.' },
    ],
    tasks: povTasks,
    metrics: [
      { group: 'Operational efficiency', name: 'Manual reporting effort', unit: 'h / month', baseline: 72, current: 16, target: '≤ 18 (−75%)', better: 'lower', status: 'met' },
      { group: 'Operational efficiency', name: 'Time to produce group vulnerability report', unit: '', baseline: '4 days', current: '< 5 min', target: 'Automated', better: 'lower', status: 'met' },
      { group: 'Operational efficiency', name: 'Duplicate findings across tools', unit: '%', baseline: rec.raw.duplicateRate, current: Math.round((rec.matching.review.length / rec.raw.unified) * 1000) / 10, target: '< 10%', better: 'lower', status: 'met' },
      { group: 'Operational efficiency', name: 'Asset coverage in central reporting', unit: '%', baseline: r7View, current: k.coverage.pct, target: '> 95%', better: 'higher', status: k.coverage.pct > 95 ? 'met' : 'progress' },
      { group: 'Security', name: 'Mean time to identify (MTTI)', unit: 'days', baseline: rec.mtti.r7, current: rec.mtti.unified, target: '< 2 days', better: 'lower', status: rec.mtti.unified < 2 ? 'met' : 'progress' },
      { group: 'Security', name: 'Mean time to remediate (MTTR)', unit: 'days', baseline: k.mttrPrev, current: k.mttr, target: 'Improve 25%', better: 'lower', status: k.mttr <= k.mttrPrev * 0.75 ? 'met' : 'progress' },
      { group: 'Security', name: 'P1/P2 open > 30 days', unit: '', baseline: crit30Prev, current: crit30, target: 'Reduce 50%', better: 'lower', status: crit30 <= crit30Prev * 0.5 ? 'met' : 'progress' },
      { group: 'Security', name: 'SLA compliance (closed in month)', unit: '%', baseline: monthly[0].met, current: monthly[monthly.length - 1].met, target: '> 85%', better: 'higher', status: monthly[monthly.length - 1].met > 85 ? 'met' : 'progress' },
      { group: 'Governance', name: 'Companies on one SLA policy', unit: '', baseline: '0 / 5', current: '5 / 5', target: '5 / 5', better: 'higher', status: 'met' },
      { group: 'Governance', name: 'Executive reporting', unit: '', baseline: 'Quarterly, manual', current: 'Monthly, automated', target: 'Automated', better: 'higher', status: 'met' },
    ],
    prerequisites: [
      { item: 'Global Administrator to start the MDVM trial', owner: 'Group IT', status: 'done' },
      { item: 'Defender for Endpoint Plan 2 (or Defender for Servers) as the MDVM base', owner: 'Licensing', status: 'done' },
      { item: 'Read-only Rapid7 InsightVM API credentials per console', owner: 'OpCo security leads', status: 'done' },
      { item: 'ServiceNow CMDB read access (criticality & ownership)', owner: 'ITSM team', status: 'progress' },
      { item: 'Power BI / Fabric workspace for Group Security', owner: 'Data platform', status: 'progress' },
      { item: 'Data-processing review for GenAI summaries (EU boundary)', owner: 'Privacy office', status: 'todo' },
    ],
  };
}

// ---------------- Reports ----------------
export function report(type, company) {
  const k = kpis(company);
  const b = briefing(company);
  const sc = scorecard();
  const rem = remediation(company);
  const rec = reconciliation(company);
  const top = topRisks(company, 8);
  const common = { company: coName(company), generatedAt: new Date().toISOString(), kpis: k };
  if (type === 'weekly') {
    return {
      ...common, type, title: 'Weekly Vulnerability Operations Report', period: `Week ending ${new Date().toISOString().slice(0, 10)}`, audience: 'Security operations & remediation owners',
      narrative: b.paragraphs.slice(0, 3),
      sections: [
        { title: 'Top remediation campaigns', columns: ['CVE', 'Product', 'Priority', 'Risk', 'Assets', 'Breached', 'Ticket'], rows: top.map((t) => [t.cve, t.product, t.priority, t.maxRisk, t.assets, t.breached, t.tickets[0] || '—']) },
        { title: 'Overdue items (top 12)', columns: ['CVE', 'Company', 'Assets', 'Days overdue', 'Owner'], rows: rem.overdue.slice(0, 12).map((o) => [o.cve, o.companyName, o.assets, o.daysOverdue, o.owner]) },
        { title: 'Teams by SLA compliance', columns: ['Owner', 'Open', 'Breached', 'Compliance', 'MTTR (d)'], rows: rem.leaderboard.slice(0, 10).map((l) => [l.owner, l.open, l.breached, `${l.compliance}%`, l.mttr]) },
      ],
    };
  }
  if (type === 'monthly') {
    return {
      ...common, type, title: 'Monthly Executive Cyber Exposure Report', period: new Date().toLocaleString('en-GB', { month: 'long', year: 'numeric' }), audience: 'Group CISO, CIO and Executive Committee',
      narrative: [b.headline, ...b.paragraphs],
      actions: b.actions.map((a) => a.text),
      sections: [
        { title: 'Group company scorecard', columns: ['Company', 'Grade', 'Exposure', '4-wk Δ', 'P1+P2', 'SLA', 'MTTR (d)', 'Coverage'], rows: sc.map((s) => [s.short, s.grade, s.exposureScore, signed(s.exposureDelta), s.openP1 + s.openP2, `${s.slaCompliance}%`, s.mttr, `${s.coverage}%`]) },
        { title: 'SLA trend (closed per month)', columns: ['Month', 'Closed', 'Met SLA', 'MTTR (d)'], rows: rem.monthly.map((m) => [new Date(m.date).toLocaleString('en-GB', { month: 'short', year: 'numeric' }), m.closed, `${m.met}%`, m.mttr]) },
      ],
    };
  }
  return {
    ...common, type: 'audit', title: 'Audit & Compliance Evidence Pack', period: `As of ${new Date().toISOString().slice(0, 10)}`, audience: 'Internal audit, ISO 27001 / NIS2 assessors',
    narrative: [
      `This pack evidences the operation of the SHV vulnerability management control (ISO 27001 A.8.8, NIS2 Art. 21(2)(e)). ${k.coverage.pct}% of ${k.assets} known assets are assessed by at least one scanner; findings are classified with a single unified risk policy and tracked against SLA.`,
      `During the last 90 days ${store.findings.filter((f) => f.status === 'Remediated' && f.remediatedAgo <= 90).length} findings were closed. ${rem.exceptions} open findings are under a documented risk exception.`,
    ],
    sections: [
      { title: 'Control: SLA policy', columns: ['Priority', 'Risk score', 'Deadline', 'Definition'], rows: SLA_POLICY.map((p) => [p.priority, `≥ ${p.minRisk}`, `${p.days} days`, p.description]) },
      { title: 'Control: SLA adherence by company', columns: ['Company', 'Overall', 'P1', 'P2', 'P3', 'P4'], rows: rem.slaMatrix.map((r) => [r.name, `${r.overall}%`, `${r.P1}%`, `${r.P2}%`, `${r.P3}%`, `${r.P4}%`]) },
      { title: 'Control: data completeness', columns: ['Check', 'Result'], rows: [
        ['Raw findings ingested (Rapid7 + Defender)', rec.raw.total],
        ['Unified findings after correlation', rec.raw.unified],
        ['Asset matches requiring manual review', rec.matching.review.length],
        ['Assets not assessed by any tool', k.coverage.none],
      ] },
    ],
  };
}
