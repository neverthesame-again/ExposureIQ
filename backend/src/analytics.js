// Turns the correlated store into the views the UI needs. Everything is computed from
// the same finding records, so every number on every screen reconciles with every other.
import { COMPANIES, SLA_POLICY } from './data/companies.js';
import { CATALOG, catalogById } from './data/catalog.js';
import { store, isoAgo, computeRisk } from './data/generator.js';

const coById = Object.fromEntries(COMPANIES.map((c) => [c.id, c]));
const round1 = (n) => Math.round(n * 10) / 10;
const avg = (arr) => (arr.length ? arr.reduce((s, x) => s + x, 0) / arr.length : 0);
const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
const PRIORITIES = ['P1', 'P2', 'P3', 'P4'];
const R7_NORMAL = { Critical: 'Critical', Severe: 'High', Moderate: 'Medium' };

export const isOpen = (f) => f.status !== 'Remediated';
const openAt = (f, d) => f.detectedAgo >= d && !(f.status === 'Remediated' && f.remediatedAgo >= d);

export function scope(company) {
  const all = !company || company === 'all';
  return {
    assets: all ? store.assets : store.assets.filter((a) => a.company === company),
    findings: all ? store.findings : store.findings.filter((f) => f.company === company),
  };
}

const K = 0.38;
export function exposureScore(findings, assetCount, d = 0) {
  let w = 0;
  for (const f of findings) if (openAt(f, d)) w += (f.risk / 100) ** 3;
  return Math.round(100 * (1 - Math.exp(-w / (Math.max(1, assetCount) * K))));
}

const gradeFor = (score) => (score < 30 ? 'A' : score < 40 ? 'B' : score < 50 ? 'C' : score < 60 ? 'D' : 'E');

function slaCompliance(findings, windowDays = 90) {
  const rel = findings.filter((f) => f.sla !== 'Exception' && (f.status === 'Open' || f.remediatedAgo <= windowDays) && f.detectedAgo <= windowDays + 90);
  const ok = rel.filter((f) => ['Met', 'On track', 'Due soon'].includes(f.sla)).length;
  return pct(ok, rel.length);
}
function mttr(findings, from = 0, to = 90) {
  return round1(avg(findings.filter((f) => f.status === 'Remediated' && f.remediatedAgo >= from && f.remediatedAgo < to).map((f) => f.detectedAgo - f.remediatedAgo)));
}
function mtti(findings, source) {
  const rel = findings.filter((f) => f.detectedAgo <= 120 && (!source || f.detected[source] !== undefined));
  return round1(avg(rel.map((f) => f.exposureAgo - (source ? f.detected[source] : f.detectedAgo))));
}
function coverage(assets) {
  const both = assets.filter((a) => a.mde && a.r7).length;
  const mde = assets.filter((a) => a.mde && !a.r7).length;
  const r7 = assets.filter((a) => a.r7 && !a.mde).length;
  const none = assets.length - both - mde - r7;
  return { total: assets.length, both, mdeOnly: mde, r7Only: r7, none, pct: pct(assets.length - none, assets.length) };
}

export function kpis(company) {
  const { assets, findings } = scope(company);
  const open = findings.filter(isOpen);
  const open28 = findings.filter((f) => openAt(f, 28));
  const raw = findings.reduce((s, f) => s + f.sources.length, 0);
  return {
    exposureScore: exposureScore(findings, assets.length),
    exposureScorePrev: exposureScore(findings, assets.length, 28),
    openFindings: open.length,
    openFindingsPrev: open28.length,
    openP1: open.filter((f) => f.priority === 'P1').length,
    openP2: open.filter((f) => f.priority === 'P2').length,
    openUrgentPrev: open28.filter((f) => f.priority === 'P1' || f.priority === 'P2').length,
    kevOpen: open.filter((f) => catalogById[f.cve].kev).length,
    kevOpenPrev: open28.filter((f) => catalogById[f.cve].kev).length,
    breached: open.filter((f) => f.sla === 'Breached').length,
    slaCompliance: slaCompliance(findings),
    mttr: mttr(findings),
    mttrPrev: mttr(findings, 90, 180),
    mtti: mtti(findings),
    mttiR7: mtti(findings, 'R7'),
    mttiMde: mtti(findings, 'MDE'),
    coverage: coverage(assets),
    rawFindings: raw,
    unifiedFindings: findings.length,
    duplicatesRemoved: raw - findings.length,
    assets: assets.length,
  };
}

export function trend(company, weeks = 13) {
  const { assets, findings } = scope(company);
  const out = [];
  for (let w = weeks - 1; w >= 0; w--) {
    const d = w * 7;
    const open = findings.filter((f) => openAt(f, d));
    out.push({
      date: isoAgo(d),
      exposure: exposureScore(findings, assets.length, d),
      open: open.length,
      urgent: open.filter((f) => f.priority === 'P1' || f.priority === 'P2').length,
      kev: open.filter((f) => catalogById[f.cve].kev).length,
      detected: findings.filter((f) => f.detectedAgo < d + 7 && f.detectedAgo >= d).length,
      remediated: findings.filter((f) => f.status === 'Remediated' && f.remediatedAgo < d + 7 && f.remediatedAgo >= d).length,
    });
  }
  return out;
}

export function scorecard() {
  return COMPANIES.map((co) => {
    const k = kpis(co.id);
    const t = trend(co.id);
    return {
      id: co.id, name: co.name, short: co.short, sector: co.sector, hq: co.hq, owner: co.owner,
      exposureScore: k.exposureScore,
      exposureDelta: k.exposureScore - k.exposureScorePrev,
      grade: gradeFor(k.exposureScore),
      openP1: k.openP1, openP2: k.openP2, kevOpen: k.kevOpen, breached: k.breached,
      openFindings: k.openFindings,
      slaCompliance: k.slaCompliance, mttr: k.mttr, coverage: k.coverage.pct, assets: k.assets,
      scanCadence: co.scanDays,
      spark: t.map((p) => p.exposure),
    };
  });
}

export function priorityByCompany() {
  return COMPANIES.map((co) => {
    const open = store.findings.filter((f) => f.company === co.id && isOpen(f));
    const row = { id: co.id, name: co.short };
    PRIORITIES.forEach((p) => { row[p] = open.filter((f) => f.priority === p).length; });
    return row;
  });
}

function aggregate(findings) {
  const map = new Map();
  for (const f of findings) {
    let g = map.get(f.cve);
    if (!g) {
      const c = catalogById[f.cve];
      g = {
        cve: f.cve, title: c.title, product: c.product, cvss: c.cvss, epss: c.epss, kev: c.kev, exploit: c.exploit,
        category: c.category || 'Vulnerability', published: c.published,
        maxRisk: 0, priority: 'P4', assets: new Set(), companies: new Set(), sources: new Set(),
        oldestAgo: 0, breached: 0, open: 0, remediated: 0, dueSoon: 0, internetFacing: 0,
      };
      map.set(f.cve, g);
    }
    const a = store.assetById[f.assetId];
    if (f.risk > g.maxRisk) { g.maxRisk = f.risk; g.priority = f.priority; }
    g.assets.add(f.assetId);
    g.companies.add(f.company);
    g.sources.add(f.sources.length === 2 ? 'Both' : f.sources[0]);
    if (isOpen(f)) { g.open++; g.oldestAgo = Math.max(g.oldestAgo, f.detectedAgo); if (a.internetFacing) g.internetFacing++; } else g.remediated++;
    if (f.sla === 'Breached') g.breached++;
    if (f.sla === 'Due soon') g.dueSoon++;
  }
  return [...map.values()].map((g) => {
    const t = store.tickets.filter((t) => t.cve === g.cve && g.companies.has(t.company));
    return {
      ...g,
      assets: g.assets.size,
      companies: [...g.companies],
      sources: [...g.sources],
      oldestDays: Math.floor(g.oldestAgo),
      tickets: t.map((x) => x.id),
      ticketCoverage: g.companies.size ? t.length / g.companies.size : 0,
    };
  });
}

export function topRisks(company, n = 6) {
  const open = scope(company).findings.filter(isOpen);
  const weight = new Map();
  for (const f of open) weight.set(f.cve, (weight.get(f.cve) || 0) + (f.risk / 100) ** 3);
  return aggregate(open)
    .map((g) => ({ ...g, contribution: Math.round(weight.get(g.cve) * 10) / 10 }))
    .sort((a, b) => a.priority.localeCompare(b.priority) || b.contribution - a.contribution)
    .slice(0, n);
}

export function vulnerabilities(q) {
  let { findings } = scope(q.company);
  const status = q.status || 'open';
  if (status === 'open') findings = findings.filter(isOpen);
  if (status === 'remediated') findings = findings.filter((f) => f.status === 'Remediated');
  if (q.priority) { const set = new Set(q.priority.split(',')); findings = findings.filter((f) => set.has(f.priority)); }
  if (q.source === 'Both') findings = findings.filter((f) => f.sources.length === 2);
  else if (q.source === 'MDE' || q.source === 'R7') findings = findings.filter((f) => f.sources.length === 1 && f.sources[0] === q.source);
  if (q.sla) findings = findings.filter((f) => f.sla === q.sla);
  if (q.kev === 'true') findings = findings.filter((f) => catalogById[f.cve].kev);
  if (q.internet === 'true') findings = findings.filter((f) => store.assetById[f.assetId].internetFacing);
  let rows = aggregate(findings);
  if (q.q) {
    const s = q.q.toLowerCase();
    rows = rows.filter((r) => r.cve.toLowerCase().includes(s) || r.title.toLowerCase().includes(s) || r.product.toLowerCase().includes(s));
  }
  const sorters = {
    risk: (a, b) => b.maxRisk - a.maxRisk || b.assets - a.assets,
    assets: (a, b) => b.assets - a.assets,
    age: (a, b) => b.oldestDays - a.oldestDays,
    cvss: (a, b) => b.cvss - a.cvss,
    breached: (a, b) => b.breached - a.breached,
  };
  rows.sort(sorters[q.sort] || sorters.risk);
  return { total: rows.length, findings: findings.length, rows };
}

const fmtFinding = (f) => {
  const a = store.assetById[f.assetId];
  return {
    id: f.id, assetId: a.id, hostname: a.hostname, company: a.company, companyName: coById[a.company].short,
    type: a.type, os: a.os, site: a.site, criticality: a.criticality, internetFacing: a.internetFacing, owner: a.owner, service: a.service,
    sources: f.sources, risk: f.risk, priority: f.priority, status: f.status, sla: f.sla,
    detectedAt: isoAgo(f.detectedAgo), ageDays: Math.floor(f.detectedAgo),
    dueInDays: Math.round(f.slaDays - f.detectedAgo),
    remediatedAt: f.remediatedAgo != null ? isoAgo(f.remediatedAgo) : null,
    detectedBy: Object.fromEntries(Object.entries(f.detected).map(([k, v]) => [k, isoAgo(v)])),
  };
};

export function vulnDetail(cve, company) {
  const c = catalogById[cve];
  if (!c) return null;
  const all = scope(company).findings.filter((f) => f.cve === cve);
  const open = all.filter(isOpen);
  const top = [...(open.length ? open : all)].sort((a, b) => b.risk - a.risk)[0];
  const topAsset = top ? store.assetById[top.assetId] : null;
  const both = all.filter((f) => f.sources.length === 2).length;
  const byCompany = COMPANIES.map((co) => ({
    id: co.id, name: co.short,
    open: open.filter((f) => f.company === co.id).length,
    breached: open.filter((f) => f.company === co.id && f.sla === 'Breached').length,
    ticket: store.tickets.find((t) => t.cve === cve && t.company === co.id) || null,
  })).filter((x) => x.open > 0);
  const affectedTypes = [...new Set(open.map((f) => store.assetById[f.assetId].type))];
  return {
    cve: c.id, title: c.title, product: c.product, cvss: c.cvss, epss: c.epss, kev: c.kev, exploit: c.exploit,
    category: c.category || 'Vulnerability', published: c.published, fix: c.fix, compensating: c.compensating,
    risk: top ? computeRisk(c, topAsset) : null,
    riskAsset: topAsset ? topAsset.hostname : null,
    sourceView: {
      r7: c.detect.r7 ? { label: c.r7Sev, normalized: R7_NORMAL[c.r7Sev], riskScore: Math.round(c.cvss * 72 + (c.kev ? 160 : 0) + c.epss * 90), instances: all.filter((f) => f.sources.includes('R7')).length } : null,
      mde: c.detect.mde ? { label: c.mdeSev, normalized: c.mdeSev, instances: all.filter((f) => f.sources.includes('MDE')).length, exposureImpact: round1(c.cvss * (c.kev ? 1.1 : 0.8)) } : null,
      overlap: both,
      disagreement: c.detect.r7 && c.detect.mde && R7_NORMAL[c.r7Sev] !== c.mdeSev,
    },
    byCompany,
    instances: all.sort((a, b) => (isOpen(b) - isOpen(a)) || b.risk - a.risk).map(fmtFinding),
    ai: aiGuidance(c, open, affectedTypes, byCompany),
  };
}

function aiGuidance(c, open, types, byCompany) {
  const internet = open.filter((f) => store.assetById[f.assetId].internetFacing).length;
  const crown = open.filter((f) => store.assetById[f.assetId].tier === 1).length;
  const breached = open.filter((f) => f.sla === 'Breached').length;
  const worst = [...byCompany].sort((a, b) => b.open - a.open)[0];
  const lines = [];
  if (!open.length) lines.push(`All known instances of ${c.id} are remediated. Keep the detection rule active to catch regressions from re-imaged or restored hosts.`);
  else {
    lines.push(`${c.id} is open on **${open.length} asset${open.length > 1 ? 's' : ''}** across **${byCompany.length} group compan${byCompany.length > 1 ? 'ies' : 'y'}**${worst ? `, concentrated in ${worst.name} (${worst.open})` : ''}.`);
    if (c.kev) lines.push('It is listed in the **CISA Known Exploited Vulnerabilities** catalogue — treat it as an active threat, not a theoretical one.');
    if (internet) lines.push(`**${internet}** affected asset${internet > 1 ? 's are' : ' is'} internet-facing, which is the most likely initial-access path.`);
    if (crown) lines.push(`${crown} instance${crown > 1 ? 's sit' : ' sits'} on crown-jewel services — coordinate the change window with the service owner.`);
    if (breached) lines.push(`${breached} instance${breached > 1 ? 's have' : ' has'} already breached the SHV SLA; escalate through the BU security lead.`);
  }
  return {
    summary: lines,
    steps: [
      internet ? 'Patch internet-facing instances first (or apply the compensating control within 24h).' : 'Group instances into a single patch campaign per company.',
      c.fix,
      `Verify closure: MDE confirms within ~24h of patching; ${c.detect.r7 ? 'Rapid7 confirms on the next scheduled scan.' : 'Rapid7 does not assess this weakness.'}`,
    ],
    compensating: c.compensating,
    affectedTypes: types,
    model: 'Simulated GenAI (Azure OpenAI in production)',
  };
}

export function assetsList(q) {
  let { assets } = scope(q.company);
  if (q.type) assets = assets.filter((a) => a.type === q.type);
  if (q.coverage === 'both') assets = assets.filter((a) => a.mde && a.r7);
  if (q.coverage === 'mde') assets = assets.filter((a) => a.mde && !a.r7);
  if (q.coverage === 'r7') assets = assets.filter((a) => a.r7 && !a.mde);
  if (q.coverage === 'none') assets = assets.filter((a) => !a.mde && !a.r7);
  if (q.internet === 'true') assets = assets.filter((a) => a.internetFacing);
  if (q.q) { const s = q.q.toLowerCase(); assets = assets.filter((a) => a.hostname.toLowerCase().includes(s) || a.os.toLowerCase().includes(s) || a.service.toLowerCase().includes(s) || a.ip.includes(s)); }
  const byAsset = new Map();
  for (const f of store.findings) if (isOpen(f)) { const l = byAsset.get(f.assetId) || []; l.push(f); byAsset.set(f.assetId, l); }
  const rows = assets.map((a) => {
    const fs = byAsset.get(a.id) || [];
    const top = fs.sort((x, y) => y.risk - x.risk)[0];
    return {
      id: a.id, hostname: a.hostname, company: a.company, companyName: coById[a.company].short, type: a.type, os: a.os, site: a.site, ip: a.ip,
      service: a.service, criticality: a.criticality, tier: a.tier, internetFacing: a.internetFacing, owner: a.owner,
      mde: a.mde, r7: a.r7, discovery: a.discovery, matchMethod: a.matchMethod, matchConfidence: a.matchConfidence,
      openFindings: fs.length, maxRisk: top ? top.risk : 0, topCve: top ? top.cve : null,
      breached: fs.filter((f) => f.sla === 'Breached').length,
      lastSeen: isoAgo(a.lastSeenAgo),
    };
  }).sort((x, y) => y.maxRisk - x.maxRisk || y.openFindings - x.openFindings);
  const types = ['Workstation', 'Server', 'Cloud VM', 'Network Device', 'OT / IoT'];
  const all = scope(q.company).assets;
  return {
    total: rows.length,
    rows,
    coverage: coverage(all),
    byType: types.map((t) => ({ type: t, ...coverage(all.filter((a) => a.type === t)) })).filter((x) => x.total > 0),
    discovery: {
      mdeDiscovered: all.filter((a) => a.discovery && a.discovery.startsWith('MDE')).length,
      cmdbOnly: all.filter((a) => a.discovery === 'CMDB only').length,
    },
  };
}

export function assetDetail(id) {
  const a = store.assetById[id];
  if (!a) return null;
  const fs = store.findings.filter((f) => f.assetId === id).sort((x, y) => (isOpen(y) - isOpen(x)) || y.risk - x.risk);
  return {
    ...a, companyName: coById[a.company].short, lastSeen: isoAgo(a.lastSeenAgo),
    findings: fs.map((f) => ({ ...fmtFinding(f), cve: f.cve, title: catalogById[f.cve].title, kev: catalogById[f.cve].kev })),
  };
}

// How Rapid7 spells a device whose match to Defender is uncertain.
export function r7NameFor(a) {
  const variants = [`${a.hostname.toLowerCase()}.${a.company}.local`, a.hostname.replace(/-/g, ''), `${a.hostname}-OLD`, a.hostname.toLowerCase()];
  return variants[a.hostname.length % variants.length];
}
// Uncertain matches still waiting for a person; the asset-match agent clears the confident ones.
export const needsReview = (a) => a.matchMethod === 'Fuzzy hostname' && a.agentReviewed !== 'rejected' && a.agentReviewed !== 'separate';

export function reconciliation(company) {
  const { assets, findings } = scope(company);
  const mde = findings.filter((f) => f.sources.includes('MDE')).length;
  const r7 = findings.filter((f) => f.sources.includes('R7')).length;
  const both = findings.filter((f) => f.sources.length === 2).length;
  const types = ['Workstation', 'Server', 'Cloud VM', 'Network Device', 'OT / IoT'];
  const uniqueByType = types.map((t) => {
    const fs = findings.filter((f) => store.assetById[f.assetId].type === t);
    return {
      type: t,
      mdeOnly: fs.filter((f) => f.sources.join() === 'MDE').length,
      both: fs.filter((f) => f.sources.length === 2).length,
      r7Only: fs.filter((f) => f.sources.join() === 'R7').length,
    };
  }).filter((x) => x.mdeOnly + x.both + x.r7Only > 0);

  const disagreements = CATALOG.filter((c) => c.detect.r7 && c.detect.mde && R7_NORMAL[c.r7Sev] !== c.mdeSev).map((c) => {
    const fs = findings.filter((f) => f.cve === c.id && f.sources.length === 2);
    const pr = {}; PRIORITIES.forEach((p) => { pr[p] = fs.filter((f) => f.priority === p).length; });
    return { cve: c.id, title: c.title, r7: c.r7Sev, r7Normalized: R7_NORMAL[c.r7Sev], mde: c.mdeSev, instances: fs.length, unified: pr };
  }).filter((d) => d.instances > 0).sort((a, b) => b.instances - a.instances);

  const matched = assets.filter((a) => a.matchMethod);
  const methods = ['Entra device ID + hostname', 'Hostname + IP address', 'MAC + IP address', 'Agent-verified match', 'Fuzzy hostname'].map((m) => ({ method: m, count: matched.filter((a) => a.matchMethod === m).length }));
  const review = matched.filter(needsReview).map((a) => {
    const co = coById[a.company];
    return {
      assetId: a.id, companyName: co.short, mdeName: a.hostname, r7Name: r7NameFor(a), agent: a.agentReviewed || null,
      ip: a.ip, confidence: a.matchConfidence, reason: a.matchConfidence < 70 ? 'IP reassigned by DHCP since last scan' : 'Hostname format differs between tools',
    };
  });
  return {
    raw: { mde, r7, total: mde + r7, unified: findings.length, both, mdeOnly: mde - both, r7Only: r7 - both, duplicateRate: pct(both * 2, mde + r7) },
    uniqueByType,
    disagreements,
    disagreementInstances: disagreements.reduce((s, d) => s + d.instances, 0),
    matching: { methods, matchedAssets: matched.length, review },
    mtti: { unified: mtti(findings), mde: mtti(findings, 'MDE'), r7: mtti(findings, 'R7') },
    blindSpots: company && company !== 'all' ? null : store.blindSpots,
  };
}

export function remediation(company) {
  const { findings } = scope(company);
  const open = findings.filter(isOpen);
  const companies = !company || company === 'all' ? COMPANIES : COMPANIES.filter((c) => c.id === company);
  const slaMatrix = companies.map((co) => {
    const fs = findings.filter((f) => f.company === co.id);
    const row = { id: co.id, name: co.short, overall: slaCompliance(fs) };
    PRIORITIES.forEach((p) => { row[p] = slaCompliance(fs.filter((f) => f.priority === p)); });
    return row;
  });
  const buckets = [['0–7 d', 0, 7], ['8–30 d', 7, 30], ['31–60 d', 30, 60], ['61–90 d', 60, 90], ['90+ d', 90, 1e9]].map(([label, lo, hi]) => {
    const row = { label };
    PRIORITIES.forEach((p) => { row[p] = open.filter((f) => f.priority === p && f.detectedAgo >= lo && f.detectedAgo < hi).length; });
    return row;
  });
  const overdueMap = new Map();
  for (const f of open.filter((x) => x.sla === 'Breached')) {
    const key = `${f.cve}|${f.company}`;
    const a = store.assetById[f.assetId];
    const g = overdueMap.get(key) || { cve: f.cve, title: catalogById[f.cve].title, company: f.company, companyName: coById[f.company].short, assets: 0, maxRisk: 0, priority: 'P4', daysOverdue: 0, owner: a.owner, kev: catalogById[f.cve].kev };
    g.assets++;
    if (f.risk > g.maxRisk) { g.maxRisk = f.risk; g.priority = f.priority; g.owner = a.owner; }
    g.daysOverdue = Math.max(g.daysOverdue, Math.floor(f.detectedAgo - f.slaDays));
    overdueMap.set(key, g);
  }
  const overdue = [...overdueMap.values()].map((g) => ({ ...g, ticket: store.tickets.find((t) => t.cve === g.cve && t.company === g.company) || null }))
    .sort((a, b) => b.maxRisk - a.maxRisk || b.daysOverdue - a.daysOverdue);

  const owners = new Map();
  for (const f of findings) {
    const o = store.assetById[f.assetId].owner;
    const l = owners.get(o) || []; l.push(f); owners.set(o, l);
  }
  const leaderboard = [...owners.entries()].map(([owner, fs]) => ({
    owner,
    open: fs.filter(isOpen).length,
    breached: fs.filter((f) => f.sla === 'Breached').length,
    compliance: slaCompliance(fs),
    mttr: mttr(fs),
  })).filter((x) => x.open > 0).sort((a, b) => a.compliance - b.compliance);

  const monthly = [];
  for (let m = 5; m >= 0; m--) {
    const lo = m * 30, hi = lo + 30;
    const rem = findings.filter((f) => f.status === 'Remediated' && f.remediatedAgo >= lo && f.remediatedAgo < hi);
    monthly.push({ date: isoAgo(lo), met: pct(rem.filter((f) => f.sla === 'Met').length, rem.length), closed: rem.length, mttr: round1(avg(rem.map((f) => f.detectedAgo - f.remediatedAgo))) });
  }
  return {
    policy: SLA_POLICY,
    compliance: slaCompliance(findings),
    breached: open.filter((f) => f.sla === 'Breached').length,
    dueSoon: open.filter((f) => f.sla === 'Due soon').length,
    exceptions: open.filter((f) => f.sla === 'Exception').length,
    mttrByPriority: PRIORITIES.map((p) => ({ priority: p, mttr: mttr(findings.filter((f) => f.priority === p)), target: SLA_POLICY.find((s) => s.priority === p).days })),
    slaMatrix, buckets, overdue, leaderboard, monthly,
    flow: trend(company),
  };
}

export function searchAll(q) {
  const s = (q || '').toLowerCase().trim();
  if (!s) return { vulns: [], assets: [] };
  const vulns = CATALOG.filter((c) => c.id.toLowerCase().includes(s) || c.title.toLowerCase().includes(s) || c.product.toLowerCase().includes(s))
    .slice(0, 6).map((c) => ({ cve: c.id, title: c.title, kev: c.kev, open: store.findings.filter((f) => f.cve === c.id && isOpen(f)).length }));
  const assets = store.assets.filter((a) => a.hostname.toLowerCase().includes(s) || a.ip.includes(s) || a.service.toLowerCase().includes(s))
    .slice(0, 6).map((a) => ({ id: a.id, hostname: a.hostname, company: coById[a.company].short, type: a.type, service: a.service }));
  return { vulns, assets };
}
