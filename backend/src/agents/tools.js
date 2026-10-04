// Tools the agents can call. Read tools look at the unified store and, where a fresh view helps, go
// back to the source system through its connector. Action tools are only ever executed by the
// orchestrator after guardrails, never directly by a model.
import { COMPANIES } from '../data/companies.js';
import { catalogById } from '../data/catalog.js';
import { store } from '../data/generator.js';
import { defender, rapid7, servicenow, soc } from '../connectors/index.js';
import { shortHost } from '../ingest/correlate.js';
import { kpis, topRisks, vulnerabilities, vulnDetail, assetsList, reconciliation, remediation, trend, scorecard, isOpen } from '../analytics.js';

export const coShort = Object.fromEntries(COMPANIES.map((c) => [c.id, c.short]));
const pct = (x) => `${Math.round(x * 100)}%`;
const findAsset = (ref) => store.assetById[ref] || store.assets.find((a) => a.hostname.toLowerCase() === String(ref || '').toLowerCase() || shortHost(a.fqdn) === shortHost(ref));

// ---------------- context about one finding ----------------
export function getAsset({ asset_id }) {
  const a = findAsset(asset_id);
  if (!a) return { error: `No asset ${asset_id}` };
  const open = store.findings.filter((f) => f.assetId === a.id && isOpen(f));
  return {
    asset_id: a.id, hostname: a.hostname, company: coShort[a.company], type: a.type, os: a.os, site: a.site,
    business_service: a.service, criticality: a.criticality, tier: a.tier, internet_facing: a.internetFacing, owner_team: a.owner,
    seen_by: [a.mde && 'Defender', a.r7 && 'Rapid7'].filter(Boolean), open_findings: open.length,
    summary: `${a.type} · ${a.os} · ${a.criticality} (${a.service}) · ${a.internetFacing ? 'internet-facing' : 'internal only'} · owner: ${a.owner}`,
  };
}

export function threatIntel({ cve }) {
  const c = catalogById[cve];
  if (!c) return { error: `Unknown vulnerability ${cve}` };
  const inst = store.findings.filter((f) => f.cve === cve && isOpen(f));
  return {
    cve, title: c.title, product: c.product, cvss: c.cvss, epss: c.epss, in_cisa_kev: c.kev, exploit_maturity: c.exploit,
    published: c.published, vendor_fix: c.fix, open_instances_in_estate: inst.length, companies_affected: [...new Set(inst.map((f) => coShort[f.company]))],
    summary: `CVSS ${c.cvss} · EPSS ${pct(c.epss)} · ${c.kev ? 'in CISA KEV (exploited in the wild)' : 'not in CISA KEV'} · exploit: ${c.exploit} · ${inst.length} open instances`,
  };
}

export function compensatingControls({ asset_id }) {
  const a = findAsset(asset_id);
  if (!a) return { error: `No asset ${asset_id}` };
  const ctl = a.controls || '';
  return { asset_id: a.id, registered_controls: ctl || null, source: 'ServiceNow CMDB (u_compensating_controls)', summary: ctl ? `Registered: ${ctl}` : 'No compensating control registered for this asset' };
}

export function searchTickets({ cve, company }) {
  const co = COMPANIES.find((c) => c.id === company || c.short === company)?.id || company;
  const ts = store.tickets.filter((t) => t.cve === cve && (!co || t.company === co) && t.state !== 'Resolved');
  return { open_tickets: ts.map((t) => ({ id: t.id, state: t.state, assignee: t.assignee, company: coShort[t.company] })), summary: ts.length ? `${ts.map((t) => `${t.id} (${t.state})`).join(', ')} already open` : 'No open ticket for this vulnerability here' };
}

// ---------------- actions (orchestrator only) ----------------
export async function createTicket(f, { priority = 'Normal', by = 'Triage Agent', note = '' } = {}) {
  const a = store.assetById[f.assetId];
  const c = catalogById[f.cve];
  const res = await servicenow.createTicket({
    shortDescription: `[${f.priority}${priority === 'Emergency' ? ' · EMERGENCY' : ''}] ${f.cve} on ${a.hostname}: ${c.title}`.slice(0, 160),
    description: `${c.title}\nAsset: ${a.hostname} (${a.service}, ${a.criticality})\nRisk ${f.risk}/100 · fix within ${f.slaDays} days\nFix: ${c.fix}\n${note}\nRaised by ExposureIQ ${by}`,
    assignmentGroup: a.owner, urgency: priority === 'Emergency' || f.priority === 'P1' ? 1 : 2, impact: a.tier, ci: a.cmdbSysId,
  });
  const t = { id: res.number, sysId: res.sys_id, cve: f.cve, company: f.company, createdAgo: 0, state: 'New', assignee: a.owner, createdBy: `${by} (AI)`, assets: 1, priority };
  store.tickets.push(t);
  return t;
}

export async function notifySoc(text) {
  return soc.notify(text);
}

// ---------------- device identity (asset-match agent) ----------------
const trimDefender = (m) => m && { id: m.id, computerDnsName: m.computerDnsName, lastIpAddress: m.lastIpAddress, mac: m.ipAddresses?.[0]?.macAddress, osPlatform: m.osPlatform, aadDeviceId: m.aadDeviceId, rbacGroupName: m.rbacGroupName, lastSeen: m.lastSeen };
const trimR7 = (r) => r && { id: r.id, hostName: r.hostName, ip: r.ip, mac: r.mac, os: r.os || r.osFingerprint?.description };
const trimCi = (c) => c && { sys_id: c.sys_id, name: c.name, fqdn: c.fqdn, ip_address: c.ip_address, mac_address: c.mac_address, serial_number: c.serial_number, os: c.os, location: c.location, support_group: c.support_group };
const macNorm = (m) => (m ? String(m).replace(/[^0-9a-f]/gi, '').toUpperCase() : '');

export async function cmdbRecord({ asset_id }) {
  const a = findAsset(asset_id);
  const ci = a && trimCi(await servicenow.ci(a.cmdbSysId));
  return ci ? { ...ci, summary: `CI ${ci.name} · ${ci.ip_address} · MAC ${ci.mac_address} · ${ci.os} · ${ci.location}` } : { error: 'No CMDB record linked' };
}
export async function defenderDevice({ asset_id }) {
  const a = findAsset(asset_id);
  const m = a && trimDefender(await defender.machine(a.mdeId));
  return m ? { ...m, summary: `${m.computerDnsName} · IP ${m.lastIpAddress} · MAC ${m.mac} · ${m.osPlatform}${m.aadDeviceId ? ` · Entra ${m.aadDeviceId.slice(0, 8)}…` : ''}` } : { error: 'Not onboarded to Defender' };
}
export async function rapid7Asset({ asset_id }) {
  const a = findAsset(asset_id);
  const r = a && trimR7(await rapid7.asset(a.r7Id));
  return r ? { ...r, summary: `${r.hostName} · IP ${r.ip} · MAC ${r.mac} · ${r.os}` } : { error: 'Not in Rapid7' };
}
export async function compareIdentities({ asset_id }) {
  const a = findAsset(asset_id);
  if (!a) return { error: `No asset ${asset_id}` };
  const [m, r, ci] = await Promise.all([defender.machine(a.mdeId), rapid7.asset(a.r7Id), servicenow.ci(a.cmdbSysId)]);
  const dm = trimDefender(m);
  const rr = trimR7(r);
  const name = (x) => shortHost(x || '');
  const base = (x) => name(x).replace(/-old$/, '').replace(/[^a-z0-9]/g, '');
  const hostname = !dm || !rr ? 'missing' : name(dm.computerDnsName) === name(rr.hostName) ? 'identical' : base(dm.computerDnsName) === base(rr.hostName) ? (name(rr.hostName).endsWith('-old') ? 'same base name, Rapid7 has "-OLD" suffix' : 'same after removing punctuation') : 'different';
  const mac = !dm?.mac || !rr?.mac ? 'missing' : macNorm(dm.mac) === macNorm(rr.mac) ? 'identical' : 'different';
  const ip = !dm || !rr ? 'missing' : dm.lastIpAddress === rr.ip ? 'identical' : 'different';
  const cmdbMac = ci?.mac_address && rr?.mac ? (macNorm(ci.mac_address) === macNorm(rr.mac) ? 'Rapid7 MAC matches CMDB' : 'Rapid7 MAC differs from CMDB') : 'no CMDB MAC';
  const os = dm && rr ? (String(rr.os || '').toLowerCase().includes(String(dm.osPlatform || '').toLowerCase().replace(/(\d+)/, ' $1').trim().split(' ')[0]) ? 'consistent' : 'unclear') : 'missing';
  return { asset_id: a.id, hostname, mac, ip, cmdb_mac: cmdbMac, os, summary: `Name: ${hostname} · MAC: ${mac} · IP: ${ip} · ${cmdbMac} · OS: ${os}` };
}

// ---------------- planning ----------------
export function openFindingsSummary({ company, limit = 30 }) {
  const co = COMPANIES.find((c) => c.id === company || c.short === company)?.id;
  const open = store.findings.filter((f) => f.status === 'Open' && (f.priority === 'P1' || f.priority === 'P2') && (!co || f.company === co));
  const groups = new Map();
  for (const f of open) {
    const a = store.assetById[f.assetId];
    const k = `${a.owner}|${f.cve}`;
    const g = groups.get(k) || { team: a.owner, company: coShort[f.company], cve: f.cve, title: catalogById[f.cve].title, findings: 0, p1: 0, kev: catalogById[f.cve].kev, asset_types: new Set(), weight: 0, oldest_days: 0 };
    g.findings++;
    if (f.priority === 'P1') g.p1++;
    g.asset_types.add(a.type);
    g.weight += (f.risk / 100) ** 3;
    g.oldest_days = Math.max(g.oldest_days, Math.round(f.detectedAgo));
    groups.set(k, g);
  }
  const all = [...groups.values()].sort((x, y) => y.weight - x.weight);
  const total = all.reduce((s, g) => s + g.weight, 0) || 1;
  const rows = all.slice(0, limit).map((g) => ({ ...g, asset_types: [...g.asset_types], share_of_urgent_risk: pct(g.weight / total), weight: undefined }));
  return { open_urgent_findings: open.length, owner_teams: new Set(open.map((f) => store.assetById[f.assetId].owner)).size, groups: rows, summary: `${open.length} open P1/P2 findings in ${all.length} (team, fix) groups; top ${Math.min(limit, all.length)} returned` };
}

export const CHANGE_WINDOWS = [
  { id: 'emergency-cab', name: 'Emergency CAB · within 48 h', for: 'P1 or actively exploited on internet-facing / crown-jewel assets' },
  { id: 'ws-ring1', name: 'Wed 20:00 · workstation ring 1', for: 'Workstations' },
  { id: 'srv-thu', name: 'Thu 22:00–02:00 CET · server window', for: 'Servers and cloud VMs' },
  { id: 'net-sun', name: 'Sun 01:00 · network window', for: 'Network devices' },
  { id: 'ot-board', name: 'Next planned stop · OT change board', for: 'OT / IoT' },
];
export function changeCalendar() {
  return { windows: CHANGE_WINDOWS, summary: CHANGE_WINDOWS.map((w) => w.name).join(' · ') };
}

// ---------------- read tools for the copilot ----------------
const top = (rows, n = 12) => rows.slice(0, n);
export const READ = {
  get_kpis: ({ company }) => { const k = kpis(company); return { ...k, summary: `exposure ${k.exposureScore}/100 · ${k.openP1 + k.openP2} open P1/P2 · ${k.kevOpen} KEV instances · SLA ${k.slaCompliance}% · MTTR ${k.mttr} d` }; },
  get_top_risks: ({ company, n = 8 }) => { const r = topRisks(company, n); return { risks: r.map((x) => ({ cve: x.cve, title: x.title, max_risk: x.maxRisk, kev: x.kev, assets: x.assets, companies: x.companies })), summary: `${r.length} vulnerabilities ranked by risk contribution` }; },
  query_findings: (q) => { const r = vulnerabilities({ company: q.company, priority: q.priority, kev: q.kev ? 'true' : undefined, internet: q.internet_facing ? 'true' : undefined, q: q.text }); return { total: r.total, rows: top(r.rows).map((x) => ({ cve: x.cve, title: x.title, priority: x.priority, max_risk: x.maxRisk, kev: x.kev, open: x.open, assets: x.assets, breached: x.breached, companies: x.companies })), summary: `${r.total} matching vulnerabilities` }; },
  get_vulnerability: ({ cve }) => { const d = vulnDetail(cve); if (!d) return { error: `${cve} not present in the estate` }; return { cve: d.cve, title: d.title, cvss: d.cvss, epss: d.epss, kev: d.kev, exploit: d.exploit, fix: d.fix, by_company: d.byCompany?.map((c) => ({ company: c.name, open: c.open, breached: c.breached })), summary: `${d.title} · CVSS ${d.cvss}${d.kev ? ' · KEV' : ''}` }; },
  get_scorecard: () => { const s = scorecard(); return { companies: s.map((c) => ({ company: c.short, grade: c.grade, exposure: c.exposureScore, delta_4w: c.exposureDelta, open_p1_p2: c.openP1 + c.openP2, kev: c.kevOpen, sla: c.slaCompliance, mttr_days: c.mttr, coverage: c.coverage })), summary: `${s.length} companies scored on one model` }; },
  get_remediation: ({ company }) => { const r = remediation(company); return { sla_compliance: r.compliance, breached: r.breached, due_soon: r.dueSoon, mttr_by_priority: r.mttrByPriority, overdue: top(r.overdue || [], 10).map((o) => ({ cve: o.cve, title: o.title, company: o.companyName, assets: o.assets, priority: o.priority, days_overdue: o.daysOverdue, owner: o.owner, kev: o.kev })), summary: `${r.breached} past SLA · ${r.dueSoon} due soon` }; },
  get_reconciliation: ({ company }) => { const r = reconciliation(company); return { raw: r.raw, summary: `${r.raw.total} raw records → ${r.raw.unified} unique findings · ${r.raw.both} seen by both tools` }; },
  get_assets: (q) => { const r = assetsList({ company: q.company, coverage: q.coverage, internet: q.internet_facing ? 'true' : undefined, q: q.text }); return { total: r.total, coverage: r.coverage, rows: top(r.rows, 10).map((a) => ({ hostname: a.hostname, company: a.companyName, type: a.type, criticality: a.criticality, internet_facing: a.internetFacing, open_findings: a.openFindings, max_risk: a.maxRisk })), summary: `${r.total} assets · coverage ${r.coverage.pct}%` }; },
  get_trend: ({ company }) => { const t = trend(company); return { weeks: t.map((p) => ({ week: p.date.slice(0, 10), exposure: p.exposure, open: p.open, urgent: p.urgent, kev: p.kev })), summary: `exposure ${t[0].exposure} → ${t[t.length - 1].exposure} over ${t.length} weeks` }; },
};
