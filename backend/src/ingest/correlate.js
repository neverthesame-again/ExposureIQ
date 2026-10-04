// Normalise and correlate. Raw records from Defender, Rapid7, ServiceNow and the threat feeds come in
// here in their native API shapes and leave as ExposureIQ's unified model: one asset per real device
// and one finding per (asset, weakness), however many tools reported it. The same code handles the
// mock tenant and the real APIs.
import { COMPANIES } from '../data/companies.js';
import { CATALOG, catalogById } from '../data/catalog.js';
import { store, computeRisk, priorityFor, slaState, NOW, DAY } from '../data/generator.js';
import { canonicalFromDefender, canonicalFromRapid7 } from '../data/crosswalk.js';
import { config } from '../config.js';

const TIER_LABEL = { 1: 'Crown Jewel', 2: 'High', 3: 'Standard' };
const EXPLOIT_MDE = { ExploitIsInKit: 'Weaponized', ExploitIsVerified: 'Weaponized', ExploitIsPublic: 'Public PoC', NoExploit: 'None' };
const isOpen = (f) => f.status !== 'Remediated';

// ---------------- helpers ----------------
const parseTs = (ts) => (ts ? Date.parse(/Z|[+-]\d\d:?\d\d$/.test(ts) ? ts : `${String(ts).replace(' ', 'T')}Z`) : NaN);
export const daysAgo = (ts) => {
  const t = parseTs(ts);
  return Number.isFinite(t) ? Math.max(0, +((NOW - t) / DAY).toFixed(2)) : 0;
};
export const shortHost = (name = '') => String(name).split('.')[0].toLowerCase();
const hostBase = (name) => shortHost(name).replace(/-old$/, '').replace(/[^a-z0-9]/g, '');
const normMac = (m) => (m ? String(m).replace(/[^0-9a-f]/gi, '').toUpperCase().match(/../g)?.join(':') || null : null);

export function companyFor({ group, site, company, host } = {}) {
  const hay = [group, site, company].filter(Boolean).map((s) => s.toLowerCase());
  const byName = COMPANIES.find((c) => hay.some((h) => h.includes(c.short.toLowerCase()) || h.includes(c.name.toLowerCase()) || h.includes(c.id)));
  if (byName) return byName.id;
  const byPrefix = host && COMPANIES.find((c) => shortHost(host).startsWith(c.prefix.toLowerCase()));
  return byPrefix ? byPrefix.id : COMPANIES[0].id;
}

function typeFor(os = '', sysClass = '') {
  const s = `${os} ${sysClass}`.toLowerCase();
  if (/server|linux|ubuntu|rhel/.test(s) && /azure|cloud|vm/.test(s)) return 'Cloud VM';
  if (/server|linux|ubuntu|rhel|centos/.test(s)) return 'Server';
  if (/fortios|pan-os|ios xe|netscaler|ivanti|router|switch|firewall|network/.test(s)) return 'Network Device';
  if (/rockwell|hmi|plc|scada|iot|ot /.test(s)) return 'OT / IoT';
  return 'Workstation';
}

function tierFrom(value) {
  if (value == null || value === '') return null;
  const m = String(value).match(/[123]/);
  if (m) return Number(m[0]);
  return { high: 1, normal: 2, low: 3 }[String(value).toLowerCase()] || null;
}

let findingSeq = 0;
function nextFindingId() {
  if (!findingSeq) findingSeq = store.findings.reduce((m, f) => Math.max(m, Number(f.id.slice(2)) || 0), 0);
  return `F-${String(++findingSeq).padStart(6, '0')}`;
}

function createAsset({ hostname, fqdn, company, type, os, ip, mac, tier = 3, internetFacing = false, site = 'Unknown' }) {
  const co = COMPANIES.find((c) => c.id === company);
  let id = `${company}-${shortHost(hostname)}`;
  while (store.assetById[id]) id += '-x';
  return store.addAsset({
    id, hostname: shortHost(hostname).toUpperCase(), fqdn, company, type, os: os || 'Unknown', site, ip: ip || '', mac: normMac(mac),
    service: 'Unassigned (not in CMDB yet)', tier, criticality: TIER_LABEL[tier], internetFacing, tags: [],
    mde: false, r7: false, discovery: null, matchMethod: null, matchConfidence: null,
    owner: `${co.short} IT`, lastSeenAgo: 0, controls: '', discovered: true,
  });
}

// ---------------- vulnerability catalogue ----------------
export function ensureVuln(id, info) {
  let c = catalogById[id];
  if (!c) {
    c = {
      id, title: info.title || id, product: info.product || 'Unknown product', cvss: Number(info.cvss) || 5,
      epss: 0.01, kev: false, exploit: info.exploit || 'None', tags: [], prob: 0, detect: { mde: false, r7: false },
      r7Sev: null, mdeSev: null, published: info.published || null, fix: info.fix || 'Apply the vendor security update.',
      compensating: '', category: info.category, discovered: true,
    };
    CATALOG.push(c);
    catalogById[id] = c;
  }
  if (info.source === 'MDE') { c.detect.mde = true; c.mdeSev ||= info.sev || null; }
  if (info.source === 'R7') { c.detect.r7 = true; c.r7Sev ||= info.sev || null; }
  if (info.exploit && info.exploit !== 'None' && c.exploit === 'None') c.exploit = info.exploit;
  return c;
}

// ---------------- findings ----------------
function buildIndex() {
  const idx = new Map();
  for (const f of store.findings) if (isOpen(f)) idx.set(`${f.assetId}|${f.cve}`, f);
  return idx;
}

function detect(idx, a, c, src, since, st) {
  const k = `${a.id}|${c.id}`;
  let f = idx.get(k);
  if (f) {
    if (!f.sources.includes(src)) { f.sources.push(src); st.nowBoth++; }
    if (f.detected[src] === undefined) f.detected[src] = daysAgo(since);
    st.merged++;
    return f;
  }
  const d = daysAgo(since);
  const risk = computeRisk(c, a).total;
  const p = priorityFor(risk);
  f = { id: nextFindingId(), cve: c.id, assetId: a.id, company: a.company, sources: [src], detected: { [src]: d }, exposureAgo: d, detectedAgo: d, status: 'Open', remediatedAgo: null, risk, priority: p.priority, slaDays: p.days, live: true };
  f.sla = slaState(f);
  store.findings.push(f);
  idx.set(k, f);
  st.created.push(f);
  return f;
}

function fix(idx, f, st) {
  if (f.status === 'Remediated') return;
  f.status = 'Remediated';
  f.remediatedAgo = 0;
  f.sla = slaState(f);
  idx.delete(`${f.assetId}|${f.cve}`);
  const t = store.tickets.find((x) => x.cve === f.cve && x.company === f.company && x.state !== 'Resolved');
  if (t && !store.findings.some((o) => o.cve === f.cve && o.company === f.company && isOpen(o))) t.state = 'Resolved';
  st.fixed.push(f);
}

export function rescore(f) {
  const before = f.priority;
  const a = store.assetById[f.assetId];
  const c = catalogById[f.cve];
  if (!a || !c || !isOpen(f)) return null;
  const risk = computeRisk(c, a).total;
  const p = priorityFor(risk);
  f.risk = risk;
  f.priority = p.priority;
  f.slaDays = p.days;
  if (f.status === 'Open') f.sla = slaState(f);
  return before !== p.priority ? { finding: f, from: before, to: p.priority } : null;
}

const newStats = () => ({ received: 0, filtered: 0, normalised: 0, merged: 0, nowBoth: 0, created: [], fixed: [], newAssets: 0, rescored: 0, priorityChanges: [], newlyKev: [] });

// ---------------- Microsoft Defender ----------------
export function upsertDefenderMachine(m, st = newStats()) {
  let a = store.assets.find((x) => x.mdeId === m.id);
  let method = null;
  if (!a && m.aadDeviceId) { a = store.assets.find((x) => x.aadDeviceId === m.aadDeviceId); method = 'Entra device ID + hostname'; }
  if (!a) {
    a = store.assets.find((x) => shortHost(x.fqdn || x.hostname) === shortHost(m.computerDnsName));
    method = a && a.ip === m.lastIpAddress ? 'Hostname + IP address' : 'Fuzzy hostname';
  }
  if (!a) {
    a = createAsset({
      hostname: m.computerDnsName, fqdn: m.computerDnsName, company: companyFor({ group: m.rbacGroupName, host: m.computerDnsName }),
      type: typeFor(m.osPlatform), os: [m.osPlatform, m.version].filter(Boolean).join(' '), ip: m.lastIpAddress,
      mac: m.ipAddresses?.[0]?.macAddress, tier: tierFrom(m.deviceValue) || 3, internetFacing: (m.machineTags || []).some((t) => /internet/i.test(t)),
    });
    st.newAssets++;
    method = null;
  }
  if (!a.mde && a.r7 && method) { a.matchMethod = method; a.matchConfidence = method === 'Fuzzy hostname' ? 70 : method.startsWith('Entra') ? 100 : 96; }
  a.mde = true;
  a.mdeId = m.id;
  a.aadDeviceId ||= m.aadDeviceId || null;
  a.discovery = null;
  if (m.lastSeen) a.lastSeenAgo = daysAgo(m.lastSeen);
  return a;
}

export function ingestDefenderVulns(rows, { full = false } = {}) {
  const st = newStats();
  const idx = buildIndex();
  const byDevice = new Map(store.assets.filter((a) => a.mdeId).map((a) => [a.mdeId, a]));
  const seen = new Set();
  st.received = rows.length;
  for (const row of rows) {
    if (!row.cveId || !row.deviceId) { st.filtered++; continue; }
    let a = byDevice.get(row.deviceId);
    if (!a) {
      a = upsertDefenderMachine({ id: row.deviceId, computerDnsName: row.deviceName, osPlatform: row.osPlatform, version: row.osVersion, rbacGroupName: row.rbacGroupName }, st);
      byDevice.set(row.deviceId, a);
    }
    const c = ensureVuln(canonicalFromDefender(row.cveId), {
      source: 'MDE', title: `${row.softwareVendor || ''} ${row.softwareName || ''} vulnerability (${row.cveId})`.trim(), product: `${row.softwareVendor || ''} ${row.softwareName || ''}`.trim(),
      cvss: row.cvssScore, sev: row.vulnerabilitySeverityLevel, exploit: EXPLOIT_MDE[row.exploitabilityLevel], fix: row.recommendedSecurityUpdate,
    });
    st.normalised++;
    if (row.status === 'Fixed') {
      const f = idx.get(`${a.id}|${c.id}`);
      if (f) fix(idx, f, st);
      continue;
    }
    seen.add(`${a.id}|${c.id}`);
    detect(idx, a, c, 'MDE', row.firstSeenTimestamp, st);
  }
  // A full snapshot is the truth: anything Defender reported before but not now has been fixed.
  if (full) for (const f of [...idx.values()]) if (f.sources.includes('MDE') && store.assetById[f.assetId]?.mde && !seen.has(`${f.assetId}|${f.cve}`) && !f.sources.includes('R7')) fix(idx, f, st);
  return st;
}

// ---------------- Rapid7 InsightVM ----------------
export function upsertRapid7Asset(ra, site, st = newStats()) {
  let a = store.assets.find((x) => x.r7Id === ra.id);
  let method = null;
  let confidence = null;
  if (!a) {
    const host = shortHost(ra.hostName);
    a = host && store.assets.find((x) => shortHost(x.fqdn || x.hostname) === host);
    if (a) { method = 'Hostname + IP address'; confidence = a.ip === ra.ip ? 96 : 90; }
  }
  if (!a && ra.mac) {
    a = store.assets.find((x) => x.mac && x.mac === normMac(ra.mac) && x.ip === ra.ip);
    if (a) { method = 'MAC + IP address'; confidence = 88; }
  }
  if (!a && ra.hostName) {
    a = store.assets.find((x) => hostBase(x.hostname) === hostBase(ra.hostName));
    if (a) { method = 'Fuzzy hostname'; confidence = a.ip === ra.ip ? 74 : 62; }
  }
  if (!a) {
    a = createAsset({
      hostname: ra.hostName || ra.ip, fqdn: ra.hostName, company: companyFor({ site: site?.name, host: ra.hostName }),
      type: typeFor(ra.os || ra.osFingerprint?.description), os: ra.os || ra.osFingerprint?.description, ip: ra.ip, mac: ra.mac,
      site: site?.name?.split(' - ').pop() || 'Unknown',
    });
    st.newAssets++;
  }
  if (!a.r7 && a.mde && method) { a.matchMethod = method; a.matchConfidence = confidence; }
  a.r7 = true;
  a.r7Id = ra.id;
  a.discovery = null;
  return a;
}

// One site's scan results: assets, each asset's vulnerabilities, and the vulnerability definitions.
export function ingestRapid7Site(site, assets, vulnsByAsset, defs) {
  const st = newStats();
  const idx = buildIndex();
  for (const ra of assets) {
    const a = upsertRapid7Asset(ra, site, st);
    const seen = new Set();
    for (const v of vulnsByAsset.get(ra.id) || []) {
      st.received++;
      if (v.status === 'potential' && !config.rapid7.includePotential) { st.filtered++; continue; }
      const def = defs.get(v.id) || {};
      const c = ensureVuln(canonicalFromRapid7(v.id, def.cves || []), {
        source: 'R7', title: def.title, product: def.title?.split(':')[0], cvss: def.cvss?.v3?.score ?? def.cvss?.v2?.score, sev: def.severity,
        exploit: def.malwareKits ? 'Weaponized' : def.exploits ? 'Public PoC' : 'None', published: def.published, category: def.categories?.find((x) => /config|end of life/i.test(x)),
      });
      st.normalised++;
      seen.add(c.id);
      detect(idx, a, c, 'R7', v.since, st);
    }
    // The rescan no longer finds what it found before: Rapid7 confirms the fix.
    for (const f of store.findings) if (f.assetId === a.id && isOpen(f) && f.status === 'Open' && f.sources.includes('R7') && !seen.has(f.cve)) fix(idx, f, st);
  }
  return st;
}

// ---------------- ServiceNow CMDB ----------------
export function ingestCmdb(cis) {
  const st = newStats();
  const sn = config.servicenow;
  st.received = cis.length;
  for (const ci of cis) {
    let a = store.assets.find((x) => x.cmdbSysId && x.cmdbSysId === ci.sys_id)
      || store.assets.find((x) => shortHost(x.fqdn || x.hostname) === shortHost(ci.fqdn || ci.name))
      || (ci.mac_address && store.assets.find((x) => x.mac === normMac(ci.mac_address) && x.ip === ci.ip_address));
    if (!a) {
      a = createAsset({ hostname: ci.name, fqdn: ci.fqdn, company: companyFor({ company: ci.company, host: ci.name }), type: typeFor(ci.os, ci.sys_class_name), os: ci.os, ip: ci.ip_address, mac: ci.mac_address, site: ci.location || 'Unknown' });
      a.discovery = 'CMDB only';
      st.newAssets++;
    }
    st.normalised++;
    const tier = tierFrom(ci[sn.tierField]) || a.tier;
    const internet = ci[sn.internetField] != null && ci[sn.internetField] !== '' ? String(ci[sn.internetField]) === 'true' : a.internetFacing;
    const changed = tier !== a.tier || internet !== a.internetFacing;
    Object.assign(a, {
      cmdbSysId: ci.sys_id || a.cmdbSysId, company: companyFor({ company: ci.company, host: ci.name }) || a.company,
      site: ci.location || a.site, service: ci[sn.serviceField] || a.service, owner: ci.support_group || a.owner,
      tier, criticality: TIER_LABEL[tier], internetFacing: internet, controls: ci.u_compensating_controls ?? a.controls ?? '',
      serial: ci.serial_number || a.serial,
    });
    if (changed) {
      for (const f of store.findings) {
        if (f.assetId !== a.id || !isOpen(f)) continue;
        st.rescored++;
        const ch = rescore(f);
        if (ch) st.priorityChanges.push(ch);
      }
    }
  }
  return st;
}

// ---------------- CISA KEV · FIRST EPSS ----------------
export function ingestThreatIntel(kev, epss) {
  const st = newStats();
  const kevIds = new Set(kev.map((k) => k.cveID));
  st.received = kev.length + epss.length;
  const touched = new Set();
  for (const c of CATALOG) {
    if (kevIds.has(c.id) && !c.kev) { c.kev = true; c.exploit = 'Weaponized'; st.newlyKev.push(c.id); touched.add(c.id); }
  }
  for (const e of epss) {
    const c = catalogById[e.cve];
    const v = Number(e.epss);
    if (!c || !Number.isFinite(v)) continue;
    st.normalised++;
    if (Math.abs(c.epss - v) >= 0.005) { c.epss = v; touched.add(c.id); }
  }
  for (const f of store.findings) {
    if (!isOpen(f) || !touched.has(f.cve)) continue;
    st.rescored++;
    const ch = rescore(f);
    if (ch) st.priorityChanges.push(ch);
  }
  st.filtered = kev.length - st.newlyKev.length;
  return st;
}

export { newStats };
