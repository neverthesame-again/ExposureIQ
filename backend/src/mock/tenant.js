// The mock tenant: a simulated SHV estate that answers in the exact JSON shapes of the real APIs
// (Defender for Endpoint, Rapid7 InsightVM v3, ServiceNow Table API, CISA KEV, FIRST EPSS).
// The connectors call it instead of the network when no credentials are configured, so mock data
// and real data take the same path through normalisation and correlation.
//
// "reality" is what is actually vulnerable right now. Each tool only sees part of it: Defender sees
// what its agent can assess on onboarded devices, Rapid7 sees what its scanner finds on scanned sites,
// and only at scan time. worldStep() moves reality on: new weaknesses appear, patches land.
import { createHash } from 'node:crypto';
import { COMPANIES } from '../data/companies.js';
import { CATALOG, catalogById } from '../data/catalog.js';
import { store, NOW, DAY } from '../data/generator.js';
import { defenderIdFor, rapid7KeyFor } from '../data/crosswalk.js';
import { r7NameFor } from '../analytics.js';

const sha = (x) => createHash('sha256').update(String(x)).digest('hex');
const rnd = Math.random;
const pick = (a) => a[Math.floor(rnd() * a.length)];
const weighted = (pairs) => {
  let x = rnd() * pairs.reduce((s, [, w]) => s + w, 0);
  for (const [v, w] of pairs) if ((x -= w) <= 0) return v;
  return pairs[pairs.length - 1][0];
};
const iso = (ms) => new Date(ms).toISOString();
const mdeTs = (ms) => iso(ms).replace('T', ' ').replace('Z', '').slice(0, 19); // Defender's "2020-11-03 10:13:34"
const coById = Object.fromEntries(COMPANIES.map((c) => [c.id, c]));
const key = (assetId, catId) => `${assetId}|${catId}`;

const reality = new Map(); // key → { since }
const mdeChanges = []; // Defender delta log: { at, status, assetId, catId, since }
const kevAdded = {}; // catId → ISO date CISA added it (mock threat-intel drift)
const mockKev = new Set(CATALOG.filter((c) => c.kev).map((c) => c.id)); // what the mock CISA feed lists
let started = false;

function init() {
  if (started) return;
  started = true;
  for (const f of store.findings) {
    if (f.status === 'Remediated') continue;
    reality.set(key(f.assetId, f.cve), { since: NOW - f.exposureAgo * DAY });
  }
}

const sees = {
  MDE: (a, c) => a.mde && c.detect.mde,
  R7: (a, c) => a.r7 && c.detect.r7,
};

// ---------------- the world changing ----------------
export function worldStep({ add = [0, 1, 1, 2, 2, 3], fix = [0, 1, 2, 2, 3], companyId } = {}) {
  init();
  const added = [];
  const fixed = [];
  const nAdd = pick(add);
  const pool = store.assets.filter((a) => !companyId || a.company === companyId);
  for (let tries = 0; added.length < nAdd && tries < 80; tries++) {
    const a = pick(pool);
    const cats = CATALOG.filter((c) => c.category !== 'End of Life' && c.tags?.some((t) => a.tags.includes(t)) && !reality.has(key(a.id, c.id)));
    if (!cats.length) continue;
    const c = weighted(cats.map((x) => [x, x.prob || 0.05]));
    const at = Date.now();
    reality.set(key(a.id, c.id), { since: at });
    if (sees.MDE(a, c)) mdeChanges.push({ at, status: 'New', assetId: a.id, catId: c.id, since: at });
    added.push({ assetId: a.id, catId: c.id });
  }
  const nFix = pick(fix);
  const current = [...reality.entries()].filter(([k]) => !companyId || store.assetById[k.split('|')[0]]?.company === companyId);
  for (let i = 0; i < nFix && current.length; i++) {
    const [k, v] = current.splice(Math.floor(rnd() * current.length), 1)[0];
    const [assetId, catId] = k.split('|');
    if (catById(catId)?.category === 'End of Life') continue;
    reality.delete(k);
    const a = store.assetById[assetId];
    if (a && sees.MDE(a, catById(catId))) mdeChanges.push({ at: Date.now(), status: 'Fixed', assetId, catId, since: v.since });
    fixed.push({ assetId, catId });
  }
  return { added, fixed };
}
const catById = (id) => catalogById[id];

// ---------------- Microsoft Defender for Endpoint ----------------
const OS_PLATFORM = (os) => (os.startsWith('Windows Server') ? `WindowsServer${os.match(/20\d\d/)?.[0] || ''}${os.includes('R2') ? 'R2' : ''}` : os.startsWith('Windows 11') ? 'Windows11' : os.startsWith('Windows 10') ? 'Windows10' : os.startsWith('macOS') ? 'macOS' : /Ubuntu|RHEL/.test(os) ? 'Linux' : 'Other');
const DEVICE_VALUE = { 1: 'High', 2: 'Normal', 3: 'Low' };

function machine(a) {
  const h = sha(a.id);
  return {
    id: a.mdeId,
    computerDnsName: a.fqdn,
    firstSeen: iso(NOW - (200 + (parseInt(h.slice(0, 4), 16) % 400)) * DAY),
    lastSeen: iso(Date.now() - a.lastSeenAgo * DAY),
    osPlatform: OS_PLATFORM(a.os),
    version: a.os.match(/\d{2}H\d/)?.[0] || '',
    osProcessor: 'x64',
    lastIpAddress: a.ip,
    lastExternalIpAddress: a.internetFacing ? `203.0.113.${parseInt(h.slice(4, 6), 16) % 250}` : null,
    healthStatus: 'Active',
    onboardingStatus: 'Onboarded',
    rbacGroupName: coById[a.company].name,
    riskScore: 'Medium',
    exposureLevel: 'Medium',
    isAadJoined: !!a.aadDeviceId,
    aadDeviceId: a.aadDeviceId,
    machineTags: a.internetFacing ? ['Internet facing'] : [],
    deviceValue: DEVICE_VALUE[a.tier],
    ipAddresses: [{ ipAddress: a.ip, macAddress: a.mac.replace(/:/g, ''), type: 'Ethernet', operationalStatus: 'Up' }],
  };
}

function software(c) {
  const [vendor, ...rest] = c.product.toLowerCase().split(/\s+/);
  return { softwareVendor: vendor.replace(/[^a-z0-9]/g, ''), softwareName: (rest.join('_') || vendor).replace(/[^a-z0-9_.]/g, '') };
}
const EXPLOITABILITY = (c) => (c.kev || c.exploit === 'Weaponized' ? 'ExploitIsInKit' : c.exploit === 'Public PoC' ? 'ExploitIsPublic' : 'NoExploit');
const SEV = (cvss) => (cvss >= 9 ? 'Critical' : cvss >= 7 ? 'High' : cvss >= 4 ? 'Medium' : 'Low');

function vulnRow(a, c, since, extra = {}) {
  const sw = software(c);
  const version = `${(parseInt(sha(a.id + c.id).slice(0, 2), 16) % 20) + 1}.${parseInt(sha(c.id).slice(0, 2), 16) % 10}.0`;
  const cveId = defenderIdFor(c);
  return {
    id: `${a.mdeId}_${sw.softwareName}_${version}_${cveId}_`,
    deviceId: a.mdeId,
    rbacGroupName: coById[a.company].name,
    deviceName: a.fqdn,
    osPlatform: OS_PLATFORM(a.os),
    osVersion: a.os,
    osArchitecture: 'x64',
    ...sw,
    softwareVersion: version,
    cveId,
    cvssScore: c.cvss,
    vulnerabilitySeverityLevel: c.mdeSev || SEV(c.cvss),
    recommendedSecurityUpdate: c.fix,
    recommendedSecurityUpdateId: null,
    diskPaths: [],
    registryPaths: [],
    firstSeenTimestamp: mdeTs(since),
    lastSeenTimestamp: mdeTs(Date.now() - a.lastSeenAgo * DAY),
    exploitabilityLevel: EXPLOITABILITY(c),
    recommendationReference: `va-_-${sw.softwareVendor}-_-${sw.softwareName}`,
    securityUpdateAvailable: c.category !== 'End of Life',
    ...extra,
  };
}
// Inventory rows without a CVE: real exports include installed software that has no known vulnerability.
function inventoryRow(a, at) {
  const sw = pick([['microsoft', 'onedrive'], ['google', 'chrome'], ['microsoft', 'edge'], ['microsoft', '.net_framework']]);
  return { id: `${a.mdeId}_${sw[1]}__`, deviceId: a.mdeId, rbacGroupName: coById[a.company].name, deviceName: a.fqdn, osPlatform: OS_PLATFORM(a.os), softwareVendor: sw[0], softwareName: sw[1], softwareVersion: '1.0.0', cveId: null, vulnerabilitySeverityLevel: null, firstSeenTimestamp: mdeTs(at), lastSeenTimestamp: mdeTs(at), exploitabilityLevel: 'NoExploit' };
}

export const defender = {
  machine(id) {
    const a = store.assets.find((x) => x.mdeId === id);
    return a ? machine(a) : null;
  },
  machines() {
    init();
    return { '@odata.context': 'mock#Machines', value: store.assets.filter((a) => a.mde).map(machine) };
  },
  softwareVulnerabilitiesByMachine() {
    init();
    const value = [];
    for (const [k, v] of reality) {
      const [assetId, catId] = k.split('|');
      const a = store.assetById[assetId];
      const c = catById(catId);
      if (a && c && sees.MDE(a, c)) value.push(vulnRow(a, c, v.since));
    }
    return { '@odata.context': 'mock#AssetVulnerability', value };
  },
  softwareVulnerabilityChangesByMachine(sinceIso) {
    init();
    const since = new Date(sinceIso).getTime();
    const value = mdeChanges.filter((e) => e.at > since).map((e) => {
      const a = store.assetById[e.assetId];
      return vulnRow(a, catById(e.catId), e.since, { status: e.status, eventTimestamp: mdeTs(e.at) });
    });
    // a few software-inventory rows with no CVE, as in the real delta feed
    const noise = Math.floor(rnd() * 4);
    for (let i = 0; i < noise; i++) value.push({ ...inventoryRow(pick(store.assets.filter((a) => a.mde)), Date.now()), status: 'Updated', eventTimestamp: mdeTs(Date.now()) });
    return { '@odata.context': 'mock#DeltaAssetVulnerability', value };
  },
};

// ---------------- Rapid7 InsightVM API v3 ----------------
const SITES = COMPANIES.flatMap((co) => co.sites.map((s) => ({ company: co.id, site: s, name: `${co.short} - ${s}` }))).map((s, i) => ({ ...s, id: i + 1 }));
const R7_SEV = (c) => c.r7Sev || (c.cvss >= 9 ? 'Critical' : c.cvss >= 7 ? 'Severe' : 'Moderate');

function r7Asset(a) {
  const fuzzy = a.matchMethod === 'Fuzzy hostname' || a.agentReviewed;
  const h = sha(a.id + 'r7');
  const sameIp = !fuzzy || (a.matchConfidence ?? 80) >= 70;
  const sameMac = !fuzzy || parseInt(h.slice(0, 2), 16) % 100 < 60;
  const ip = sameIp ? a.ip : a.ip.replace(/\.\d+$/, `.${(parseInt(h.slice(2, 4), 16) % 200) + 20}`);
  const mac = sameMac ? a.mac : h.slice(6, 18).match(/../g).join(':').toUpperCase();
  const hostName = fuzzy ? r7NameFor(a) : a.fqdn;
  return {
    id: a.r7Id,
    ip,
    mac,
    hostName,
    addresses: [{ ip, mac }],
    hostNames: [{ name: hostName, source: 'dns' }],
    os: a.os,
    osFingerprint: { description: a.os, family: a.os.split(' ')[0] },
    riskScore: 0,
  };
}

export const rapid7 = {
  asset(r7Id) {
    const a = store.assets.find((x) => x.r7Id === Number(r7Id));
    return a ? r7Asset(a) : null;
  },
  sites() {
    return { resources: SITES.map((s) => ({ id: s.id, name: s.name, assets: store.assets.filter((a) => a.r7 && a.company === s.company && a.site === s.site).length })), page: { number: 0, size: SITES.length, totalResources: SITES.length, totalPages: 1 } };
  },
  site(id) { return SITES.find((s) => String(s.id) === String(id)); },
  siteAssets(siteId) {
    const s = SITES.find((x) => String(x.id) === String(siteId));
    const resources = s ? store.assets.filter((a) => a.r7 && a.company === s.company && a.site === s.site).map(r7Asset) : [];
    return { resources, page: { number: 0, size: resources.length, totalResources: resources.length, totalPages: 1 } };
  },
  assetVulnerabilities(r7Id) {
    init();
    const a = store.assets.find((x) => x.r7Id === Number(r7Id));
    const resources = [];
    if (a) {
      for (const [k, v] of reality) {
        if (!k.startsWith(`${a.id}|`)) continue;
        const c = catById(k.split('|')[1]);
        if (!c || !sees.R7(a, c)) continue;
        resources.push({ id: rapid7KeyFor(c), instances: 1, status: 'vulnerable', since: iso(Math.max(v.since, Date.now() - 2 * DAY)), results: [{ port: c.category === 'Configuration' ? 443 : null, protocol: 'tcp', status: 'vulnerable-version', proof: `Vulnerable ${c.product} detected` }] });
      }
      // unconfirmed checks that a real console also returns
      if (rnd() < 0.3) resources.push({ id: 'generic-tcp-timestamp', instances: 1, status: 'potential', since: iso(Date.now()), results: [] });
    }
    return { resources, page: { number: 0, size: resources.length, totalResources: resources.length, totalPages: 1 } };
  },
  vulnerability(key) {
    const c = CATALOG.find((x) => rapid7KeyFor(x) === key);
    if (!c) return { id: key, title: key.replace(/-/g, ' '), severity: 'Moderate', severityScore: 2, cvss: { v3: { score: 2.1 } }, cves: [], exploits: 0, malwareKits: 0, published: '2010-01-01' };
    return {
      id: key, title: c.title, severity: R7_SEV(c), severityScore: Math.round(c.cvss),
      cvss: { v3: { score: c.cvss } }, cves: c.id.startsWith('CVE-') ? [c.id] : [],
      exploits: c.exploit === 'None' ? 0 : 1, malwareKits: c.exploit === 'Weaponized' ? 1 : 0,
      published: c.published, categories: [c.category || 'Vulnerability'],
    };
  },
};

// ---------------- ServiceNow Table API ----------------
const TIER_LABEL = { 1: '1 - Crown Jewel', 2: '2 - High', 3: '3 - Standard' };
const cmdbOverrides = new Map(); // assetId → fields the CMDB owner changed since the last sync
export const servicenow = {
  cmdb() {
    return {
      result: store.assets.map((a) => ({ ...cmdbRecord(a), ...(cmdbOverrides.get(a.id) || {}) })),
    };
  },
  // Lookup of one CI by sys_id (used by the asset-match agent)
  ci(sysId) {
    const a = store.assets.find((x) => x.cmdbSysId === sysId);
    return a ? { ...cmdbRecord(a), ...(cmdbOverrides.get(a.id) || {}) } : null;
  },
  // Now and then an owner re-classifies a server, e.g. it starts hosting a crown-jewel service.
  maybeChangeCi() {
    if (rnd() > 0.35) return null;
    const open = new Set(store.findings.filter((f) => f.status === 'Open').map((f) => f.assetId));
    const cands = store.assets.filter((a) => a.tier === 3 && (a.type === 'Server' || a.type === 'Cloud VM') && open.has(a.id) && !cmdbOverrides.has(a.id));
    if (!cands.length) return null;
    const a = pick(cands);
    const co = coById[a.company];
    const svc = co.services.find((x) => x.tier === 1) || { name: 'Critical service' };
    cmdbOverrides.set(a.id, { u_criticality_tier: TIER_LABEL[1], u_business_service: svc.name });
    return { assetId: a.id, hostname: a.hostname, service: svc.name };
  },
  createRecord(table, body) {
    const number = store.nextTicket();
    return { result: { number, sys_id: sha(number).slice(0, 32), table, short_description: body.short_description } };
  },
};

function cmdbRecord(a) {
  return {
    sys_id: a.cmdbSysId, name: a.hostname, fqdn: a.fqdn, ip_address: a.ip, mac_address: a.mac, serial_number: a.serial,
    os: a.os, sys_class_name: a.type, company: coById[a.company].name, location: a.site, support_group: a.owner,
    u_business_service: a.service, u_criticality_tier: TIER_LABEL[a.tier], u_internet_facing: String(a.internetFacing),
    u_compensating_controls: controlFor(a),
  };
}

// Compensating controls the security team has registered against a CI (kept in the CMDB here).
function controlFor(a) {
  if (parseInt(sha(a.id + 'ctl').slice(0, 2), 16) % 100 >= 30) return '';
  return {
    Workstation: 'Defender ASR rules in block mode',
    Server: 'Host firewall restricts service ports to the application subnet',
    'Cloud VM': 'Azure NSG limits inbound to the load balancer',
    'Network Device': 'Management plane reachable only from admin jump hosts',
    'OT / IoT': 'Isolated OT segment, no route to office network',
  }[a.type];
}

// ---------------- CISA KEV · FIRST EPSS ----------------
export const intel = {
  kev() {
    const vulns = CATALOG.filter((c) => mockKev.has(c.id) && c.id.startsWith('CVE-')).map((c) => ({
      cveID: c.id, vendorProject: c.product.split(' ')[0], product: c.product, vulnerabilityName: c.title,
      dateAdded: kevAdded[c.id] || c.published, shortDescription: c.title, requiredAction: c.fix, knownRansomwareCampaignUse: 'Unknown',
    }));
    return { title: 'CISA Catalog of Known Exploited Vulnerabilities (mock)', catalogVersion: new Date().toISOString().slice(0, 10), count: vulns.length, vulnerabilities: vulns };
  },
  epss(cves) {
    const data = cves.map((id) => catById(id)).filter(Boolean).map((c) => ({ cve: c.id, epss: String(Math.min(0.99, Math.max(0.001, c.epss + (rnd() - 0.5) * 0.02)).toFixed(5)), percentile: '0.9', date: new Date().toISOString().slice(0, 10) }));
    return { status: 'OK', total: data.length, data };
  },
  // Occasionally CISA adds a CVE we already have open to KEV — the moment triage must re-look.
  maybeAddToKev() {
    if (rnd() > 0.25) return null;
    const open = new Set([...reality.keys()].map((k) => k.split('|')[1]));
    const candidates = CATALOG.filter((c) => !mockKev.has(c.id) && c.id.startsWith('CVE-') && c.exploit !== 'None' && open.has(c.id));
    if (!candidates.length) return null;
    const c = pick(candidates);
    mockKev.add(c.id);
    kevAdded[c.id] = new Date().toISOString().slice(0, 10);
    return c.id;
  },
};

export const mockSites = SITES;
