// Deterministic mock-data engine. Simulates what the Rapid7 InsightVM API and the
// Microsoft Defender Vulnerability Management API would return, then correlates both
// into one unified, de-duplicated finding per (asset, vulnerability).
import { COMPANIES, SLA_POLICY, TOOL_COVERAGE } from './companies.js';
import { CATALOG } from './catalog.js';

export const DAY = 86400000;
export const WINDOW = 420; // days of history we simulate (UI shows the last ~180)
const PROB_SCALE = 2.4; // raise to generate a noisier estate
const today = new Date();
today.setHours(0, 0, 0, 0);
export const NOW = today.getTime();

export const isoAgo = (daysAgo) => new Date(NOW - daysAgo * DAY).toISOString();

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const r = mulberry32(20260929);
const pick = (arr) => arr[Math.floor(r() * arr.length)];
const weighted = (pairs) => {
  const total = pairs.reduce((s, [, w]) => s + w, 0);
  let x = r() * total;
  for (const [v, w] of pairs) { if ((x -= w) <= 0) return v; }
  return pairs[pairs.length - 1][0];
};

const OS_BY_TYPE = {
  Workstation: [['Windows 11 23H2', 0.6], ['Windows 10 22H2', 0.32], ['macOS 14 Sonoma', 0.08]],
  Server: [['Windows Server 2022', 0.36], ['Windows Server 2019', 0.3], ['Windows Server 2012 R2', 0.07], ['RHEL 8.9', 0.15], ['Ubuntu 22.04 LTS', 0.12]],
  'Network Device': [['FortiOS 7.2', 0.3], ['PAN-OS 10.2', 0.25], ['Cisco IOS XE 17.6', 0.25], ['Citrix NetScaler ADC 13.1', 0.12], ['Ivanti Connect Secure 22.4', 0.08]],
  'Cloud VM': [['Ubuntu 22.04 LTS', 0.4], ['Windows Server 2022', 0.4], ['RHEL 9.3', 0.2]],
  'OT / IoT': [['Rockwell ControlLogix 5580', 0.55], ['Windows 10 IoT LTSC (HMI)', 0.45]],
};
const TYPE_CODE = { Workstation: 'WS', Server: 'SRV', 'Network Device': 'NET', 'Cloud VM': 'AZ', 'OT / IoT': 'OT' };
const TEAM = { Workstation: 'Endpoint Team', Server: 'Server & Cloud Team', 'Cloud VM': 'Server & Cloud Team', 'Network Device': 'Network Team', 'OT / IoT': 'OT Engineering' };
const TIER_LABEL = { 1: 'Crown Jewel', 2: 'High', 3: 'Standard' };

function tagsFor(os, type, company) {
  const t = new Set();
  const isWin = os.startsWith('Windows');
  if (isWin) {
    t.add('windows');
    t.add(type === 'Workstation' || os.includes('HMI') ? 'windows-client' : 'windows-server');
    if (os.includes('2012')) t.add('ws2012');
  }
  if (/Ubuntu|RHEL/.test(os)) t.add('linux');
  if (os.startsWith('macOS')) t.add('macos');
  if (os.startsWith('FortiOS')) t.add('fortios');
  if (os.startsWith('PAN-OS')) t.add('panos');
  if (os.includes('IOS XE')) t.add('iosxe');
  if (os.includes('NetScaler')) t.add('netscaler');
  if (os.includes('Ivanti')) t.add('ivanti');
  if (os.includes('Rockwell')) t.add('rockwell');
  if (os.includes('HMI')) t.add('hmi');
  if (type === 'Workstation') {
    if (r() < (isWin ? 0.95 : 0.8)) t.add('office');
    if (r() < 0.85) t.add('chrome');
    if (isWin && r() < 0.25) t.add('winrar');
    if (isWin && r() < 0.35) t.add('7zip');
    if (r() < 0.3) t.add('zoom');
  }
  if (type === 'Server' || type === 'Cloud VM') {
    if (r() < 0.3) t.add('java');
    const web = r() < 0.45;
    if (web) t.add('web');
    if (web && t.has('linux') && r() < 0.18) t.add('php');
    if (r() < 0.035) t.add('jenkins');
    if (r() < 0.03) t.add('confluence');
    if (r() < 0.03) t.add('activemq');
    if (r() < 0.02) t.add('moveit');
    if (isWin && r() < 0.05) t.add('sharepoint');
    if (isWin && r() < (company.id === 'npm' ? 0.35 : 0.015)) t.add('screenconnect');
  }
  return t;
}

export function computeRisk(cat, asset) {
  const base = +(cat.cvss * 5).toFixed(1);
  const threatExploit = cat.kev ? 20 : cat.exploit === 'Weaponized' ? 14 : cat.exploit === 'Public PoC' ? 7 : 0;
  const threatEpss = +(cat.epss * 8).toFixed(1);
  const assetCrit = asset.tier === 1 ? 15 : asset.tier === 2 ? 8 : 2;
  const exposure = asset.internetFacing ? 10 : 0;
  const total = Math.min(100, Math.round(base + threatExploit + threatEpss + assetCrit + exposure));
  return {
    total,
    breakdown: [
      { factor: 'Technical severity', detail: `CVSS ${cat.cvss.toFixed(1)} × 5`, points: base, max: 50 },
      { factor: 'Threat intelligence', detail: cat.kev ? 'In CISA KEV — actively exploited' : cat.exploit === 'None' ? 'No known exploit' : `${cat.exploit} exploit available`, points: threatExploit, max: 20 },
      { factor: 'Exploit likelihood', detail: `EPSS ${(cat.epss * 100).toFixed(0)}% probability of exploitation in 30 days`, points: threatEpss, max: 8 },
      { factor: 'Business criticality', detail: `${TIER_LABEL[asset.tier]} asset — ${asset.service}`, points: assetCrit, max: 15 },
      { factor: 'Attack surface', detail: asset.internetFacing ? 'Internet-facing' : 'Internal only', points: exposure, max: 10 },
    ],
  };
}

export const priorityFor = (risk) => SLA_POLICY.find((p) => risk >= p.minRisk);

function buildAssets() {
  const assets = [];
  COMPANIES.forEach((co, ci) => {
    let seq = 1;
    const types = Object.entries(co.mix).filter(([, w]) => w > 0);
    for (let i = 0; i < co.assets; i++) {
      const type = weighted(types);
      const os = weighted(OS_BY_TYPE[type]);
      const siteIdx = Math.floor(r() * co.sites.length);
      let service, tier;
      if (type === 'Workstation') {
        const exec = r() < 0.08;
        service = exec ? 'Executive Devices' : 'Office Productivity';
        tier = exec ? 2 : 3;
      } else if (type === 'OT / IoT') {
        const s = co.services.find((x) => x.tier === 1);
        service = s.name; tier = 1;
      } else if (type === 'Network Device') {
        service = 'Perimeter & Site Connectivity'; tier = 2;
      } else {
        const s = pick(co.services.filter((x) => x.name !== 'Office Productivity'));
        service = s.name; tier = s.tier;
      }
      const tags = tagsFor(os, type, co);
      let internetFacing = false;
      if (type === 'Network Device') internetFacing = r() < 0.6;
      else if (tags.has('web') || tags.has('moveit') || tags.has('screenconnect')) internetFacing = r() < 0.35;
      else if (type === 'Cloud VM') internetFacing = r() < 0.15;
      if (type === 'Network Device' && internetFacing) tier = 1;

      const cov = TOOL_COVERAGE[type];
      const mde = r() < cov.mde * co.mdeFactor;
      const r7 = r() < cov.r7 * co.r7Factor;
      let discovery = null;
      if (!mde && !r7) discovery = r() < 0.55 ? 'MDE device discovery (unmanaged)' : 'CMDB only';

      let matchMethod = null, matchConfidence = null;
      if (mde && r7) {
        const m = weighted([['Entra device ID + hostname', 0.55], ['Hostname + IP address', 0.3], ['MAC + IP address', 0.1], ['Fuzzy hostname', 0.05]]);
        matchMethod = m;
        matchConfidence = m === 'Entra device ID + hostname' ? 100 : m === 'Hostname + IP address' ? 96 : m === 'MAC + IP address' ? 88 : 60 + Math.floor(r() * 18);
      }
      const hostname = `${co.prefix}-${TYPE_CODE[type]}-${String(seq++).padStart(4, '0')}`;
      assets.push({
        id: `${co.id}-${hostname}`.toLowerCase(),
        hostname,
        company: co.id,
        type,
        os,
        site: co.sites[siteIdx],
        ip: `10.${ci * 20 + siteIdx + 10}.${Math.floor(r() * 250) + 1}.${Math.floor(r() * 250) + 2}`,
        service,
        tier,
        criticality: TIER_LABEL[tier],
        internetFacing,
        tags: [...tags],
        mde, r7, discovery,
        matchMethod, matchConfidence,
        owner: `${co.short} ${TEAM[type]}`,
        lastSeenAgo: +(r() * 3).toFixed(2),
      });
    }
  });
  return assets;
}

function buildFindings(assets) {
  const findings = [];
  let blindSpots = 0;
  let fid = 1;
  const coById = Object.fromEntries(COMPANIES.map((c) => [c.id, c]));
  for (const a of assets) {
    const co = coById[a.company];
    const tagSet = new Set(a.tags);
    // Two exposure "episodes" per weakness (e.g. original + regression after re-image), one per half of the window.
    for (const [cat, episode] of CATALOG.flatMap((c) => [[c, 0], [c, 1]])) {
      if (!cat.tags.some((t) => tagSet.has(t))) continue;
      if (cat.category === 'End of Life' && episode === 1) continue;
      if (r() >= Math.min(0.92, cat.prob * PROB_SCALE)) continue;
      const visible = [];
      if (cat.detect.mde && a.mde) visible.push('MDE');
      if (cat.detect.r7 && a.r7) visible.push('R7');
      if (!visible.length) { blindSpots++; continue; }

      const exposureAgo = cat.category === 'End of Life' ? WINDOW : (episode + r()) * (WINDOW / 2);
      const detected = {};
      if (visible.includes('MDE')) detected.MDE = exposureAgo - (0.2 + r() * 2);
      if (visible.includes('R7')) detected.R7 = exposureAgo - (0.5 + r() * co.scanDays);
      for (const k of Object.keys(detected)) if (detected[k] < 0) delete detected[k];
      if (!Object.keys(detected).length) continue;
      const detectedAgo = Math.max(...Object.values(detected));

      const risk = computeRisk(cat, a);
      const p = priorityFor(risk.total);
      let mean = p.days * co.maturity * (0.45 + 1.3 * (detectedAgo / WINDOW));
      if (p.priority === 'P1') mean *= 2.5; // emergency patches still wait for change windows
      if (cat.category === 'End of Life') mean *= 5;
      if (cat.category === 'Configuration') mean *= 2;
      if (a.type === 'OT / IoT') mean *= 3;
      if (r() < 0.14) mean *= 4; // stuck: change freeze, vendor dependency, no owner
      const ttr = -Math.log(1 - r()) * mean * 0.85;
      const remediatedAgo = detectedAgo - ttr;

      let status = 'Open';
      if (remediatedAgo > 0) {
        status = 'Remediated';
        for (const k of Object.keys(detected)) if (Object.keys(detected).length > 1 && detected[k] < remediatedAgo) delete detected[k];
      } else if (p.priority !== 'P1' && p.priority !== 'P2' && r() < 0.05) status = 'Risk Accepted';

      findings.push({
        id: `F-${String(fid++).padStart(6, '0')}`,
        cve: cat.id,
        assetId: a.id,
        company: a.company,
        sources: Object.keys(detected),
        detected,
        exposureAgo,
        detectedAgo,
        status,
        remediatedAgo: status === 'Remediated' ? remediatedAgo : null,
        risk: risk.total,
        priority: p.priority,
        slaDays: p.days,
      });
    }
  }
  return { findings, blindSpots };
}

// Per-finding SLA state relative to "today" (daysAgo = 0)
export function slaState(f) {
  if (f.status === 'Risk Accepted') return 'Exception';
  if (f.status === 'Remediated') return f.detectedAgo - f.remediatedAgo <= f.slaDays ? 'Met' : 'Missed';
  const dueIn = f.slaDays - f.detectedAgo;
  if (dueIn < 0) return 'Breached';
  if (dueIn <= Math.max(2, f.slaDays * 0.2)) return 'Due soon';
  return 'On track';
}

const assets = buildAssets();
const { findings, blindSpots } = buildFindings(assets);
findings.forEach((f) => { f.sla = slaState(f); });

// Seed ServiceNow tickets for part of the open urgent work, so the POC shows both states.
const tickets = [];
let ticketSeq = 4120;
const seen = new Set();
for (const f of findings) {
  const key = `${f.cve}|${f.company}`;
  if (f.status !== 'Open' || seen.has(key)) continue;
  seen.add(key);
  if ((f.priority === 'P1' || f.priority === 'P2') && r() < 0.45) {
    tickets.push({
      id: `VIT${String(ticketSeq++).padStart(7, '0')}`,
      cve: f.cve,
      company: f.company,
      createdAgo: Math.max(0, f.detectedAgo - 1 - r() * 3),
      state: pick(['New', 'In Progress', 'In Progress', 'Awaiting Change Window']),
      assignee: assets.find((a) => a.id === f.assetId).owner,
      createdBy: 'ExposureIQ automation',
    });
  }
}

export const store = {
  assets,
  assetById: Object.fromEntries(assets.map((a) => [a.id, a])),
  findings,
  blindSpots,
  tickets,
  nextTicket: () => `VIT${String(ticketSeq++).padStart(7, '0')}`,
};
