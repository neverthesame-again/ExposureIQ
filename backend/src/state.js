// Live mode keeps its own history: Defender and Rapid7 only return the current state, so trends,
// MTTR and remediation history exist only because ExposureIQ stores what it saw on every sync.
// Saved to backend/data/state.json (git-ignored). Times are stored as absolute timestamps and turned
// back into "days ago" on load. Mock mode never writes this file.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { config, ROOT } from './config.js';
import { CATALOG, catalogById } from './data/catalog.js';
import { store, NOW, DAY, slaState } from './data/generator.js';

const DIR = path.join(ROOT, 'data');
const FILE = path.join(DIR, 'state.json');
const toAt = (ago) => (ago == null ? null : Math.round(NOW - ago * DAY));
const toAgo = (at) => (at == null ? null : Math.max(0, +((NOW - at) / DAY).toFixed(3)));
let timer = null;

export function saveState() {
  if (config.mode !== 'live' || timer) return;
  timer = setTimeout(() => {
    timer = null;
    const data = {
      savedAt: new Date().toISOString(),
      ticketSeq: store.getTicketSeq(),
      assets: store.assets.map((a) => ({ ...a, lastSeenAt: toAt(a.lastSeenAgo), lastSeenAgo: undefined })),
      findings: store.findings.map((f) => ({
        ...f, exposureAt: toAt(f.exposureAgo), detectedAt: toAt(f.detectedAgo), remediatedAt: toAt(f.remediatedAgo),
        detectedBy: Object.fromEntries(Object.entries(f.detected).map(([k, v]) => [k, toAt(v)])),
        exposureAgo: undefined, detectedAgo: undefined, remediatedAgo: undefined, detected: undefined,
      })),
      tickets: store.tickets.map((t) => ({ ...t, createdAt: toAt(t.createdAgo), createdAgo: undefined })),
      catalog: CATALOG.map((c) => (c.discovered ? c : { id: c.id, kev: c.kev, epss: c.epss, exploit: c.exploit, detect: c.detect })),
    };
    try {
      mkdirSync(DIR, { recursive: true });
      writeFileSync(`${FILE}.tmp`, JSON.stringify(data));
      renameSync(`${FILE}.tmp`, FILE);
    } catch (e) {
      console.error('Could not save state:', e.message);
    }
  }, 5000);
}

export function restoreState() {
  if (config.mode !== 'live' || !existsSync(FILE)) return null;
  const data = JSON.parse(readFileSync(FILE, 'utf8'));
  for (const c of data.catalog || []) {
    if (catalogById[c.id]) Object.assign(catalogById[c.id], c);
    else { CATALOG.push(c); catalogById[c.id] = c; }
  }
  for (const a of data.assets || []) store.addAsset({ ...a, lastSeenAgo: toAgo(a.lastSeenAt) });
  for (const f of data.findings || []) {
    store.findings.push({
      ...f, exposureAgo: toAgo(f.exposureAt), detectedAgo: toAgo(f.detectedAt), remediatedAgo: toAgo(f.remediatedAt),
      detected: Object.fromEntries(Object.entries(f.detectedBy || {}).map(([k, v]) => [k, toAgo(v)])),
    });
  }
  for (const f of store.findings) f.sla = slaState(f);
  for (const t of data.tickets || []) store.tickets.push({ ...t, createdAgo: toAgo(t.createdAt) });
  if (data.ticketSeq) store.setTicketSeq(data.ticketSeq);
  return { assets: store.assets.length, findings: store.findings.length, savedAt: data.savedAt };
}
