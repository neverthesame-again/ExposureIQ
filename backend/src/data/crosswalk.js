// Each tool names a weakness its own way. CVEs line up by themselves; everything else (end-of-life
// software, configuration checks) needs this crosswalk to land on one canonical ExposureIQ id.
// Add rows here as you meet new non-CVE checks in your own Defender / Rapid7 data.
const ROWS = [
  // canonical id     Defender (TVM id)     Rapid7 check key
  ['EOL-WS2012R2', 'TVM-2020-0002', 'microsoft-windows-server-2012-r2-obsolete'],
  ['R7-SMB-SIGNING', 'TVM-2021-0019', 'cifs-smb-signing-not-required'],
  ['R7-TLS-WEAK', null, 'tls-server-supports-tls-1-0-1-1'],
  ['R7-SSL-SELFSIGNED', null, 'ssl-self-signed-certificate'],
  ['R7-ICMP-TS', null, 'generic-icmp-timestamp'],
];

const fromMde = Object.fromEntries(ROWS.filter((r) => r[1]).map(([c, m]) => [m, c]));
const fromR7 = Object.fromEntries(ROWS.filter((r) => r[2]).map(([c, , k]) => [k, c]));
const toMde = Object.fromEntries(ROWS.filter((r) => r[1]).map(([c, m]) => [c, m]));
const toR7 = Object.fromEntries(ROWS.filter((r) => r[2]).map(([c, , k]) => [c, k]));

// Defender row → canonical id
export const canonicalFromDefender = (cveId) => fromMde[cveId] || cveId;

// Rapid7 vulnerability definition → canonical id
export function canonicalFromRapid7(key, cves = []) {
  if (fromR7[key]) return fromR7[key];
  if (cves.length) return cves[0];
  return `R7-${key.toUpperCase()}`;
}

// Canonical id → how the mock tenant spells it in each tool
export const defenderIdFor = (cat) => toMde[cat.id] || cat.id;
export function rapid7KeyFor(cat) {
  if (toR7[cat.id]) return toR7[cat.id];
  if (cat.id.startsWith('CVE-')) return `${cat.product.toLowerCase().split(/\s+/)[0].replace(/[^a-z0-9]/g, '')}-${cat.id.toLowerCase()}`;
  return cat.id.replace(/^R7-/, '').toLowerCase();
}
