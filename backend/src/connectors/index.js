// Connectors to the systems ExposureIQ reads from and writes to. Each one has the same methods
// whether it talks to the real API (credentials in .env) or to the built-in mock tenant, so the
// rest of the backend never knows the difference.
//
//   Microsoft Defender for Endpoint / MDVM   Entra ID app (client credentials), Machine.Read.All + Vulnerability.Read.All
//   Rapid7 InsightVM (console API v3)        basic auth, a user with "Manage sites" / read access to the sites in scope
//   ServiceNow Table API                     basic auth, read on the CMDB table, create on the ticket table
//   CISA KEV · FIRST EPSS                    public feeds, no credentials
//   SOC notification                         any incoming-webhook URL that accepts {"text": "..."} (Teams, Slack)
import { config, configured } from '../config.js';
import { fetchJson, basicAuth } from './http.js';
import * as mock from '../mock/tenant.js';

const live = config.mode === 'live';
const status = (name, mode) => ({ name, mode, lastSync: null, lastError: null, lastCount: null, calls: 0 });
const modeFor = (key) => (live ? (configured[key] ? 'live' : 'off') : 'mock');

// ---------------- Microsoft Defender for Endpoint ----------------
const d = config.defender;
let defenderToken = null;
async function defenderAuth() {
  if (defenderToken && defenderToken.exp > Date.now() + 60000) return defenderToken.value;
  const j = await fetchJson(`https://login.microsoftonline.com/${d.tenantId}/oauth2/v2.0/token`, {
    method: 'POST', form: { client_id: d.clientId, client_secret: d.clientSecret, grant_type: 'client_credentials', scope: d.scope },
  });
  defenderToken = { value: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return defenderToken.value;
}
async function defenderAll(path) {
  const out = [];
  let url = `${d.apiBase}${path}`;
  while (url) {
    const j = await fetchJson(url, { headers: { Authorization: `Bearer ${await defenderAuth()}` }, timeoutMs: 120000 });
    defender.status.calls++;
    out.push(...(j.value || []));
    url = j['@odata.nextLink'] || null;
  }
  return out;
}

export const defender = {
  id: 'defender',
  status: status('Microsoft Defender for Endpoint / MDVM', modeFor('defender')),
  async machines() {
    if (this.status.mode === 'mock') return mock.defender.machines().value;
    return defenderAll('/api/machines?$top=10000');
  },
  async machine(id) {
    if (!id) return null;
    if (this.status.mode === 'mock') return mock.defender.machine(id);
    this.status.calls++;
    return fetchJson(`${d.apiBase}/api/machines/${encodeURIComponent(id)}`, { headers: { Authorization: `Bearer ${await defenderAuth()}` } });
  },
  // Full snapshot: one row per device × software × CVE.
  async vulnerabilitiesFull() {
    if (this.status.mode === 'mock') return mock.defender.softwareVulnerabilitiesByMachine().value;
    return defenderAll('/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=50000');
  },
  // Changes since a point in time (New / Fixed / Updated). The API accepts at most 14 days back.
  async vulnerabilityChanges(sinceIso) {
    const since = new Date(Math.max(new Date(sinceIso).getTime(), Date.now() - 13.9 * 86400000)).toISOString();
    if (this.status.mode === 'mock') return mock.defender.softwareVulnerabilityChangesByMachine(since).value;
    return defenderAll(`/api/machines/SoftwareVulnerabilityChangesByMachine?pageSize=50000&sinceTime=${encodeURIComponent(since)}`);
  },
  async test() {
    if (this.status.mode === 'mock') return { ok: true, detail: `Mock tenant · ${mock.defender.machines().value.length} devices` };
    await defenderAuth();
    const j = await fetchJson(`${d.apiBase}/api/machines?$top=1`, { headers: { Authorization: `Bearer ${await defenderAuth()}` } });
    return { ok: true, detail: `Token OK · machines API reachable (${(j.value || []).length ? 'devices found' : 'no devices returned'})` };
  },
};

// ---------------- Rapid7 InsightVM ----------------
const r = config.rapid7;
const r7Headers = () => ({ Authorization: basicAuth(r.username, r.password) });
async function r7All(path) {
  const out = [];
  for (let page = 0; ; page++) {
    const sep = path.includes('?') ? '&' : '?';
    const j = await fetchJson(`${r.url}/api/3${path}${sep}page=${page}&size=500`, { headers: r7Headers(), timeoutMs: 60000 });
    rapid7.status.calls++;
    out.push(...(j.resources || []));
    if (!j.page || page + 1 >= j.page.totalPages) return out;
  }
}
const r7Defs = new Map();

export const rapid7 = {
  id: 'rapid7',
  status: status('Rapid7 InsightVM', modeFor('rapid7')),
  async sites() {
    if (this.status.mode === 'mock') return mock.rapid7.sites().resources;
    const all = await r7All('/sites');
    return r.sites.length ? all.filter((s) => r.sites.includes(String(s.id))) : all;
  },
  async siteAssets(siteId) {
    if (this.status.mode === 'mock') return mock.rapid7.siteAssets(siteId).resources;
    return r7All(`/sites/${siteId}/assets`);
  },
  async asset(id) {
    if (!id) return null;
    if (this.status.mode === 'mock') return mock.rapid7.asset(id);
    this.status.calls++;
    return fetchJson(`${r.url}/api/3/assets/${encodeURIComponent(id)}`, { headers: r7Headers() });
  },
  async assetVulnerabilities(assetId) {
    if (this.status.mode === 'mock') return mock.rapid7.assetVulnerabilities(assetId).resources;
    return r7All(`/assets/${assetId}/vulnerabilities`);
  },
  async vulnerability(key) {
    if (this.status.mode === 'mock') return mock.rapid7.vulnerability(key);
    if (!r7Defs.has(key)) {
      r7Defs.set(key, await fetchJson(`${r.url}/api/3/vulnerabilities/${encodeURIComponent(key)}`, { headers: r7Headers() }));
      this.status.calls++;
    }
    return r7Defs.get(key);
  },
  async test() {
    if (this.status.mode === 'mock') return { ok: true, detail: `Mock console · ${mock.rapid7.sites().resources.length} sites` };
    const j = await fetchJson(`${r.url}/api/3/sites?size=1`, { headers: r7Headers() });
    return { ok: true, detail: `Console reachable · ${j.page?.totalResources ?? '?'} sites visible to this user` };
  },
};

// ---------------- ServiceNow ----------------
const s = config.servicenow;
const snHeaders = () => ({ Authorization: basicAuth(s.username, s.password) });
const CMDB_FIELDS = ['sys_id', 'name', 'fqdn', 'ip_address', 'mac_address', 'serial_number', 'os', 'sys_class_name', 'company', 'location', 'support_group', s.tierField, s.serviceField, s.internetField, 'u_compensating_controls'];

export const servicenow = {
  id: 'servicenow',
  status: status('ServiceNow (CMDB + tickets)', modeFor('servicenow')),
  async cmdb() {
    if (this.status.mode === 'mock') return mock.servicenow.cmdb().result;
    const out = [];
    for (let offset = 0; ; offset += 1000) {
      const j = await fetchJson(`${s.instance}/api/now/table/${s.cmdbTable}?sysparm_limit=1000&sysparm_offset=${offset}&sysparm_display_value=true&sysparm_exclude_reference_link=true&sysparm_fields=${CMDB_FIELDS.join(',')}`, { headers: snHeaders(), timeoutMs: 120000 });
      this.status.calls++;
      out.push(...(j.result || []));
      if ((j.result || []).length < 1000) return out;
    }
  },
  async ci(sysId) {
    if (!sysId) return null;
    if (this.status.mode === 'mock') return mock.servicenow.ci(sysId);
    this.status.calls++;
    const j = await fetchJson(`${s.instance}/api/now/table/${s.cmdbTable}/${sysId}?sysparm_display_value=true&sysparm_exclude_reference_link=true&sysparm_fields=${CMDB_FIELDS.join(',')}`, { headers: snHeaders() });
    return j.result || null;
  },
  async createTicket({ shortDescription, description, assignmentGroup, urgency = 2, impact = 2, ci }) {
    const body = { short_description: shortDescription, description, assignment_group: assignmentGroup, urgency, impact, cmdb_ci: ci };
    if (this.status.mode !== 'live') return mock.servicenow.createRecord(s.ticketTable, body).result;
    const j = await fetchJson(`${s.instance}/api/now/table/${s.ticketTable}`, { method: 'POST', headers: snHeaders(), body });
    this.status.calls++;
    return j.result;
  },
  async test() {
    if (this.status.mode === 'mock') return { ok: true, detail: `Mock instance · ${mock.servicenow.cmdb().result.length} CIs` };
    await fetchJson(`${s.instance}/api/now/table/${s.cmdbTable}?sysparm_limit=1&sysparm_fields=sys_id`, { headers: snHeaders() });
    return { ok: true, detail: `Table API reachable · ${s.cmdbTable} readable` };
  },
};

// ---------------- CISA KEV · FIRST EPSS (public, no credentials) ----------------
export const intel = {
  id: 'intel',
  status: status('CISA KEV · FIRST EPSS', live ? 'live' : 'mock'),
  async kev() {
    if (this.status.mode === 'mock') return mock.intel.kev().vulnerabilities;
    const j = await fetchJson(config.intel.kevUrl, { timeoutMs: 60000 });
    this.status.calls++;
    return j.vulnerabilities || [];
  },
  async epss(cves) {
    const ids = cves.filter((c) => /^CVE-/.test(c));
    if (this.status.mode === 'mock') return mock.intel.epss(ids).data;
    const out = [];
    for (let i = 0; i < ids.length; i += 80) {
      const j = await fetchJson(`${config.intel.epssUrl}?cve=${ids.slice(i, i + 80).join(',')}`);
      this.status.calls++;
      out.push(...(j.data || []));
    }
    return out;
  },
  async test() {
    if (this.status.mode === 'mock') return { ok: true, detail: 'Mock feeds' };
    const j = await fetchJson(`${config.intel.epssUrl}?cve=CVE-2021-44228`);
    return { ok: true, detail: `EPSS reachable (Log4Shell EPSS ${j.data?.[0]?.epss ?? '?'})` };
  },
};

// ---------------- SOC notifications ----------------
export const soc = {
  id: 'soc',
  status: status('SOC notifications (webhook)', configured.soc ? 'live' : 'mock'),
  sent: [],
  async notify(text) {
    const entry = { at: new Date().toISOString(), text };
    this.sent.unshift(entry);
    this.sent.length = Math.min(this.sent.length, 50);
    if (this.status.mode === 'live') {
      await fetchJson(config.soc.webhookUrl, { method: 'POST', body: { text } });
      this.status.calls++;
    }
    return { delivered: this.status.mode === 'live' ? 'webhook' : 'mock log' };
  },
  async test() {
    return { ok: true, detail: this.status.mode === 'live' ? 'Webhook configured (not called by the test)' : 'Mock: notifications are logged only' };
  },
};

export const CONNECTORS = { defender, rapid7, servicenow, intel, soc };

export function connectorStatus() {
  return Object.values(CONNECTORS).map((c) => ({ id: c.id, ...c.status }));
}

export async function testConnector(id) {
  const c = CONNECTORS[id];
  if (!c) return { ok: false, detail: 'Unknown connector' };
  if (c.status.mode === 'off') return { ok: false, detail: 'Not configured: add credentials to backend/.env and restart' };
  try {
    return await c.test();
  } catch (e) {
    return { ok: false, detail: `${e.message}${e.body ? ` · ${e.body.slice(0, 160)}` : ''}` };
  }
}
