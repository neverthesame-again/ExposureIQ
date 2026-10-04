// Runtime configuration, read from backend/.env (see .env.example).
// DATA_MODE=auto (default) runs on the built-in mock tenant until real credentials are present;
// as soon as any connector has credentials, ExposureIQ switches to live mode and only syncs
// from the configured sources.
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const envFile = path.join(ROOT, '.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

const env = (k, d = '') => String(process.env[k] ?? d).trim();
const num = (k, d) => (Number.isFinite(Number(env(k))) && env(k) !== '' ? Number(env(k)) : d);
const list = (k) => env(k).split(',').map((s) => s.trim()).filter(Boolean);

export const config = {
  port: num('PORT', 4100),
  gemini: {
    apiKey: env('GEMINI_API_KEY'),
    model: env('GEMINI_MODEL', 'gemini-3.8-flash'),
    apiBase: env('GEMINI_API_BASE', 'https://generativelanguage.googleapis.com/v1beta').replace(/\/+$/, ''),
    maxRunsPerMinute: num('AGENT_MAX_RUNS_PER_MIN', 3),
    backgroundRunsPerMinute: num('AGENT_BACKGROUND_RUNS_PER_MIN', 1),
    fallbackModels: list('GEMINI_FALLBACK_MODELS').length ? list('GEMINI_FALLBACK_MODELS') : ['gemini-3.5-flash-lite'],
    maxCallsPerMinute: num('GEMINI_MAX_CALLS_PER_MIN', 5),
    maxSteps: num('AGENT_MAX_STEPS', 10),
  },
  defender: {
    tenantId: env('DEFENDER_TENANT_ID'),
    clientId: env('DEFENDER_CLIENT_ID'),
    clientSecret: env('DEFENDER_CLIENT_SECRET'),
    apiBase: env('DEFENDER_API_BASE', 'https://api.security.microsoft.com'),
    scope: env('DEFENDER_SCOPE', 'https://api.securitycenter.microsoft.com/.default'),
    syncMinutes: num('DEFENDER_SYNC_MINUTES', 30),
  },
  rapid7: {
    url: env('RAPID7_CONSOLE_URL').replace(/\/+$/, ''),
    username: env('RAPID7_USERNAME'),
    password: env('RAPID7_PASSWORD'),
    sites: list('RAPID7_SITE_IDS'),
    includePotential: env('RAPID7_INCLUDE_POTENTIAL', 'false') === 'true',
    syncMinutes: num('RAPID7_SYNC_MINUTES', 60),
  },
  servicenow: {
    instance: env('SERVICENOW_INSTANCE').replace(/\/+$/, ''),
    username: env('SERVICENOW_USERNAME'),
    password: env('SERVICENOW_PASSWORD'),
    cmdbTable: env('SERVICENOW_CMDB_TABLE', 'cmdb_ci_computer'),
    ticketTable: env('SERVICENOW_TICKET_TABLE', 'incident'),
    tierField: env('SERVICENOW_TIER_FIELD', 'u_criticality_tier'),
    serviceField: env('SERVICENOW_SERVICE_FIELD', 'u_business_service'),
    internetField: env('SERVICENOW_INTERNET_FIELD', 'u_internet_facing'),
    syncMinutes: num('CMDB_SYNC_MINUTES', 720),
  },
  intel: {
    kevUrl: env('KEV_FEED_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
    epssUrl: env('EPSS_API_URL', 'https://api.first.org/data/v1/epss'),
    syncMinutes: num('INTEL_SYNC_MINUTES', 720),
  },
  soc: { webhookUrl: env('SOC_WEBHOOK_URL') },
  demoTickMs: num('DEMO_TICK_MS', 6000),
};

export const configured = {
  gemini: !!config.gemini.apiKey,
  defender: !!(config.defender.tenantId && config.defender.clientId && config.defender.clientSecret),
  rapid7: !!(config.rapid7.url && config.rapid7.username && config.rapid7.password),
  servicenow: !!(config.servicenow.instance && config.servicenow.username && config.servicenow.password),
  soc: !!config.soc.webhookUrl,
};

const requested = env('DATA_MODE', 'auto');
const anyReal = configured.defender || configured.rapid7 || configured.servicenow;
// mock: built-in tenant only · live: only real connectors (unconfigured ones are switched off)
config.mode = requested === 'mock' ? 'mock' : requested === 'live' || anyReal ? 'live' : 'mock';
