# ExposureIQ — SHV Group Vulnerability Intelligence (agentic POC)

> **Use case:** Lack of centralised visibility for cross-group vulnerability information (Rapid7 & Microsoft Defender for Endpoint).
> **Positioning:** Rapid7 stays a *source* · Microsoft Defender Vulnerability Management (MDVM) becomes the *exposure-management layer* · Power BI is the *reporting layer* · four AI agents (Gemini) triage, match, plan and answer on top.

ExposureIQ runs in one of two modes, chosen automatically from `backend/.env`:

| Mode | When | Data |
|---|---|---|
| **Mock tenant** (default) | No source credentials configured | A simulated SHV estate that answers in the exact JSON of the Defender, Rapid7 InsightVM, ServiceNow, CISA KEV and FIRST EPSS APIs, and keeps changing (new vulnerabilities, patches, CMDB edits, KEV additions) |
| **Live** | Any of Defender / Rapid7 / ServiceNow credentials present | Your real systems. Sources without credentials are switched off. History is kept in `backend/data/state.json` |

Both modes use the same connectors' method signatures, the same normalisation and correlation code, and the same agents.

## Run it

Requires Node.js 20.12+.

```bash
cd backend
npm install
npm start          # http://localhost:4100
```

```bash
cd frontend
npm install
npm run dev        # http://localhost:5180  (proxies /api → :4100)
```

Open http://localhost:5180. **Data Sources → Connections** shows each connector's mode, last sync, errors and a *Test* button.

## Turn on the AI agents (Gemini)

Put your key in `backend/.env` (git-ignored) and restart the backend:

```
GEMINI_API_KEY=your-key
GEMINI_MODEL=gemini-3.8-flash      # optional
AGENT_MAX_RUNS_PER_MIN=4           # budget; extra work falls back to the rules engine
```

Without a key, every agent runs on a deterministic rules engine with the same tools, guardrails and trace format.

## Connect your real systems

Copy what you need from `backend/.env.example` into `backend/.env`, then restart. Credentials stay on the server; the browser never sees them.

| Source | What you need | API used |
|---|---|---|
| **Microsoft Defender for Endpoint / MDVM** | Entra ID app registration with *WindowsDefenderATP* application permissions `Machine.Read.All` and `Vulnerability.Read.All` (admin consent) → `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` | `/api/machines`, `/api/machines/SoftwareVulnerabilitiesByMachine` (first full snapshot), `/api/machines/SoftwareVulnerabilityChangesByMachine` (changes since last sync) |
| **Rapid7 InsightVM** | Security console URL and a user with read access to the sites in scope → `RAPID7_CONSOLE_URL`, `RAPID7_USERNAME`, `RAPID7_PASSWORD` (optionally `RAPID7_SITE_IDS`). For a self-signed console certificate, start the backend with `NODE_EXTRA_CA_CERTS=path/to/ca.pem` | API v3: `/sites`, `/sites/{id}/assets`, `/assets/{id}/vulnerabilities`, `/vulnerabilities/{id}` |
| **ServiceNow** | Instance URL and a user with read on the CMDB table and create on the ticket table → `SERVICENOW_*`. Map your CMDB field names with `SERVICENOW_TIER_FIELD`, `SERVICENOW_SERVICE_FIELD`, `SERVICENOW_INTERNET_FIELD` | Table API: `cmdb_ci_computer` (read), `incident` (create) |
| **CISA KEV · FIRST EPSS** | Nothing (public feeds); used automatically in live mode | KEV JSON feed, EPSS API |
| **SOC notifications** | Optional `SOC_WEBHOOK_URL` (Teams / Slack incoming webhook) | POST `{ "text": … }` |

Group companies are recognised from Defender device-group names, Rapid7 site names and the CMDB `company` field. Edit `backend/src/data/companies.js` so the names match yours. Non-CVE checks (end-of-life software, configuration findings) are mapped between tools in `backend/src/data/crosswalk.js`.

> The connectors are built against the vendors' documented API formats and tested end-to-end against the mock tenant, which returns the same shapes. Expect to adjust field mappings on first connection to a real tenant: custom CMDB fields, device-group naming, permissions.

## How data flows

```
 Defender ─┐                    ┌─ normalise (device ids, CVE / TVM / Rapid7 check ids via crosswalk)
 Rapid7 ───┼─ connectors ──────►├─ correlate (one asset per device: Defender id → Entra id → hostname → MAC+IP → fuzzy)
 CMDB ─────┤  (real or mock)    ├─ de-duplicate (one finding per asset × weakness), detect fixes, re-score
 KEV/EPSS ─┘                    └─ store ──► dashboards · Power BI · AI agents · ServiceNow
```

The Command Center streams every sync as a batch that walks six steps: **Collect → Normalise → Correlate → Score & prioritise → AI agent triage → Deliver**.

| Sync | Mock tenant | Live |
|---|---|---|
| Defender | changes every few seconds | first a full snapshot, then changes since the last sync, every `DEFENDER_SYNC_MINUTES` |
| Rapid7 | a random site's scan | each site in turn; every site re-read once per `RAPID7_SYNC_MINUTES` |
| CMDB | occasional re-classification of a server to Crown Jewel | every `CMDB_SYNC_MINUTES` |
| KEV / EPSS | occasional CISA addition | every `INTEL_SYNC_MINUTES` |

## The four AI agents

Each agent has a goal, a fixed set of tools and guardrails. The model (Gemini, via function calling) decides what to look up and what to do; **this backend executes actions only after guardrail checks**. Every thought, tool call, guardrail intervention and decision is traced on the **AI Agents** page as it happens.

| Agent | Triggered by | Tools | Acts alone | Needs a person |
|---|---|---|---|---|
| **Triage** | New P1/P2 or KEV findings; findings whose priority rises (CMDB or KEV change) | asset context, threat intel, compensating controls (CMDB), open tickets | Tickets, adding to tickets, SOC escalation | Risk acceptance (never allowed for P1/KEV) |
| **Asset-Match** | CMDB syncs; *Run now* | CMDB record, Defender device, Rapid7 asset, identity comparison | Merge at ≥ 90% **and** identical MAC; keep apart at ≥ 90% | Anything less certain |
| **Remediation Planner** | Start-up; *Run now* | open findings by team × fix, change calendar | Drafting | Submitting to ServiceNow (campaigns are validated against real findings first) |
| **Analyst Copilot** | Questions on *Ask ExposureIQ* | read-only KPIs, findings, scorecard, remediation, reconciliation, assets, trend | Answering | — |

If Gemini is unavailable, over budget or returns an error, the run finishes on the rules engine, and the trace says so.

## Code map

```
backend/
  server.js                   Express API
  .env.example                every setting, documented
  src/config.js               reads .env, picks mock / live mode
  src/connectors/             Defender, Rapid7, ServiceNow, KEV/EPSS, SOC webhook (real + mock)
  src/mock/tenant.js          the mock tenant: real API shapes, an estate that changes over time
  src/ingest/correlate.js     normalisation, asset matching, de-duplication, fix detection, re-scoring
  src/data/crosswalk.js       non-CVE ids across tools
  src/live.js                 sync scheduler + live stream (SSE) to the UI
  src/ai/gemini.js            Gemini client (generateContent + function calling), agent loop, budget
  src/agents/tools.js         tools the agents can call
  src/agents.js               the four agents, guardrails, approvals
  src/state.js                live-mode history (data/state.json)
  src/data/generator.js       mock-mode history (13 months, seeded)
  src/analytics.js            KPIs, trends, scorecards, SLA (all screens)
frontend/src/
  pages/*.jsx                 one file per screen (Overview = Command Center, Agents, Sources, …)
  components/LivePipeline.jsx the six-step flow
  components/AgentTrace.jsx   agent trace viewer
```

- **Unified risk score (0–100):** CVSS × 5 (50) + KEV / exploit maturity (20) + EPSS (8) + business criticality from CMDB (15) + internet-facing (10). SLA: P1 ≥ 85 → 7 days, P2 ≥ 70 → 30, P3 ≥ 50 → 60, P4 → 90.

## API

`GET /api/connectors` · `POST /api/connectors/:id/test` · `GET /api/live/stream` (SSE: `snapshot`, `batch`, `batchUpdate`) · `POST /api/live/trigger {source: MDE|R7|CMDB|INTEL}` · `GET /api/agents` · `POST /api/agents/:id/run` · `POST /api/approvals/:id {decision}` · `POST /api/copilot {question, company}` · `GET /api/overview` · `GET /api/vulnerabilities[/:cve]` · `GET /api/assets[/:id]` · `GET /api/reconciliation` · `GET /api/remediation` · `GET /api/reports/:type`

## Still to do for production

1. Run against a real tenant and adjust field mappings (CMDB fields, device groups, crosswalk).
2. Move state from `data/state.json` to a database (e.g. Azure SQL / Fabric Lakehouse) and publish the model to Power BI.
3. Authentication for the UI (Entra ID SSO) and role-based approval rights.
4. Agent evaluation: replay a week of findings through Triage and compare with analyst decisions before widening its autonomy.
