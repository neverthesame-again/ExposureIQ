# ExposureIQ — SHV Group Vulnerability Intelligence (POC)

> **Use case:** Lack of centralised visibility for cross-group vulnerability information (Rapid7 & Microsoft Defender for Endpoint).
> **Positioning:** Rapid7 stays a *source* · Microsoft Defender Vulnerability Management (MDVM) becomes the *exposure-management layer* · Power BI is the *reporting layer* · GenAI adds *insight* on top.

All data is **simulated** by the backend. It is generated deterministically, so every run shows the same numbers, and every screen reconciles with every other screen.

## Run it

Requires Node.js 18+.

```bash
cd exposureiq-poc/backend
npm install
npm start          # http://localhost:4100
```

```bash
cd exposureiq-poc/frontend
npm install
npm run dev        # http://localhost:5180  (proxies /api → :4100)
```

Open http://localhost:5180.

## What's inside

| Screen | Who it's for | What it shows |
|---|---|---|
| **Command Center** | Group CISO / leadership | AI executive briefing, enterprise exposure score gauge, KPIs (P1/P2, KEV, SLA, MTTR, MTTI, coverage), 13-week trend, company scorecard, "fix these first", the correlation dividend |
| **Ask ExposureIQ** | Everyone | GenAI copilot (simulated): board summaries, patch plans, KEV exposure, SLA breaches, company deep dives, CVE explanations. Answers include tables, cited sources and follow-up questions |
| **Vulnerabilities** | Security analysts | One de-duplicated, risk-ranked list across both tools. Filters, CSV export and a detail drawer with the score breakdown, a "two tools, one truth" comparison, AI remediation guidance and ServiceNow ticket creation |
| **Assets & Coverage** | Analysts, infra leads | Unified inventory, scanner coverage donut, "who sees what" by asset type, blind spots found by Defender device discovery |
| **Remediation & SLA** | BU IT leads | SHV unified SLA policy, company × priority compliance heatmap, MTTR vs target, backlog ageing, inflow vs outflow, overdue work, team accountability |
| **Correlation Engine** | Analysts, auditors | Sankey of 2 raw feeds → unified findings, overlap Venn, MTTI by source, severity disagreements resolved, asset-match review queue |
| **Data Sources** | Platform team | Animated data pipeline, connector health, sync now, field mappings (MDVM, MDE, Rapid7, CMDB, KEV/EPSS, Power BI, Azure OpenAI) |
| **Reports** | Leadership, audit | Weekly ops, monthly executive and audit evidence packs. Printable (Save as PDF), with schedules |
| **Trial & Value Tracker** | Steering group | 90-day MDVM trial countdown, 4-phase PoV plan with tasks you can tick off, success criteria (baseline vs today vs target), prerequisites |

Other things to try: the **company selector** (scopes every view), the **persona switcher** (CISO / Analyst / BU IT Lead each land on their own view), **Ctrl + K** search, and the light/dark toggle.

## Live mode

The Command Center is live. Every 6 seconds `backend/src/live.js` simulates a batch arriving from one source (Defender, Rapid7 scan job, ServiceNow CMDB or KEV/EPSS). The batch passes through the same six steps a real connector would: collect → normalise → correlate & de-duplicate → risk score → prioritise & SLA → deliver. New findings, confirmed fixes and auto-raised tickets are written to the shared store, so every other screen stays consistent with the live view.

- `GET /api/live/stream?company=`: Server-Sent Events (`snapshot` on connect, then a `batch` event per tick)
- `GET /api/live`: the current live view as plain JSON
- `POST /api/live/trigger` `{ "source": "MDE" | "R7" | "CMDB" | "INTEL" }`: run a batch now (the "Run now" buttons)

Change `TICK_MS` in `live.js` to speed up or slow down the feed. Live changes are in memory and reset when the backend restarts.

## AI agents (simulated reasoning)

`backend/src/agents.js` defines four agents. Each one has a goal, a fixed list of tools and guardrails on what it may do without a person. Every run is stored as a trace (thought → tool call → result → decision) and shown on the **AI Agents** page.

| Agent | Triggered by | Acts alone | Needs a person |
|---|---|---|---|
| Triage | Each new P1/P2 or KEV finding in the live feed | Raise tickets, add to existing tickets, escalate to SOC | Risk acceptance |
| Asset-Match | Each CMDB sync, or "Run now" | Merge at ≥ 90% confidence | Merges below 90% |
| Remediation Planner | Daily (runs at startup), or "Run now" | Draft campaigns | Submit to ServiceNow |
| Analyst Copilot | Each question on Ask ExposureIQ | Read-only | — |

The reasoning is scripted over the real store, so decisions are consistent with every other screen. In production each agent would be an LLM (e.g. Azure OpenAI) calling the same tools, with guardrails enforced outside the model.

- `GET /api/agents`: agents, stats, approvals and recent runs
- `POST /api/agents/:id/run` (`triage` | `match` | `planner`): run an agent now
- `POST /api/approvals/:id` `{ "decision": "approve" | "reject" }`

## How the mock works

```
backend/
  server.js                 Express API (all endpoints)
  src/data/companies.js     Group companies, tool coverage, maturity, SLA policy  ← edit to change the story
  src/data/catalog.js       ~45 real CVEs / config weaknesses, with which tool detects each one
  src/data/generator.js     Seeded generator: assets, per-tool detections, correlation, remediation history
  src/analytics.js          KPIs, trends, scorecards, reconciliation, SLA; everything derived from findings
  src/insights.js           Simulated GenAI: briefings, copilot intents, reports, integrations, PoV tracker
frontend/src/
  App.jsx, nav.js           Shell, routing (hash), personas
  pages/*.jsx               One file per screen
  components/charts.jsx     Hand-built SVG charts (line, stacked columns, donut, gauge, Venn, Sankey)
```

- **Correlation:** each asset may be covered by Defender, Rapid7, both or neither. A weakness produces one *unified finding* per (asset, CVE), carrying every source that detected it. Raw rows minus unified findings = duplicates removed.
- **Unified risk score (0–100):** CVSS × 5 (50) + KEV / exploit maturity (20) + EPSS (8) + business criticality from CMDB (15) + internet-facing (10). It maps to the SHV SLA: P1 ≥ 85 → 7 days, P2 ≥ 70 → 30 days, P3 ≥ 50 → 60 days, P4 → 90 days.
- **MTTI:** Defender detects within ~1 day (agent); Rapid7 detects on its scan cadence (7–30 days per company). Unified MTTI takes the earliest signal from either tool.
- **State:** tickets, PoV task ticks and connector syncs live in memory and reset when the backend restarts.

## Main API endpoints

`GET /api/overview?company=` · `GET /api/vulnerabilities` · `GET /api/vulnerabilities/:cve` · `GET /api/assets` · `GET /api/assets/:id` · `GET /api/reconciliation` · `GET /api/remediation` · `POST /api/copilot` · `POST /api/tickets` · `GET /api/integrations` · `POST /api/integrations/:id/sync` · `GET /api/pov` · `GET /api/reports/:type` (weekly | monthly | audit) · `GET /api/search?q=`

## Path to production (for the discussion)

1. Replace `generator.js` with connectors: Defender XDR API / Advanced Hunting (`DeviceTvmSoftwareVulnerabilities`, `DeviceInfo`), Rapid7 InsightVM API v3, ServiceNow CMDB Table API, CISA KEV + FIRST EPSS feeds.
2. Persist to a store (e.g. Fabric Lakehouse / Azure SQL) and publish the same model to Power BI.
3. Swap `insights.js` templates for Azure OpenAI prompts grounded on the computed metrics (EU data boundary; no raw host data in prompts).
