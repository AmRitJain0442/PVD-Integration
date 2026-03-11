# NightWatch Sentinel

NightWatch Sentinel is a hackathon-grade cybersecurity web app built around a market gap:

- Security posture tools are fragmented across endpoint checks, phishing triage, permission audits, and response guidance.
- Small teams need a single interface that can quickly scan browser/device exposure and generate an actionable incident playbook.

This project ships a cohesive MVP with:

- Cyber-themed, high-clarity web UI
- Modular client-side analyzers (permissions, device surface, network signals, URL risk heuristics)
- API-first backend with event ingestion endpoints
- Gemini-based remediation copilot using `GEMINI_API_KEY` from `.env`
- Exportable JSON report for integrations

## Why This Is A Strong Hackathon Idea

- Clear market pain: Security teams lose time juggling disconnected tools.
- Immediate value: One click gives risk score + prioritized findings + remediation plan.
- Startup path: Analyzer modules and event API are easy to integrate into SOC pipelines, SIEM, and managed security products.

## Quick Start

1. Create env file:

```bash
copy .env.example .env
```

2. Put your Gemini key in `.env`:

```env
GEMINI_API_KEY=your_real_key
PORT=3000
```

3. Run:

```bash
npm start
```

4. Open:

```text
http://localhost:3000
```

## Core Features

- Full Threat Scan: Runs all analyzers and builds a unified risk context.
- Permission Pulse: Audits browser permission states and requests high-value permissions on demand.
- Network & Surface Signals: Collects local network metadata and browser/device hardening indicators.
- URL Threat Heuristics: Detects suspicious URL characteristics for phishing triage.
- Gemini SOC Copilot: Generates practical incident and hardening plan from scan data.
- Integration Hooks: POST scan events to `/api/events/ingest` and pull recent events from `/api/events`.

## API Endpoints

- `GET /api/health` -> Service health + Gemini config state
- `POST /api/gemini/analyze` -> Gemini playbook generation
- `POST /api/events/ingest` -> Store incoming event payload
- `GET /api/events` -> Read recent ingested events

## Architecture

- `server.js` -> Zero-dependency Node HTTP server + API routes
- `public/app.js` -> UI orchestration + workflow logic
- `public/modules/riskEngine.js` -> Risk scoring and scan-state normalization
- `public/modules/analyzers.js` -> Pluggable analyzer functions
- `docs/market-gaps.md` -> Market analysis and product rationale

## Future Extensions

- Multi-tenant auth and team dashboards
- Agent-based endpoint collector (desktop helper)
- Threat intel feeds and IOC enrichment (optional free/open sources)
- Webhook connectors for SIEM/SOAR

