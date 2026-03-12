# NightWatch Sentinel

**Browser-native cybersecurity platform** that unifies threat detection, risk scoring, and AI-powered incident response into a single operator console.

## The Problem

Security teams at SMBs juggle disconnected tools for permission auditing, phishing triage, device posture checks, and incident response. NightWatch Sentinel replaces that fragmented workflow with a single scan that produces an actionable, Gemini-generated playbook — no agents, no installs, zero deployment friction.

## Key Features

- **Unified Threat Scan** — Runs 5 analyzers in parallel (permissions, device surface, network signals, Bluetooth, URL heuristics) and consolidates findings
- **Risk Scoring Engine** — Severity-weighted 0–100 score with critical+high breakout and confidence scoring
- **AI Incident Playbooks** — Gemini 2.0 Flash generates structured containment, hardening, and roadmap plans from scan context
- **Scenario Lab** — 4 preset threat narratives (phishing kit, shadow network, rogue device, rapid hardening) for demos and testing
- **Event Relay API** — REST endpoints for event ingestion, retrieval, and playbook generation
- **Operator Console** — Terminal-style workspace with keyboard shortcuts, live telemetry, and severity filtering

## Quick Start

```bash
# 1. Clone and enter the project
git clone https://github.com/AmRitJain0442/PVD-Integration.git
cd PVD-Integration

# 2. Create env file and add your Gemini key
copy .env.example .env
# Edit .env → set GEMINI_API_KEY (get one at https://aistudio.google.com/app/apikey)

# 3. Start the server
npm start

# 4. Open in browser
# http://localhost:3000
```

> **Requirements:** Node.js 20+ (zero external dependencies)

## Pages

| Route | Purpose |
|-------|---------|
| `/` | Landing page — product pitch and navigation |
| `/platform` | Platform overview — system architecture and roadmap |
| `/console` | Operator console — live scanning, triage, and response |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Service health + Gemini config state |
| `GET` | `/api/events` | Retrieve last 100 ingested events |
| `POST` | `/api/events/ingest` | Store incoming event payload |
| `POST` | `/api/gemini/analyze` | Generate AI incident playbook (rate limited) |

## Architecture

```
Browser Client
├── app.js          → UI orchestration, scan workflow, event relay
├── modules/
│   ├── analyzers.js → 5 pluggable analyzer modules
│   └── riskEngine.js → Severity-weighted scoring engine
│
Server (zero-dep Node.js)
├── server.js       → Static serving, API routes, Gemini proxy
├── Security headers, CORS, rate limiting
└── In-memory event buffer (500 max)
```

## Security Features

- **CORS** — Configurable origin allowlist via `CORS_ORIGINS` env var
- **Rate limiting** — Gemini endpoint capped at 10 req/min (configurable)
- **Security headers** — X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- **Input validation** — Body size limits, JSON validation, string sanitization
- **Request timeouts** — 15s timeout on Gemini API calls
- **Path traversal protection** — Normalized paths checked against public directory boundary
- **XSS prevention** — HTML escaping on all user-generated display content

## Keyboard Shortcuts (Console)

| Key | Action |
|-----|--------|
| `/` | Focus URL triage input |
| `g` | Focus mission prompt |
| `r` | Run full threat scan |
| `e` | Refresh event relay |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes | — | Google Gemini API key for playbook generation |
| `PORT` | No | `3000` | Server port |
| `CORS_ORIGINS` | No | `*` | Comma-separated allowed origins |
| `GEMINI_RATE_LIMIT` | No | `10` | Max Gemini requests per minute |
| `NODE_ENV` | No | — | Set to `production` to hide detailed errors |

## Future Roadmap

- Multi-tenant auth and team dashboards
- Saved scan sessions with historical comparison
- Command palette for keyboard-first navigation
- Webhook connectors for SIEM/SOAR integration
- TypeScript migration and Next.js framework upgrade
- PostgreSQL persistence layer

