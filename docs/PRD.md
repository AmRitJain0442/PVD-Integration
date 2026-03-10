# Product Requirements Document — NightWatch Sentinel

**Version:** 1.0  
**Date:** March 11, 2026  
**Status:** Draft  
**Author:** Product Team

---

## 1. Executive Summary

NightWatch Sentinel is a browser-native cybersecurity platform that unifies threat detection, risk scoring, and incident response into a single operator console. It replaces the fragmented tooling that small security teams juggle daily — endpoint checks, phishing triagers, permission audits, and response runbooks — with a one-click scan that produces an actionable, AI-generated playbook.

The product's key differentiator is **zero-install, browser-native detection**: no agents, no endpoint software, no deployment friction. SOC analysts at small-to-medium businesses get enterprise-grade detection-to-response workflows without enterprise-grade complexity or cost.

V1 ships the current hackathon MVP (5 analyzers, risk engine, Gemini-powered playbooks, event relay API) and extends it with saved sessions, a command palette, webhook connectors, user authentication, and multi-tenant support — backed by a full-stack framework and persistent database.

---

## 2. Problem Statement

### The Problem

Security teams at SMBs operate with 1–5 analysts who must cover the same threat surface as enterprise SOCs with 50+ staff. They rely on a patchwork of disconnected tools:

| Task | Typical Tool | Pain |
|------|-------------|------|
| Permission auditing | Manual browser checks | No aggregation, no history |
| Phishing triage | URL scanners (VirusTotal, URLScan) | Context-switch per URL, no risk scoring |
| Device posture | Endpoint agents (if deployed) | Requires install, maintenance, budget |
| Incident response | Wikis, PDFs, tribal knowledge | Not actionable, not context-aware |
| SOC integration | SIEM/SOAR consoles | Expensive, complex onboarding |

### Three Market Gaps Addressed

1. **Fragmented Security Visibility** — No single tool provides a unified detection-to-action flow across permissions, URLs, device surface, and network signals.
2. **Detection-to-Remediation Friction** — Existing tools generate alerts but lack concrete, executable playbooks tailored to the specific findings.
3. **Poor API-First Design** — Early-stage security products build demo dashboards but don't expose ingestion/export APIs needed by real SOC workflows.

### Impact of Inaction

Without consolidation, SMB security teams waste 30–40% of analyst time on tool-switching and manual correlation. Alert fatigue leads to missed detections. Incident response depends on the most senior analyst being available.

---

## 3. Target Users

### Primary Persona: SOC Analyst at an SMB

| Attribute | Detail |
|-----------|--------|
| **Role** | Security Analyst / IT Security Generalist |
| **Team size** | 1–5 people covering all security operations |
| **Company size** | 50–500 employees |
| **Experience** | 2–7 years in IT/security |
| **Daily tools** | SIEM dashboard, email, ticketing system, 3–6 point security tools |
| **Budget authority** | Recommends tools; manager approves < $5K/month |

**Behaviors:**
- Triages 20–50 alerts per day across multiple consoles
- Responds to phishing reports from employees 3–5 times per week
- Runs ad-hoc security checks when onboarding new SaaS tools
- Documents incidents in shared docs or ticketing systems

**Pain Points:**
- Constant context-switching between disconnected tools
- No unified risk score — must mentally correlate findings
- Incident response playbooks are static documents, not tied to live data
- Can't justify enterprise SOAR platforms on SMB budgets
- Lack of historical scan data for trend analysis

### Secondary Persona: MSSP Analyst

Managed Security Service Providers serving multiple SMB clients need multi-tenant visibility and API-driven event ingestion to integrate NightWatch into their existing workflows.

---

## 4. Feature Requirements

### Priority Framework

| Priority | Definition |
|----------|-----------|
| **P0** | Must ship in v1 — product is incomplete without it |
| **P1** | Should ship in v1 — significant value, descope only if timeline demands |
| **P2** | Nice to have — schedule for v1.1 or later |

### P0 — Must Have (v1)

#### 4.1 Unified Threat Scan Engine
- **Description:** One-click scan that runs all analyzers in parallel and returns a consolidated finding set.
- **Analyzers (5 modules):**
  - **Permission Pulse** — Audits browser permissions (camera, microphone, geolocation, notifications, clipboard, Bluetooth)
  - **Device Surface Audit** — Collects platform, cookie state, hardware concurrency, secure context
  - **Network Signal Audit** — Extracts protocol, bandwidth, latency, local IP hints
  - **Bluetooth Audit** — Validates BLE support and secure context requirements
  - **URL Threat Heuristics** — Detects phishing via shortener domains, high-risk TLDs (`.zip`, `.click`, `.work`), lure keywords
- **Acceptance Criteria:**
  - Scan completes within 5 seconds under normal conditions
  - Each analyzer returns findings with severity (critical/high/medium/low/info) and confidence (0.0–1.0)
  - Scan failures in one analyzer do not block others

#### 4.2 Risk Scoring Engine
- **Description:** Normalizes findings from all analyzers into a single 0–100 risk score with severity-weighted calculation.
- **Scoring weights:** Critical = 30, High = 20, Medium = 11, Low = 5, Info = 1
- **Acceptance Criteria:**
  - Score updates in real-time as findings are added
  - Critical + high finding count is surfaced separately
  - Signal metadata from each analyzer is preserved for drill-down

#### 4.3 AI-Powered Incident Playbook (Gemini Integration)
- **Description:** Sends scan context to Google Gemini 2.0 Flash API and receives a structured incident response playbook.
- **Playbook sections:**
  - Immediate containment actions (0–4 hours)
  - Hardening steps (24–72 hours)
  - Product roadmap recommendations
  - SIEM/SOAR integration guidance
- **Acceptance Criteria:**
  - Playbook generates within 10 seconds
  - Output is structured, actionable, and specific to the scan findings
  - Graceful degradation if Gemini API is unavailable (display cached/fallback guidance)

#### 4.4 Operator Console
- **Description:** Terminal-style workspace with live telemetry, scenario lab, findings deck, playbook deck, relay deck, and context deck.
- **Features:**
  - Keyboard shortcuts (`/` focus URL, `g` mission prompt, `r` scan, `e` relay refresh)
  - Health monitor (API status, Gemini status, uptime)
  - Mini-cards for risk score, finding count, critical+high count, relay buffer
- **Acceptance Criteria:**
  - Console loads in < 2 seconds
  - All hotkeys function without conflict
  - Responsive layout at 1280px+ viewport

#### 4.5 Event Relay API
- **Description:** REST API for event ingestion and retrieval, enabling pipeline integration.
- **Endpoints:**
  - `GET /api/health` — Service health + Gemini configuration state
  - `GET /api/events` — Retrieve last 100 ingested events
  - `POST /api/events/ingest` — Store incoming security event payloads
  - `POST /api/gemini/analyze` — Generate incident response playbook
- **Acceptance Criteria:**
  - Events are persisted (not just in-memory buffer)
  - API returns proper HTTP status codes and JSON error bodies
  - Rate limiting on `/api/gemini/analyze` (max 10 req/min per tenant)

#### 4.6 User Authentication & Multi-Tenant Support
- **Description:** User accounts with role-based access, scoped to organizational tenants.
- **Requirements:**
  - Email/password registration and login
  - JWT-based session management
  - Tenant isolation — users only see their organization's data
  - Admin role can invite team members
- **Acceptance Criteria:**
  - Authentication tokens expire after 24 hours
  - Password hashing uses bcrypt with cost factor ≥ 12
  - Tenant data is fully isolated at the database level

### P1 — Should Have (v1)

#### 4.7 Saved Sessions
- **Description:** Persist scan contexts as historical incidents for replay, comparison, and trend analysis.
- **Requirements:**
  - Save scan results with timestamp, risk score, all findings, and playbook
  - List/search past sessions with filters (date range, risk score threshold, severity)
  - Compare two sessions side-by-side to track remediation progress
- **Acceptance Criteria:**
  - Sessions persist across browser refreshes and logins
  - Minimum 90-day retention per tenant

#### 4.8 Command Palette
- **Description:** Fast operator launcher for scan actions, filters, and route jumps — keyboard-first UX.
- **Requirements:**
  - `Ctrl+K` / `Cmd+K` opens palette
  - Fuzzy search across actions, recent sessions, and navigation targets
  - Extensible action registry for future modules
- **Acceptance Criteria:**
  - Palette opens in < 100ms
  - Top result is relevant for common queries (scan, playbook, settings)

#### 4.9 Webhook Connectors
- **Description:** Push structured payloads to external SIEM/SOAR destinations when scans complete or critical findings are detected.
- **Requirements:**
  - Configure webhook URLs per tenant with shared secret authentication
  - Payload format: JSON with scan summary, findings, risk score
  - Retry logic: 3 attempts with exponential backoff
  - Event types: `scan.completed`, `finding.critical`, `playbook.generated`
- **Acceptance Criteria:**
  - Webhooks fire within 5 seconds of trigger event
  - Failed deliveries are logged and visible in console
  - Webhook secrets are stored encrypted at rest

### P2 — Future (v1.1+)

| Feature | Description |
|---------|-------------|
| **Agent-based Endpoint Collector** | Desktop helper app for deeper OS-level telemetry beyond browser APIs |
| **Threat Intel Feed Integration** | Enrich findings with IOC data from MISP, OTX, or commercial feeds |
| **Analyzer Marketplace** | Plugin ecosystem for community-contributed detection modules |
| **Team Dashboards** | Aggregate risk views across multiple analysts and scan targets |
| **SSO / SAML** | Enterprise identity provider integration |
| **Compliance Mapping** | Map findings to CIS Controls, NIST CSF, SOC 2 requirements |

---

## 5. Technical Architecture

### 5.1 Current State (Hackathon MVP)

```
┌──────────────────────────────────────────────────┐
│                   Browser Client                  │
│  ┌──────────┐  ┌────────────┐  ┌──────────────┐ │
│  │ app.js   │  │analyzers.js│  │riskEngine.js │ │
│  │(orchestr)│→ │(5 modules) │→ │(scoring)     │ │
│  └──────────┘  └────────────┘  └──────────────┘ │
│       │                                           │
│       ▼ HTTP                                      │
├──────────────────────────────────────────────────┤
│              Node.js Server (zero-dep)            │
│  ┌──────────┐  ┌────────────┐  ┌──────────────┐ │
│  │Static    │  │Event Buffer│  │Gemini Proxy  │ │
│  │Serving   │  │(in-memory) │  │(API relay)   │ │
│  └──────────┘  └────────────┘  └──────────────┘ │
└──────────────────────────────────────────────────┘
```

### 5.2 V1 Target Architecture

```
┌──────────────────────────────────────────────────┐
│              Next.js Application                  │
│  ┌──────────────────────────────────────────────┐│
│  │              Frontend (React/SSR)            ││
│  │  ┌──────────┐ ┌──────────┐ ┌─────────────┐ ││
│  │  │Console   │ │Dashboard │ │Auth Pages   │ ││
│  │  │(operator)│ │(sessions)│ │(login/reg)  │ ││
│  │  └──────────┘ └──────────┘ └─────────────┘ ││
│  └──────────────────────────────────────────────┘│
│  ┌──────────────────────────────────────────────┐│
│  │              API Routes (Next.js)            ││
│  │  /api/scan  /api/events  /api/gemini        ││
│  │  /api/auth  /api/sessions /api/webhooks     ││
│  └─────────────────┬────────────────────────────┘│
└────────────────────┼─────────────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
┌──────────┐  ┌──────────┐  ┌──────────┐
│PostgreSQL│  │Gemini API│  │Webhook   │
│(sessions,│  │(playbook │  │Endpoints │
│ events,  │  │ gen)     │  │(external)│
│ tenants) │  │          │  │          │
└──────────┘  └──────────┘  └──────────┘
```

### 5.3 Tech Stack (v1)

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Framework** | Next.js 14+ (App Router) | Full-stack React with SSR, API routes, middleware |
| **Language** | TypeScript | Type safety for security-critical logic |
| **Database** | PostgreSQL | Relational integrity for tenants, sessions, events |
| **ORM** | Prisma | Type-safe queries, migrations, multi-tenant patterns |
| **Auth** | NextAuth.js | JWT sessions, credential provider, extensible to SSO |
| **AI** | Google Gemini 2.0 Flash | Low-latency playbook generation (existing integration) |
| **Styling** | Tailwind CSS | Rapid iteration on cyber-themed UI |
| **Deployment** | Vercel / Docker | Zero-config for Next.js; Docker for self-hosted |
| **Testing** | Vitest + Playwright | Unit tests for analyzers/risk engine; E2E for console |

### 5.4 Data Model (Core Entities)

```
Tenant
├── id, name, slug, createdAt
├── has many → Users
├── has many → Sessions
├── has many → WebhookConfigs
└── has many → Events

User
├── id, email, passwordHash, role (admin|analyst), tenantId
└── has many → Sessions (creator)

Session (Saved Scan)
├── id, tenantId, createdBy, timestamp
├── riskScore, findingCount, criticalHighCount
├── findings (JSON), signals (JSON), playbook (text)
└── url (scanned target)

Event
├── id, tenantId, type, payload (JSON), createdAt
└── source (scan|webhook|manual)

WebhookConfig
├── id, tenantId, url, secretHash, eventTypes[], active
└── lastDeliveryStatus, lastDeliveryAt
```

---

## 6. Success Metrics

### Primary KPIs (6-month targets)

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Weekly Active Users (WAU)** | 200 analysts running scans | Unique users triggering ≥ 1 scan/week |
| **Organizations Deployed** | 30 SMBs with active tenants | Tenants with ≥ 1 scan in last 30 days |
| **Scan-to-Playbook Completion** | 70% of scans generate a playbook | Playbook requests / total scans |
| **Session Save Rate** | 40% of scans are saved | Saved sessions / total scans |
| **Webhook Integration Rate** | 20% of tenants configure ≥ 1 webhook | Active webhook configs / total tenants |

### Secondary KPIs

| Metric | Target |
|--------|--------|
| **Mean Scan Duration** | < 5 seconds |
| **Playbook Generation Time** | < 10 seconds (p95) |
| **Console Load Time** | < 2 seconds (p95) |
| **API Uptime** | 99.5% |
| **User Retention (Week 4)** | 35% of signups active in week 4 |

### Leading Indicators

- Number of repeat scans per user (engagement depth)
- Playbook section click-through (are playbooks actionable?)
- Webhook delivery success rate (integration health)
- Support ticket volume per 100 users (usability signal)

---

## 7. Timeline

### Phase 1: Foundation (Weeks 1–3)
- Migrate to Next.js + TypeScript project structure
- Set up PostgreSQL with Prisma schema (tenants, users, sessions, events)
- Implement authentication (NextAuth.js with credentials provider)
- Port existing analyzers and risk engine to TypeScript modules
- Port event relay API to Next.js API routes

### Phase 2: Core Experience (Weeks 4–5)
- Rebuild operator console in React with existing cyber-themed design
- Integrate Gemini playbook generation via server-side API route
- Implement saved sessions (CRUD + list/search)
- Build tenant admin page (invite users, manage team)

### Phase 3: Integration & Polish (Weeks 6–7)
- Command palette with fuzzy search
- Webhook connector configuration and delivery engine
- Session comparison view (side-by-side diff)
- Keyboard shortcut system (port existing hotkeys)

### Phase 4: Launch Prep (Week 8)
- E2E test suite (Playwright) for critical paths
- Security audit (auth flows, tenant isolation, API rate limiting)
- Performance optimization (bundle size, SSR, database queries)
- Documentation (API docs, onboarding guide)
- Deploy to production

### Key Milestones

| Date | Milestone |
|------|-----------|
| Week 3 | Auth + database running, analyzers ported |
| Week 5 | Console rebuilt, sessions working, playbooks integrated |
| Week 7 | Webhooks live, command palette shipped |
| Week 8 | V1 launch-ready |

---

## 8. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Gemini API rate limits / outages** | Medium | High | Cache recent playbooks; implement fallback static playbook templates; queue requests during outages |
| **Browser API restrictions tighten** | Medium | High | Abstract analyzer interfaces so alternative data sources (agent, extension) can substitute browser APIs |
| **Next.js migration takes longer than planned** | Medium | Medium | Migrate incrementally — keep existing vanilla JS console functional during transition; port page-by-page |
| **Multi-tenant data leakage** | Low | Critical | Enforce tenant scoping at ORM level (Prisma middleware); automated tests for cross-tenant access; security audit in Phase 4 |
| **Low initial adoption** | Medium | High | Focus on hackathon/conference demos for initial traction; offer generous free tier; create shareable scan reports |
| **Scope creep beyond 8-week timeline** | High | Medium | Strict P0/P1/P2 prioritization; P2 features are explicitly deferred; weekly scope reviews |
| **Competitor adds browser-native scanning** | Low | Medium | Move fast on saved sessions + webhook integrations to build switching costs; brand as the SMB-first alternative |

---

## 9. Out of Scope (v1)

The following are explicitly **not** in scope for v1 and will not be worked on:

- Agent-based endpoint collector (P2 — requires desktop app distribution)
- Threat intelligence feed integration (P2 — requires feed licensing)
- Analyzer marketplace / plugin ecosystem (P2 — requires plugin API design)
- SSO / SAML authentication (P2 — enterprise feature, not needed for SMB launch)
- Compliance mapping (P2 — requires framework-specific research)
- Mobile-responsive console (console is desktop-first for operator workflows)
- On-premise deployment packaging (Docker support only for self-hosted)

---

## 10. Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Should the free tier have a scan limit (e.g., 10/day) or unlimited scans with gated playbooks? | Product | Open |
| 2 | PostgreSQL vs SQLite for self-hosted deployments — support both or pick one? | Engineering | Open |
| 3 | Should webhook payloads follow a standard format (e.g., CloudEvents) for SIEM compatibility? | Engineering | Open |
| 4 | Is Vercel sufficient for launch or do we need dedicated infrastructure for WebSocket support? | Engineering | Open |
| 5 | What's the maximum scan history retention before archival for cost management? | Product | Open |

---

*This is a living document. Update as decisions are made and scope evolves.*
