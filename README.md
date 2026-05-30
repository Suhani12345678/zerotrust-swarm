# ZeroTrust-Swarm 
**Microsoft Build AI Hackathon 2026 — Theme: Security in the Agentic Future + Agent Swarms**

> *"One agent is useful. A swarm of agents securing other agents? That's a different game entirely."*

---

## The Problem

Companies are deploying AI agents to handle their most sensitive operations — HR queries, financial analysis, code execution. These agents connect to internal databases, external APIs, and each other. The threat: a single compromised agent can move laterally across internal systems, exfiltrate sensitive data, or be hijacked via prompt injection — all invisibly, in milliseconds.

**What existing tools miss:**

| Tool | What it covers | What it misses |
|------|---------------|----------------|
| Azure Defender for Cloud | Infrastructure/VM threats | Agent-to-agent trust, semantic intent |
| Prisma Cloud | Container/API security | Agentic role semantics, LLM intent |
| AWS Macie | S3 data classification | Real-time agent action inspection |
| **ZeroTrust-Swarm** | **All of the above + identity, intent, behavioral drift, obfuscated exfiltration** | — |

---

## Solution: ZeroTrust-Swarm v2.3

A **swarm of 3 specialized AI security agents** that wrap any corporate AI agent in an invisible security layer — based on Microsoft's Zero Trust principle: *Never trust, always verify.*

### The Three Agents

| Agent | Role | AI Capabilities |
|-------|------|-----------------|
| **Passport Officer** | Cryptographic identity validation | JWT check + token replay detection + DB-failure graceful fallback |
|  **Border Control** | AI-powered exfiltration detection | Regex + base64/hex/URL decode + semantic context scoring |
|  **Sanity Auditor** | Behavioral + intent check | Statistical mean+3σ baseline + LLM intent (GitHub Models GPT-4o) |

Every action → all 3 agents in parallel → returns **ALLOW / SOFT_BLOCK / HARD_BLOCK** in < 5ms P99.

---

## Microsoft AI Stack Used

| Component | Technology |
|-----------|------------|
| LLM Intent Analysis | **GitHub Models — Azure OpenAI GPT-4o** (Azure infrastructure) |
| Backend Deployment | **Azure App Service** (production path) |
| Frontend Deployment | **Azure Static Web Apps** (production path) |
| Database | **Azure Cosmos DB** (migration script included) |
| Identity | **Azure Entra ID + Managed Identity** (production path) |
| CI/CD | **GitHub Actions** with Azure deployment |
| Dev Assistance | **GitHub Copilot** used throughout development |

> Dev fallback: Groq free tier (same API interface as Azure OpenAI) used for local development.
> `backend/migrate_to_cosmos.py` — one-command migration to Azure Cosmos DB.

---

## Architecture

```
External Threats
[Rogue Agents]  [Prompt Injection]  [Obfuscated Exfil]  [Slow-Drip]
        ↓
┌─────────────────────────────────────────────────────────┐
│               ZeroTrust-Swarm v2.3 Proxy                 │
│                                                           │
│  ┌───────────────────────┐  ┌───────────────────────┐    │
│  │    Passport Officer    │  │   Border Control      │ ←─ Parallel
│  │  JWT + Replay detect  │  │  AI 3-pass detection   │    │
│  └───────────────────────┘  └───────────────────────┘    │
│                 ↓                      ↓                  │
│         ┌──────────────────────────────────┐              │
│         │        Sanity Auditor              │              │
│         │  mean+3σ baseline  | GPT-4o intent│              │
│         └──────────────────────────────────┘              │
│                         ↓                                 │
│          ALLOW / SOFT_BLOCK / HARD_BLOCK                  │
└─────────────────────────────────────────────────────────┘
        ↓
  Corporate AI Agent (protected)
```

---

## Performance

```
n = 1,000 inspections (3-agent swarm, local AI + obfuscation decode, SQLite)

  Average:   ~2ms
  P50:       ~2.5ms
  P95:       ~4ms
  P99:       ~5ms      ← 40× better than <200ms requirement
  Throughput: ~400,000+ inspections/sec (single process)
```

**17 scenarios correctly classified** — 13 core + 4 OWASP LLM Top 10.

---

## OWASP LLM Top 10 Coverage

| OWASP ID | Vulnerability | Coverage |
|----------|--------------|----------|
| LLM01 | Prompt Injection |  4 test cases |
| LLM02 | Insecure Output Handling |  2 test cases |
| LLM04 | Model Denial of Service |  Rate limiting 60/min per IP |
| LLM06 | Sensitive Info Disclosure |  4 test cases (incl. obfuscated) |
| LLM08 | Excessive Agency |  4 test cases |
| LLM09 | Overreliance |  2 test cases |
| LLM10 | Model Theft |  3 test cases |

---

## Setup (5 minutes)

### Prerequisites
- Python 3.11+
- Node.js 18+
- Git

### Step 1 — Clone & configure

```bash
git clone https://github.com/Suhani12345678/zerotrust-swarm.git
cd zerotrust-swarm
cp .env.example .env
```

Edit `.env` — add your GitHub token (free):
```
GITHUB_TOKEN=your_github_token   # github.com/settings/tokens → Generate new token (classic)
```

### Step 2 — Start backend

```bash
cd backend
pip install -r requirements.txt
python main.py
# → http://localhost:8000/docs
```

### Step 3 — Start frontend

```bash
cd frontend
npm install
npm run dev
# → SOC Dashboard at http://localhost:5173
```

### Step 4 — Live Demo

| Service                      | URL                                                      |
| ---------------------------- | -------------------------------------------------------- |
| **SOC Dashboard (Frontend)** | https://zerotrust-swarm-hanumate-s-projects.vercel.app   |
| **API Backend**              | https://zerotrust-swarm-production.up.railway.app        |
| **API Docs (Swagger)**       | https://zerotrust-swarm-production.up.railway.app/docs   |
| **Health Check**             | https://zerotrust-swarm-production.up.railway.app/health |

> Test credentials not required — demo agents pre-loaded.


## Deploy (Free, No Credit Card)

### Backend → Railway

1. railway.app → Login with GitHub → New Project → Deploy from GitHub repo
2. Select `zerotrust-swarm` repo → Root directory: `backend`
3. Add environment variable: `GITHUB_TOKEN=your_token`
4. Copy the generated URL (e.g. `https://zerotrust-swarm-production.up.railway.app`)

### Frontend → Vercel

1. vercel.com → Login with GitHub → New Project → Import `zerotrust-swarm`
2. Root directory: `frontend`
3. Add environment variable: `VITE_API_URL=https://your-railway-url.railway.app`
4. Deploy → get live URL

---

## Evaluation Criteria Coverage

| Criterion | Weight | How we address it |
|-----------|--------|-------------------|
| **AI Integration** | 25% | GitHub Models GPT-4o intent check + 3-pass obfuscation decode; Azure stack throughout |
| **System Architecture** | 25% | 3-agent swarm; mean+3σ baseline; token replay; rate limiting; SHA-256; CORS lockdown |
| **UX / Presentation** | 15% | React SOC dashboard; live threat feed (2s poll); risk timeline; per-agent breakdown |
| **Prototype Readiness** | 15% | 5-min setup; 17-scenario test suite; OWASP LLM Top 10; Azure deploy script; Railway/Vercel |
| **Problem Depth** | 10% | Fills exact gap vs Azure Defender / Prisma — obfuscation decode + intent check |
| **Market Fit** | 10% | 60% Fortune 500 deploying AI agents; $4.88M avg breach cost; < 5ms detection |

---

## Team

| **Suhani Behl** | Full-stack + AI Security Architecture |
| **Divya Verma** | Full-stack + AI Security Architecture |

*University of Jammu

---

## AI Tools Used

- **GitHub Copilot** — code completion during development
- **Claude (Anthropic)** — architecture review and adversarial scenario design
- **GitHub Models / Azure OpenAI GPT-4o** — runtime LLM-powered intent analysis

---

## Data Privacy

- All test data is **fully synthetic** — no real user PII is processed or stored
- SQLite used for development; Azure Cosmos DB in production (migration script: `backend/migrate_to_cosmos.py`)
- No secrets or API keys committed to source control (`.env.example` pattern used)
- CORS locked to explicit origins; rate-limited at 60 requests/min per IP

---

## License

MIT — open source, freely adaptable.

*Built for Microsoft Build AI Hackathon, May–June 2026*
