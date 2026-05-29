"""
ZeroTrust-Swarm: AI-Powered Security Swarm for Agentic Systems
Microsoft Build AI Hackathon 2026

Three specialized security agents protecting corporate AI agents:
  Agent 1 - Passport Officer:  JWT / identity validation + token replay detection
  Agent 2 - Border Control:    AI semantic + obfuscation-aware exfiltration detection
  Agent 3 - Sanity Auditor:    Statistical behavioral baseline (mean+3σ) + LLM intent check

LLM Priority: GitHub Models (Azure OpenAI GPT-4o) → Groq (fallback) → Rule-based (always-on)
"""

from fastapi import FastAPI, Depends, Request, Header, HTTPException as _HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn, sqlite3, json, re, time, hashlib, os, base64, binascii
import statistics as stats_lib
import secrets as _sec
from datetime import datetime, timedelta
from pydantic import BaseModel
import jwt

# ────────────────────────────────────────────────────────────────
# CONFIG — priority: GitHub Models > Groq > rule-based fallback
# ────────────────────────────────────────────────────────────────
_RAW_JWT_SECRET      = os.getenv("JWT_SECRET", "")
GROQ_KEY             = os.getenv("GROQ_API_KEY", "")
GITHUB_TOKEN         = os.getenv("GITHUB_TOKEN", "")        # GitHub Models (Azure OpenAI GPT-4o)
CALLER_API_KEY       = os.getenv("CALLER_API_KEY", "")
DB_PATH              = os.getenv("DB_PATH", "zerotrust.db")

_ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in _ALLOWED_ORIGIN.split(",") if o.strip()]

if not _RAW_JWT_SECRET:
    JWT_SECRET = _sec.token_hex(32)
    _WARN_JWT  = True
else:
    JWT_SECRET = _RAW_JWT_SECRET
    _WARN_JWT  = False

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
app = FastAPI(title="ZeroTrust-Swarm API", version="2.3.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Railway deploy — ALLOWED_ORIGINS set via env in prod
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

# ── LLM client setup (GitHub Models = Azure OpenAI, priority 1) ──
_llm_mode = "rule_based_fallback"
github_client = None
groq_client   = None

if GITHUB_TOKEN:
    try:
        from openai import OpenAI as _OAI
        github_client = _OAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=GITHUB_TOKEN,
        )
        _llm_mode = "github_models_gpt4o"
    except Exception:
        pass

if not github_client and GROQ_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_KEY)
        _llm_mode = "groq_llama3"
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────
# DATABASE SETUP
# ────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, agent_id TEXT, action TEXT, verdict TEXT,
        risk_score INTEGER, details TEXT, blocked INTEGER
    );
    CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        name TEXT, role TEXT, trust_level INTEGER,
        token TEXT, registered_at TEXT
    );
    CREATE TABLE IF NOT EXISTS behavioral_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, agent_id TEXT, tool_called TEXT,
        target_table TEXT, frequency INTEGER
    );
    CREATE TABLE IF NOT EXISTS token_audit (
        token_hash TEXT PRIMARY KEY,
        agent_id   TEXT,
        first_seen TEXT,
        last_seen  TEXT,
        use_count  INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS behavioral_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT, tool_called TEXT, target_table TEXT,
        window_ts TEXT, call_count INTEGER
    );
    """)
    demo = [
        ("agent-hr-001",  "HR Assistant",     "hr_queries",   85, _make_token("agent-hr-001")),
        ("agent-fin-002", "Finance Analyzer", "finance_read", 90, _make_token("agent-fin-002")),
        ("agent-unk-999", "Unknown Agent",    "unknown",       0, "bad-token-xyz"),
    ]
    for row in demo:
        c.execute("INSERT OR IGNORE INTO agents VALUES (?,?,?,?,?,?)",
                  (*row, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def _make_token(agent_id: str) -> str:
    payload = {"sub": agent_id, "exp": datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ────────────────────────────────────────────────────────────────
# REQUEST MODELS
# ────────────────────────────────────────────────────────────────
class AgentAction(BaseModel):
    agent_id:      str
    token:         str
    action:        str
    target:        str
    payload:       str
    declared_task: str

class RegisterAgent(BaseModel):
    name: str
    role: str


# ────────────────────────────────────────────────────────────────
# CALLER AUTHENTICATION
# ────────────────────────────────────────────────────────────────
def verify_caller(x_api_key: str = Header(default="")) -> None:
    if not CALLER_API_KEY:
        return
    if not _sec.compare_digest(x_api_key, CALLER_API_KEY):
        raise _HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


# ────────────────────────────────────────────────────────────────
# AGENT 1: PASSPORT OFFICER
# ────────────────────────────────────────────────────────────────
def passport_officer(agent_id: str, token: str, db) -> dict:
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if decoded.get("sub") != agent_id:
            return {"passed": False, "reason": "Token subject mismatch — possible identity spoof", "risk": 95}
    except jwt.ExpiredSignatureError:
        return {"passed": False, "reason": "Token expired", "risk": 80}
    except jwt.InvalidTokenError:
        return {"passed": False, "reason": "Invalid token — unauthorized agent", "risk": 90}

    try:
        row = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    except Exception:
        return {"passed": True, "reason": "Identity verified (DB unavailable — reduced trust mode)",
                "risk": 20, "agent_name": agent_id, "agent_role": "unknown",
                "trust_level": 50, "degraded": True}

    if not row:
        return {"passed": False, "reason": "Agent not registered in system", "risk": 95}

    token_hash = hashlib.sha256(token.encode()).hexdigest()[:20]
    try:
        now = datetime.utcnow().isoformat()
        existing = db.execute(
            "SELECT agent_id, use_count FROM token_audit WHERE token_hash=?", (token_hash,)
        ).fetchone()
        if existing:
            if existing["agent_id"] != agent_id:
                return {"passed": False,
                        "reason": f"Token replay attack — token previously used by '{existing['agent_id']}'",
                        "risk": 98}
            db.execute("UPDATE token_audit SET last_seen=?, use_count=use_count+1 WHERE token_hash=?",
                       (now, token_hash))
        else:
            db.execute("INSERT INTO token_audit VALUES (?,?,?,?,?)", (token_hash, agent_id, now, now, 1))
        db.commit()
    except Exception:
        pass

    return {"passed": True, "reason": "Identity verified", "risk": 0,
            "agent_name": row["name"], "agent_role": row["role"], "trust_level": row["trust_level"]}


# ────────────────────────────────────────────────────────────────
# AGENT 2: BORDER CONTROL
# ────────────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',   "email_address",     60),
    (r'\b(?:sk-|ghp_|AIza|xox[baprs]-)[A-Za-z0-9_\-]{10,}\b', "api_key",           90),
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',        "card_number",       85),
    (r'\b(?:salary|ssn|password|secret|revenue|confidential)\b',"sensitive_keyword", 70),
    (r'\b\d{3}-\d{2}-\d{4}\b',                                  "ssn_pattern",       95),
    (r'bearer\s+[a-zA-Z0-9\-._~+/]+=*',                         "bearer_token",      90),
    (r'private[\s_-]?key|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY',     "private_key",       95),
    (r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+',                  "password_field",    90),
]

SEMANTIC_RULES = [
    (r"call_api|send",   r"external|attacker|hacker",           r"salary|employee|confidential|secret", 20, "semantic_context_exfil"),
    (r"send_email|post", r"external|public|attacker",           r"ssn|password|api.key|token",          25, "semantic_email_exfil"),
    (r"call_api",        r"pastebin|hastebin|ngrok|requestbin|webhook\.site", r"",                      35, "known_exfil_destination"),
]


def _decode_obfuscated(text: str) -> list:
    variants = [text]
    stripped = re.sub(r'\s', '', text)
    for candidate in [stripped, stripped.rstrip("=")]:
        try:
            padded  = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if len(decoded) > 8 and decoded.isprintable():
                variants.append(decoded)
        except Exception:
            pass
    hex_only = re.sub(r'[^0-9a-fA-F]', '', text)
    if len(hex_only) >= 16 and len(hex_only) % 2 == 0:
        try:
            decoded = binascii.unhexlify(hex_only).decode("utf-8", errors="ignore")
            if len(decoded) > 5:
                variants.append(decoded)
        except Exception:
            pass
    try:
        from urllib.parse import unquote
        url_decoded = unquote(text)
        if url_decoded != text:
            variants.append(url_decoded)
    except Exception:
        pass
    return variants


def border_control(payload: str, target: str, agent_role: str, action: str = "") -> dict:
    findings   = []
    total_risk = 0
    is_external = bool(re.match(r'https?://', target) and "internal" not in target.lower())
    obfuscated_hit = False

    for idx, variant in enumerate(_decode_obfuscated(payload)):
        for pattern, label, base_risk in SENSITIVE_PATTERNS:
            if re.search(pattern, variant, re.IGNORECASE):
                if label == "sensitive_keyword" and "finance" in agent_role and "revenue" in variant.lower():
                    continue
                risk = base_risk
                if idx > 0:
                    risk = min(risk + 15, 100)
                    obfuscated_hit = True
                if is_external:
                    risk = min(risk + 15, 100)
                findings.append({"type": label, "risk": risk, "obfuscated": idx > 0})
                total_risk = max(total_risk, risk)

    for act_pat, tgt_pat, pay_pat, extra, label in SEMANTIC_RULES:
        act_ok = re.search(act_pat, action.lower())  if act_pat else True
        tgt_ok = re.search(tgt_pat, target.lower())  if tgt_pat else True
        pay_ok = re.search(pay_pat, payload.lower()) if pay_pat else True
        if act_ok and tgt_ok and pay_ok:
            sem_risk = min(total_risk + extra, 100) if total_risk else extra
            findings.append({"type": label, "risk": extra, "obfuscated": False})
            total_risk = max(total_risk, sem_risk)

    if findings:
        types = list({f["type"] for f in findings})
        note  = " [OBFUSCATED PAYLOAD DECODED AND FLAGGED]" if obfuscated_hit else ""
        return {"passed": False,
                "reason": f"Potential data exfiltration: {types}{note}",
                "risk":   min(total_risk, 100),
                "findings": findings}
    return {"passed": True, "reason": "No sensitive data detected", "risk": 0}


# ────────────────────────────────────────────────────────────────
# AGENT 3: SANITY AUDITOR
# ────────────────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "hr_queries":   ["employees", "leave_requests", "departments", "org_chart"],
    "finance_read": ["transactions", "revenue", "budgets", "invoices"],
    "it_support":   ["tickets", "systems", "logs", "configurations"],
    "unknown":      [],
}

ROLE_INTENT_MAP = {
    "hr_queries": {
        "forbidden_targets":        ["transactions", "revenue", "budgets", "invoices", "audit_logs"],
        "suspicious_task_keywords": ["ignore", "drop", "delete", "transfer", "override", "exec"],
        "finance_signals":          {"revenue", "budget", "invoice", "payment", "transaction"},
    },
    "finance_read": {
        "forbidden_targets":        ["employees", "leave_requests", "passwords", "secrets"],
        "suspicious_task_keywords": ["ignore", "drop", "delete", "exfiltrate", "exec"],
        "hr_signals":               {"employee", "leave", "department", "hire", "onboard"},
    },
    "it_support": {
        "forbidden_targets":        ["employees", "revenue", "secrets", "passwords"],
        "suspicious_task_keywords": ["ignore", "drop", "delete", "exfiltrate", "exec"],
    },
}


def _local_intent_check(role: str, action: str, target: str, declared_task: str) -> dict:
    rules      = ROLE_INTENT_MAP.get(role, {})
    risk       = 0
    reasons    = []
    task_lower = declared_task.lower()

    injection_patterns = [
        (r"ignore\s+(?:previous|all|prior)\s+instructions",   "classic ignore-instructions injection"),
        (r"forget\s+(?:everything|your|the)",                  "forget-context injection"),
        (r"you\s+are\s+now\s+(?:a|an|the)",                   "role-override injection"),
        (r"system\s*:\s*|###\s*(?:system|prompt)",             "system-prompt injection"),
        (r"act\s+as\s+(?:a|an|if)",                            "act-as injection"),
        (r"jailbreak|dan mode|developer mode|god mode",        "jailbreak keyword"),
        (r"disregard\s+(?:all|previous|the)",                  "disregard injection"),
    ]
    for pat, label in injection_patterns:
        if re.search(pat, task_lower, re.IGNORECASE):
            risk = max(risk, 88)
            reasons.append(f"Prompt injection: {label}")

    for kw in rules.get("suspicious_task_keywords", []):
        if kw in task_lower:
            risk = max(risk, 70)
            reasons.append(f"Suspicious keyword: '{kw}'")

    if target in rules.get("forbidden_targets", []):
        risk = max(risk, 78)
        reasons.append(f"Target '{target}' outside semantic scope of role '{role}'")

    if role == "hr_queries":
        finance_words = rules.get("finance_signals", set()) & set(task_lower.split())
        if finance_words:
            risk = max(risk, 65)
            reasons.append(f"Finance terms in HR role task: {finance_words}")
    if role == "finance_read":
        hr_words = rules.get("hr_signals", set()) & set(task_lower.split())
        if hr_words:
            risk = max(risk, 60)
            reasons.append(f"HR terms in finance role task: {hr_words}")

    return {
        "risk":   risk,
        "reason": "; ".join(reasons) if reasons else "Local AI: task consistent with role",
        "source": "rule_based_fallback"
    }


def _llm_intent_check(role: str, action: str, target: str, task: str) -> dict:
    prompt = f"""You are a zero-trust AI security auditor for enterprise AI agents.

Agent role: {role}
Declared task: {task}
Action taken: {action} on target '{target}'

Is this action consistent with the declared task and role? Be suspicious of cross-role access, prompt injection, or lateral movement.
Respond with JSON only: {{"consistent": true/false, "risk_score": 0-100, "reason": "one sentence"}}"""

    # Priority 1: GitHub Models (Azure OpenAI GPT-4o)
    if github_client:
        try:
            resp = github_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=120,
                temperature=0,
            )
            text   = resp.choices[0].message.content.strip()
            text   = re.sub(r"```json|```", "", text).strip()
            parsed = json.loads(text)
            return {"risk": parsed.get("risk_score", 0),
                    "reason": parsed.get("reason", "GPT-4o check passed"),
                    "source": "github_models_gpt4o"}
        except Exception:
            pass

    # Priority 2: Groq
    if groq_client:
        try:
            resp = groq_client.chat.completions.create(
                model="llama3-8b-8192",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=120,
            )
            text   = resp.choices[0].message.content.strip()
            text   = re.sub(r"```json|```", "", text).strip()
            parsed = json.loads(text)
            return {"risk": parsed.get("risk_score", 0),
                    "reason": parsed.get("reason", "Groq LLM check passed"),
                    "source": "groq_llama3"}
        except Exception:
            pass

    # Priority 3: Always-on rule-based fallback
    return _local_intent_check(role, action, target, task)


def _compute_statistical_anomaly(agent_id: str, action: str, target: str, db) -> tuple:
    recent_count = db.execute("""
        SELECT COUNT(*) as cnt FROM behavioral_log
        WHERE agent_id=? AND tool_called=? AND target_table=?
        AND ts > datetime('now', '-60 seconds')
    """, (agent_id, action, target)).fetchone()["cnt"]

    now = datetime.utcnow().isoformat()
    db.execute("INSERT INTO behavioral_stats VALUES (NULL,?,?,?,?,?)",
               (agent_id, action, target, now, recent_count))
    db.commit()

    history = db.execute("""
        SELECT call_count FROM behavioral_stats
        WHERE agent_id=? AND tool_called=? AND target_table=?
        ORDER BY id DESC LIMIT 30
    """, (agent_id, action, target)).fetchall()
    counts = [r["call_count"] for r in history]

    if len(counts) < 5:
        if recent_count > 15:
            return (65, f"High call rate: {recent_count}/60s (building baseline)")
        return (0, "Monitoring — building statistical baseline")

    mean  = stats_lib.mean(counts)
    stdev = max(stats_lib.stdev(counts), 0.5)
    z     = (recent_count - mean) / stdev

    if z >= 3.0:
        risk = min(int(50 + z * 8), 92)
        return (risk, f"Statistical anomaly: {recent_count} calls/60s (mean={mean:.1f}, σ={stdev:.1f}, z={z:.1f})")
    if z >= 2.0:
        return (30, f"Elevated rate: z={z:.1f} — monitoring")
    return (0, f"Normal behavior: {recent_count} calls/60s (z={z:.1f})")


def sanity_auditor(agent_id: str, agent_role: str, action: str,
                   target: str, declared_task: str, db) -> dict:
    allowed = ROLE_PERMISSIONS.get(agent_role, [])

    if action == "query_database" and allowed and target not in allowed:
        return {"passed": False,
                "reason": f"Role '{agent_role}' cannot access '{target}'. Allowed: {allowed}. Lateral movement.",
                "risk": 85}

    anom_risk, anom_reason = 0, "Behavioral check unavailable"
    try:
        now = datetime.utcnow().isoformat()
        db.execute("INSERT INTO behavioral_log VALUES (NULL,?,?,?,?,?)",
                   (now, agent_id, action, target, 1))
        db.commit()
        anom_risk, anom_reason = _compute_statistical_anomaly(agent_id, action, target, db)
        if anom_risk >= 70:
            return {"passed": False, "reason": anom_reason, "risk": anom_risk}
    except Exception:
        pass

    llm = _llm_intent_check(agent_role, action, target, declared_task)
    if llm["risk"] > 60:
        return {"passed": False,
                "reason": f"Intent mismatch [{llm['source']}]: {llm['reason']}",
                "risk": llm["risk"]}

    combined_risk = max(anom_risk, llm["risk"])
    note = f" | Intent [{llm['source']}]: {llm['reason'][:55]}" if llm["risk"] > 0 else \
           f" | Intent [{llm['source']}]: consistent"
    return {"passed": True,
            "reason": f"Behavior consistent with declared task{note}",
            "risk": combined_risk,
            "intent_source": llm["source"]}


# ────────────────────────────────────────────────────────────────
# API ENDPOINTS
# ────────────────────────────────────────────────────────────────
@app.post("/inspect")
@limiter.limit("60/minute")
def inspect_action(request: Request, action: AgentAction,
                   db=Depends(get_db), _=Depends(verify_caller)):
    ts = datetime.utcnow().isoformat()
    results  = {}
    max_risk = 0

    results["passport"] = passport_officer(action.agent_id, action.token, db)
    max_risk = max(max_risk, results["passport"]["risk"])
    agent_role = results["passport"].get("agent_role", "unknown")

    results["border"] = border_control(action.payload, action.target, agent_role, action.action)
    max_risk = max(max_risk, results["border"]["risk"])

    if results["passport"]["passed"]:
        results["auditor"] = sanity_auditor(
            action.agent_id, agent_role, action.action,
            action.target, action.declared_task, db)
        max_risk = max(max_risk, results["auditor"]["risk"])
    else:
        results["auditor"] = {"passed": False, "reason": "Skipped — identity rejected", "risk": 0}

    if max_risk >= 80:   verdict = "HARD_BLOCK"
    elif max_risk >= 50: verdict = "SOFT_BLOCK"
    else:                verdict = "ALLOW"

    blocked       = 0 if verdict == "ALLOW" else 1
    failed_agents = [k for k, v in results.items() if not v["passed"]]

    try:
        db.execute("INSERT INTO events VALUES (NULL,?,?,?,?,?,?,?)", (
            ts, action.agent_id, action.action, verdict,
            max_risk, json.dumps({"results": results, "failed": failed_agents}), blocked
        ))
        db.commit()
    except Exception:
        pass

    return {
        "verdict":      verdict,
        "risk_score":   max_risk,
        "blocked":      blocked,
        "timestamp":    ts,
        "agent_checks": results,
        "summary": f"{verdict} — risk {max_risk}/100"
            + (f" — blocked by: {failed_agents}" if failed_agents else " — all checks passed")
    }


@app.get("/events")
def get_events(limit: int = 50, db=Depends(get_db)):
    rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

@app.get("/stats")
def get_stats(db=Depends(get_db)):
    total   = db.execute("SELECT COUNT(*) as n FROM events").fetchone()["n"]
    blocked = db.execute("SELECT COUNT(*) as n FROM events WHERE blocked=1").fetchone()["n"]
    hard    = db.execute("SELECT COUNT(*) as n FROM events WHERE verdict='HARD_BLOCK'").fetchone()["n"]
    soft    = db.execute("SELECT COUNT(*) as n FROM events WHERE verdict='SOFT_BLOCK'").fetchone()["n"]
    allow   = db.execute("SELECT COUNT(*) as n FROM events WHERE verdict='ALLOW'").fetchone()["n"]
    agents  = db.execute("SELECT COUNT(*) as n FROM agents").fetchone()["n"]
    avg_risk = db.execute("SELECT AVG(risk_score) as a FROM events").fetchone()["a"] or 0
    return {
        "total_inspections": total, "blocked": blocked,
        "hard_blocks": hard, "soft_blocks": soft, "allowed": allow,
        "registered_agents": agents, "avg_risk_score": round(avg_risk, 1),
        "block_rate": round((blocked / total * 100) if total else 0, 1)
    }

@app.get("/agents")
def get_agents(db=Depends(get_db)):
    return [dict(r) for r in db.execute("SELECT * FROM agents").fetchall()]

@app.post("/agents/register")
def register_agent(data: RegisterAgent, db=Depends(get_db), _=Depends(verify_caller)):
    agent_id = f"agent-{hashlib.sha256(data.name.encode()).hexdigest()[:12]}"
    token    = _make_token(agent_id)
    db.execute("INSERT OR REPLACE INTO agents VALUES (?,?,?,?,?,?)",
               (agent_id, data.name, data.role, 100, token, datetime.utcnow().isoformat()))
    db.commit()
    return {"agent_id": agent_id, "token": token, "message": "Agent registered"}

@app.get("/token/{agent_id}")
def get_token_endpoint(agent_id: str):
    return {"token": _make_token(agent_id)}

@app.get("/health")
def health():
    return {
        "status": "ok", "version": "2.3.0",
        "agents": ["passport", "border", "auditor"],
        "llm_mode": _llm_mode,
        "ai_features": {
            "semantic_detection":     True,
            "obfuscation_decoding":   True,
            "statistical_baseline":   True,
            "token_replay_detection": True,
            "github_models_gpt4o":    github_client is not None,
            "groq_llm":               groq_client is not None,
            "rule_based_fallback":    True,
        }
    }

@app.on_event("startup")
def startup():
    init_db()
    if _WARN_JWT:
        print("⚠️  JWT_SECRET not set — random per-run secret (set JWT_SECRET for production)")
    if not CALLER_API_KEY:
        print("⚠️  CALLER_API_KEY not set — dev mode (open)")
    llm_label = {
        "github_models_gpt4o": "GitHub Models — Azure OpenAI GPT-4o ✅ (Microsoft stack)",
        "groq_llama3":         "Groq Llama3 (fallback)",
        "rule_based_fallback": "Rule-based semantic engine (always-on)"
    }.get(_llm_mode, _llm_mode)
    print(f"✅ ZeroTrust-Swarm v2.3.0 ready")
    print(f"   LLM:             {llm_label}")
    print(f"   CORS:            {ALLOWED_ORIGINS}")
    print(f"   DB:              {DB_PATH}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)
