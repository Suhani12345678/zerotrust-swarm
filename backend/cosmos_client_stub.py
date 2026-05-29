"""
ZeroTrust-Swarm — Azure Cosmos DB Client Stub
==============================================
Drop-in replacement for the SQLite get_db() dependency.
Swap this in main.py for production deployment on Azure.

Steps to activate:
  1. pip install azure-cosmos  (add to requirements.txt)
  2. Set COSMOS_ENDPOINT, COSMOS_KEY, COSMOS_DATABASE env vars
  3. Replace `from main import get_db` usages with this module
  4. Replace SQLite SQL in endpoints with the Cosmos query methods shown below

Azure production benefits vs SQLite:
  - Globally distributed, 99.999% availability SLA
  - Built-in encryption at rest + in transit
  - Azure Managed Identity auth (no key needed)
  - Cosmos DB RBAC integrates with Azure Entra ID
"""

import os
from azure.cosmos import CosmosClient, PartitionKey

COSMOS_ENDPOINT = os.getenv("COSMOS_ENDPOINT", "")
COSMOS_KEY      = os.getenv("COSMOS_KEY",      "")
DATABASE_NAME   = os.getenv("COSMOS_DATABASE", "zerotrust")

_client   = CosmosClient(COSMOS_ENDPOINT, credential=COSMOS_KEY)
_database = _client.get_database_client(DATABASE_NAME)


def get_container(name: str):
    """Get a Cosmos DB container client by name."""
    return _database.get_container_client(name)


# ── Query helpers (swap for SQLite execute() calls) ──────────────

def log_event(agent_id, action, verdict, risk_score, details, blocked):
    """Replace: db.execute('INSERT INTO events ...')"""
    get_container("events").upsert_item({
        "id":          f"{agent_id}-{__import__('time').time_ns()}",
        "agent_id":    agent_id,
        "action":      action,
        "verdict":     verdict,
        "risk_score":  risk_score,
        "details":     details,
        "blocked":     blocked,
        "ts":          __import__('datetime').datetime.utcnow().isoformat(),
    })


def get_agent(agent_id: str):
    """Replace: db.execute('SELECT * FROM agents WHERE agent_id=?')"""
    try:
        items = list(get_container("agents").query_items(
            query="SELECT * FROM c WHERE c.id=@id",
            parameters=[{"name": "@id", "value": agent_id}],
            enable_cross_partition_query=True,
        ))
        return items[0] if items else None
    except Exception:
        return None


def register_agent(agent_id, name, role, trust_level, token, registered_at):
    """Replace: db.execute('INSERT OR REPLACE INTO agents ...')"""
    get_container("agents").upsert_item({
        "id":            agent_id,
        "role":          role,
        "name":          name,
        "trust_level":   trust_level,
        "token":         token,
        "registered_at": registered_at,
    })


def log_behavioral(agent_id, tool_called, target_table):
    """Replace: INSERT INTO behavioral_log"""
    get_container("behavioral_log").upsert_item({
        "id":           f"{agent_id}-{tool_called}-{__import__('time').time_ns()}",
        "agent_id":     agent_id,
        "tool_called":  tool_called,
        "target_table": target_table,
        "ts":           __import__('datetime').datetime.utcnow().isoformat(),
        "frequency":    1,
    })


def count_recent_calls(agent_id, tool_called, target_table, since_iso):
    """Replace: COUNT(*) FROM behavioral_log WHERE ts > ?"""
    items = list(get_container("behavioral_log").query_items(
        query="""SELECT VALUE COUNT(1) FROM c
                 WHERE c.agent_id=@a AND c.tool_called=@t
                 AND c.target_table=@tbl AND c.ts > @since""",
        parameters=[
            {"name": "@a",    "value": agent_id},
            {"name": "@t",    "value": tool_called},
            {"name": "@tbl",  "value": target_table},
            {"name": "@since","value": since_iso},
        ],
        enable_cross_partition_query=True,
    ))
    return items[0] if items else 0


# ── Azure Managed Identity (preferred over key auth) ─────────────
# from azure.identity import DefaultAzureCredential
# _client = CosmosClient(COSMOS_ENDPOINT, credential=DefaultAzureCredential())
# No key needed — works automatically in Azure App Service with system-assigned identity.
