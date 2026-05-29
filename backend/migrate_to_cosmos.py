"""
ZeroTrust-Swarm — SQLite → Azure Cosmos DB Migration Script
============================================================
Reads all data from the local SQLite database and writes it to
Azure Cosmos DB (NoSQL API), matching the same schema.

Usage:
  pip install azure-cosmos
  export COSMOS_ENDPOINT=https://your-account.documents.azure.com:443/
  export COSMOS_KEY=your_primary_key_here
  export COSMOS_DATABASE=zerotrust          # created if absent
  python migrate_to_cosmos.py

What gets migrated:
  SQLite table     → Cosmos DB container   (partition key)
  ─────────────────────────────────────────────────────────
  events           → events                (/agent_id)
  agents           → agents                (/role)
  behavioral_log   → behavioral_log        (/agent_id)
  token_audit      → token_audit           (/agent_id)
  behavioral_stats → behavioral_stats      (/agent_id)

After migration:
  Set COSMOS_ENDPOINT + COSMOS_KEY env vars in your App Service,
  then swap get_db() to use CosmosClient — see cosmos_client.py stub below.
"""

import sqlite3, os, json, sys
from datetime import datetime, timezone

try:
    from azure.cosmos import CosmosClient, PartitionKey, exceptions
except ImportError:
    sys.exit("Run:  pip install azure-cosmos  then retry.")

# ── Config ──────────────────────────────────────────────────────
SQLITE_PATH      = os.getenv("SQLITE_PATH",    "zerotrust.db")
COSMOS_ENDPOINT  = os.getenv("COSMOS_ENDPOINT", "")
COSMOS_KEY       = os.getenv("COSMOS_KEY",      "")
COSMOS_DATABASE  = os.getenv("COSMOS_DATABASE", "zerotrust")

if not COSMOS_ENDPOINT or not COSMOS_KEY:
    sys.exit("Set COSMOS_ENDPOINT and COSMOS_KEY env vars before running.")

# ── Container definitions ────────────────────────────────────────
CONTAINERS = {
    "events":           ("/agent_id",   ["verdict", "blocked"]),
    "agents":           ("/role",       []),
    "behavioral_log":   ("/agent_id",   ["tool_called"]),
    "token_audit":      ("/agent_id",   []),
    "behavioral_stats": ("/agent_id",   []),
}

# ── Helpers ──────────────────────────────────────────────────────
def sqlite_rows(conn, table):
    try:
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []  # table doesn't exist yet (older DB)

def to_cosmos_doc(table, row):
    """Convert a SQLite row dict to a Cosmos DB document."""
    doc = {k: v for k, v in row.items()}
    # Cosmos requires a string 'id' field
    if "id" in doc:
        doc["id"] = str(doc["id"])
    elif "token_hash" in doc:
        doc["id"] = doc["token_hash"]
    else:
        doc["id"] = f"{table}-{hash(json.dumps(doc, sort_keys=True)) & 0xFFFFFFFF}"
    # Ensure partition key field is a non-null string
    pk_field = CONTAINERS[table][0].lstrip("/")
    if not doc.get(pk_field):
        doc[pk_field] = "unknown"
    return doc

def upsert_batch(container, docs, table_name):
    ok = fail = 0
    for doc in docs:
        try:
            container.upsert_item(doc)
            ok += 1
        except exceptions.CosmosHttpResponseError as e:
            fail += 1
            print(f"  ⚠️  Failed to upsert {table_name} id={doc.get('id')}: {e.message[:80]}")
    return ok, fail

# ── Main ─────────────────────────────────────────────────────────
def main():
    print(f"ZeroTrust-Swarm — SQLite → Cosmos DB Migration")
    print(f"  Source:   {SQLITE_PATH}")
    print(f"  Endpoint: {COSMOS_ENDPOINT[:40]}...")
    print(f"  Database: {COSMOS_DATABASE}\n")

    # Connect to SQLite
    if not os.path.exists(SQLITE_PATH):
        sys.exit(f"SQLite DB not found at '{SQLITE_PATH}'. Run the backend at least once first.")
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row

    # Connect to Cosmos DB
    client   = CosmosClient(COSMOS_ENDPOINT, credential=COSMOS_KEY)
    database = client.create_database_if_not_exists(id=COSMOS_DATABASE)
    print(f"✅ Connected to Cosmos DB database '{COSMOS_DATABASE}'")

    total_ok = total_fail = 0

    for table, (pk_path, index_fields) in CONTAINERS.items():
        # Create container (idempotent)
        try:
            container = database.create_container_if_not_exists(
                id=table,
                partition_key=PartitionKey(path=pk_path),
            )
        except exceptions.CosmosHttpResponseError as e:
            print(f"  ❌ Could not create container '{table}': {e.message}")
            continue

        rows = sqlite_rows(conn, table)
        if not rows:
            print(f"  ⏭  {table}: empty, skipping")
            continue

        docs   = [to_cosmos_doc(table, r) for r in rows]
        ok, fail = upsert_batch(container, docs, table)
        total_ok   += ok
        total_fail += fail
        status = "✅" if fail == 0 else "⚠️"
        print(f"  {status} {table}: {ok} migrated, {fail} failed  (partition key: {pk_path})")

    conn.close()
    print(f"\n{'='*50}")
    print(f"Migration complete: {total_ok} documents written, {total_fail} failed")

    if total_fail == 0:
        print("\nNext steps:")
        print("  1. Set COSMOS_ENDPOINT + COSMOS_KEY in Azure App Service → Configuration")
        print("  2. Set COSMOS_DATABASE=zerotrust")
        print("  3. Swap get_db() in main.py to use CosmosClient (see cosmos_client_stub.py)")
        print("  4. Remove sqlite3 dependency from requirements.txt")
    else:
        print(f"\n  ⚠️  {total_fail} documents failed — check partition key values above.")

if __name__ == "__main__":
    main()
