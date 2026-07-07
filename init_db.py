#!/usr/bin/env python3
"""Create all tables and seed the DB with sample data.

Usage:
    python init_db.py             # idempotent — safe to run multiple times
    python init_db.py --reset     # drop + recreate all tables (destroys data)
"""
import json
import os
import sys
from urllib.parse import urlparse

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/vulndb")

# ── Auto-create the database if it doesn't exist ──────────────────────────

def _ensure_database(db_url: str) -> bool:
    """Connect to the 'postgres' maintenance DB and create the target DB if absent.

    Returns True if the database is ready, False if the connection itself failed
    (e.g. PostgreSQL not running) so the caller can print a helpful message.
    """
    parsed = urlparse(db_url)
    db_name = parsed.path.lstrip("/")
    # Swap the path component to the maintenance database
    maintenance_url = db_url.rsplit("/", 1)[0] + "/postgres"
    try:
        import psycopg2
        from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

        conn = psycopg2.connect(maintenance_url, connect_timeout=5)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (db_name,))
        exists = cur.fetchone()
        if not exists:
            cur.execute(f'CREATE DATABASE "{db_name}"')
            print(f"  [db] Database '{db_name}' created.")
        else:
            print(f"  [db] Database '{db_name}' already exists.")
        cur.close()
        conn.close()
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"  [db] Auto-create skipped: {exc}")
        print(f"  [db] If the database is missing, run:")
        print(f"  [db]   psql -U postgres -c \"CREATE DATABASE {db_name};\"")
        return False


# ── Main ──────────────────────────────────────────────────────────────────

def seed(db):
    from app import crud, schemas

    apps = [
        schemas.ApplicationCreate(
            ait_id="AIT-001",
            name="web-server-prod",
            owner_email="ait-owner@accenture.com",
            owner_name="Platform Owner",
            environment="production",
            host="172.16.0.9",
        ),
        schemas.ApplicationCreate(
            ait_id="AIT-002",
            name="api-gateway-staging",
            owner_email="api-team@accenture.com",
            owner_name="API Team",
            environment="staging",
            host="172.16.0.10",
        ),
    ]
    for app_data in apps:
        if not crud.get_application(db, app_data.ait_id):
            crud.create_application(db, app_data)
            print(f"  created {app_data.ait_id} — {app_data.name}")
        else:
            print(f"  {app_data.ait_id} already exists, skipping")

    dry_run = os.environ.get("DRY_RUN") == "1"

    # In live mode (DRY_RUN=0) the watch_agent imports real findings from the
    # target node.  Seeding sample findings here would create duplicates when
    # watch_agent later imports the real Trivy report.
    if not dry_run:
        print("  DRY_RUN=0 (live mode) — skipping sample findings.")
        print("  watch_agent.py will import real findings from the target.")
        return

    sample = os.path.join(os.path.dirname(__file__), "sample_report.json")
    if os.path.exists(sample):
        existing = crud.list_findings(db, "AIT-001")
        if not existing:
            with open(sample) as fh:
                data = json.load(fh)
            raw = []
            for result in data.get("Results") or []:
                for v in result.get("Vulnerabilities") or []:
                    raw.append({
                        "cve": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"),
                        "severity": v.get("Severity"),
                        "title": v.get("Title", ""),
                        "os": result.get("Target", ""),
                    })
            scan = crud.create_scan(db, "AIT-001", "sample_report.json", len(raw))
            for f in raw:
                category = "npt" if not f.get("fixed") else "vulnerability"
                obj = crud.create_finding(db, scan.id, "AIT-001", f, category)
                if category == "npt":
                    crud.upsert_plan(db, obj.id, None, "No fix available (NPT finding — no fixed version published).")
                    crud.update_finding(db, obj.id, plan_status="na")
                elif dry_run:
                    plan = {
                        "action": "update_package",
                        "package": obj.package,
                        "reboot_required": False,
                        "services_to_restart": [],
                        "reason": f"[DRY-RUN] Update {obj.package} from {obj.installed_version} to {obj.fixed_version} to fix {obj.cve_id}.",
                        "restore_plan": f"[DRY-RUN] dnf history undo last — restores {obj.package} to {obj.installed_version}.",
                    }
                    crud.upsert_plan(db, obj.id, plan, None)
                    crud.update_finding(db, obj.id, plan_status="ready")
            print(f"  imported {len(raw)} findings from sample_report.json")
        else:
            print(f"  AIT-001 already has {len(existing)} findings, skipping import")
    else:
        print("  sample_report.json not found — no findings seeded")


def _migrate_columns(engine):
    """Add any columns present in ORM models but missing from the live DB.

    Safe to call repeatedly — each ALTER is skipped when the column already
    exists.  Extend the list below whenever a new column is added to a model.
    """
    migrations = [
        # (table, column, pg_type)
        ("applications", "dep_report", "jsonb"),
        ("findings",     "dep_note",   "text"),
    ]
    with engine.connect() as conn:
        for table, column, pg_type in migrations:
            exists = conn.execute(
                __import__("sqlalchemy").text(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_name=:t AND column_name=:c"
                ),
                {"t": table, "c": column},
            ).fetchone()
            if not exists:
                conn.execute(
                    __import__("sqlalchemy").text(
                        f'ALTER TABLE {table} ADD COLUMN {column} {pg_type}'
                    )
                )
                conn.commit()
                print(f"  [migrate] Added column {table}.{column} ({pg_type})")
            else:
                print(f"  [migrate] {table}.{column} already exists — skipped")


def main():
    db_url = os.environ["DATABASE_URL"]

    # Step 1 — ensure the database itself exists
    print("\n[1/3] Checking database...")
    _ensure_database(db_url)

    # Step 2 — create / migrate tables
    print("\n[2/3] Creating tables...")
    from app.database import Base, SessionLocal, engine
    from app import models  # registers all ORM classes with Base before create_all

    reset = "--reset" in sys.argv
    if reset:
        print("  WARNING: dropping all tables (--reset)...")
        Base.metadata.drop_all(bind=engine)
        print("  Dropped.")

    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        print(f"\nERROR: Could not connect to PostgreSQL.\n  {exc}")
        print("\nEnsure PostgreSQL is running and DATABASE_URL is correct:")
        print(f"  {db_url}")
        sys.exit(1)

    # Apply additive column migrations for tables that already exist.
    # create_all() only creates missing tables — it never alters existing ones.
    _migrate_columns(engine)
    print("  Tables ready.")

    # Step 3 — seed sample data
    print("\n[3/3] Seeding sample data...")
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()

    print("\nDatabase initialised successfully.")


if __name__ == "__main__":
    main()
