"""
SQLite storage for the hackathon build. Swap for Postgres/Supabase later
by changing DB_PATH's connection logic -- the SQL below is plain enough
to port directly.
"""
import json
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "vouch.db"
DB_PATH.parent.mkdir(exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    verify_token TEXT NOT NULL,
    domain_verified INTEGER NOT NULL DEFAULT 0,
    public_key_pem TEXT,
    private_key_pem TEXT,
    ats_webhook_secret TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS recruiters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER NOT NULL REFERENCES companies(id),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    linkedin_url TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS offers (
    id TEXT PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id),
    candidate_email TEXT NOT NULL,
    role TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    pdf_sha256 TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS lookalikes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER NOT NULL REFERENCES companies(id),
    domain TEXT NOT NULL,
    has_mx INTEGER NOT NULL DEFAULT 0,
    registered_days_ago INTEGER,
    risk TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(company_id, domain)
);

CREATE TABLE IF NOT EXISTS webhook_events (
    event_id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # MEMORY journal mode avoids creating a separate -journal file on disk.
    # Some bridged/network mounts (e.g. a folder shared into a VM) don't
    # support the file locking SQLite's default journal relies on, which
    # otherwise surfaces as "sqlite3.OperationalError: disk I/O error".
    conn.execute("PRAGMA journal_mode = MEMORY")
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# --------- companies ---------

def create_company(name: str, domain: str) -> sqlite3.Row:
    token = "vouch-verify=" + secrets.token_hex(8)
    webhook_secret = secrets.token_hex(24)
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO companies (name, domain, verify_token, ats_webhook_secret) "
            "VALUES (?, ?, ?, ?)",
            (name, domain, token, webhook_secret),
        )
        new_id = cur.lastrowid
    # fetched only after the transaction above has committed (the `with`
    # block's __exit__ commits it) -- otherwise this lookup can race the
    # insert and return None on some SQLite configurations
    return get_company(new_id)


def get_company(company_id: int) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM companies WHERE id = ?", (company_id,)
        ).fetchone()


def get_company_by_domain(domain: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM companies WHERE domain = ?", (domain,)
        ).fetchone()


def set_company_verified(company_id: int, public_key_pem: str, private_key_pem: str):
    with db() as conn:
        conn.execute(
            "UPDATE companies SET domain_verified = 1, public_key_pem = ?, "
            "private_key_pem = ? WHERE id = ?",
            (public_key_pem, private_key_pem, company_id),
        )


def list_companies() -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute("SELECT * FROM companies ORDER BY id").fetchall()


# --------- recruiters ---------

def add_recruiter(company_id: int, name: str, email: str, linkedin_url: str = ""):
    with db() as conn:
        conn.execute(
            "INSERT INTO recruiters (company_id, name, email, linkedin_url) "
            "VALUES (?, ?, ?, ?)",
            (company_id, name, email.lower(), linkedin_url),
        )


def list_recruiters(company_id: int) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM recruiters WHERE company_id = ? AND active = 1", (company_id,)
        ).fetchall()


def is_registered_recruiter(company_id: int, email: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM recruiters WHERE company_id = ? AND email = ? AND active = 1",
            (company_id, email.lower()),
        ).fetchone()
        return row is not None


# --------- offers ---------

def save_offer(offer_id: str, company_id: int, candidate_email: str, role: str,
               payload: dict, signature: str):
    with db() as conn:
        conn.execute(
            "INSERT INTO offers (id, company_id, candidate_email, role, payload_json, "
            "signature, pdf_sha256, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (offer_id, company_id, candidate_email, role, json.dumps(payload),
             signature, payload["pdf_sha256"], payload["issued_at"]),
        )


def get_offer(offer_id: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM offers WHERE id = ?", (offer_id,)).fetchone()


def find_offer_by_hash(pdf_sha256: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM offers WHERE pdf_sha256 = ?", (pdf_sha256,)
        ).fetchone()


def list_offers(company_id: int) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM offers WHERE company_id = ? ORDER BY issued_at DESC", (company_id,)
        ).fetchall()


# --------- lookalikes ---------

def upsert_lookalike(company_id: int, domain: str, has_mx: bool,
                      registered_days_ago: int | None, risk: str, source: str):
    with db() as conn:
        conn.execute(
            "INSERT INTO lookalikes (company_id, domain, has_mx, registered_days_ago, "
            "risk, source) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(company_id, domain) DO UPDATE SET "
            "has_mx=excluded.has_mx, registered_days_ago=excluded.registered_days_ago, "
            "risk=excluded.risk",
            (company_id, domain, int(has_mx), registered_days_ago, risk, source),
        )


def list_lookalikes(company_id: int) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM lookalikes WHERE company_id = ? ORDER BY first_seen DESC",
            (company_id,),
        ).fetchall()


def is_known_fake_domain(domain: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM lookalikes WHERE domain = ? AND risk != 'low'", (domain,)
        ).fetchone()


# --------- webhook idempotency ---------

def webhook_event_seen(event_id: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM webhook_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row is not None


def mark_webhook_event_seen(event_id: str):
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO webhook_events (event_id) VALUES (?)", (event_id,)
        )


if __name__ == "__main__":
    DB_PATH.unlink(missing_ok=True)
    init_db()
    c = create_company("Northwind Robotics", "northwind.xyz")
    assert c["domain"] == "northwind.xyz"
    add_recruiter(c["id"], "Priya Shah", "priya.shah@northwind.xyz")
    assert is_registered_recruiter(c["id"], "priya.shah@northwind.xyz")
    assert not is_registered_recruiter(c["id"], "someone@else.com")
    print("db self-test passed")
