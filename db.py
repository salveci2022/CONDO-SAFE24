"""
CONDO-SAFE24 — Camada de persistência SQLite
Alertas persistem entre restarts do servidor
"""
import sqlite3, os, json
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo

DB_PATH = Path(os.environ.get('CONDO_DB_PATH', 'data/condosafe.db'))
TZ = ZoneInfo(os.environ.get('APP_TZ', 'America/Sao_Paulo'))

def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS alertas (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            caller      TEXT,
            location    TEXT,
            type        TEXT,
            description TEXT,
            contact     TEXT,
            lat         REAL,
            lng         REAL,
            accuracy    REAL,
            maps_url    TEXT,
            client_key  TEXT,
            client_name TEXT,
            ip          TEXT,
            resolved    INTEGER DEFAULT 0,
            resolved_at TEXT,
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            action     TEXT,
            details    TEXT,
            ip         TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE INDEX IF NOT EXISTS idx_alertas_client ON alertas(client_key);
        CREATE INDEX IF NOT EXISTS idx_alertas_resolved ON alertas(resolved);
        CREATE INDEX IF NOT EXISTS idx_alertas_created ON alertas(created_at);
        """)

def salvar_alerta(a: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO alertas
              (caller,location,type,description,contact,lat,lng,accuracy,
               maps_url,client_key,client_name,ip,resolved,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?)
        """, (a.get('caller'), a.get('location'), a.get('type'),
              a.get('description'), a.get('contact'),
              a.get('lat'), a.get('lng'), a.get('accuracy'),
              a.get('maps_url'), a.get('client_key'), a.get('client_name'),
              a.get('ip'), a.get('timestamp')))
        return cur.lastrowid

def listar_alertas(client_key=None, limit=200):
    with get_conn() as conn:
        if client_key:
            rows = conn.execute(
                "SELECT * FROM alertas WHERE client_key=? ORDER BY id DESC LIMIT ?",
                (client_key, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alertas ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

def resolver_alerta_db(alert_id=None):
    now = datetime.now(TZ).strftime('%d/%m/%Y %H:%M:%S')
    with get_conn() as conn:
        if alert_id:
            conn.execute("UPDATE alertas SET resolved=1, resolved_at=? WHERE id=?", (now, alert_id))
        else:
            conn.execute("UPDATE alertas SET resolved=1, resolved_at=? WHERE resolved=0 AND id=(SELECT MIN(id) FROM alertas WHERE resolved=0)", (now,))

def limpar_alertas_db():
    with get_conn() as conn:
        conn.execute("DELETE FROM alertas")

def stats_alertas(client_key=None):
    with get_conn() as conn:
        base = "WHERE client_key=?" if client_key else ""
        args = (client_key,) if client_key else ()
        total    = conn.execute(f"SELECT COUNT(*) FROM alertas {base}", args).fetchone()[0]
        ativos   = conn.execute(f"SELECT COUNT(*) FROM alertas {base} {'AND' if base else 'WHERE'} resolved=0", args).fetchone()[0]
        por_tipo = conn.execute(f"SELECT type, COUNT(*) as n FROM alertas {base} GROUP BY type ORDER BY n DESC", args).fetchall()
        por_hora = conn.execute(f"SELECT strftime('%H', created_at) as h, COUNT(*) as n FROM alertas {base} GROUP BY h ORDER BY h", args).fetchall()
        return {
            'total': total, 'ativos': ativos, 'resolvidos': total - ativos,
            'por_tipo': [dict(r) for r in por_tipo],
            'por_hora': [dict(r) for r in por_hora],
        }

def audit(action, details='', ip=''):
    with get_conn() as conn:
        conn.execute("INSERT INTO audit_log (action, details, ip) VALUES (?,?,?)", (action, details, ip))
