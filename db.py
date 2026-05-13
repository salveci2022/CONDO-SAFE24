"""
CONDO-SAFE24 — Camada de persistência SQLite v3.0
Arquitetura de Privacidade por Design (LGPD)

Separação de camadas:
  alertas        → dados operacionais (sem dados pessoais)
  identity_vault → dados de identidade cifrados AES-256-GCM (expiração 90 dias)
  audit_log      → log imutável de acessos a dados pessoais

SpyNet Tecnologia Forense | CNPJ 64.000.808/0001-51
"""

import sqlite3, os, json, secrets, hashlib, base64, logging
from pathlib import Path
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

log = logging.getLogger('condosafe.db')

DB_PATH = Path(os.environ.get('CONDO_DB_PATH', 'data/condosafe.db'))
TZ      = ZoneInfo(os.environ.get('APP_TZ', 'America/Sao_Paulo'))

# ── Chave AES-256 (32 bytes obrigatório em produção) ──────────────────────────
_RAW_KEY = os.environ.get('VAULT_ENCRYPTION_KEY', '').strip()
if len(_RAW_KEY) == 64:
    VAULT_KEY = bytes.fromhex(_RAW_KEY)
elif _RAW_KEY:
    # Aceita string arbitrária — deriva com SHA-256
    VAULT_KEY = hashlib.sha256(_RAW_KEY.encode()).digest()
else:
    # Chave temporária em memória — dados não persistem entre restarts de forma legível
    VAULT_KEY = secrets.token_bytes(32)
    log.warning("VAULT_ENCRYPTION_KEY não definida. Configure uma chave fixa em produção!")

IP_SALT = os.environ.get('IP_HASH_SALT', 'condosafe-ip-salt-2026')

# ── Retenção de dados pessoais ────────────────────────────────────────────────
VAULT_RETENTION_DAYS = int(os.environ.get('VAULT_RETENTION_DAYS', '90'))


# ════════════════════════════════════════════════════════════════════════════
#  CRIPTOGRAFIA — AES-256-GCM via cryptography (lib padrão de produção)
#  Fallback: XOR + base64 caso cryptography não esteja instalada
# ════════════════════════════════════════════════════════════════════════════

def _try_import_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        return None

_AESGCM = _try_import_aesgcm()


def cifrar(texto: str) -> str:
    """Cifra texto com AES-256-GCM. Retorna base64(nonce+ciphertext)."""
    if not texto:
        return ''
    if _AESGCM:
        nonce = os.urandom(12)          # 96 bits — padrão GCM
        ct    = _AESGCM(VAULT_KEY).encrypt(nonce, texto.encode('utf-8'), None)
        return base64.b64encode(nonce + ct).decode('ascii')
    else:
        # Fallback simples (menos seguro — instale cryptography em produção)
        import itertools
        xored = bytes(a ^ b for a, b in zip(texto.encode('utf-8'), itertools.cycle(VAULT_KEY)))
        return 'FB:' + base64.b64encode(xored).decode('ascii')


def decifrar(token_b64: str) -> str:
    """Decifra texto produzido por cifrar()."""
    if not token_b64:
        return ''
    if token_b64.startswith('FB:'):
        import itertools
        raw   = base64.b64decode(token_b64[3:])
        return bytes(a ^ b for a, b in zip(raw, itertools.cycle(VAULT_KEY))).decode('utf-8')
    if _AESGCM:
        raw   = base64.b64decode(token_b64)
        nonce = raw[:12]
        ct    = raw[12:]
        return _AESGCM(VAULT_KEY).decrypt(nonce, ct, None).decode('utf-8')
    return '[chave indisponível]'


# ════════════════════════════════════════════════════════════════════════════
#  TOKEN ANÔNIMO E HASH DE IP
# ════════════════════════════════════════════════════════════════════════════

def gerar_token_id() -> str:
    """Gera token opaco — ex: TKN-A7F3-B2C1. Não contém info do morador."""
    rand = secrets.token_hex(8).upper()
    return f"TKN-{rand[:4]}-{rand[4:]}"


def hash_ip(ip: str) -> str:
    """Pseudonimiza IP com SHA-256 + salt. Irreversível sem o salt."""
    if not ip:
        return ''
    return hashlib.sha256(f"{IP_SALT}:{ip}".encode()).hexdigest()[:16]


# ════════════════════════════════════════════════════════════════════════════
#  CONEXÃO
# ════════════════════════════════════════════════════════════════════════════

def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ════════════════════════════════════════════════════════════════════════════
#  INICIALIZAÇÃO DO BANCO
# ════════════════════════════════════════════════════════════════════════════

def init_db():
    with get_conn() as conn:
        conn.executescript("""
        -- ── Tabela operacional (sem dados pessoais) ──────────────────────
        CREATE TABLE IF NOT EXISTS alertas (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id    TEXT NOT NULL,              -- referência anônima ao identity_vault
            area        TEXT,                       -- área genérica ex: "Bloco A", nunca unidade
            type        TEXT NOT NULL DEFAULT 'Pânico',
            prioridade  INTEGER DEFAULT 2,          -- 1=crítico 2=alto 3=médio
            description TEXT,
            lat         REAL,
            lng         REAL,
            accuracy    REAL,
            maps_url    TEXT,
            client_key  TEXT NOT NULL,
            client_name TEXT,
            ip_hash     TEXT,                       -- SHA-256 do IP, não o IP direto
            resolved    INTEGER DEFAULT 0,
            resolved_at TEXT,
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        );

        -- ── Vault de identidade (dados pessoais cifrados) ─────────────────
        CREATE TABLE IF NOT EXISTS identity_vault (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id    TEXT NOT NULL UNIQUE,       -- chave de ligação com alertas
            nome_enc    TEXT,                       -- AES-256-GCM cifrado
            contato_enc TEXT,                       -- AES-256-GCM cifrado
            unidade_enc TEXT,                       -- AES-256-GCM cifrado
            client_key  TEXT NOT NULL,
            ip_hash     TEXT,
            expires_at  TEXT NOT NULL,              -- created_at + VAULT_RETENTION_DAYS
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        );

        -- ── Log de auditoria imutável ─────────────────────────────────────
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT NOT NULL,
            token_id    TEXT,
            operator    TEXT,
            ip_hash     TEXT,
            details     TEXT,
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        );

        -- ── Índices ───────────────────────────────────────────────────────
        CREATE INDEX IF NOT EXISTS idx_alertas_client   ON alertas(client_key);
        CREATE INDEX IF NOT EXISTS idx_alertas_resolved ON alertas(resolved);
        CREATE INDEX IF NOT EXISTS idx_alertas_created  ON alertas(created_at);
        CREATE INDEX IF NOT EXISTS idx_vault_token      ON identity_vault(token_id);
        CREATE INDEX IF NOT EXISTS idx_vault_expires    ON identity_vault(expires_at);
        CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_log(action);
        """)
    log.info("Banco de dados v3.0 inicializado.")


# ════════════════════════════════════════════════════════════════════════════
#  SALVAR ALERTA (nova arquitetura)
# ════════════════════════════════════════════════════════════════════════════

def salvar_alerta(a: dict) -> dict:
    """
    Salva alerta separando identidade de ocorrência.
    Retorna: {'token_id': ..., 'alert_id': ...}
    """
    token_id   = gerar_token_id()
    ip_h       = hash_ip(a.get('ip', ''))
    now_str    = datetime.now(TZ).strftime('%d/%m/%Y %H:%M:%S')
    expires_at = (datetime.now(TZ) + timedelta(days=VAULT_RETENTION_DAYS)).strftime('%Y-%m-%d')

    # ── 1. Salva identidade cifrada no vault ──────────────────────────────
    nome     = a.get('caller') or a.get('nome') or ''
    contato  = a.get('contact') or a.get('contato') or ''
    unidade  = a.get('unidade') or ''

    with get_conn() as conn:
        conn.execute("""
            INSERT INTO identity_vault
              (token_id, nome_enc, contato_enc, unidade_enc, client_key, ip_hash, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            token_id,
            cifrar(nome)    if nome    else '',
            cifrar(contato) if contato else '',
            cifrar(unidade) if unidade else '',
            a.get('client_key', ''),
            ip_h,
            expires_at
        ))

        # ── 2. Salva ocorrência operacional sem dados pessoais ────────────
        cur = conn.execute("""
            INSERT INTO alertas
              (token_id, area, type, prioridade, description, lat, lng, accuracy,
               maps_url, client_key, client_name, ip_hash, resolved, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (
            token_id,
            a.get('area') or a.get('location') or '',
            a.get('type') or 'Pânico',
            a.get('prioridade', 2),
            a.get('description') or '',
            a.get('lat'),
            a.get('lng'),
            a.get('accuracy'),
            a.get('maps_url'),
            a.get('client_key', ''),
            a.get('client_name', ''),
            ip_h,
            now_str
        ))
        alert_id = cur.lastrowid

    return {'token_id': token_id, 'alert_id': alert_id}


# ════════════════════════════════════════════════════════════════════════════
#  LISTAR ALERTAS (sem dados pessoais)
# ════════════════════════════════════════════════════════════════════════════

def listar_alertas(client_key=None, limit=200):
    """Retorna alertas operacionais — sem nome, contato ou unidade."""
    with get_conn() as conn:
        if client_key:
            rows = conn.execute(
                "SELECT * FROM alertas WHERE client_key=? ORDER BY id DESC LIMIT ?",
                (client_key, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alertas ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


# ════════════════════════════════════════════════════════════════════════════
#  REVELAR IDENTIDADE (acesso restrito + auditado)
# ════════════════════════════════════════════════════════════════════════════

def revelar_identidade(token_id: str, operator: str = '', ip: str = '') -> dict:
    """
    Retorna dados decifrados do identity_vault.
    SEMPRE registra no audit_log.
    """
    ip_h = hash_ip(ip)
    audit('REVEAL_IDENTITY', token_id=token_id, operator=operator, ip=ip,
          details=f"Operador solicitou identidade do token {token_id}")

    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM identity_vault WHERE token_id=?", (token_id,)
        ).fetchone()

    if not row:
        return {'encontrado': False}

    return {
        'encontrado': True,
        'token_id':   token_id,
        'nome':       decifrar(row['nome_enc'])    if row['nome_enc']    else '—',
        'contato':    decifrar(row['contato_enc']) if row['contato_enc'] else '—',
        'unidade':    decifrar(row['unidade_enc']) if row['unidade_enc'] else '—',
        'expires_at': row['expires_at'],
    }


# ════════════════════════════════════════════════════════════════════════════
#  RESOLVER ALERTA
# ════════════════════════════════════════════════════════════════════════════

def resolver_alerta_db(alert_id=None, token_id=None):
    now = datetime.now(TZ).strftime('%d/%m/%Y %H:%M:%S')
    with get_conn() as conn:
        if alert_id:
            conn.execute(
                "UPDATE alertas SET resolved=1, resolved_at=? WHERE id=?",
                (now, alert_id))
        elif token_id:
            conn.execute(
                "UPDATE alertas SET resolved=1, resolved_at=? WHERE token_id=?",
                (now, token_id))
        else:
            conn.execute(
                "UPDATE alertas SET resolved=1, resolved_at=? "
                "WHERE resolved=0 AND id=(SELECT MIN(id) FROM alertas WHERE resolved=0)",
                (now,))


# ════════════════════════════════════════════════════════════════════════════
#  LIMPAR ALERTAS
# ════════════════════════════════════════════════════════════════════════════

def limpar_alertas_db():
    with get_conn() as conn:
        conn.execute("DELETE FROM alertas")


# ════════════════════════════════════════════════════════════════════════════
#  EXPIRAÇÃO AUTOMÁTICA DO VAULT (rodar diariamente)
# ════════════════════════════════════════════════════════════════════════════

def expirar_vault() -> int:
    """Remove dados de identidade vencidos. Retorna quantidade removida."""
    today = datetime.now(TZ).strftime('%Y-%m-%d')
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM identity_vault WHERE expires_at < ?", (today,))
        removed = cur.rowcount
    if removed:
        log.info(f"Vault: {removed} registros expirados removidos.")
        audit('VAULT_EXPIRATION', details=f"{removed} registros removidos automaticamente")
    return removed


# ════════════════════════════════════════════════════════════════════════════
#  ESTATÍSTICAS
# ════════════════════════════════════════════════════════════════════════════

def stats_alertas(client_key=None):
    with get_conn() as conn:
        base = "WHERE client_key=?" if client_key else ""
        args = (client_key,) if client_key else ()
        and_ = "AND" if client_key else "WHERE"

        total    = conn.execute(f"SELECT COUNT(*) FROM alertas {base}", args).fetchone()[0]
        ativos   = conn.execute(f"SELECT COUNT(*) FROM alertas {base} {and_} resolved=0", args).fetchone()[0]
        por_tipo = conn.execute(
            f"SELECT type, COUNT(*) as n FROM alertas {base} GROUP BY type ORDER BY n DESC", args
        ).fetchall()
        por_hora = conn.execute(
            f"SELECT strftime('%H', created_at) as h, COUNT(*) as n "
            f"FROM alertas {base} GROUP BY h ORDER BY h", args
        ).fetchall()

        # Tokens expirados no vault
        today           = datetime.now(TZ).strftime('%Y-%m-%d')
        vault_ativos    = conn.execute(
            "SELECT COUNT(*) FROM identity_vault WHERE expires_at >= ?", (today,)
        ).fetchone()[0]
        vault_expirados = conn.execute(
            "SELECT COUNT(*) FROM identity_vault WHERE expires_at < ?", (today,)
        ).fetchone()[0]

        return {
            'total': total, 'ativos': ativos, 'resolvidos': total - ativos,
            'por_tipo':         [dict(r) for r in por_tipo],
            'por_hora':         [dict(r) for r in por_hora],
            'vault_ativos':     vault_ativos,
            'vault_expirados':  vault_expirados,
        }


# ════════════════════════════════════════════════════════════════════════════
#  AUDITORIA
# ════════════════════════════════════════════════════════════════════════════

def audit(action: str, token_id: str = '', operator: str = '',
          ip: str = '', details: str = ''):
    ip_h = hash_ip(ip) if ip and not ip.startswith('0') else ip
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log (action, token_id, operator, ip_hash, details) VALUES (?,?,?,?,?)",
            (action, token_id, operator, ip_h, details)
        )


def listar_audit(limit=100):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
