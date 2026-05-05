"""
database.py — Baza de date SQLite pentru IoT IDPS

Stochează persistent:
  - Incidente (înlocuiește JSON-urile separate)
  - Istoric blocări (pentru dublare timer la recurență)
  - Anomalii detectate (pentru statistici și dashboard)
  - Acțiuni AI (timeline interventions)

Folosit de: response.py, ai_agent.py, api.py
"""

import sqlite3
import json
import os
import threading
from datetime import datetime

DB_PATH = 'idps.db'

_db_lock = threading.Lock()

def _get_conn():
    """Creează o conexiune la baza de date."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row  
    conn.execute("PRAGMA journal_mode=WAL")  
    return conn


def init_db():
    """Creează tabelele dacă nu există. Apelat la pornirea sistemului."""
    with _db_lock:
        conn = _get_conn()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidente (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                sursa_ip TEXT NOT NULL,
                sursa_tip TEXT,
                dispozitiv_victima TEXT,
                container_victima TEXT,
                scor_ecod REAL,
                threshold REAL,
                ratio REAL,
                severitate TEXT,
                features_anormale TEXT,
                anomalii_5min INTEGER,
                anomalii_fereastra INTEGER,
                decizie TEXT,
                timer_secunde INTEGER,
                decizie_sursa TEXT DEFAULT 'rules',
                ai_verdict TEXT,
                abuseipdb TEXT,
                whois TEXT,
                ai_elapsed_seconds REAL,
                status TEXT DEFAULT 'active',
                deblocat_la TEXT,
                recurenta INTEGER DEFAULT 0,
                timer_anterior INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS istoric_blocari (
                ip TEXT PRIMARY KEY,
                ultimul_timer INTEGER NOT NULL,
                numar_blocari INTEGER DEFAULT 1,
                prima_blocare TEXT,
                ultima_blocare TEXT,
                ultima_deblocare TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalii (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sursa_ip TEXT NOT NULL,
                dst_ip TEXT,
                device TEXT,
                scor REAL,
                threshold REAL,
                este_anomalie INTEGER,
                incident_id TEXT
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidente_status ON incidente(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidente_timestamp ON incidente(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidente_sursa ON incidente(sursa_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalii_timestamp ON anomalii(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalii_device ON anomalii(device)')

        conn.commit()
        conn.close()

    print(f"[DATABASE] Baza de date inițializată: {DB_PATH}")

def salveaza_incident(incident):
    with _db_lock:
        conn = _get_conn()
        try:
            conn.execute('''
                INSERT OR REPLACE INTO incidente 
                (id, timestamp, sursa_ip, sursa_tip, dispozitiv_victima,
                 container_victima, scor_ecod, threshold, ratio, severitate,
                 features_anormale, anomalii_5min, anomalii_fereastra,
                 decizie, timer_secunde, decizie_sursa, ai_verdict,
                 abuseipdb, whois, ai_elapsed_seconds, status,
                 deblocat_la, recurenta, timer_anterior)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident['id'],
                incident['timestamp'],
                incident['sursa_ip'],
                incident.get('sursa_tip', ''),
                incident.get('dispozitiv_victima', ''),
                incident.get('container_victima', ''),
                incident.get('scor_ecod', 0),
                incident.get('threshold', 0),
                incident.get('ratio', 0),
                incident.get('severitate', ''),
                json.dumps(incident.get('features_anormale', []), ensure_ascii=False),
                incident.get('anomalii_5min', 0),
                incident.get('anomalii_fereastra', 0),
                incident.get('decizie', ''),
                incident.get('timer_secunde', 0),
                incident.get('decizie_sursa', 'rules'),
                json.dumps(incident.get('ai_verdict'), ensure_ascii=False) if incident.get('ai_verdict') else None,
                json.dumps(incident.get('abuseipdb'), ensure_ascii=False) if incident.get('abuseipdb') else None,
                json.dumps(incident.get('whois'), ensure_ascii=False) if incident.get('whois') else None,
                incident.get('ai_elapsed_seconds'),
                incident.get('status', 'active'),
                incident.get('deblocat_la'),
                incident.get('recurenta', 0),
                incident.get('timer_anterior', 0),
            ))
            conn.commit()
        finally:
            conn.close()


def actualizeaza_incident(incident_id, **kwargs):
    """Actualizează câmpuri specifice ale unui incident."""
    if not incident_id:
        return

    with _db_lock:
        conn = _get_conn()
        try:
            for key in ('ai_verdict', 'abuseipdb', 'whois', 'features_anormale'):
                if key in kwargs and kwargs[key] is not None:
                    kwargs[key] = json.dumps(kwargs[key], ensure_ascii=False)

            sets = ', '.join(f"{k} = ?" for k in kwargs.keys())
            values = list(kwargs.values()) + [incident_id]
            conn.execute(f"UPDATE incidente SET {sets} WHERE id = ?", values)
            conn.commit()
        finally:
            conn.close()


def get_incident(incident_id):
    """Citește un incident din baza de date."""
    with _db_lock:
        conn = _get_conn()
        try:
            row = conn.execute("SELECT * FROM incidente WHERE id = ?", (incident_id,)).fetchone()
            if row:
                return _row_to_incident(row)
            return None
        finally:
            conn.close()


def get_toate_incidentele():
    """Citește toate incidentele, ordonate descrescător pe timestamp."""
    with _db_lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM incidente ORDER BY timestamp DESC"
            ).fetchall()
            return [_row_to_incident(row) for row in rows]
        finally:
            conn.close()


def get_incidente_active():
    """Citește doar incidentele cu status 'active'."""
    with _db_lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM incidente WHERE status = 'active' ORDER BY timestamp DESC"
            ).fetchall()
            return [_row_to_incident(row) for row in rows]
        finally:
            conn.close()


def _row_to_incident(row):
    """Convertește un row SQLite în dict (format identic cu JSON-ul vechi)."""
    incident = dict(row)
    # Deserializăm câmpurile JSON
    for key in ('features_anormale', 'ai_verdict', 'abuseipdb', 'whois'):
        if incident.get(key):
            try:
                incident[key] = json.loads(incident[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return incident


def salveaza_istoric_blocare(ip, timer_secunde):
    """Salvează/actualizează istoricul de blocare pentru un IP."""
    now = datetime.now().isoformat()
    with _db_lock:
        conn = _get_conn()
        try:
            existing = conn.execute(
                "SELECT numar_blocari FROM istoric_blocari WHERE ip = ?", (ip,)
            ).fetchone()

            if existing:
                conn.execute('''
                    UPDATE istoric_blocari 
                    SET ultimul_timer = ?, numar_blocari = numar_blocari + 1,
                        ultima_deblocare = ?
                    WHERE ip = ?
                ''', (timer_secunde, now, ip))
            else:
                conn.execute('''
                    INSERT INTO istoric_blocari (ip, ultimul_timer, numar_blocari, prima_blocare, ultima_blocare)
                    VALUES (?, ?, 1, ?, ?)
                ''', (ip, timer_secunde, now, now))

            conn.commit()
        finally:
            conn.close()


def get_istoric_blocare(ip):
    """Citește istoricul de blocare pentru un IP (pentru dublare timer)."""
    with _db_lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM istoric_blocari WHERE ip = ?", (ip,)
            ).fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()


def get_tot_istoricul_blocari():
    """Citește tot istoricul de blocări."""
    with _db_lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM istoric_blocari ORDER BY ultima_blocare DESC"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


def salveaza_anomalie(timestamp, sursa_ip, dst_ip, device, scor, threshold, 
                       este_anomalie, incident_id=None):
    """Salvează o anomalie detectată (pentru grafice live)."""
    with _db_lock:
        conn = _get_conn()
        try:
            conn.execute('''
                INSERT INTO anomalii (timestamp, sursa_ip, dst_ip, device, scor, 
                                       threshold, este_anomalie, incident_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, sursa_ip, dst_ip, device, scor, threshold,
                  1 if este_anomalie else 0, incident_id))
            conn.commit()
        finally:
            conn.close()


def get_anomalii_recente(minute=30):
    """Citește anomaliile din ultimele N minute (pentru grafic live)."""
    with _db_lock:
        conn = _get_conn()
        try:
            rows = conn.execute('''
                SELECT * FROM anomalii 
                WHERE timestamp > datetime('now', ?)
                ORDER BY timestamp DESC
            ''', (f'-{minute} minutes',)).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


def get_anomalii_per_device(minute=30):
    """Statistici anomalii per device (pentru grafic)."""
    with _db_lock:
        conn = _get_conn()
        try:
            rows = conn.execute('''
                SELECT device, 
                       COUNT(*) as total,
                       SUM(este_anomalie) as anomalii,
                       AVG(scor) as scor_mediu,
                       MAX(scor) as scor_max
                FROM anomalii 
                WHERE timestamp > datetime('now', ?)
                GROUP BY device
            ''', (f'-{minute} minutes',)).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

def get_statistici():
    """Returnează statistici agregate pentru dashboard."""
    with _db_lock:
        conn = _get_conn()
        try:
            stats = {}

            stats['total_incidente'] = conn.execute(
                "SELECT COUNT(*) FROM incidente"
            ).fetchone()[0]

            stats['incidente_active'] = conn.execute(
                "SELECT COUNT(*) FROM incidente WHERE status = 'active'"
            ).fetchone()[0]

            for sev in ('HIGH', 'MEDIUM', 'LOW', 'LOG_ONLY'):
                stats[f'incidente_{sev.lower()}'] = conn.execute(
                    "SELECT COUNT(*) FROM incidente WHERE severitate = ?", (sev,)
                ).fetchone()[0]

            row = conn.execute(
                "SELECT AVG(ai_elapsed_seconds) FROM incidente WHERE ai_elapsed_seconds > 0"
            ).fetchone()
            stats['avg_ai_response'] = round(row[0], 1) if row[0] else 0

            stats['atacatori_unici'] = conn.execute(
                "SELECT COUNT(DISTINCT sursa_ip) FROM incidente WHERE decizie != 'log_only'"
            ).fetchone()[0]

            stats['recurente'] = conn.execute(
                "SELECT COUNT(*) FROM istoric_blocari WHERE numar_blocari > 1"
            ).fetchone()[0]

            return stats
        finally:
            conn.close()