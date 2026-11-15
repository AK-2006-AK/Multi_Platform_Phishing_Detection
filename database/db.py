import sqlite3
import os
from datetime import datetime

DB_PATH = "database/phishguard.db"

def init_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            customer_id TEXT,
            username TEXT,
            platform TEXT DEFAULT 'Telegram',
            input TEXT NOT NULL,
            source_type TEXT,
            risk_score REAL,
            verdict TEXT,
            nlp_score REAL,
            url_score REAL,
            qr_score REAL,
            threat_intel_score REAL,
            mitigation TEXT,
            reason TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            domain TEXT PRIMARY KEY,
            threat_type TEXT DEFAULT 'Phishing',
            added_on TEXT
        )
    ''')
    seed = [
        ("secure-login-update.com", "Phishing"),
        ("paytm-login-secure.net", "Malicious"),
        ("freegift-claim.xyz", "Scam"),
        ("sbi-kyc-update.net", "Phishing"),
        ("telegram-verify-code.net", "Account Hijack")
    ]
    for domain, t_type in seed:
        c.execute("INSERT OR IGNORE INTO threat_intelligence VALUES (?, ?, ?)", (domain, t_type, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def log_scan(data: dict):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO scan_logs (timestamp, customer_id, username, platform, input, source_type,
                               risk_score, verdict, nlp_score, url_score, qr_score,
                               threat_intel_score, mitigation, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        data.get("customer_id", "CUS-1055"),
        data.get("username", "@user"),
        data.get("platform", "Telegram"),
        data.get("input", ""),
        data.get("source_type", "Message"),
        data.get("risk_score", 0),
        data.get("verdict", "Safe"),
        data.get("nlp_score", 0),
        data.get("url_score", 0),
        data.get("qr_score", 0),
        data.get("threat_intel_score", 0),
        data.get("mitigation", "Passed"),
        data.get("reason", "")
    ))
    conn.commit()
    conn.close()

def is_blacklisted(domain: str) -> bool:
    if not domain:
        return False
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM threat_intelligence WHERE domain = ?", (domain.lower(),))
    res = c.fetchone()
    conn.close()
    return res is not None

def add_to_blacklist(domain: str):
    if not domain:
        return
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO threat_intelligence VALUES (?, ?, ?)", (domain.lower(), "Malicious", datetime.now().isoformat()))
    conn.commit()
    conn.close()
    