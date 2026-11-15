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
);

CREATE TABLE IF NOT EXISTS threat_intelligence (
    domain TEXT PRIMARY KEY,
    threat_type TEXT DEFAULT 'Phishing',
    added_on TEXT
);
