use rusqlite::{params, Connection, Result as SqlResult};
use std::path::Path;
use tracing::info;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS doc_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    fetched_at      TEXT    NOT NULL,
    etag            TEXT,
    last_modified   TEXT,
    sha256          TEXT    NOT NULL,
    semantic_hash   TEXT,
    content         TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS doc_diffs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    url                  TEXT    NOT NULL,
    previous_snapshot_id INTEGER REFERENCES doc_snapshots(id),
    current_snapshot_id  INTEGER REFERENCES doc_snapshots(id),
    diff_type            TEXT    NOT NULL,
    summary              TEXT    NOT NULL,
    severity             TEXT    NOT NULL,
    created_at           TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT    NOT NULL,
    resolver    TEXT    NOT NULL,
    record_type TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    ttl         INTEGER,
    answers     TEXT    NOT NULL,
    authority   TEXT,
    additional  TEXT
);

CREATE TABLE IF NOT EXISTS dns_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT    NOT NULL,
    event_type TEXT    NOT NULL,
    old_value  TEXT,
    new_value  TEXT,
    severity   TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_doc_url         ON doc_snapshots(url);
CREATE INDEX IF NOT EXISTS idx_doc_url_fetched ON doc_snapshots(url, fetched_at);
CREATE INDEX IF NOT EXISTS idx_dns_host        ON dns_snapshots(host, resolver, record_type);
CREATE INDEX IF NOT EXISTS idx_dns_host_ts     ON dns_snapshots(host, resolver, record_type, timestamp);
"#;

// ── Row types ──

#[derive(Debug, Clone)]
pub struct DocSnapshot {
    pub id: Option<i64>,
    pub url: String,
    pub fetched_at: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub sha256: String,
    pub semantic_hash: Option<String>,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct DnsSnapshot {
    pub id: Option<i64>,
    pub host: String,
    pub resolver: String,
    pub record_type: String,
    pub timestamp: String,
    pub ttl: Option<i64>,
    pub answers: Vec<String>,
    pub authority: Option<String>,
    pub additional: Option<String>,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> SqlResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        info!(?path, "database initialized");
        Ok(Self { conn })
    }

    // ── Doc snapshots ──

    pub fn insert_doc_snapshot(&self, snap: &DocSnapshot) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO doc_snapshots (url, fetched_at, etag, last_modified, sha256, semantic_hash, content)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                snap.url, snap.fetched_at, snap.etag, snap.last_modified,
                snap.sha256, snap.semantic_hash, snap.content
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn latest_doc_snapshot(&self, url: &str) -> SqlResult<Option<DocSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, url, fetched_at, etag, last_modified, sha256, semantic_hash, content
             FROM doc_snapshots WHERE url = ?1 ORDER BY fetched_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![url])?;
        match rows.next()? {
            Some(row) => Ok(Some(DocSnapshot {
                id: Some(row.get(0)?),
                url: row.get(1)?,
                fetched_at: row.get(2)?,
                etag: row.get(3)?,
                last_modified: row.get(4)?,
                sha256: row.get(5)?,
                semantic_hash: row.get(6)?,
                content: row.get(7)?,
            })),
            None => Ok(None),
        }
    }

    pub fn insert_doc_diff(
        &self,
        url: &str,
        prev_id: i64,
        curr_id: i64,
        diff_type: &str,
        summary: &str,
        severity: &str,
    ) -> SqlResult<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO doc_diffs (url, previous_snapshot_id, current_snapshot_id, diff_type, summary, severity, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![url, prev_id, curr_id, diff_type, summary, severity, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    // ── DNS snapshots ──

    pub fn insert_dns_snapshot(&self, snap: &DnsSnapshot) -> SqlResult<i64> {
        let answers_json = serde_json::to_string(&snap.answers).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO dns_snapshots (host, resolver, record_type, timestamp, ttl, answers, authority, additional)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                snap.host, snap.resolver, snap.record_type, snap.timestamp,
                snap.ttl, answers_json, snap.authority, snap.additional
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn latest_dns_snapshot(
        &self,
        host: &str,
        resolver: &str,
        record_type: &str,
    ) -> SqlResult<Option<DnsSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, host, resolver, record_type, timestamp, ttl, answers, authority, additional
             FROM dns_snapshots
             WHERE host = ?1 AND resolver = ?2 AND record_type = ?3
             ORDER BY timestamp DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![host, resolver, record_type])?;
        match rows.next()? {
            Some(row) => {
                let answers_raw: String = row.get(6)?;
                let answers: Vec<String> =
                    serde_json::from_str(&answers_raw).unwrap_or_default();
                Ok(Some(DnsSnapshot {
                    id: Some(row.get(0)?),
                    host: row.get(1)?,
                    resolver: row.get(2)?,
                    record_type: row.get(3)?,
                    timestamp: row.get(4)?,
                    ttl: row.get(5)?,
                    answers,
                    authority: row.get(7)?,
                    additional: row.get(8)?,
                }))
            }
            None => Ok(None),
        }
    }

    pub fn insert_dns_event(
        &self,
        host: &str,
        event_type: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
        severity: &str,
    ) -> SqlResult<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO dns_events (host, event_type, old_value, new_value, severity, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![host, event_type, old_value, new_value, severity, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }
}
