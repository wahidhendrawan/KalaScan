use crate::{ScanRequest, ScanResult};
use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DB_FILENAME: &str = "kalascan.db";

fn db_path() -> PathBuf {
    let mut path = dirs_or_cwd();
    path.push(DB_FILENAME);
    path
}

fn dirs_or_cwd() -> PathBuf {
    if let Some(home) = std::env::var_os("KALASCAN_HOME") {
        PathBuf::from(home)
    } else {
        std::env::current_dir().unwrap_or_default()
    }
}

pub(crate) fn open_db() -> Result<Connection> {
    let conn = Connection::open(db_path())
        .with_context(|| format!("Failed to open database at {:?}", db_path()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
        .context("Failed to set pragmas")?;
    Ok(conn)
}

/// Schema version applied by `migrate`. Bump when adding a migration step.
const SCHEMA_VERSION: i64 = 4;

pub fn init_db() -> Result<()> {
    let conn = open_db()?;
    ensure_schema(&conn)?;
    migrate(&conn)
}

/// Apply incremental migrations keyed on `PRAGMA user_version`.
///
/// Version 1 legacy databases were built by `CREATE TABLE IF NOT EXISTS` with
/// per-column `ALTER`s, so they report `user_version = 0` while already having
/// most columns. Step 1 therefore only adds missing columns, then stamps 1.
fn migrate(conn: &Connection) -> Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current >= SCHEMA_VERSION {
        return Ok(());
    }

    if current < 1 {
        // Older versions created the table once and never migrated it, so
        // legacy DBs can be missing columns added in later releases.
        const LEGACY_COLUMNS: &[(&str, &str)] = &[
            ("status", "TEXT NOT NULL DEFAULT 'completed'"),
            ("ai_analysis_json", "TEXT"),
            ("rule_matches_json", "TEXT DEFAULT '[]'"),
            ("triage_json", "TEXT"),
            ("deobfuscation_json", "TEXT"),
            ("emulation_json", "TEXT"),
            ("ttp_json", "TEXT"),
            ("sandbox_json", "TEXT"),
        ];
        for (column, decl) in LEGACY_COLUMNS {
            if !column_exists(conn, "scan_history", column)? {
                conn.execute(
                    &format!("ALTER TABLE scan_history ADD COLUMN {} {}", column, decl),
                    [],
                )
                .with_context(|| format!("Failed to add {} column", column))?;
            }
        }
        conn.execute_batch("PRAGMA user_version = 1")?;
    }

    if current < 2 {
        // Scans are now enqueued before they start; index the status column so
        // `list_scans` and queue lookups stay cheap as history grows.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status)",
            [],
        )
        .context("Failed to create status index")?;
        conn.execute_batch("PRAGMA user_version = 2")?;
    }

    if current < 3 {
        // v3: multi-user auth + audit log + scan worker persistence.
        if !column_exists(conn, "scan_history", "request_json")? {
            conn.execute("ALTER TABLE scan_history ADD COLUMN request_json TEXT", [])
                .context("Failed to add request_json column")?;
        }
        if !column_exists(conn, "scan_history", "duration_ms")? {
            conn.execute(
                "ALTER TABLE scan_history ADD COLUMN duration_ms INTEGER",
                [],
            )
            .context("Failed to add duration_ms column")?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                token_prefix TEXT NOT NULL UNIQUE,
                token_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);",
        )
        .context("Failed to create users/audit_log tables")?;
        conn.execute_batch("PRAGMA user_version = 3")?;
    }

    if current < 4 {
        // v4: indicators of compromise extracted per scan.
        if !column_exists(conn, "scan_history", "iocs_json")? {
            conn.execute("ALTER TABLE scan_history ADD COLUMN iocs_json TEXT", [])
                .context("Failed to add iocs_json column")?;
        }
        conn.execute_batch("PRAGMA user_version = 4")?;
    }

    Ok(())
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            repo_url TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            total_files INTEGER NOT NULL,
            scanned_files INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            total_matches INTEGER NOT NULL,
            status TEXT NOT NULL,
            ai_analysis_json TEXT,
            rule_matches_json TEXT,
            triage_json TEXT,
            deobfuscation_json TEXT,
            emulation_json TEXT,
            ttp_json TEXT,
            sandbox_json TEXT
        )",
        [],
    )
    .context("Failed to create scan_history table")?;

    migrate(conn)
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({})", table))
        .context("Failed to inspect table schema")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .context("Failed to read table schema")?;
    for name in columns {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn save_scan(result: &ScanResult) -> Result<()> {
    let conn = open_db()?;
    ensure_schema(&conn)?;
    let ai_json = result
        .ai_analysis
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let rules_json = serde_json::to_string(&result.rule_matches)?;
    let triage_json = result
        .triage
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let deobfuscation_json = result
        .deobfuscation
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let emulation_json = result
        .emulation
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let ttp_json = result.ttp.as_ref().map(serde_json::to_string).transpose()?;
    let sandbox_json = result
        .sandbox
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let iocs_json = serde_json::to_string(&result.iocs)?;

    conn.execute(
        "INSERT INTO scan_history (id, repo_url, timestamp, total_files, scanned_files, risk_score, total_matches, status, ai_analysis_json, rule_matches_json, triage_json, deobfuscation_json, emulation_json, ttp_json, sandbox_json, request_json, duration_ms, iocs_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
         ON CONFLICT(id) DO UPDATE SET
            status = excluded.status,
            total_files = excluded.total_files,
            scanned_files = excluded.scanned_files,
            risk_score = excluded.risk_score,
            total_matches = excluded.total_matches,
            ai_analysis_json = excluded.ai_analysis_json,
            rule_matches_json = excluded.rule_matches_json,
            triage_json = excluded.triage_json,
            deobfuscation_json = excluded.deobfuscation_json,
            emulation_json = excluded.emulation_json,
            ttp_json = excluded.ttp_json,
            sandbox_json = excluded.sandbox_json,
            iocs_json = excluded.iocs_json,
            duration_ms = COALESCE(excluded.duration_ms, scan_history.duration_ms)",
        rusqlite::params![
            result.id,
            result.repo_url,
            result.timestamp,
            result.total_files as i64,
            result.scanned_files as i64,
            result.risk_score as i64,
            result.total_matches as i64,
            result.status,
            ai_json,
            rules_json,
            triage_json,
            deobfuscation_json,
            emulation_json,
            ttp_json,
            sandbox_json,
            Option::<String>::None,
            result.duration_ms.map(|d| d as i64),
            iocs_json,
        ],
    )
    .context("Failed to insert scan result")?;

    Ok(())
}

/// Persist a queued scan together with the request needed to resume it.
///
/// Scan workers live in-process, so a restart loses unstarted work; storing the
/// request lets the next boot requeue it (`pending_scans`).
pub fn save_pending(id: &str, req: &ScanRequest, timestamp: &str) -> Result<()> {
    let conn = open_db()?;
    ensure_schema(&conn)?;
    // Never persist secrets with the queued request.
    let mut safe = req.clone();
    safe.llm_api_key = None;
    let request_json = serde_json::to_string(&safe)?;
    conn.execute(
        "INSERT INTO scan_history (id, repo_url, timestamp, total_files, scanned_files, risk_score, total_matches, status, rule_matches_json, request_json)
         VALUES (?1, ?2, ?3, 0, 0, 0, 0, 'queued', '[]', ?4)
         ON CONFLICT(id) DO UPDATE SET status = 'queued', request_json = excluded.request_json",
        rusqlite::params![id, req.repo_url, timestamp, request_json],
    )
    .context("Failed to insert pending scan")?;
    Ok(())
}

/// Scans that were queued or running when the process stopped.
pub fn pending_scans(limit: u32) -> Result<Vec<(String, ScanRequest)>> {
    let conn = open_db()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, request_json FROM scan_history
             WHERE status IN ('queued', 'running') AND request_json IS NOT NULL
             ORDER BY timestamp ASC LIMIT ?1",
        )
        .context("Failed to prepare pending_scans statement")?;
    let rows = stmt
        .query_map(rusqlite::params![limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .context("Failed to query pending scans")?;
    let mut out = Vec::new();
    for row in rows {
        let (id, json) = row.context("Failed to read pending scan")?;
        match serde_json::from_str::<ScanRequest>(&json) {
            Ok(req) => out.push((id, req)),
            // An unreadable request can never be resumed; drop it so the queue
            // does not retry it forever.
            Err(e) => {
                eprintln!("Discarding unresumable scan {}: {}", id, e);
                let _ = delete_scan(&id);
            }
        }
    }
    Ok(out)
}

/// Delete all but the newest `keep` finished scans. Used to bound DB growth.
pub fn prune_scans(keep: u32) -> Result<usize> {
    let conn = open_db()?;
    let affected = conn
        .execute(
            "DELETE FROM scan_history WHERE id NOT IN (
                SELECT id FROM scan_history ORDER BY timestamp DESC LIMIT ?1
             ) AND status NOT IN ('queued', 'running')",
            rusqlite::params![keep],
        )
        .context("Failed to prune scan history")?;
    Ok(affected)
}

pub fn get_scan(id: &str) -> Result<Option<ScanResult>> {
    let conn = open_db()?;
    ensure_schema(&conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, repo_url, timestamp, total_files, scanned_files, risk_score, total_matches, status, ai_analysis_json, rule_matches_json, triage_json, deobfuscation_json, emulation_json, ttp_json, sandbox_json, duration_ms, iocs_json
             FROM scan_history WHERE id = ?1",
        )
        .context("Failed to prepare get_scan statement")?;

    let mut rows = stmt.query(rusqlite::params![id])?;

    match rows.next()? {
        Some(row) => {
            let ai_json: Option<String> = row.get(8)?;
            let rules_json: String = row.get(9)?;
            let triage_json: Option<String> = row.get(10)?;
            let deobfuscation_json: Option<String> = row.get(11)?;
            let emulation_json: Option<String> = row.get(12)?;
            let ttp_json: Option<String> = row.get(13)?;
            let sandbox_json: Option<String> = row.get(14)?;

            let ai_analysis = match ai_json {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).ok(),
                _ => None,
            };
            let rule_matches = serde_json::from_str(&rules_json)
                .context("Failed to deserialize rule_matches from DB")?;
            let triage = match triage_json {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).ok(),
                _ => None,
            };
            let deobfuscation = match deobfuscation_json {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).ok(),
                _ => None,
            };
            let emulation = match emulation_json {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).ok(),
                _ => None,
            };
            let ttp = match ttp_json {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).ok(),
                _ => None,
            };
            let sandbox = match sandbox_json {
                Some(s) if !s.is_empty() => serde_json::from_str(&s).ok(),
                _ => None,
            };
            let duration_ms: Option<i64> = row.get(15)?;
            let iocs: Vec<crate::iocs::Ioc> = row
                .get::<_, Option<String>>(16)?
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();

            Ok(Some(ScanResult {
                id: row.get(0)?,
                repo_url: row.get(1)?,
                timestamp: row.get(2)?,
                total_files: row.get::<_, i64>(3)? as usize,
                scanned_files: row.get::<_, i64>(4)? as usize,
                risk_score: row.get::<_, i64>(5)? as u8,
                total_matches: row.get::<_, i64>(6)? as usize,
                status: row.get(7)?,
                ai_analysis,
                rule_matches,
                triage,
                deobfuscation,
                emulation,
                ttp,
                sandbox,
                duration_ms: duration_ms.map(|d| d as u64),
                iocs,
            }))
        }
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultSummary {
    pub id: String,
    pub repo_url: String,
    pub timestamp: String,
    pub risk_score: u8,
    pub total_matches: usize,
    pub status: String,
}

pub fn list_scans(limit: u32) -> Result<Vec<ScanResultSummary>> {
    let conn = open_db()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, repo_url, timestamp, risk_score, total_matches, status
             FROM scan_history
             ORDER BY timestamp DESC
             LIMIT ?1",
        )
        .context("Failed to prepare list_scans statement")?;

    let rows = stmt
        .query_map(rusqlite::params![limit], |row| {
            Ok(ScanResultSummary {
                id: row.get(0)?,
                repo_url: row.get(1)?,
                timestamp: row.get(2)?,
                risk_score: row.get::<_, i64>(3)? as u8,
                total_matches: row.get::<_, i64>(4)? as usize,
                status: row.get(5)?,
            })
        })
        .context("Failed to query scan list")?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.context("Failed to read scan row")?);
    }
    Ok(results)
}

pub fn delete_scan(id: &str) -> Result<()> {
    let conn = open_db()?;
    let affected = conn
        .execute(
            "DELETE FROM scan_history WHERE id = ?1",
            rusqlite::params![id],
        )
        .context("Failed to delete scan")?;
    if affected == 0 {
        anyhow::bail!("Scan with id '{}' not found", id);
    }
    Ok(())
}

/// Open a connection with the schema guaranteed to exist (used by auth).
pub(crate) fn ready_conn() -> Result<Connection> {
    let conn = open_db()?;
    ensure_schema(&conn)?;
    Ok(conn)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
}

pub fn audit_insert(
    actor: &str,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    let conn = ready_conn()?;
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, action, target, detail)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            chrono::Utc::now().to_rfc3339(),
            actor,
            action,
            target,
            detail
        ],
    )
    .context("Failed to write audit log")?;
    Ok(())
}

pub fn audit_list(limit: u32) -> Result<Vec<AuditEntry>> {
    let conn = ready_conn()?;
    let mut stmt = conn
        .prepare(
            "SELECT timestamp, actor, action, target, detail FROM audit_log
             ORDER BY id DESC LIMIT ?1",
        )
        .context("Failed to prepare audit_list statement")?;
    let rows = stmt
        .query_map(rusqlite::params![limit], |row| {
            Ok(AuditEntry {
                timestamp: row.get(0)?,
                actor: row.get(1)?,
                action: row.get(2)?,
                target: row.get(3)?,
                detail: row.get(4)?,
            })
        })
        .context("Failed to query audit log")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("Failed to read audit row")?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_legacy_table_and_stamps_version() {
        let conn = Connection::open_in_memory().unwrap();
        // v1.2-era schema: only the core columns, no JSON report columns.
        conn.execute_batch(
            "CREATE TABLE scan_history (
                id TEXT PRIMARY KEY,
                repo_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                scanned_files INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                total_matches INTEGER NOT NULL
            );",
        )
        .unwrap();

        ensure_schema(&conn).unwrap();

        for column in [
            "status",
            "ai_analysis_json",
            "triage_json",
            "deobfuscation_json",
            "emulation_json",
            "ttp_json",
            "sandbox_json",
        ] {
            assert!(
                column_exists(&conn, "scan_history", column).unwrap(),
                "missing column {}",
                column
            );
        }
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Running again must be a no-op.
        ensure_schema(&conn).unwrap();
    }

    #[test]
    fn fresh_database_gets_current_version() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert!(column_exists(&conn, "scan_history", "status").unwrap());
        // v3 additions
        assert!(column_exists(&conn, "scan_history", "request_json").unwrap());
        assert!(column_exists(&conn, "scan_history", "duration_ms").unwrap());
        assert!(column_exists(&conn, "scan_history", "iocs_json").unwrap());
        let users: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(users, 1);
        let audit: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(audit, 1);
    }
}
