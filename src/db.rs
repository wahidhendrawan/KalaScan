use crate::ScanResult;
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

fn open_db() -> Result<Connection> {
    let conn = Connection::open(db_path())
        .with_context(|| format!("Failed to open database at {:?}", db_path()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
        .context("Failed to set pragmas")?;
    Ok(conn)
}

pub fn init_db() -> Result<()> {
    let conn = open_db()?;
    ensure_schema(&conn)
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
            triage_json TEXT
        )",
        [],
    )
    .context("Failed to create scan_history table")?;

    if !column_exists(conn, "scan_history", "triage_json")? {
        conn.execute("ALTER TABLE scan_history ADD COLUMN triage_json TEXT", [])
            .context("Failed to add triage_json column")?;
    }

    Ok(())
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
    let ai_json = result.ai_analysis.as_ref().map(serde_json::to_string).transpose()?;
    let rules_json = serde_json::to_string(&result.rule_matches)?;
    let triage_json = result.triage.as_ref().map(serde_json::to_string).transpose()?;

    conn.execute(
        "INSERT INTO scan_history (id, repo_url, timestamp, total_files, scanned_files, risk_score, total_matches, status, ai_analysis_json, rule_matches_json, triage_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
        ],
    )
    .context("Failed to insert scan result")?;

    Ok(())
}

pub fn get_scan(id: &str) -> Result<Option<ScanResult>> {
    let conn = open_db()?;
    ensure_schema(&conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, repo_url, timestamp, total_files, scanned_files, risk_score, total_matches, status, ai_analysis_json, rule_matches_json, triage_json
             FROM scan_history WHERE id = ?1",
        )
        .context("Failed to prepare get_scan statement")?;

    let mut rows = stmt.query(rusqlite::params![id])?;

    match rows.next()? {
        Some(row) => {
            let ai_json: Option<String> = row.get(8)?;
            let rules_json: String = row.get(9)?;
            let triage_json: Option<String> = row.get(10)?;

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
        .execute("DELETE FROM scan_history WHERE id = ?1", rusqlite::params![id])
        .context("Failed to delete scan")?;
    if affected == 0 {
        anyhow::bail!("Scan with id '{}' not found", id);
    }
    Ok(())
}
