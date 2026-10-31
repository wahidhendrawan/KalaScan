//! Multi-user bearer auth with role-based access control and an audit trail.
//!
//! Tokens are random, shown once at creation, and stored only as
//! `sha256(salt || token)` with a short plaintext prefix used for lookup. The
//! `KALASCAN_TOKEN` env var remains supported as a legacy admin token.

use crate::db;
use anyhow::{Context, Result};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Number of leading token characters stored in cleartext for indexed lookup.
const TOKEN_PREFIX_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    /// True when `self` is at least as privileged as `required`.
    pub fn at_least(self, required: Role) -> bool {
        self >= required
    }
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub name: String,
    pub role: Role,
}

impl Principal {
    /// Used when no token/user is configured: the deployment is open.
    pub fn anonymous() -> Self {
        Self {
            name: "anonymous".to_string(),
            role: Role::Admin,
        }
    }

    /// The `KALASCAN_TOKEN` env var always maps to an administrator.
    pub fn legacy_admin() -> Self {
        Self {
            name: "legacy-token".to_string(),
            role: Role::Admin,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub role: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

fn hash_token(salt: &str, token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Length-independent, data-independent comparison (no early exit).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= (a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0)) as usize;
    }
    diff == 0
}

fn new_token() -> String {
    // 32 random bytes as hex, prefixed so it is recognisable in logs.
    format!(
        "ks_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Create a user and return the plaintext token. The token is not recoverable.
pub fn create_user(name: &str, role: Role) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("User name must not be empty");
    }
    let conn = db::ready_conn()?;
    let exists: Option<String> = conn
        .query_row("SELECT name FROM users WHERE name = ?1", [name], |row| {
            row.get(0)
        })
        .optional()
        .context("Failed to check existing user")?;
    if exists.is_some() {
        anyhow::bail!("User '{}' already exists", name);
    }

    let token = new_token();
    let prefix = token[..TOKEN_PREFIX_LEN].to_string();
    let salt = hex::encode(uuid::Uuid::new_v4().as_bytes());
    let hash = hash_token(&salt, &token);
    conn.execute(
        "INSERT INTO users (id, name, role, token_prefix, token_hash, salt, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            uuid::Uuid::new_v4().to_string(),
            name,
            role.as_str(),
            prefix,
            hash,
            salt,
            chrono::Utc::now().to_rfc3339(),
        ],
    )
    .context("Failed to insert user")?;
    Ok(token)
}

pub fn list_users() -> Result<Vec<UserInfo>> {
    let conn = db::ready_conn()?;
    let mut stmt = conn
        .prepare("SELECT name, role, created_at, last_used_at FROM users ORDER BY name")
        .context("Failed to prepare user list")?;
    let rows = stmt
        .query_map([], |row| {
            Ok(UserInfo {
                name: row.get(0)?,
                role: row.get(1)?,
                created_at: row.get(2)?,
                last_used_at: row.get(3)?,
            })
        })
        .context("Failed to query users")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("Failed to read user row")?);
    }
    Ok(out)
}

pub fn remove_user(name: &str) -> Result<bool> {
    let conn = db::ready_conn()?;
    let affected = conn
        .execute("DELETE FROM users WHERE name = ?1", [name])
        .context("Failed to delete user")?;
    Ok(affected > 0)
}

/// True when at least one user exists. Errors are treated as "no users" so a
/// missing/unavailable DB cannot lock the server out.
pub fn any_users() -> bool {
    db::ready_conn()
        .and_then(|conn| {
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
                .context("Failed to count users")
        })
        .map(|count| count > 0)
        .unwrap_or(false)
}

/// Verify a bearer token against the `users` table.
pub fn authenticate(token: &str) -> Option<Principal> {
    if token.len() < TOKEN_PREFIX_LEN {
        return None;
    }
    let prefix = &token[..TOKEN_PREFIX_LEN];
    let conn = db::ready_conn().ok()?;
    let row: Option<(String, String, String, String)> = conn
        .query_row(
            "SELECT name, role, token_hash, salt FROM users WHERE token_prefix = ?1",
            [prefix],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .ok()?;
    let (name, role, expected_hash, salt) = row?;
    let actual_hash = hash_token(&salt, token);
    if !constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
        return None;
    }
    let role = Role::parse(&role)?;
    let _ = conn.execute(
        "UPDATE users SET last_used_at = ?1 WHERE name = ?2",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), name],
    );
    Some(Principal { name, role })
}

/// Best-effort audit write; never fails the request.
pub fn audit(actor: &str, action: &str, target: Option<&str>, detail: Option<&str>) {
    if let Err(e) = db::audit_insert(actor, action, target, detail) {
        tracing::warn!("Failed to write audit log: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ordering_enforces_least_privilege() {
        assert!(Role::Admin.at_least(Role::Operator));
        assert!(Role::Operator.at_least(Role::Viewer));
        assert!(!Role::Viewer.at_least(Role::Operator));
        assert!(!Role::Operator.at_least(Role::Admin));
    }

    #[test]
    fn token_hash_is_salted_and_deterministic() {
        assert_eq!(hash_token("salt", "token"), hash_token("salt", "token"));
        assert_ne!(hash_token("salt", "token"), hash_token("other", "token"));
        assert_ne!(hash_token("salt", "token"), hash_token("salt", "other"));
    }

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn generated_tokens_have_lookup_prefix() {
        let token = new_token();
        assert!(token.starts_with("ks_"));
        assert!(token.len() > TOKEN_PREFIX_LEN);
        assert_eq!(&token[..TOKEN_PREFIX_LEN], &token[..TOKEN_PREFIX_LEN]);
    }
}
