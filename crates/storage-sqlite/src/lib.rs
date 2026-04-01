use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use common_model::{
    AppConfig, Event, EvidenceDataset, FileArtifact, HostInfo, NetConnection, PersistenceArtifact,
    ProcessIdentity, RuleMatch,
};
use rusqlite::{Connection, params};

/// SQLite + JSONL evidence writer/reader.
pub struct EvidenceStore {
    conn: Connection,
    jsonl_path: Option<PathBuf>,
    jsonl_writer: Option<BufWriter<File>>,
    jsonl_line_count: usize,
    last_event_hash: Option<String>,
}

impl EvidenceStore {
    /// Open or create an artifact directory with SQLite and JSONL outputs.
    pub fn create(output_dir: &Path, config: &AppConfig) -> Result<Self> {
        fs::create_dir_all(output_dir)
            .with_context(|| format!("failed to create {}", output_dir.display()))?;
        let db_path = output_dir.join(&config.output.db_name);
        let jsonl_path = output_dir.join(&config.output.jsonl_name);
        Self::open_internal(&db_path, Some(jsonl_path), true)
    }

    /// Open an existing database for read-only style access.
    pub fn open_db(db_path: &Path) -> Result<Self> {
        Self::open_internal(db_path, None, false)
    }

    fn open_internal(db_path: &Path, jsonl_path: Option<PathBuf>, writable: bool) -> Result<Self> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("failed to open database {}", db_path.display()))?;
        let mut store = Self {
            conn,
            jsonl_path,
            jsonl_writer: None,
            jsonl_line_count: 0,
            last_event_hash: None,
        };
        store.init_schema()?;
        store.last_event_hash = store.fetch_last_event_hash()?;

        if writable {
            if let Some(path) = store.jsonl_path.clone() {
                if path.exists() {
                    store.jsonl_line_count = fs::read_to_string(&path)
                        .map(|content| content.lines().count())
                        .unwrap_or_default();
                }
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .with_context(|| format!("failed to open jsonl {}", path.display()))?;
                store.jsonl_writer = Some(BufWriter::new(file));
            }
        }

        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS host_info (
                host_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                platform TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                collector TEXT NOT NULL,
                details_json TEXT
            );

            CREATE TABLE IF NOT EXISTS processes (
                entity_key TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                ppid INTEGER NOT NULL,
                start_time TEXT NOT NULL,
                exe TEXT,
                cmdline_json TEXT NOT NULL,
                cwd TEXT,
                user_name TEXT,
                hash_sha256 TEXT,
                signer TEXT,
                fd_count INTEGER,
                mapped_modules_json TEXT,
                deleted_paths_json TEXT,
                suspicious_flags_json TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_running INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                ts_wall TEXT NOT NULL,
                ts_mono INTEGER,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                parent_entity_key TEXT,
                severity TEXT NOT NULL,
                fields_json TEXT NOT NULL,
                raw_ref TEXT,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_wall);
            CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity_key);

            CREATE TABLE IF NOT EXISTS net_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_key TEXT NOT NULL,
                protocol TEXT NOT NULL,
                local_addr TEXT NOT NULL,
                remote_addr TEXT NOT NULL,
                dns_name TEXT,
                direction TEXT NOT NULL,
                state TEXT,
                ts TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_key TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'generic',
                path TEXT NOT NULL,
                file_id TEXT,
                op TEXT NOT NULL,
                sha256 TEXT,
                size INTEGER,
                owner_name TEXT,
                group_name TEXT,
                mode TEXT,
                mtime TEXT,
                ctime TEXT,
                atime TEXT,
                is_hidden INTEGER NOT NULL DEFAULT 0,
                is_suid INTEGER NOT NULL DEFAULT 0,
                is_sgid INTEGER NOT NULL DEFAULT 0,
                is_executable INTEGER NOT NULL DEFAULT 0,
                is_elf INTEGER NOT NULL DEFAULT 0,
                content_ref TEXT,
                notes_json TEXT,
                ts TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS persistence_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_key TEXT NOT NULL,
                mechanism TEXT NOT NULL,
                location TEXT NOT NULL,
                value TEXT NOT NULL,
                ts TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rule_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                severity TEXT NOT NULL,
                why_matched TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                facts_json TEXT NOT NULL
            );
            "#,
        )?;
        self.ensure_column("host_info", "details_json", "TEXT")?;
        self.ensure_column("processes", "fd_count", "INTEGER")?;
        self.ensure_column("processes", "mapped_modules_json", "TEXT")?;
        self.ensure_column("processes", "deleted_paths_json", "TEXT")?;
        self.ensure_column("processes", "suspicious_flags_json", "TEXT")?;
        self.ensure_column(
            "file_artifacts",
            "category",
            "TEXT NOT NULL DEFAULT 'generic'",
        )?;
        self.ensure_column("file_artifacts", "size", "INTEGER")?;
        self.ensure_column("file_artifacts", "owner_name", "TEXT")?;
        self.ensure_column("file_artifacts", "group_name", "TEXT")?;
        self.ensure_column("file_artifacts", "mode", "TEXT")?;
        self.ensure_column("file_artifacts", "mtime", "TEXT")?;
        self.ensure_column("file_artifacts", "ctime", "TEXT")?;
        self.ensure_column("file_artifacts", "atime", "TEXT")?;
        self.ensure_column("file_artifacts", "is_hidden", "INTEGER NOT NULL DEFAULT 0")?;
        self.ensure_column("file_artifacts", "is_suid", "INTEGER NOT NULL DEFAULT 0")?;
        self.ensure_column("file_artifacts", "is_sgid", "INTEGER NOT NULL DEFAULT 0")?;
        self.ensure_column(
            "file_artifacts",
            "is_executable",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        self.ensure_column("file_artifacts", "is_elf", "INTEGER NOT NULL DEFAULT 0")?;
        self.ensure_column("file_artifacts", "content_ref", "TEXT")?;
        self.ensure_column("file_artifacts", "notes_json", "TEXT")?;
        self.ensure_column("net_connections", "net_namespace", "TEXT")?;
        self.ensure_column("net_connections", "observation_source", "TEXT")?;
        self.ensure_column("net_connections", "socket_inode", "INTEGER")?;
        Ok(())
    }

    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> Result<()> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut stmt = self.conn.prepare(&pragma)?;
        let exists = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .any(|name| name == column);
        if !exists {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
            self.conn.execute(&sql, [])?;
        }
        Ok(())
    }

    fn fetch_last_event_hash(&self) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1")?;
        let hash = stmt.query_row([], |row| row.get(0)).optional()?;
        Ok(hash)
    }

    pub fn persist_host(&self, host: &HostInfo) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO host_info (host_id, hostname, platform, collected_at, collector, details_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(host_id) DO UPDATE SET
                hostname = excluded.hostname,
                platform = excluded.platform,
                collected_at = excluded.collected_at,
                collector = excluded.collector,
                details_json = excluded.details_json
            "#,
            params![
                host.host_id,
                host.hostname,
                host.platform.to_string(),
                host.collected_at.to_rfc3339(),
                host.collector,
                serde_json::to_string(host)?,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_process(&self, process: &ProcessIdentity) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO processes (
                entity_key, pid, ppid, start_time, exe, cmdline_json, cwd, user_name,
                hash_sha256, signer, fd_count, mapped_modules_json, deleted_paths_json,
                suspicious_flags_json, first_seen, last_seen, is_running
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            ON CONFLICT(entity_key) DO UPDATE SET
                ppid = excluded.ppid,
                exe = excluded.exe,
                cmdline_json = excluded.cmdline_json,
                cwd = excluded.cwd,
                user_name = excluded.user_name,
                hash_sha256 = excluded.hash_sha256,
                signer = excluded.signer,
                fd_count = excluded.fd_count,
                mapped_modules_json = excluded.mapped_modules_json,
                deleted_paths_json = excluded.deleted_paths_json,
                suspicious_flags_json = excluded.suspicious_flags_json,
                first_seen = MIN(processes.first_seen, excluded.first_seen),
                last_seen = MAX(processes.last_seen, excluded.last_seen),
                is_running = excluded.is_running
            "#,
            params![
                process.entity_key,
                process.pid,
                process.ppid,
                process.start_time.to_rfc3339(),
                process.exe,
                serde_json::to_string(&process.cmdline)?,
                process.cwd,
                process.user,
                process.hash_sha256,
                process.signer,
                process.fd_count.map(i64::from),
                serde_json::to_string(&process.mapped_modules)?,
                serde_json::to_string(&process.deleted_paths)?,
                serde_json::to_string(&process.suspicious_flags)?,
                process.first_seen.to_rfc3339(),
                process.last_seen.to_rfc3339(),
                if process.is_running { 1_i64 } else { 0_i64 },
            ],
        )?;
        Ok(())
    }

    pub fn insert_net_connection(&self, connection: &NetConnection) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO net_connections (
                entity_key, protocol, local_addr, remote_addr, dns_name, direction, state,
                net_namespace, observation_source, socket_inode, ts
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                connection.entity_key,
                connection.protocol,
                connection.local_addr,
                connection.remote_addr,
                connection.dns_name,
                format!("{:?}", connection.direction).to_lowercase(),
                connection.state,
                connection.net_namespace,
                connection.observation_source,
                connection
                    .socket_inode
                    .map(|value| i64::try_from(value).unwrap_or_default()),
                connection.ts.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn insert_file_artifact(&self, artifact: &FileArtifact) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO file_artifacts (
                entity_key, category, path, file_id, op, sha256, size, owner_name, group_name,
                mode, mtime, ctime, atime, is_hidden, is_suid, is_sgid, is_executable, is_elf,
                content_ref, notes_json, ts
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)
            "#,
            params![
                artifact.entity_key,
                artifact.category,
                artifact.path,
                artifact.file_id,
                format!("{:?}", artifact.op).to_lowercase(),
                artifact.sha256,
                artifact.size.map(to_sql_i64),
                artifact.owner,
                artifact.group,
                artifact.mode,
                artifact.mtime.map(|value| value.to_rfc3339()),
                artifact.ctime.map(|value| value.to_rfc3339()),
                artifact.atime.map(|value| value.to_rfc3339()),
                if artifact.is_hidden { 1_i64 } else { 0_i64 },
                if artifact.is_suid { 1_i64 } else { 0_i64 },
                if artifact.is_sgid { 1_i64 } else { 0_i64 },
                if artifact.is_executable { 1_i64 } else { 0_i64 },
                if artifact.is_elf { 1_i64 } else { 0_i64 },
                artifact.content_ref,
                serde_json::to_string(&artifact.notes)?,
                artifact.ts.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn insert_persistence_artifact(&self, artifact: &PersistenceArtifact) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO persistence_artifacts (entity_key, mechanism, location, value, ts)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                artifact.entity_key,
                artifact.mechanism,
                artifact.location,
                artifact.value,
                artifact.ts.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn append_event(&mut self, event: &mut Event) -> Result<()> {
        if event.raw_ref.is_none() {
            event.raw_ref = self
                .jsonl_path
                .as_ref()
                .map(|path| format!("{}:{}", path.display(), self.jsonl_line_count + 1));
        }
        event.seal(self.last_event_hash.clone())?;

        if let Some(writer) = self.jsonl_writer.as_mut() {
            serde_json::to_writer(&mut *writer, event)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            self.jsonl_line_count += 1;
        }

        self.conn.execute(
            r#"
            INSERT INTO events (
                event_id, ts_wall, ts_mono, source, event_type, entity_key, parent_entity_key,
                severity, fields_json, raw_ref, prev_event_hash, event_hash
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                event.event_id,
                event.ts_wall.to_rfc3339(),
                event.ts_mono.map(|value| value as i64),
                format!("{:?}", event.source).to_lowercase(),
                format!("{:?}", event.event_type).to_lowercase(),
                event.entity_key,
                event.parent_entity_key,
                event.severity.to_string(),
                serde_json::to_string(&event.fields)?,
                event.raw_ref,
                event.prev_event_hash,
                event.event_hash,
            ],
        )?;

        self.last_event_hash = Some(event.event_hash.clone());
        Ok(())
    }

    pub fn append_events(&mut self, events: &mut [Event]) -> Result<()> {
        for event in events {
            self.append_event(event)?;
        }
        Ok(())
    }

    pub fn replace_rule_matches(&self, matches: &[RuleMatch]) -> Result<()> {
        self.conn.execute("DELETE FROM rule_matches", [])?;
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO rule_matches (
                    rule_id, entity_key, severity, why_matched, evidence_refs_json, facts_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
            )?;
            for item in matches {
                stmt.execute(params![
                    item.rule_id,
                    item.entity_key,
                    item.severity.to_string(),
                    item.why_matched,
                    serde_json::to_string(&item.evidence_refs)?,
                    serde_json::to_string(&item.facts)?,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_dataset(&self) -> Result<EvidenceDataset> {
        Ok(EvidenceDataset {
            host: self.load_host_info()?,
            processes: self.load_processes()?,
            events: self.load_events()?,
            net_connections: self.load_net_connections()?,
            file_artifacts: self.load_file_artifacts()?,
            persistence_artifacts: self.load_persistence_artifacts()?,
            rule_matches: self.load_rule_matches()?,
        })
    }

    fn load_host_info(&self) -> Result<Option<HostInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT host_id, hostname, platform, collected_at, collector, details_json FROM host_info LIMIT 1",
        )?;
        let host = stmt
            .query_row([], |row| {
                let details_json = row.get::<_, Option<String>>(5)?;
                if let Some(details_json) = details_json {
                    if let Ok(host) = serde_json::from_str::<HostInfo>(&details_json) {
                        return Ok(host);
                    }
                }
                Ok(HostInfo {
                    host_id: row.get(0)?,
                    hostname: row.get(1)?,
                    platform: match row.get::<_, String>(2)?.as_str() {
                        "linux" => common_model::Platform::Linux,
                        "windows" => common_model::Platform::Windows,
                        _ => common_model::Platform::Unknown,
                    },
                    collected_at: parse_ts(row.get(3)?)?,
                    collector: row.get(4)?,
                    kernel_version: None,
                    os_version: None,
                    boot_time: None,
                    timezone: None,
                    environment_summary: common_model::EnvironmentSummary::default(),
                    current_user: None,
                    interfaces: Vec::new(),
                    mounts: Vec::new(),
                    disks: Vec::new(),
                    routes: Vec::new(),
                    dns: common_model::DnsConfig::default(),
                    hosts_entries: Vec::new(),
                    neighbors: Vec::new(),
                    firewall_rules: Vec::new(),
                    current_online_users: Vec::new(),
                    recent_logins: Vec::new(),
                    failed_logins: Vec::new(),
                    user_accounts: Vec::new(),
                    groups: Vec::new(),
                })
            })
            .optional()?;
        Ok(host)
    }

    fn load_processes(&self) -> Result<Vec<ProcessIdentity>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT entity_key, pid, ppid, start_time, exe, cmdline_json, cwd, user_name,
                   hash_sha256, signer, fd_count, mapped_modules_json, deleted_paths_json,
                   suspicious_flags_json, first_seen, last_seen, is_running
            FROM processes
            ORDER BY start_time ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ProcessIdentity {
                entity_key: row.get(0)?,
                pid: row.get(1)?,
                ppid: row.get(2)?,
                start_time: parse_ts(row.get(3)?)?,
                exe: row.get(4)?,
                cmdline: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(5)?)
                    .unwrap_or_default(),
                cwd: row.get(6)?,
                user: row.get(7)?,
                hash_sha256: row.get(8)?,
                signer: row.get(9)?,
                fd_count: row
                    .get::<_, Option<i64>>(10)?
                    .and_then(|value| u32::try_from(value).ok()),
                mapped_modules: parse_json_array(row.get(11)?),
                deleted_paths: parse_json_array(row.get(12)?),
                suspicious_flags: parse_json_array(row.get(13)?),
                first_seen: parse_ts(row.get(14)?)?,
                last_seen: parse_ts(row.get(15)?)?,
                is_running: row.get::<_, i64>(16)? != 0,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn load_events(&self) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT event_id, ts_wall, ts_mono, source, event_type, entity_key, parent_entity_key,
                   severity, fields_json, raw_ref, prev_event_hash, event_hash
            FROM events
            ORDER BY ts_wall ASC, rowid ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Event {
                event_id: row.get(0)?,
                ts_wall: parse_ts(row.get(1)?)?,
                ts_mono: row.get::<_, Option<i64>>(2)?.map(|value| value as u64),
                source: parse_source(&row.get::<_, String>(3)?),
                event_type: parse_event_type(&row.get::<_, String>(4)?),
                entity_key: row.get(5)?,
                parent_entity_key: row.get(6)?,
                severity: parse_severity(&row.get::<_, String>(7)?),
                fields: serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or_default(),
                raw_ref: row.get(9)?,
                prev_event_hash: row.get(10)?,
                event_hash: row.get(11)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn load_net_connections(&self) -> Result<Vec<NetConnection>> {
        let mut stmt = self.conn.prepare(
            "SELECT entity_key, protocol, local_addr, remote_addr, dns_name, direction, state, net_namespace, observation_source, socket_inode, ts FROM net_connections ORDER BY ts ASC, id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(NetConnection {
                entity_key: row.get(0)?,
                protocol: row.get(1)?,
                local_addr: row.get(2)?,
                remote_addr: row.get(3)?,
                dns_name: row.get(4)?,
                direction: parse_direction(&row.get::<_, String>(5)?),
                state: row.get(6)?,
                net_namespace: row.get(7)?,
                observation_source: row.get(8)?,
                socket_inode: row
                    .get::<_, Option<i64>>(9)?
                    .and_then(|value| u64::try_from(value).ok()),
                ts: parse_ts(row.get(10)?)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn load_file_artifacts(&self) -> Result<Vec<FileArtifact>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT entity_key, category, path, file_id, op, sha256, size, owner_name, group_name,
                   mode, mtime, ctime, atime, is_hidden, is_suid, is_sgid, is_executable, is_elf,
                   content_ref, notes_json, ts
            FROM file_artifacts
            ORDER BY ts ASC, id ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(FileArtifact {
                entity_key: row.get(0)?,
                category: row
                    .get::<_, Option<String>>(1)?
                    .unwrap_or_else(|| "generic".to_string()),
                path: row.get(2)?,
                file_id: row.get(3)?,
                op: parse_file_op(&row.get::<_, String>(4)?),
                sha256: row.get(5)?,
                size: row
                    .get::<_, Option<i64>>(6)?
                    .and_then(|value| u64::try_from(value).ok()),
                owner: row.get(7)?,
                group: row.get(8)?,
                mode: row.get(9)?,
                mtime: parse_optional_ts(row.get(10)?)?,
                ctime: parse_optional_ts(row.get(11)?)?,
                atime: parse_optional_ts(row.get(12)?)?,
                is_hidden: row.get::<_, i64>(13)? != 0,
                is_suid: row.get::<_, i64>(14)? != 0,
                is_sgid: row.get::<_, i64>(15)? != 0,
                is_executable: row.get::<_, i64>(16)? != 0,
                is_elf: row.get::<_, i64>(17)? != 0,
                content_ref: row.get(18)?,
                notes: parse_json_array(row.get(19)?),
                ts: parse_ts(row.get(20)?)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn load_persistence_artifacts(&self) -> Result<Vec<PersistenceArtifact>> {
        let mut stmt = self.conn.prepare(
            "SELECT entity_key, mechanism, location, value, ts FROM persistence_artifacts ORDER BY ts ASC, id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PersistenceArtifact {
                entity_key: row.get(0)?,
                mechanism: row.get(1)?,
                location: row.get(2)?,
                value: row.get(3)?,
                ts: parse_ts(row.get(4)?)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn load_rule_matches(&self) -> Result<Vec<RuleMatch>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT rule_id, entity_key, severity, why_matched, evidence_refs_json, facts_json
            FROM rule_matches
            ORDER BY id ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RuleMatch {
                rule_id: row.get(0)?,
                entity_key: row.get(1)?,
                severity: parse_severity(&row.get::<_, String>(2)?),
                why_matched: row.get(3)?,
                evidence_refs: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or_default(),
                facts: serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default(),
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn db_path(&self) -> Result<PathBuf> {
        let path = self
            .conn
            .path()
            .ok_or_else(|| anyhow::anyhow!("database path unavailable"))?;
        Ok(PathBuf::from(path))
    }
}

fn parse_ts(input: String) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&input)
        .map(|ts| ts.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                input.len(),
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
}

fn parse_optional_ts(input: Option<String>) -> rusqlite::Result<Option<DateTime<Utc>>> {
    input.map(parse_ts).transpose()
}

fn parse_json_array(input: Option<String>) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&input.unwrap_or_else(|| "[]".to_string()))
        .unwrap_or_default()
}

fn to_sql_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn parse_source(value: &str) -> common_model::EventSource {
    match value {
        "snapshot" => common_model::EventSource::Snapshot,
        "processpoller" => common_model::EventSource::ProcessPoller,
        "networkpoller" => common_model::EventSource::NetworkPoller,
        "filewatcher" => common_model::EventSource::FileWatcher,
        "persistencescanner" => common_model::EventSource::PersistenceScanner,
        "ebpf" => common_model::EventSource::Ebpf,
        "ruleengine" => common_model::EventSource::RuleEngine,
        _ => common_model::EventSource::Snapshot,
    }
}

fn parse_event_type(value: &str) -> common_model::EventType {
    match value {
        "processsnapshot" => common_model::EventType::ProcessSnapshot,
        "processstart" => common_model::EventType::ProcessStart,
        "processexit" => common_model::EventType::ProcessExit,
        "netconnect" => common_model::EventType::NetConnect,
        "fileobserved" => common_model::EventType::FileObserved,
        "filecreate" => common_model::EventType::FileCreate,
        "filewrite" => common_model::EventType::FileWrite,
        "rename" => common_model::EventType::Rename,
        "persistenceobserved" => common_model::EventType::PersistenceObserved,
        "persistencecreate" => common_model::EventType::PersistenceCreate,
        "privilegechange" => common_model::EventType::PrivilegeChange,
        "rulematch" => common_model::EventType::RuleMatch,
        "snapshotcomplete" => common_model::EventType::SnapshotComplete,
        _ => common_model::EventType::ProcessSnapshot,
    }
}

fn parse_severity(value: &str) -> common_model::Severity {
    match value {
        "low" => common_model::Severity::Low,
        "medium" => common_model::Severity::Medium,
        "high" => common_model::Severity::High,
        "critical" => common_model::Severity::Critical,
        _ => common_model::Severity::Info,
    }
}

fn parse_direction(value: &str) -> common_model::Direction {
    match value {
        "inbound" => common_model::Direction::Inbound,
        "outbound" => common_model::Direction::Outbound,
        _ => common_model::Direction::Unknown,
    }
}

fn parse_file_op(value: &str) -> common_model::FileOp {
    match value {
        "create" => common_model::FileOp::Create,
        "write" => common_model::FileOp::Write,
        "rename" => common_model::FileOp::Rename,
        _ => common_model::FileOp::Observed,
    }
}

trait OptionalRow<T> {
    fn optional(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalRow<T> for rusqlite::Result<T> {
    fn optional(self) -> rusqlite::Result<Option<T>> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use common_model::{Direction, EventSource, EventType, FieldMap, Platform, Severity};
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn writes_and_reads_schema() {
        let temp = tempdir().unwrap();
        let config = AppConfig::default();
        let mut store = EvidenceStore::create(temp.path(), &config).unwrap();
        let host = HostInfo {
            host_id: "host:windows:test".into(),
            hostname: "test-host".into(),
            platform: Platform::Windows,
            collected_at: Utc::now(),
            collector: "unit-test".into(),
            kernel_version: None,
            os_version: None,
            boot_time: None,
            timezone: None,
            environment_summary: common_model::EnvironmentSummary::default(),
            current_user: None,
            interfaces: Vec::new(),
            mounts: Vec::new(),
            disks: Vec::new(),
            routes: Vec::new(),
            dns: common_model::DnsConfig::default(),
            hosts_entries: Vec::new(),
            neighbors: Vec::new(),
            firewall_rules: Vec::new(),
            current_online_users: Vec::new(),
            recent_logins: Vec::new(),
            failed_logins: Vec::new(),
            user_accounts: Vec::new(),
            groups: Vec::new(),
        };
        store.persist_host(&host).unwrap();

        let process = ProcessIdentity {
            entity_key: "windows:1:123".into(),
            pid: 1,
            ppid: 0,
            start_time: Utc::now(),
            exe: Some("C:\\Windows\\System32\\cmd.exe".into()),
            cmdline: vec!["cmd.exe".into()],
            cwd: Some("C:\\".into()),
            user: Some("SYSTEM".into()),
            hash_sha256: Some("aa".repeat(32)),
            signer: None,
            fd_count: Some(8),
            mapped_modules: vec!["C:\\Windows\\System32\\kernel32.dll".into()],
            deleted_paths: Vec::new(),
            suspicious_flags: vec!["suspicious_cmdline".into()],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            is_running: true,
        };
        store.upsert_process(&process).unwrap();

        let artifact = FileArtifact {
            entity_key: process.entity_key.clone(),
            category: "process_executable".into(),
            path: "C:\\Windows\\System32\\cmd.exe".into(),
            file_id: Some("1:2".into()),
            op: common_model::FileOp::Observed,
            sha256: Some("bb".repeat(32)),
            size: Some(1024),
            owner: Some("SYSTEM".into()),
            group: None,
            mode: Some("0755".into()),
            mtime: None,
            ctime: None,
            atime: None,
            is_hidden: false,
            is_suid: false,
            is_sgid: false,
            is_executable: true,
            is_elf: false,
            content_ref: None,
            notes: vec!["test".into()],
            ts: Utc::now(),
        };
        store.insert_file_artifact(&artifact).unwrap();

        let connection = NetConnection {
            entity_key: process.entity_key.clone(),
            protocol: "tcp".into(),
            local_addr: "127.0.0.1:1000".into(),
            remote_addr: "1.1.1.1:443".into(),
            dns_name: None,
            direction: Direction::Outbound,
            state: Some("established".into()),
            net_namespace: Some("net:[4026531993]".into()),
            observation_source: Some("proc_pid_net".into()),
            socket_inode: Some(12345),
            ts: Utc::now(),
        };
        store.insert_net_connection(&connection).unwrap();

        let mut event = Event::new(
            Utc::now(),
            Some(42),
            EventSource::Snapshot,
            EventType::ProcessSnapshot,
            process.entity_key.clone(),
            None,
            Severity::Info,
            FieldMap::from([("exe".into(), json!("cmd.exe"))]),
        );
        store.append_event(&mut event).unwrap();

        let dataset = store.load_dataset().unwrap();
        assert_eq!(dataset.processes.len(), 1);
        assert_eq!(dataset.events.len(), 1);
        assert_eq!(dataset.net_connections.len(), 1);
        assert_eq!(dataset.file_artifacts.len(), 1);
        assert_eq!(dataset.processes[0].fd_count, Some(8));
        assert_eq!(dataset.processes[0].mapped_modules.len(), 1);
        assert_eq!(dataset.file_artifacts[0].category, "process_executable");
        assert_eq!(
            dataset.net_connections[0].net_namespace.as_deref(),
            Some("net:[4026531993]")
        );
        assert_eq!(
            dataset.net_connections[0].observation_source.as_deref(),
            Some("proc_pid_net")
        );
        assert_eq!(dataset.net_connections[0].socket_inode, Some(12345));
        assert!(dataset.host.is_some());
    }
}
