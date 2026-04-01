use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub type FieldMap = BTreeMap<String, Value>;

/// Supported host platforms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Windows,
    Unknown,
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Unknown => "unknown",
        };
        f.write_str(text)
    }
}

/// Event origin.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Snapshot,
    ProcessPoller,
    NetworkPoller,
    FileWatcher,
    PersistenceScanner,
    Ebpf,
    RuleEngine,
}

/// Normalized evidence event types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessSnapshot,
    ProcessStart,
    ProcessExit,
    NetConnect,
    FileObserved,
    FileCreate,
    FileWrite,
    Rename,
    PersistenceObserved,
    PersistenceCreate,
    PrivilegeChange,
    RuleMatch,
    SnapshotComplete,
}

/// Alerting severity with numeric scoring support.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 15,
            Self::Medium => 35,
            Self::High => 60,
            Self::Critical => 90,
        }
    }
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(text)
    }
}

/// Network direction when inferable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

/// File operation represented by a file artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    Observed,
    Create,
    Write,
    Rename,
}

/// Process identity stable across PID reuse by combining pid and start time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessIdentity {
    pub entity_key: String,
    pub pid: i64,
    pub ppid: i64,
    pub start_time: DateTime<Utc>,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub hash_sha256: Option<String>,
    pub signer: Option<String>,
    pub fd_count: Option<u32>,
    pub mapped_modules: Vec<String>,
    pub deleted_paths: Vec<String>,
    pub suspicious_flags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_running: bool,
}

impl ProcessIdentity {
    pub fn display_name(&self) -> String {
        self.exe
            .as_deref()
            .and_then(|path| std::path::Path::new(path).file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("pid-{}", self.pid))
    }
}

/// Hash-chained event record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub event_id: String,
    pub ts_wall: DateTime<Utc>,
    pub ts_mono: Option<u64>,
    pub source: EventSource,
    pub event_type: EventType,
    pub entity_key: String,
    pub parent_entity_key: Option<String>,
    pub severity: Severity,
    pub fields: FieldMap,
    pub raw_ref: Option<String>,
    pub prev_event_hash: Option<String>,
    pub event_hash: String,
}

impl Event {
    pub fn new(
        ts_wall: DateTime<Utc>,
        ts_mono: Option<u64>,
        source: EventSource,
        event_type: EventType,
        entity_key: impl Into<String>,
        parent_entity_key: Option<String>,
        severity: Severity,
        fields: FieldMap,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            ts_wall,
            ts_mono,
            source,
            event_type,
            entity_key: entity_key.into(),
            parent_entity_key,
            severity,
            fields,
            raw_ref: None,
            prev_event_hash: None,
            event_hash: String::new(),
        }
    }

    pub fn seal(&mut self, prev_event_hash: Option<String>) -> Result<()> {
        self.prev_event_hash = prev_event_hash;
        self.event_hash = self.compute_hash()?;
        Ok(())
    }

    pub fn compute_hash(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            event_id: &'a str,
            ts_wall: &'a DateTime<Utc>,
            ts_mono: &'a Option<u64>,
            source: &'a EventSource,
            event_type: &'a EventType,
            entity_key: &'a str,
            parent_entity_key: &'a Option<String>,
            severity: &'a Severity,
            fields: &'a FieldMap,
            raw_ref: &'a Option<String>,
            prev_event_hash: &'a Option<String>,
        }

        let canonical = Canonical {
            event_id: &self.event_id,
            ts_wall: &self.ts_wall,
            ts_mono: &self.ts_mono,
            source: &self.source,
            event_type: &self.event_type,
            entity_key: &self.entity_key,
            parent_entity_key: &self.parent_entity_key,
            severity: &self.severity,
            fields: &self.fields,
            raw_ref: &self.raw_ref,
            prev_event_hash: &self.prev_event_hash,
        };

        let payload = serde_json::to_vec(&canonical)?;
        let mut hasher = Sha256::new();
        hasher.update(payload);
        Ok(hex::encode(hasher.finalize()))
    }
}

/// Network connection evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetConnection {
    pub entity_key: String,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub dns_name: Option<String>,
    pub direction: Direction,
    pub state: Option<String>,
    pub net_namespace: Option<String>,
    pub observation_source: Option<String>,
    pub socket_inode: Option<u64>,
    pub ts: DateTime<Utc>,
}

/// File-related evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileArtifact {
    pub entity_key: String,
    pub category: String,
    pub path: String,
    pub file_id: Option<String>,
    pub op: FileOp,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: Option<String>,
    pub mtime: Option<DateTime<Utc>>,
    pub ctime: Option<DateTime<Utc>>,
    pub atime: Option<DateTime<Utc>>,
    pub is_hidden: bool,
    pub is_suid: bool,
    pub is_sgid: bool,
    pub is_executable: bool,
    pub is_elf: bool,
    pub content_ref: Option<String>,
    pub notes: Vec<String>,
    pub ts: DateTime<Utc>,
}

/// Persistence-related evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistenceArtifact {
    pub entity_key: String,
    pub mechanism: String,
    pub location: String,
    pub value: String,
    pub ts: DateTime<Utc>,
}

/// Host metadata persisted with every evidence package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostInfo {
    pub host_id: String,
    pub hostname: String,
    pub platform: Platform,
    pub collected_at: DateTime<Utc>,
    pub collector: String,
    pub kernel_version: Option<String>,
    pub os_version: Option<String>,
    pub boot_time: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub environment_summary: EnvironmentSummary,
    pub current_user: Option<String>,
    pub interfaces: Vec<NetworkInterface>,
    pub mounts: Vec<MountInfo>,
    pub disks: Vec<DiskUsage>,
    pub routes: Vec<RouteEntry>,
    pub dns: DnsConfig,
    pub hosts_entries: Vec<HostsEntry>,
    pub neighbors: Vec<NeighborEntry>,
    pub firewall_rules: Vec<FirewallRule>,
    pub current_online_users: Vec<OnlineUser>,
    pub recent_logins: Vec<LoginRecord>,
    pub failed_logins: Vec<LoginRecord>,
    pub user_accounts: Vec<UserAccount>,
    pub groups: Vec<GroupEntry>,
}

/// Environment variable inventory summarized for the report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EnvironmentSummary {
    pub total_vars: usize,
    pub highlights: FieldMap,
}

/// Network interface snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: Option<String>,
    pub oper_state: Option<String>,
    pub mtu: Option<u64>,
    pub addresses: Vec<String>,
}

/// Mounted filesystem snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MountInfo {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: Vec<String>,
}

/// Filesystem usage summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskUsage {
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

/// Route table entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub flags: Vec<String>,
    pub source: String,
}

/// DNS resolver snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DnsConfig {
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
    pub raw_ref: Option<String>,
}

/// Parsed hosts-file row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostsEntry {
    pub address: String,
    pub names: Vec<String>,
}

/// Layer-2 neighbor table entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NeighborEntry {
    pub address: String,
    pub hw_address: Option<String>,
    pub interface: Option<String>,
    pub state: Option<String>,
    pub source: String,
}

/// Firewall rule collection summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallRule {
    pub backend: String,
    pub summary: String,
    pub raw_ref: Option<String>,
}

/// Interactive or recent login record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginRecord {
    pub user: Option<String>,
    pub terminal: Option<String>,
    pub host: Option<String>,
    pub login_time: Option<DateTime<Utc>>,
    pub logout_time: Option<String>,
    pub status: Option<String>,
    pub source: String,
}

/// Current online user approximation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OnlineUser {
    pub user: String,
    pub tty: Option<String>,
    pub source: String,
}

/// Parsed local account summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserAccount {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub password_state: Option<String>,
}

/// Parsed local group summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// Point-in-time collector output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotBundle {
    pub host: HostInfo,
    pub processes: Vec<ProcessIdentity>,
    pub net_connections: Vec<NetConnection>,
    pub file_artifacts: Vec<FileArtifact>,
    pub persistence_artifacts: Vec<PersistenceArtifact>,
}

/// Native realtime collector output returned for a bounded monitor session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RealtimeMonitorBundle {
    pub snapshot: SnapshotBundle,
    pub processes: Vec<ProcessIdentity>,
    pub events: Vec<Event>,
    pub net_connections: Vec<NetConnection>,
    pub file_artifacts: Vec<FileArtifact>,
    pub persistence_artifacts: Vec<PersistenceArtifact>,
    pub notes: Vec<String>,
}

/// Complete evidence dataset reconstructed from storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceDataset {
    pub host: Option<HostInfo>,
    pub processes: Vec<ProcessIdentity>,
    pub events: Vec<Event>,
    pub net_connections: Vec<NetConnection>,
    pub file_artifacts: Vec<FileArtifact>,
    pub persistence_artifacts: Vec<PersistenceArtifact>,
    pub rule_matches: Vec<RuleMatch>,
}

impl Default for EvidenceDataset {
    fn default() -> Self {
        Self {
            host: None,
            processes: Vec::new(),
            events: Vec::new(),
            net_connections: Vec::new(),
            file_artifacts: Vec::new(),
            persistence_artifacts: Vec::new(),
            rule_matches: Vec::new(),
        }
    }
}

/// Explainable rule hit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleMatch {
    pub rule_id: String,
    pub entity_key: String,
    pub severity: Severity,
    pub why_matched: String,
    pub evidence_refs: Vec<String>,
    pub facts: FieldMap,
}

/// Process risk summary after correlation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuspiciousProcess {
    pub entity_key: String,
    pub display_name: String,
    pub risk_score: u32,
    pub severity: Severity,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
}

/// Process tree node for reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessNode {
    pub entity_key: String,
    pub parent_entity_key: Option<String>,
    pub pid: i64,
    pub ppid: i64,
    pub name: String,
    pub start_time: DateTime<Utc>,
    pub children: Vec<String>,
}

/// Time-ordered evidence summary row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineEntry {
    pub ts: DateTime<Utc>,
    pub label: String,
    pub severity: Severity,
    pub entity_key: Option<String>,
    pub refs: Vec<String>,
    pub is_inference: bool,
}

/// Correlated suspicious chain tying facts and inferred findings together.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrelatedChain {
    pub chain_id: String,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    pub risk_score: u32,
    pub process_keys: Vec<String>,
    pub file_paths: Vec<String>,
    pub remote_endpoints: Vec<String>,
    pub persistence_locations: Vec<String>,
    pub rule_ids: Vec<String>,
    pub event_refs: Vec<String>,
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
}

/// Aggregated host overview.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostOverview {
    pub hostname: String,
    pub platform: Platform,
    pub process_count: usize,
    pub event_count: usize,
    pub suspicious_processes: usize,
    pub rule_match_count: usize,
    pub listening_ports: usize,
    pub remote_ip_count: usize,
    pub collected_file_count: usize,
}

/// Full analysis package consumed by the HTML reporter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisBundle {
    pub host_overview: HostOverview,
    pub suspicious_processes: Vec<SuspiciousProcess>,
    pub top_chains: Vec<CorrelatedChain>,
    pub timeline: Vec<TimelineEntry>,
    pub process_tree: Vec<ProcessNode>,
    pub rule_matches: Vec<RuleMatch>,
    pub dataset: EvidenceDataset,
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    #[test]
    fn serializes_process_identity_roundtrip() {
        let process = ProcessIdentity {
            entity_key: "windows:42:1".into(),
            pid: 42,
            ppid: 4,
            start_time: Utc::now(),
            exe: Some("C:\\Windows\\System32\\cmd.exe".into()),
            cmdline: vec!["cmd.exe".into(), "/c".into(), "whoami".into()],
            cwd: Some("C:\\".into()),
            user: Some("SYSTEM".into()),
            hash_sha256: Some("ab".repeat(32)),
            signer: Some("Microsoft Windows".into()),
            fd_count: Some(12),
            mapped_modules: vec!["C:\\Windows\\System32\\kernel32.dll".into()],
            deleted_paths: vec![],
            suspicious_flags: vec![],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            is_running: true,
        };
        let encoded = serde_json::to_string(&process).unwrap();
        let decoded: ProcessIdentity = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.entity_key, process.entity_key);
        assert_eq!(decoded.cmdline, process.cmdline);
        assert_eq!(decoded.hash_sha256, process.hash_sha256);
    }

    #[test]
    fn hashes_event_chain_deterministically() {
        let now = Utc::now();
        let mut first = Event::new(
            now,
            Some(1),
            EventSource::Snapshot,
            EventType::ProcessStart,
            "linux:123:1",
            None,
            Severity::Info,
            FieldMap::from([("pid".into(), json!(123))]),
        );
        first.raw_ref = Some("events.jsonl:1".into());
        first.seal(None).unwrap();

        let mut second = Event::new(
            now,
            Some(2),
            EventSource::NetworkPoller,
            EventType::NetConnect,
            "linux:123:1",
            None,
            Severity::Medium,
            FieldMap::from([("remote_addr".into(), json!("8.8.8.8:443"))]),
        );
        second.raw_ref = Some("events.jsonl:2".into());
        second.seal(Some(first.event_hash.clone())).unwrap();

        assert_eq!(
            second.prev_event_hash.as_deref(),
            Some(first.event_hash.as_str())
        );

        let original_hash = second.event_hash.clone();
        second
            .fields
            .insert("remote_addr".into(), json!("1.1.1.1:53"));
        let changed_hash = second.compute_hash().unwrap();
        assert_ne!(original_hash, changed_hash);
    }
}
