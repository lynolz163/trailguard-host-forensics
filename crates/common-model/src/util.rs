use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{BufReader, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

#[cfg(any(target_os = "linux", test))]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::{collections::BTreeSet, fs};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use dirs::home_dir;
use hostname::get as get_hostname;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::debug;
use walkdir::WalkDir;

use crate::{
    Direction, FieldMap, FileArtifact, FileOp, NetConnection, Platform, ProcessIdentity, Severity,
};

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcSocketEntry {
    inode: u64,
    protocol: String,
    local_addr: String,
    remote_addr: String,
    state: Option<String>,
    net_namespace: Option<String>,
}

/// Create a host-scoped entity key.
pub fn host_entity_key(platform: Platform, hostname: &str) -> String {
    format!("host:{}:{}", platform, hostname.to_lowercase())
}

/// Create a process-stable entity key.
pub fn process_entity_key(platform: Platform, pid: i64, start_time: DateTime<Utc>) -> String {
    format!("{platform}:{pid}:{}", start_time.timestamp_millis())
}

/// Expand `~`, `%VAR%`, and `$VAR` path templates.
pub fn expand_path_template(input: &str) -> PathBuf {
    let mut rendered = input.to_string();
    if rendered.starts_with('~') {
        if let Some(home) = home_dir() {
            rendered = rendered.replacen('~', &home.to_string_lossy(), 1);
        }
    }

    for (key, value) in env::vars() {
        let windows_var = format!("%{key}%");
        if rendered.contains(&windows_var) {
            rendered = rendered.replace(&windows_var, &value);
        }
        let unix_var = format!("${key}");
        if rendered.contains(&unix_var) {
            rendered = rendered.replace(&unix_var, &value);
        }
    }

    PathBuf::from(rendered)
}

/// Convert a path to a UTF-8 lossy string.
pub fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Best-effort current hostname lookup.
pub fn current_hostname() -> String {
    get_hostname()
        .ok()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}

/// Return lowercase filename if available.
pub fn basename_lower(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| path.to_lowercase())
}

/// Best-effort file hashing with a size ceiling.
pub fn sha256_file(path: &Path, max_megabytes: u64) -> Result<Option<String>> {
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
    };

    if !metadata.is_file() {
        return Ok(None);
    }

    if metadata.len() > max_megabytes.saturating_mul(1024 * 1024) {
        debug!("skipping hash for large file {}", path.display());
        return Ok(None);
    }

    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
    );
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(Some(hex::encode(hasher.finalize())))
}

/// Collect current system network connections and map them to known process keys.
pub fn collect_system_net_connections(
    process_map: &HashMap<i64, String>,
    ts: DateTime<Utc>,
) -> Result<Vec<NetConnection>> {
    #[cfg(target_os = "linux")]
    match collect_linux_proc_net_connections(process_map, ts) {
        Ok(connections) => return Ok(connections),
        Err(error) => debug!("falling back to host socket enumeration: {error}"),
    }

    collect_host_net_connections(process_map, ts)
}

fn collect_host_net_connections(
    process_map: &HashMap<i64, String>,
    ts: DateTime<Utc>,
) -> Result<Vec<NetConnection>> {
    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .context("failed to enumerate sockets")?;

    let mut connections = Vec::new();
    for socket in sockets {
        let socket_inode = host_socket_inode(&socket);
        let pids = socket.associated_pids.clone();
        let protocol = match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => "tcp",
            ProtocolSocketInfo::Udp(_) => "udp",
        };

        for pid in pids {
            let pid = i64::from(pid);
            let Some(entity_key) = process_map.get(&pid) else {
                continue;
            };

            let (local_addr, remote_addr, state) = match socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(ref tcp) => (
                    format_socket_addr(tcp.local_addr, tcp.local_port),
                    format_socket_addr(tcp.remote_addr, tcp.remote_port),
                    Some(format!("{:?}", tcp.state).to_lowercase()),
                ),
                ProtocolSocketInfo::Udp(ref udp) => (
                    format!("{}:{}", udp.local_addr, udp.local_port),
                    "*".to_string(),
                    None,
                ),
            };

            connections.push(NetConnection {
                entity_key: entity_key.clone(),
                protocol: protocol.to_string(),
                local_addr,
                remote_addr,
                dns_name: None,
                direction: Direction::Unknown,
                state,
                net_namespace: None,
                observation_source: Some("host_netstat".to_string()),
                socket_inode,
                ts,
            });
        }
    }

    Ok(connections)
}

#[cfg(target_os = "linux")]
fn collect_linux_proc_net_connections(
    process_map: &HashMap<i64, String>,
    ts: DateTime<Utc>,
) -> Result<Vec<NetConnection>> {
    let mut connections = Vec::new();
    for (pid, entity_key) in process_map {
        let socket_inodes = list_process_socket_inodes(*pid);
        if socket_inodes.is_empty() {
            continue;
        }
        let net_namespace = read_process_net_namespace(*pid);
        for socket in enumerate_process_sockets(*pid, &socket_inodes, net_namespace.as_deref()) {
            let direction = infer_direction(&socket);
            let remote_addr = normalize_remote_addr(&socket.remote_addr);
            connections.push(NetConnection {
                entity_key: entity_key.clone(),
                protocol: socket.protocol,
                local_addr: socket.local_addr,
                remote_addr,
                dns_name: None,
                direction,
                state: socket.state,
                net_namespace: socket.net_namespace,
                observation_source: Some("proc_pid_net".to_string()),
                socket_inode: Some(socket.inode),
                ts,
            });
        }
    }

    connections.sort_by(|left, right| {
        left.ts
            .cmp(&right.ts)
            .then_with(|| left.entity_key.cmp(&right.entity_key))
            .then_with(|| left.protocol.cmp(&right.protocol))
            .then_with(|| left.local_addr.cmp(&right.local_addr))
            .then_with(|| left.remote_addr.cmp(&right.remote_addr))
    });
    Ok(connections)
}

#[cfg(target_os = "linux")]
fn list_process_socket_inodes(pid: i64) -> BTreeSet<u64> {
    let mut inodes = BTreeSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return inodes;
    };
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        if let Some(inode) = parse_socket_inode(&target.to_string_lossy()) {
            inodes.insert(inode);
        }
    }
    inodes
}

#[cfg(target_os = "linux")]
fn read_process_net_namespace(pid: i64) -> Option<String> {
    let target = fs::read_link(format!("/proc/{pid}/ns/net")).ok()?;
    Some(target.to_string_lossy().to_string())
}

#[cfg(target_os = "linux")]
fn enumerate_process_sockets(
    pid: i64,
    socket_inodes: &BTreeSet<u64>,
    net_namespace: Option<&str>,
) -> Vec<ProcSocketEntry> {
    let mut sockets = Vec::new();
    for (name, protocol, ipv6) in [
        ("tcp", "tcp", false),
        ("tcp6", "tcp", true),
        ("udp", "udp", false),
        ("udp6", "udp", true),
    ] {
        let path = format!("/proc/{pid}/net/{name}");
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        sockets.extend(
            parse_proc_net_table(&content, protocol, ipv6, net_namespace)
                .into_iter()
                .filter(|entry| socket_inodes.contains(&entry.inode)),
        );
    }
    sockets
}

#[cfg(target_os = "linux")]
fn parse_socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse::<u64>()
        .ok()
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_table(
    content: &str,
    protocol: &str,
    ipv6: bool,
    net_namespace: Option<&str>,
) -> Vec<ProcSocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| parse_proc_net_line(line, protocol, ipv6, net_namespace))
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_line(
    line: &str,
    protocol: &str,
    ipv6: bool,
    net_namespace: Option<&str>,
) -> Option<ProcSocketEntry> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 10 {
        return None;
    }
    Some(ProcSocketEntry {
        inode: parts.get(9)?.parse::<u64>().ok()?,
        protocol: protocol.to_string(),
        local_addr: parse_proc_socket_addr(parts.get(1)?, ipv6)?,
        remote_addr: parse_proc_socket_addr(parts.get(2)?, ipv6)?,
        state: parse_proc_socket_state(parts.get(3)?, protocol),
        net_namespace: net_namespace.map(str::to_string),
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_socket_addr(raw: &str, ipv6: bool) -> Option<String> {
    let (addr_hex, port_hex) = raw.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ipv6 {
        IpAddr::V6(parse_proc_ipv6(addr_hex)?)
    } else {
        IpAddr::V4(parse_proc_ipv4(addr_hex)?)
    };
    Some(SocketAddr::new(ip, port).to_string())
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_ipv4(raw: &str) -> Option<Ipv4Addr> {
    if raw.len() != 8 {
        return None;
    }
    let mut bytes = [0_u8; 4];
    for index in 0..4 {
        let start = index * 2;
        bytes[index] = u8::from_str_radix(&raw[start..start + 2], 16).ok()?;
    }
    bytes.reverse();
    Some(Ipv4Addr::from(bytes))
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_ipv6(raw: &str) -> Option<Ipv6Addr> {
    if raw.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for word in 0..4 {
        let base = word * 8;
        let mut chunk = [0_u8; 4];
        for index in 0..4 {
            let start = base + index * 2;
            chunk[index] = u8::from_str_radix(&raw[start..start + 2], 16).ok()?;
        }
        chunk.reverse();
        bytes[word * 4..word * 4 + 4].copy_from_slice(&chunk);
    }
    Some(Ipv6Addr::from(bytes))
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_socket_state(raw: &str, protocol: &str) -> Option<String> {
    if protocol != "tcp" {
        return None;
    }
    let normalized = match raw {
        "01" => "established",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "04" => "fin_wait1",
        "05" => "fin_wait2",
        "06" => "time_wait",
        "07" => "close",
        "08" => "close_wait",
        "09" => "last_ack",
        "0A" => "listen",
        "0B" => "closing",
        "0C" => "new_syn_recv",
        _ => return Some(raw.to_lowercase()),
    };
    Some(normalized.to_string())
}

fn format_socket_addr(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

#[cfg(any(target_os = "linux", test))]
fn is_unspecified_remote(remote_addr: &str) -> bool {
    matches!(remote_addr, "0.0.0.0:0" | "[::]:0" | "[::ffff:0.0.0.0]:0")
}

#[cfg(any(target_os = "linux", test))]
fn normalize_remote_addr(remote_addr: &str) -> String {
    if is_unspecified_remote(remote_addr) {
        "*".to_string()
    } else {
        remote_addr.to_string()
    }
}

#[cfg(any(target_os = "linux", test))]
fn infer_direction(socket: &ProcSocketEntry) -> Direction {
    if socket.protocol == "tcp" {
        if matches!(socket.state.as_deref(), Some("listen"))
            || is_unspecified_remote(&socket.remote_addr)
        {
            Direction::Unknown
        } else {
            Direction::Outbound
        }
    } else if is_unspecified_remote(&socket.remote_addr) {
        Direction::Unknown
    } else {
        Direction::Outbound
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn host_socket_inode(socket: &netstat2::SocketInfo) -> Option<u64> {
    Some(u64::from(socket.inode))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn host_socket_inode(_socket: &netstat2::SocketInfo) -> Option<u64> {
    None
}

/// Generate snapshot-backed file artifacts from running executables.
pub fn observed_executable_artifacts(
    processes: &[ProcessIdentity],
    ts: DateTime<Utc>,
) -> Vec<FileArtifact> {
    processes
        .iter()
        .filter_map(|process| {
            process.exe.as_ref().map(|path| FileArtifact {
                entity_key: process.entity_key.clone(),
                category: "process_executable".to_string(),
                path: path.clone(),
                file_id: None,
                op: FileOp::Observed,
                sha256: process.hash_sha256.clone(),
                size: None,
                owner: process.user.clone(),
                group: None,
                mode: None,
                mtime: None,
                ctime: None,
                atime: None,
                is_hidden: false,
                is_suid: false,
                is_sgid: false,
                is_executable: true,
                is_elf: path.to_lowercase().ends_with(".so")
                    || path.to_lowercase().contains("/bin/")
                    || path.to_lowercase().contains("/lib"),
                content_ref: None,
                notes: process.suspicious_flags.clone(),
                ts,
            })
        })
        .collect()
}

/// Build structured fields map from string key-value pairs.
pub fn fields(
    entries: impl IntoIterator<Item = (impl Into<String>, serde_json::Value)>,
) -> FieldMap {
    entries
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
}

/// Check whether a path should be treated as executable for reporting purposes.
pub fn looks_executable(path: &str) -> bool {
    let lower = path.to_lowercase();
    let path = Path::new(path);
    if let Some(ext) = path
        .extension()
        .map(|ext| ext.to_string_lossy().to_lowercase())
    {
        matches!(
            ext.as_str(),
            "exe"
                | "dll"
                | "com"
                | "bat"
                | "cmd"
                | "ps1"
                | "vbs"
                | "js"
                | "jar"
                | "msi"
                | "scr"
                | "sh"
                | "bin"
                | "run"
                | "py"
        )
    } else {
        lower.starts_with("/tmp/")
            || lower.starts_with("/dev/shm/")
            || lower.starts_with("/var/tmp/")
            || lower.starts_with("/home/")
    }
}

/// Walk a directory tree and return files only.
pub fn walk_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect()
}

/// Helper to compose informational monitor notes.
pub fn monitor_note(note: &str) -> String {
    note.to_string()
}

/// Create a standardized "unknown filesystem actor" entity key.
pub fn filesystem_actor(platform: Platform, hostname: &str) -> String {
    format!("{}:filesystem", host_entity_key(platform, hostname))
}

/// Create common event fields for a file event.
pub fn file_fields(path: &str, sha256: Option<&str>) -> FieldMap {
    fields([("path", json!(path)), ("sha256", json!(sha256))])
}

/// Create a human-readable risk description helper.
pub fn risk_reason(reason: impl Into<String>, severity: Severity) -> String {
    format!("{} ({severity})", reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_ipv4_entry() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 1308590A:BE90 0D08590A:1B75 01 00000000:00000000 00:00000000 00000000     0        0 3946409 1 0000000000000000 20 4 26 10 -1\n";
        let entries = parse_proc_net_table(content, "tcp", false, Some("net:[4026533082]"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local_addr, "10.89.8.19:48784");
        assert_eq!(entries[0].remote_addr, "10.89.8.13:7029");
        assert_eq!(entries[0].state.as_deref(), Some("established"));
        assert_eq!(entries[0].inode, 3946409);
        assert_eq!(
            entries[0].net_namespace.as_deref(),
            Some("net:[4026533082]")
        );
    }

    #[test]
    fn parses_proc_net_ipv6_entry() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 20 4 26 10 -1\n";
        let entries = parse_proc_net_table(content, "tcp", true, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local_addr, "[::1]:8080");
        assert_eq!(entries[0].remote_addr, "[::]:0");
        assert_eq!(entries[0].state.as_deref(), Some("listen"));
    }

    #[test]
    fn normalizes_unspecified_remote_and_infers_direction() {
        let socket = ProcSocketEntry {
            inode: 1,
            protocol: "tcp".into(),
            local_addr: "127.0.0.1:8080".into(),
            remote_addr: "0.0.0.0:0".into(),
            state: Some("listen".into()),
            net_namespace: Some("net:[4026531993]".into()),
        };
        assert!(is_unspecified_remote(&socket.remote_addr));
        assert_eq!(normalize_remote_addr(&socket.remote_addr), "*");
        assert_eq!(infer_direction(&socket), Direction::Unknown);
    }
}
