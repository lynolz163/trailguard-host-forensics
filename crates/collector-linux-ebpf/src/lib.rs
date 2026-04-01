#[cfg(any(target_os = "linux", test))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(any(target_os = "linux", test))]
use common_model::{EventType, FileOp};
#[cfg(any(target_os = "linux", test))]
use linux_ebpf_shared::{
    ADDR_FAMILY_INET, ADDR_FAMILY_INET6, CAP_SUMMARY_NET_ADMIN, CAP_SUMMARY_SETGID,
    CAP_SUMMARY_SETUID, CAP_SUMMARY_SYS_ADMIN, CAP_SUMMARY_SYS_MODULE, CAP_SUMMARY_SYS_PTRACE,
    CAP_SUMMARY_SYS_RAWIO, FILE_OP_CREATE, FILE_OP_OBSERVED, FILE_OP_RENAME, FILE_OP_WRITE,
    ID_NO_CHANGE, PRIV_OP_CAPSET, PRIV_OP_EXEC_COMMIT, PRIV_OP_SETEGID, PRIV_OP_SETEUID,
    PRIV_OP_SETGID, PRIV_OP_SETREGID, PRIV_OP_SETRESGID, PRIV_OP_SETRESUID, PRIV_OP_SETREUID,
    PRIV_OP_SETUID, TrailRawEvent,
};

#[cfg(any(target_os = "linux", test))]
fn read_cstr(input: &[u8]) -> String {
    let end = input
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(input.len());
    String::from_utf8_lossy(&input[..end]).trim().to_string()
}

#[cfg(any(target_os = "linux", test))]
fn format_remote_addr(raw: &TrailRawEvent) -> String {
    let port = u16::from_be(raw.port_be);
    match raw.family {
        ADDR_FAMILY_INET => format!(
            "{}:{}",
            Ipv4Addr::new(raw.ip[0], raw.ip[1], raw.ip[2], raw.ip[3]),
            port
        ),
        ADDR_FAMILY_INET6 => format!("[{}]:{}", Ipv6Addr::from(raw.ip), port),
        _ => "unknown".to_string(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn map_file_op(op: u8) -> FileOp {
    match op {
        FILE_OP_CREATE => FileOp::Create,
        FILE_OP_WRITE => FileOp::Write,
        FILE_OP_RENAME => FileOp::Rename,
        _ => FileOp::Observed,
    }
}

#[cfg(any(target_os = "linux", test))]
fn map_file_event(op: u8) -> EventType {
    match op {
        FILE_OP_CREATE => EventType::FileCreate,
        FILE_OP_WRITE => EventType::FileWrite,
        FILE_OP_RENAME => EventType::Rename,
        FILE_OP_OBSERVED => EventType::FileObserved,
        _ => EventType::FileObserved,
    }
}

#[cfg(any(target_os = "linux", test))]
fn privilege_operation_name(op: u8) -> &'static str {
    match op {
        PRIV_OP_SETUID => "setuid",
        PRIV_OP_SETEUID => "seteuid",
        PRIV_OP_SETREUID => "setreuid",
        PRIV_OP_SETRESUID => "setresuid",
        PRIV_OP_SETGID => "setgid",
        PRIV_OP_SETEGID => "setegid",
        PRIV_OP_SETREGID => "setregid",
        PRIV_OP_SETRESGID => "setresgid",
        PRIV_OP_CAPSET => "capset",
        PRIV_OP_EXEC_COMMIT => "exec_credential_commit",
        _ => "privilege_change",
    }
}

#[cfg(any(target_os = "linux", test))]
fn normalize_raw_id(value: u32) -> Option<u32> {
    (value != ID_NO_CHANGE).then_some(value)
}

#[cfg(any(target_os = "linux", test))]
fn is_privileged_uid(value: u32) -> bool {
    value == 0
}

#[cfg(any(target_os = "linux", test))]
fn decode_capability_summary(summary: u32) -> Vec<&'static str> {
    let mut caps = Vec::new();
    for (bit, name) in [
        (CAP_SUMMARY_SYS_ADMIN, "cap_sys_admin"),
        (CAP_SUMMARY_NET_ADMIN, "cap_net_admin"),
        (CAP_SUMMARY_SYS_PTRACE, "cap_sys_ptrace"),
        (CAP_SUMMARY_SYS_MODULE, "cap_sys_module"),
        (CAP_SUMMARY_SYS_RAWIO, "cap_sys_rawio"),
        (CAP_SUMMARY_SETUID, "cap_setuid"),
        (CAP_SUMMARY_SETGID, "cap_setgid"),
    ] {
        if summary & bit != 0 {
            caps.push(name);
        }
    }
    caps
}

#[cfg(any(target_os = "linux", test))]
fn parse_socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse::<u64>()
        .ok()
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcSocketEntry {
    inode: u64,
    protocol: String,
    local_addr: String,
    remote_addr: String,
    state: Option<String>,
    net_namespace: Option<String>,
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
        local_addr: parse_proc_socket_addr(parts.get(1)?, ipv6)?,
        remote_addr: parse_proc_socket_addr(parts.get(2)?, ipv6)?,
        state: parse_proc_socket_state(parts.get(3)?, protocol),
        inode: parts.get(9)?.parse::<u64>().ok()?,
        protocol: protocol.to_string(),
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

#[cfg(any(target_os = "linux", test))]
fn is_unspecified_remote(remote: &str) -> bool {
    matches!(remote, "0.0.0.0:0" | "[::]:0" | "[::ffff:0.0.0.0]:0")
}

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        collections::{HashMap, HashSet},
        fs, mem,
        net::{IpAddr, SocketAddr},
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        thread,
        time::{Duration, Instant},
    };

    use crate::{
        ProcSocketEntry, decode_capability_summary, format_remote_addr, is_privileged_uid,
        is_unspecified_remote, map_file_event, map_file_op, normalize_raw_id, parse_proc_net_table,
        parse_socket_inode, privilege_operation_name, read_cstr,
    };
    use anyhow::{Context, Result, anyhow};
    use aya::{
        Ebpf,
        maps::PerfEventArray,
        programs::{KProbe, TracePoint},
        util::online_cpus,
    };
    use bytes::BytesMut;
    use chrono::Utc;
    use collector_linux_proc::{LinuxProcCollector, collect_process_identity};
    use common_model::{
        AppConfig, Event, EventSource, EventType, FileArtifact, FileOp, HostCollector,
        NetConnection, PersistenceArtifact, Platform, ProcessIdentity, RealtimeMonitorBundle,
        Severity, SnapshotBundle, expand_path_template, fields, looks_executable, monitor_note,
        sha256_file,
    };
    use linux_ebpf_shared::{
        EVENT_KIND_FILE_OPEN, EVENT_KIND_FILE_RENAME, EVENT_KIND_NET_CONNECT,
        EVENT_KIND_PRIVILEGE_CHANGE, EVENT_KIND_PROCESS_EXIT, EVENT_KIND_PROCESS_START,
        PRIV_OP_CAPSET, PRIV_OP_EXEC_COMMIT, TrailRawEvent,
    };
    use netstat2::{
        AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, get_sockets_info,
    };
    use serde_json::json;

    include!(concat!(env!("OUT_DIR"), "/embedded_ebpf.rs"));

    pub struct LinuxEbpfCollector;

    impl LinuxEbpfCollector {
        pub fn is_available(&self, config: &AppConfig) -> bool {
            (unsafe { libc::geteuid() == 0 }) && self.resolve_object_bytes(config).is_ok()
        }

        pub fn rationale(&self) -> &'static str {
            "Linux eBPF realtime path uses sched_process_exec/exit tracepoints plus connect and capset/set*id kprobes, while socket tuples are enriched from /proc/<pid>/net within each process netns."
        }

        fn resolve_object_bytes(&self, config: &AppConfig) -> Result<Vec<u8>> {
            if let Some(path) = config
                .collection
                .linux
                .ebpf_object_path
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                let path = expand_path_template(path);
                return fs::read(&path)
                    .with_context(|| format!("failed to read eBPF object {}", path.display()));
            }
            if HAS_EMBEDDED_EBPF {
                return Ok(EMBEDDED_EBPF.to_vec());
            }
            Err(anyhow!(BUILD_MESSAGE))
        }

        fn baseline_snapshot(&self, config: &AppConfig) -> Result<SnapshotBundle> {
            LinuxProcCollector.collect_snapshot(config)
        }

        fn attach_kprobe(
            bpf: &mut Ebpf,
            program_name: &str,
            candidates: &[&str],
        ) -> Result<String> {
            let program: &mut KProbe = bpf
                .program_mut(program_name)
                .with_context(|| format!("missing eBPF program {program_name}"))?
                .try_into()?;
            program.load()?;
            let mut last_error = None;
            for candidate in candidates {
                match program.attach(candidate, 0) {
                    Ok(_) => return Ok((*candidate).to_string()),
                    Err(error) => last_error = Some(error.to_string()),
                }
            }
            Err(anyhow!(
                "unable to attach {program_name} to any candidate symbol {:?}: {}",
                candidates,
                last_error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }

        fn try_attach_kprobe(
            bpf: &mut Ebpf,
            program_name: &str,
            candidates: &[&str],
            notes: &mut Vec<String>,
        ) -> Option<String> {
            match Self::attach_kprobe(bpf, program_name, candidates) {
                Ok(target) => Some(target),
                Err(error) => {
                    notes.push(format!(
                        "optional eBPF program {} not attached: {}",
                        program_name, error
                    ));
                    None
                }
            }
        }

        fn attach_tracepoint(
            bpf: &mut Ebpf,
            program_name: &str,
            category: &str,
            name: &str,
        ) -> Result<String> {
            let program: &mut TracePoint = bpf
                .program_mut(program_name)
                .with_context(|| format!("missing eBPF tracepoint {program_name}"))?
                .try_into()?;
            program.load()?;
            program.attach(category, name)?;
            Ok(format!("tracepoint:{category}:{name}"))
        }
    }

    impl HostCollector for LinuxEbpfCollector {
        fn backend_name(&self) -> &'static str {
            "linux-ebpf"
        }

        fn platform(&self) -> Platform {
            Platform::Linux
        }

        fn collect_snapshot(&self, config: &AppConfig) -> Result<SnapshotBundle> {
            self.baseline_snapshot(config)
        }

        fn monitor_native(
            &self,
            config: &AppConfig,
            duration: Duration,
        ) -> Result<Option<RealtimeMonitorBundle>> {
            let snapshot = self.baseline_snapshot(config)?;
            let mut process_cache = ProcessCache::from_snapshot(&snapshot);
            let object = self.resolve_object_bytes(config)?;
            let mut bpf = Ebpf::load(&object).context("failed to load eBPF object")?;

            let mut attached = Vec::new();
            let mut attachment_notes = Vec::new();
            attached.push(Self::attach_kprobe(
                &mut bpf,
                "enter_execve",
                &["__x64_sys_execve", "__arm64_sys_execve", "sys_execve"],
            )?);
            if let Some(target) = Self::try_attach_kprobe(
                &mut bpf,
                "enter_execveat",
                &["__x64_sys_execveat", "__arm64_sys_execveat", "sys_execveat"],
                &mut attachment_notes,
            ) {
                attached.push(target);
            }
            attached.push(Self::attach_tracepoint(
                &mut bpf,
                "sched_process_exec",
                "sched",
                "sched_process_exec",
            )?);
            attached.push(Self::attach_tracepoint(
                &mut bpf,
                "sched_process_exit",
                "sched",
                "sched_process_exit",
            )?);
            attached.push(Self::attach_tracepoint(
                &mut bpf,
                "enter_connect",
                "syscalls",
                "sys_enter_connect",
            )?);
            attached.push(Self::attach_tracepoint(
                &mut bpf,
                "exit_connect",
                "syscalls",
                "sys_exit_connect",
            )?);
            for (program_name, candidates) in [
                (
                    "enter_setuid",
                    ["__x64_sys_setuid", "__arm64_sys_setuid", "sys_setuid"],
                ),
                (
                    "exit_setuid",
                    ["__x64_sys_setuid", "__arm64_sys_setuid", "sys_setuid"],
                ),
                (
                    "enter_setreuid",
                    ["__x64_sys_setreuid", "__arm64_sys_setreuid", "sys_setreuid"],
                ),
                (
                    "exit_setreuid",
                    ["__x64_sys_setreuid", "__arm64_sys_setreuid", "sys_setreuid"],
                ),
                (
                    "enter_setresuid",
                    [
                        "__x64_sys_setresuid",
                        "__arm64_sys_setresuid",
                        "sys_setresuid",
                    ],
                ),
                (
                    "exit_setresuid",
                    [
                        "__x64_sys_setresuid",
                        "__arm64_sys_setresuid",
                        "sys_setresuid",
                    ],
                ),
                (
                    "enter_setgid",
                    ["__x64_sys_setgid", "__arm64_sys_setgid", "sys_setgid"],
                ),
                (
                    "exit_setgid",
                    ["__x64_sys_setgid", "__arm64_sys_setgid", "sys_setgid"],
                ),
                (
                    "enter_setregid",
                    ["__x64_sys_setregid", "__arm64_sys_setregid", "sys_setregid"],
                ),
                (
                    "exit_setregid",
                    ["__x64_sys_setregid", "__arm64_sys_setregid", "sys_setregid"],
                ),
                (
                    "enter_setresgid",
                    [
                        "__x64_sys_setresgid",
                        "__arm64_sys_setresgid",
                        "sys_setresgid",
                    ],
                ),
                (
                    "exit_setresgid",
                    [
                        "__x64_sys_setresgid",
                        "__arm64_sys_setresgid",
                        "sys_setresgid",
                    ],
                ),
                (
                    "enter_capset",
                    ["__x64_sys_capset", "__arm64_sys_capset", "sys_capset"],
                ),
                (
                    "exit_capset",
                    ["__x64_sys_capset", "__arm64_sys_capset", "sys_capset"],
                ),
            ] {
                attached.push(Self::attach_kprobe(&mut bpf, program_name, &candidates)?);
            }
            for (program_name, candidates) in [
                (
                    "enter_seteuid",
                    ["__x64_sys_seteuid", "__arm64_sys_seteuid", "sys_seteuid"],
                ),
                (
                    "exit_seteuid",
                    ["__x64_sys_seteuid", "__arm64_sys_seteuid", "sys_seteuid"],
                ),
                (
                    "enter_setegid",
                    ["__x64_sys_setegid", "__arm64_sys_setegid", "sys_setegid"],
                ),
                (
                    "exit_setegid",
                    ["__x64_sys_setegid", "__arm64_sys_setegid", "sys_setegid"],
                ),
            ] {
                if let Some(target) = Self::try_attach_kprobe(
                    &mut bpf,
                    program_name,
                    &candidates,
                    &mut attachment_notes,
                ) {
                    attached.push(target);
                }
            }
            let mut perf_array = PerfEventArray::try_from(
                bpf.take_map("EVENTS")
                    .context("missing EVENTS perf array in eBPF object")?,
            )?;
            let mut perf_buffers = Vec::new();
            for cpu in online_cpus().map_err(|(_cpu, error)| error)? {
                perf_buffers
                    .push(perf_array.open(cpu, Some(config.collection.linux.ebpf_perf_pages))?);
            }

            let mut result = RealtimeMonitorBundle {
                snapshot,
                processes: Vec::new(),
                events: Vec::new(),
                net_connections: Vec::new(),
                file_artifacts: Vec::new(),
                persistence_artifacts: Vec::new(),
                notes: vec![
                    self.rationale().to_string(),
                    format!("attachment targets: {}", attached.join(", ")),
                    BUILD_MESSAGE.to_string(),
                ],
            };
            let mut snapshot_state = SnapshotPollState::from_snapshot(&result.snapshot);
            result.notes.extend(attachment_notes);
            let poll_interval =
                Duration::from_secs(std::cmp::max(1, config.collection.poll_interval_secs));
            let mut last_poll = Instant::now();

            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(mem::size_of::<TrailRawEvent>()))
                .collect::<Vec<_>>();
            let started = Instant::now();
            while started.elapsed() < duration {
                let mut saw_event = false;
                for perf_buffer in &mut perf_buffers {
                    if !perf_buffer.readable() {
                        continue;
                    }
                    let events = perf_buffer.read_events(&mut buffers)?;
                    if events.lost > 0 {
                        result
                            .notes
                            .push(format!("lost {} eBPF events on perf buffer", events.lost));
                    }
                    for buffer in buffers.iter_mut().take(events.read) {
                        saw_event = true;
                        if let Some(raw) = decode_raw_event(buffer) {
                            handle_raw_event(config, &mut process_cache, raw, &mut result)?;
                        }
                        buffer.clear();
                    }
                }

                if last_poll.elapsed() >= poll_interval {
                    let current = LinuxProcCollector.collect_snapshot(config)?;
                    apply_snapshot_poll(
                        &current,
                        started.elapsed(),
                        &mut snapshot_state,
                        &mut result,
                    );
                    last_poll = Instant::now();
                }

                if !saw_event {
                    thread::sleep(Duration::from_millis(25));
                }
            }

            Ok(Some(result))
        }

        fn recommended_watch_paths(&self, config: &AppConfig) -> Vec<PathBuf> {
            LinuxProcCollector.recommended_watch_paths(config)
        }

        fn realtime_notes(&self) -> Vec<String> {
            vec![
                monitor_note("native realtime uses eBPF kprobes + tracepoints"),
                monitor_note(
                    "connect plus selected set*id/capset privilege changes are kernel-backed",
                ),
                monitor_note(
                    "sched_process_exec captures pre/post-exec credentials for stronger exec credential commit attribution",
                ),
                monitor_note(
                    "connect uses syscall tracepoints and enriches tuples from /proc/<pid>/net inside each process netns",
                ),
                monitor_note(
                    "setuid/setgid exec transitions combine tracepoint pre-exec IDs with file mode metadata",
                ),
                monitor_note(
                    "snapshot diff polling supplements process and socket state coverage during native monitoring",
                ),
                monitor_note(BUILD_MESSAGE),
            ]
        }
    }

    fn decode_raw_event(buffer: &BytesMut) -> Option<TrailRawEvent> {
        if buffer.len() < mem::size_of::<TrailRawEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TrailRawEvent>()) })
    }

    fn handle_raw_event(
        config: &AppConfig,
        process_cache: &mut ProcessCache,
        raw: TrailRawEvent,
        result: &mut RealtimeMonitorBundle,
    ) -> Result<()> {
        let ts = Utc::now();
        match raw.kind {
            EVENT_KIND_PROCESS_START => {
                let previous_process = process_cache.get(raw.pid as i64).cloned();
                if let Some(process) = process_cache.refresh_started(config, raw.pid as i64, ts)? {
                    let parent = process_cache.parent_entity(process.ppid);
                    let parent_process = process_cache.get(process.ppid).cloned();
                    let severity = if process
                        .exe
                        .as_deref()
                        .map(looks_executable)
                        .unwrap_or(false)
                    {
                        Severity::Medium
                    } else {
                        Severity::Info
                    };
                    result.processes.push(process.clone());
                    result.events.push(Event::new(
                        ts,
                        Some(raw.ts_ns),
                        EventSource::Ebpf,
                        EventType::ProcessStart,
                        process.entity_key.clone(),
                        parent,
                        severity,
                        fields([
                            ("pid", json!(process.pid)),
                            ("ppid", json!(process.ppid)),
                            ("exe", json!(process.exe)),
                            ("cmdline", json!(process.cmdline)),
                            ("cwd", json!(process.cwd)),
                            ("user", json!(process.user)),
                            ("execve_path", json!(read_cstr(&raw.primary))),
                            ("comm", json!(read_cstr(&raw.comm))),
                        ]),
                    ));
                    if let Some(exe) = &process.exe {
                        result.file_artifacts.push(FileArtifact {
                            entity_key: process.entity_key.clone(),
                            category: "process_executable".to_string(),
                            path: exe.clone(),
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
                            is_elf: exe.ends_with(".so")
                                || exe.contains("/bin/")
                                || exe.contains("/lib/"),
                            content_ref: None,
                            notes: process.suspicious_flags.clone(),
                            ts,
                        });
                    }
                    if let Some(event) = maybe_exec_credential_commit(
                        &process,
                        previous_process.as_ref(),
                        parent_process.as_ref(),
                        &raw,
                        ts,
                    ) {
                        result.events.push(event);
                    }
                }
            }
            EVENT_KIND_PROCESS_EXIT => {
                if let Some(process) = process_cache.mark_exit(raw.pid as i64, ts) {
                    result.processes.push(process.clone());
                    result.events.push(Event::new(
                        ts,
                        Some(raw.ts_ns),
                        EventSource::Ebpf,
                        EventType::ProcessExit,
                        process.entity_key.clone(),
                        None,
                        Severity::Info,
                        fields([
                            ("pid", json!(process.pid)),
                            ("exe", json!(process.exe)),
                            ("user", json!(process.user)),
                            ("comm", json!(read_cstr(&raw.comm))),
                        ]),
                    ));
                }
            }
            EVENT_KIND_NET_CONNECT => {
                if let Some((process, inserted)) =
                    process_cache.ensure_present(config, raw.pid as i64, ts)?
                {
                    if inserted {
                        result.processes.push(process.clone());
                    }
                    let remote_addr = format_remote_addr(&raw);
                    let observation = enrich_socket_tuple(raw.pid as i64, raw.flags, &remote_addr);
                    let connection = NetConnection {
                        entity_key: process.entity_key.clone(),
                        protocol: observation
                            .as_ref()
                            .map(|item| item.protocol.clone())
                            .unwrap_or_else(|| "connect".to_string()),
                        local_addr: observation
                            .as_ref()
                            .map(|item| item.local_addr.clone())
                            .unwrap_or_else(|| "unknown".to_string()),
                        remote_addr: observation
                            .as_ref()
                            .map(|item| item.remote_addr.clone())
                            .unwrap_or_else(|| remote_addr.clone()),
                        dns_name: None,
                        direction: common_model::Direction::Outbound,
                        state: observation.as_ref().and_then(|item| item.state.clone()),
                        net_namespace: observation
                            .as_ref()
                            .and_then(|item| item.net_namespace.clone()),
                        observation_source: observation
                            .as_ref()
                            .map(|item| item.source.to_string()),
                        socket_inode: observation.as_ref().and_then(|item| item.socket_inode),
                        ts,
                    };
                    result.net_connections.push(connection.clone());
                    result.events.push(Event::new(
                        ts,
                        Some(raw.ts_ns),
                        EventSource::Ebpf,
                        EventType::NetConnect,
                        process.entity_key.clone(),
                        None,
                        Severity::Info,
                        fields([
                            ("local_addr", json!(connection.local_addr)),
                            ("remote_addr", json!(connection.remote_addr)),
                            ("protocol", json!(connection.protocol)),
                            ("state", json!(connection.state)),
                            ("socket_fd", json!(raw.flags)),
                            ("connect_result", json!(raw.result)),
                            ("family", json!(raw.family)),
                            (
                                "socket_inode",
                                json!(observation.as_ref().and_then(|item| item.socket_inode)),
                            ),
                            (
                                "net_namespace",
                                json!(
                                    observation
                                        .as_ref()
                                        .and_then(|item| item.net_namespace.clone())
                                ),
                            ),
                            (
                                "socket_tuple_source",
                                json!(observation.as_ref().map(|item| item.source)),
                            ),
                            ("comm", json!(read_cstr(&raw.comm))),
                            ("uid", json!(raw.uid)),
                            ("gid", json!(raw.gid)),
                        ]),
                    ));
                }
            }
            EVENT_KIND_FILE_OPEN => {
                if let Some((process, inserted)) =
                    process_cache.ensure_present(config, raw.pid as i64, ts)?
                {
                    if inserted {
                        result.processes.push(process.clone());
                    }
                    let path = read_cstr(&raw.primary);
                    if path.is_empty() {
                        return Ok(());
                    }
                    let file_op = map_file_op(raw.op);
                    let sha256 =
                        sha256_file(Path::new(&path), config.collection.hash_file_limit_mb)
                            .ok()
                            .flatten();
                    let artifact = FileArtifact {
                        entity_key: process.entity_key.clone(),
                        category: "ebpf_file".to_string(),
                        path: path.clone(),
                        file_id: None,
                        op: file_op,
                        sha256: sha256.clone(),
                        size: None,
                        owner: process.user.clone(),
                        group: None,
                        mode: None,
                        mtime: None,
                        ctime: None,
                        atime: None,
                        is_hidden: Path::new(&path)
                            .file_name()
                            .map(|name| name.to_string_lossy().starts_with('.'))
                            .unwrap_or(false),
                        is_suid: false,
                        is_sgid: false,
                        is_executable: looks_executable(&path),
                        is_elf: path.ends_with(".so")
                            || path.contains("/bin/")
                            || path.contains("/lib/"),
                        content_ref: None,
                        notes: Vec::new(),
                        ts,
                    };
                    result.file_artifacts.push(artifact.clone());
                    result.events.push(Event::new(
                        ts,
                        Some(raw.ts_ns),
                        EventSource::Ebpf,
                        map_file_event(raw.op),
                        process.entity_key.clone(),
                        None,
                        if looks_executable(&path) {
                            Severity::Medium
                        } else {
                            Severity::Info
                        },
                        fields([
                            ("path", json!(path)),
                            ("flags", json!(raw.flags)),
                            ("sha256", json!(sha256)),
                            ("comm", json!(read_cstr(&raw.comm))),
                        ]),
                    ));
                    if let Some(persistence) =
                        maybe_persistence_artifact(config, &process, &path, ts)
                    {
                        result.persistence_artifacts.push(persistence.clone());
                        result.events.push(Event::new(
                            ts,
                            Some(raw.ts_ns),
                            EventSource::Ebpf,
                            EventType::PersistenceCreate,
                            persistence.entity_key.clone(),
                            None,
                            Severity::High,
                            fields([
                                ("mechanism", json!(persistence.mechanism)),
                                ("location", json!(persistence.location)),
                                ("value", json!(persistence.value)),
                            ]),
                        ));
                    }
                }
            }
            EVENT_KIND_FILE_RENAME => {
                if let Some((process, inserted)) =
                    process_cache.ensure_present(config, raw.pid as i64, ts)?
                {
                    if inserted {
                        result.processes.push(process.clone());
                    }
                    let old_path = read_cstr(&raw.primary);
                    let new_path = read_cstr(&raw.secondary);
                    if new_path.is_empty() {
                        return Ok(());
                    }
                    let sha256 =
                        sha256_file(Path::new(&new_path), config.collection.hash_file_limit_mb)
                            .ok()
                            .flatten();
                    let artifact = FileArtifact {
                        entity_key: process.entity_key.clone(),
                        category: "ebpf_file".to_string(),
                        path: new_path.clone(),
                        file_id: None,
                        op: FileOp::Rename,
                        sha256: sha256.clone(),
                        size: None,
                        owner: process.user.clone(),
                        group: None,
                        mode: None,
                        mtime: None,
                        ctime: None,
                        atime: None,
                        is_hidden: Path::new(&new_path)
                            .file_name()
                            .map(|name| name.to_string_lossy().starts_with('.'))
                            .unwrap_or(false),
                        is_suid: false,
                        is_sgid: false,
                        is_executable: looks_executable(&new_path),
                        is_elf: new_path.ends_with(".so")
                            || new_path.contains("/bin/")
                            || new_path.contains("/lib/"),
                        content_ref: None,
                        notes: Vec::new(),
                        ts,
                    };
                    result.file_artifacts.push(artifact);
                    result.events.push(Event::new(
                        ts,
                        Some(raw.ts_ns),
                        EventSource::Ebpf,
                        EventType::Rename,
                        process.entity_key.clone(),
                        None,
                        if looks_executable(&new_path) {
                            Severity::Medium
                        } else {
                            Severity::Info
                        },
                        fields([
                            ("old_path", json!(old_path)),
                            ("new_path", json!(new_path)),
                            ("sha256", json!(sha256)),
                            ("comm", json!(read_cstr(&raw.comm))),
                        ]),
                    ));
                }
            }
            EVENT_KIND_PRIVILEGE_CHANGE => {
                if let Some((previous, process, inserted)) =
                    process_cache.refresh_identity(config, raw.pid as i64, ts)?
                {
                    let previous_user = previous.as_ref().and_then(|item| item.user.clone());
                    let current_user = process.user.clone();
                    if inserted
                        || previous_user != current_user
                        || previous
                            .as_ref()
                            .map(|item| item.last_seen != process.last_seen)
                            .unwrap_or(true)
                    {
                        result.processes.push(process.clone());
                    }
                    let event = if raw.op == PRIV_OP_CAPSET {
                        let caps = decode_capability_summary(raw.aux_uid);
                        let severity = if caps.is_empty() {
                            Severity::Low
                        } else {
                            Severity::High
                        };
                        Event::new(
                            ts,
                            Some(raw.ts_ns),
                            EventSource::Ebpf,
                            EventType::PrivilegeChange,
                            process.entity_key.clone(),
                            None,
                            severity,
                            fields([
                                ("syscall", json!(privilege_operation_name(raw.op))),
                                ("target_pid", json!(raw.flags)),
                                ("capability_summary_bits", json!(raw.aux_uid)),
                                ("capability_summary", json!(caps)),
                                ("previous_user", json!(previous_user)),
                                ("current_user", json!(current_user)),
                                ("result", json!(raw.result)),
                                ("comm", json!(read_cstr(&raw.comm))),
                                ("tid", json!(raw.tid)),
                            ]),
                        )
                    } else {
                        let old_uid = raw.uid;
                        let new_uid = normalize_raw_id(raw.aux_uid);
                        let old_gid = raw.gid;
                        let new_gid = normalize_raw_id(raw.aux_gid);
                        let severity = match (
                            is_privileged_uid(old_uid),
                            new_uid.map(is_privileged_uid).unwrap_or(false),
                        ) {
                            (false, true) => Severity::High,
                            (true, false) => Severity::Medium,
                            _ => Severity::Low,
                        };
                        Event::new(
                            ts,
                            Some(raw.ts_ns),
                            EventSource::Ebpf,
                            EventType::PrivilegeChange,
                            process.entity_key.clone(),
                            None,
                            severity,
                            fields([
                                ("syscall", json!(privilege_operation_name(raw.op))),
                                ("old_uid", json!(old_uid)),
                                ("old_gid", json!(old_gid)),
                                ("new_uid", json!(new_uid)),
                                ("new_gid", json!(new_gid)),
                                ("previous_user", json!(previous_user)),
                                ("current_user", json!(current_user)),
                                ("result", json!(raw.result)),
                                ("comm", json!(read_cstr(&raw.comm))),
                                ("tid", json!(raw.tid)),
                            ]),
                        )
                    };
                    result.events.push(event);
                }
            }
            _ => {}
        }
        Ok(())
    }

    #[derive(Clone)]
    struct SocketObservation {
        protocol: String,
        local_addr: String,
        remote_addr: String,
        state: Option<String>,
        socket_inode: Option<u64>,
        net_namespace: Option<String>,
        source: &'static str,
    }

    struct SnapshotPollState {
        processes: HashMap<String, ProcessIdentity>,
        net_signatures: HashSet<String>,
    }

    impl SnapshotPollState {
        fn from_snapshot(snapshot: &SnapshotBundle) -> Self {
            Self {
                processes: snapshot
                    .processes
                    .iter()
                    .map(|process| (process.entity_key.clone(), process.clone()))
                    .collect(),
                net_signatures: snapshot.net_connections.iter().map(net_signature).collect(),
            }
        }
    }

    struct ExecSecurityProfile {
        mode: u32,
        owner_uid: u32,
        owner_gid: u32,
        setuid: bool,
        setgid: bool,
    }

    fn enrich_socket_tuple(pid: i64, fd: u32, remote_addr: &str) -> Option<SocketObservation> {
        for wait_ms in [0_u64, 10, 25, 50] {
            if wait_ms > 0 {
                thread::sleep(Duration::from_millis(wait_ms));
            }
            let process_sockets = enumerate_process_sockets(pid);
            if let Some(inode) = socket_inode_for_fd(pid, fd) {
                if let Some(observation) =
                    lookup_process_socket_by_inode(&process_sockets, inode, remote_addr)
                {
                    return Some(observation);
                }
                if let Some(observation) = lookup_host_socket_by_inode(pid, inode, remote_addr) {
                    return Some(observation);
                }
            }
            if let Some(observation) =
                lookup_process_socket_by_remote(&process_sockets, remote_addr)
            {
                return Some(observation);
            }
            if let Some(observation) = lookup_host_socket_by_remote(pid, remote_addr) {
                return Some(observation);
            }
        }
        None
    }

    fn socket_inode_for_fd(pid: i64, fd: u32) -> Option<u64> {
        let target = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
        parse_socket_inode(&target.to_string_lossy())
    }

    fn enumerate_process_sockets(pid: i64) -> Vec<ProcSocketEntry> {
        let net_namespace = read_net_namespace(pid);
        let net_namespace_ref = net_namespace.as_deref();
        let mut entries = Vec::new();
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
            entries.extend(parse_proc_net_table(
                &content,
                protocol,
                ipv6,
                net_namespace_ref,
            ));
        }
        entries
    }

    fn read_net_namespace(pid: i64) -> Option<String> {
        let target = fs::read_link(format!("/proc/{pid}/ns/net")).ok()?;
        Some(target.to_string_lossy().to_string())
    }

    fn lookup_process_socket_by_inode(
        sockets: &[ProcSocketEntry],
        inode: u64,
        fallback_remote: &str,
    ) -> Option<SocketObservation> {
        sockets
            .iter()
            .find(|socket| socket.inode == inode)
            .map(|socket| proc_socket_observation(socket, fallback_remote))
    }

    fn lookup_process_socket_by_remote(
        sockets: &[ProcSocketEntry],
        remote_addr: &str,
    ) -> Option<SocketObservation> {
        sockets
            .iter()
            .find(|socket| socket.remote_addr == remote_addr)
            .map(|socket| proc_socket_observation(socket, remote_addr))
    }

    fn lookup_host_socket_by_inode(
        pid: i64,
        inode: u64,
        fallback_remote: &str,
    ) -> Option<SocketObservation> {
        enumerate_host_sockets()
            .ok()?
            .into_iter()
            .find_map(|socket| {
                if u64::from(socket.inode) != inode
                    || !socket.associated_pids.contains(&(pid as u32))
                {
                    return None;
                }
                Some(host_socket_observation(socket, fallback_remote))
            })
    }

    fn lookup_host_socket_by_remote(pid: i64, remote_addr: &str) -> Option<SocketObservation> {
        enumerate_host_sockets()
            .ok()?
            .into_iter()
            .find_map(|socket| {
                if !socket.associated_pids.contains(&(pid as u32)) {
                    return None;
                }
                match &socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(tcp)
                        if format_socket_addr(tcp.remote_addr, tcp.remote_port) == remote_addr =>
                    {
                        Some(host_socket_observation(socket, remote_addr))
                    }
                    _ => None,
                }
            })
    }

    fn enumerate_host_sockets() -> Result<Vec<SocketInfo>> {
        get_sockets_info(
            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
            ProtocolFlags::TCP | ProtocolFlags::UDP,
        )
        .context("failed to enumerate sockets for eBPF enrichment")
    }

    fn proc_socket_observation(
        socket: &ProcSocketEntry,
        fallback_remote: &str,
    ) -> SocketObservation {
        SocketObservation {
            protocol: socket.protocol.clone(),
            local_addr: socket.local_addr.clone(),
            remote_addr: if is_unspecified_remote(&socket.remote_addr) {
                fallback_remote.to_string()
            } else {
                socket.remote_addr.clone()
            },
            state: socket.state.clone(),
            socket_inode: Some(socket.inode),
            net_namespace: socket.net_namespace.clone(),
            source: "proc_pid_net",
        }
    }

    fn host_socket_observation(socket: SocketInfo, fallback_remote: &str) -> SocketObservation {
        let inode = u64::from(socket.inode);
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => SocketObservation {
                protocol: "tcp".to_string(),
                local_addr: format_socket_addr(tcp.local_addr, tcp.local_port),
                remote_addr: format_socket_addr(tcp.remote_addr, tcp.remote_port),
                state: Some(format!("{:?}", tcp.state).to_lowercase()),
                socket_inode: Some(inode),
                net_namespace: None,
                source: "host_netstat",
            },
            ProtocolSocketInfo::Udp(udp) => SocketObservation {
                protocol: "udp".to_string(),
                local_addr: format_socket_addr(udp.local_addr, udp.local_port),
                remote_addr: fallback_remote.to_string(),
                state: None,
                socket_inode: Some(inode),
                net_namespace: None,
                source: "host_netstat",
            },
        }
    }

    fn format_socket_addr(ip: IpAddr, port: u16) -> String {
        SocketAddr::new(ip, port).to_string()
    }

    fn apply_snapshot_poll(
        current: &SnapshotBundle,
        elapsed: Duration,
        state: &mut SnapshotPollState,
        result: &mut RealtimeMonitorBundle,
    ) {
        let now = current.host.collected_at;
        let pid_lookup = current
            .processes
            .iter()
            .map(|process| (process.pid, process.entity_key.clone()))
            .collect::<HashMap<_, _>>();
        let current_processes = current
            .processes
            .iter()
            .map(|process| (process.entity_key.clone(), process.clone()))
            .collect::<HashMap<_, _>>();

        for connection in &current.net_connections {
            if state.net_signatures.insert(net_signature(connection)) {
                result.net_connections.push(connection.clone());
                result.events.push(Event::new(
                    connection.ts,
                    Some(elapsed.as_millis() as u64),
                    EventSource::NetworkPoller,
                    EventType::NetConnect,
                    connection.entity_key.clone(),
                    None,
                    Severity::Info,
                    fields([
                        ("protocol", json!(connection.protocol)),
                        ("local_addr", json!(connection.local_addr)),
                        ("remote_addr", json!(connection.remote_addr)),
                        ("state", json!(connection.state)),
                    ]),
                ));
            }
        }

        for (entity_key, process) in &current_processes {
            if state
                .processes
                .insert(entity_key.clone(), process.clone())
                .is_none()
            {
                result.processes.push(process.clone());
                result.events.push(Event::new(
                    now,
                    Some(elapsed.as_millis() as u64),
                    EventSource::ProcessPoller,
                    EventType::ProcessStart,
                    process.entity_key.clone(),
                    pid_lookup.get(&process.ppid).cloned(),
                    if process
                        .exe
                        .as_deref()
                        .map(looks_executable)
                        .unwrap_or(false)
                    {
                        Severity::Medium
                    } else {
                        Severity::Info
                    },
                    fields([
                        ("pid", json!(process.pid)),
                        ("ppid", json!(process.ppid)),
                        ("exe", json!(process.exe)),
                        ("cmdline", json!(process.cmdline)),
                        ("user", json!(process.user)),
                    ]),
                ));
            }
        }

        let current_keys = current_processes.keys().cloned().collect::<HashSet<_>>();
        let previous_keys = state.processes.keys().cloned().collect::<Vec<_>>();
        for key in previous_keys {
            if current_keys.contains(&key) {
                continue;
            }
            if let Some(mut exited) = state.processes.remove(&key) {
                exited.last_seen = now;
                exited.is_running = false;
                result.processes.push(exited.clone());
                result.events.push(Event::new(
                    now,
                    Some(elapsed.as_millis() as u64),
                    EventSource::ProcessPoller,
                    EventType::ProcessExit,
                    exited.entity_key.clone(),
                    None,
                    Severity::Info,
                    fields([
                        ("pid", json!(exited.pid)),
                        ("exe", json!(exited.exe)),
                        ("user", json!(exited.user)),
                    ]),
                ));
            }
        }

        state.processes = current_processes;
        state.net_signatures = current
            .net_connections
            .iter()
            .map(net_signature)
            .collect::<HashSet<_>>();
    }

    fn net_signature(connection: &NetConnection) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            connection.entity_key,
            connection.protocol,
            connection.local_addr,
            connection.remote_addr,
            connection.state.clone().unwrap_or_default(),
            connection.net_namespace.clone().unwrap_or_default()
        )
    }

    fn maybe_exec_credential_commit(
        process: &ProcessIdentity,
        previous: Option<&ProcessIdentity>,
        parent: Option<&ProcessIdentity>,
        raw: &TrailRawEvent,
        ts: chrono::DateTime<Utc>,
    ) -> Option<Event> {
        let exe = process.exe.as_deref()?;
        let profile = exec_security_profile(exe)?;
        let parent_name = parent.map(ProcessIdentity::display_name);
        let parent_user = parent.and_then(|item| item.user.clone());
        let previous_user = previous.and_then(|item| item.user.clone());
        let old_uid = normalize_raw_id(raw.aux_uid);
        let old_gid = normalize_raw_id(raw.aux_gid);
        let old_user = previous_user.clone().or_else(|| {
            old_uid
                .filter(|value| *value != raw.uid)
                .map(|value| value.to_string())
        });
        let current_user = process.user.clone();
        let broker_parent = parent_name
            .as_deref()
            .map(is_privilege_broker)
            .unwrap_or(false);
        let user_changed = previous_user.is_some() && previous_user != current_user;
        let uid_changed = old_uid.map(|value| value != raw.uid).unwrap_or(false);
        let gid_changed = old_gid.map(|value| value != raw.gid).unwrap_or(false);
        let privileged_child = current_user
            .as_deref()
            .map(is_privileged_username)
            .unwrap_or(false)
            || is_privileged_uid(raw.uid);
        if !(profile.setuid || profile.setgid || broker_parent || uid_changed || gid_changed) {
            return None;
        }
        if !(user_changed || privileged_child || uid_changed || gid_changed) {
            return None;
        }
        Some(Event::new(
            ts,
            Some(raw.ts_ns),
            EventSource::Ebpf,
            EventType::PrivilegeChange,
            process.entity_key.clone(),
            parent.map(|item| item.entity_key.clone()),
            if uid_changed || gid_changed || privileged_child {
                Severity::High
            } else {
                Severity::Medium
            },
            fields([
                (
                    "syscall",
                    json!(privilege_operation_name(PRIV_OP_EXEC_COMMIT)),
                ),
                ("old_user", json!(old_user)),
                ("new_user", json!(current_user)),
                ("old_uid", json!(old_uid)),
                ("old_gid", json!(old_gid)),
                ("new_uid", json!(raw.uid)),
                ("new_gid", json!(raw.gid)),
                ("parent_process", json!(parent_name)),
                ("parent_user", json!(parent_user)),
                ("via_privilege_broker", json!(broker_parent)),
                ("setuid_bit", json!(profile.setuid)),
                ("setgid_bit", json!(profile.setgid)),
                ("kernel_exec_uid_change", json!(uid_changed)),
                ("kernel_exec_gid_change", json!(gid_changed)),
                ("credential_source", json!("sched_process_exec")),
                ("file_mode", json!(format!("{:#o}", profile.mode & 0o7777))),
                ("file_owner_uid", json!(profile.owner_uid)),
                ("file_owner_gid", json!(profile.owner_gid)),
                ("exe", json!(process.exe)),
                ("execve_path", json!(read_cstr(&raw.primary))),
            ]),
        ))
    }

    fn exec_security_profile(path: &str) -> Option<ExecSecurityProfile> {
        let metadata = fs::metadata(path).ok()?;
        let mode = metadata.mode();
        Some(ExecSecurityProfile {
            mode,
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            setuid: mode & 0o4000 != 0,
            setgid: mode & 0o2000 != 0,
        })
    }

    fn is_privilege_broker(name: &str) -> bool {
        matches!(
            name.to_lowercase().as_str(),
            "sudo" | "su" | "doas" | "pkexec" | "runuser"
        )
    }

    fn is_privileged_username(user: &str) -> bool {
        matches!(
            user.to_lowercase().as_str(),
            "root" | "system" | "administrator"
        ) || user.to_lowercase().ends_with("\\administrator")
    }

    fn maybe_persistence_artifact(
        config: &AppConfig,
        process: &ProcessIdentity,
        path: &str,
        ts: chrono::DateTime<Utc>,
    ) -> Option<PersistenceArtifact> {
        let lowered = path.to_lowercase();
        if !config
            .collection
            .linux
            .persistence_paths
            .iter()
            .any(|item| {
                lowered.starts_with(&expand_path_template(item).to_string_lossy().to_lowercase())
            })
        {
            return None;
        }
        let mechanism = if lowered.contains("systemd") {
            "systemd"
        } else if lowered.contains("cron") {
            "cron"
        } else if lowered.contains("autostart") {
            "autostart"
        } else {
            "persistence_file"
        };
        Some(PersistenceArtifact {
            entity_key: process.entity_key.clone(),
            mechanism: mechanism.to_string(),
            location: path.to_string(),
            value: path.to_string(),
            ts,
        })
    }

    struct ProcessCache {
        by_pid: HashMap<i64, ProcessIdentity>,
    }

    impl ProcessCache {
        fn from_snapshot(snapshot: &SnapshotBundle) -> Self {
            Self {
                by_pid: snapshot
                    .processes
                    .iter()
                    .map(|process| (process.pid, process.clone()))
                    .collect(),
            }
        }

        fn parent_entity(&self, ppid: i64) -> Option<String> {
            self.by_pid
                .get(&ppid)
                .map(|process| process.entity_key.clone())
        }

        fn get(&self, pid: i64) -> Option<&ProcessIdentity> {
            self.by_pid.get(&pid)
        }

        fn refresh_started(
            &mut self,
            config: &AppConfig,
            pid: i64,
            ts: chrono::DateTime<Utc>,
        ) -> Result<Option<ProcessIdentity>> {
            let previous = self.by_pid.get(&pid).cloned();
            let Some(mut process) = collect_process_identity(config, pid, ts)? else {
                return Ok(None);
            };
            process.first_seen = previous
                .as_ref()
                .filter(|item| item.entity_key == process.entity_key)
                .map(|item| item.first_seen)
                .unwrap_or(ts);
            process.last_seen = ts;
            self.by_pid.insert(pid, process.clone());
            Ok(Some(process))
        }

        fn ensure_present(
            &mut self,
            config: &AppConfig,
            pid: i64,
            ts: chrono::DateTime<Utc>,
        ) -> Result<Option<(ProcessIdentity, bool)>> {
            if let Some(process) = self.by_pid.get_mut(&pid) {
                process.last_seen = ts;
                return Ok(Some((process.clone(), false)));
            }
            let Some(process) = collect_process_identity(config, pid, ts)? else {
                return Ok(None);
            };
            self.by_pid.insert(pid, process.clone());
            Ok(Some((process, true)))
        }

        fn refresh_identity(
            &mut self,
            config: &AppConfig,
            pid: i64,
            ts: chrono::DateTime<Utc>,
        ) -> Result<Option<(Option<ProcessIdentity>, ProcessIdentity, bool)>> {
            let previous = self.by_pid.get(&pid).cloned();
            let Some(mut process) =
                collect_process_identity(config, pid, ts)?.or_else(|| previous.clone())
            else {
                return Ok(None);
            };
            process.last_seen = ts;
            let inserted = previous.is_none();
            self.by_pid.insert(pid, process.clone());
            Ok(Some((previous, process, inserted)))
        }

        fn mark_exit(&mut self, pid: i64, ts: chrono::DateTime<Utc>) -> Option<ProcessIdentity> {
            let mut process = self.by_pid.remove(&pid)?;
            process.last_seen = ts;
            process.is_running = false;
            Some(process)
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::LinuxEbpfCollector;

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::{path::PathBuf, time::Duration};

    use anyhow::{Result, bail};
    use common_model::{AppConfig, HostCollector, Platform, RealtimeMonitorBundle, SnapshotBundle};

    pub struct LinuxEbpfCollector;

    impl LinuxEbpfCollector {
        pub fn is_available(&self, _config: &AppConfig) -> bool {
            false
        }

        pub fn rationale(&self) -> &'static str {
            "linux eBPF collector is only available on Linux"
        }
    }

    impl HostCollector for LinuxEbpfCollector {
        fn backend_name(&self) -> &'static str {
            "linux-ebpf"
        }

        fn platform(&self) -> Platform {
            Platform::Linux
        }

        fn collect_snapshot(&self, _config: &AppConfig) -> Result<SnapshotBundle> {
            bail!(self.rationale())
        }

        fn monitor_native(
            &self,
            _config: &AppConfig,
            _duration: Duration,
        ) -> Result<Option<RealtimeMonitorBundle>> {
            Ok(None)
        }

        fn recommended_watch_paths(&self, _config: &AppConfig) -> Vec<PathBuf> {
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use imp::LinuxEbpfCollector;

#[cfg(test)]
mod tests {
    use super::*;
    use linux_ebpf_shared::{
        CAP_SUMMARY_NET_ADMIN, CAP_SUMMARY_SYS_ADMIN, EVENT_KIND_FILE_OPEN, EVENT_KIND_FILE_RENAME,
        EVENT_KIND_NET_CONNECT, EVENT_KIND_PRIVILEGE_CHANGE, EVENT_KIND_PROCESS_EXIT,
        EVENT_KIND_PROCESS_START,
    };

    #[test]
    fn reads_c_string_until_first_null() {
        assert_eq!(read_cstr(b"/tmp/demo\0ignored"), "/tmp/demo");
        assert_eq!(read_cstr(b"  /tmp/trim  \0"), "/tmp/trim");
    }

    #[test]
    fn formats_remote_addresses() {
        let mut ipv4 = TrailRawEvent::zeroed();
        ipv4.family = ADDR_FAMILY_INET;
        ipv4.port_be = 443u16.to_be();
        ipv4.ip[..4].copy_from_slice(&[8, 8, 4, 4]);
        assert_eq!(format_remote_addr(&ipv4), "8.8.4.4:443");

        let mut ipv6 = TrailRawEvent::zeroed();
        ipv6.family = ADDR_FAMILY_INET6;
        ipv6.port_be = 53u16.to_be();
        ipv6.ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_remote_addr(&ipv6), "[2001:db8::1]:53");

        let unknown = TrailRawEvent::zeroed();
        assert_eq!(format_remote_addr(&unknown), "unknown");
    }

    #[test]
    fn maps_file_ops_and_event_types() {
        assert_eq!(map_file_op(FILE_OP_CREATE), FileOp::Create);
        assert_eq!(map_file_op(FILE_OP_WRITE), FileOp::Write);
        assert_eq!(map_file_op(FILE_OP_RENAME), FileOp::Rename);
        assert_eq!(map_file_op(255), FileOp::Observed);

        assert_eq!(map_file_event(FILE_OP_CREATE), EventType::FileCreate);
        assert_eq!(map_file_event(FILE_OP_WRITE), EventType::FileWrite);
        assert_eq!(map_file_event(FILE_OP_RENAME), EventType::Rename);
        assert_eq!(map_file_event(FILE_OP_OBSERVED), EventType::FileObserved);
        assert_eq!(map_file_event(255), EventType::FileObserved);
    }

    #[test]
    fn event_kind_constants_are_stable() {
        assert_eq!(EVENT_KIND_PROCESS_START, 1);
        assert_eq!(EVENT_KIND_PROCESS_EXIT, 2);
        assert_eq!(EVENT_KIND_NET_CONNECT, 3);
        assert_eq!(EVENT_KIND_FILE_OPEN, 4);
        assert_eq!(EVENT_KIND_FILE_RENAME, 5);
        assert_eq!(EVENT_KIND_PRIVILEGE_CHANGE, 6);
    }

    #[test]
    fn maps_privilege_ops_and_socket_inode() {
        assert_eq!(privilege_operation_name(PRIV_OP_SETUID), "setuid");
        assert_eq!(privilege_operation_name(PRIV_OP_SETRESUID), "setresuid");
        assert_eq!(privilege_operation_name(PRIV_OP_SETRESGID), "setresgid");
        assert_eq!(privilege_operation_name(PRIV_OP_CAPSET), "capset");
        assert_eq!(
            privilege_operation_name(PRIV_OP_EXEC_COMMIT),
            "exec_credential_commit"
        );
        assert_eq!(privilege_operation_name(255), "privilege_change");
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345_u64));
        assert_eq!(parse_socket_inode("anon_inode:[eventfd]"), None);
        assert_eq!(normalize_raw_id(0), Some(0));
        assert_eq!(normalize_raw_id(ID_NO_CHANGE), None);
        assert!(is_privileged_uid(0));
        assert!(!is_privileged_uid(1000));
        assert_eq!(
            decode_capability_summary(CAP_SUMMARY_SYS_ADMIN | CAP_SUMMARY_NET_ADMIN),
            vec!["cap_sys_admin", "cap_net_admin"]
        );
    }

    #[test]
    fn parses_proc_net_tcp_entries_with_namespace() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 0D08590A:1B75 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 20 4 26 10 -1\n";
        let entries = parse_proc_net_table(content, "tcp", false, Some("net:[4026534000]"));
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.local_addr, "127.0.0.1:8080");
        assert_eq!(entry.remote_addr, "10.89.8.13:7029");
        assert_eq!(entry.state.as_deref(), Some("established"));
        assert_eq!(entry.inode, 12345);
        assert_eq!(entry.net_namespace.as_deref(), Some("net:[4026534000]"));
    }

    #[test]
    fn parses_proc_net_tcp6_loopback_and_unspecified_remote() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 20 4 26 10 -1\n";
        let entries = parse_proc_net_table(content, "tcp", true, None);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.local_addr, "[::1]:8080");
        assert_eq!(entry.remote_addr, "[::]:0");
        assert_eq!(entry.state.as_deref(), Some("listen"));
        assert!(is_unspecified_remote(&entry.remote_addr));
    }
}
