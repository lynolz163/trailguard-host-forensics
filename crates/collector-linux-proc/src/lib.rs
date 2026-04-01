#[cfg(target_os = "linux")]
mod imp {
    use std::{
        collections::{BTreeSet, HashMap, HashSet},
        env,
        ffi::CString,
        fs,
        mem::MaybeUninit,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Command,
    };

    use anyhow::{Context, Result};
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use common_model::{
        AppConfig, Direction, DiskUsage, DnsConfig, EnvironmentSummary, FileArtifact, FileOp,
        FirewallRule, GroupEntry, HostCollector, HostInfo, HostsEntry, LoginRecord, MountInfo,
        NeighborEntry, NetworkInterface, OnlineUser, PersistenceArtifact, Platform,
        ProcessIdentity, RouteEntry, SnapshotBundle, UserAccount, collect_system_net_connections,
        current_hostname, expand_path_template, host_entity_key, path_to_string,
        process_entity_key, sha256_file, walk_files,
    };
    use glob::glob;
    use rayon::prelude::*;
    use serde_json::json;

    pub struct LinuxProcCollector;

    #[derive(Default)]
    struct IdentityContext {
        users_by_uid: HashMap<u32, String>,
        groups_by_gid: HashMap<u32, String>,
        accounts_by_name: HashMap<String, UserAccount>,
        groups: Vec<GroupEntry>,
    }

    impl LinuxProcCollector {
        fn collect_processes(
            &self,
            config: &AppConfig,
            identity: &IdentityContext,
            ts: DateTime<Utc>,
        ) -> Result<Vec<ProcessIdentity>> {
            let boot_time = read_boot_time()?;
            let clock_ticks = read_clock_ticks();
            let mut processes = Vec::new();

            for entry in fs::read_dir("/proc").context("failed to read /proc")? {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                let file_name = entry.file_name();
                let Ok(pid) = file_name.to_string_lossy().parse::<i64>() else {
                    continue;
                };
                if let Some(process) = collect_process_identity_with_cache(
                    config,
                    identity,
                    pid,
                    ts,
                    boot_time,
                    clock_ticks,
                )? {
                    processes.push(process);
                }
            }

            processes.sort_by_key(|process| process.start_time);
            Ok(processes)
        }

        fn collect_persistence(
            &self,
            config: &AppConfig,
            host_id: &str,
            ts: DateTime<Utc>,
        ) -> Vec<PersistenceArtifact> {
            let mut items = Vec::new();
            for template in &config.collection.linux.persistence_paths {
                let path = expand_path_template(template);
                for target in expand_targets(&path) {
                    if target.is_dir() {
                        for file in walk_files(&target) {
                            items.push(persistence_artifact(host_id, &file, ts));
                        }
                    } else if target.is_file() {
                        items.push(persistence_artifact(host_id, &target, ts));
                    }
                }
            }
            items.sort_by(|left, right| left.location.cmp(&right.location));
            items.dedup_by(|left, right| left.location == right.location);
            items
        }

        fn collect_host_info(
            &self,
            config: &AppConfig,
            identity: &IdentityContext,
            hostname: String,
            ts: DateTime<Utc>,
        ) -> HostInfo {
            HostInfo {
                host_id: host_entity_key(Platform::Linux, &hostname),
                hostname,
                platform: Platform::Linux,
                collected_at: ts,
                collector: self.backend_name().to_string(),
                kernel_version: read_first_line("/proc/sys/kernel/osrelease"),
                os_version: read_os_version(),
                boot_time: read_boot_time().ok(),
                timezone: read_timezone(),
                environment_summary: collect_environment_summary(),
                current_user: current_login_user(identity),
                interfaces: collect_interfaces(),
                mounts: collect_mounts(),
                disks: collect_disk_usage(),
                routes: collect_routes(),
                dns: collect_dns_config(),
                hosts_entries: collect_hosts_entries(),
                neighbors: collect_neighbors(),
                firewall_rules: collect_firewall_rules(),
                current_online_users: collect_online_users(identity),
                recent_logins: collect_login_records(
                    "last",
                    &["-F", "-n"],
                    config.collection.linux.max_recent_login_records,
                ),
                failed_logins: collect_login_records(
                    "lastb",
                    &["-F", "-n"],
                    config.collection.linux.max_failed_login_records,
                ),
                user_accounts: identity.accounts_by_name.values().cloned().collect(),
                groups: identity.groups.clone(),
            }
        }
    }

    pub fn collect_process_identity(
        config: &AppConfig,
        pid: i64,
        ts: DateTime<Utc>,
    ) -> Result<Option<ProcessIdentity>> {
        let identity = read_identity_context();
        collect_process_identity_with_cache(
            config,
            &identity,
            pid,
            ts,
            read_boot_time()?,
            read_clock_ticks(),
        )
    }

    fn collect_process_identity_with_cache(
        config: &AppConfig,
        identity: &IdentityContext,
        pid: i64,
        ts: DateTime<Utc>,
        boot_time: DateTime<Utc>,
        clock_ticks: i64,
    ) -> Result<Option<ProcessIdentity>> {
        let proc_root = PathBuf::from(format!("/proc/{pid}"));
        if !proc_root.exists() {
            return Ok(None);
        }
        let (ppid, start_ticks) = match read_proc_stat(&proc_root) {
            Ok(stat) => stat,
            Err(_) => return Ok(None),
        };
        let start_ts = boot_time
            + chrono::Duration::milliseconds(
                ((start_ticks as f64 / clock_ticks as f64) * 1000.0) as i64,
            );
        let entity_key = process_entity_key(Platform::Linux, pid, start_ts);
        let exe = fs::read_link(proc_root.join("exe"))
            .ok()
            .map(|path| path_to_string(&path));
        let cwd = fs::read_link(proc_root.join("cwd"))
            .ok()
            .map(|path| path_to_string(&path));
        let cmdline = read_cmdline(&proc_root).unwrap_or_default();
        let user = read_uid(&proc_root).and_then(|uid| identity.users_by_uid.get(&uid).cloned());
        let hash_sha256 = exe
            .as_deref()
            .map(Path::new)
            .map(|path| sha256_file(path, config.collection.hash_file_limit_mb))
            .transpose()?
            .flatten();
        let fd_count =
            count_entries(&proc_root.join("fd")).and_then(|value| u32::try_from(value).ok());
        let (mapped_modules, deleted_paths) = read_mapped_modules(
            &proc_root,
            config.collection.linux.max_mapped_modules_per_process,
        );
        let suspicious_flags = basic_process_flags(
            config,
            exe.as_deref(),
            cwd.as_deref(),
            &cmdline,
            &deleted_paths,
        );

        Ok(Some(ProcessIdentity {
            entity_key,
            pid,
            ppid,
            start_time: start_ts,
            exe,
            cmdline,
            cwd,
            user,
            hash_sha256,
            signer: None,
            fd_count,
            mapped_modules,
            deleted_paths,
            suspicious_flags,
            first_seen: ts,
            last_seen: ts,
            is_running: true,
        }))
    }

    impl HostCollector for LinuxProcCollector {
        fn backend_name(&self) -> &'static str {
            "linux-proc"
        }

        fn platform(&self) -> Platform {
            Platform::Linux
        }

        fn collect_snapshot(&self, config: &AppConfig) -> Result<SnapshotBundle> {
            let ts = Utc::now();
            let hostname = current_hostname();
            let identity = read_identity_context();
            let mut host = self.collect_host_info(config, &identity, hostname, ts);
            let mut processes = self.collect_processes(config, &identity, ts)?;
            let process_map = processes
                .iter()
                .map(|process| (process.pid, process.entity_key.clone()))
                .collect::<HashMap<_, _>>();
            let net_connections = collect_system_net_connections(&process_map, ts)?;
            mark_network_suspicious_processes(&mut processes, &net_connections);
            let persistence_artifacts = self.collect_persistence(config, &host.host_id, ts);

            let mut file_artifacts =
                collect_process_file_artifacts(config, &processes, ts, &identity);
            file_artifacts.extend(collect_targeted_file_artifacts(
                config,
                &host.host_id,
                &identity,
                ts,
            ));
            file_artifacts.extend(collect_command_log_artifacts(config, &host.host_id, ts));
            file_artifacts.extend(
                persistence_artifacts
                    .iter()
                    .filter(|artifact| Path::new(&artifact.location).is_file())
                    .map(|artifact| {
                        build_file_artifact(
                            &artifact.entity_key,
                            "persistence",
                            Path::new(&artifact.location),
                            FileOp::Observed,
                            config.collection.hash_file_limit_mb,
                            ts,
                            &identity.users_by_uid,
                            &identity.groups_by_gid,
                        )
                    }),
            );
            file_artifacts.sort_by(|left, right| {
                left.category
                    .cmp(&right.category)
                    .then_with(|| left.path.cmp(&right.path))
                    .then_with(|| left.ts.cmp(&right.ts))
            });
            file_artifacts
                .dedup_by(|left, right| left.category == right.category && left.path == right.path);

            host.user_accounts
                .sort_by(|left, right| left.uid.cmp(&right.uid));
            host.groups.sort_by(|left, right| left.gid.cmp(&right.gid));

            Ok(SnapshotBundle {
                host,
                processes,
                net_connections,
                file_artifacts,
                persistence_artifacts,
            })
        }

        fn recommended_watch_paths(&self, config: &AppConfig) -> Vec<PathBuf> {
            let mut paths = Vec::new();
            for template in config
                .collection
                .linux
                .risk_dirs
                .iter()
                .chain(config.collection.linux.persistence_paths.iter())
                .chain(config.collection.linux.high_risk_scan_paths.iter())
                .chain(config.collection.file_watch_paths.iter())
            {
                let candidate = expand_path_template(template);
                paths.extend(expand_targets(&candidate));
            }
            paths.retain(|path| path.exists() && path.is_dir());
            paths.sort();
            paths.dedup();
            paths
        }

        fn realtime_notes(&self) -> Vec<String> {
            vec![
                "process/network realtime uses snapshot diff polling when native eBPF is unavailable"
                    .to_string(),
                "file realtime uses native filesystem notifications".to_string(),
                "native Linux eBPF monitoring is selected automatically on supported hosts"
                    .to_string(),
                "snapshot now captures host baseline, account files, high-risk files, and login traces"
                    .to_string(),
            ]
        }
    }

    fn current_login_user(identity: &IdentityContext) -> Option<String> {
        let euid = unsafe { libc::geteuid() };
        identity
            .users_by_uid
            .get(&euid)
            .cloned()
            .or_else(|| env::var("USER").ok())
    }

    fn collect_process_file_artifacts(
        config: &AppConfig,
        processes: &[ProcessIdentity],
        ts: DateTime<Utc>,
        identity: &IdentityContext,
    ) -> Vec<FileArtifact> {
        let mut files = processes
            .par_iter()
            .map(|process| {
                let mut process_files = Vec::new();
                if let Some(exe) = &process.exe {
                    let path = Path::new(exe);
                    if path.is_file() {
                        let mut artifact = build_file_artifact(
                            &process.entity_key,
                            "process_executable",
                            path,
                            FileOp::Observed,
                            config.collection.hash_file_limit_mb,
                            ts,
                            &identity.users_by_uid,
                            &identity.groups_by_gid,
                        );
                        artifact.notes.extend(process.suspicious_flags.clone());
                        process_files.push(artifact);
                    }
                }
                for deleted in &process.deleted_paths {
                    let mut artifact = FileArtifact {
                        entity_key: process.entity_key.clone(),
                        category: "deleted_mapping".to_string(),
                        path: deleted.clone(),
                        file_id: None,
                        op: FileOp::Observed,
                        sha256: None,
                        size: None,
                        owner: None,
                        group: None,
                        mode: None,
                        mtime: None,
                        ctime: None,
                        atime: None,
                        is_hidden: false,
                        is_suid: false,
                        is_sgid: false,
                        is_executable: true,
                        is_elf: deleted.to_lowercase().ends_with(".so")
                            || deleted.to_lowercase().contains("/lib")
                            || deleted.to_lowercase().contains("/bin/"),
                        content_ref: None,
                        notes: vec!["process still maps deleted file".to_string()],
                        ts,
                    };
                    if process.exe.as_deref() == Some(deleted.as_str()) {
                        artifact
                            .notes
                            .push("deleted executable still in use".to_string());
                    }
                    process_files.push(artifact);
                }
                process_files
            })
            .reduce(Vec::new, |mut left, mut right| {
                left.append(&mut right);
                left
            });
        files.sort_by(|left, right| {
            left.category
                .cmp(&right.category)
                .then_with(|| left.path.cmp(&right.path))
                .then_with(|| left.entity_key.cmp(&right.entity_key))
        });
        files
    }

    fn collect_targeted_file_artifacts(
        config: &AppConfig,
        host_id: &str,
        identity: &IdentityContext,
        ts: DateTime<Utc>,
    ) -> Vec<FileArtifact> {
        let mut artifacts = Vec::new();
        let mut seen = HashSet::new();

        for (category, templates, recursive, limit) in [
            (
                "auth_file",
                config.collection.linux.auth_paths.as_slice(),
                true,
                usize::MAX,
            ),
            (
                "log_file",
                config.collection.linux.log_paths.as_slice(),
                false,
                usize::MAX,
            ),
            (
                "app_log_file",
                config.collection.linux.app_log_paths.as_slice(),
                false,
                usize::MAX,
            ),
            (
                "risk_scan",
                config.collection.linux.high_risk_scan_paths.as_slice(),
                true,
                config.collection.linux.max_risk_scan_files,
            ),
        ] {
            let mut emitted = 0usize;
            let mut category_candidates = Vec::new();
            for template in templates {
                let path = expand_path_template(template);
                for target in expand_targets(&path) {
                    let mut candidates = Vec::new();
                    if target.is_dir() {
                        if recursive {
                            candidates.extend(walk_files(&target));
                        }
                    } else if target.is_file() {
                        candidates.push(target.clone());
                    }
                    for candidate in candidates {
                        if limit != usize::MAX && emitted >= limit {
                            break;
                        }
                        let key = format!("{category}:{}", candidate.display());
                        if !seen.insert(key) {
                            continue;
                        }
                        category_candidates.push(candidate);
                        emitted += 1;
                    }
                }
            }
            let mut built = category_candidates
                .into_par_iter()
                .map(|candidate| {
                    build_targeted_file_artifact(
                        category, host_id, &candidate, config, identity, ts,
                    )
                })
                .collect::<Vec<_>>();
            artifacts.append(&mut built);
        }

        artifacts
    }

    fn collect_command_log_artifacts(
        config: &AppConfig,
        host_id: &str,
        ts: DateTime<Utc>,
    ) -> Vec<FileArtifact> {
        let mut artifacts = Vec::new();
        for collector in &config.collection.linux.command_log_collectors {
            match collector.as_str() {
                "journalctl" if command_in_path("journalctl").is_some() => {
                    artifacts.push(FileArtifact {
                        entity_key: host_id.to_string(),
                        category: "command_log".to_string(),
                        path: "command:journalctl".to_string(),
                        file_id: None,
                        op: FileOp::Observed,
                        sha256: None,
                        size: None,
                        owner: None,
                        group: None,
                        mode: None,
                        mtime: None,
                        ctime: None,
                        atime: None,
                        is_hidden: false,
                        is_suid: false,
                        is_sgid: false,
                        is_executable: false,
                        is_elf: false,
                        content_ref: None,
                        notes: vec![format!(
                            "capture_command:journalctl --no-pager -o short-iso -n {}",
                            config.collection.log_tail_lines
                        )],
                        ts,
                    })
                }
                "dmesg" if command_in_path("dmesg").is_some() => artifacts.push(FileArtifact {
                    entity_key: host_id.to_string(),
                    category: "command_log".to_string(),
                    path: "command:dmesg".to_string(),
                    file_id: None,
                    op: FileOp::Observed,
                    sha256: None,
                    size: None,
                    owner: None,
                    group: None,
                    mode: None,
                    mtime: None,
                    ctime: None,
                    atime: None,
                    is_hidden: false,
                    is_suid: false,
                    is_sgid: false,
                    is_executable: false,
                    is_elf: false,
                    content_ref: None,
                    notes: vec!["capture_command:dmesg --ctime --color=never".to_string()],
                    ts,
                }),
                _ => {}
            }
        }
        artifacts
    }

    fn build_targeted_file_artifact(
        category: &str,
        host_id: &str,
        path: &Path,
        config: &AppConfig,
        identity: &IdentityContext,
        ts: DateTime<Utc>,
    ) -> FileArtifact {
        let mut artifact = build_file_artifact(
            host_id,
            category,
            path,
            FileOp::Observed,
            config.collection.hash_file_limit_mb,
            ts,
            &identity.users_by_uid,
            &identity.groups_by_gid,
        );
        let lower = artifact.path.to_lowercase();
        if lower.ends_with("/shadow") || lower == "/etc/shadow" {
            artifact.notes.push("sensitive_shadow_file".to_string());
        }
        if artifact.is_hidden {
            artifact.notes.push("hidden_file".to_string());
        }
        if artifact.is_suid {
            artifact.notes.push("suid".to_string());
        }
        if artifact.is_sgid {
            artifact.notes.push("sgid".to_string());
        }
        if is_recent_file(path, config.collection.linux.recent_file_window_hours) {
            artifact.notes.push("recently_modified".to_string());
        }
        if is_web_script(path, &config.collection.linux.web_root_paths) {
            artifact.notes.push("web_script".to_string());
        }
        artifact
    }

    fn build_file_artifact(
        entity_key: &str,
        category: &str,
        path: &Path,
        op: FileOp,
        hash_limit_mb: u64,
        ts: DateTime<Utc>,
        users_by_uid: &HashMap<u32, String>,
        groups_by_gid: &HashMap<u32, String>,
    ) -> FileArtifact {
        let metadata = fs::symlink_metadata(path).ok();
        let mode_bits = metadata
            .as_ref()
            .map(|meta| meta.permissions().mode())
            .unwrap_or_default();
        let uid = metadata.as_ref().map(MetadataExt::uid);
        let gid = metadata.as_ref().map(MetadataExt::gid);
        FileArtifact {
            entity_key: entity_key.to_string(),
            category: category.to_string(),
            path: path_to_string(path),
            file_id: metadata
                .as_ref()
                .map(|meta| format!("{}:{}", meta.dev(), meta.ino())),
            op,
            sha256: sha256_file(path, hash_limit_mb).ok().flatten(),
            size: metadata.as_ref().map(MetadataExt::size),
            owner: uid.and_then(|value| users_by_uid.get(&value).cloned()),
            group: gid.and_then(|value| groups_by_gid.get(&value).cloned()),
            mode: metadata
                .as_ref()
                .map(|_| format!("{mode_bits:04o}", mode_bits = mode_bits & 0o7777)),
            mtime: metadata
                .as_ref()
                .and_then(|meta| utc_from_epoch(meta.mtime(), meta.mtime_nsec())),
            ctime: metadata
                .as_ref()
                .and_then(|meta| utc_from_epoch(meta.ctime(), meta.ctime_nsec())),
            atime: metadata
                .as_ref()
                .and_then(|meta| utc_from_epoch(meta.atime(), meta.atime_nsec())),
            is_hidden: path
                .file_name()
                .map(|name| name.to_string_lossy().starts_with('.'))
                .unwrap_or(false),
            is_suid: mode_bits & 0o4000 != 0,
            is_sgid: mode_bits & 0o2000 != 0,
            is_executable: mode_bits & 0o111 != 0,
            is_elf: is_elf(path),
            content_ref: None,
            notes: Vec::new(),
            ts,
        }
    }

    fn read_identity_context() -> IdentityContext {
        let groups = read_groups();
        let users = read_users();
        let shadow = read_shadow_password_state();
        let mut accounts_by_name = HashMap::new();
        let mut users_by_uid = HashMap::new();
        for mut user in users {
            users_by_uid.insert(user.uid, user.username.clone());
            if let Some(password_state) = shadow.get(&user.username).cloned() {
                user.password_state = Some(password_state);
            }
            accounts_by_name.insert(user.username.clone(), user);
        }
        let groups_by_gid = groups
            .iter()
            .map(|group| (group.gid, group.name.clone()))
            .collect::<HashMap<_, _>>();
        IdentityContext {
            users_by_uid,
            groups_by_gid,
            accounts_by_name,
            groups,
        }
    }

    fn collect_environment_summary() -> EnvironmentSummary {
        let mut highlights = common_model::FieldMap::new();
        let keys = [
            "LANG",
            "PATH",
            "SHELL",
            "HOME",
            "USER",
            "LOGNAME",
            "TZ",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
        ];
        let vars = env::vars().collect::<HashMap<_, _>>();
        for key in keys {
            if let Some(value) = vars.get(key) {
                let summarized =
                    if matches!(key, "PATH" | "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY") {
                        summarize_env_value(value)
                    } else {
                        value.clone()
                    };
                highlights.insert(key.to_string(), json!(summarized));
            }
        }
        EnvironmentSummary {
            total_vars: vars.len(),
            highlights,
        }
    }

    fn summarize_env_value(value: &str) -> String {
        const MAX_CHARS: usize = 240;
        if value.len() <= MAX_CHARS {
            value.to_string()
        } else {
            format!("{}...", &value[..MAX_CHARS])
        }
    }

    fn collect_interfaces() -> Vec<NetworkInterface> {
        let mut interfaces = Vec::new();
        let mut address_map = collect_interface_addresses();
        let Ok(entries) = fs::read_dir("/sys/class/net") else {
            return interfaces;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let base = entry.path();
            interfaces.push(NetworkInterface {
                name: name.clone(),
                mac_address: read_first_line(base.join("address")),
                oper_state: read_first_line(base.join("operstate")),
                mtu: read_first_line(base.join("mtu")).and_then(|value| value.parse::<u64>().ok()),
                addresses: address_map.remove(&name).unwrap_or_default(),
            });
        }
        interfaces.sort_by(|left, right| left.name.cmp(&right.name));
        interfaces
    }

    fn collect_interface_addresses() -> HashMap<String, Vec<String>> {
        let Some(output) = run_command_if_present("ip", &["-o", "addr", "show"]) else {
            return HashMap::new();
        };
        let mut map = HashMap::<String, Vec<String>>::new();
        for line in output.lines() {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 4 {
                continue;
            }
            let name = parts[1].trim_end_matches(':').to_string();
            if matches!(parts[2], "inet" | "inet6") {
                map.entry(name).or_default().push(parts[3].to_string());
            }
        }
        for values in map.values_mut() {
            values.sort();
            values.dedup();
        }
        map
    }

    fn collect_mounts() -> Vec<MountInfo> {
        let mut mounts = Vec::new();
        let Ok(content) = fs::read_to_string("/proc/mounts") else {
            return mounts;
        };
        for line in content.lines() {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 4 {
                continue;
            }
            mounts.push(MountInfo {
                source: parts[0].to_string(),
                target: parts[1].to_string(),
                fstype: parts[2].to_string(),
                options: parts[3].split(',').map(str::to_string).collect(),
            });
        }
        mounts
    }

    fn collect_disk_usage() -> Vec<DiskUsage> {
        let mut disks = Vec::new();
        for mount in collect_mounts() {
            if let Some(usage) = statvfs_usage(&mount.target) {
                disks.push(DiskUsage {
                    mount_point: mount.target,
                    total_bytes: usage.0,
                    used_bytes: usage.1,
                    available_bytes: usage.2,
                });
            }
        }
        disks.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
        disks.dedup_by(|left, right| left.mount_point == right.mount_point);
        disks
    }

    fn statvfs_usage(path: &str) -> Option<(u64, u64, u64)> {
        let c_path = CString::new(path).ok()?;
        let mut buf = MaybeUninit::<libc::statvfs>::zeroed();
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), buf.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        let buf = unsafe { buf.assume_init() };
        let block_size = if buf.f_frsize > 0 {
            buf.f_frsize
        } else {
            buf.f_bsize
        };
        let total = block_size.saturating_mul(buf.f_blocks);
        let available = block_size.saturating_mul(buf.f_bavail);
        let free = block_size.saturating_mul(buf.f_bfree);
        let used = total.saturating_sub(free);
        Some((total, used, available))
    }

    fn collect_routes() -> Vec<RouteEntry> {
        let mut routes = Vec::new();
        let Ok(content) = fs::read_to_string("/proc/net/route") else {
            return routes;
        };
        for line in content.lines().skip(1) {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 8 {
                continue;
            }
            routes.push(RouteEntry {
                interface: parts[0].to_string(),
                destination: decode_route_hex(parts[1]),
                gateway: decode_route_hex(parts[2]),
                flags: decode_route_flags(parts[3]),
                source: "/proc/net/route".to_string(),
            });
        }
        routes
    }

    fn decode_route_hex(raw: &str) -> String {
        if raw.len() != 8 {
            return raw.to_string();
        }
        let mut octets = [0_u8; 4];
        for index in 0..4 {
            let start = index * 2;
            octets[index] = u8::from_str_radix(&raw[start..start + 2], 16).unwrap_or_default();
        }
        octets.reverse();
        format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    }

    fn decode_route_flags(raw: &str) -> Vec<String> {
        let value = u32::from_str_radix(raw, 16).unwrap_or_default();
        let mut flags = Vec::new();
        if value & 0x1 != 0 {
            flags.push("up".to_string());
        }
        if value & 0x2 != 0 {
            flags.push("gateway".to_string());
        }
        if value & 0x4 != 0 {
            flags.push("host".to_string());
        }
        if value & 0x10 != 0 {
            flags.push("dynamic".to_string());
        }
        if flags.is_empty() {
            flags.push(format!("0x{value:x}"));
        }
        flags
    }

    fn collect_dns_config() -> DnsConfig {
        let mut config = DnsConfig::default();
        let path = Path::new("/etc/resolv.conf");
        if path.exists() {
            config.raw_ref = Some(path_to_string(path));
        }
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }
                if let Some(rest) = trimmed.strip_prefix("nameserver ") {
                    config.nameservers.push(rest.trim().to_string());
                } else if let Some(rest) = trimmed.strip_prefix("search ") {
                    config
                        .search
                        .extend(rest.split_whitespace().map(str::to_string));
                }
            }
        }
        config
    }

    fn collect_hosts_entries() -> Vec<HostsEntry> {
        let mut rows = Vec::new();
        if let Ok(content) = fs::read_to_string("/etc/hosts") {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let parts = trimmed.split_whitespace().collect::<Vec<_>>();
                if parts.len() >= 2 {
                    rows.push(HostsEntry {
                        address: parts[0].to_string(),
                        names: parts[1..].iter().map(|item| item.to_string()).collect(),
                    });
                }
            }
        }
        rows
    }

    fn collect_neighbors() -> Vec<NeighborEntry> {
        let mut rows = Vec::new();
        if let Ok(content) = fs::read_to_string("/proc/net/arp") {
            for line in content.lines().skip(1) {
                let parts = line.split_whitespace().collect::<Vec<_>>();
                if parts.len() >= 6 {
                    rows.push(NeighborEntry {
                        address: parts[0].to_string(),
                        hw_address: Some(parts[3].to_string()),
                        interface: Some(parts[5].to_string()),
                        state: Some(parts[2].to_string()),
                        source: "/proc/net/arp".to_string(),
                    });
                }
            }
        }
        if rows.is_empty() {
            if let Some(output) = run_command_if_present("ip", &["neigh", "show"]) {
                for line in output.lines() {
                    let parts = line.split_whitespace().collect::<Vec<_>>();
                    if parts.len() >= 3 {
                        rows.push(NeighborEntry {
                            address: parts[0].to_string(),
                            hw_address: parts
                                .iter()
                                .position(|item| *item == "lladdr")
                                .and_then(|index| parts.get(index + 1))
                                .map(|value| value.to_string()),
                            interface: parts
                                .iter()
                                .position(|item| *item == "dev")
                                .and_then(|index| parts.get(index + 1))
                                .map(|value| value.to_string()),
                            state: parts.last().map(|value| value.to_string()),
                            source: "ip neigh".to_string(),
                        });
                    }
                }
            }
        }
        rows
    }

    fn collect_firewall_rules() -> Vec<FirewallRule> {
        let mut rules = Vec::new();
        if let Some(output) = run_command_if_present("nft", &["list", "ruleset"]) {
            rules.push(FirewallRule {
                backend: "nft".to_string(),
                summary: summarize_multiline(&output, 6, 480),
                raw_ref: Some("nft list ruleset".to_string()),
            });
        }
        if let Some(output) = run_command_if_present("iptables-save", &[]) {
            rules.push(FirewallRule {
                backend: "iptables".to_string(),
                summary: summarize_multiline(&output, 6, 480),
                raw_ref: Some("iptables-save".to_string()),
            });
        } else if let Some(output) = run_command_if_present("iptables", &["-S"]) {
            rules.push(FirewallRule {
                backend: "iptables".to_string(),
                summary: summarize_multiline(&output, 6, 480),
                raw_ref: Some("iptables -S".to_string()),
            });
        }
        rules
    }

    fn summarize_multiline(content: &str, max_lines: usize, max_chars: usize) -> String {
        let mut lines = content
            .lines()
            .take(max_lines)
            .collect::<Vec<_>>()
            .join(" | ");
        if lines.len() > max_chars {
            lines.truncate(max_chars);
            lines.push_str("...");
        }
        lines
    }

    fn collect_online_users(identity: &IdentityContext) -> Vec<OnlineUser> {
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return rows;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(pid) = name.parse::<i64>() else {
                continue;
            };
            let proc_root = PathBuf::from(format!("/proc/{pid}"));
            let tty = fs::read_link(proc_root.join("fd/0"))
                .ok()
                .map(|path| path_to_string(&path))
                .filter(|value| value.starts_with("/dev/") && value != "/dev/null");
            let Some(tty) = tty else {
                continue;
            };
            let Some(uid) = read_uid(&proc_root) else {
                continue;
            };
            let Some(user) = identity.users_by_uid.get(&uid).cloned() else {
                continue;
            };
            let key = format!("{user}:{tty}");
            if seen.insert(key) {
                rows.push(OnlineUser {
                    user,
                    tty: Some(tty),
                    source: "/proc/<pid>/fd/0".to_string(),
                });
            }
        }
        rows
    }

    fn collect_login_records(
        command: &str,
        prefix_args: &[&str],
        limit: usize,
    ) -> Vec<LoginRecord> {
        let limit_str = limit.to_string();
        let mut args = prefix_args.to_vec();
        args.push(&limit_str);
        args.push("-w");
        let mut iso_args = args.clone();
        iso_args.push("--time-format");
        iso_args.push("iso");

        let output = run_command_if_present(command, &iso_args)
            .or_else(|| run_command_if_present(command, &args));
        let Some(output) = output else {
            return Vec::new();
        };
        parse_last_output(command, &output)
    }

    fn parse_last_output(source: &str, content: &str) -> Vec<LoginRecord> {
        let mut rows = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("wtmp begins")
                || trimmed.starts_with("btmp begins")
                || trimmed.starts_with("reboot ")
            {
                continue;
            }
            let parts = trimmed.split_whitespace().collect::<Vec<_>>();
            rows.push(LoginRecord {
                user: parts.first().map(|value| value.to_string()),
                terminal: parts.get(1).map(|value| value.to_string()),
                host: parts.get(2).map(|value| value.to_string()),
                login_time: extract_login_time(trimmed),
                logout_time: extract_logout_time(trimmed),
                status: Some(trimmed.to_string()),
                source: source.to_string(),
            });
        }
        rows
    }

    fn run_command_if_present(command: &str, args: &[&str]) -> Option<String> {
        let path = command_in_path(command)?;
        let output = Command::new(path).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (!text.is_empty()).then_some(text)
    }

    fn command_in_path(command: &str) -> Option<PathBuf> {
        let path = env::var_os("PATH")?;
        env::split_paths(&path)
            .map(|entry| entry.join(command))
            .find(|candidate| candidate.is_file())
    }

    fn extract_login_time(line: &str) -> Option<DateTime<Utc>> {
        line.split_whitespace()
            .find_map(parse_login_timestamp_token)
    }

    fn extract_logout_time(line: &str) -> Option<String> {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let start = tokens
            .iter()
            .position(|token| parse_login_timestamp_token(token).is_some())?;
        let after = tokens.get(start + 1)?;
        if *after == "-" {
            tokens.get(start + 2).map(|value| value.to_string())
        } else {
            None
        }
    }

    fn parse_login_timestamp_token(token: &str) -> Option<DateTime<Utc>> {
        if !(token.contains('T') && token.contains('-') && token.contains(':')) {
            return None;
        }
        let normalized = normalize_timezone_offset(token);
        DateTime::parse_from_rfc3339(&normalized)
            .ok()
            .map(|value| value.with_timezone(&Utc))
    }

    fn normalize_timezone_offset(token: &str) -> String {
        if token.len() >= 5 {
            let split_at = token.len() - 5;
            let (prefix, suffix) = token.split_at(split_at);
            if (suffix.starts_with('+') || suffix.starts_with('-'))
                && suffix.chars().skip(1).all(|char| char.is_ascii_digit())
            {
                return format!("{}{}:{}", prefix, &suffix[..3], &suffix[3..]);
            }
        }
        token.to_string()
    }

    fn read_users() -> Vec<UserAccount> {
        let mut users = Vec::new();
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts = line.split(':').collect::<Vec<_>>();
                if parts.len() >= 7 {
                    if let (Ok(uid), Ok(gid)) = (parts[2].parse::<u32>(), parts[3].parse::<u32>()) {
                        users.push(UserAccount {
                            username: parts[0].to_string(),
                            uid,
                            gid,
                            home: Some(parts[5].to_string()),
                            shell: Some(parts[6].to_string()),
                            password_state: None,
                        });
                    }
                }
            }
        }
        users
    }

    fn read_shadow_password_state() -> HashMap<String, String> {
        let mut shadow = HashMap::new();
        if let Ok(content) = fs::read_to_string("/etc/shadow") {
            for line in content.lines() {
                let parts = line.split(':').collect::<Vec<_>>();
                if parts.len() >= 2 {
                    let state = match parts[1] {
                        "" => "empty",
                        value if value.starts_with('!') || value.starts_with('*') => "locked",
                        _ => "hash_present",
                    };
                    shadow.insert(parts[0].to_string(), state.to_string());
                }
            }
        }
        shadow
    }

    fn read_groups() -> Vec<GroupEntry> {
        let mut groups = Vec::new();
        if let Ok(content) = fs::read_to_string("/etc/group") {
            for line in content.lines() {
                let parts = line.split(':').collect::<Vec<_>>();
                if parts.len() >= 4 {
                    if let Ok(gid) = parts[2].parse::<u32>() {
                        groups.push(GroupEntry {
                            name: parts[0].to_string(),
                            gid,
                            members: parts[3]
                                .split(',')
                                .filter(|item| !item.is_empty())
                                .map(str::to_string)
                                .collect(),
                        });
                    }
                }
            }
        }
        groups
    }

    fn read_clock_ticks() -> i64 {
        unsafe { libc::sysconf(libc::_SC_CLK_TCK) as i64 }
    }

    fn read_boot_time() -> Result<DateTime<Utc>> {
        let content = fs::read_to_string("/proc/stat").context("failed to read /proc/stat")?;
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("btime ") {
                let epoch = value
                    .trim()
                    .parse::<i64>()
                    .context("invalid btime in /proc/stat")?;
                return Utc
                    .timestamp_opt(epoch, 0)
                    .single()
                    .context("invalid boot timestamp");
            }
        }
        anyhow::bail!("missing btime in /proc/stat")
    }

    fn read_os_version() -> Option<String> {
        let content = fs::read_to_string("/etc/os-release").ok()?;
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                return Some(value.trim_matches('"').to_string());
            }
        }
        None
    }

    fn read_timezone() -> Option<String> {
        read_first_line("/etc/timezone").or_else(|| {
            fs::read_link("/etc/localtime")
                .ok()
                .map(|path| path_to_string(&path))
                .and_then(|value| value.split("/zoneinfo/").nth(1).map(str::to_string))
        })
    }

    fn read_first_line(path: impl AsRef<Path>) -> Option<String> {
        fs::read_to_string(path)
            .ok()
            .and_then(|content| content.lines().next().map(|line| line.trim().to_string()))
            .filter(|value| !value.is_empty())
    }

    fn read_proc_stat(proc_root: &Path) -> Result<(i64, i64)> {
        let raw = fs::read_to_string(proc_root.join("stat"))
            .with_context(|| format!("failed to read {}", proc_root.join("stat").display()))?;
        let close = raw
            .rfind(')')
            .context("malformed /proc stat line: missing comm terminator")?;
        let tail = raw
            .get(close + 2..)
            .context("malformed /proc stat line: missing fields")?;
        let parts = tail.split_whitespace().collect::<Vec<_>>();
        let ppid = parts
            .get(1)
            .context("missing ppid field")?
            .parse::<i64>()
            .context("invalid ppid field")?;
        let start_ticks = parts
            .get(19)
            .context("missing starttime field")?
            .parse::<i64>()
            .context("invalid starttime field")?;
        Ok((ppid, start_ticks))
    }

    fn read_cmdline(proc_root: &Path) -> Result<Vec<String>> {
        let raw = fs::read(proc_root.join("cmdline"))?;
        let values = raw
            .split(|byte| *byte == 0)
            .filter(|segment| !segment.is_empty())
            .map(|segment| String::from_utf8_lossy(segment).into_owned())
            .collect::<Vec<_>>();
        Ok(values)
    }

    fn read_uid(proc_root: &Path) -> Option<u32> {
        let content = fs::read_to_string(proc_root.join("status")).ok()?;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                return rest.split_whitespace().next()?.parse::<u32>().ok();
            }
        }
        None
    }

    fn count_entries(path: &Path) -> Option<usize> {
        fs::read_dir(path).ok().map(|items| items.flatten().count())
    }

    fn read_mapped_modules(proc_root: &Path, limit: usize) -> (Vec<String>, Vec<String>) {
        let mut modules = Vec::new();
        let mut deleted = Vec::new();
        let Ok(content) = fs::read_to_string(proc_root.join("maps")) else {
            return (modules, deleted);
        };
        let mut seen = HashSet::new();
        let mut deleted_seen = HashSet::new();
        for line in content.lines() {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 6 || !parts[1].contains('x') {
                continue;
            }
            let path = parts[5..].join(" ");
            if path.starts_with('[') || path.is_empty() {
                continue;
            }
            if path.contains(" (deleted)") && deleted_seen.insert(path.clone()) {
                deleted.push(path.clone());
            }
            if seen.insert(path.clone()) {
                modules.push(path);
                if modules.len() >= limit {
                    break;
                }
            }
        }
        (modules, deleted)
    }

    fn basic_process_flags(
        config: &AppConfig,
        exe: Option<&str>,
        cwd: Option<&str>,
        cmdline: &[String],
        deleted_paths: &[String],
    ) -> Vec<String> {
        let mut flags = Vec::new();
        if let Some(path) = exe {
            if is_in_risk_dir(&config.collection.linux.risk_dirs, path) {
                flags.push("exe_in_risk_dir".to_string());
            }
            if looks_masqueraded_system_name(path)
                && !is_in_risk_dir(&config.collection.linux.trusted_system_dirs, path)
            {
                flags.push("masquerade_like_system_process".to_string());
            }
        }
        if let Some(path) = cwd {
            if is_in_risk_dir(&config.collection.linux.risk_dirs, path) {
                flags.push("cwd_in_risk_dir".to_string());
            }
        }
        if !deleted_paths.is_empty() {
            flags.push("deleted_file_still_mapped".to_string());
        }
        let joined = cmdline.join(" ").to_lowercase();
        for marker in [
            "stratum", "wallet", "xmrig", "minerd", "cpuminer", "wget ", "curl ", "http://",
            "https://", "chmod +x", "/dev/shm",
        ] {
            if joined.contains(marker) {
                flags.push(format!("cmdline:{marker}"));
            }
        }
        flags.sort();
        flags.dedup();
        flags
    }

    fn is_in_risk_dir(dirs: &[String], path: &str) -> bool {
        let lower = path.to_lowercase();
        dirs.iter().any(|item| {
            let expanded = expand_path_template(item);
            let prefix = expanded.to_string_lossy().to_lowercase();
            lower.starts_with(&prefix)
        })
    }

    fn looks_masqueraded_system_name(path: &str) -> bool {
        let basename = Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        matches!(
            basename.as_str(),
            "systemd"
                | "dbus-daemon"
                | "cron"
                | "sshd"
                | "kthreadd"
                | "networkmanager"
                | "svchost.exe"
                | "lsass.exe"
                | "explorer.exe"
        )
    }

    fn mark_network_suspicious_processes(
        processes: &mut [ProcessIdentity],
        net_connections: &[common_model::NetConnection],
    ) {
        let suspicious = net_connections
            .iter()
            .filter(|connection| {
                connection.direction == Direction::Outbound
                    && parse_port(&connection.remote_addr)
                        .map(|port| {
                            matches!(
                                port,
                                3333 | 3334
                                    | 4444
                                    | 4555
                                    | 5555
                                    | 5556
                                    | 6666
                                    | 6667
                                    | 7029
                                    | 7777
                                    | 7778
                                    | 8888
                                    | 8899
                                    | 9000
                                    | 9999
                                    | 14433
                                    | 14444
                                    | 14455
                                    | 15555
                            )
                        })
                        .unwrap_or(false)
            })
            .map(|connection| connection.entity_key.clone())
            .collect::<HashSet<_>>();
        for process in processes {
            if suspicious.contains(&process.entity_key) {
                process
                    .suspicious_flags
                    .push("associated_suspicious_network_connection".to_string());
            }
            process.suspicious_flags.sort();
            process.suspicious_flags.dedup();
        }
    }

    fn parse_port(addr: &str) -> Option<u16> {
        addr.rsplit_once(':')?.1.parse::<u16>().ok()
    }

    fn is_elf(path: &Path) -> bool {
        let Ok(mut file) = fs::File::open(path) else {
            return false;
        };
        let mut magic = [0_u8; 4];
        std::io::Read::read_exact(&mut file, &mut magic).is_ok()
            && magic == [0x7f, b'E', b'L', b'F']
    }

    fn is_recent_file(path: &Path, window_hours: i64) -> bool {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        utc_from_epoch(meta.mtime(), meta.mtime_nsec())
            .map(|mtime| Utc::now() - mtime <= Duration::hours(window_hours))
            .unwrap_or(false)
    }

    fn is_web_script(path: &Path, roots: &[String]) -> bool {
        let lower = path.to_string_lossy().to_lowercase();
        let under_root = roots.iter().any(|root| {
            let expanded = expand_path_template(root);
            let prefix = expanded.to_string_lossy().to_lowercase();
            lower.starts_with(&prefix)
        });
        let ext = path
            .extension()
            .map(|value| value.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        under_root
            && matches!(
                ext.as_str(),
                "php" | "jsp" | "jspx" | "asp" | "aspx" | "cgi" | "pl" | "py" | "sh"
            )
    }

    fn utc_from_epoch(secs: i64, nanos: i64) -> Option<DateTime<Utc>> {
        let nanos = u32::try_from(nanos.max(0)).ok()?;
        Utc.timestamp_opt(secs, nanos).single()
    }

    fn expand_targets(path: &Path) -> Vec<PathBuf> {
        let raw = path.to_string_lossy();
        if raw.contains('*') {
            return glob(&raw)
                .ok()
                .into_iter()
                .flat_map(|paths| paths.flatten())
                .collect();
        }
        vec![path.to_path_buf()]
    }

    fn persistence_artifact(host_id: &str, file: &Path, ts: DateTime<Utc>) -> PersistenceArtifact {
        let location = path_to_string(file);
        PersistenceArtifact {
            entity_key: host_id.to_string(),
            mechanism: detect_linux_mechanism(&location).to_string(),
            value: extract_persistence_value(file).unwrap_or_else(|| location.clone()),
            location,
            ts,
        }
    }

    fn detect_linux_mechanism(path: &str) -> &'static str {
        let lower = path.to_lowercase();
        if lower.contains("systemd") {
            "systemd"
        } else if lower.contains("cron") {
            "cron"
        } else if lower.contains("autostart") {
            "autostart"
        } else if lower.ends_with("rc.local") {
            "rc_local"
        } else if lower.contains("/init.d/") {
            "init_d"
        } else if lower.contains("ld.so.preload") {
            "ld_preload"
        } else if lower.contains("authorized_keys") {
            "ssh_authorized_keys"
        } else {
            "persistence_file"
        }
    }

    fn extract_persistence_value(path: &Path) -> Option<String> {
        let content = fs::read_to_string(path).ok()?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("ExecStart=") || trimmed.starts_with("Exec=") {
                return trimmed
                    .split_once('=')
                    .map(|(_, value)| value.trim().to_string());
            }
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                return Some(trimmed.to_string());
            }
        }
        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use chrono::{Datelike, Timelike};

        #[test]
        fn parses_last_output_with_iso_timestamp() {
            let rows = parse_last_output(
                "last",
                "demo pts/0 203.0.113.10 2026-03-27T10:20:30+0800 - 2026-03-27T10:25:00+0800  (00:04)",
            );
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].user.as_deref(), Some("demo"));
            assert_eq!(rows[0].terminal.as_deref(), Some("pts/0"));
            assert_eq!(rows[0].host.as_deref(), Some("203.0.113.10"));
            let ts = rows[0].login_time.expect("login timestamp");
            assert_eq!(ts.year(), 2026);
            assert_eq!(ts.minute(), 20);
            assert_eq!(
                rows[0].logout_time.as_deref(),
                Some("2026-03-27T10:25:00+0800")
            );
        }

        #[test]
        fn normalizes_compact_timezone_offset() {
            assert_eq!(
                normalize_timezone_offset("2026-03-27T10:20:30+0800"),
                "2026-03-27T10:20:30+08:00"
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::{LinuxProcCollector, collect_process_identity};

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::path::PathBuf;

    use anyhow::{Result, bail};
    use common_model::{AppConfig, HostCollector, Platform, SnapshotBundle};

    pub struct LinuxProcCollector;

    impl HostCollector for LinuxProcCollector {
        fn backend_name(&self) -> &'static str {
            "linux-proc"
        }

        fn platform(&self) -> Platform {
            Platform::Linux
        }

        fn collect_snapshot(&self, _config: &AppConfig) -> Result<SnapshotBundle> {
            bail!("linux /proc collector is only available on Linux")
        }

        fn recommended_watch_paths(&self, _config: &AppConfig) -> Vec<PathBuf> {
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use imp::LinuxProcCollector;
