#[cfg(target_os = "windows")]
mod imp {
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
    };

    use anyhow::Result;
    use chrono::{DateTime, TimeZone, Utc};
    use common_model::{
        AppConfig, FileArtifact, HostCollector, HostInfo, PersistenceArtifact, Platform,
        ProcessIdentity, SnapshotBundle, collect_system_net_connections, current_hostname,
        expand_path_template, host_entity_key, observed_executable_artifacts, path_to_string,
        process_entity_key, sha256_file, walk_files,
    };
    use sysinfo::{System, Users};
    use winreg::{RegKey, enums::*};

    pub struct WindowsCollector;

    impl WindowsCollector {
        fn collect_processes(
            &self,
            config: &AppConfig,
            ts: DateTime<Utc>,
        ) -> Result<Vec<ProcessIdentity>> {
            let mut system = System::new_all();
            system.refresh_all();
            let users = Users::new_with_refreshed_list();
            let mut processes = Vec::new();

            for (pid, process) in system.processes() {
                let pid = pid.as_u32() as i64;
                let ppid = process
                    .parent()
                    .map(|value| value.as_u32() as i64)
                    .unwrap_or(0);
                let start_time = Utc
                    .timestamp_opt(process.start_time() as i64, 0)
                    .single()
                    .unwrap_or(ts);
                let exe = process.exe().map(path_to_string);
                let cwd = process.cwd().map(path_to_string);
                let cmdline = process
                    .cmd()
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                let user = process
                    .user_id()
                    .and_then(|user_id| users.get_user_by_id(user_id))
                    .map(|user| user.name().to_string());
                let hash_sha256 = exe
                    .as_deref()
                    .map(Path::new)
                    .map(|path| sha256_file(path, config.collection.hash_file_limit_mb))
                    .transpose()?
                    .flatten();

                processes.push(ProcessIdentity {
                    entity_key: process_entity_key(Platform::Windows, pid, start_time),
                    pid,
                    ppid,
                    start_time,
                    exe,
                    cmdline,
                    cwd,
                    user,
                    hash_sha256,
                    signer: None,
                    fd_count: None,
                    mapped_modules: Vec::new(),
                    deleted_paths: Vec::new(),
                    suspicious_flags: Vec::new(),
                    first_seen: ts,
                    last_seen: ts,
                    is_running: true,
                });
            }

            processes.sort_by_key(|process| process.start_time);
            Ok(processes)
        }

        fn collect_persistence(
            &self,
            config: &AppConfig,
            host_id: &str,
            ts: DateTime<Utc>,
            processes: &[ProcessIdentity],
        ) -> Vec<PersistenceArtifact> {
            let mut artifacts = Vec::new();
            let mut exe_index = HashMap::new();
            for process in processes {
                if let Some(exe) = &process.exe {
                    exe_index.insert(exe.to_lowercase(), process.entity_key.clone());
                }
            }

            for key_name in &config.collection.windows.run_keys {
                if let Ok((hive, sub_key)) = split_registry_path(key_name) {
                    if let Ok(key) = hive.open_subkey_with_flags(sub_key, KEY_READ) {
                        for item in key.enum_values().flatten() {
                            let value = decode_reg_value(&item.1);
                            let target_path = extract_command_path(&value);
                            let entity_key = target_path
                                .as_deref()
                                .and_then(|path| exe_index.get(&path.to_lowercase()).cloned())
                                .unwrap_or_else(|| host_id.to_string());
                            artifacts.push(PersistenceArtifact {
                                entity_key,
                                mechanism: "run_key".to_string(),
                                location: key_name.to_string(),
                                value: format!("{}={}", item.0, value),
                                ts,
                            });
                        }
                    }
                }
            }

            for template in &config.collection.windows.startup_paths {
                let path = expand_path_template(template);
                for target in expand_targets(&path) {
                    if target.is_dir() {
                        for file in walk_files(&target) {
                            artifacts.push(PersistenceArtifact {
                                entity_key: host_id.to_string(),
                                mechanism: detect_windows_mechanism(&file).to_string(),
                                location: path_to_string(&file),
                                value: path_to_string(&file),
                                ts,
                            });
                        }
                    } else if target.is_file() {
                        artifacts.push(PersistenceArtifact {
                            entity_key: host_id.to_string(),
                            mechanism: detect_windows_mechanism(&target).to_string(),
                            location: path_to_string(&target),
                            value: path_to_string(&target),
                            ts,
                        });
                    }
                }
            }

            artifacts
        }
    }

    impl HostCollector for WindowsCollector {
        fn backend_name(&self) -> &'static str {
            "windows-snapshot"
        }

        fn platform(&self) -> Platform {
            Platform::Windows
        }

        fn collect_snapshot(&self, config: &AppConfig) -> Result<SnapshotBundle> {
            let ts = Utc::now();
            let hostname = current_hostname();
            let host = HostInfo {
                host_id: host_entity_key(Platform::Windows, &hostname),
                hostname,
                platform: Platform::Windows,
                collected_at: ts,
                collector: self.backend_name().to_string(),
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
            let processes = self.collect_processes(config, ts)?;
            let process_map = processes
                .iter()
                .map(|process| (process.pid, process.entity_key.clone()))
                .collect::<HashMap<_, _>>();
            let net_connections = collect_system_net_connections(&process_map, ts)?;
            let mut file_artifacts = observed_executable_artifacts(&processes, ts);
            let persistence_artifacts =
                self.collect_persistence(config, &host.host_id, ts, &processes);
            file_artifacts.extend(
                persistence_artifacts
                    .iter()
                    .filter(|artifact| Path::new(&artifact.location).is_file())
                    .map(|artifact| FileArtifact {
                        entity_key: artifact.entity_key.clone(),
                        category: "persistence".to_string(),
                        path: artifact.location.clone(),
                        file_id: None,
                        op: common_model::FileOp::Observed,
                        sha256: sha256_file(
                            Path::new(&artifact.location),
                            config.collection.hash_file_limit_mb,
                        )
                        .ok()
                        .flatten(),
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
                        notes: Vec::new(),
                        ts: artifact.ts,
                    }),
            );

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
                .windows
                .risk_dirs
                .iter()
                .chain(config.collection.windows.startup_paths.iter())
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
                "process/network realtime uses snapshot diff polling".to_string(),
                "filesystem realtime uses ReadDirectoryChanges via notify".to_string(),
                "ETW-native collector can be added behind the same trait later".to_string(),
            ]
        }
    }

    fn split_registry_path(path: &str) -> Result<(RegKey, &str)> {
        if let Some(subkey) = path.strip_prefix("HKCU\\") {
            Ok((RegKey::predef(HKEY_CURRENT_USER), subkey))
        } else if let Some(subkey) = path.strip_prefix("HKLM\\") {
            Ok((RegKey::predef(HKEY_LOCAL_MACHINE), subkey))
        } else {
            anyhow::bail!("unsupported registry hive {path}")
        }
    }

    fn decode_reg_value(value: &winreg::RegValue) -> String {
        String::from_utf8(value.bytes.clone()).unwrap_or_else(|_| format!("{:?}", value.bytes))
    }

    fn extract_command_path(value: &str) -> Option<String> {
        let trimmed = value.trim_matches(char::from(0)).trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some(rest) = trimmed.strip_prefix('"') {
            return rest.split('"').next().map(str::to_string);
        }
        trimmed.split_whitespace().next().map(str::to_string)
    }

    fn detect_windows_mechanism(path: &Path) -> &'static str {
        let lower = path.to_string_lossy().to_lowercase();
        if lower.contains("\\tasks") {
            "scheduled_task"
        } else if lower.contains("\\startup") {
            "startup_folder"
        } else {
            "persistence_file"
        }
    }

    fn expand_targets(path: &Path) -> Vec<PathBuf> {
        vec![path.to_path_buf()]
    }
}

#[cfg(target_os = "windows")]
pub use imp::WindowsCollector;

#[cfg(not(target_os = "windows"))]
mod imp {
    use std::path::PathBuf;

    use anyhow::{Result, bail};
    use common_model::{AppConfig, HostCollector, Platform, SnapshotBundle};

    pub struct WindowsCollector;

    impl HostCollector for WindowsCollector {
        fn backend_name(&self) -> &'static str {
            "windows-snapshot"
        }

        fn platform(&self) -> Platform {
            Platform::Windows
        }

        fn collect_snapshot(&self, _config: &AppConfig) -> Result<SnapshotBundle> {
            bail!("windows collector is only available on Windows")
        }

        fn recommended_watch_paths(&self, _config: &AppConfig) -> Vec<PathBuf> {
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub use imp::WindowsCollector;
