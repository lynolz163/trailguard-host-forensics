use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result};
use chrono::Duration;
use common_model::{
    AppConfig, Event, EventType, EvidenceDataset, FileOp, NetConnection, Platform, ProcessIdentity,
    RuleMatch, Severity, basename_lower, expand_path_template, fields, looks_executable,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Explainable rule catalog loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    pub interpreters: Vec<String>,
    pub script_hosts: Vec<String>,
    pub office_browser_chat: Vec<String>,
    pub privilege_brokers: Vec<String>,
    pub suspicious_parent_child: Vec<ParentChildPattern>,
    pub masquerade_names: Vec<String>,
    pub uncommon_remote_ports: Vec<u16>,
    pub miner_process_names: Vec<String>,
    pub miner_cmdline_keywords: Vec<String>,
    pub miner_pool_ports: Vec<u16>,
    pub miner_pool_indicators: Vec<String>,
    pub rapid_file_exec_window_secs: i64,
    pub parent_exit_network_grace_secs: i64,
    pub failed_login_burst_threshold: usize,
    pub suspicious_auth_paths: Vec<String>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            interpreters: vec![
                "python".to_string(),
                "python3".to_string(),
                "bash".to_string(),
                "sh".to_string(),
                "zsh".to_string(),
                "pwsh".to_string(),
                "powershell".to_string(),
                "wscript".to_string(),
                "cscript".to_string(),
            ],
            script_hosts: vec![
                "powershell.exe".to_string(),
                "pwsh.exe".to_string(),
                "cmd.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
                "bash".to_string(),
                "sh".to_string(),
                "python".to_string(),
                "python3".to_string(),
            ],
            office_browser_chat: vec![
                "winword.exe".to_string(),
                "excel.exe".to_string(),
                "powerpnt.exe".to_string(),
                "outlook.exe".to_string(),
                "chrome.exe".to_string(),
                "msedge.exe".to_string(),
                "firefox.exe".to_string(),
                "teams.exe".to_string(),
                "slack.exe".to_string(),
                "discord.exe".to_string(),
                "wechat.exe".to_string(),
                "qq.exe".to_string(),
            ],
            privilege_brokers: vec![
                "sudo".to_string(),
                "su".to_string(),
                "doas".to_string(),
                "pkexec".to_string(),
                "runuser".to_string(),
            ],
            suspicious_parent_child: vec![
                ParentChildPattern::new("winword.exe", "powershell.exe"),
                ParentChildPattern::new("excel.exe", "cmd.exe"),
                ParentChildPattern::new("chrome.exe", "powershell.exe"),
                ParentChildPattern::new("outlook.exe", "wscript.exe"),
                ParentChildPattern::new("firefox.exe", "cmd.exe"),
            ],
            masquerade_names: vec![
                "svchost.exe".to_string(),
                "lsass.exe".to_string(),
                "explorer.exe".to_string(),
                "systemd".to_string(),
                "dbus-daemon".to_string(),
                "cron".to_string(),
            ],
            uncommon_remote_ports: vec![
                3333, 3334, 4444, 4555, 5555, 5556, 6666, 6667, 7029, 7777, 7778, 8081, 8443, 8888,
                8899, 9000, 9999, 14433, 14444, 14455, 15555,
            ],
            miner_process_names: Vec::new(),
            miner_cmdline_keywords: Vec::new(),
            miner_pool_ports: vec![
                3333, 3334, 4444, 4555, 5555, 5556, 6666, 6667, 7029, 7777, 7778, 8888, 8899, 9000,
                9999, 14433, 14444, 14455, 15555,
            ],
            miner_pool_indicators: vec![
                "stratum".to_string(),
                "pool".to_string(),
                "supportxmr".to_string(),
                "minexmr".to_string(),
                "nanopool".to_string(),
                "ethermine".to_string(),
                "2miners".to_string(),
                "moneroocean".to_string(),
                "hashvault".to_string(),
                "nicehash".to_string(),
                "f2pool".to_string(),
                "xmr".to_string(),
                "xmrig".to_string(),
                "mock-pool".to_string(),
            ],
            rapid_file_exec_window_secs: 180,
            parent_exit_network_grace_secs: 120,
            failed_login_burst_threshold: 3,
            suspicious_auth_paths: vec![
                "/etc/sudoers".to_string(),
                "/etc/sudoers.d".to_string(),
                "authorized_keys".to_string(),
                "known_hosts".to_string(),
                "ld.so.preload".to_string(),
                ".bashrc".to_string(),
                ".profile".to_string(),
            ],
        }
    }
}

impl RuleConfig {
    pub fn load_from_file(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => {
                let content = fs::read_to_string(path)
                    .with_context(|| format!("failed to read rules file {}", path.display()))?;
                let config = toml::from_str(&content)
                    .with_context(|| format!("failed to parse rules file {}", path.display()))?;
                Ok(config)
            }
            None => {
                let default_path = Path::new("config").join("rules.toml");
                if default_path.exists() {
                    let content = fs::read_to_string(&default_path).with_context(|| {
                        format!("failed to read rules file {}", default_path.display())
                    })?;
                    let config = toml::from_str(&content).with_context(|| {
                        format!("failed to parse rules file {}", default_path.display())
                    })?;
                    Ok(config)
                } else {
                    Ok(Self::default())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentChildPattern {
    pub parent: String,
    pub child: String,
}

impl ParentChildPattern {
    pub fn new(parent: impl Into<String>, child: impl Into<String>) -> Self {
        Self {
            parent: parent.into(),
            child: child.into(),
        }
    }
}

/// Explainable rules evaluator.
pub struct RuleEngine {
    config: RuleConfig,
}

impl RuleEngine {
    pub fn new(config: RuleConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(&self, app: &AppConfig, dataset: &EvidenceDataset) -> Vec<RuleMatch> {
        let process_map = dataset
            .processes
            .iter()
            .map(|process| (process.entity_key.clone(), process))
            .collect::<HashMap<_, _>>();
        let parent_map = dataset
            .processes
            .iter()
            .filter_map(|process| {
                dataset
                    .processes
                    .iter()
                    .find(|candidate| candidate.pid == process.ppid)
                    .map(|parent| (process.entity_key.clone(), parent.entity_key.clone()))
            })
            .collect::<HashMap<_, _>>();
        let net_by_entity = group_net_by_entity(&dataset.net_connections);
        let privilege_events_by_entity =
            dataset
                .events
                .iter()
                .fold(HashMap::<String, Vec<&Event>>::new(), |mut acc, event| {
                    if event.event_type == EventType::PrivilegeChange {
                        acc.entry(event.entity_key.clone()).or_default().push(event);
                    }
                    acc
                });
        let file_by_path = dataset.file_artifacts.iter().fold(
            HashMap::<String, Vec<_>>::new(),
            |mut acc, artifact| {
                acc.entry(artifact.path.to_lowercase())
                    .or_default()
                    .push(artifact);
                acc
            },
        );
        let persistence_by_entity = dataset.persistence_artifacts.iter().fold(
            HashMap::<String, Vec<_>>::new(),
            |mut acc, artifact| {
                acc.entry(artifact.entity_key.clone())
                    .or_default()
                    .push(artifact);
                acc
            },
        );
        let events_by_entity =
            dataset
                .events
                .iter()
                .fold(HashMap::<String, Vec<String>>::new(), |mut acc, event| {
                    acc.entry(event.entity_key.clone())
                        .or_default()
                        .push(event.event_id.clone());
                    acc
                });

        let host_platform = dataset
            .host
            .as_ref()
            .map(|host| host.platform)
            .unwrap_or(Platform::Unknown);

        let mut matches = Vec::new();
        for process in &dataset.processes {
            matches.extend(self.rule_high_risk_exec(
                app,
                host_platform,
                process,
                &events_by_entity,
            ));
            matches.extend(self.rule_parent_chain(
                process,
                &process_map,
                &parent_map,
                &net_by_entity,
                &events_by_entity,
            ));
            matches.extend(self.rule_network_behaviour(
                app,
                host_platform,
                process,
                &process_map,
                &parent_map,
                &net_by_entity,
                &file_by_path,
                &events_by_entity,
            ));
            matches.extend(self.rule_persistence(
                app,
                host_platform,
                process,
                dataset,
                &events_by_entity,
            ));
            matches.extend(self.rule_privilege(
                app,
                host_platform,
                process,
                &process_map,
                &parent_map,
                &privilege_events_by_entity,
                &events_by_entity,
            ));
            matches.extend(self.rule_miner_like(
                app,
                host_platform,
                process,
                &net_by_entity,
                &persistence_by_entity,
                &events_by_entity,
            ));
        }

        for artifact in &dataset.file_artifacts {
            matches.extend(self.rule_file_drop(app, host_platform, artifact, &events_by_entity));
            matches.extend(self.rule_file_metadata(
                app,
                host_platform,
                artifact,
                &events_by_entity,
            ));
        }

        if let Some(host) = &dataset.host {
            matches.extend(self.rule_auth_activity(host, &events_by_entity));
        }

        dedup_matches(matches)
    }

    fn rule_high_risk_exec(
        &self,
        app: &AppConfig,
        platform: Platform,
        process: &ProcessIdentity,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let Some(exe) = process.exe.as_deref() else {
            return Vec::new();
        };
        let Some(dir) = first_risk_dir(app, platform, exe) else {
            return Vec::new();
        };
        vec![RuleMatch {
            rule_id: "TG-R001".to_string(),
            entity_key: process.entity_key.clone(),
            severity: Severity::High,
            why_matched: format!("executable runs from high-risk directory `{dir}`"),
            evidence_refs: evidence_refs(events_by_entity, &process.entity_key, [exe.to_string()]),
            facts: fields([
                ("exe", json!(exe)),
                ("risk_dir", json!(dir)),
                ("user", json!(process.user)),
            ]),
        }]
    }

    fn rule_parent_chain(
        &self,
        process: &ProcessIdentity,
        process_map: &HashMap<String, &ProcessIdentity>,
        parent_map: &HashMap<String, String>,
        net_by_entity: &HashMap<String, Vec<&NetConnection>>,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let process_name = process.display_name().to_lowercase();
        let parent = parent_map
            .get(&process.entity_key)
            .and_then(|key| process_map.get(key))
            .copied();
        let grandparent = parent
            .and_then(|parent| parent_map.get(&parent.entity_key))
            .and_then(|key| process_map.get(key))
            .copied();

        if let (Some(parent), Some(grandparent)) = (parent, grandparent) {
            let parent_name = parent.display_name().to_lowercase();
            let grandparent_name = grandparent.display_name().to_lowercase();
            if self.config.script_hosts.contains(&parent_name)
                && self.config.interpreters.contains(&grandparent_name)
            {
                matches.push(RuleMatch {
                    rule_id: "TG-R002".to_string(),
                    entity_key: process.entity_key.clone(),
                    severity: Severity::Medium,
                    why_matched: format!(
                        "matched interpreter -> shell/script host -> child chain: {} -> {} -> {}",
                        grandparent.display_name(),
                        parent.display_name(),
                        process.display_name()
                    ),
                    evidence_refs: evidence_refs(
                        events_by_entity,
                        &process.entity_key,
                        [
                            process.entity_key.clone(),
                            parent.entity_key.clone(),
                            grandparent.entity_key.clone(),
                        ],
                    ),
                    facts: fields([
                        ("grandparent", json!(grandparent.display_name())),
                        ("parent", json!(parent.display_name())),
                        ("child", json!(process.display_name())),
                    ]),
                });
            }

            if self.config.office_browser_chat.contains(&grandparent_name)
                && self.config.script_hosts.contains(&parent_name)
                && net_by_entity.contains_key(&process.entity_key)
            {
                matches.push(RuleMatch {
                    rule_id: "TG-R003".to_string(),
                    entity_key: process.entity_key.clone(),
                    severity: Severity::High,
                    why_matched: format!(
                        "network-active child is descended from {} via script host {}",
                        grandparent.display_name(),
                        parent.display_name()
                    ),
                    evidence_refs: evidence_refs(
                        events_by_entity,
                        &process.entity_key,
                        [process.entity_key.clone(), grandparent.entity_key.clone()],
                    ),
                    facts: fields([
                        ("grandparent", json!(grandparent.display_name())),
                        ("parent", json!(parent.display_name())),
                        ("child", json!(process_name)),
                    ]),
                });
            }

            for pattern in &self.config.suspicious_parent_child {
                if parent_name == pattern.parent.to_lowercase()
                    && process_name == pattern.child.to_lowercase()
                {
                    matches.push(RuleMatch {
                        rule_id: "TG-R004".to_string(),
                        entity_key: process.entity_key.clone(),
                        severity: Severity::Medium,
                        why_matched: format!(
                            "matched uncommon parent/child pair {} -> {}",
                            parent.display_name(),
                            process.display_name()
                        ),
                        evidence_refs: evidence_refs(
                            events_by_entity,
                            &process.entity_key,
                            [process.entity_key.clone(), parent.entity_key.clone()],
                        ),
                        facts: fields([
                            ("parent", json!(parent.display_name())),
                            ("child", json!(process.display_name())),
                        ]),
                    });
                }
            }

            if let Some(connections) = net_by_entity.get(&process.entity_key) {
                if !parent.is_running
                    || connections.iter().any(|connection| {
                        connection.ts
                            > parent.last_seen
                                + Duration::seconds(self.config.parent_exit_network_grace_secs)
                    })
                {
                    matches.push(RuleMatch {
                        rule_id: "TG-R005".to_string(),
                        entity_key: process.entity_key.clone(),
                        severity: Severity::Medium,
                        why_matched: format!(
                            "parent process {} exited before child maintained external connectivity",
                            parent.display_name()
                        ),
                        evidence_refs: evidence_refs(
                            events_by_entity,
                            &process.entity_key,
                            [process.entity_key.clone(), parent.entity_key.clone()],
                        ),
                        facts: fields([
                            ("parent_last_seen", json!(parent.last_seen)),
                            ("child", json!(process.display_name())),
                            ("connection_count", json!(connections.len())),
                        ]),
                    });
                }
            }
        }

        matches
    }

    #[allow(clippy::too_many_arguments)]
    fn rule_network_behaviour(
        &self,
        app: &AppConfig,
        platform: Platform,
        process: &ProcessIdentity,
        _process_map: &HashMap<String, &ProcessIdentity>,
        _parent_map: &HashMap<String, String>,
        net_by_entity: &HashMap<String, Vec<&NetConnection>>,
        file_by_path: &HashMap<String, Vec<&common_model::FileArtifact>>,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let Some(connections) = net_by_entity.get(&process.entity_key) else {
            return Vec::new();
        };
        let mut matches = Vec::new();

        if let Some(exe) = process.exe.as_deref() {
            if let Some(artifacts) = file_by_path.get(&exe.to_lowercase()) {
                if artifacts.iter().any(|artifact| {
                    matches!(artifact.op, FileOp::Create | FileOp::Write)
                        && process.start_time
                            <= artifact.ts
                                + Duration::seconds(self.config.rapid_file_exec_window_secs)
                        && connections.iter().any(|connection| {
                            connection.ts
                                <= process.start_time
                                    + Duration::seconds(app.collection.rapid_connect_window_secs)
                        })
                }) {
                    matches.push(RuleMatch {
                        rule_id: "TG-R006".to_string(),
                        entity_key: process.entity_key.clone(),
                        severity: Severity::High,
                        why_matched: format!(
                            "newly landed executable `{exe}` rapidly established network connectivity"
                        ),
                        evidence_refs: evidence_refs(
                            events_by_entity,
                            &process.entity_key,
                            [exe.to_string()],
                        ),
                        facts: fields([
                            ("exe", json!(exe)),
                            ("connection_count", json!(connections.len())),
                        ]),
                    });
                }
            }

            let base = basename_lower(exe);
            let under_trusted = is_under_trusted_dir(app, platform, exe);
            if self.config.masquerade_names.contains(&base) && !under_trusted {
                matches.push(RuleMatch {
                    rule_id: "TG-R007".to_string(),
                    entity_key: process.entity_key.clone(),
                    severity: Severity::High,
                    why_matched: format!(
                        "system-like filename `{base}` initiated network activity outside trusted directories"
                    ),
                    evidence_refs: evidence_refs(
                        events_by_entity,
                        &process.entity_key,
                        [exe.to_string()],
                    ),
                    facts: fields([
                        ("exe", json!(exe)),
                        ("connections", json!(connections.len())),
                    ]),
                });
            }
        }

        if !process.is_running
            && process.last_seen - process.start_time
                <= Duration::seconds(app.collection.short_lived_process_secs)
        {
            matches.push(RuleMatch {
                rule_id: "TG-R008".to_string(),
                entity_key: process.entity_key.clone(),
                severity: Severity::Medium,
                why_matched: "short-lived process initiated network activity".to_string(),
                evidence_refs: evidence_refs(events_by_entity, &process.entity_key, []),
                facts: fields([
                    (
                        "runtime_secs",
                        json!((process.last_seen - process.start_time).num_seconds()),
                    ),
                    ("connections", json!(connections.len())),
                ]),
            });
        }

        for connection in connections {
            let port = parse_port(&connection.remote_addr);
            if port
                .map(|value| self.config.uncommon_remote_ports.contains(&value))
                .unwrap_or(false)
            {
                matches.push(RuleMatch {
                    rule_id: "TG-R009".to_string(),
                    entity_key: process.entity_key.clone(),
                    severity: Severity::Medium,
                    why_matched: format!(
                        "connection to uncommon remote port {} observed",
                        port.unwrap()
                    ),
                    evidence_refs: evidence_refs(
                        events_by_entity,
                        &process.entity_key,
                        [connection.remote_addr.clone()],
                    ),
                    facts: fields([
                        ("remote_addr", json!(connection.remote_addr)),
                        ("protocol", json!(connection.protocol)),
                        (
                            "direction",
                            json!(format!("{:?}", connection.direction).to_lowercase()),
                        ),
                        ("net_namespace", json!(connection.net_namespace)),
                        ("observation_source", json!(connection.observation_source)),
                        ("socket_inode", json!(connection.socket_inode)),
                    ]),
                });
            }
        }

        matches
    }

    fn rule_file_drop(
        &self,
        app: &AppConfig,
        platform: Platform,
        artifact: &common_model::FileArtifact,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let risk_dir = first_risk_dir(app, platform, &artifact.path);
        if matches!(artifact.op, FileOp::Create | FileOp::Write)
            && looks_executable(&artifact.path)
            && risk_dir.is_some()
        {
            matches.push(RuleMatch {
                rule_id: "TG-R010".to_string(),
                entity_key: artifact.entity_key.clone(),
                severity: Severity::High,
                why_matched: format!(
                    "executable-like file landed in risky path {}",
                    artifact.path
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &artifact.entity_key,
                    [artifact.path.clone()],
                ),
                facts: fields([
                    ("path", json!(artifact.path)),
                    ("sha256", json!(artifact.sha256)),
                    ("risk_dir", json!(risk_dir)),
                ]),
            });
        }

        if matches!(artifact.op, FileOp::Rename) {
            let base = basename_lower(&artifact.path);
            if self.config.masquerade_names.contains(&base) {
                matches.push(RuleMatch {
                    rule_id: "TG-R011".to_string(),
                    entity_key: artifact.entity_key.clone(),
                    severity: Severity::Medium,
                    why_matched: format!("rename created masquerading filename `{base}`"),
                    evidence_refs: evidence_refs(
                        events_by_entity,
                        &artifact.entity_key,
                        [artifact.path.clone()],
                    ),
                    facts: fields([("path", json!(artifact.path))]),
                });
            }
        }

        matches
    }

    fn rule_file_metadata(
        &self,
        app: &AppConfig,
        platform: Platform,
        artifact: &common_model::FileArtifact,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let risk_dir = first_risk_dir(app, platform, &artifact.path);

        if artifact.is_hidden && artifact.is_executable && risk_dir.is_some() {
            matches.push(RuleMatch {
                rule_id: "TG-R020".to_string(),
                entity_key: artifact.entity_key.clone(),
                severity: Severity::High,
                why_matched: format!(
                    "hidden executable-like file discovered in risky path {}",
                    artifact.path
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &artifact.entity_key,
                    [
                        artifact.path.clone(),
                        artifact.content_ref.clone().unwrap_or_default(),
                    ],
                ),
                facts: fields([
                    ("path", json!(artifact.path)),
                    ("category", json!(artifact.category)),
                    ("mode", json!(artifact.mode)),
                    ("risk_dir", json!(risk_dir)),
                ]),
            });
        }

        if (artifact.is_suid || artifact.is_sgid) && risk_dir.is_some() {
            matches.push(RuleMatch {
                rule_id: "TG-R021".to_string(),
                entity_key: artifact.entity_key.clone(),
                severity: Severity::High,
                why_matched: format!("SUID/SGID file discovered in risky path {}", artifact.path),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &artifact.entity_key,
                    [artifact.path.clone()],
                ),
                facts: fields([
                    ("path", json!(artifact.path)),
                    ("is_suid", json!(artifact.is_suid)),
                    ("is_sgid", json!(artifact.is_sgid)),
                    ("mode", json!(artifact.mode)),
                    ("owner", json!(artifact.owner)),
                ]),
            });
        }

        if artifact.notes.iter().any(|item| item == "web_script")
            && artifact
                .notes
                .iter()
                .any(|item| item == "recently_modified")
        {
            matches.push(RuleMatch {
                rule_id: "TG-R022".to_string(),
                entity_key: artifact.entity_key.clone(),
                severity: Severity::Medium,
                why_matched: format!(
                    "recently modified web-root script requires review: {}",
                    artifact.path
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &artifact.entity_key,
                    [artifact.path.clone()],
                ),
                facts: fields([
                    ("path", json!(artifact.path)),
                    ("mtime", json!(artifact.mtime)),
                    ("notes", json!(artifact.notes)),
                ]),
            });
        }

        if artifact.category == "auth_file"
            && artifact
                .notes
                .iter()
                .any(|item| item == "recently_modified")
            && self
                .config
                .suspicious_auth_paths
                .iter()
                .any(|item| artifact.path.to_lowercase().contains(&item.to_lowercase()))
        {
            matches.push(RuleMatch {
                rule_id: "TG-R023".to_string(),
                entity_key: artifact.entity_key.clone(),
                severity: Severity::High,
                why_matched: format!(
                    "sensitive auth or startup material was recently modified: {}",
                    artifact.path
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &artifact.entity_key,
                    [
                        artifact.path.clone(),
                        artifact.content_ref.clone().unwrap_or_default(),
                    ],
                ),
                facts: fields([
                    ("path", json!(artifact.path)),
                    ("mtime", json!(artifact.mtime)),
                    ("notes", json!(artifact.notes)),
                    ("sha256", json!(artifact.sha256)),
                ]),
            });
        }

        matches
    }

    fn rule_persistence(
        &self,
        app: &AppConfig,
        platform: Platform,
        process: &ProcessIdentity,
        dataset: &EvidenceDataset,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let Some(exe) = process.exe.as_deref() else {
            return matches;
        };
        for artifact in dataset.persistence_artifacts.iter().filter(|artifact| {
            artifact.entity_key == process.entity_key || artifact.value.contains(exe)
        }) {
            let severity = if first_risk_dir(app, platform, exe).is_some() {
                Severity::High
            } else {
                Severity::Medium
            };
            matches.push(RuleMatch {
                rule_id: "TG-R012".to_string(),
                entity_key: process.entity_key.clone(),
                severity,
                why_matched: format!(
                    "process is linked to persistence artifact {} at {}",
                    artifact.mechanism, artifact.location
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &process.entity_key,
                    [artifact.location.clone(), artifact.value.clone()],
                ),
                facts: fields([
                    ("mechanism", json!(artifact.mechanism)),
                    ("location", json!(artifact.location)),
                    ("value", json!(artifact.value)),
                ]),
            });
        }
        matches
    }

    fn rule_privilege(
        &self,
        app: &AppConfig,
        platform: Platform,
        process: &ProcessIdentity,
        process_map: &HashMap<String, &ProcessIdentity>,
        parent_map: &HashMap<String, String>,
        privilege_events_by_entity: &HashMap<String, Vec<&Event>>,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let privileged = process
            .user
            .as_deref()
            .map(is_privileged_user)
            .unwrap_or(false);
        let risky_origin = process
            .exe
            .as_deref()
            .and_then(|exe| first_risk_dir(app, platform, exe))
            .is_some();
        if privileged && risky_origin {
            matches.push(RuleMatch {
                rule_id: "TG-R013".to_string(),
                entity_key: process.entity_key.clone(),
                severity: Severity::High,
                why_matched: "privileged process is executing from a writable or risky directory"
                    .to_string(),
                evidence_refs: evidence_refs(events_by_entity, &process.entity_key, []),
                facts: fields([("exe", json!(process.exe)), ("user", json!(process.user))]),
            });
        }

        if let Some(parent_key) = parent_map.get(&process.entity_key) {
            if let Some(parent) = process_map.get(parent_key) {
                let parent_privileged = parent
                    .user
                    .as_deref()
                    .map(is_privileged_user)
                    .unwrap_or(false);
                if privileged && !parent_privileged {
                    matches.push(RuleMatch {
                        rule_id: "TG-R014".to_string(),
                        entity_key: process.entity_key.clone(),
                        severity: Severity::High,
                        why_matched: format!(
                            "apparent privilege transition from {:?} to {:?}",
                            parent.user, process.user
                        ),
                        evidence_refs: evidence_refs(
                            events_by_entity,
                            &process.entity_key,
                            [parent.entity_key.clone(), process.entity_key.clone()],
                        ),
                        facts: fields([
                            ("parent_user", json!(parent.user)),
                            ("child_user", json!(process.user)),
                        ]),
                    });
                }
            }
        }

        if let Some(events) = privilege_events_by_entity.get(&process.entity_key) {
            let mut saw_uid_transition = false;
            let mut saw_exec_commit = false;
            let mut saw_capset = false;
            for event in events {
                let syscall = event
                    .fields
                    .get("syscall")
                    .and_then(|value| value.as_str())
                    .unwrap_or("privilege_change");
                let old_uid = field_as_u32(event, "old_uid");
                let new_uid = field_as_u32(event, "new_uid");
                if !saw_uid_transition && old_uid.is_some() && new_uid.is_some() {
                    if old_uid.map(is_privileged_id).unwrap_or(false)
                        || !new_uid.map(is_privileged_id).unwrap_or(false)
                    {
                    } else {
                        matches.push(RuleMatch {
                            rule_id: "TG-R015".to_string(),
                            entity_key: process.entity_key.clone(),
                            severity: Severity::High,
                            why_matched: format!(
                                "observed successful privilege transition via {} from uid {} to uid {}",
                                syscall,
                                old_uid.unwrap_or_default(),
                                new_uid.unwrap_or_default()
                            ),
                            evidence_refs: evidence_refs(
                                events_by_entity,
                                &process.entity_key,
                                [event.event_id.clone()],
                            ),
                            facts: fields([
                                ("old_uid", json!(old_uid)),
                                ("new_uid", json!(new_uid)),
                                (
                                    "syscall",
                                    event
                                        .fields
                                        .get("syscall")
                                        .cloned()
                                        .unwrap_or_else(|| json!(null)),
                                ),
                                ("current_user", json!(process.user)),
                            ]),
                        });
                        saw_uid_transition = true;
                    }
                }

                if !saw_exec_commit && syscall == "exec_credential_commit" {
                    let via_broker = event
                        .fields
                        .get("via_privilege_broker")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false);
                    let parent_process = event
                        .fields
                        .get("parent_process")
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown");
                    let setuid_bit = event
                        .fields
                        .get("setuid_bit")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false);
                    let setgid_bit = event
                        .fields
                        .get("setgid_bit")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false);
                    let kernel_exec_uid_change = event
                        .fields
                        .get("kernel_exec_uid_change")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false);
                    let kernel_exec_gid_change = event
                        .fields
                        .get("kernel_exec_gid_change")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false);
                    let credential_source = event
                        .fields
                        .get("credential_source")
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown");
                    if via_broker
                        || setuid_bit
                        || setgid_bit
                        || kernel_exec_uid_change
                        || kernel_exec_gid_change
                    {
                        matches.push(RuleMatch {
                            rule_id: "TG-R016".to_string(),
                            entity_key: process.entity_key.clone(),
                            severity: Severity::High,
                            why_matched: format!(
                                "observed exec credential commit via {} using parent {}",
                                if via_broker {
                                    "privilege broker"
                                } else if kernel_exec_uid_change || kernel_exec_gid_change {
                                    credential_source
                                } else {
                                    "setuid/setgid binary"
                                },
                                parent_process
                            ),
                            evidence_refs: evidence_refs(
                                events_by_entity,
                                &process.entity_key,
                                [event.event_id.clone()],
                            ),
                            facts: fields([
                                ("parent_process", json!(parent_process)),
                                ("via_privilege_broker", json!(via_broker)),
                                ("setuid_bit", json!(setuid_bit)),
                                ("setgid_bit", json!(setgid_bit)),
                                ("kernel_exec_uid_change", json!(kernel_exec_uid_change)),
                                ("kernel_exec_gid_change", json!(kernel_exec_gid_change)),
                                ("credential_source", json!(credential_source)),
                                ("current_user", json!(process.user)),
                            ]),
                        });
                        saw_exec_commit = true;
                    }
                }

                if !saw_capset && syscall == "capset" {
                    let caps = event
                        .fields
                        .get("capability_summary")
                        .and_then(|value| value.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if !caps.is_empty() {
                        matches.push(RuleMatch {
                            rule_id: "TG-R017".to_string(),
                            entity_key: process.entity_key.clone(),
                            severity: Severity::High,
                            why_matched: format!(
                                "observed capset enabling high-risk capabilities via {}",
                                syscall
                            ),
                            evidence_refs: evidence_refs(
                                events_by_entity,
                                &process.entity_key,
                                [event.event_id.clone()],
                            ),
                            facts: fields([
                                ("capability_summary", json!(caps)),
                                ("target_pid", json!(event.fields.get("target_pid"))),
                                ("current_user", json!(process.user)),
                            ]),
                        });
                        saw_capset = true;
                    }
                }
            }
        }

        matches
    }

    fn rule_miner_like(
        &self,
        app: &AppConfig,
        platform: Platform,
        process: &ProcessIdentity,
        net_by_entity: &HashMap<String, Vec<&NetConnection>>,
        persistence_by_entity: &HashMap<String, Vec<&common_model::PersistenceArtifact>>,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let display_name = process.display_name().to_lowercase();
        let cmdline_joined = process.cmdline.join(" ").to_lowercase();
        let name_hit = self
            .config
            .miner_process_names
            .iter()
            .find(|item| display_name == item.to_lowercase());
        let keyword_hit = self
            .config
            .miner_cmdline_keywords
            .iter()
            .find(|item| cmdline_joined.contains(&item.to_lowercase()));
        let miner_connections = net_by_entity
            .get(&process.entity_key)
            .map(|connections| {
                connections
                    .iter()
                    .filter(|connection| is_miner_pool_connection(&self.config, connection))
                    .copied()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let network_hits = miner_connections
            .iter()
            .map(|connection| connection.remote_addr.clone())
            .collect::<Vec<_>>();
        let network_namespaces = miner_connections
            .iter()
            .filter_map(|connection| connection.net_namespace.clone())
            .collect::<Vec<_>>();
        let network_sources = miner_connections
            .iter()
            .filter_map(|connection| connection.observation_source.clone())
            .collect::<Vec<_>>();
        let network_inodes = miner_connections
            .iter()
            .filter_map(|connection| connection.socket_inode)
            .collect::<Vec<_>>();
        let persistence_hits = persistence_by_entity
            .get(&process.entity_key)
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.location.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let risky_origin = process
            .exe
            .as_deref()
            .and_then(|exe| first_risk_dir(app, platform, exe))
            .is_some();

        let mut matches = Vec::new();
        if let Some(hit) = name_hit.or(keyword_hit) {
            matches.push(RuleMatch {
                rule_id: "TG-M001".to_string(),
                entity_key: process.entity_key.clone(),
                severity: if risky_origin {
                    Severity::High
                } else {
                    Severity::Medium
                },
                why_matched: format!(
                    "process shows miner-like executable or command-line trait `{hit}`"
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &process.entity_key,
                    process.exe.clone().into_iter(),
                ),
                facts: fields([
                    ("display_name", json!(display_name)),
                    ("cmdline", json!(process.cmdline)),
                    ("risky_origin", json!(risky_origin)),
                ]),
            });
        }

        if !network_hits.is_empty() {
            matches.push(RuleMatch {
                rule_id: "TG-M002".to_string(),
                entity_key: process.entity_key.clone(),
                severity: Severity::High,
                why_matched: format!(
                    "process connected to miner-like pool endpoint(s): {}",
                    network_hits.join(", ")
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &process.entity_key,
                    network_hits.clone(),
                ),
                facts: fields([
                    ("remote_endpoints", json!(network_hits.clone())),
                    ("miner_pool_ports", json!(self.config.miner_pool_ports)),
                    ("net_namespaces", json!(network_namespaces.clone())),
                    ("observation_sources", json!(network_sources.clone())),
                    ("socket_inodes", json!(network_inodes.clone())),
                ]),
            });
        }

        if !network_hits.is_empty() && !network_namespaces.is_empty() {
            matches.push(RuleMatch {
                rule_id: "TG-M004".to_string(),
                entity_key: process.entity_key.clone(),
                severity: if risky_origin || name_hit.is_some() || keyword_hit.is_some() {
                    Severity::Critical
                } else {
                    Severity::High
                },
                why_matched: format!(
                    "miner-like pool connection is attributed by per-process socket evidence inside netns {}",
                    network_namespaces.join(", ")
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &process.entity_key,
                    network_hits
                        .clone()
                        .into_iter()
                        .chain(network_namespaces.clone()),
                ),
                facts: fields([
                    ("remote_endpoints", json!(network_hits.clone())),
                    ("net_namespaces", json!(network_namespaces.clone())),
                    ("observation_sources", json!(network_sources.clone())),
                    ("socket_inodes", json!(network_inodes.clone())),
                ]),
            });
        }

        if (name_hit.is_some() || keyword_hit.is_some()) && !network_hits.is_empty() {
            matches.push(RuleMatch {
                rule_id: "TG-M003".to_string(),
                entity_key: process.entity_key.clone(),
                severity: if risky_origin || !persistence_hits.is_empty() {
                    Severity::Critical
                } else {
                    Severity::High
                },
                why_matched:
                    "process combines miner-like binary traits with pool-like network activity"
                        .to_string(),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &process.entity_key,
                    process
                        .exe
                        .clone()
                        .into_iter()
                        .chain(network_hits.clone())
                        .chain(persistence_hits.clone()),
                ),
                facts: fields([
                    ("exe", json!(process.exe)),
                    ("cmdline", json!(process.cmdline)),
                    ("remote_endpoints", json!(network_hits.clone())),
                    ("net_namespaces", json!(network_namespaces.clone())),
                    ("observation_sources", json!(network_sources.clone())),
                    ("socket_inodes", json!(network_inodes.clone())),
                    ("persistence_locations", json!(persistence_hits)),
                    ("risky_origin", json!(risky_origin)),
                ]),
            });
        }

        matches
    }

    fn rule_auth_activity(
        &self,
        host: &common_model::HostInfo,
        events_by_entity: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let mut failed_by_user_host = HashMap::<(String, String), usize>::new();
        for record in &host.failed_logins {
            let user = record.user.clone().unwrap_or_else(|| "unknown".to_string());
            let peer = record.host.clone().unwrap_or_else(|| "-".to_string());
            *failed_by_user_host.entry((user, peer)).or_default() += 1;
        }

        for ((user, peer), count) in failed_by_user_host {
            if count < self.config.failed_login_burst_threshold {
                continue;
            }
            let severity = if is_privileged_user(&user) {
                Severity::High
            } else {
                Severity::Medium
            };
            matches.push(RuleMatch {
                rule_id: "TG-R018".to_string(),
                entity_key: host.host_id.clone(),
                severity,
                why_matched: format!(
                    "repeated failed logins observed for user {} from {} ({} attempts)",
                    user, peer, count
                ),
                evidence_refs: evidence_refs(
                    events_by_entity,
                    &host.host_id,
                    [user.clone(), peer.clone()],
                ),
                facts: fields([
                    ("user", json!(user)),
                    ("peer", json!(peer)),
                    ("attempt_count", json!(count)),
                ]),
            });
        }

        for record in &host.recent_logins {
            let Some(user) = record.user.as_deref() else {
                continue;
            };
            let Some(peer) = record.host.as_deref() else {
                continue;
            };
            if is_privileged_user(user) && is_remote_peer(peer) {
                matches.push(RuleMatch {
                    rule_id: "TG-R019".to_string(),
                    entity_key: host.host_id.clone(),
                    severity: Severity::High,
                    why_matched: format!(
                        "remote privileged login observed for user {} from {}",
                        user, peer
                    ),
                    evidence_refs: evidence_refs(
                        events_by_entity,
                        &host.host_id,
                        [user.to_string(), peer.to_string()],
                    ),
                    facts: fields([
                        ("user", json!(user)),
                        ("peer", json!(peer)),
                        ("terminal", json!(record.terminal)),
                        ("login_time", json!(record.login_time)),
                    ]),
                });
            }
        }

        matches
    }
}

fn dedup_matches(matches: Vec<RuleMatch>) -> Vec<RuleMatch> {
    let mut seen = HashMap::new();
    for item in matches {
        let key = format!(
            "{}::{}::{}",
            item.rule_id, item.entity_key, item.why_matched
        );
        seen.entry(key).or_insert(item);
    }
    let mut values = seen.into_values().collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    values
}

fn group_net_by_entity<'a>(
    connections: &'a [NetConnection],
) -> HashMap<String, Vec<&'a NetConnection>> {
    let mut map = HashMap::new();
    for connection in connections {
        map.entry(connection.entity_key.clone())
            .or_insert_with(Vec::new)
            .push(connection);
    }
    map
}

fn evidence_refs(
    events_by_entity: &HashMap<String, Vec<String>>,
    entity_key: &str,
    extras: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut refs = events_by_entity
        .get(entity_key)
        .cloned()
        .unwrap_or_default();
    refs.extend(extras);
    refs.sort();
    refs.dedup();
    refs
}

fn first_risk_dir(app: &AppConfig, platform: Platform, path: &str) -> Option<String> {
    let risk_dirs = match platform {
        Platform::Linux => &app.collection.linux.risk_dirs,
        Platform::Windows => &app.collection.windows.risk_dirs,
        Platform::Unknown => return None,
    };
    let lower = path.to_lowercase();
    risk_dirs.iter().find_map(|item| {
        let dir = expand_path_template(item);
        let prefix = dir.to_string_lossy().to_lowercase();
        lower.starts_with(&prefix).then(|| prefix)
    })
}

fn is_under_trusted_dir(app: &AppConfig, platform: Platform, path: &str) -> bool {
    let trusted = match platform {
        Platform::Linux => &app.collection.linux.trusted_system_dirs,
        Platform::Windows => &app.collection.windows.trusted_system_dirs,
        Platform::Unknown => return false,
    };
    let lower = path.to_lowercase();
    trusted.iter().any(|item| {
        let dir = expand_path_template(item);
        lower.starts_with(&dir.to_string_lossy().to_lowercase())
    })
}

fn parse_port(addr: &str) -> Option<u16> {
    if let Some((_, port)) = addr.rsplit_once(':') {
        return port.parse::<u16>().ok();
    }
    None
}

fn is_miner_pool_connection(config: &RuleConfig, connection: &NetConnection) -> bool {
    let remote = connection.remote_addr.to_lowercase();
    let dns = connection
        .dns_name
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    parse_port(&connection.remote_addr)
        .map(|port| config.miner_pool_ports.contains(&port))
        .unwrap_or(false)
        || config.miner_pool_indicators.iter().any(|item| {
            let item = item.to_lowercase();
            remote.contains(&item) || dns.contains(&item)
        })
}

fn is_privileged_user(user: &str) -> bool {
    let lower = user.to_lowercase();
    lower == "root"
        || lower == "system"
        || lower == "administrator"
        || lower.ends_with("\\administrator")
}

fn is_remote_peer(peer: &str) -> bool {
    let lower = peer.trim().to_lowercase();
    !(lower.is_empty()
        || lower == "-"
        || lower == "localhost"
        || lower == "127.0.0.1"
        || lower == "::1"
        || lower == "0.0.0.0")
}

fn is_privileged_id(value: u32) -> bool {
    value == 0
}

fn field_as_u32(event: &Event, key: &str) -> Option<u32> {
    event
        .fields
        .get(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use common_model::{
        AppConfig, Direction, Event, EventSource, EventType, EvidenceDataset, FileArtifact, FileOp,
        HostInfo, LoginRecord, NetConnection, Platform, ProcessIdentity, Severity as EventSeverity,
        host_entity_key,
    };

    use super::*;

    #[test]
    fn matches_high_risk_executable_rule() {
        let ts = Utc::now();
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_entity_key(Platform::Linux, "demo"),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            processes: vec![ProcessIdentity {
                entity_key: "linux:11:1".into(),
                pid: 11,
                ppid: 10,
                start_time: ts,
                exe: Some("/tmp/svchost.exe".into()),
                cmdline: vec![],
                cwd: None,
                user: Some("demo".into()),
                hash_sha256: None,
                signer: None,
                fd_count: None,
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec![],
                first_seen: ts,
                last_seen: ts,
                is_running: true,
            }],
            net_connections: vec![NetConnection {
                entity_key: "linux:11:1".into(),
                protocol: "tcp".into(),
                local_addr: "10.0.0.2:51514".into(),
                remote_addr: "8.8.8.8:443".into(),
                dns_name: None,
                direction: Direction::Outbound,
                state: Some("established".into()),
                net_namespace: None,
                observation_source: Some("host_netstat".into()),
                socket_inode: None,
                ts,
            }],
            file_artifacts: vec![FileArtifact {
                entity_key: "linux:11:1".into(),
                category: "process_executable".into(),
                path: "/tmp/svchost.exe".into(),
                file_id: None,
                op: FileOp::Create,
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
                is_elf: true,
                content_ref: None,
                notes: vec![],
                ts,
            }],
            persistence_artifacts: vec![],
            events: vec![],
            rule_matches: vec![],
        };
        let mut config = AppConfig::default();
        config.collection.linux.risk_dirs = vec!["/tmp".into()];
        let engine = RuleEngine::new(RuleConfig::default());
        let results = engine.evaluate(&config, &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-R001"));
        assert!(results.iter().any(|item| item.rule_id == "TG-R007"));
    }

    #[test]
    fn matches_real_privilege_change_rule() {
        let ts = Utc::now();
        let entity_key = "linux:22:1".to_string();
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_entity_key(Platform::Linux, "demo"),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            processes: vec![ProcessIdentity {
                entity_key: entity_key.clone(),
                pid: 22,
                ppid: 1,
                start_time: ts,
                exe: Some("/usr/bin/sudo".into()),
                cmdline: vec!["sudo".into()],
                cwd: None,
                user: Some("root".into()),
                hash_sha256: None,
                signer: None,
                fd_count: None,
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec![],
                first_seen: ts,
                last_seen: ts,
                is_running: true,
            }],
            events: vec![Event::new(
                ts,
                Some(1),
                EventSource::Ebpf,
                EventType::PrivilegeChange,
                entity_key.clone(),
                None,
                EventSeverity::High,
                fields([
                    ("syscall", json!("setresuid")),
                    ("old_uid", json!(1000)),
                    ("new_uid", json!(0)),
                ]),
            )],
            ..EvidenceDataset::default()
        };
        let engine = RuleEngine::new(RuleConfig::default());
        let results = engine.evaluate(&AppConfig::default(), &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-R015"));
    }

    #[test]
    fn matches_exec_credential_commit_rule() {
        let ts = Utc::now();
        let entity_key = "linux:30:1".to_string();
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_entity_key(Platform::Linux, "demo"),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            processes: vec![ProcessIdentity {
                entity_key: entity_key.clone(),
                pid: 30,
                ppid: 1,
                start_time: ts,
                exe: Some("/usr/bin/id".into()),
                cmdline: vec!["id".into()],
                cwd: None,
                user: Some("root".into()),
                hash_sha256: None,
                signer: None,
                fd_count: None,
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec![],
                first_seen: ts,
                last_seen: ts,
                is_running: true,
            }],
            events: vec![Event::new(
                ts,
                Some(2),
                EventSource::Ebpf,
                EventType::PrivilegeChange,
                entity_key.clone(),
                None,
                EventSeverity::High,
                fields([
                    ("syscall", json!("exec_credential_commit")),
                    ("old_user", json!("demo")),
                    ("old_uid", json!(1000)),
                    ("old_gid", json!(1000)),
                    ("new_user", json!("root")),
                    ("new_uid", json!(0)),
                    ("new_gid", json!(0)),
                    ("via_privilege_broker", json!(true)),
                    ("parent_process", json!("sudo")),
                    ("setuid_bit", json!(true)),
                    ("kernel_exec_uid_change", json!(true)),
                    ("credential_source", json!("sched_process_exec")),
                ]),
            )],
            ..EvidenceDataset::default()
        };
        let engine = RuleEngine::new(RuleConfig::default());
        let results = engine.evaluate(&AppConfig::default(), &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-R015"));
        assert!(results.iter().any(|item| item.rule_id == "TG-R016"));
    }

    #[test]
    fn matches_capset_rule() {
        let ts = Utc::now();
        let entity_key = "linux:31:1".to_string();
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_entity_key(Platform::Linux, "demo"),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            processes: vec![ProcessIdentity {
                entity_key: entity_key.clone(),
                pid: 31,
                ppid: 1,
                start_time: ts,
                exe: Some("/usr/bin/python3".into()),
                cmdline: vec!["python3".into()],
                cwd: None,
                user: Some("root".into()),
                hash_sha256: None,
                signer: None,
                fd_count: None,
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec![],
                first_seen: ts,
                last_seen: ts,
                is_running: true,
            }],
            events: vec![Event::new(
                ts,
                Some(3),
                EventSource::Ebpf,
                EventType::PrivilegeChange,
                entity_key.clone(),
                None,
                EventSeverity::High,
                fields([
                    ("syscall", json!("capset")),
                    (
                        "capability_summary",
                        json!(["cap_sys_admin", "cap_net_admin"]),
                    ),
                    ("target_pid", json!(31)),
                ]),
            )],
            ..EvidenceDataset::default()
        };
        let engine = RuleEngine::new(RuleConfig::default());
        let results = engine.evaluate(&AppConfig::default(), &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-R017"));
    }

    #[test]
    fn matches_miner_like_rules() {
        let ts = Utc::now();
        let entity_key = "linux:32:1".to_string();
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_entity_key(Platform::Linux, "demo"),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            processes: vec![ProcessIdentity {
                entity_key: entity_key.clone(),
                pid: 32,
                ppid: 1,
                start_time: ts,
                exe: Some("/tmp/simulated-miner".into()),
                cmdline: vec![
                    "/tmp/simulated-miner".into(),
                    "--url".into(),
                    "stratum+tcp://pool.example:3333".into(),
                ],
                cwd: Some("/tmp".into()),
                user: Some("demo".into()),
                hash_sha256: None,
                signer: None,
                fd_count: None,
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec![],
                first_seen: ts,
                last_seen: ts,
                is_running: true,
            }],
            net_connections: vec![NetConnection {
                entity_key: entity_key.clone(),
                protocol: "tcp".into(),
                local_addr: "10.0.0.5:52525".into(),
                remote_addr: "198.51.100.7:3333".into(),
                dns_name: Some("stratum.pool.example".into()),
                direction: Direction::Outbound,
                state: Some("established".into()),
                net_namespace: Some("net:[4026533082]".into()),
                observation_source: Some("proc_pid_net".into()),
                socket_inode: Some(3946409),
                ts,
            }],
            persistence_artifacts: vec![],
            file_artifacts: vec![],
            events: vec![],
            rule_matches: vec![],
        };
        let mut config = RuleConfig::default();
        config.miner_process_names = vec!["simulated-miner".into()];
        config.miner_cmdline_keywords = vec!["stratum+tcp".into(), "--url".into()];
        config.miner_pool_indicators = vec!["pool.example".into(), "stratum".into()];
        let engine = RuleEngine::new(config);
        let results = engine.evaluate(&AppConfig::default(), &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-M001"));
        assert!(results.iter().any(|item| item.rule_id == "TG-M002"));
        assert!(results.iter().any(|item| item.rule_id == "TG-M003"));
        assert!(results.iter().any(|item| item.rule_id == "TG-M004"));
    }

    #[test]
    fn matches_failed_login_burst_rule() {
        let ts = Utc::now();
        let host_id = host_entity_key(Platform::Linux, "demo");
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_id.clone(),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![],
                failed_logins: vec![
                    LoginRecord {
                        user: Some("root".into()),
                        terminal: Some("ssh:notty".into()),
                        host: Some("203.0.113.77".into()),
                        login_time: Some(ts),
                        logout_time: None,
                        status: Some("failed".into()),
                        source: "lastb".into(),
                    };
                    3
                ],
                user_accounts: vec![],
                groups: vec![],
            }),
            ..EvidenceDataset::default()
        };
        let results =
            RuleEngine::new(RuleConfig::default()).evaluate(&AppConfig::default(), &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-R018"));
    }

    #[test]
    fn matches_remote_privileged_login_rule() {
        let ts = Utc::now();
        let host_id = host_entity_key(Platform::Linux, "demo");
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_id.clone(),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![LoginRecord {
                    user: Some("root".into()),
                    terminal: Some("pts/1".into()),
                    host: Some("198.51.100.20".into()),
                    login_time: Some(ts),
                    logout_time: None,
                    status: Some("still logged in".into()),
                    source: "last".into(),
                }],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            ..EvidenceDataset::default()
        };
        let results =
            RuleEngine::new(RuleConfig::default()).evaluate(&AppConfig::default(), &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-R019"));
    }

    #[test]
    fn matches_hidden_exec_and_sensitive_auth_file_rules() {
        let ts = Utc::now();
        let host_id = host_entity_key(Platform::Linux, "demo");
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: host_id.clone(),
                hostname: "demo".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: None,
                timezone: None,
                environment_summary: Default::default(),
                current_user: None,
                interfaces: vec![],
                mounts: vec![],
                disks: vec![],
                routes: vec![],
                dns: Default::default(),
                hosts_entries: vec![],
                neighbors: vec![],
                firewall_rules: vec![],
                current_online_users: vec![],
                recent_logins: vec![],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            file_artifacts: vec![
                FileArtifact {
                    entity_key: host_id.clone(),
                    category: "risk_scan".into(),
                    path: "/tmp/.hidden-x".into(),
                    file_id: None,
                    op: FileOp::Observed,
                    sha256: None,
                    size: Some(128),
                    owner: Some("demo".into()),
                    group: Some("demo".into()),
                    mode: Some("4755".into()),
                    mtime: Some(ts),
                    ctime: Some(ts),
                    atime: None,
                    is_hidden: true,
                    is_suid: true,
                    is_sgid: false,
                    is_executable: true,
                    is_elf: true,
                    content_ref: Some("collected_files/demo".into()),
                    notes: vec![],
                    ts,
                },
                FileArtifact {
                    entity_key: host_id.clone(),
                    category: "auth_file".into(),
                    path: "/root/.ssh/authorized_keys".into(),
                    file_id: None,
                    op: FileOp::Observed,
                    sha256: None,
                    size: Some(128),
                    owner: Some("root".into()),
                    group: Some("root".into()),
                    mode: Some("0600".into()),
                    mtime: Some(ts),
                    ctime: Some(ts),
                    atime: None,
                    is_hidden: false,
                    is_suid: false,
                    is_sgid: false,
                    is_executable: false,
                    is_elf: false,
                    content_ref: Some("collected_files/auth".into()),
                    notes: vec!["recently_modified".into()],
                    ts,
                },
            ],
            ..EvidenceDataset::default()
        };
        let results =
            RuleEngine::new(RuleConfig::default()).evaluate(&AppConfig::default(), &dataset);
        assert!(results.iter().any(|item| item.rule_id == "TG-R020"));
        assert!(results.iter().any(|item| item.rule_id == "TG-R021"));
        assert!(results.iter().any(|item| item.rule_id == "TG-R023"));
    }
}
