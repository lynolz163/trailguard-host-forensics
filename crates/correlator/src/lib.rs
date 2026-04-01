use std::collections::{BTreeSet, HashMap};

use anyhow::Result;
use chrono::{DateTime, Utc};
use common_model::{
    AnalysisBundle, CorrelatedChain, EvidenceDataset, HostOverview, ProcessIdentity, ProcessNode,
    RuleMatch, Severity, SuspiciousProcess, TimelineEntry,
};
use uuid::Uuid;

/// Correlates raw evidence and explainable rule hits into operator-facing chains.
pub struct Correlator {
    top_n: usize,
}

impl Correlator {
    pub fn new(top_n: usize) -> Self {
        Self { top_n }
    }

    pub fn analyze(
        &self,
        dataset: EvidenceDataset,
        rule_matches: Vec<RuleMatch>,
    ) -> Result<AnalysisBundle> {
        let process_map = dataset
            .processes
            .iter()
            .map(|process| (process.entity_key.clone(), process.clone()))
            .collect::<HashMap<_, _>>();
        let parent_lookup = parent_lookup(&dataset.processes);
        let rules_by_entity = group_rules_by_entity(&rule_matches);
        let process_tree = build_process_tree(&dataset.processes, &parent_lookup);
        let suspicious_processes =
            build_suspicious_processes(&dataset, &rules_by_entity, &self.top_n);
        let top_chains = build_chains(
            &dataset,
            &process_map,
            &parent_lookup,
            &rules_by_entity,
            &suspicious_processes,
        );
        let timeline = build_timeline(&dataset, &rule_matches);
        let host = dataset.host.clone();
        let host_overview = HostOverview {
            hostname: host
                .as_ref()
                .map(|item| item.hostname.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            platform: host
                .as_ref()
                .map(|item| item.platform)
                .unwrap_or(common_model::Platform::Unknown),
            process_count: dataset.processes.len(),
            event_count: dataset.events.len(),
            suspicious_processes: suspicious_processes.len(),
            rule_match_count: rule_matches.len(),
            listening_ports: dataset
                .net_connections
                .iter()
                .filter(|connection| {
                    connection.state.as_deref() == Some("listen")
                        || connection.remote_addr.ends_with(":0")
                        || connection.remote_addr == "0.0.0.0:0"
                        || connection.remote_addr == "[::]:0"
                })
                .count(),
            remote_ip_count: dataset
                .net_connections
                .iter()
                .map(|connection| connection.remote_addr.clone())
                .collect::<BTreeSet<_>>()
                .len(),
            collected_file_count: dataset.file_artifacts.len(),
        };

        Ok(AnalysisBundle {
            host_overview,
            suspicious_processes,
            top_chains,
            timeline,
            process_tree,
            rule_matches,
            dataset,
        })
    }
}

fn build_process_tree(
    processes: &[ProcessIdentity],
    parent_lookup: &HashMap<String, Option<String>>,
) -> Vec<ProcessNode> {
    let mut children = HashMap::<String, Vec<String>>::new();
    for (child, parent) in parent_lookup {
        if let Some(parent) = parent {
            children
                .entry(parent.clone())
                .or_default()
                .push(child.clone());
        }
    }

    let mut nodes = processes
        .iter()
        .map(|process| ProcessNode {
            entity_key: process.entity_key.clone(),
            parent_entity_key: parent_lookup.get(&process.entity_key).cloned().flatten(),
            pid: process.pid,
            ppid: process.ppid,
            name: process.display_name(),
            start_time: process.start_time,
            children: children.remove(&process.entity_key).unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    nodes.sort_by_key(|node| node.start_time);
    nodes
}

fn build_suspicious_processes(
    dataset: &EvidenceDataset,
    rules_by_entity: &HashMap<String, Vec<RuleMatch>>,
    top_n: &usize,
) -> Vec<SuspiciousProcess> {
    let net_count = dataset.net_connections.iter().fold(
        HashMap::<String, usize>::new(),
        |mut acc, connection| {
            *acc.entry(connection.entity_key.clone()).or_default() += 1;
            acc
        },
    );
    let file_count =
        dataset
            .file_artifacts
            .iter()
            .fold(HashMap::<String, usize>::new(), |mut acc, artifact| {
                *acc.entry(artifact.entity_key.clone()).or_default() += 1;
                acc
            });
    let persistence_count = dataset.persistence_artifacts.iter().fold(
        HashMap::<String, usize>::new(),
        |mut acc, artifact| {
            *acc.entry(artifact.entity_key.clone()).or_default() += 1;
            acc
        },
    );

    let mut suspicious = dataset
        .processes
        .iter()
        .filter_map(|process| {
            let rules = rules_by_entity.get(&process.entity_key)?;
            let max_severity = rules
                .iter()
                .map(|rule| rule.severity)
                .max()
                .unwrap_or(Severity::Info);
            let base = rules.iter().map(|rule| rule.severity.score()).sum::<u32>();
            let bonus = (net_count
                .get(&process.entity_key)
                .copied()
                .unwrap_or_default() as u32
                * 5)
                + (file_count
                    .get(&process.entity_key)
                    .copied()
                    .unwrap_or_default() as u32
                    * 4)
                + (persistence_count
                    .get(&process.entity_key)
                    .copied()
                    .unwrap_or_default() as u32
                    * 8);
            let risk_score = (base + bonus).min(100);
            Some(SuspiciousProcess {
                entity_key: process.entity_key.clone(),
                display_name: process.display_name(),
                risk_score,
                severity: max_severity,
                reasons: rules.iter().map(|rule| rule.why_matched.clone()).collect(),
                evidence_refs: rules
                    .iter()
                    .flat_map(|rule| rule.evidence_refs.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            })
        })
        .collect::<Vec<_>>();

    suspicious.sort_by(|left, right| {
        right
            .risk_score
            .cmp(&left.risk_score)
            .then_with(|| right.severity.cmp(&left.severity))
    });
    suspicious.truncate(*top_n);
    suspicious
}

fn build_chains(
    dataset: &EvidenceDataset,
    process_map: &HashMap<String, ProcessIdentity>,
    parent_lookup: &HashMap<String, Option<String>>,
    rules_by_entity: &HashMap<String, Vec<RuleMatch>>,
    suspicious_processes: &[SuspiciousProcess],
) -> Vec<CorrelatedChain> {
    suspicious_processes
        .iter()
        .filter_map(|suspicious| {
            let process = process_map.get(&suspicious.entity_key)?;
            let mut process_keys = ancestor_chain(&process.entity_key, process_map, parent_lookup);
            process_keys.push(process.entity_key.clone());
            let mut seen = BTreeSet::new();
            process_keys.retain(|key| seen.insert(key.clone()));

            let file_paths = dataset
                .file_artifacts
                .iter()
                .filter(|artifact| process_keys.contains(&artifact.entity_key))
                .map(|artifact| artifact.path.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let remote_endpoints = dataset
                .net_connections
                .iter()
                .filter(|connection| process_keys.contains(&connection.entity_key))
                .map(|connection| connection.remote_addr.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let persistence_locations = dataset
                .persistence_artifacts
                .iter()
                .filter(|artifact| {
                    process_keys.contains(&artifact.entity_key)
                        || process
                            .exe
                            .as_ref()
                            .map(|exe| artifact.value.contains(exe))
                            .unwrap_or(false)
                })
                .map(|artifact| artifact.location.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let rules = rules_by_entity
                .get(&process.entity_key)
                .cloned()
                .unwrap_or_default();
            let rule_ids = rules
                .iter()
                .map(|rule| rule.rule_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let event_refs = rules
                .iter()
                .flat_map(|rule| rule.evidence_refs.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let start_ts = min_ts(
                std::iter::once(process.start_time)
                    .chain(
                        dataset
                            .file_artifacts
                            .iter()
                            .filter(|artifact| process_keys.contains(&artifact.entity_key))
                            .map(|artifact| artifact.ts),
                    )
                    .chain(
                        dataset
                            .net_connections
                            .iter()
                            .filter(|connection| process_keys.contains(&connection.entity_key))
                            .map(|connection| connection.ts),
                    ),
            )
            .unwrap_or(process.start_time);
            let end_ts = max_ts(
                std::iter::once(process.last_seen)
                    .chain(
                        dataset
                            .file_artifacts
                            .iter()
                            .filter(|artifact| process_keys.contains(&artifact.entity_key))
                            .map(|artifact| artifact.ts),
                    )
                    .chain(
                        dataset
                            .net_connections
                            .iter()
                            .filter(|connection| process_keys.contains(&connection.entity_key))
                            .map(|connection| connection.ts),
                    ),
            )
            .unwrap_or(process.last_seen);
            let summary = suspicious.reasons.join("；");

            Some(CorrelatedChain {
                chain_id: Uuid::new_v4().to_string(),
                title: format!("{} suspicious execution chain", suspicious.display_name),
                summary,
                severity: suspicious.severity,
                risk_score: suspicious.risk_score,
                process_keys,
                file_paths,
                remote_endpoints,
                persistence_locations,
                rule_ids,
                event_refs,
                start_ts,
                end_ts,
            })
        })
        .collect()
}

fn build_timeline(dataset: &EvidenceDataset, rule_matches: &[RuleMatch]) -> Vec<TimelineEntry> {
    let mut timeline = dataset
        .events
        .iter()
        .map(|event| TimelineEntry {
            ts: event.ts_wall,
            label: format!("{:?}: {}", event.event_type, event.entity_key),
            severity: event.severity,
            entity_key: Some(event.entity_key.clone()),
            refs: vec![event.event_id.clone()],
            is_inference: false,
        })
        .collect::<Vec<_>>();

    for artifact in &dataset.file_artifacts {
        if let Some(ctime) = artifact.ctime {
            timeline.push(TimelineEntry {
                ts: ctime,
                label: format!("file ctime [{}]: {}", artifact.category, artifact.path),
                severity: file_artifact_severity(artifact),
                entity_key: Some(artifact.entity_key.clone()),
                refs: vec![artifact.path.clone()],
                is_inference: false,
            });
        }
        if let Some(mtime) = artifact.mtime {
            timeline.push(TimelineEntry {
                ts: mtime,
                label: format!("file mtime [{}]: {}", artifact.category, artifact.path),
                severity: file_artifact_severity(artifact),
                entity_key: Some(artifact.entity_key.clone()),
                refs: vec![artifact.path.clone()],
                is_inference: false,
            });
        }
    }

    for artifact in &dataset.persistence_artifacts {
        timeline.push(TimelineEntry {
            ts: artifact.ts,
            label: format!("persistence {}: {}", artifact.mechanism, artifact.location),
            severity: Severity::Medium,
            entity_key: Some(artifact.entity_key.clone()),
            refs: vec![artifact.location.clone(), artifact.value.clone()],
            is_inference: false,
        });
    }

    if let Some(host) = &dataset.host {
        if let Some(boot_time) = host.boot_time {
            timeline.push(TimelineEntry {
                ts: boot_time,
                label: format!("host boot: {}", host.hostname),
                severity: Severity::Info,
                entity_key: Some(host.host_id.clone()),
                refs: vec![host.hostname.clone()],
                is_inference: false,
            });
        }

        for login in &host.recent_logins {
            if let Some(login_time) = login.login_time {
                timeline.push(TimelineEntry {
                    ts: login_time,
                    label: login_timeline_label("login", login),
                    severity: Severity::Info,
                    entity_key: None,
                    refs: vec![login.source.clone()],
                    is_inference: false,
                });
            }
        }

        for login in &host.failed_logins {
            if let Some(login_time) = login.login_time {
                timeline.push(TimelineEntry {
                    ts: login_time,
                    label: login_timeline_label("failed_login", login),
                    severity: Severity::Medium,
                    entity_key: None,
                    refs: vec![login.source.clone()],
                    is_inference: false,
                });
            }
        }
    }

    let process_lookup = dataset
        .processes
        .iter()
        .map(|process| (process.entity_key.clone(), process))
        .collect::<HashMap<_, _>>();
    for rule in rule_matches {
        let ts = process_lookup
            .get(&rule.entity_key)
            .map(|process| process.last_seen)
            .unwrap_or_else(Utc::now);
        timeline.push(TimelineEntry {
            ts,
            label: format!("{}: {}", rule.rule_id, rule.why_matched),
            severity: rule.severity,
            entity_key: Some(rule.entity_key.clone()),
            refs: rule.evidence_refs.clone(),
            is_inference: true,
        });
    }

    timeline.sort_by(|left, right| {
        left.ts
            .cmp(&right.ts)
            .then_with(|| left.is_inference.cmp(&right.is_inference))
            .then_with(|| left.label.cmp(&right.label))
    });
    timeline
}

fn file_artifact_severity(artifact: &common_model::FileArtifact) -> Severity {
    if artifact.is_suid || artifact.is_sgid {
        Severity::High
    } else if artifact.notes.iter().any(|item| {
        matches!(
            item.as_str(),
            "recently_modified" | "hidden_file" | "web_script" | "sensitive_shadow_file"
        )
    }) {
        Severity::Medium
    } else {
        Severity::Info
    }
}

fn login_timeline_label(prefix: &str, record: &common_model::LoginRecord) -> String {
    let user = record.user.as_deref().unwrap_or("unknown");
    let terminal = record.terminal.as_deref().unwrap_or("-");
    let host = record.host.as_deref().unwrap_or("-");
    format!("{prefix}: user={user} terminal={terminal} host={host}")
}

fn ancestor_chain(
    entity_key: &str,
    process_map: &HashMap<String, ProcessIdentity>,
    parent_lookup: &HashMap<String, Option<String>>,
) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = parent_lookup.get(entity_key).cloned().flatten();
    let mut seen = BTreeSet::new();
    while let Some(key) = current {
        if !seen.insert(key.clone()) {
            break;
        }
        chain.push(key.clone());
        current = parent_lookup.get(&key).cloned().flatten();
        if let Some(candidate) = &current {
            if !process_map.contains_key(candidate) {
                break;
            }
        }
    }
    chain.reverse();
    chain
}

fn parent_lookup(processes: &[ProcessIdentity]) -> HashMap<String, Option<String>> {
    let by_pid = processes
        .iter()
        .map(|process| (process.pid, process.entity_key.clone()))
        .collect::<HashMap<_, _>>();
    processes
        .iter()
        .map(|process| {
            let parent = by_pid.get(&process.ppid).cloned();
            (process.entity_key.clone(), parent)
        })
        .collect()
}

fn group_rules_by_entity(rule_matches: &[RuleMatch]) -> HashMap<String, Vec<RuleMatch>> {
    let mut map = HashMap::new();
    for rule in rule_matches {
        map.entry(rule.entity_key.clone())
            .or_insert_with(Vec::new)
            .push(rule.clone());
    }
    map
}

fn min_ts(values: impl IntoIterator<Item = DateTime<Utc>>) -> Option<DateTime<Utc>> {
    values.into_iter().min()
}

fn max_ts(values: impl IntoIterator<Item = DateTime<Utc>>) -> Option<DateTime<Utc>> {
    values.into_iter().max()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use common_model::{
        EvidenceDataset, FileArtifact, FileOp, HostInfo, LoginRecord, PersistenceArtifact,
        Platform, ProcessIdentity, RuleMatch,
    };

    use super::*;

    #[test]
    fn builds_process_tree() {
        let ts = Utc::now();
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: "host:linux:test".into(),
                hostname: "test".into(),
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
            processes: vec![
                ProcessIdentity {
                    entity_key: "p1".into(),
                    pid: 1,
                    ppid: 0,
                    start_time: ts,
                    exe: Some("/sbin/init".into()),
                    cmdline: vec![],
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
                },
                ProcessIdentity {
                    entity_key: "p2".into(),
                    pid: 2,
                    ppid: 1,
                    start_time: ts,
                    exe: Some("/tmp/payload".into()),
                    cmdline: vec![],
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
                },
            ],
            ..EvidenceDataset::default()
        };
        let correlator = Correlator::new(5);
        let analysis = correlator
            .analyze(
                dataset,
                vec![RuleMatch {
                    rule_id: "R1".into(),
                    entity_key: "p2".into(),
                    severity: Severity::High,
                    why_matched: "test".into(),
                    evidence_refs: vec![],
                    facts: Default::default(),
                }],
            )
            .unwrap();
        let node = analysis
            .process_tree
            .iter()
            .find(|node| node.entity_key == "p1")
            .unwrap();
        assert_eq!(node.children, vec!["p2"]);
    }

    #[test]
    fn builds_extended_timeline() {
        let ts = Utc::now();
        let entity_key = "linux:10:1".to_string();
        let dataset = EvidenceDataset {
            host: Some(HostInfo {
                host_id: "host:linux:test".into(),
                hostname: "test".into(),
                platform: Platform::Linux,
                collected_at: ts,
                collector: "test".into(),
                kernel_version: None,
                os_version: None,
                boot_time: Some(ts),
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
                    user: Some("demo".into()),
                    terminal: Some("pts/0".into()),
                    host: Some("203.0.113.10".into()),
                    login_time: Some(ts),
                    logout_time: None,
                    status: None,
                    source: "last".into(),
                }],
                failed_logins: vec![],
                user_accounts: vec![],
                groups: vec![],
            }),
            processes: vec![ProcessIdentity {
                entity_key: entity_key.clone(),
                pid: 10,
                ppid: 1,
                start_time: ts,
                exe: Some("/tmp/miner".into()),
                cmdline: vec!["/tmp/miner".into()],
                cwd: Some("/tmp".into()),
                user: Some("demo".into()),
                hash_sha256: None,
                signer: None,
                fd_count: Some(4),
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec!["exe_in_risk_dir".into()],
                first_seen: ts,
                last_seen: ts,
                is_running: true,
            }],
            file_artifacts: vec![FileArtifact {
                entity_key: entity_key.clone(),
                category: "risk_scan".into(),
                path: "/tmp/miner".into(),
                file_id: None,
                op: FileOp::Observed,
                sha256: None,
                size: Some(42),
                owner: Some("demo".into()),
                group: Some("demo".into()),
                mode: Some("0755".into()),
                mtime: Some(ts),
                ctime: Some(ts),
                atime: None,
                is_hidden: false,
                is_suid: false,
                is_sgid: false,
                is_executable: true,
                is_elf: true,
                content_ref: None,
                notes: vec!["recently_modified".into()],
                ts,
            }],
            persistence_artifacts: vec![PersistenceArtifact {
                entity_key: entity_key.clone(),
                mechanism: "cron".into(),
                location: "/etc/cron.d/miner".into(),
                value: "/tmp/miner".into(),
                ts,
            }],
            ..EvidenceDataset::default()
        };

        let analysis = Correlator::new(5)
            .analyze(
                dataset,
                vec![RuleMatch {
                    rule_id: "TG-TST".into(),
                    entity_key,
                    severity: Severity::High,
                    why_matched: "test timeline inference".into(),
                    evidence_refs: vec!["evt-1".into()],
                    facts: Default::default(),
                }],
            )
            .unwrap();

        assert!(
            analysis
                .timeline
                .iter()
                .any(|item| item.label.contains("file mtime"))
        );
        assert!(
            analysis
                .timeline
                .iter()
                .any(|item| item.label.contains("login: user=demo"))
        );
        assert!(
            analysis
                .timeline
                .iter()
                .any(|item| item.label.contains("persistence cron"))
        );
        assert!(analysis.timeline.iter().any(|item| item.is_inference));
    }
}
