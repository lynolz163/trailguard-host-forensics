use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    hash::{Hash, Hasher},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
#[cfg(target_os = "linux")]
use collector_linux_ebpf::LinuxEbpfCollector;
#[cfg(target_os = "linux")]
use collector_linux_proc::LinuxProcCollector;
#[cfg(target_os = "windows")]
use collector_windows::WindowsCollector;
use common_model::{
    AppConfig, Event, EventSource, EventType, FileArtifact, FileOp, HostCollector,
    PersistenceArtifact, Platform, Severity, SnapshotBundle, expand_path_template, fields,
    file_fields, filesystem_actor, looks_executable, monitor_note, sha256_file,
};
use correlator::Correlator;
use notify::{EventKind, RecursiveMode, Watcher};
use reporter_html::HtmlReporter;
use rule_engine::{RuleConfig, RuleEngine};
use serde_json::json;
use storage_sqlite::EvidenceStore;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "trailguard",
    version,
    about = "主机异常进程发现与溯源证据链构建工具",
    long_about = "TrailGuard 是防御型本机取证工具，提供快照、近实时监控、规则分析、证据链报告输出。"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    rules: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// 采集主机快照并写入证据包
    Snapshot {
        #[arg(long)]
        output: PathBuf,
    },
    /// 轮询进程/网络并实时监听文件变化
    Monitor {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 300)]
        duration: u64,
    },
    /// 对证据包执行规则分析并输出结构化分析结果
    Analyze {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
    /// 根据数据库生成 HTML 报告与 Mermaid 图
    Report {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        html: PathBuf,
        #[arg(long)]
        graph: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    let config = AppConfig::load_from_file(cli.config.as_deref())?;
    let rules = RuleConfig::load_from_file(cli.rules.as_deref())?;

    match cli.command {
        Commands::Snapshot { output } => run_snapshot(&config, &output),
        Commands::Monitor { output, duration } => run_monitor(&config, &output, duration),
        Commands::Analyze { input, report } => run_analyze(&config, &rules, &input, &report),
        Commands::Report { db, html, graph } => {
            run_report(&config, &rules, &db, &html, graph.as_deref())
        }
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn run_snapshot(config: &AppConfig, output: &Path) -> Result<()> {
    let collector = select_snapshot_collector(config);
    info!("collector backend: {}", collector.backend_name());
    let mut snapshot = collector.collect_snapshot(config)?;
    let mut store = EvidenceStore::create(output, config)?;
    persist_snapshot(&mut store, &mut snapshot, config)?;
    info!("snapshot saved to {}", output.display());
    Ok(())
}

fn run_monitor(config: &AppConfig, output: &Path, duration_secs: u64) -> Result<()> {
    let collector = select_collector(config);
    let platform = collector.platform();
    let notes = collector
        .realtime_notes()
        .into_iter()
        .map(|note| monitor_note(&note))
        .collect::<Vec<_>>();
    for note in notes {
        info!("{note}");
    }

    let mut store = EvidenceStore::create(output, config)?;
    if let Some(bundle) = collector.monitor_native(config, Duration::from_secs(duration_secs))? {
        let mut bundle = bundle;
        persist_snapshot(&mut store, &mut bundle.snapshot, config)?;
        persist_realtime_bundle(&mut store, &mut bundle, config)?;
        info!("native monitor session complete");
        return Ok(());
    }

    let mut baseline = collector.collect_snapshot(config)?;
    persist_snapshot(&mut store, &mut baseline, config)?;
    let watch_actor = filesystem_actor(platform, &baseline.host.hostname);
    let watch_paths = collector.recommended_watch_paths(config);
    let (_watcher, rx) = build_watcher(&watch_paths)?;
    let mut state = SnapshotState::from_snapshot(&baseline);
    let started = Instant::now();

    while started.elapsed() < Duration::from_secs(duration_secs) {
        drain_file_events(
            &mut store,
            rx.as_ref(),
            config,
            &baseline.host.hostname,
            platform,
            &watch_actor,
            started.elapsed(),
        )?;

        thread::sleep(Duration::from_secs(config.collection.poll_interval_secs));
        let current = collector.collect_snapshot(config)?;
        apply_snapshot_diff(&mut store, &mut state, &current, config, started.elapsed())?;
    }

    info!("monitor session complete");
    Ok(())
}

fn run_analyze(
    config: &AppConfig,
    rules: &RuleConfig,
    input: &Path,
    report_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(report_dir)
        .with_context(|| format!("failed to create {}", report_dir.display()))?;
    let db_path = resolve_db_path(input, config);
    let store = EvidenceStore::open_db(&db_path)?;
    let dataset = store.load_dataset()?;
    let engine = RuleEngine::new(rules.clone());
    let matches = engine.evaluate(config, &dataset);
    store.replace_rule_matches(&matches)?;
    let correlator = Correlator::new(config.report.top_chains);
    let mut analysis = correlator.analyze(dataset, matches)?;
    augment_analysis_with_command_logs(&mut analysis, db_path.parent().unwrap_or(Path::new(".")))?;
    fs::write(
        report_dir.join(&config.output.analysis_name),
        serde_json::to_vec_pretty(&analysis)?,
    )?;
    write_timeline_outputs(config, report_dir, &analysis.timeline)?;
    let reporter = HtmlReporter::new(config.report.max_raw_events);
    fs::write(
        report_dir.join(&config.output.graph_name),
        reporter.render_mermaid(&analysis),
    )?;
    info!("analysis artifacts saved to {}", report_dir.display());
    Ok(())
}

fn run_report(
    config: &AppConfig,
    rules: &RuleConfig,
    db: &Path,
    html_path: &Path,
    graph_path: Option<&Path>,
) -> Result<()> {
    if let Some(parent) = html_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let store = EvidenceStore::open_db(db)?;
    let dataset = store.load_dataset()?;
    let engine = RuleEngine::new(rules.clone());
    let matches = engine.evaluate(config, &dataset);
    store.replace_rule_matches(&matches)?;
    let correlator = Correlator::new(config.report.top_chains);
    let mut analysis = correlator.analyze(dataset, matches)?;
    augment_analysis_with_command_logs(&mut analysis, db.parent().unwrap_or(Path::new(".")))?;
    let reporter = HtmlReporter::new(config.report.max_raw_events);
    if let Some(report_dir) = html_path.parent() {
        write_timeline_outputs(config, report_dir, &analysis.timeline)?;
    }
    fs::write(html_path, reporter.render_html(&analysis)?)?;
    let graph_target = graph_path
        .map(Path::to_path_buf)
        .or_else(|| {
            html_path
                .parent()
                .map(|dir| dir.join(&config.output.graph_name))
        })
        .unwrap_or_else(|| PathBuf::from(&config.output.graph_name));
    fs::write(&graph_target, reporter.render_mermaid(&analysis))?;
    info!("report written to {}", html_path.display());
    Ok(())
}

fn select_collector(_config: &AppConfig) -> Box<dyn HostCollector> {
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsCollector)
    }
    #[cfg(target_os = "linux")]
    {
        let ebpf = LinuxEbpfCollector;
        if ebpf.is_available(_config) {
            return Box::new(ebpf);
        }
        Box::new(LinuxProcCollector)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        panic!("unsupported platform")
    }
}

fn select_snapshot_collector(_config: &AppConfig) -> Box<dyn HostCollector> {
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsCollector)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxProcCollector)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        panic!("unsupported platform")
    }
}

fn persist_snapshot(
    store: &mut EvidenceStore,
    snapshot: &mut SnapshotBundle,
    config: &AppConfig,
) -> Result<()> {
    let output_dir = evidence_output_dir(store)?;
    stage_file_artifacts(&output_dir, &mut snapshot.file_artifacts, config)?;
    store.persist_host(&snapshot.host)?;
    for process in &snapshot.processes {
        store.upsert_process(process)?;
    }
    for artifact in &snapshot.file_artifacts {
        store.insert_file_artifact(artifact)?;
    }
    for connection in &snapshot.net_connections {
        store.insert_net_connection(connection)?;
    }
    for artifact in &snapshot.persistence_artifacts {
        store.insert_persistence_artifact(artifact)?;
    }

    let mut events = snapshot_events(snapshot);
    store.append_events(&mut events)?;
    Ok(())
}

fn persist_realtime_bundle(
    store: &mut EvidenceStore,
    bundle: &mut common_model::RealtimeMonitorBundle,
    config: &AppConfig,
) -> Result<()> {
    let output_dir = evidence_output_dir(store)?;
    stage_file_artifacts(&output_dir, &mut bundle.file_artifacts, config)?;
    for process in &bundle.processes {
        store.upsert_process(process)?;
    }
    for connection in &bundle.net_connections {
        store.insert_net_connection(connection)?;
    }
    for artifact in &bundle.file_artifacts {
        store.insert_file_artifact(artifact)?;
    }
    for artifact in &bundle.persistence_artifacts {
        store.insert_persistence_artifact(artifact)?;
    }
    let mut events = bundle.events.clone();
    store.append_events(&mut events)?;
    Ok(())
}

fn snapshot_events(snapshot: &SnapshotBundle) -> Vec<Event> {
    let pid_lookup = snapshot
        .processes
        .iter()
        .map(|process| (process.pid, process.entity_key.clone()))
        .collect::<HashMap<_, _>>();
    let mut events = Vec::new();
    for process in &snapshot.processes {
        events.push(Event::new(
            snapshot.host.collected_at,
            None,
            EventSource::Snapshot,
            EventType::ProcessSnapshot,
            process.entity_key.clone(),
            pid_lookup.get(&process.ppid).cloned(),
            Severity::Info,
            fields([
                ("pid", json!(process.pid)),
                ("ppid", json!(process.ppid)),
                ("exe", json!(process.exe)),
                ("cmdline", json!(process.cmdline)),
                ("cwd", json!(process.cwd)),
                ("user", json!(process.user)),
                ("hash_sha256", json!(process.hash_sha256)),
                ("fd_count", json!(process.fd_count)),
                ("mapped_modules", json!(process.mapped_modules)),
                ("deleted_paths", json!(process.deleted_paths)),
                ("suspicious_flags", json!(process.suspicious_flags)),
            ]),
        ));
    }
    for connection in &snapshot.net_connections {
        events.push(Event::new(
            connection.ts,
            None,
            EventSource::Snapshot,
            EventType::NetConnect,
            connection.entity_key.clone(),
            None,
            Severity::Info,
            network_event_fields(connection),
        ));
    }
    for artifact in &snapshot.file_artifacts {
        events.push(Event::new(
            artifact.ts,
            None,
            EventSource::Snapshot,
            EventType::FileObserved,
            artifact.entity_key.clone(),
            None,
            Severity::Info,
            fields([
                ("category", json!(artifact.category)),
                ("path", json!(artifact.path)),
                ("op", json!(format!("{:?}", artifact.op))),
                ("sha256", json!(artifact.sha256)),
                ("size", json!(artifact.size)),
                ("owner", json!(artifact.owner)),
                ("group", json!(artifact.group)),
                ("mode", json!(artifact.mode)),
                (
                    "mtime",
                    json!(artifact.mtime.map(|value| value.to_rfc3339())),
                ),
                (
                    "ctime",
                    json!(artifact.ctime.map(|value| value.to_rfc3339())),
                ),
                (
                    "atime",
                    json!(artifact.atime.map(|value| value.to_rfc3339())),
                ),
                ("is_hidden", json!(artifact.is_hidden)),
                ("is_suid", json!(artifact.is_suid)),
                ("is_sgid", json!(artifact.is_sgid)),
                ("is_executable", json!(artifact.is_executable)),
                ("is_elf", json!(artifact.is_elf)),
                ("content_ref", json!(artifact.content_ref)),
                ("notes", json!(artifact.notes)),
            ]),
        ));
    }
    for artifact in &snapshot.persistence_artifacts {
        events.push(Event::new(
            artifact.ts,
            None,
            EventSource::Snapshot,
            EventType::PersistenceObserved,
            artifact.entity_key.clone(),
            None,
            Severity::Info,
            fields([
                ("mechanism", json!(artifact.mechanism)),
                ("location", json!(artifact.location)),
                ("value", json!(artifact.value)),
            ]),
        ));
    }
    events.push(Event::new(
        snapshot.host.collected_at,
        None,
        EventSource::Snapshot,
        EventType::SnapshotComplete,
        snapshot.host.host_id.clone(),
        None,
        Severity::Info,
        fields([
            ("process_count", json!(snapshot.processes.len())),
            ("connection_count", json!(snapshot.net_connections.len())),
            (
                "persistence_count",
                json!(snapshot.persistence_artifacts.len()),
            ),
        ]),
    ));
    events
}

fn build_watcher(
    watch_paths: &[PathBuf],
) -> Result<(
    Option<notify::RecommendedWatcher>,
    Option<Receiver<notify::Result<notify::Event>>>,
)> {
    if watch_paths.is_empty() {
        return Ok((None, None));
    }
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |result| {
        let _ = tx.send(result);
    })?;
    for path in watch_paths {
        if let Err(error) = watcher.watch(path, RecursiveMode::Recursive) {
            warn!("failed to watch {}: {error}", path.display());
        }
    }
    Ok((Some(watcher), Some(rx)))
}

fn drain_file_events(
    store: &mut EvidenceStore,
    rx: Option<&Receiver<notify::Result<notify::Event>>>,
    config: &AppConfig,
    hostname: &str,
    platform: Platform,
    watch_actor: &str,
    elapsed: Duration,
) -> Result<()> {
    let Some(rx) = rx else {
        return Ok(());
    };

    while let Ok(result) = rx.try_recv() {
        let event = match result {
            Ok(event) => event,
            Err(error) => {
                warn!("notify error: {error}");
                continue;
            }
        };
        let (event_type, file_op) = map_file_event(&event.kind);
        let Some(event_type) = event_type else {
            continue;
        };
        for path in event.paths {
            let path_str = path.to_string_lossy().into_owned();
            let sha = sha256_file(&path, config.collection.hash_file_limit_mb)
                .ok()
                .flatten();
            let artifact = FileArtifact {
                entity_key: watch_actor.to_string(),
                category: "watch_path".to_string(),
                path: path_str.clone(),
                file_id: None,
                op: file_op.unwrap_or(FileOp::Observed),
                sha256: sha.clone(),
                size: None,
                owner: None,
                group: None,
                mode: None,
                mtime: None,
                ctime: None,
                atime: None,
                is_hidden: path
                    .file_name()
                    .map(|name| name.to_string_lossy().starts_with('.'))
                    .unwrap_or(false),
                is_suid: false,
                is_sgid: false,
                is_executable: looks_executable(&path_str),
                is_elf: path_str.ends_with(".so")
                    || path_str.contains("/bin/")
                    || path_str.contains("/lib/"),
                content_ref: None,
                notes: Vec::new(),
                ts: chrono::Utc::now(),
            };
            store.insert_file_artifact(&artifact)?;
            let mut evidence = Event::new(
                artifact.ts,
                Some(elapsed.as_millis() as u64),
                EventSource::FileWatcher,
                event_type,
                artifact.entity_key.clone(),
                None,
                if looks_executable(&path_str) {
                    Severity::Medium
                } else {
                    Severity::Info
                },
                file_fields(&path_str, sha.as_deref()),
            );
            store.append_event(&mut evidence)?;

            if let Some(persistence) =
                maybe_persistence_artifact(config, hostname, platform, &path_str, artifact.ts)
            {
                store.insert_persistence_artifact(&persistence)?;
                let mut persistence_event = Event::new(
                    persistence.ts,
                    Some(elapsed.as_millis() as u64),
                    EventSource::FileWatcher,
                    EventType::PersistenceCreate,
                    persistence.entity_key.clone(),
                    None,
                    Severity::High,
                    fields([
                        ("mechanism", json!(persistence.mechanism)),
                        ("location", json!(persistence.location)),
                        ("value", json!(persistence.value)),
                    ]),
                );
                store.append_event(&mut persistence_event)?;
            }
        }
    }

    Ok(())
}

fn apply_snapshot_diff(
    store: &mut EvidenceStore,
    state: &mut SnapshotState,
    current: &SnapshotBundle,
    _config: &AppConfig,
    elapsed: Duration,
) -> Result<()> {
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

    for process in current_processes.values() {
        store.upsert_process(process)?;
    }
    for connection in &current.net_connections {
        if state.net_signatures.insert(net_signature(connection)) {
            store.insert_net_connection(connection)?;
            let mut event = Event::new(
                connection.ts,
                Some(elapsed.as_millis() as u64),
                EventSource::NetworkPoller,
                EventType::NetConnect,
                connection.entity_key.clone(),
                None,
                Severity::Info,
                network_event_fields(connection),
            );
            store.append_event(&mut event)?;
        }
    }

    for artifact in &current.persistence_artifacts {
        if state
            .persistence_signatures
            .insert(persistence_signature(artifact))
        {
            store.insert_persistence_artifact(artifact)?;
            let mut event = Event::new(
                artifact.ts,
                Some(elapsed.as_millis() as u64),
                EventSource::PersistenceScanner,
                EventType::PersistenceCreate,
                artifact.entity_key.clone(),
                None,
                Severity::High,
                fields([
                    ("mechanism", json!(artifact.mechanism)),
                    ("location", json!(artifact.location)),
                    ("value", json!(artifact.value)),
                ]),
            );
            store.append_event(&mut event)?;
        }
    }

    for (entity_key, process) in &current_processes {
        if state
            .processes
            .insert(entity_key.clone(), process.clone())
            .is_none()
        {
            let mut event = Event::new(
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
            );
            store.append_event(&mut event)?;
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
            store.upsert_process(&exited)?;
            let mut event = Event::new(
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
            );
            store.append_event(&mut event)?;
        }
    }

    state.processes = current_processes;
    state.net_signatures = current
        .net_connections
        .iter()
        .map(net_signature)
        .collect::<HashSet<_>>();
    state.persistence_signatures = current
        .persistence_artifacts
        .iter()
        .map(persistence_signature)
        .collect::<HashSet<_>>();
    Ok(())
}

fn maybe_persistence_artifact(
    config: &AppConfig,
    hostname: &str,
    platform: Platform,
    path: &str,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<PersistenceArtifact> {
    let path_lower = path.to_lowercase();
    let matches = match platform {
        Platform::Linux => config
            .collection
            .linux
            .persistence_paths
            .iter()
            .any(|item| {
                path_lower.starts_with(&expand_path_template(item).to_string_lossy().to_lowercase())
            }),
        Platform::Windows => config.collection.windows.startup_paths.iter().any(|item| {
            path_lower.starts_with(&expand_path_template(item).to_string_lossy().to_lowercase())
        }),
        Platform::Unknown => false,
    };
    if !matches {
        return None;
    }
    Some(PersistenceArtifact {
        entity_key: filesystem_actor(platform, hostname),
        mechanism: if path_lower.contains("systemd") {
            "systemd"
        } else if path_lower.contains("cron") {
            "cron"
        } else if path_lower.contains("startup") {
            "startup_folder"
        } else if path_lower.contains("\\tasks") {
            "scheduled_task"
        } else {
            "persistence_file"
        }
        .to_string(),
        location: path.to_string(),
        value: path.to_string(),
        ts,
    })
}

fn map_file_event(kind: &EventKind) -> (Option<EventType>, Option<FileOp>) {
    match kind {
        EventKind::Create(_) => (Some(EventType::FileCreate), Some(FileOp::Create)),
        EventKind::Modify(notify::event::ModifyKind::Data(_)) => {
            (Some(EventType::FileWrite), Some(FileOp::Write))
        }
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
            (Some(EventType::Rename), Some(FileOp::Rename))
        }
        EventKind::Modify(_) => (Some(EventType::FileWrite), Some(FileOp::Write)),
        _ => (None, None),
    }
}

fn resolve_db_path(input: &Path, config: &AppConfig) -> PathBuf {
    if input.is_dir() {
        input.join(&config.output.db_name)
    } else {
        input.to_path_buf()
    }
}

fn net_signature(connection: &common_model::NetConnection) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        connection.entity_key,
        connection.protocol,
        connection.local_addr,
        connection.remote_addr,
        connection.state.clone().unwrap_or_default(),
        connection.net_namespace.clone().unwrap_or_default(),
        connection.ts.timestamp()
    )
}

fn network_event_fields(connection: &common_model::NetConnection) -> common_model::FieldMap {
    fields([
        ("protocol", json!(connection.protocol)),
        ("local_addr", json!(connection.local_addr)),
        ("remote_addr", json!(connection.remote_addr)),
        ("state", json!(connection.state)),
        ("net_namespace", json!(connection.net_namespace)),
        ("socket_tuple_source", json!(connection.observation_source)),
        ("socket_inode", json!(connection.socket_inode)),
    ])
}

fn persistence_signature(artifact: &PersistenceArtifact) -> String {
    format!(
        "{}|{}|{}|{}",
        artifact.entity_key, artifact.mechanism, artifact.location, artifact.value
    )
}

fn write_timeline_outputs(
    config: &AppConfig,
    report_dir: &Path,
    timeline: &[common_model::TimelineEntry],
) -> Result<()> {
    fs::create_dir_all(report_dir)
        .with_context(|| format!("failed to create {}", report_dir.display()))?;

    let jsonl_path = report_dir.join(&config.output.timeline_jsonl_name);
    let markdown_path = report_dir.join(&config.output.timeline_markdown_name);

    let mut jsonl = fs::File::create(&jsonl_path)
        .with_context(|| format!("failed to create {}", jsonl_path.display()))?;
    for entry in timeline {
        let category = timeline_category(entry);
        let source = if entry.is_inference {
            "rule_engine"
        } else {
            "evidence"
        };
        let subject = entry
            .entity_key
            .clone()
            .unwrap_or_else(|| "host".to_string());
        let record = json!({
            "timestamp": entry.ts.to_rfc3339(),
            "source": source,
            "category": category,
            "subject": subject,
            "detail": entry.label.clone(),
            "severity": entry.severity.to_string(),
            "refs": entry.refs.clone(),
        });
        serde_json::to_writer(&mut jsonl, &record)?;
        jsonl.write_all(b"\n")?;
    }

    let mut markdown = String::from(
        "# TrailGuard Timeline\n\n| timestamp | source | category | subject | detail | severity |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    for entry in timeline {
        let source = if entry.is_inference {
            "rule_engine"
        } else {
            "evidence"
        };
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            entry.ts.to_rfc3339(),
            source,
            timeline_category(entry),
            entry.entity_key.as_deref().unwrap_or("host"),
            entry.label.replace('|', "\\|"),
            entry.severity
        ));
    }
    fs::write(&markdown_path, markdown)
        .with_context(|| format!("failed to write {}", markdown_path.display()))?;
    Ok(())
}

fn timeline_category(entry: &common_model::TimelineEntry) -> &'static str {
    let lower = entry.label.to_lowercase();
    if lower.contains("file") || lower.contains("mtime") || lower.contains("ctime") {
        "file"
    } else if lower.contains("login")
        || lower.contains("auth")
        || lower.contains("sudo")
        || lower.contains("failed password")
        || lower.contains("sshd")
        || lower.contains("pam_")
    {
        "auth"
    } else if lower.contains("net")
        || lower.contains("connect")
        || lower.contains("dns")
        || lower.contains("resolved")
    {
        "network"
    } else if lower.contains("persist")
        || lower.contains("systemd")
        || lower.contains("cron")
        || lower.contains("timer")
    {
        "persistence"
    } else if lower.contains("dmesg")
        || lower.contains("kernel")
        || lower.contains("segfault")
        || lower.contains("oom")
        || lower.contains("audit")
    {
        "kernel"
    } else if lower.contains("rule") {
        "rule"
    } else {
        "process"
    }
}

fn augment_analysis_with_command_logs(
    analysis: &mut common_model::AnalysisBundle,
    evidence_dir: &Path,
) -> Result<()> {
    let records = load_command_log_records(&analysis.dataset, evidence_dir)?;
    if records.is_empty() {
        return Ok(());
    }
    let mut extra_timeline = command_log_timeline_entries(&records);
    analysis.timeline.append(&mut extra_timeline);
    let extra_matches = derive_command_log_rule_matches(&records);
    if !extra_matches.is_empty() {
        analysis.rule_matches.extend(extra_matches);
        dedup_rule_matches(&mut analysis.rule_matches);
        analysis.host_overview.rule_match_count = analysis.rule_matches.len();
    }
    analysis.timeline.sort_by(|left, right| {
        left.ts
            .cmp(&right.ts)
            .then_with(|| left.is_inference.cmp(&right.is_inference))
            .then_with(|| left.label.cmp(&right.label))
    });
    Ok(())
}

#[derive(Debug, Clone)]
struct CommandLogRecord {
    entity_key: String,
    source_path: String,
    content_ref: String,
    ts: chrono::DateTime<chrono::Utc>,
    line: String,
    severity: Severity,
}

fn load_command_log_records(
    dataset: &common_model::EvidenceDataset,
    evidence_dir: &Path,
) -> Result<Vec<CommandLogRecord>> {
    let mut records = Vec::new();
    for artifact in dataset
        .file_artifacts
        .iter()
        .filter(|artifact| artifact.category == "command_log")
    {
        let Some(content_ref) = artifact.content_ref.as_deref() else {
            continue;
        };
        let path = evidence_dir.join(content_ref);
        if !path.is_file() {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("# trailguard_") {
                continue;
            }
            records.push(CommandLogRecord {
                entity_key: artifact.entity_key.clone(),
                source_path: artifact.path.clone(),
                content_ref: content_ref.to_string(),
                ts: parse_common_log_timestamp(trimmed).unwrap_or(artifact.ts),
                line: trimmed.to_string(),
                severity: command_log_line_severity(trimmed),
            });
        }
    }
    Ok(records)
}

fn command_log_timeline_entries(records: &[CommandLogRecord]) -> Vec<common_model::TimelineEntry> {
    records
        .iter()
        .map(|record| common_model::TimelineEntry {
            ts: record.ts,
            label: format!("{}: {}", record.source_path, record.line),
            severity: record.severity,
            entity_key: Some(record.entity_key.clone()),
            refs: vec![record.source_path.clone(), record.content_ref.clone()],
            is_inference: false,
        })
        .collect()
}

fn derive_command_log_rule_matches(records: &[CommandLogRecord]) -> Vec<common_model::RuleMatch> {
    const AVC_BURST_THRESHOLD: usize = 3;

    let mut grouped = HashMap::<String, Vec<&CommandLogRecord>>::new();
    for record in records {
        grouped
            .entry(record.entity_key.clone())
            .or_default()
            .push(record);
    }

    let mut matches = Vec::new();
    for (entity_key, entity_records) in grouped {
        let privilege_lines = entity_records
            .iter()
            .copied()
            .filter(|record| is_privilege_command_log_line(&record.line))
            .collect::<Vec<_>>();
        if !privilege_lines.is_empty() {
            matches.push(build_command_log_rule_match(
                "TG-L001",
                &entity_key,
                Severity::Medium,
                format!(
                    "privilege brokerage activity observed in command logs ({} line(s))",
                    privilege_lines.len()
                ),
                &privilege_lines,
            ));
        }

        let kernel_lines = entity_records
            .iter()
            .copied()
            .filter(|record| is_kernel_health_command_log_line(&record.line))
            .collect::<Vec<_>>();
        if !kernel_lines.is_empty() {
            let severity = if kernel_lines
                .iter()
                .any(|record| record.line.to_lowercase().contains("panic"))
            {
                Severity::Critical
            } else {
                Severity::High
            };
            matches.push(build_command_log_rule_match(
                "TG-L002",
                &entity_key,
                severity,
                format!(
                    "kernel panic or OOM activity observed in command logs ({} line(s))",
                    kernel_lines.len()
                ),
                &kernel_lines,
            ));
        }

        let fault_lines = entity_records
            .iter()
            .copied()
            .filter(|record| is_fault_command_log_line(&record.line))
            .collect::<Vec<_>>();
        if !fault_lines.is_empty() {
            matches.push(build_command_log_rule_match(
                "TG-L003",
                &entity_key,
                Severity::High,
                format!(
                    "segfault or general protection fault observed in command logs ({} line(s))",
                    fault_lines.len()
                ),
                &fault_lines,
            ));
        }

        let avc_lines = entity_records
            .iter()
            .copied()
            .filter(|record| is_avc_denial_command_log_line(&record.line))
            .collect::<Vec<_>>();
        if avc_lines.len() >= AVC_BURST_THRESHOLD {
            matches.push(build_command_log_rule_match(
                "TG-L004",
                &entity_key,
                Severity::High,
                format!(
                    "audit or AVC denial burst observed in command logs ({} line(s))",
                    avc_lines.len()
                ),
                &avc_lines,
            ));
        }
    }

    dedup_and_sort_rule_matches(matches)
}

fn build_command_log_rule_match(
    rule_id: &str,
    entity_key: &str,
    severity: Severity,
    why_matched: String,
    records: &[&CommandLogRecord],
) -> common_model::RuleMatch {
    let mut ordered = records.to_vec();
    ordered.sort_by_key(|record| record.ts);

    let first_ts = ordered.first().map(|record| record.ts.to_rfc3339());
    let last_ts = ordered.last().map(|record| record.ts.to_rfc3339());
    let sample_lines = ordered
        .iter()
        .take(5)
        .map(|record| truncate_command_log_line(&record.line))
        .collect::<Vec<_>>();
    let source_paths = ordered
        .iter()
        .map(|record| record.source_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let evidence_refs = ordered
        .iter()
        .flat_map(|record| [record.source_path.clone(), record.content_ref.clone()])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    common_model::RuleMatch {
        rule_id: rule_id.to_string(),
        entity_key: entity_key.to_string(),
        severity,
        why_matched,
        evidence_refs,
        facts: fields([
            ("collector", json!("command_log")),
            ("source_paths", json!(source_paths)),
            ("sample_lines", json!(sample_lines)),
            ("line_count", json!(ordered.len())),
            ("first_ts", json!(first_ts)),
            ("last_ts", json!(last_ts)),
        ]),
    }
}

fn dedup_rule_matches(matches: &mut Vec<common_model::RuleMatch>) {
    *matches = dedup_and_sort_rule_matches(std::mem::take(matches));
}

fn dedup_and_sort_rule_matches(
    matches: Vec<common_model::RuleMatch>,
) -> Vec<common_model::RuleMatch> {
    let mut seen = HashSet::new();
    let mut deduped = matches
        .into_iter()
        .filter(|item| {
            seen.insert(format!(
                "{}::{}::{}",
                item.rule_id, item.entity_key, item.why_matched
            ))
        })
        .collect::<Vec<_>>();
    deduped.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.entity_key.cmp(&right.entity_key))
            .then_with(|| left.why_matched.cmp(&right.why_matched))
    });
    deduped
}

fn is_privilege_command_log_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    (lower.contains("sudo")
        || lower.contains("pkexec")
        || lower.contains("pam_unix(su")
        || lower.contains(" su: ")
        || lower.contains("su["))
        && [
            "command=",
            "session opened",
            "session closed",
            "authentication failure",
            "user=root",
            "user root",
            "tty=",
            "incorrect password attempt",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn is_kernel_health_command_log_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    [
        "kernel panic",
        "panic - not syncing",
        "oom-killer",
        "invoked oom-killer",
        "out of memory: killed process",
        "killed process ",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_fault_command_log_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    ["segfault", "general protection fault"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn is_avc_denial_command_log_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("apparmor=\"denied\"")
        || lower.contains("apparmor=\"audit\"")
        || (lower.contains("avc:") && lower.contains("denied"))
        || (lower.contains("audit") && lower.contains("denied"))
}

fn truncate_command_log_line(line: &str) -> String {
    const MAX_CHARS: usize = 180;
    let mut truncated = String::new();
    for (index, ch) in line.chars().enumerate() {
        if index >= MAX_CHARS {
            truncated.push_str("...");
            return truncated;
        }
        truncated.push(ch);
    }
    truncated
}

fn command_log_line_severity(line: &str) -> Severity {
    let lower = line.to_lowercase();
    if [
        "kernel panic",
        "oom-killer",
        "failed password",
        "authentication failure",
        "segfault",
        "audit",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        Severity::High
    } else if [
        "sudo",
        "session opened",
        "session closed",
        "invalid user",
        "refused",
        "denied",
        "error",
        "warn",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        Severity::Medium
    } else {
        Severity::Info
    }
}

fn evidence_output_dir(store: &EvidenceStore) -> Result<PathBuf> {
    let db_path = store.db_path()?;
    db_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("failed to resolve evidence output directory"))
}

fn stage_file_artifacts(
    output_dir: &Path,
    artifacts: &mut [FileArtifact],
    config: &AppConfig,
) -> Result<()> {
    let staged_dir = output_dir.join("collected_files");
    fs::create_dir_all(&staged_dir)
        .with_context(|| format!("failed to create {}", staged_dir.display()))?;

    for artifact in artifacts {
        if artifact.content_ref.is_some() {
            continue;
        }
        let staged = match artifact.category.as_str() {
            "log_file" | "app_log_file" => {
                let source_path = Path::new(&artifact.path);
                if !source_path.is_file() {
                    None
                } else {
                    Some(stage_log_excerpt(
                        &staged_dir,
                        source_path,
                        artifact,
                        config,
                    )?)
                }
            }
            "auth_file" => {
                let source_path = Path::new(&artifact.path);
                if !source_path.is_file() {
                    None
                } else {
                    Some(stage_auth_artifact(
                        &staged_dir,
                        source_path,
                        artifact,
                        config,
                    )?)
                }
            }
            "command_log" => stage_command_artifact(&staged_dir, artifact, config)?,
            _ => None,
        };

        artifact.content_ref = staged;
    }
    Ok(())
}

fn stage_log_excerpt(
    staged_dir: &Path,
    source_path: &Path,
    artifact: &FileArtifact,
    config: &AppConfig,
) -> Result<String> {
    let content = read_tail_bytes(source_path, config.collection.log_max_bytes)?;
    let filtered = filter_log_content_by_time_window(
        &String::from_utf8_lossy(&content),
        config.collection.log_time_window_hours,
    );
    let excerpt = tail_lines(&filtered, config.collection.log_tail_lines);
    let staged_name = format!(
        "log_{}_{}.txt",
        stable_name(&artifact.path),
        stable_name(&artifact.category)
    );
    let staged_path = staged_dir.join(staged_name);
    let payload = format_text_capture(
        &artifact.path,
        &artifact.category,
        "tail_excerpt",
        &excerpt,
        Some(&format!(
            "max_bytes={} tail_lines={} time_window_hours={}",
            config.collection.log_max_bytes,
            config.collection.log_tail_lines,
            config.collection.log_time_window_hours
        )),
    );
    fs::write(&staged_path, payload.as_bytes())
        .with_context(|| format!("failed to write {}", staged_path.display()))?;
    Ok(relative_ref(
        staged_dir.parent().unwrap_or(staged_dir),
        &staged_path,
    ))
}

fn stage_auth_artifact(
    staged_dir: &Path,
    source_path: &Path,
    artifact: &FileArtifact,
    config: &AppConfig,
) -> Result<String> {
    let sensitive = is_sensitive_auth_path(&artifact.path);
    if sensitive && !config.collection.collect_sensitive_content {
        let manifest = json!({
            "source_path": artifact.path,
            "category": artifact.category,
            "collected_at": chrono::Utc::now().to_rfc3339(),
            "copied": false,
            "reason": "sensitive_content_disabled",
            "sha256": artifact.sha256,
        });
        let staged_path = staged_dir.join(format!("meta_{}.json", stable_name(&artifact.path)));
        fs::write(&staged_path, serde_json::to_vec_pretty(&manifest)?)
            .with_context(|| format!("failed to write {}", staged_path.display()))?;
        return Ok(relative_ref(
            staged_dir.parent().unwrap_or(staged_dir),
            &staged_path,
        ));
    }

    let content = read_tail_bytes(source_path, config.collection.log_max_bytes)?;
    let staged_path = staged_dir.join(format!("auth_{}.txt", stable_name(&artifact.path)));
    let payload = format_text_capture(
        &artifact.path,
        &artifact.category,
        "raw_or_tail",
        &String::from_utf8_lossy(&content),
        Some(&format!(
            "max_bytes={} time_window_hours={}",
            config.collection.log_max_bytes, config.collection.log_time_window_hours
        )),
    );
    fs::write(&staged_path, payload.as_bytes())
        .with_context(|| format!("failed to write {}", staged_path.display()))?;
    Ok(relative_ref(
        staged_dir.parent().unwrap_or(staged_dir),
        &staged_path,
    ))
}

fn stage_command_artifact(
    staged_dir: &Path,
    artifact: &FileArtifact,
    config: &AppConfig,
) -> Result<Option<String>> {
    let Some((command, arg_sets)) = command_capture_spec(&artifact.path, config) else {
        return Ok(None);
    };
    let Some(path) = command_in_path(command) else {
        return Ok(None);
    };
    let mut chosen_args = None;
    let mut chosen_stdout = None;
    for args in arg_sets {
        let output = Command::new(&path).args(&args).output();
        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        if stdout.trim().is_empty() {
            continue;
        }
        chosen_args = Some(args);
        chosen_stdout = Some(stdout);
        break;
    }
    let Some(args) = chosen_args else {
        return Ok(None);
    };
    let Some(stdout) = chosen_stdout else {
        return Ok(None);
    };
    let payload = format_text_capture(
        &artifact.path,
        &artifact.category,
        "command_output",
        &tail_lines(&stdout, config.collection.log_tail_lines),
        Some(&format!("command={} {}", command, args.join(" "))),
    );
    let staged_path = staged_dir.join(format!("cmd_{}.txt", stable_name(&artifact.path)));
    fs::write(&staged_path, payload.as_bytes())
        .with_context(|| format!("failed to write {}", staged_path.display()))?;
    Ok(Some(relative_ref(
        staged_dir.parent().unwrap_or(staged_dir),
        &staged_path,
    )))
}

fn command_capture_spec(
    path: &str,
    config: &AppConfig,
) -> Option<(&'static str, Vec<Vec<String>>)> {
    match path {
        "command:journalctl" => Some((
            "journalctl",
            vec![
                vec![
                    "--no-pager".to_string(),
                    "-o".to_string(),
                    "short-iso".to_string(),
                    "--since".to_string(),
                    format!("-{} hours", config.collection.log_time_window_hours),
                    "-n".to_string(),
                    config.collection.log_tail_lines.to_string(),
                ],
                vec![
                    "--no-pager".to_string(),
                    "-o".to_string(),
                    "short-iso".to_string(),
                    "-n".to_string(),
                    config.collection.log_tail_lines.to_string(),
                ],
            ],
        )),
        "command:dmesg" => Some((
            "dmesg",
            vec![
                vec![
                    "--ctime".to_string(),
                    "--color=never".to_string(),
                    "--since".to_string(),
                    format!("{} hours ago", config.collection.log_time_window_hours),
                ],
                vec!["--ctime".to_string(), "--color=never".to_string()],
            ],
        )),
        _ => None,
    }
}

fn format_text_capture(
    source: &str,
    category: &str,
    mode: &str,
    body: &str,
    extra: Option<&str>,
) -> String {
    let mut text = format!(
        "# trailguard_source: {source}\n# trailguard_category: {category}\n# trailguard_mode: {mode}\n# trailguard_collected_at: {}\n",
        chrono::Utc::now().to_rfc3339()
    );
    if let Some(extra) = extra {
        text.push_str(&format!("# trailguard_extra: {extra}\n"));
    }
    text.push('\n');
    text.push_str(body);
    if !body.ends_with('\n') {
        text.push('\n');
    }
    text
}

fn command_in_path(command: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|entry| entry.join(command))
        .find(|candidate| candidate.is_file())
}

fn read_tail_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let file_len = file.metadata().map(|meta| meta.len()).unwrap_or_default();
    if file_len > max_bytes {
        file.seek(SeekFrom::Start(file_len - max_bytes))?;
    }
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn tail_lines(content: &str, lines: usize) -> String {
    let mut rows = content.lines().collect::<Vec<_>>();
    if rows.len() > lines {
        rows = rows.split_off(rows.len() - lines);
    }
    rows.join("\n")
}

fn filter_log_content_by_time_window(content: &str, window_hours: i64) -> String {
    if window_hours <= 0 {
        return content.to_string();
    }
    let cutoff = chrono::Utc::now() - chrono::Duration::hours(window_hours);
    content
        .lines()
        .filter(|line| match parse_common_log_timestamp(line) {
            Some(ts) => ts >= cutoff,
            None => true,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_common_log_timestamp(line: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{Datelike, Local, NaiveDateTime, TimeZone};

    let line = line.trim_start();
    let first = line.split_whitespace().next()?;

    if first.contains('T') {
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(first) {
            return Some(parsed.with_timezone(&chrono::Utc));
        }
    }

    if line.len() >= 19 {
        let candidate = &line[..19];
        if let Ok(parsed) = NaiveDateTime::parse_from_str(candidate, "%Y-%m-%d %H:%M:%S") {
            return Local
                .from_local_datetime(&parsed)
                .single()
                .map(|value| value.with_timezone(&chrono::Utc));
        }
    }

    if line.len() >= 20 {
        let candidate = &line[..20];
        if let Ok(parsed) = NaiveDateTime::parse_from_str(candidate, "%Y-%m-%dT%H:%M:%S") {
            return Local
                .from_local_datetime(&parsed)
                .single()
                .map(|value| value.with_timezone(&chrono::Utc));
        }
    }

    if line.len() >= 15 {
        let candidate = &line[..15];
        if let Ok(parsed) = NaiveDateTime::parse_from_str(
            &format!("{} {}", Local::now().year(), candidate),
            "%Y %b %e %H:%M:%S",
        ) {
            return Local
                .from_local_datetime(&parsed)
                .single()
                .map(|value| value.with_timezone(&chrono::Utc));
        }
    }

    if line.len() >= 24 {
        let candidate = &line[..24];
        if let Ok(parsed) = NaiveDateTime::parse_from_str(candidate, "%a %b %e %H:%M:%S %Y") {
            return Local
                .from_local_datetime(&parsed)
                .single()
                .map(|value| value.with_timezone(&chrono::Utc));
        }
    }

    None
}

fn stable_name(value: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn relative_ref(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_sensitive_auth_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with("/shadow")
        || lower.contains("authorized_keys")
        || lower.contains("known_hosts")
        || lower.ends_with(".bash_history")
        || lower.ends_with(".zsh_history")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn journalctl_capture_prefers_since_window() {
        let config = AppConfig::default();
        let (command, arg_sets) = command_capture_spec("command:journalctl", &config).unwrap();
        assert_eq!(command, "journalctl");
        assert_eq!(arg_sets.len(), 2);
        assert!(arg_sets[0].iter().any(|item| item == "--since"));
        assert!(
            arg_sets[0]
                .iter()
                .any(|item| item == &format!("-{} hours", config.collection.log_time_window_hours))
        );
    }

    #[test]
    fn format_text_capture_adds_metadata_header() {
        let rendered = format_text_capture(
            "command:journalctl",
            "command_log",
            "command_output",
            "line1\nline2",
            Some("command=journalctl -n 10"),
        );
        assert!(rendered.contains("# trailguard_source: command:journalctl"));
        assert!(rendered.contains("# trailguard_category: command_log"));
        assert!(rendered.contains("# trailguard_mode: command_output"));
        assert!(rendered.contains("# trailguard_extra: command=journalctl -n 10"));
        assert!(rendered.ends_with("line1\nline2\n"));
    }

    #[test]
    fn filters_common_log_lines_by_time_window() {
        let recent = chrono::Utc::now().to_rfc3339();
        let old = (chrono::Utc::now() - chrono::Duration::hours(96)).to_rfc3339();
        let input = format!("{old} old\n{recent} new\nno-ts keep");
        let output = filter_log_content_by_time_window(&input, 72);
        assert!(!output.contains("old"));
        assert!(output.contains("new"));
        assert!(output.contains("no-ts keep"));
    }

    #[test]
    fn augments_analysis_with_command_log_entries() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("trailguard-test-{unique}"));
        let sidecar_dir = root.join("collected_files");
        std::fs::create_dir_all(&sidecar_dir).unwrap();
        let sidecar_path = sidecar_dir.join("cmd_demo.txt");
        std::fs::write(
            &sidecar_path,
            "# trailguard_source: command:journalctl\n\n2026-03-27T10:00:00+08:00 host sshd[1]: Failed password for root\n",
        )
        .unwrap();

        let mut analysis = common_model::AnalysisBundle {
            host_overview: common_model::HostOverview {
                hostname: "demo".into(),
                platform: Platform::Linux,
                process_count: 0,
                event_count: 0,
                suspicious_processes: 0,
                rule_match_count: 0,
                listening_ports: 0,
                remote_ip_count: 0,
                collected_file_count: 1,
            },
            suspicious_processes: vec![],
            top_chains: vec![],
            timeline: vec![],
            process_tree: vec![],
            rule_matches: vec![],
            dataset: common_model::EvidenceDataset {
                file_artifacts: vec![common_model::FileArtifact {
                    entity_key: "host:linux:demo".into(),
                    category: "command_log".into(),
                    path: "command:journalctl".into(),
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
                    content_ref: Some("collected_files/cmd_demo.txt".into()),
                    notes: vec![],
                    ts: chrono::Utc::now(),
                }],
                ..Default::default()
            },
        };

        augment_analysis_with_command_logs(&mut analysis, &root).unwrap();
        assert_eq!(analysis.timeline.len(), 1);
        assert!(analysis.timeline[0].label.contains("Failed password"));
        assert_eq!(analysis.timeline[0].severity, Severity::High);
        assert!(analysis.rule_matches.is_empty());
        assert_eq!(analysis.host_overview.rule_match_count, 0);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn augments_analysis_with_command_log_rule_matches() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("trailguard-test-rules-{unique}"));
        let sidecar_dir = root.join("collected_files");
        std::fs::create_dir_all(&sidecar_dir).unwrap();
        let sidecar_path = sidecar_dir.join("cmd_rules.txt");
        std::fs::write(
            &sidecar_path,
            [
                "# trailguard_source: command:journalctl",
                "",
                "2026-03-27T10:00:00+08:00 host sudo: alice : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
                "2026-03-27T10:01:00+08:00 host kernel: invoked oom-killer: gfp_mask=0x0 order=0 oom_score_adj=0",
                "2026-03-27T10:02:00+08:00 host kernel: miner[123]: segfault at 0 ip 00007f error 4",
                "2026-03-27T10:03:00+08:00 host audit[100]: AVC avc:  denied  { read } for pid=1 comm=\"evil\"",
                "2026-03-27T10:03:01+08:00 host audit[101]: AVC avc:  denied  { write } for pid=1 comm=\"evil\"",
                "2026-03-27T10:03:02+08:00 host audit[102]: AVC avc:  denied  { execute } for pid=1 comm=\"evil\"",
                "",
            ]
            .join("\n"),
        )
        .unwrap();

        let mut analysis = common_model::AnalysisBundle {
            host_overview: common_model::HostOverview {
                hostname: "demo".into(),
                platform: Platform::Linux,
                process_count: 0,
                event_count: 0,
                suspicious_processes: 0,
                rule_match_count: 0,
                listening_ports: 0,
                remote_ip_count: 0,
                collected_file_count: 1,
            },
            suspicious_processes: vec![],
            top_chains: vec![],
            timeline: vec![],
            process_tree: vec![],
            rule_matches: vec![],
            dataset: common_model::EvidenceDataset {
                file_artifacts: vec![common_model::FileArtifact {
                    entity_key: "host:linux:demo".into(),
                    category: "command_log".into(),
                    path: "command:journalctl".into(),
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
                    content_ref: Some("collected_files/cmd_rules.txt".into()),
                    notes: vec![],
                    ts: chrono::Utc::now(),
                }],
                ..Default::default()
            },
        };

        augment_analysis_with_command_logs(&mut analysis, &root).unwrap();

        assert_eq!(analysis.timeline.len(), 6);
        assert_eq!(analysis.rule_matches.len(), 4);
        assert_eq!(analysis.host_overview.rule_match_count, 4);
        assert!(
            analysis
                .rule_matches
                .iter()
                .any(|item| item.rule_id == "TG-L001" && item.severity == Severity::Medium)
        );
        assert!(
            analysis
                .rule_matches
                .iter()
                .any(|item| item.rule_id == "TG-L002" && item.severity == Severity::High)
        );
        assert!(
            analysis
                .rule_matches
                .iter()
                .any(|item| item.rule_id == "TG-L003" && item.severity == Severity::High)
        );
        assert!(
            analysis
                .rule_matches
                .iter()
                .any(|item| item.rule_id == "TG-L004" && item.severity == Severity::High)
        );
        assert!(analysis.rule_matches.iter().all(|item| {
            item.evidence_refs
                .iter()
                .any(|reference| reference == "command:journalctl")
        }));

        let _ = std::fs::remove_dir_all(root);
    }
}

struct SnapshotState {
    processes: HashMap<String, common_model::ProcessIdentity>,
    net_signatures: HashSet<String>,
    persistence_signatures: HashSet<String>,
}

impl SnapshotState {
    fn from_snapshot(snapshot: &SnapshotBundle) -> Self {
        Self {
            processes: snapshot
                .processes
                .iter()
                .map(|process| (process.entity_key.clone(), process.clone()))
                .collect(),
            net_signatures: snapshot.net_connections.iter().map(net_signature).collect(),
            persistence_signatures: snapshot
                .persistence_artifacts
                .iter()
                .map(persistence_signature)
                .collect(),
        }
    }
}
