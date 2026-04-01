use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Runtime configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub output: OutputConfig,
    pub collection: CollectionConfig,
    pub report: ReportConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            output: OutputConfig::default(),
            collection: CollectionConfig::default(),
            report: ReportConfig::default(),
        }
    }
}

impl AppConfig {
    /// Loads configuration from TOML, falling back to defaults when absent.
    pub fn load_from_file(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => {
                let content = fs::read_to_string(path)
                    .with_context(|| format!("failed to read config file {}", path.display()))?;
                let config: Self = toml::from_str(&content)
                    .with_context(|| format!("failed to parse config file {}", path.display()))?;
                Ok(config)
            }
            None => Ok(Self::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub db_name: String,
    pub jsonl_name: String,
    pub analysis_name: String,
    pub graph_name: String,
    pub timeline_jsonl_name: String,
    pub timeline_markdown_name: String,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            db_name: "evidence.db".to_string(),
            jsonl_name: "events.jsonl".to_string(),
            analysis_name: "analysis.json".to_string(),
            graph_name: "chains.mmd".to_string(),
            timeline_jsonl_name: "timeline.jsonl".to_string(),
            timeline_markdown_name: "timeline.md".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectionConfig {
    pub poll_interval_secs: u64,
    pub process_exit_grace_secs: u64,
    pub rapid_connect_window_secs: i64,
    pub short_lived_process_secs: i64,
    pub file_watch_paths: Vec<String>,
    pub hash_file_limit_mb: u64,
    pub collect_sensitive_content: bool,
    pub log_tail_lines: usize,
    pub log_max_bytes: u64,
    pub log_time_window_hours: i64,
    pub linux: LinuxCollectionConfig,
    pub windows: WindowsCollectionConfig,
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 2,
            process_exit_grace_secs: 2,
            rapid_connect_window_secs: 120,
            short_lived_process_secs: 90,
            file_watch_paths: Vec::new(),
            hash_file_limit_mb: 64,
            collect_sensitive_content: false,
            log_tail_lines: 2000,
            log_max_bytes: 8 * 1024 * 1024,
            log_time_window_hours: 72,
            linux: LinuxCollectionConfig::default(),
            windows: WindowsCollectionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LinuxCollectionConfig {
    pub risk_dirs: Vec<String>,
    pub persistence_paths: Vec<String>,
    pub trusted_system_dirs: Vec<String>,
    pub auth_paths: Vec<String>,
    pub log_paths: Vec<String>,
    pub command_log_collectors: Vec<String>,
    pub app_log_paths: Vec<String>,
    pub high_risk_scan_paths: Vec<String>,
    pub web_root_paths: Vec<String>,
    pub recent_file_window_hours: i64,
    pub max_mapped_modules_per_process: usize,
    pub max_recent_login_records: usize,
    pub max_failed_login_records: usize,
    pub max_risk_scan_files: usize,
    pub ebpf_object_path: Option<String>,
    pub ebpf_perf_pages: usize,
}

impl Default for LinuxCollectionConfig {
    fn default() -> Self {
        Self {
            risk_dirs: vec![
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/dev/shm".to_string(),
                "~/.cache".to_string(),
                "~/Downloads".to_string(),
            ],
            persistence_paths: vec![
                "/etc/systemd/system".to_string(),
                "/usr/lib/systemd/system".to_string(),
                "~/.config/systemd/user".to_string(),
                "~/.config/autostart".to_string(),
                "/etc/cron.d".to_string(),
                "/etc/cron.daily".to_string(),
                "/etc/cron.hourly".to_string(),
                "/etc/cron.weekly".to_string(),
                "/etc/cron.monthly".to_string(),
                "/var/spool/cron".to_string(),
            ],
            trusted_system_dirs: vec![
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/usr/lib".to_string(),
                "/lib".to_string(),
            ],
            auth_paths: vec![
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "/etc/group".to_string(),
                "/etc/sudoers".to_string(),
                "/etc/sudoers.d".to_string(),
                "/root/.ssh/authorized_keys".to_string(),
                "/root/.ssh/known_hosts".to_string(),
                "/root/.bash_history".to_string(),
                "/home/*/.ssh/authorized_keys".to_string(),
                "/home/*/.ssh/known_hosts".to_string(),
                "/home/*/.bash_history".to_string(),
                "/home/*/.zsh_history".to_string(),
            ],
            log_paths: vec![
                "/var/log/auth.log".to_string(),
                "/var/log/secure".to_string(),
                "/var/log/messages".to_string(),
                "/var/log/syslog".to_string(),
                "/var/log/nginx/access.log".to_string(),
                "/var/log/nginx/error.log".to_string(),
                "/var/log/apache2/access.log".to_string(),
                "/var/log/apache2/error.log".to_string(),
                "/var/log/httpd/access_log".to_string(),
                "/var/log/httpd/error_log".to_string(),
            ],
            command_log_collectors: vec!["journalctl".to_string(), "dmesg".to_string()],
            app_log_paths: Vec::new(),
            high_risk_scan_paths: vec![
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/dev/shm".to_string(),
                "/etc".to_string(),
                "/usr/local/bin".to_string(),
                "/usr/bin".to_string(),
                "/root".to_string(),
                "/home".to_string(),
            ],
            web_root_paths: vec![
                "/var/www".to_string(),
                "/usr/share/nginx/html".to_string(),
                "/srv/www".to_string(),
            ],
            recent_file_window_hours: 72,
            max_mapped_modules_per_process: 32,
            max_recent_login_records: 40,
            max_failed_login_records: 40,
            max_risk_scan_files: 2500,
            ebpf_object_path: None,
            ebpf_perf_pages: 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowsCollectionConfig {
    pub risk_dirs: Vec<String>,
    pub startup_paths: Vec<String>,
    pub run_keys: Vec<String>,
    pub trusted_system_dirs: Vec<String>,
}

impl Default for WindowsCollectionConfig {
    fn default() -> Self {
        Self {
            risk_dirs: vec![
                "%TEMP%".to_string(),
                "%LOCALAPPDATA%\\Temp".to_string(),
                "%USERPROFILE%\\Downloads".to_string(),
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".to_string(),
                "%USERPROFILE%\\AppData\\Roaming".to_string(),
            ],
            startup_paths: vec![
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".to_string(),
                "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".to_string(),
                "C:\\Windows\\System32\\Tasks".to_string(),
            ],
            run_keys: vec![
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
            ],
            trusted_system_dirs: vec![
                "C:\\Windows\\System32".to_string(),
                "C:\\Windows\\SysWOW64".to_string(),
                "C:\\Program Files".to_string(),
                "C:\\Program Files (x86)".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportConfig {
    pub top_chains: usize,
    pub max_timeline_entries: usize,
    pub max_raw_events: usize,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            top_chains: 10,
            max_timeline_entries: 250,
            max_raw_events: 500,
        }
    }
}
