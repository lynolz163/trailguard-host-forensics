#[cfg(target_os = "linux")]
mod linux_snapshot_fixture {
    use std::{env, path::PathBuf};

    use anyhow::Result;
    use collector_linux_proc::{LinuxProcCollector, collect_process_identity};
    use common_model::{AppConfig, HostCollector};

    #[test]
    fn collects_live_linux_snapshot_basics() -> Result<()> {
        let config = AppConfig::default();
        let collector = LinuxProcCollector;
        let snapshot = collector.collect_snapshot(&config)?;

        assert_eq!(snapshot.host.platform.to_string(), "linux");
        assert!(!snapshot.host.hostname.is_empty());
        assert!(!snapshot.processes.is_empty());
        assert!(
            snapshot
                .file_artifacts
                .iter()
                .any(|artifact| artifact.category == "auth_file" && artifact.path == "/etc/passwd")
        );

        for command in &config.collection.linux.command_log_collectors {
            if command_in_path(command).is_some() {
                let marker = format!("command:{command}");
                assert!(
                    snapshot
                        .file_artifacts
                        .iter()
                        .any(|artifact| artifact.category == "command_log"
                            && artifact.path == marker)
                );
            }
        }

        Ok(())
    }

    #[test]
    fn collects_current_process_identity() -> Result<()> {
        let config = AppConfig::default();
        let ts = chrono::Utc::now();
        let pid = i64::from(std::process::id());
        let process = collect_process_identity(&config, pid, ts)?
            .ok_or_else(|| anyhow::anyhow!("missing current process identity"))?;

        assert_eq!(process.pid, pid);
        assert!(!process.entity_key.is_empty());
        assert!(process.fd_count.is_some());
        Ok(())
    }

    fn command_in_path(command: &str) -> Option<PathBuf> {
        let path = env::var_os("PATH")?;
        env::split_paths(&path)
            .map(|entry| entry.join(command))
            .find(|candidate| candidate.is_file())
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn linux_snapshot_fixture_is_linux_only() {}
