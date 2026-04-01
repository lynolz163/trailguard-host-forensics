use std::{path::PathBuf, time::Duration};

use anyhow::Result;

use crate::{AppConfig, Platform, RealtimeMonitorBundle, SnapshotBundle};

/// Platform collector contract used by the CLI to gather snapshots.
pub trait HostCollector: Send + Sync {
    /// Human-readable backend name.
    fn backend_name(&self) -> &'static str;

    /// Platform implemented by the collector.
    fn platform(&self) -> Platform;

    /// Collect a point-in-time host snapshot.
    fn collect_snapshot(&self, config: &AppConfig) -> Result<SnapshotBundle>;

    /// Native realtime capture path when the collector can produce kernel-backed events directly.
    fn monitor_native(
        &self,
        _config: &AppConfig,
        _duration: Duration,
    ) -> Result<Option<RealtimeMonitorBundle>> {
        Ok(None)
    }

    /// Directories worth watching in monitor mode.
    fn recommended_watch_paths(&self, config: &AppConfig) -> Vec<PathBuf>;

    /// Realtime capture notes shown to the operator.
    fn realtime_notes(&self) -> Vec<String> {
        Vec::new()
    }
}
