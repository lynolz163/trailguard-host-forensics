# TrailGuard Architecture

## Positioning

TrailGuard is a defensive host forensics tool. It performs local collection, explainable detection, evidence correlation, and reporting. It does **not** implement offensive capabilities such as exploitation, persistence deployment, privilege escalation, lateral movement, or data exfiltration.

## Workspace Layout

```text
/crates
  /common-model          # Unified data model, config, collector trait, shared helpers
  /storage-sqlite        # SQLite schema, JSONL writer, evidence loading
  /rule-engine           # Explainable rules loaded from TOML
  /correlator            # Process tree, timeline, risk scoring, suspicious chains
  /reporter-html         # HTML and Mermaid outputs
  /collector-linux-proc  # Linux snapshot collector using /proc + netstat2
  /collector-linux-ebpf  # Linux native realtime collector using Aya eBPF
  /collector-windows     # Windows snapshot collector using sysinfo + registry/startup paths
  /cli                   # snapshot / monitor / analyze / report commands
/config
/docs
/examples
/tests
```

## Data Flow

1. `snapshot`
   - Selects the current-platform collector.
   - Collects process, host baseline, network, file, auth, log, and persistence facts.
   - Writes structured tables to SQLite.
   - Writes normalized raw events to JSONL with `prev_event_hash` and `event_hash`.
   - Stages log slices and selected raw/auth artifacts into the evidence package.

2. `monitor`
   - Takes an initial baseline snapshot.
   - Polls process and network state at a configurable interval.
   - Uses native filesystem notifications for file changes.
   - Emits normalized `ProcessStart`, `ProcessExit`, `NetConnect`, `FileCreate`, `FileWrite`, `Rename`, and `PersistenceCreate` events when evidence is observed.

3. `analyze`
   - Loads the evidence dataset from SQLite.
   - Applies explainable rules configured in `config/rules.toml`.
   - Correlates auth/login traces, high-risk file metadata, and command-log sidecars into operator-facing findings.
   - Persists rule hits back into SQLite.
   - Generates `analysis.json`, `timeline.jsonl`, `timeline.md`, and Mermaid graph.

4. `report`
   - Re-runs analysis from the persisted dataset.
   - Generates an HTML report that separates raw facts from inferred conclusions.
   - Links suspicious chains back to raw event IDs and JSONL references.

## Collector Strategy

### Linux

- Implemented now:
  - `/proc` process enumeration
  - `/proc/<pid>/stat`, `cmdline`, `exe`, `cwd`, `status` parsing
  - command-backed log capture placeholders for `journalctl` and `dmesg` with presence checks
  - persistence snapshot of common `systemd`, `cron`, and autostart locations
  - network enumeration through `netstat2`
  - near-real-time process/network monitoring through snapshot diff polling
  - file monitoring through native filesystem notifications
  - native eBPF realtime collector using:
    - kprobes for `execve`, `execveat`, `connect`, `openat`, `openat2`, `renameat`, `renameat2`
    - tracepoints for `sched_process_exec` and `sched_process_exit`
    - perf event array delivery to user space
- Current Linux eBPF design:
  - baseline snapshot still comes from `/proc`
  - realtime process identity enrichment still consults `/proc` to obtain stable `entity_key`, `cmdline`, `cwd`, `hash`
  - realtime connect events enrich local socket tuples from `/proc/<pid>/fd/<fd>` inode lookups plus socket tables
  - realtime privilege change events are emitted from successful `setuid` / `setreuid` / `setresuid` / `setgid` / `setregid` / `setresgid` / `capset`
  - exec credential commit is reconstructed from eBPF exec events plus setuid/setgid file mode metadata and parent process context
  - persistence creation is inferred from eBPF file events hitting configured persistence paths
- Build requirement:
  - embedding the eBPF object requires a Linux build host with `nightly`, `rust-src`, and `bpf-linker`
  - alternatively an operator can provide `collection.linux.ebpf_object_path`

### Windows

- Implemented now:
  - process snapshot via `sysinfo`
  - network snapshot via `netstat2`
  - persistence snapshot of `Run/RunOnce`, Startup folders, and `System32\\Tasks`
  - near-real-time process/network monitoring through snapshot diff polling
  - file monitoring through native filesystem notifications
- Reserved:
  - ETW-native collector path behind the same trait boundary
  - signer enrichment and richer service metadata

## Evidence Integrity

- All normalized events are hash chained:
  - `prev_event_hash`
  - `event_hash`
- The chain is generated at write time before SQLite and JSONL persistence.
- `raw_ref` points back to the JSONL line reference.
- HTML reporting uses raw event IDs and raw refs for operator review.

## Design Decisions

- **SQLite + JSONL dual output**: SQLite supports query and correlation; JSONL preserves append-only raw events.
- **Evidence sidecar files**: logs and selected auth/raw files are staged into `collected_files/`, while sensitive content stays behind a default-safe switch.
- **Command capture fallback**: `journalctl` and `dmesg` are only used when present; the collector emits pseudo file artifacts and the CLI materializes them into captured text sidecars.
- **Unified model first**: platform collectors normalize into shared structs before any rule logic runs.
- **Explainable rules first**: the first version intentionally avoids black-box scoring.
- **Rules from config first**: `config/rules.toml` is loaded by default when present, allowing focused rule packs such as miner-like detections without shipping a heavyweight runtime dependency.
- **Minimal runtime dependencies**: native Rust binary, bundled SQLite, no Python/Node/.NET runtime dependency.
- **Pragmatic realtime MVP**: polling + filesystem notifications deliver a working path now while preserving eBPF/ETW extension points.

## Known MVP Gaps

- Snapshot-only file evidence remains filesystem-scoped; Linux eBPF realtime now adds process-attributed open/write/rename events.
- DNS reverse lookup and Windows signer enrichment are not yet implemented.
- Linux snapshot network capture still uses system socket enumeration; realtime Linux connect events are now emitted from eBPF.
- Windows realtime is polling-based, not ETW-native yet.
- Linux eBPF local socket tuple enrichment is best-effort and depends on the target process/socket still existing when userspace resolves the inode.
- Linux eBPF build embedding is intended for Linux hosts; Windows development can still validate user-space and eBPF Rust syntax separately.
