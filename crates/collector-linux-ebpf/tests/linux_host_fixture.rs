#[cfg(target_os = "linux")]
mod linux_host_fixture {
    use std::{
        io::Read, net::TcpListener, os::unix::fs::MetadataExt, path::Path, process::Command,
        thread, time::Duration,
    };

    use anyhow::{Context, Result};
    use collector_linux_ebpf::LinuxEbpfCollector;
    use common_model::{AppConfig, EventType, HostCollector};

    #[test]
    #[ignore = "requires Linux root privileges, eBPF support, and a Linux build host"]
    fn captures_local_socket_tuple_and_privilege_change() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping linux host fixture: requires root");
            return Ok(());
        }

        let config = AppConfig::default();
        let collector = LinuxEbpfCollector;
        if !collector.is_available(&config) {
            eprintln!("skipping linux host fixture: eBPF object unavailable");
            return Ok(());
        }

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let listener_addr = listener.local_addr()?;
        let listener_addr_text = listener_addr.to_string();
        let listener_thread = thread::spawn(move || {
            let Ok((mut socket, _peer)) = listener.accept() else {
                return;
            };
            let mut buf = [0_u8; 32];
            let _ = socket.read(&mut buf);
            thread::sleep(Duration::from_millis(300));
        });

        let monitor_config = config.clone();
        let monitor_thread = thread::spawn(move || -> Result<_> {
            let collector = LinuxEbpfCollector;
            collector
                .monitor_native(&monitor_config, Duration::from_secs(4))?
                .context("native monitor returned no bundle")
        });

        thread::sleep(Duration::from_millis(400));
        run_fixture(&["connect", &listener_addr_text, "900"])?;
        run_fixture(&["privdrop", "65534", "65534", "250"])?;
        run_fixture(&["priveffective", "65534", "65534", "250"])?;
        let exec_fixture = find_setuid_exec_fixture();
        if let Some((binary, args)) = exec_fixture.clone() {
            let mut owned_args = vec![
                "execas".to_string(),
                "65534".to_string(),
                "65534".to_string(),
                binary,
            ];
            owned_args.extend(args);
            run_fixture_owned(&owned_args)?;
        } else {
            eprintln!("skipping exec credential commit fixture: no suitable setuid binary");
        }

        let bundle = monitor_thread
            .join()
            .map_err(|_| anyhow::anyhow!("monitor thread panicked"))??;
        let _ = listener_thread.join();

        let connection = bundle
            .net_connections
            .iter()
            .find(|item| item.remote_addr == listener_addr_text && item.local_addr != "unknown")
            .context("expected local socket tuple enrichment for fixture connection")?;
        assert_eq!(connection.protocol, "tcp");

        let net_event = bundle
            .events
            .iter()
            .find(|event| {
                event.event_type == EventType::NetConnect
                    && event
                        .fields
                        .get("remote_addr")
                        .and_then(|value| value.as_str())
                        == Some(listener_addr_text.as_str())
            })
            .context("expected normalized NetConnect event for fixture connection")?;
        assert_ne!(
            net_event
                .fields
                .get("local_addr")
                .and_then(|value| value.as_str()),
            Some("unknown")
        );

        let gid_event = bundle
            .events
            .iter()
            .find(|event| {
                event.event_type == EventType::PrivilegeChange
                    && event.fields.get("syscall").and_then(|value| value.as_str())
                        == Some("setresgid")
            })
            .context("expected setresgid privilege change event")?;
        assert_eq!(
            gid_event
                .fields
                .get("new_gid")
                .and_then(|value| value.as_u64()),
            Some(65534)
        );

        let uid_event = bundle
            .events
            .iter()
            .find(|event| {
                event.event_type == EventType::PrivilegeChange
                    && event.fields.get("syscall").and_then(|value| value.as_str())
                        == Some("setresuid")
            })
            .context("expected setresuid privilege change event")?;
        assert_eq!(
            uid_event
                .fields
                .get("new_uid")
                .and_then(|value| value.as_u64()),
            Some(65534)
        );

        let egid_event = bundle
            .events
            .iter()
            .find(|event| {
                event.event_type == EventType::PrivilegeChange
                    && event.fields.get("syscall").and_then(|value| value.as_str())
                        == Some("setegid")
            })
            .context("expected setegid privilege change event")?;
        assert_eq!(
            egid_event
                .fields
                .get("new_gid")
                .and_then(|value| value.as_u64()),
            Some(65534)
        );

        let euid_event = bundle
            .events
            .iter()
            .find(|event| {
                event.event_type == EventType::PrivilegeChange
                    && event.fields.get("syscall").and_then(|value| value.as_str())
                        == Some("seteuid")
            })
            .context("expected seteuid privilege change event")?;
        assert_eq!(
            euid_event
                .fields
                .get("new_uid")
                .and_then(|value| value.as_u64()),
            Some(65534)
        );

        if exec_fixture.is_some() {
            let exec_event = bundle
                .events
                .iter()
                .find(|event| {
                    event.event_type == EventType::PrivilegeChange
                        && event.fields.get("syscall").and_then(|value| value.as_str())
                            == Some("exec_credential_commit")
                        && event
                            .fields
                            .get("kernel_exec_uid_change")
                            .and_then(|value| value.as_bool())
                            == Some(true)
                })
                .context("expected exec credential commit event")?;
            assert_eq!(
                exec_event
                    .fields
                    .get("old_uid")
                    .and_then(|value| value.as_u64()),
                Some(65534)
            );
            assert_eq!(
                exec_event
                    .fields
                    .get("new_uid")
                    .and_then(|value| value.as_u64()),
                Some(0)
            );
        }

        Ok(())
    }

    fn run_fixture(args: &[&str]) -> Result<()> {
        let status = Command::new(env!("CARGO_BIN_EXE_trailguard-linux-fixture"))
            .args(args)
            .status()
            .with_context(|| format!("failed to launch fixture {:?}", args))?;
        if !status.success() {
            anyhow::bail!("fixture {:?} exited with {}", args, status);
        }
        Ok(())
    }

    fn run_fixture_owned(args: &[String]) -> Result<()> {
        let status = Command::new(env!("CARGO_BIN_EXE_trailguard-linux-fixture"))
            .args(args)
            .status()
            .with_context(|| format!("failed to launch fixture {:?}", args))?;
        if !status.success() {
            anyhow::bail!("fixture {:?} exited with {}", args, status);
        }
        Ok(())
    }

    fn find_setuid_exec_fixture() -> Option<(String, Vec<String>)> {
        for (path, args) in [
            ("/usr/bin/passwd", vec!["--help"]),
            ("/bin/su", vec!["--help"]),
            ("/usr/bin/chsh", vec!["--help"]),
            ("/usr/bin/chfn", vec!["--help"]),
        ] {
            let Ok(metadata) = std::fs::metadata(path) else {
                continue;
            };
            if !metadata.is_file() || metadata.mode() & 0o4000 == 0 {
                continue;
            }
            return Some((
                Path::new(path).to_string_lossy().to_string(),
                args.into_iter().map(str::to_string).collect(),
            ));
        }
        None
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn linux_host_fixture_is_linux_only() {}
