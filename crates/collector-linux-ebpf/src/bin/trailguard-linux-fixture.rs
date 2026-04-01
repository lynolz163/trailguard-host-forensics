#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use std::{
        env, io::Write, net::TcpStream, os::unix::process::CommandExt, process::Command, thread,
        time::Duration,
    };

    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("connect") => {
            let addr = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing <addr> for connect"))?;
            let hold_ms = parse_ms(args.next().as_deref())?;
            let mut stream = TcpStream::connect(&addr)?;
            let _ = stream.write_all(b"trailguard-fixture");
            thread::sleep(Duration::from_millis(hold_ms));
            Ok(())
        }
        Some("privdrop") => {
            let uid = parse_id(args.next().as_deref(), "uid")?;
            let gid = parse_id(args.next().as_deref(), "gid")?;
            let hold_ms = parse_ms(args.next().as_deref())?;
            let setgid_rc = unsafe { libc::setresgid(gid, gid, gid) };
            if setgid_rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let setuid_rc = unsafe { libc::setresuid(uid, uid, uid) };
            if setuid_rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            thread::sleep(Duration::from_millis(hold_ms));
            Ok(())
        }
        Some("priveffective") => {
            let uid = parse_id(args.next().as_deref(), "uid")?;
            let gid = parse_id(args.next().as_deref(), "gid")?;
            let hold_ms = parse_ms(args.next().as_deref())?;
            let setgid_rc = unsafe { libc::setegid(gid) };
            if setgid_rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let setuid_rc = unsafe { libc::seteuid(uid) };
            if setuid_rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            thread::sleep(Duration::from_millis(hold_ms));
            Ok(())
        }
        Some("execas") => {
            let uid = parse_id(args.next().as_deref(), "uid")?;
            let gid = parse_id(args.next().as_deref(), "gid")?;
            let program = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing <program> for execas"))?;
            let rest = args.collect::<Vec<_>>();
            let setgid_rc = unsafe { libc::setresgid(gid, gid, gid) };
            if setgid_rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let setuid_rc = unsafe { libc::setresuid(uid, uid, uid) };
            if setuid_rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let error = Command::new(program).args(rest).exec();
            Err(error.into())
        }
        _ => Err(anyhow::anyhow!(
            "usage: trailguard-linux-fixture <connect <addr> <hold_ms> | privdrop <uid> <gid> <hold_ms> | priveffective <uid> <gid> <hold_ms> | execas <uid> <gid> <program> [args...]>"
        )),
    }
}

#[cfg(target_os = "linux")]
fn parse_ms(value: Option<&str>) -> anyhow::Result<u64> {
    value
        .ok_or_else(|| anyhow::anyhow!("missing <hold_ms>"))?
        .parse::<u64>()
        .map_err(Into::into)
}

#[cfg(target_os = "linux")]
fn parse_id(value: Option<&str>, name: &str) -> anyhow::Result<u32> {
    value
        .ok_or_else(|| anyhow::anyhow!("missing <{name}>"))?
        .parse::<u32>()
        .map_err(Into::into)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("trailguard-linux-fixture is only available on Linux");
}
