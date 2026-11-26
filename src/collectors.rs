use std::{env, fs, path::{Path, PathBuf}, process::Command, time::{Duration, SystemTime, UNIX_EPOCH}};
use crate::process::run_bounded;
use crate::model::{BwError, Snapshot};
const VERSION: &str = env!("CARGO_PKG_VERSION");
const CHILD_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;

fn read_source(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| error.kind().to_string())
}

fn collect_file(
    snapshot: &mut Snapshot,
    key: &str,
    path: PathBuf,
    transform: impl FnOnce(&str) -> String,
) {
    match read_source(&path) {
        Ok(contents) => {
            snapshot.fields.insert(key.into(), transform(&contents));
        }
        Err(reason) => snapshot.notes.push(format!("{key}: no disponible ({reason})")),
    }
}

fn trimmed(value: &str) -> String {
    value.trim().into()
}

fn os_name(value: &str) -> String {
    value
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|name| name.trim_matches('"').to_owned())
        .unwrap_or_else(|| "unknown".into())
}

fn memory_value(value: &str, key: &str) -> String {
    value
        .lines()
        .find(|line| line.starts_with(&format!("{key}:")))
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("unknown")
        .into()
}

fn pressure_summary(value: &str) -> String {
    value
        .lines()
        .map(|line| line.split_whitespace().take(4).collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn redact_boot_arguments(value: &str) -> String {
    value
        .split_whitespace()
        .map(|argument| {
            let key = argument.split('=').next().unwrap_or(argument).to_ascii_lowercase();
            let sensitive = ["password", "passwd", "token", "secret", "key"]
                .iter()
                .any(|fragment| key.contains(fragment));
            if sensitive {
                format!("{}=[REDACTED]", argument.split('=').next().unwrap_or(argument))
            } else {
                argument.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn collect_snapshot(name: &str) -> Result<(Snapshot, String), BwError> {
    let root = env::var_os("BW_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    let proc = root.join("proc");
    let mut snapshot = Snapshot::default();

    collect_file(&mut snapshot, "kernel.release", proc.join("sys/kernel/osrelease"), trimmed);
    collect_file(&mut snapshot, "kernel.version", proc.join("version"), trimmed);
    collect_file(&mut snapshot, "kernel.cmdline", proc.join("cmdline"), redact_boot_arguments);
    collect_file(&mut snapshot, "os.pretty_name", root.join("etc/os-release"), os_name);
    collect_file(&mut snapshot, "memory.total_kib", proc.join("meminfo"), |data| {
        memory_value(data, "MemTotal")
    });
    collect_file(&mut snapshot, "memory.available_kib", proc.join("meminfo"), |data| {
        memory_value(data, "MemAvailable")
    });
    collect_file(&mut snapshot, "modules.count", proc.join("modules"), |data| {
        data.lines().count().to_string()
    });
    collect_file(&mut snapshot, "mounts.count", proc.join("self/mountinfo"), |data| {
        data.lines().count().to_string()
    });
    collect_file(&mut snapshot, "diskstats.count", proc.join("diskstats"), |data| {
        data.lines().count().to_string()
    });
    for subsystem in ["cpu", "memory", "io"] {
        collect_file(
            &mut snapshot,
            &format!("pressure.{subsystem}"),
            proc.join(format!("pressure/{subsystem}")),
            pressure_summary,
        );
    }

    match fs::read_dir(root.join("sys/class/net")) {
        Ok(entries) => {
            let mut interfaces = entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect::<Vec<_>>();
            interfaces.sort();
            snapshot.fields.insert("network.interfaces".into(), interfaces.join(","));
        }
        Err(error) => snapshot
            .notes
            .push(format!("network.interfaces: no disponible ({})", error.kind())),
    }

    collect_journal(&mut snapshot);
    collect_systemd(&mut snapshot);

    if snapshot.fields.is_empty() {
        return Err(BwError("ninguna fuente disponible; revisa BW_ROOT".into()));
    }

    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let timestamp_ns = duration.as_nanos();
    snapshot.fields.insert("snapshot.name".into(), name.into());
    snapshot.fields.insert("snapshot.created_unix".into(), duration.as_secs().to_string());
    snapshot.fields.insert("snapshot.created_unix_ns".into(), timestamp_ns.to_string());
    snapshot.fields.insert("snapshot.collector".into(), format!("bw/{VERSION}"));

    Ok((snapshot, format!("{timestamp_ns}-{name}")))
}


fn collect_journal(snapshot: &mut Snapshot) {
    if !crate::program_exists("journalctl") {
        snapshot.fields.insert("journal.status".into(), "unavailable".into());
        snapshot.notes.push("journalctl no está instalado".into());
        return;
    }

    let mut command = Command::new("journalctl");
    command.args([
        "--dmesg",
        "--boot",
        "--priority=err",
        "--no-pager",
        "--output=cat",
        "--lines=500",
    ]);
    match run_bounded(&mut command, CHILD_TIMEOUT, CHILD_OUTPUT_LIMIT) {
        Ok(result) if result.timed_out => {
            snapshot.fields.insert("journal.status".into(), "timeout".into());
            snapshot.notes.push("journalctl excedió el límite de 5 segundos".into());
        }
        Ok(result) if result.status.success() => {
            snapshot.fields.insert(
                "journal.status".into(),
                if result.output_truncated { "truncated" } else { "available" }.into(),
            );
            snapshot.events = String::from_utf8_lossy(&result.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect();
            if result.output_truncated {
                snapshot.notes.push("journalctl truncado al límite local de salida".into());
            }
        }
        Ok(result) => {
            snapshot.fields.insert("journal.status".into(), "unavailable".into());
            snapshot.notes.push(format!(
                "journalctl terminó con {} (puede faltar permiso para leer el journal del kernel)",
                result.status
            ));
            if !result.stderr.is_empty() {
                snapshot.notes.push("journalctl escribió diagnósticos en stderr; se omitió su contenido".into());
            }
        }
        Err(error) => {
            snapshot.fields.insert("journal.status".into(), "unavailable".into());
            snapshot.notes.push(format!("no se pudo iniciar journalctl: {error}"));
        }
    }
}

fn collect_systemd(snapshot: &mut Snapshot) {
    if !crate::program_exists("systemctl") {
        snapshot.fields.insert("systemd.status".into(), "unavailable".into());
        snapshot.notes.push("systemctl no está instalado".into());
        return;
    }

    let mut command = Command::new("systemctl");
    command.args(["--failed", "--no-legend", "--plain"]);
    match run_bounded(&mut command, CHILD_TIMEOUT, 1024 * 1024) {
        Ok(result) if result.timed_out => {
            snapshot.fields.insert("systemd.status".into(), "timeout".into());
            snapshot.notes.push("systemctl excedió el límite de 5 segundos".into());
        }
        Ok(result) if result.status.success() => {
            let mut units = String::from_utf8_lossy(&result.stdout)
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter(|unit| !unit.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            units.sort();
            snapshot.fields.insert(
                "systemd.status".into(),
                if result.output_truncated { "truncated" } else { "available" }.into(),
            );
            snapshot.fields.insert("systemd.failed_units".into(), units.join(","));
            if result.output_truncated {
                snapshot.notes.push("salida de systemctl truncada".into());
            }
        }
        Ok(result) => {
            snapshot.fields.insert("systemd.status".into(), "unavailable".into());
            snapshot.notes.push("systemctl no pudo consultar unidades (systemd puede no ser PID 1)".into());
            if !result.stderr.is_empty() {
                snapshot.notes.push("systemctl escribió diagnósticos en stderr; se omitió su contenido".into());
            }
        }
        Err(error) => {
            snapshot.fields.insert("systemd.status".into(), "unavailable".into());
            snapshot.notes.push(format!("no se pudo iniciar systemctl: {error}"));
        }
    }
}
