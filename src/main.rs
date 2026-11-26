#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const FORMAT_HEADER: &str = "BOOTWITNESS\t1";
const VERSION: &str = "0.1.0";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Snapshot {
    fields: BTreeMap<String, String>,
    events: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug)]
struct BwError(String);

impl std::fmt::Display for BwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<io::Error> for BwError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("bw: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), BwError> {
    match args.first().map(String::as_str) {
        None | Some("--help") | Some("help") => {
            print_help();
            Ok(())
        }
        Some("--version") => {
            println!("bw {VERSION}");
            Ok(())
        }
        Some("init") => {
            let path = state_dir()?;
            create_private_dir(&path)?;
            println!("Estado local preparado en {}", path.display());
            Ok(())
        }
        Some("doctor") => doctor(),
        Some("snapshot") => snapshot_command(&args[1..]),
        Some("diff") => diff_command(&args[1..]),
        Some("report") => report_command(&args[1..]),
        Some("evidence") => verify_command(&args[1..]),
        Some(command) => Err(BwError(format!("comando desconocido: {command}"))),
    }
}

fn print_help() {
    println!(
        "BOOTWITNESS — capturas y comparación local de Linux

USO:
  bw init
  bw doctor
  bw snapshot create --name NOMBRE
  bw snapshot list
  bw snapshot show ID-O-RUTA
  bw diff BASE ACTUAL
  bw report BASE ACTUAL [--output ARCHIVO]
  bw evidence verify SNAPSHOT.bws

Los cambios observados no demuestran causalidad. El programa no envía datos."
    );
}

fn state_dir() -> Result<PathBuf, BwError> {
    if let Some(path) = env::var_os("BW_HOME") {
        return Ok(path.into());
    }

    let root = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| BwError("define BW_HOME, HOME o XDG_STATE_HOME".into()))?;

    Ok(root.join("bootwitness"))
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn program_exists(program: &str) -> bool {
    env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .split(':')
        .any(|directory| Path::new(directory).join(program).is_file())
}

fn doctor() -> Result<(), BwError> {
    let path = state_dir()?;
    create_private_dir(&path)?;
    println!("Linux: {}", cfg!(target_os = "linux"));
    println!("Arquitectura: {}", env::consts::ARCH);
    println!(
        "journalctl: {}",
        if program_exists("journalctl") { "disponible" } else { "no encontrado" }
    );
    println!(
        "sha256sum: {}",
        if program_exists("sha256sum") { "disponible" } else { "FALTA" }
    );
    println!("Estado local: {}", path.display());
    Ok(())
}

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

fn redact_boot_arguments(value: &str) -> String {
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

fn collect_snapshot(name: &str) -> Result<(Snapshot, String), BwError> {
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

    if root == Path::new("/") && program_exists("journalctl") {
        match Command::new("journalctl")
            .args(["--boot", "--priority=err", "--no-pager", "--output=cat", "--lines=500"])
            .stdin(Stdio::null())
            .output()
        {
            Ok(output) if output.status.success() => {
                snapshot.fields.insert("journal.status".into(), "available".into());
                snapshot.events = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            _ => {
                snapshot.fields.insert("journal.status".into(), "unavailable".into());
                snapshot.notes.push("journalctl falló o requiere permisos".into());
            }
        }
    } else {
        snapshot.notes.push("journal omitido en fixture local".into());
    }

    if snapshot.fields.is_empty() {
        return Err(BwError("ninguna fuente disponible; revisa BW_ROOT".into()));
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    snapshot.fields.insert("snapshot.name".into(), name.into());
    snapshot.fields.insert("snapshot.created_unix".into(), timestamp.to_string());
    snapshot.fields.insert("snapshot.collector".into(), format!("bw/{VERSION}"));

    Ok((snapshot, format!("{timestamp}-{name}")))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, BwError> {
    if !value.len().is_multiple_of(2) {
        return Err(BwError("hexadecimal de longitud impar".into()));
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap_or(""), 16)
                .map_err(|_| BwError("hexadecimal inválido".into()))
        })
        .collect()
}

fn serialize(snapshot: &Snapshot) -> String {
    let mut output = format!("{FORMAT_HEADER}\n");
    for (key, value) in &snapshot.fields {
        output.push_str(&format!(
            "field\t{}\t{}\n",
            encode_hex(key.as_bytes()),
            encode_hex(value.as_bytes())
        ));
    }
    for event in &snapshot.events {
        output.push_str(&format!("event\t{}\n", encode_hex(event.as_bytes())));
    }
    for note in &snapshot.notes {
        output.push_str(&format!("note\t{}\n", encode_hex(note.as_bytes())));
    }
    output
}

fn parse_snapshot(value: &str) -> Result<Snapshot, BwError> {
    let mut lines = value.lines();
    if lines.next() != Some(FORMAT_HEADER) {
        return Err(BwError("formato de snapshot desconocido".into()));
    }

    let mut snapshot = Snapshot::default();
    for line in lines {
        let parts = line.split('\t').collect::<Vec<_>>();
        match parts.as_slice() {
            ["field", key, value] => {
                let key = String::from_utf8(decode_hex(key)?)
                    .map_err(|_| BwError("clave no UTF-8".into()))?;
                let value = String::from_utf8(decode_hex(value)?)
                    .map_err(|_| BwError("valor no UTF-8".into()))?;
                if snapshot.fields.insert(key, value).is_some() {
                    return Err(BwError("campo duplicado".into()));
                }
            }
            ["event", event] => snapshot.events.push(
                String::from_utf8(decode_hex(event)?)
                    .map_err(|_| BwError("evento no UTF-8".into()))?,
            ),
            ["note", note] => snapshot.notes.push(
                String::from_utf8(decode_hex(note)?)
                    .map_err(|_| BwError("nota no UTF-8".into()))?,
            ),
            _ => return Err(BwError("registro mal formado".into())),
        }
    }
    Ok(snapshot)
}

fn save_snapshot(path: &Path, snapshot: &Snapshot) -> Result<(), BwError> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(serialize(snapshot).as_bytes())?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<Snapshot, BwError> {
    let mut contents = String::new();
    File::open(path)?.read_to_string(&mut contents)?;
    parse_snapshot(&contents)
}

fn resolve_snapshot(value: &str) -> Result<PathBuf, BwError> {
    let path = PathBuf::from(value);
    if path.is_file() {
        return Ok(path);
    }
    let path = state_dir()?.join(format!("{value}.bws"));
    if path.is_file() {
        Ok(path)
    } else {
        Err(BwError(format!("snapshot no encontrado: {value}")))
    }
}

fn snapshot_command(args: &[String]) -> Result<(), BwError> {
    match args.first().map(String::as_str) {
        Some("create") => {
            let name = args
                .iter()
                .position(|arg| arg == "--name")
                .and_then(|index| args.get(index + 1))
                .map(String::as_str)
                .unwrap_or("snapshot");
            if name.is_empty()
                || name.len() > 64
                || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            {
                return Err(BwError("nombre inválido; usa letras ASCII, números, - y _".into()));
            }

            let directory = state_dir()?;
            create_private_dir(&directory)?;
            let (snapshot, id) = collect_snapshot(name)?;
            let path = directory.join(format!("{id}.bws"));
            save_snapshot(&path, &snapshot)?;
            let digest = sha256(&fs::read(&path)?)?;
            let sidecar = path.with_extension("bws.sha256");
            fs::write(&sidecar, format!("{digest}\n"))?;
            println!("Snapshot: {}", path.display());
            println!("SHA-256: {digest}");
            println!("Campos: {} | eventos: {}", snapshot.fields.len(), snapshot.events.len());
            println!("Revisa los datos sensibles antes de compartir la captura.");
            Ok(())
        }
        Some("list") => {
            let directory = state_dir()?;
            if directory.exists() {
                for entry in fs::read_dir(directory)?.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|extension| extension == "bws") {
                        println!("{}", path.display());
                    }
                }
            }
            Ok(())
        }
        Some("show") => {
            let path = resolve_snapshot(
                args.get(1).ok_or_else(|| BwError("falta ID o ruta".into()))?,
            )?;
            let snapshot = read_snapshot(&path)?;
            for (key, value) in snapshot.fields {
                println!("{key}: {value}");
            }
            println!("eventos: {}", snapshot.events.len());
            for note in snapshot.notes {
                println!("nota: {note}");
            }
            Ok(())
        }
        _ => Err(BwError("uso: snapshot create --name N | list | show ID".into())),
    }
}

#[derive(Default)]
struct Changes {
    fields: Vec<(String, Option<String>, Option<String>)>,
    errors: Vec<(String, usize)>,
}

fn compare(base: &Snapshot, current: &Snapshot) -> Changes {
    let ignored: BTreeSet<&str> = [
        "snapshot.name",
        "snapshot.created_unix",
        "snapshot.collector",
        "boot.id",
    ]
    .into_iter()
    .collect();
    let keys: BTreeSet<&String> = base.fields.keys().chain(current.fields.keys()).collect();
    let mut changes = Changes::default();

    for key in keys {
        if ignored.contains(key.as_str()) {
            continue;
        }
        let (before, after) = (base.fields.get(key).cloned(), current.fields.get(key).cloned());
        if before != after {
            changes.fields.push((key.clone(), before, after));
        }
    }

    let mut previous_counts = BTreeMap::new();
    for event in &base.events {
        *previous_counts.entry(event).or_insert(0usize) += 1;
    }
    let mut current_counts = BTreeMap::new();
    for event in &current.events {
        *current_counts.entry(event).or_insert(0usize) += 1;
    }
    for (event, count) in current_counts {
        let previous = previous_counts.get(event).copied().unwrap_or(0);
        if count > previous {
            changes.errors.push((event.clone(), count - previous));
        }
    }
    changes
}

fn load_pair(args: &[String]) -> Result<(Snapshot, Snapshot), BwError> {
    if args.len() < 2 {
        return Err(BwError("se requieren BASE y ACTUAL".into()));
    }
    Ok((
        read_snapshot(&resolve_snapshot(&args[0])?)?,
        read_snapshot(&resolve_snapshot(&args[1])?)?,
    ))
}

fn diff_command(args: &[String]) -> Result<(), BwError> {
    let (base, current) = load_pair(args)?;
    let changes = compare(&base, &current);
    for (key, before, after) in changes.fields {
        println!(
            "CAMBIO {key}: {} -> {}",
            before.unwrap_or_else(|| "no disponible".into()),
            after.unwrap_or_else(|| "no disponible".into())
        );
    }
    for (event, increase) in changes.errors {
        println!("ERROR NUEVO +{increase}: {event}");
    }
    println!("Observaciones comparativas; no prueban causalidad.");
    Ok(())
}

fn redact(value: &str) -> String {
    let mut output = value.to_owned();
    if let Some(home) = env::var_os("HOME")
        .map(|path| path.to_string_lossy().into_owned())
        .filter(|home| !home.is_empty())
    {
        output = output.replace(&home, "[HOME]");
    }
    output
        .split_whitespace()
        .map(|word| {
            let candidate = word.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');
            let parts = candidate.split('.').collect::<Vec<_>>();
            if parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok()) {
                word.replace(candidate, "[IP]")
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn report_command(args: &[String]) -> Result<(), BwError> {
    let (base, current) = load_pair(args)?;
    let changes = compare(&base, &current);
    let mut report = String::from(
        "# BOOTWITNESS — informe de investigación\n\n\
         > Las diferencias no demuestran causalidad. Requieren reproducción y revisión.\n\n\
         ## Cambios observados\n\n",
    );
    for (key, before, after) in changes.fields {
        report.push_str(&format!(
            "- {key}: {} → {}\n",
            redact(before.as_deref().unwrap_or("no disponible")),
            redact(after.as_deref().unwrap_or("no disponible"))
        ));
    }
    report.push_str("\n## Errores nuevos o aumentados\n\n");
    for (event, increase) in changes.errors {
        report.push_str(&format!("- +{increase}: {}\n", redact(&event)));
    }
    report.push_str(
        "\n## Límites y privacidad\n\n\
         Los eventos dependen de permisos y retención. La redacción de la ruta HOME es \
         limitada; revisa el informe antes de compartirlo.\n",
    );

    if let Some(index) = args.iter().position(|arg| arg == "--output") {
        let path = PathBuf::from(
            args.get(index + 1)
                .ok_or_else(|| BwError("falta la ruta de --output".into()))?,
        );
        fs::write(&path, report)?;
        println!("Informe escrito en {}", path.display());
    } else {
        print!("{report}");
    }
    Ok(())
}

fn verify_command(args: &[String]) -> Result<(), BwError> {
    if args.len() != 2 || args[0] != "verify" {
        return Err(BwError("uso: evidence verify SNAPSHOT.bws".into()));
    }
    let path = resolve_snapshot(&args[1])?;
    let expected = fs::read_to_string(path.with_extension("bws.sha256"))?;
    let actual = sha256(&fs::read(&path)?)?;
    if expected.trim() != actual {
        return Err(BwError("el SHA-256 no coincide".into()));
    }
    read_snapshot(&path)?;
    println!("SHA-256 válido. Detecta cambios; no demuestra autenticidad.");
    Ok(())
}

fn sha256(value: &[u8]) -> Result<String, BwError> {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| BwError(format!("no puedo iniciar sha256sum: {error}")))?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(value)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(BwError("sha256sum falló".into()));
    }
    let digest = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    if digest.len() != 64 {
        return Err(BwError("sha256sum devolvió un resultado inválido".into()));
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(kernel: &str, events: &[&str]) -> Snapshot {
        Snapshot {
            fields: BTreeMap::from([
                ("kernel.release".into(), kernel.into()),
                ("snapshot.name".into(), "fixture".into()),
            ]),
            events: events.iter().map(|event| (*event).into()).collect(),
            notes: vec![],
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_unicode_and_newlines() {
        let mut input = fixture("6.1", &["EXT4 error"]);
        input.fields.insert("unicode".into(), "Linux 🐧\nsecond line".into());
        assert_eq!(parse_snapshot(&serialize(&input)).unwrap(), input);
    }

    #[test]
    fn parser_rejects_unknown_format_and_duplicate_fields() {
        assert!(parse_snapshot("wrong\n").is_err());
        assert!(parse_snapshot("BOOTWITNESS\t1\nfield\t61\t00\nfield\t61\t01\n").is_err());
    }

    #[test]
    fn comparison_ignores_identity_and_finds_new_kernel_and_event() {
        let base = fixture("6.1", &["old error"]);
        let current = fixture("6.2", &["old error", "new error"]);
        let changes = compare(&base, &current);
        assert_eq!(changes.fields.len(), 1);
        assert_eq!(changes.errors, vec![("new error".into(), 1)]);
    }

    #[test]
    fn error_comparison_counts_only_increases() {
        let base = fixture("6.1", &["same", "same", "gone"]);
        let current = fixture("6.1", &["same", "same", "same"]);
        assert_eq!(compare(&base, &current).errors, vec![("same".into(), 1)]);
    }

    #[test]
    fn boot_arguments_mask_common_secret_parameters() {
        assert_eq!(
            redact_boot_arguments("quiet api_token=abc CryptKey=xyz"),
            "quiet api_token=[REDACTED] CryptKey=[REDACTED]"
        );
    }

    #[test]
    fn report_redacts_home_path_and_ipv4_addresses() {
        let report = redact(&format!(
            "failure at 192.168.1.5 {}",
            env::var("HOME").unwrap_or_default()
        ));
        assert!(report.contains("[IP]"));
        assert!(!report.contains("192.168.1.5"));
        if let Ok(home) = env::var("HOME") {
            assert!(report.contains("[HOME]"));
            assert!(!report.contains(&home));
        }
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
