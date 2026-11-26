use std::{env, fs::{self, File, OpenOptions}, io::{self, Read, Write}, path::{Path, PathBuf}, process::Command, time::{Duration, SystemTime, UNIX_EPOCH}};
use crate::process::run_bounded_with_input;
use crate::model::{BwError, Snapshot};
const FORMAT_HEADER: &str = "BOOTWITNESS\t2";
const LEGACY_FORMAT_HEADER: &str = "BOOTWITNESS\t1";


pub fn state_dir() -> Result<PathBuf, BwError> {
    if let Some(path) = env::var_os("BW_HOME") {
        return Ok(path.into());
    }

    let root = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| BwError("define BW_HOME, HOME o XDG_STATE_HOME".into()))?;

    Ok(root.join("bootwitness"))
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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

pub fn serialize(snapshot: &Snapshot) -> String {
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

pub fn parse_snapshot(value: &str) -> Result<Snapshot, BwError> {
    let mut lines = value.lines();
    let format = lines.next();
    if format != Some(FORMAT_HEADER) && format != Some(LEGACY_FORMAT_HEADER) {
        return Err(BwError("formato de snapshot desconocido".into()));
    }
    let legacy = format == Some(LEGACY_FORMAT_HEADER);

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
    if legacy {
        // v0.1 queried the general system journal, so its events cannot be mixed with v0.2 kernel-only logs.
        snapshot.fields.insert("journal.status".into(), "legacy-incompatible".into());
        snapshot.fields.insert("systemd.status".into(), "unavailable".into());
        snapshot.notes.push("snapshot legacy v1: los mensajes de journal no eran kernel-only y no se comparan".into());
    }
    Ok(snapshot)
}

pub fn save_snapshot(path: &Path, snapshot: &Snapshot) -> Result<(), BwError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(serialize(snapshot).as_bytes())?;
    file.sync_all()?;
    drop(file);

    // hard_link is atomic and fails if a target with this snapshot ID already exists.
    let result = fs::hard_link(&temporary, path);
    let _ = fs::remove_file(&temporary);
    result?;
    Ok(())
}

pub fn read_snapshot(path: &Path) -> Result<Snapshot, BwError> {
    let mut contents = String::new();
    File::open(path)?.read_to_string(&mut contents)?;
    parse_snapshot(&contents)
}

pub fn resolve_snapshot(selector: &str) -> Result<PathBuf, BwError> {
    let explicit_path = PathBuf::from(selector);
    if explicit_path.is_file() {
        return Ok(explicit_path);
    }

    let directory = state_dir()?;
    let by_id = directory.join(format!("{selector}.bws"));
    if by_id.is_file() {
        return Ok(by_id);
    }

    // The human-readable name is an alias. If reused, resolve to its newest capture.
    let mut matches = fs::read_dir(&directory)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "bws"))
        .filter_map(|path| {
            let snapshot = read_snapshot(&path).ok()?;
            if snapshot.fields.get("snapshot.name")?.as_str() != selector {
                return None;
            }
            let created = snapshot
                .fields
                .get("snapshot.created_unix_ns")
                .and_then(|value| value.parse::<u128>().ok())
                .unwrap_or_default();
            Some((created, path))
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|(created, _)| *created);
    matches.pop().map(|(_, path)| path).ok_or_else(|| {
        BwError(format!("snapshot no encontrado por ID, nombre o ruta: {selector}"))
    })
}

pub fn sha256(value: &[u8]) -> Result<String, BwError> {
    let mut command = Command::new("sha256sum");
    let output = run_bounded_with_input(
        &mut command,
        Some(value.to_vec()),
        Duration::from_secs(3),
        1024,
    )
    .map_err(|error| BwError(format!("no puedo iniciar sha256sum: {error}")))?;
    if output.timed_out {
        return Err(BwError("sha256sum excedió el límite de 3 segundos".into()));
    }
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
