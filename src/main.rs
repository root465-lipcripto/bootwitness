#![forbid(unsafe_code)]

use std::{env, fs, path::{Path, PathBuf}};
const VERSION: &str = env!("CARGO_PKG_VERSION");
mod analysis;
mod collectors;
mod model;
mod process;
mod storage;
use analysis::{compare, diagnose, render_report, Changes};
use collectors::collect_snapshot;
use model::{BwError, Snapshot};
use storage::{create_private_dir, read_snapshot, resolve_snapshot, save_snapshot, sha256, state_dir};


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
        Some("diagnose") => diagnose_command(&args[1..]),
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
  bw diagnose BASE ACTUAL
  bw report BASE ACTUAL [--output ARCHIVO]
  bw evidence verify SNAPSHOT.bws

Los cambios observados no demuestran causalidad. El programa no envía datos."
    );
}

pub(crate) fn program_exists(program: &str) -> bool {
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
            let mut snapshot = snapshot;
            snapshot.fields.insert("snapshot.id".into(), id.clone());
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
                    if path.extension().is_some_and(|extension| extension == "bws")
                        && let Ok(snapshot) = read_snapshot(&path)
                    {
                        println!(
                            "{}\t{}\t{}",
                            path.file_stem().unwrap_or_default().to_string_lossy(),
                            snapshot.fields.get("snapshot.name").map(String::as_str).unwrap_or("unnamed"),
                            snapshot.fields.get("snapshot.created_unix").map(String::as_str).unwrap_or("unknown")
                        );
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
    if let Some(warning) = changes.event_warning {
        println!("EVENTOS NO COMPARABLES: {warning}");
    }
    println!("Observaciones comparativas; no prueban causalidad.");
    Ok(())
}

fn diagnose_command(args: &[String]) -> Result<(), BwError> {
    let (base, current) = load_pair(args)?;
    let changes = compare(&base, &current);
    print_findings(&base, &current, &changes);
    Ok(())
}

fn print_findings(base: &Snapshot, current: &Snapshot, changes: &Changes) {
    let findings = diagnose(base, current, changes);
    if findings.is_empty() {
        println!("No hay hallazgos para las reglas incluidas.");
    }
    for finding in findings {
        println!("[{}] {} — {}", finding.subsystem, finding.title, finding.evidence);
    }
    if let Some(warning) = &changes.event_warning {
        println!("[cobertura incompleta] {warning}");
    }
    println!("Reglas deterministas sobre evidencia observada; no confirman regresión ni causa.");
}

fn report_command(args: &[String]) -> Result<(), BwError> {
    let (base, current) = load_pair(args)?;
    let report = render_report(&base, &current);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use crate::{analysis::redact, collectors::redact_boot_arguments, storage::{parse_snapshot, serialize}};

    fn fixture(kernel: &str, events: &[&str]) -> Snapshot {
        Snapshot {
            fields: BTreeMap::from([
                ("kernel.release".into(), kernel.into()),
                ("snapshot.name".into(), "fixture".into()),
                ("journal.status".into(), "available".into()),
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
        assert!(parse_snapshot("BOOTWITNESS\t2\nfield\t61\t00\nfield\t61\t01\n").is_err());
    }

    #[test]
    fn legacy_v1_journal_events_are_marked_incompatible() {
        let legacy = parse_snapshot("BOOTWITNESS\t1\nevent\t6f6c64206d657373616765\n").unwrap();
        assert_eq!(legacy.fields.get("journal.status").unwrap(), "legacy-incompatible");
        assert!(!compare(&legacy, &fixture("6.2", &["new error"])).events_comparable);
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
