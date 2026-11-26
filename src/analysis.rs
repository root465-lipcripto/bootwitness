use std::{collections::{BTreeMap, BTreeSet}, net::Ipv6Addr, str::FromStr};

use crate::model::Snapshot;

#[derive(Default, Debug)]
pub struct Changes {
    pub fields: Vec<(String, Option<String>, Option<String>)>,
    pub errors: Vec<(String, usize)>,
    pub events_comparable: bool,
    pub event_warning: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub subsystem: &'static str,
    pub title: &'static str,
    pub evidence: String,
}

pub fn compare(base: &Snapshot, current: &Snapshot) -> Changes {
    let ignored: BTreeSet<&str> = [
        "snapshot.name",
        "snapshot.created_unix",
        "snapshot.created_unix_ns",
        "snapshot.id",
        "snapshot.collector",
        "journal.status",
        "systemd.status",
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

    changes.events_comparable = base.fields.get("journal.status").map(String::as_str)
        == Some("available")
        && current.fields.get("journal.status").map(String::as_str) == Some("available");

    if changes.events_comparable {
        let mut baseline_counts = BTreeMap::new();
        for event in &base.events {
            *baseline_counts.entry(event).or_insert(0usize) += 1;
        }
        let mut current_counts = BTreeMap::new();
        for event in &current.events {
            *current_counts.entry(event).or_insert(0usize) += 1;
        }
        for (event, count) in current_counts {
            let previous = baseline_counts.get(event).copied().unwrap_or(0);
            if count > previous {
                changes.errors.push((event.clone(), count - previous));
            }
        }
    } else {
        changes.event_warning = Some(
            "No se compararon eventos: journal.status debe ser available en ambas capturas.".into(),
        );
    }

    changes
}

pub fn diagnose(base: &Snapshot, current: &Snapshot, changes: &Changes) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (event, increase) in &changes.errors {
        let text = event.to_ascii_lowercase();
        let subsystem = if text.contains("ext4-fs error") || text.contains("jbd2/") {
            Some(("EXT4/JBD2", "Nuevo error de filesystem EXT4/JBD2"))
        } else if text.contains("amdgpu") || text.contains("drm:") || text.contains("drm/amd") {
            Some(("GPU/DRM", "Nuevo error de gráficos AMDGPU/DRM"))
        } else if text.contains("out of memory") || text.contains("oom-kill") || text.contains("oom killer") {
            Some(("memoria", "Nuevo evento OOM o presión de memoria"))
        } else if text.contains("failed to start") || text.contains("systemd[") || text.contains("unit failed") {
            Some(("systemd", "Nuevo error relacionado con systemd"))
        } else {
            None
        };
        if let Some((subsystem, title)) = subsystem {
            findings.push(Finding {
                subsystem,
                title,
                evidence: format!("recuento aumentado en {increase}: {event}"),
            });
        }
    }

    if base.fields.get("systemd.status").map(String::as_str) == Some("available")
        && current.fields.get("systemd.status").map(String::as_str) == Some("available")
    {
        let old = base.fields.get("systemd.failed_units").cloned().unwrap_or_default();
        let new = current.fields.get("systemd.failed_units").cloned().unwrap_or_default();
        let old_units = old.split(',').filter(|unit| !unit.is_empty()).collect::<BTreeSet<_>>();
        let new_units = new.split(',').filter(|unit| !unit.is_empty()).collect::<BTreeSet<_>>();
        let added = new_units.difference(&old_units).copied().collect::<Vec<_>>();
        if !added.is_empty() {
            findings.push(Finding {
                subsystem: "systemd",
                title: "Aparecieron unidades fallidas",
                evidence: format!("unidades nuevas: {}", added.join(", ")),
            });
        }
    }

    if let (Some(before), Some(after)) = (
        base.fields.get("memory.available_kib").and_then(|v| v.parse::<u64>().ok()),
        current.fields.get("memory.available_kib").and_then(|v| v.parse::<u64>().ok()),
    ) && before > 0 && after < before.saturating_mul(3) / 4
    {
        findings.push(Finding {
            subsystem: "memoria",
            title: "Memoria disponible descendió más de un 25 %",
            evidence: format!("MemAvailable: {before} KiB -> {after} KiB"),
        });
    }

    findings
}

pub fn render_report(base: &Snapshot, current: &Snapshot) -> String {
    let changes = compare(base, current);
    let findings = diagnose(base, current, &changes);
    let mut report = String::from(
        "# BOOTWITNESS — informe de investigación\n\n\
         > Hallazgos heurísticos para revisión. Las diferencias no demuestran causalidad.\n\n\
         ## Diagnósticos por subsistema\n\n",
    );
    if findings.is_empty() {
        report.push_str("No hay hallazgos para las reglas incluidas.\n\n");
    }
    for finding in findings {
        report.push_str(&format!(
            "- **{}:** {} — {}\n",
            finding.subsystem,
            finding.title,
            redact(&finding.evidence)
        ));
    }

    report.push_str("\n## Cambios observados\n\n");
    if changes.fields.is_empty() {
        report.push_str("Sin cambios en los campos comparables.\n");
    }
    for (key, before, after) in changes.fields {
        report.push_str(&format!(
            "- {key}: {} → {}\n",
            redact(before.as_deref().unwrap_or("no disponible")),
            redact(after.as_deref().unwrap_or("no disponible"))
        ));
    }

    report.push_str("\n## Eventos del kernel\n\n");
    if let Some(warning) = changes.event_warning {
        report.push_str(&format!("No disponible: {warning}\n"));
    } else if changes.errors.is_empty() {
        report.push_str("No se observaron nuevos errores en los mensajes capturados.\n");
    } else {
        for (event, increase) in changes.errors {
            report.push_str(&format!("- +{increase}: {}\n", redact(&event)));
        }
    }

    report.push_str(
        "\n## Límites y próximos pasos\n\n\
         - Las reglas clasifican texto y contadores; no prueban que el cambio del kernel sea la causa.\n\
         - Reproduce el problema con arranques A/B y revisa journal, estado de unidades y hardware.\n\
         - La redacción automática es best-effort. Lee el informe antes de compartirlo.\n",
    );
    report
}

pub fn redact(value: &str) -> String {
    let mut output = value.to_owned();
    if let Some(home) = std::env::var_os("HOME")
        .map(|path| path.to_string_lossy().into_owned())
        .filter(|home| !home.is_empty())
    {
        output = output.replace(&home, "[HOME]");
    }

    output
        .split_whitespace()
        .map(redact_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_token(token: &str) -> String {
    if let Some((key, _value)) = token.split_once('=') {
        let key_lower = key.to_ascii_lowercase();
        if ["password", "passwd", "token", "secret", "api_key", "apikey", "authorization", "cookie"]
            .iter()
            .any(|fragment| key_lower.contains(fragment))
        {
            return format!("{key}=[REDACTED]");
        }
    }

    let (prefix, candidate, suffix) = peel_punctuation(token);
    if is_ipv4(candidate) || is_mac_address(candidate) || is_email(candidate) || is_ipv6(candidate) {
        return format!("{prefix}[REDACTED]{suffix}");
    }
    token.to_owned()
}

fn peel_punctuation(value: &str) -> (&str, &str, &str) {
    let start = value
        .char_indices()
        .find(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == ':' || *ch == '@')
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    let end = value
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == ':' || *ch == '@')
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(start);
    (&value[..start], &value[start..end], &value[end..])
}

fn is_ipv4(value: &str) -> bool {
    let address = value.split_once(':').map(|(ip, _port)| ip).unwrap_or(value);
    let parts = address.split('.').collect::<Vec<_>>();
    parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn is_ipv6(value: &str) -> bool {
    let address = value.split_once('%').map(|(ip, _scope)| ip).unwrap_or(value);
    Ipv6Addr::from_str(address).is_ok()
}

fn is_mac_address(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(journal_status: Option<&str>, events: &[&str]) -> Snapshot {
        let mut fields = BTreeMap::new();
        if let Some(status) = journal_status {
            fields.insert("journal.status".into(), status.into());
        }
        Snapshot {
            fields,
            events: events.iter().map(|event| (*event).into()).collect(),
            notes: vec![],
        }
    }

    #[test]
    fn missing_baseline_journal_never_marks_existing_errors_as_new() {
        let base = snapshot(Some("unavailable"), &[]);
        let current = snapshot(Some("available"), &["known kernel error"]);
        let changes = compare(&base, &current);
        assert!(!changes.events_comparable);
        assert!(changes.errors.is_empty());
        assert!(changes.event_warning.is_some());
    }

    #[test]
    fn journal_events_compare_only_when_both_sides_are_available() {
        let base = snapshot(Some("available"), &["old"]);
        let current = snapshot(Some("available"), &["old", "new"]);
        let changes = compare(&base, &current);
        assert!(changes.events_comparable);
        assert_eq!(changes.errors, vec![("new".into(), 1)]);
    }

    #[test]
    fn diagnoses_kernel_subsystems_and_new_failed_units() {
        let mut base = snapshot(Some("available"), &[]);
        let mut current = snapshot(Some("available"), &["EXT4-fs error on device", "amdgpu: ring timeout", "Out of memory: Killed process"]);
        base.fields.insert("systemd.status".into(), "available".into());
        base.fields.insert("systemd.failed_units".into(), "old.service".into());
        current.fields.insert("systemd.status".into(), "available".into());
        current.fields.insert("systemd.failed_units".into(), "new.service,old.service".into());
        let changes = compare(&base, &current);
        let findings = diagnose(&base, &current, &changes);
        assert!(findings.iter().any(|finding| finding.subsystem == "EXT4/JBD2"));
        assert!(findings.iter().any(|finding| finding.subsystem == "GPU/DRM"));
        assert!(findings.iter().any(|finding| finding.subsystem == "memoria"));
        assert!(findings.iter().any(|finding| finding.evidence.contains("new.service")));
    }

    #[test]
    fn missing_systemd_baseline_does_not_report_all_failed_units_as_new() {
        let base = snapshot(Some("available"), &[]);
        let mut current = snapshot(Some("available"), &[]);
        current.fields.insert("systemd.status".into(), "available".into());
        current.fields.insert("systemd.failed_units".into(), "old.service".into());
        let findings = diagnose(&base, &current, &compare(&base, &current));
        assert!(!findings.iter().any(|finding| finding.title == "Aparecieron unidades fallidas"));
    }

    #[test]
    fn redacts_ip_mac_email_and_secret_assignment() {
        let clean = redact("host 192.168.1.4 [2001:db8::1] aa:bb:cc:dd:ee:ff me@example.com api_token=abc");
        assert!(!clean.contains("192.168.1.4"));
        assert!(!clean.contains("2001:db8::1"));
        assert!(!clean.contains("aa:bb:cc:dd:ee:ff"));
        assert!(!clean.contains("me@example.com"));
        assert!(!clean.contains("api_token=abc"));
    }
}
