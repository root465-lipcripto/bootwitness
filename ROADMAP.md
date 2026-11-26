# Roadmap

## 0.1 — Foundation (implemented)

- Single Rust CLI with no third-party crates.
- Selected procfs/sysfs and journal collectors.
- Versioned snapshots, diff, report, checksum verification.
- Documentation and synthetic smoke test.

## 0.2 — Stronger comparisons

- Normalize journal timestamps while preserving raw evidence.
- Track collector coverage and truncation explicitly.
- Add configurable, declarative diagnostic rules.
- Add package/kernel boot context collectors with fixtures.

## 0.3 — Evidence workflow

- Structured JSON export and report metadata.
- Redaction preview and field-level export controls.
- Retention and storage-size limits.
- Stable format migration strategy.

## Later

- TUI, optional systemd integration, QEMU integration tests, and reproducible A/B assistance.
- Any background or privileged component requires a separate threat-model review.
