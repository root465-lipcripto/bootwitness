# Roadmap

## 0.1 — Foundation (implemented)

- Single Rust CLI, local snapshots, diff, Markdown report and checksum verification.

## 0.2 — Safer regression evidence (implemented)

- Modular source layout.
- Stable labels plus unique snapshot IDs.
- Kernel-only journal collection and explicit coverage status.
- Bounded child processes.
- systemd failed-unit context.
- Deterministic EXT4/JBD2, AMDGPU/DRM, OOM/memory and systemd findings.
- Broader best-effort report redaction and synthetic collector tests.

## 0.3 — Better evidence quality

- Normalize journal timestamps while retaining raw evidence.
- Distinguish message signatures from exact message strings.
- Add a stable JSON export format and coverage metadata.
- Add validated threshold/rule configuration with documented defaults.
- Track update and boot history from supported package managers.

## Later

- TUI, optional systemd integration, QEMU-backed regression fixtures, and reproducible A/B assistance.
- Any background or privileged component requires a separate threat-model review.
