# Changelog

## 0.2.0 — Regression evidence and subsystem diagnosis

- Split model, collectors, storage, analysis, and child-process handling into modules.
- Resolve snapshots by human-readable label and make timestamp IDs collision-resistant; refuse to overwrite an existing snapshot file.
- Collect kernel-only error messages and failed systemd units through bounded child processes.
- Mark journal/systemd coverage as available, unavailable, or timed out. Do not compare kernel events when either journal is incomplete.
- Add deterministic EXT4/JBD2, AMDGPU/DRM, OOM/memory and systemd findings plus a diagnose command.
- Expand best-effort report redaction to IPv4, IPv6, MAC, email-like tokens and common secret assignments.
- Exercise journal and systemd collectors with local stubs in the smoke test.

## 0.1.0 — Initial MVP

- Linux state snapshots and local comparison.
- Markdown report generation and SHA-256 sidecar validation.
- Offline, read-only operation.
