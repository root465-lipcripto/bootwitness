# Contributing

- Keep default behavior offline and read-only.
- Do not add arbitrary command execution or automatic system changes.
- Mark unavailable or timed-out sources explicitly. Never treat missing data as a zero measurement.
- Keep kernel messages restricted to kernel journal sources.
- Add tests for available, unavailable, timed-out, truncated, and malformed inputs when touching collectors or storage.
- Preserve the causal uncertainty in diffs and reports.
- Document sensitive data sources and report redaction limits.
- Run cargo test --all-targets, cargo clippy --all-targets -- -D warnings, cargo build --release, and bash tests/smoke.sh before submitting.
