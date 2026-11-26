# Contributing

Thanks for helping improve BOOTWITNESS.

- Keep the default behavior offline and read-only.
- Do not add arbitrary shell execution or automatic system changes.
- Represent unavailable data as unavailable; do not invent defaults that look like measurements.
- Add deterministic tests or fixtures for parser, collector, and comparison changes.
- Explain data sensitivity and permission requirements for each new source.
- Keep reports clear that correlation does not prove causation.
- Run cargo fmt --check, cargo test, cargo clippy -- -D warnings, and bash tests/smoke.sh before submitting changes.
