# BOOTWITNESS

**Linux Regression Intelligence — Capture. Compare. Diagnose. Prove.**

BOOTWITNESS is a local-first Linux CLI that records a small, versioned snapshot of selected system state, compares two snapshots, highlights newly observed kernel-journal errors, and writes a cautious Markdown investigation report.

The first release is intentionally an MVP. It does not claim to identify the cause of a failure. A changed kernel and a changed error count are observations that help guide controlled reproduction; they are not proof of a kernel regression.

## What it does

- Captures kernel release/version, selected boot arguments, OS name, memory totals, loaded module count, mount and disk device counts, CPU/memory/I/O pressure summaries, network interface names, and up to 500 current-boot journal error messages when journalctl is readable.
- Stores snapshots as local versioned text files with restrictive permissions on Unix systems.
- Compares fields and event counts between a baseline and a later snapshot.
- Generates a Markdown report with best-effort redaction of the current home path and IPv4 addresses.
- Writes a SHA-256 sidecar and checks it later to catch accidental file changes.
- Works offline and requires no root privileges for the basic capture. Journal visibility depends on the local system's permissions.

## What it does not do yet

No daemon, automatic update hooks, TUI, SQLite database, active probes, hardware/PCI inventory, package history, statistical scoring, kernel bisect, recovery actions, or automatic upstream reporting are included. The roadmap lists these as future work, not current features.

## Requirements

- Linux for real system collection.
- Rust toolchain with Cargo to build from source.
- sha256sum from GNU coreutils for integrity hashing.
- journalctl is optional; without it, journal events are recorded as unavailable.
- No network connection is used by the program.

## Build and install

```
git clone https://github.com/root465-lipcripto/bootwitness.git
cd bootwitness
cargo build --release
./target/release/bw --help
```

To install for the current user:

```
install -Dm755 target/release/bw "$HOME/.local/bin/bw"
```

Make sure $HOME/.local/bin is on PATH.

## Typical workflow

Capture a healthy baseline before a kernel or driver update:

```
bw doctor
bw snapshot create --name before-update
bw snapshot list
```

After updating and rebooting:

```
bw snapshot create --name after-update
bw diff before-update after-update
bw report before-update after-update --output regression-report.md
```

The report is local. Review it and remove sensitive information before sharing it with maintainers or support teams.

To validate the stored snapshot and checksum:

```
bw evidence verify "$HOME/.local/state/bootwitness/ID.bws"
```

Or use the path printed by snapshot creation. Integrity verification detects changes relative to the adjacent local checksum file; it does not authenticate who created either file.

## Command reference

| Command | Purpose |
| --- | --- |
| bw init | Create the local state directory. |
| bw doctor | Check platform, architecture, journalctl availability, and state directory access. |
| bw snapshot create --name NAME | Capture a snapshot. Names accept ASCII letters, digits, hyphens, and underscores. |
| bw snapshot list | List local snapshots. |
| bw snapshot show ID | Print the fields and collection notes in a snapshot. |
| bw diff BASE CURRENT | Compare snapshots and show changed fields and errors whose count increased. |
| bw report BASE CURRENT [--output FILE] | Generate a Markdown report. |
| bw evidence verify FILE | Validate snapshot format and SHA-256 sidecar. |

Snapshot arguments can be IDs from the local state directory or explicit file paths.

## Testing without touching the host

The smoke test builds a minimal fake Linux proc/sys tree, captures two snapshots from it, changes the kernel release and journal fixture, and checks diff/report/integrity behavior.

```
cargo test
cargo build
bash tests/smoke.sh
```

For deterministic local experiments, set BW_HOME to a temporary state directory and BW_ROOT to a fixture root containing proc, sys, and etc folders. BW_ROOT is intended for development/testing; it does not emulate all Linux kernel interfaces.

## Data and privacy

Snapshots stay in the selected local state directory. The default is $XDG_STATE_HOME/bootwitness, or ~/.local/state/bootwitness when XDG_STATE_HOME is unset. Set BW_HOME to choose another location.

On Unix, the directory is set to mode 0700 and snapshot files to 0600. The snapshot can contain raw journal error messages and boot parameters. Boot arguments whose key appears to contain password, passwd, token, secret, or key are masked during collection, but this is not a complete secret detector.

Report redaction is deliberately described as best-effort. It replaces the current HOME path and IPv4-looking tokens; it does not promise removal of usernames, serial numbers, MAC addresses, email addresses, IPv6 addresses, or arbitrary secrets. Read the report before sharing it.

See docs/privacy.md and docs/threat-model.md for details.

## How to interpret results

- “New error” means an exact event string was absent from the baseline event set or its count increased. Timestamps are not normalized, so repeated messages with different timestamps may look like new messages.
- The journal collector asks journalctl for the latest 500 error-priority messages from the current boot. Access restrictions, retention, and truncation affect the comparison.
- Captures taken at different points in a boot can differ because the system state changed normally.
- A kernel version change next to a new error is temporal context only. Reproduce with controlled A/B boots before calling it a regression.
- SHA-256 protects against unnoticed accidental modifications only when the checksum file itself is trusted.

## Contributing

See CONTRIBUTING.md. Changes should preserve the offline, read-only default and include fixtures or tests for new collection behavior.

## License

GPL-3.0-or-later. See LICENSE.
