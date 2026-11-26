# BOOTWITNESS

**Linux Regression Intelligence — Capture. Compare. Diagnose. Prove.**

BOOTWITNESS is a local-first Linux CLI for collecting a small system snapshot, comparing it with a baseline, and organizing evidence into subsystem-specific findings. Version 0.2.0 adds kernel-only journal collection, failed-unit context, cautious comparison rules, and best-effort report redaction.

A finding is a lead to investigate. It is not a confirmed regression, root cause, or probability score.

## What 0.2.0 does

- Captures selected procfs/sysfs values: kernel release/version and boot arguments, OS name, memory totals, module count, mounted filesystem count, disk device count, CPU/memory/I/O PSI summaries, and network interface names.
- Reads up to 500 current-boot error-priority kernel messages using journalctl with the kernel-only option.
- Records failed systemd unit names when systemctl is reachable.
- Tracks collection availability explicitly. Error events are compared only when both snapshots report an available kernel journal; incomplete coverage is shown as a warning.
- Compares system fields and event counts, and resolves snapshots by ID, explicit path, or human-readable name. Reusing a name resolves to its newest snapshot; each capture receives a nanosecond timestamp ID and does not overwrite an existing target.
- Runs deterministic rules for EXT4/JBD2 errors, AMDGPU/DRM errors, OOM events and substantial drops in available memory, plus newly failed systemd units.
- Produces Markdown reports that redact common secrets, IPv4/IPv6 addresses, MAC addresses, email-like tokens and the current home path. Redaction remains best-effort.
- Bounds journalctl and systemctl execution to five seconds and caps captured output. SHA-256 execution is also bounded.
- Stores data locally with private Unix directory/file permissions and makes no network requests.

## Deliberate limits

The diagnostic engine classifies collected evidence; it does not run active hardware or filesystem probes, change system state, identify a responsible kernel commit, or prove causality. Event matching is still exact text matching, so timestamps and message formatting can affect comparisons. Existing failed systemd units are not called new unless both snapshots had a usable systemd baseline.

This version does not include a daemon, update hooks, TUI, SQLite, hardware/PCI inventory, package history, statistical confidence score, kernel bisect, recovery actions, or automatic upstream reporting.

## Requirements

- Linux for real system collection.
- Rust stable with Cargo to build.
- sha256sum from GNU coreutils for evidence hashes.
- journalctl and systemctl are optional. Their status is recorded as available, unavailable, or timed out.
- No root access or network connection is required for normal use.

## Build and install

~~~
git clone https://github.com/root465-lipcripto/bootwitness.git
cd bootwitness
cargo build --release
./target/release/bw --help
install -Dm755 target/release/bw "$HOME/.local/bin/bw"
~~~

Make sure $HOME/.local/bin is on PATH.

## Typical workflow

Capture a healthy baseline before a kernel or driver update:

~~~
bw doctor
bw snapshot create --name before-update
bw snapshot list
~~~

After the update and reboot:

~~~
bw snapshot create --name after-update
bw diff before-update after-update
bw diagnose before-update after-update
bw report before-update after-update --output regression-report.md
~~~

The examples resolve by label; if a label is reused, BOOTWITNESS selects its most recent capture. Use the full ID or path printed during capture when you need an exact one.

Verify a snapshot and its adjacent checksum:

~~~
bw evidence verify "$HOME/.local/state/bootwitness/ID.bws"
~~~

This catches accidental changes only if the sidecar itself is trusted. It does not authenticate the snapshot's origin.

## Commands

| Command | Purpose |
| --- | --- |
| bw init | Create the local state directory. |
| bw doctor | Check Linux, architecture, state directory, journalctl, and sha256sum. |
| bw snapshot create --name NAME | Capture system context and evidence. |
| bw snapshot list | List IDs, names, and capture timestamps. |
| bw snapshot show ID-OR-NAME | Inspect a snapshot and collection notes. |
| bw diff BASE CURRENT | Compare fields and kernel error counts; report coverage gaps. |
| bw diagnose BASE CURRENT | Run deterministic subsystem rules over the captured evidence. |
| bw report BASE CURRENT [--output FILE] | Write a reviewable Markdown report. |
| bw evidence verify FILE | Check snapshot format and SHA-256 sidecar. |

Arguments to diff, diagnose, report and show accept an ID, a name, or a direct snapshot path.

## Data collection and privacy

Snapshots are stored under XDG_STATE_HOME/bootwitness, or ~/.local/state/bootwitness if XDG_STATE_HOME is unset. Set BW_HOME for a different location. Unix state directories use mode 0700 and snapshot files mode 0600.

Snapshots may include raw kernel error messages and boot arguments. Common secret-like boot argument keys are masked during capture. Report redaction runs on the exported report, but it is not a security boundary and does not modify the original snapshot. Review reports before sharing.

journalctl and systemctl are run with fixed arguments and no shell. Child processes have a five-second timeout; output is bounded. Missing permissions or missing services are recorded as unavailable rather than replaced with invented values.

See docs/privacy.md, docs/threat-model.md, and docs/architecture.md.

## Interpretation

- A kernel version change beside new messages is temporal context, not proof of a cause.
- Kernel messages are compared only if both snapshot collectors report journal status available.
- The collection reads only the latest 500 current-boot kernel messages at error priority. Permissions, journal retention and output limits affect coverage.
- systemd unit differences are only inferred when both captures could query systemctl.
- Memory availability falling by more than 25% is a deterministic investigation hint, not a regression claim.
- Event text is compared exactly. Message timestamps or changing values can cause similar events to appear distinct.
- Reproduce the issue with controlled A/B boots and review the generated evidence before reporting upstream.

## Development and tests

The source is split into model, collector, storage, analysis and process modules.

~~~
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
bash tests/smoke.sh
~~~

The smoke test builds a fake proc/sys tree and stub journalctl/systemctl executables. It checks kernel-only journal arguments, subsystem diagnosis, missing-baseline handling, label lookup, unique IDs, redaction, timeout/output bounds, permissions, and integrity tampering without changing the host.

## License

GPL-3.0-only. See LICENSE.
