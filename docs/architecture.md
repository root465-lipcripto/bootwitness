# Architecture

BOOTWITNESS 0.2 is a dependency-free Rust binary split into five modules:

- model: shared snapshot and application error types.
- collectors: procfs/sysfs, kernel-only journalctl and failed systemd unit collection.
- storage: versioned snapshot codec, local paths, collision-safe writes, and SHA-256 verification.
- analysis: field/event comparison, deterministic subsystem diagnoses, and report redaction/rendering.
- process: bounded child process execution with timeout and stdout/stderr limits.

Collectors use fixed executable names and fixed arguments. They do not invoke a shell. journalctl and systemctl have a five-second timeout; their captured output is capped and truncation is recorded. The output reader drains stdout and stderr concurrently to avoid pipe deadlocks.

Kernel events are comparable only when both snapshots have journal.status=available. Timed-out, failed, or truncated output is not comparable. systemd failed-unit additions are diagnosed only when both snapshots have systemd.status=available. Missing coverage never becomes an empty-success result.

Snapshots use a versioned text format with hex-encoded keys and values. The on-disk format remains version 1, so prior snapshots remain readable; older snapshots without explicit collector status are conservatively treated as incomplete for event comparison.

The application is local and read-only. It has no daemon, database, network client, automatic action, or privileged helper.
