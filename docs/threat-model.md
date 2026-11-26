# Threat model

## Assets

- Locally collected kernel and systemd evidence.
- Integrity of snapshot bytes during ordinary storage and transfer.

## Controls

- Offline and read-only operation.
- Fixed journalctl/systemctl arguments; no shell interpretation.
- Five-second process timeout and bounded captured output.
- User-private Unix state directory and snapshot file modes.
- Atomic no-overwrite snapshot creation.
- Versioned parser rejects malformed and duplicate records.
- SHA-256 checksum detects accidental data modification.
- Event conclusions suppressed when the baseline or current journal is unavailable.

## Limits

The tool does not defend against root or same-user tampering, forged snapshots, malicious kernel interfaces, host compromise, or complete deanonymization. Hash and sidecar are stored together and are not a signature. Redaction is not a security boundary.

Subsystem rules are heuristic text classifiers. They do not prove a kernel regression or identify a root cause. Exact journal string comparison can miss semantically identical messages that differ in timestamps or values.
