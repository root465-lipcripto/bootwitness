# Threat model

## Assets

- Local system metadata and journal error messages.
- Integrity of saved snapshot bytes during ordinary storage and transfer.

## Assumptions

- The current user account and operating system are not already compromised.
- Users review generated reports before external sharing.
- journalctl and procfs/sysfs are provided by the local host.

## Controls

- No network access or automatic reporting.
- Fixed journalctl executable and arguments; no shell invocation.
- Read-only collection.
- User-private directory and file modes on Unix.
- Versioned parser rejects malformed records.
- SHA-256 sidecar allows accidental corruption checks.

## Out of scope

The tool does not defend against root or same-user tampering, forged snapshots, malicious kernel interfaces, denial-of-service from unusually large local data, or complete deanonymization. Hashes are not signatures. Best-effort report redaction is not a security boundary.
