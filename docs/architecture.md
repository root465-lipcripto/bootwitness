# Architecture

BOOTWITNESS 0.1 is a single Rust binary with no third-party crates.

1. **Collector** reads selected procfs/sysfs/os-release values and optionally invokes journalctl with fixed arguments. It never evaluates user-provided shell text.
2. **Snapshot codec** writes a version header and hex-encodes keys and values so tabs, newlines, and Unicode cannot corrupt record boundaries.
3. **Comparator** ignores snapshot identity fields and compares the remaining collected values plus exact event string counts.
4. **Report writer** formats observed deltas and repeats the causal uncertainty in the output.
5. **Integrity check** hashes snapshot bytes with sha256sum and stores the digest next to the snapshot.

The snapshot format is versioned. Unsupported versions and malformed or duplicate fields fail closed. The current format is text, not a stable interchange format yet.

The initial data directory is per-user state. There is no database schema, service, background scheduler, or privileged collector split in this release.
