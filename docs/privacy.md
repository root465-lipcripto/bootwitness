# Privacy

Collection is local and does not upload data. The journal collector may save error-priority message text, which can contain usernames, paths, device identifiers, addresses, or application data. Treat snapshot files as sensitive.

Unix state folders use mode 0700 and snapshot files use mode 0600. These permissions reduce exposure to other local accounts; they do not protect against the same user, root, backups, or a compromised host.

The boot command line is kept with values masked when their parameter names contain common secret-related fragments. This heuristic can miss secrets and can mask harmless values.

Report redaction currently replaces the active HOME path and IPv4-like tokens. It is not comprehensive anonymization. Inspect reports manually before publishing or sending them. Snapshot exports are not implemented.

The checksum detects data changes compared with the sidecar. Since both are stored locally and can be edited together, it is not a signature or proof of origin.
