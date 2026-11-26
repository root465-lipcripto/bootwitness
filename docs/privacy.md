# Privacy

Collection is local and does not upload data. Kernel journal error text may contain paths, user names, addresses, device identifiers, or application data. Treat snapshots as sensitive.

On Unix, state directories are set to mode 0700 and snapshot files to 0600. The checksum sidecar is not itself sensitive. These permissions do not protect against the same user, root, backups, or a compromised host.

The kernel command line masks parameter names containing password, passwd, token, secret, or key. Reports additionally redact the active HOME path, IPv4 and IPv6-like tokens, MAC addresses, email-like tokens, and common secret assignments. This is best-effort text processing; it may miss secrets and can redact harmless strings. It does not modify snapshots.

The journal collector requests only current-boot, error-priority kernel messages, capped at 500 lines and a bounded output size. It records whether collection was available. The systemd collector records names of failed units when systemctl can query the manager.

Review reports before sharing them. Do not submit real journal content, personal paths, addresses, or secrets in public issues.
