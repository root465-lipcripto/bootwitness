#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bin="$tmp/bw"
CARGO_PKG_VERSION=0.2.0 rustc --edition=2024 "$repo_root/src/main.rs" -o "$bin"
root="$tmp/root"
state="$tmp/state"
mkdir -p "$tmp/bin" "$root/proc/sys/kernel" "$root/proc/pressure" "$root/proc/self" "$root/sys/class/net/lo" "$root/etc"

cat > "$tmp/bin/journalctl" <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$@" >> "$BW_JOURNAL_ARGS"
[ "${BW_JOURNAL_FAIL:-0}" = 0 ] || exit 1
cat "$BW_JOURNAL_FILE"
SCRIPT
cat > "$tmp/bin/systemctl" <<'SCRIPT'
#!/bin/sh
[ "${BW_SYSTEMD_FAIL:-0}" = 0 ] || exit 1
cat "$BW_UNITS_FILE"
SCRIPT
chmod +x "$tmp/bin/journalctl" "$tmp/bin/systemctl"

printf '6.1.0-test\n' > "$root/proc/sys/kernel/osrelease"
printf 'Linux version fixture\n' > "$root/proc/version"
printf 'quiet api_token=secret-value\n' > "$root/proc/cmdline"
printf 'MemTotal: 1000 kB\nMemAvailable: 800 kB\n' > "$root/proc/meminfo"
printf 'module 0 0 - Live 0\n' > "$root/proc/modules"
printf 'mount fixture\n' > "$root/proc/self/mountinfo"
printf 'disk fixture\n' > "$root/proc/diskstats"
printf 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n' > "$root/proc/pressure/cpu"
cp "$root/proc/pressure/cpu" "$root/proc/pressure/memory"
cp "$root/proc/pressure/cpu" "$root/proc/pressure/io"
printf 'PRETTY_NAME="Fixture Linux"\n' > "$root/etc/os-release"
printf 'baseline kernel marker\n' > "$tmp/journal"
: > "$tmp/units"
export PATH="$tmp/bin:$PATH" BW_ROOT="$root" BW_HOME="$state"
export BW_JOURNAL_FILE="$tmp/journal" BW_JOURNAL_ARGS="$tmp/journal-args" BW_UNITS_FILE="$tmp/units"

"$bin" doctor
"$bin" snapshot create --name before-update > "$tmp/before.out"
before="$(find "$state" -name '*-before-update.bws' -print -quit)"
"$bin" snapshot show "$before" | grep -q 'api_token=\[REDACTED\]'
grep -qx -- '--dmesg' "$tmp/journal-args"
printf '6.2.0-test\n' > "$root/proc/sys/kernel/osrelease"
printf 'baseline kernel marker\nEXT4-fs error on /dev/test at 192.0.2.55 user@example.test aa:bb:cc:dd:ee:ff [2001:db8::1]\namdgpu: ring timeout\nOut of memory: Killed process\n' > "$tmp/journal"
printf 'broken.service loaded failed failed fixture\n' > "$tmp/units"
"$bin" snapshot create --name after-update > "$tmp/after.out"
after="$(find "$state" -name '*-after-update.bws' -print -quit)"
"$bin" diff before-update after-update > "$tmp/diff.out"
grep -q 'CAMBIO kernel.release' "$tmp/diff.out"
"$bin" diagnose before-update after-update > "$tmp/diagnose.out"
grep -q '\[EXT4/JBD2\]' "$tmp/diagnose.out"
grep -q '\[GPU/DRM\]' "$tmp/diagnose.out"
grep -q '\[memoria\]' "$tmp/diagnose.out"
grep -q '\[systemd\]' "$tmp/diagnose.out"
"$bin" report before-update after-update --output "$tmp/report.md"
grep -q 'no demuestran causalidad' "$tmp/report.md"
if grep -Eq '192\.0\.2\.55|user@example\.test|aa:bb:cc:dd:ee:ff|2001:db8::1' "$tmp/report.md"; then
  echo 'report contained a value that should have been redacted' >&2
  exit 1
fi
"$bin" evidence verify "$before"

# Legacy v1 snapshots remain readable, but their mixed-system journal is never compared.
cp "$before" "$tmp/legacy-v1.bws"
sed -i '1s/2$/1/' "$tmp/legacy-v1.bws"
"$bin" snapshot show "$tmp/legacy-v1.bws" | grep -q 'journal.status: legacy-incompatible'
"$bin" diff "$tmp/legacy-v1.bws" "$after" > "$tmp/legacy-diff.out"
if grep -q 'ERROR NUEVO' "$tmp/legacy-diff.out"; then
  echo 'legacy mixed journal events were compared as kernel events' >&2
  exit 1
fi

# An unavailable baseline must suppress event conclusions instead of flagging everything as new.
BW_JOURNAL_FAIL=1 BW_SYSTEMD_FAIL=1 "$bin" snapshot create --name unavailable > "$tmp/unavailable.out"
unavailable="$(find "$state" -name '*-unavailable.bws' -print -quit)"
"$bin" diff "$unavailable" "$after" > "$tmp/incomplete-diff.out"
grep -q 'EVENTOS NO COMPARABLES' "$tmp/incomplete-diff.out"
if grep -q 'ERROR NUEVO' "$tmp/incomplete-diff.out"; then
  echo 'events from a partial baseline were misclassified as new' >&2
  exit 1
fi

# Reusing a label creates distinct IDs; name lookup resolves successfully.
"$bin" snapshot create --name repeated > /dev/null
"$bin" snapshot create --name repeated > /dev/null
count="$(find "$state" -name '*-repeated.bws' | wc -l)"
[ "$count" -eq 2 ]
"$bin" diff repeated after-update > /dev/null

# A corrupted copy fails integrity validation, and unsafe names are rejected.
cp "$before" "$tmp/corrupt.bws"
cp "$before" "$tmp/corrupt.bws.sha256"
printf 'tamper\n' >> "$tmp/corrupt.bws"
if "$bin" evidence verify "$tmp/corrupt.bws" >/dev/null 2>&1; then
  echo 'tampered snapshot unexpectedly passed verification' >&2
  exit 1
fi
if "$bin" snapshot create --name '../escape' >/dev/null 2>&1; then
  echo 'unsafe snapshot name unexpectedly accepted' >&2
  exit 1
fi
if [ "$(stat -c %a "$state")" != 700 ] || [ "$(stat -c %a "$before")" != 600 ]; then
  echo 'snapshot storage permissions were not restrictive' >&2
  exit 1
fi
printf 'smoke test passed\n'
