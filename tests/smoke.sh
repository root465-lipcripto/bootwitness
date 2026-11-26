#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bin="$tmp/bw"
rustc --edition=2024 "$repo_root/src/main.rs" -o "$bin"
root="$tmp/root"
state="$tmp/state"
mkdir -p "$root/proc/sys/kernel" "$root/proc/pressure" "$root/proc/self" "$root/sys/class/net/lo" "$root/etc"
printf '6.1.0-test\n' > "$root/proc/sys/kernel/osrelease"
printf 'Linux version fixture\n' > "$root/proc/version"
printf 'quiet api_token=secret-value\n' > "$root/proc/cmdline"
printf 'MemTotal: 1000 kB\nMemAvailable: 500 kB\n' > "$root/proc/meminfo"
printf 'module 0 0 - Live 0\n' > "$root/proc/modules"
printf 'mount fixture\n' > "$root/proc/self/mountinfo"
printf 'disk fixture\n' > "$root/proc/diskstats"
printf 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n' > "$root/proc/pressure/cpu"
cp "$root/proc/pressure/cpu" "$root/proc/pressure/memory"
cp "$root/proc/pressure/cpu" "$root/proc/pressure/io"
printf 'PRETTY_NAME="Fixture Linux"\n' > "$root/etc/os-release"
export BW_ROOT="$root" BW_HOME="$state"
"$bin" doctor
"$bin" snapshot create --name before > "$tmp/before.out"
before="$(find "$state" -name '*-before.bws' -print -quit)"
"$bin" snapshot show "$before" | grep -q 'api_token=\[REDACTED\]'
printf '6.2.0-test\n' > "$root/proc/sys/kernel/osrelease"
"$bin" snapshot create --name after > "$tmp/after.out"
after="$(find "$state" -name '*-after.bws' -print -quit)"
"$bin" diff "$before" "$after" > "$tmp/diff.out"
grep -q 'CAMBIO kernel.release' "$tmp/diff.out"
"$bin" report "$before" "$after" --output "$tmp/report.md"
grep -q 'no demuestran causalidad' "$tmp/report.md"
"$bin" evidence verify "$before"
# A corrupted copy must not pass integrity verification.
cp "$before" "$tmp/corrupt.bws"
cp "$before" "$tmp/corrupt.bws.sha256"
printf 'tamper\n' >> "$tmp/corrupt.bws"
if "$bin" evidence verify "$tmp/corrupt.bws" >/dev/null 2>&1; then
  echo 'tampered snapshot unexpectedly passed verification' >&2
  exit 1
fi
# Unsafe path-like snapshot names must be rejected.
if "$bin" snapshot create --name '../escape' >/dev/null 2>&1; then
  echo 'unsafe snapshot name unexpectedly accepted' >&2
  exit 1
fi
printf 'smoke test passed\n'
