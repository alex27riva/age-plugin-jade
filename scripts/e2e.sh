#!/usr/bin/env bash
# End-to-end test: real age CLI + age-plugin-jade + mock Jade devices.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$PWD/bin:$PATH"
command -v age >/dev/null || { echo "age not found on PATH"; exit 1; }

W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT

jade-mock -listen 127.0.0.1:30121 2>"$W/mock.log" &
jade-mock -listen 127.0.0.1:30122 -passphrase other 2>/dev/null &
jade-mock -listen 127.0.0.1:30123 -decline 2>/dev/null &
sleep 0.5

export JADE_PORT=tcp:127.0.0.1:30121
age-plugin-jade --generate -o "$W/id.txt" 2>/dev/null
R=$(age-plugin-jade -y "$W/id.txt")
head -c 100000 /dev/urandom >"$W/plain"

# Encryption must not need the device.
JADE_PORT=tcp:127.0.0.1:1 age -r "$R" -o "$W/enc.age" "$W/plain"
age -d -i "$W/id.txt" "$W/enc.age" 2>/dev/null | cmp - "$W/plain"
echo "PASS decrypt"

if JADE_PORT=tcp:127.0.0.1:30122 age -d -i "$W/id.txt" "$W/enc.age" 2>"$W/err" >/dev/null; then
  echo "FAIL: wrong passphrase decrypted"; exit 1
fi
grep -q "different key" "$W/err" && echo "PASS wrong passphrase rejected before prompting"

if JADE_PORT=tcp:127.0.0.1:30123 age -d -i "$W/id.txt" "$W/enc.age" 2>"$W/err" >/dev/null; then
  echo "FAIL: declined but decrypted"; exit 1
fi
grep -q "declined" "$W/err" && echo "PASS decline"

echo "all e2e checks passed"
