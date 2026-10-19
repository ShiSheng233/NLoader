#!/bin/sh
# Model-specific firmware addresses belong in profiles, including host code.
set -eu
cd "$(dirname "$0")/.."
# One allocation entry in core (tests/check_core_alloc.sh).
sh tests/check_core_alloc.sh
result=0
# Z8 XIP (0x4xxxxxxx) and 64-bit RAM (0xaxxxxxxxx), with Rust separators.
pattern='0x(4(_?[0-9a-f]){7}|a(_?[0-9a-f]){8})([^0-9a-f_]|$)'
grep -rEin --include='*.rs' --include='*.c' --include='*.h' \
    --include='*.S' --include='*.s' "$pattern" core tool/nloader/crates \
    || result=$?
case "$result" in
    1) exit 0 ;;
    0) echo 'Firmware address literal found in core or host sources.' >&2; exit 1 ;;
    *) exit "$result" ;;
esac
