#!/bin/sh
# Every block core takes from the camera's heap goes through one entry,
# nlr_alloc_whole (core/exec.c): granted whole where the heap's books can be
# read, else the allocator at its word. No other core source may call the
# services' alloc member, test its presence or hand it on as a function
# pointer; host tests (core/test_*.c) model the allocator and are exempt.
set -eu
cd "$(dirname "$0")/.."
found=$(grep -rnE '(->|\.)[[:space:]]*alloc([^a-zA-Z0-9_]|$)' core \
            --include='*.c' --include='*.h' --include='*.S' |
        grep -vE '^core/test_[^:]*:' |
        grep -vE '^core/exec\.c:' |
        grep -vE '^[^:]*:[0-9]+:[[:space:]]*(/?\*|//)' || true)
if [ -n "$found" ]; then
    echo "$found" >&2
    echo 'Core calls the heap allocator outside nlr_alloc_whole (core/exec.c).' >&2
    exit 1
fi
