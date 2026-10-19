#!/bin/bash
set -euo pipefail
tests_dir="$(cd "$(dirname "$0")" && pwd)"
libc_dir="$(cd "$tests_dir/.." && pwd)"
sdk_dir="$(cd "$libc_dir/.." && pwd)"
output="${1:?usage: run.sh NEW_OUTPUT_DIRECTORY}"
compiler="${NLR_LIBC_HOST_CC:-clang}"
[[ ! -e "$output" ]] || { echo "Output already exists" >&2; exit 2; }
mkdir -p "$output"
flags=(-O1 -g -fno-builtin -fno-common -fno-omit-frame-pointer
    -fsanitize=address,undefined -Wall -Wextra -Werror)
"$compiler" "${flags[@]}" -I "$libc_dir/include" -I "$sdk_dir" \
    -include "$tests_dir/host_namespace.h" -c "$libc_dir/libc.c" -o "$output/libc.o"
"$compiler" "${flags[@]}" -I "$sdk_dir" "$tests_dir/test_libc.c" \
    "$output/libc.o" -o "$output/test_libc"
"$output/test_libc"
