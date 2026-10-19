#!/bin/sh
# build.sh <new out dir> [clang] [z63|z8]: the ABI 5 code-channel fixtures,
# CODET.NLB (foreground) and HOOKX.NLB (resource extension), for the body
# whose target.h and declarations sit in that subdirectory (default z63).
# The output directory must not exist yet.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:?usage: build.sh <new out dir> [clang] [z63|z8]}
CC=${2:-clang}
BODY=${3:-z63}
TARGET="$HERE/$BODY"
[ -f "$TARGET/target.h" ] || { echo "unknown body: $BODY" >&2; exit 1; }
[ -e "$OUT" ] && { echo "refusing: $OUT exists" >&2; exit 1; }
RES=$($CC -print-resource-dir)/include
mkdir -p "$OUT/obj"
COMMON="--target=aarch64-none-elf -march=armv8-a -ffreestanding -fno-common
 -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables
 -fPIC -fvisibility=hidden -nostdinc -isystem $RES -I $ROOT/sdk -I $TARGET
 -fno-jump-tables -fno-builtin -O2 -Wall -Wextra -Werror"
$CC $COMMON -c "$HERE/code_channel.c" -o "$OUT/obj/code_channel.o"
$CC $COMMON -c "$HERE/hook_extension.c" -o "$OUT/obj/hook_extension.o"
$CC --target=aarch64-none-elf -x assembler-with-cpp -DNLR_PROGRAM_FOREGROUND \
    -c "$ROOT/sdk/crt0.s" -o "$OUT/obj/crt0_app.o"
$CC --target=aarch64-none-elf -x assembler-with-cpp -DNLR_PROGRAM_EXTENSION \
    -c "$ROOT/sdk/crt0.s" -o "$OUT/obj/crt0_ext.o"
N="$ROOT/tool/nloader/target/debug/nloader"
"$N" program --decl "$TARGET/code_channel.json" \
    --object "$OUT/obj/crt0_app.o" --object "$OUT/obj/code_channel.o" \
    --manifest "$OUT/MANIFEST.app" --out "$OUT/CODET.NLB"
"$N" program --decl "$TARGET/hook_extension.json" \
    --object "$OUT/obj/crt0_ext.o" --object "$OUT/obj/hook_extension.o" \
    --manifest "$OUT/MANIFEST.ext" --out "$OUT/HOOKX.NLB"
