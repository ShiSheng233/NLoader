#!/bin/sh
# build.sh <new out dir> [clang]: the ABI 5 card-write fixture, CARDW.NLB
# (foreground), for a native-card model. The output directory must not
# exist yet.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:?usage: build.sh <new out dir> [clang]}
CC=${2:-clang}
[ -e "$OUT" ] && { echo "refusing: $OUT exists" >&2; exit 1; }
RES=$($CC -print-resource-dir)/include
mkdir -p "$OUT/obj"
COMMON="--target=aarch64-none-elf -march=armv8-a -ffreestanding -fno-common
 -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables
 -fPIC -fvisibility=hidden -nostdinc -isystem $RES -I $ROOT/sdk
 -fno-jump-tables -fno-builtin -O2 -Wall -Wextra -Werror"
$CC $COMMON -c "$HERE/card_write.c" -o "$OUT/obj/card_write.o"
$CC --target=aarch64-none-elf -x assembler-with-cpp -DNLR_PROGRAM_FOREGROUND \
    -c "$ROOT/sdk/crt0.s" -o "$OUT/obj/crt0_app.o"
N="$ROOT/tool/nloader/target/debug/nloader"
"$N" program --decl "$HERE/card_write.json" \
    --object "$OUT/obj/crt0_app.o" --object "$OUT/obj/card_write.o" \
    --manifest "$OUT/MANIFEST.app" --out "$OUT/CARDW.NLB"
