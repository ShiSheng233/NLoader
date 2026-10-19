/* Host tests for dev firmware's stage 0 (core/stage0.c): the checks a core
 * file must pass before anything is allocated for it, and what the start
 * mark says to do. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nlr/stage0.h"
#include "nlr/load.h"

static int failures;
#define CHECK(c)                                                            \
    do {                                                                    \
        if (!(c)) {                                                         \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);            \
            failures++;                                                     \
        }                                                                   \
    } while (0)

static uint32_t crc(const uint8_t *p, uint32_t n)
{
    uint32_t c = ~0u;
    while (n--) {
        c ^= *p++;
        for (int b = 0; b < 8; b++)
            c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
    }
    return ~c;
}

static void put32(uint8_t *p, uint32_t v)
{
    for (int n = 0; n < 4; n++)
        p[n] = (uint8_t)(v >> (8 * n));
}

struct reloc {
    uint32_t offset, target, kind;
};

/* A core file: header, description, relocations, image, data. */
static uint32_t make(uint8_t *out, const char *meta_text, uint32_t kind,
                     uint32_t bss, const struct reloc *relocs, uint32_t nrelocs,
                     uint32_t image, uint32_t data)
{
    uint32_t meta = (uint32_t)strlen(meta_text);
    uint32_t meta_padded = (meta + 7u) & ~7u;
    uint32_t reloc = nrelocs * 12u;
    uint32_t total = 64 + meta_padded + reloc + image + data;
    memset(out, 0, total);
    memcpy(out, "NPLD", 4);
    out[4] = 3;
    out[6] = 64;
    uint8_t *m = out + 64;
    memcpy(m, meta_text, meta);
    uint8_t *t = m + meta_padded;
    for (uint32_t n = 0; n < nrelocs; n++) {
        put32(t + 12 * n, relocs[n].offset);
        put32(t + 12 * n + 4, relocs[n].target);
        put32(t + 12 * n + 8, relocs[n].kind);
    }
    uint8_t *code = t + reloc;
    for (uint32_t n = 0; n < image; n++)
        code[n] = (uint8_t)(n * 7u + 1u);
    /* an ADRP at image offset 0 for the relocation tests */
    put32(code, 0x90000000u);
    uint8_t *init = code + image;
    for (uint32_t n = 0; n < data; n++)
        init[n] = (uint8_t)(n + 3u);
    put32(out + 0x0c, image);
    put32(out + 0x10, bss);
    put32(out + 0x14, 8);
    put32(out + 0x18, 8);
    put32(out + 0x1c, crc(code, image));
    put32(out + 0x20, kind);
    put32(out + 0x24, reloc);
    put32(out + 0x28, meta_padded);
    put32(out + 0x2c, crc(m, meta_padded));
    put32(out + 0x30, data ? crc(init, data) : 0);
    put32(out + 0x34, reloc ? crc(t, reloc) : 0);
    return total;
}

#define CORE_META "id=core\nkind=extension\nname=NLoader core\nmin_abi=1\nstage0=1\ndata=readonly\ncore_abi=8\n"

int main(void)
{
    static uint8_t file[1 << 16];
    struct nlr_program_segments seg;
    const struct reloc good[] = {
        { 0, 16, NLR_RELOC_ADRP },        /* image -> data */
        { 8, 32, NLR_RELOC_ABS64 },       /* data word -> image */
        { 16, 24, NLR_RELOC_ABS64_DATA }, /* data word -> data */
    };
    uint32_t n = make(file, CORE_META, 1, 0, good, 3, 256, 64);
    memset(&seg, 0xa5, sizeof seg);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_OK);
    CHECK(seg.kind == 1 && seg.image_size == 256 && seg.data_size == 64 &&
          seg.bss_size == 0 && seg.entry_offset == 8 && seg.reloc_size == 36 &&
          seg.flat == 1 && seg.consumed == 0 && seg.abi_version == 8);
    CHECK(seg.image == file + 64 + 88 + 36 && seg.data == seg.image + 256 &&
          seg.reloc == file + 64 + 88);

    /* every byte counts */
    for (uint32_t at = 0; at < n; at += 37) {
        if (at >= 0x38 && at < 0x40)
            continue; /* reserved words: tested below */
        uint8_t keep = file[at];
        file[at] ^= 0x40;
        int r = nlr_stage0_check(file, n, &seg);
        CHECK(r != NLR_OK);
        file[at] = keep;
    }
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_OK);
    file[0x38] = 1;
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_FORMAT);
    file[0x38] = 0;
    /* truncated, or a byte longer */
    CHECK(nlr_stage0_check(file, n - 1, &seg) != NLR_OK);
    CHECK(nlr_stage0_check(file, 63, &seg) == NLR_FORMAT);
    CHECK(nlr_stage0_check(0, n, &seg) == NLR_FORMAT);

    /* version 2: a program, not a described core */
    file[4] = 2;
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_FORMAT);
    file[4] = 3;

    /* not a core for this stage 0 */
    n = make(file, CORE_META, 2, 0, good, 3, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_REFUSED); /* foreground kind */
    n = make(file, "id=lvui\nkind=extension\nname=X\nmin_abi=1\nstage0=1\ndata=readonly\n", 1, 0, good, 3, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_REFUSED);
    n = make(file, "id=core\nkind=extension\nname=X\nmin_abi=1\nstage0=2\ndata=readonly\n", 1, 0, good, 3, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_REFUSED);
    n = make(file, "id=core\nkind=extension\nname=X\nmin_abi=1\nstage0=1\n", 1, 0, good, 3, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_REFUSED); /* writable data */
    n = make(file, "id=core\nkind=extension\nname=X\nmin_abi=1\nstage0=11\ndata=readonly\n", 1, 0, good, 3, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_REFUSED); /* a prefix is not a match */
    n = make(file, CORE_META, 1, 16, good, 3, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_REFUSED); /* BSS */

    /* relocations that would write outside the core's own block */
    const struct reloc far_adrp[] = { { 0, 64, NLR_RELOC_ADRP } };
    n = make(file, CORE_META, 1, 0, far_adrp, 1, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_BOUNDS);
    const struct reloc adrp_past_code[] = { { 256, 0, NLR_RELOC_ADRP } };
    n = make(file, CORE_META, 1, 0, adrp_past_code, 1, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_BOUNDS);
    const struct reloc adrp_odd[] = { { 2, 0, NLR_RELOC_ADRP } };
    n = make(file, CORE_META, 1, 0, adrp_odd, 1, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_BOUNDS);
    const struct reloc far_abs[] = { { 64, 0, NLR_RELOC_ABS64 } };
    n = make(file, CORE_META, 1, 0, far_abs, 1, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_BOUNDS);
    const struct reloc odd_abs[] = { { 4, 0, NLR_RELOC_ABS64 } };
    n = make(file, CORE_META, 1, 0, odd_abs, 1, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_BOUNDS);
    const struct reloc code_target[] = { { 8, 256, NLR_RELOC_ABS64 } };
    n = make(file, CORE_META, 1, 0, code_target, 1, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_BOUNDS);
    const struct reloc unknown[] = { { 8, 0, 7 } };
    n = make(file, CORE_META, 1, 0, unknown, 1, 256, 64);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_FORMAT);
    /* relocations need somewhere to point */
    n = make(file, CORE_META, 1, 0, good, 1, 256, 0);
    CHECK(nlr_stage0_check(file, n, &seg) == NLR_BOUNDS);

    /* the start mark */
    CHECK(nlr_stage0_mark_says((const uint8_t *)"run", 3) == NLR_STAGE0_MARK_SKIP);
    CHECK(nlr_stage0_mark_says((const uint8_t *)"run\n", 4) == NLR_STAGE0_MARK_SKIP);
    CHECK(nlr_stage0_mark_says((const uint8_t *)"ok", 2) == NLR_STAGE0_MARK_START);
    CHECK(nlr_stage0_mark_says((const uint8_t *)"skipped", 7) == NLR_STAGE0_MARK_START);
    CHECK(nlr_stage0_mark_says((const uint8_t *)"refused", 7) == NLR_STAGE0_MARK_START);
    CHECK(nlr_stage0_mark_says((const uint8_t *)"ru", 2) == NLR_STAGE0_MARK_START);
    CHECK(nlr_stage0_mark_says(0, 0) == NLR_STAGE0_MARK_START);

    if (failures) {
        printf("%d stage 0 checks failed\n", failures);
        return 1;
    }
    printf("stage 0 behavior tests passed\n");
    return 0;
}
