/* Host test for the executor's flat layout (exec.c program_run_flat, dev
 * firmware's core): one region holds the image and, from the next page,
 * the data; every relocation lands in that region; the region ends up
 * executable; the entry is called with the given argument; the blocks
 * stay. */
#include "nlr/exec.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAG_W 0x21u
#define FLAG_X 0x34u
#define REGION NLR_EXEC_BLOCK_SIZE

static uint8_t *raw;
static uint32_t flags, protects, releases, calls, invalidated;
static uint8_t *code_seen;
static uint64_t argument_seen;

int nlr_api_program_cleanup(struct nlr_program_state *p)
{
    (void)p;
    return 0;
}

void nlr_exec_resident_recheck(const struct nlr_exec_services *services)
{
    (void)services;
}

/* The allocation entry's books (core/exec.c): none here. */
const struct nlr_exec_services nlr_exec_services = {0};

static int32_t allocate(uint32_t bytes, void **out)
{
    /* aligned, so the executor's exact request is taken as it is */
    raw = aligned_alloc(REGION, ((size_t)bytes + REGION - 1u) / REGION * REGION);
    assert(raw);
    memset(raw, 0xa5, bytes);
    *out = raw;
    flags = FLAG_W;
    return 0;
}

static int32_t release(void *allocation)
{
    assert(allocation == raw);
    releases++;
    free(raw);
    raw = 0;
    return 0;
}

static int32_t audit(void *page, uint32_t bytes, uint32_t expected)
{
    assert(bytes == REGION && (uintptr_t)page % REGION == 0);
    return flags == expected ? 0 : -1;
}

static int32_t protect(void *page, uint64_t bytes, uint32_t requested)
{
    assert(bytes == REGION && (uintptr_t)page % REGION == 0);
    protects++;
    flags = requested;
    return 0;
}

static int32_t clean(void *page, uint32_t bytes)
{
    assert(bytes == REGION && flags == FLAG_W);
    (void)page;
    return 0;
}

static int32_t invalidate_code(void *page, uint64_t bytes)
{
    assert(flags == FLAG_X);
    (void)page;
    invalidated = (uint32_t)bytes;
    return 0;
}

static uint64_t call(void *entry, uint64_t argument)
{
    (void)entry;
    (void)argument;
    assert(0 && "a flat program is a resident extension");
    return 0;
}

static int32_t extension_call(void *entry, uint64_t argument, int32_t *exit_code,
                              uint32_t *started)
{
    assert(flags == FLAG_X);
    code_seen = (uint8_t *)entry;
    argument_seen = argument;
    calls++;
    *started = 1;
    *exit_code = 0;
    return 0;
}

static const struct nlr_exec_services services = {
    .region_bytes = REGION,
    .flag_writable = FLAG_W,
    .flag_executable = FLAG_X,
    .program_budget_blocks = 6,
    .program_max_resident = 3,
    .allocate = allocate,
    .release = release,
    .audit = audit,
    .protect = protect,
    .clean = clean,
    .invalidate_code = invalidate_code,
    .call = call,
    .extension_call = extension_call,
};

static void put32(uint8_t *p, uint32_t v)
{
    for (int n = 0; n < 4; n++)
        p[n] = (uint8_t)(v >> (8 * n));
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int n = 7; n >= 0; n--)
        v = v << 8 | p[n];
    return v;
}

int main(void)
{
    static uint8_t image[5000], data[64], table[36];
    for (uint32_t n = 0; n < sizeof image; n++)
        image[n] = (uint8_t)(n + 1u);
    put32(image, 0x90000000u);      /* ADRP x0 at offset 0 */
    for (uint32_t n = 0; n < sizeof data; n++)
        data[n] = (uint8_t)(0x40 + n);
    /* ADRP at 0 -> data + 16; data word 8 <- code + 32; data word 24 <- data + 40 */
    put32(table, 0); put32(table + 4, 16); put32(table + 8, NLR_RELOC_ADRP);
    put32(table + 12, 8); put32(table + 16, 32); put32(table + 20, NLR_RELOC_ABS64);
    put32(table + 24, 24); put32(table + 28, 40); put32(table + 32, NLR_RELOC_ABS64_DATA);
    struct nlr_program_segments seg = {
        .reloc = table, .image = image, .data = data,
        .image_size = sizeof image, .data_size = sizeof data, .bss_size = 0,
        .entry_offset = 64, .reloc_size = sizeof table, .kind = 1, .abi_version = 8,
        .flat = 1,
    };
    struct nlr_program_state state;
    memset(&state, 0, sizeof state);
    uint64_t handshake = 0x1234;
    int result = nlr_program_run(&state, &services, &seg,
                                 (const struct nlr_api *)(const void *)&handshake, 0);
    assert(result == 0);
    assert(state.kept && state.returned && state.entry_started && !state.data_page);
    assert(calls == 1 && argument_seen == (uint64_t)(uintptr_t)&handshake);
    assert(code_seen == state.code_page + 64);
    /* one region, made writable once and executable once */
    assert(protects == 2 && flags == FLAG_X && releases == 0);
    uint8_t *code = state.code_page;
    uint8_t *placed = code + 8192; /* the next page boundary after 5000 bytes */
    assert(invalidated == 8192 + sizeof data);
    assert(memcmp(code + 4, image + 4, sizeof image - 4) == 0);
    for (uint32_t n = sizeof image; n < 8192; n++)
        assert(code[n] == 0);
    /* the ADRP now reaches the page of placed + 16 */
    uint32_t word = (uint32_t)code[0] | (uint32_t)code[1] << 8 | (uint32_t)code[2] << 16 |
                    (uint32_t)code[3] << 24;
    int64_t pages = ((int64_t)(((uintptr_t)placed + 16) >> 12)) - (int64_t)((uintptr_t)code >> 12);
    uint32_t immlo = (word >> 29) & 3u, immhi = (word >> 5) & 0x7ffffu;
    assert((int64_t)(immhi << 2 | immlo) == pages);
    assert(get64(placed + 8) == (uint64_t)(uintptr_t)(code + 32));
    assert(get64(placed + 24) == (uint64_t)(uintptr_t)(placed + 40));
    assert(placed[0] == 0x40 && placed[63] == 0x40 + 63);

    /* refused: BSS, a foreground program, a data block past the region */
    struct nlr_program_state again;
    memset(&again, 0, sizeof again);
    seg.bss_size = 8;
    assert(nlr_program_run(&again, &services, &seg, 0 ? 0 : (const struct nlr_api *)1, 0) != 0);
    seg.bss_size = 0;
    seg.kind = 2;
    assert(nlr_program_run(&again, &services, &seg, (const struct nlr_api *)1, 0) != 0);
    seg.kind = 1;
    seg.data_size = REGION;
    assert(nlr_program_run(&again, &services, &seg, (const struct nlr_api *)1, 0) != 0);
    /* prepare-only has no meaning for a resident core */
    seg.data_size = sizeof data;
    assert(nlr_program_run(&again, &services, &seg, (const struct nlr_api *)1, 1) != 0);
    assert(calls == 1);
    puts("flat layout tests passed");
    return 0;
}
