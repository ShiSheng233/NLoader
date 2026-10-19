#include "nlr/exec.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Synthetic permission encodings: host tests must not bake in one model's
 * values; the core only has to tell the two semantics apart. */
#define MOCK_FLAG_W 0x21u
#define MOCK_FLAG_X 0x34u

static const uint8_t probe[64] = {
    'N',  'P',  'L',  'D',  2,    0,    48,   0,    1,    0,    0,
    0,    16,   0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    1,    0,    0,    0,    0x87, 0xea, 0x73, 0x7f, 2,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0x00, 0x44, 0xc0, 0x93, 0x00, 0x34, 0x00,
    0xca, 0x00, 0x44, 0x0c, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
};
static char events[64];
static unsigned event_count, fail_at, restore_failure, mismatch, releases;
static uint32_t flags;
static uint32_t region_bytes = NLR_EXEC_PAGE_SIZE;
static void *raw;

static int record(char event)
{
    events[event_count++] = event;
    events[event_count] = 0;
    return event_count == fail_at ? -1 : 0;
}

/* The loader's resident guard lives in core/runtime.c; this ladder links
 * the executor on its own. Nothing here injects a grant probe, so a short
 * grant cannot be met and the stub only has to exist. */
void nlr_exec_resident_recheck(const struct nlr_exec_services *services)
{
    (void)services;
    assert(0 && "the probe ladder has no grant services");
}

static int32_t allocate(uint32_t bytes, void **out)
{
    assert(bytes == 2u * region_bytes - 1u);
    if (record('a'))
        return -1;
    raw = malloc(bytes);
    assert(raw);
    memset(raw, 0xa5, bytes);
    *out = raw;
    flags = MOCK_FLAG_W;
    return 0;
}

static int32_t release(void *allocation)
{
    assert(allocation == raw);
    if (record('f'))
        return -1;
    free(raw);
    raw = 0;
    releases++;
    return 0;
}

static void check_page(void *page, uint64_t bytes)
{
    assert(bytes == region_bytes && (uintptr_t)page % region_bytes == 0);
    assert((uintptr_t)page >= (uintptr_t)raw);
    assert((uintptr_t)page + bytes <= (uintptr_t)raw + 2u * region_bytes - 1u);
}

static int32_t audit(void *page, uint32_t bytes, uint32_t expected)
{
    check_page(page, bytes);
    assert(flags == expected);
    return record('u');
}

static int32_t protect(void *page, uint64_t bytes, uint32_t requested)
{
    check_page(page, bytes);
    if (restore_failure && flags == MOCK_FLAG_X && requested == MOCK_FLAG_W) {
        record('w');
        return -1;
    }
    /* Simulate a partial mapping change even when failure is returned. */
    flags = requested;
    return record(requested == MOCK_FLAG_W ? 'w' : 'x');
}

static int32_t clean(void *page, uint32_t bytes)
{
    check_page(page, bytes);
    assert(flags == MOCK_FLAG_W);
    assert(memcmp(page, probe + 48, 16) == 0);
    for (uint32_t i = 0; i < 2u * region_bytes - 1u; i++) {
        uint8_t *p = (uint8_t *)raw + i;
        if (p < (uint8_t *)page || p >= (uint8_t *)page + 16)
            assert(*p == 0xa5);
    }
    return record('c');
}

static int32_t invalidate_code(void *page, uint64_t bytes)
{
    assert(bytes == NLR_PROBE_IMAGE_SIZE);
    check_page(page, region_bytes);
    assert(flags == MOCK_FLAG_X);
    return record('i');
}

static uint64_t call(void *entry, uint64_t challenge)
{
    check_page(entry, region_bytes);
    assert(events[event_count - 1] == 'i');
    assert(challenge == UINT64_C(0x0123456789abcdef));
    record('e');
    return UINT64_C(0x16e5b4c7da2967e6) ^ mismatch;
}

static const struct nlr_exec_services services = {
    .region_bytes = NLR_EXEC_PAGE_SIZE,
    .flag_writable = MOCK_FLAG_W,
    .flag_executable = MOCK_FLAG_X,
    .allocate = allocate,
    .release = release,
    .audit = audit,
    .protect = protect,
    .clean = clean,
    .invalidate_code = invalidate_code,
    .call = call,
};

static void reset(void)
{
    assert(!raw);
    event_count = fail_at = restore_failure = mismatch = releases = 0;
    memset(events, 0, sizeof(events));
}

static int run(struct nlr_probe_state *state, uint32_t prepare_only)
{
    struct nlr_exec_services selected = services;
    selected.region_bytes = region_bytes;
    return nlr_probe_run(state, &selected, probe, sizeof(probe), 2,
                         UINT64_C(0x0123456789abcdef), prepare_only);
}

int main(void)
{
    assert(nlr_probe_response(0) == 0x311);
    assert(nlr_probe_response(1) == UINT64_C(0x1000800000000311));
    assert(nlr_probe_response(UINT64_MAX) == 0x2310);
    assert(nlr_probe_validate(probe, 64, 2) == NLR_OK);
    for (unsigned i = 0; i < sizeof(probe); i++) {
        uint8_t changed[64];
        memcpy(changed, probe, sizeof(changed));
        changed[i] ^= 1;
        assert(nlr_probe_validate(changed, 64, 2) != NLR_OK);
        assert(nlr_probe_validate(probe, i, 2) != NLR_OK);
    }
    assert(nlr_probe_validate(probe, 65, 2) != NLR_OK);
    assert(nlr_probe_validate(probe, 64, 1) != NLR_OK);
    assert(nlr_probe_validate(probe, 64, 0) != NLR_OK);

    const uint32_t regions[] = {NLR_EXEC_PAGE_SIZE, NLR_EXEC_BLOCK_SIZE};
    for (unsigned region = 0; region < 2; region++) {
        region_bytes = regions[region];
        reset();
        struct nlr_probe_state state = {0};
        assert(run(&state, 0) == NLR_OK);
        assert(strcmp(events, "auwucxuiewuf") == 0);
        assert(state.prepared && state.entry_started && state.returned);
        assert(state.expected == state.response && !state.allocation &&
               releases == 1);
        assert(state.region_bytes == region_bytes);

        reset();
        assert(run(&state, 1) == NLR_OK);
        assert(strcmp(events, "auwucxuiwuf") == 0);
        assert(state.prepared && !state.entry_started && !state.returned);

        reset();
        mismatch = 1;
        assert(run(&state, 0) == NLR_EXEC_RESPONSE);
        assert(state.returned && state.response != state.expected &&
               !state.allocation);

        /* Each preparation service error prevents the call, including protect
         * failures after a mapping has already changed. All safe paths free. */
        for (unsigned failure = 1; failure <= 8; failure++) {
            reset();
            fail_at = failure;
            assert(run(&state, 0) == NLR_NOT_READY);
            assert(!state.entry_started && !state.allocation);
            assert(releases == (failure == 1 ? 0u : 1u));
        }

        reset();
        restore_failure = 1;
        assert(run(&state, 0) == NLR_EXEC_RESTORE);
        assert(state.allocation && state.permissions_touched && !releases);
        unsigned old_count = event_count;
        assert(run(&state, 0) == NLR_BUSY && event_count == old_count);
        /* Test teardown, not loader recovery. */
        free(raw);
        raw = 0;
        memset(&state, 0, sizeof(state));

        for (unsigned failure = 10; failure <= 12; failure++) {
            reset();
            fail_at = failure;
            assert(run(&state, 0) == NLR_EXEC_RESTORE);
            assert(state.allocation && !releases && state.returned);
            assert(run(&state, 0) == NLR_BUSY);
            free(raw);
            raw = 0;
            memset(&state, 0, sizeof(state));
        }

        reset();
        struct nlr_exec_services missing = services;
        missing.audit = 0;
        assert(nlr_probe_run(&state, &missing, probe, 64, 2, 1, 0) ==
               NLR_NOT_READY);
        assert(event_count == 0);
    }
    struct nlr_probe_state state = {0};
    const uint32_t invalid_regions[] = {0,    1,       16,        4095,
                                        8192, 2097151, UINT32_MAX};
    for (unsigned i = 0;
         i < sizeof(invalid_regions) / sizeof(invalid_regions[0]); i++) {
        struct nlr_exec_services invalid = services;
        invalid.region_bytes = invalid_regions[i];
        reset();
        assert(nlr_probe_run(&state, &invalid, probe, 64, 2, 1, 0) ==
               NLR_NOT_READY);
        assert(!event_count && !state.allocation);
    }
    assert(nlr_probe_run(&state, &services, probe, 64, 1, 1, 0) == NLR_FORMAT);
    assert(event_count == 0);
    for (unsigned variant = 0; variant < 3; variant++) {
        struct nlr_exec_services broken = services;
        if (variant == 0)
            broken.flag_writable = 0;
        else if (variant == 1)
            broken.flag_executable = 0;
        else
            broken.flag_executable = broken.flag_writable;
        reset();
        assert(nlr_probe_run(&state, &broken, probe, 64, 2, 1, 0) ==
               NLR_NOT_READY);
        assert(!event_count && !state.allocation);
    }
    puts("probe execution tests passed");
    return 0;
}
