#include <assert.h>
#include <stdint.h>
#include <string.h>

#define NLR_OK 0
#define NLR_NOT_READY -5
#define NLR_EXEC_REGION_BYTES 0x200000u
#define NLR_EXEC_FLAGS_X 0x34u
static _Alignas(0x200000) uint8_t image[NLR_EXEC_REGION_BYTES];
static _Alignas(8) uint8_t manager[64];
static uint8_t covered[NLR_EXEC_REGION_BYTES];
static uint64_t cursor;
static uint32_t calls, audit_calls, change_after, denied_offset;
static int audit_result;
static uint32_t get(uint32_t offset) {
    uint32_t value; memcpy(&value, manager + offset, 4); return value;
}
static void set(uint32_t offset, uint32_t value) { memcpy(manager + offset, &value, 4); }
static uint32_t mock_cacheable(void *pointer) {
    return (uintptr_t)pointer != (uintptr_t)image + denied_offset;
}
static int nlr_exec_audit(void *page, uint32_t bytes, uint32_t flags) {
    assert(page == image && bytes == sizeof image && flags == NLR_EXEC_FLAGS_X);
    audit_calls++; return audit_result;
}
static void mock_invalidate(void *page, uint64_t bytes) {
    uint64_t offset = (uint8_t *)page - image;
    uint32_t line = get(0x38);
    assert(bytes && bytes < get(0x28));
    assert(offset == cursor && !(offset % 64) && !(offset % line));
    uint64_t rounded = (bytes + line - 1) & ~((uint64_t)line - 1);
    assert(offset + rounded <= sizeof image);
    for (uint64_t i = offset; i < offset + bytes; i++) {
        assert(!covered[i]); covered[i] = 1;
    }
    cursor += bytes; calls++;
    if (change_after && calls == change_after) set(0x28, 64);
}
#define NLR_EXEC_CACHE_MANAGER ((uintptr_t)manager)
#define NLR_EXEC_ICACHE ((uintptr_t)mock_invalidate)
#define NLR_EXEC_CACHEABLE ((uintptr_t)mock_cacheable)

/* ADAPTER_UNDER_TEST */

static void reset(uint32_t threshold, uint32_t line) {
    memset(manager, 0, sizeof manager); memset(covered, 0, sizeof covered);
    set(0x28, threshold); set(0x38, line);
    cursor = 0; calls = audit_calls = change_after = 0;
    denied_offset = UINT32_MAX; audit_result = 0;
}
int main(void) {
    const uint32_t sizes[] = {1, 32767, 32768, 300628, NLR_EXEC_REGION_BYTES};
    const uint32_t lines[] = {4, 64, 128, 4096};
    for (uint32_t l = 0; l < 4; l++) for (uint32_t n = 0; n < 5; n++) {
        reset(32768, lines[l]);
        assert(nlr_exec_icache(image, sizes[n]) == 0);
        assert(cursor == sizes[n] && calls && audit_calls == 1);
        for (uint32_t i = 0; i < sizeof covered; i++) assert(covered[i] == (i < sizes[n]));
    }
    reset(65, 64); assert(nlr_exec_icache(image, 129) == 0 && calls == 3);
    reset(32768, 64); audit_result = -5;
    assert(nlr_exec_icache(image, 300628) == -5 && calls == 0);
    reset(32768, 64); change_after = 1;
    assert(nlr_exec_icache(image, 300628) == -5 && calls == 1 && cursor == 32704);
    reset(32768, 64); denied_offset = 32704;
    assert(nlr_exec_icache(image, 300628) == -5 && calls == 1);
    reset(64, 64); assert(nlr_exec_icache(image, 1) == -5 && !calls);
    reset(4096, 4096); assert(nlr_exec_icache(image, 1) == -5 && !calls);
    reset(32768, 96); assert(nlr_exec_icache(image, 1) == -5 && !calls);
    reset(32768, 64); assert(nlr_exec_icache(image, 0) == -5 && !calls);
    assert(nlr_exec_icache(image, sizeof image + 1) == -5 && !calls);
    assert(nlr_exec_icache(image + 1, 1) == -5 && !calls);
    return 0;
}
