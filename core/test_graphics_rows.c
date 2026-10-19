#include "nlr/menu.h"
#include "nlr/native_graphics.h"
#include "nlr/runtime.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifndef NLR_TEST_DYNAMIC_ROWS
#define NLR_TEST_DYNAMIC_ROWS 0
#endif
#ifndef NLR_TEST_STAY_NEXT
#define NLR_TEST_STAY_NEXT 1
#endif
#ifndef NLR_TEST_PAGE_ROWS
#define NLR_TEST_PAGE_ROWS 4
#endif
#ifndef NLR_TEST_UNALIGNED_ROWS
#define NLR_TEST_UNALIGNED_ROWS 0
#endif

static uint8_t window[96];
static uint8_t other_window[96];
/* The page record as built (in its window-table entry); its count word is
 * the one the page_count pointer names. */
static _Alignas(8) uint8_t page_record[NLR_MENU_PAGE_BYTES];
#define COUNT_OFFSET (0x20u + NLR_TEST_UNALIGNED_ROWS)

/* Only the tested bridge is retained by the host linker. All pointers are
 * local fixtures; no original-camera function is supplied or invoked. */
const struct nlr_native_graphics_services nlr_native_graphics_services = {
    .window = window,
    .row_count = 4,
};

const struct nlr_menu_page nlr_menu_page = {
    .row_count = NLR_TEST_PAGE_ROWS,
#if NLR_TEST_DYNAMIC_ROWS
    .page_count = (uint16_t *)(void *)(page_record + COUNT_OFFSET),
    .page_record = page_record,
#endif
    .stay_next = NLR_TEST_STAY_NEXT,
};

/* The runtime the bridge finds: once the loader's own window is installed
 * the page record lives in it (menu_page.c own_install). */
const struct nlr_services nlr_services;
static struct nlr_runtime runtime;
struct nlr_runtime *nlr_runtime_find(const struct nlr_services *svc, uint32_t *named)
{
    (void)svc;
    (void)named;
    return &runtime;
}

static void put_count(uint8_t *record, uint16_t count)
{
    memcpy(record + COUNT_OFFSET, &count, sizeof count);
}

int main(void)
{
    static const uint16_t counts[] = {0, 1, 2, 3, 4, 5, UINT16_MAX};
#if NLR_TEST_PAGE_ROWS != 4 || NLR_TEST_UNALIGNED_ROWS || \
    (NLR_TEST_DYNAMIC_ROWS && !NLR_TEST_STAY_NEXT)
    static const uint32_t expected[] = {0, 0, 0, 0, 0, 0, 0};
#elif NLR_TEST_DYNAMIC_ROWS
    static const uint32_t expected[] = {0, 1, 2, 3, 4, 0, 0};
#else
    static const uint32_t expected[] = {4, 4, 4, 4, 4, 4, 4};
#endif
    assert(nlr_native_graphics_row_count(other_window) == 0);
    assert(nlr_native_graphics_row_count(0) == 0);
    for (uint32_t n = 0; n < sizeof counts / sizeof counts[0]; n++) {
        put_count(page_record, counts[n]);
        assert(nlr_native_graphics_row_count(window) == expected[n]);
    }
    /* A rejected count must not poison the next valid page construction. */
    put_count(page_record, 1);
    assert(nlr_native_graphics_row_count(window) == expected[1]);

    /* Moved: the entry now holds the keyboard's window record, and only
     * the runtime's copy carries the count. */
    runtime.own.ready = 1;
    for (uint32_t n = 0; n < sizeof counts / sizeof counts[0]; n++) {
        put_count(page_record, 0x5d6);
        put_count(runtime.own.page_record, counts[n]);
        assert(nlr_native_graphics_row_count(window) == expected[n]);
    }
    puts("native graphics actual row count checks passed");
    return 0;
}
