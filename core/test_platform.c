/* Host tests for the ABI 7 pure parts (core/platform.c): routing, the
 * event ring, scans into events, timers and the settings store reader. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nlr/platform.h"
#include "nlr/services.h"

static int failures;
#define CHECK(c)                                                            \
    do {                                                                    \
        if (!(c)) {                                                         \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);            \
            failures++;                                                     \
        }                                                                   \
    } while (0)

#define BIT(c) (UINT64_C(1) << (c))

static const struct nlr_platform_control controls[] = {
    { NLR_CTL_UP, 0, 0, 0x20 },
    { NLR_CTL_OK, 1, 0, 0x1 },
    { NLR_CTL_HALF, 0, 0, 1u << 31 },
    { NLR_CTL_FULL, 0, 0, 1u << 30 },
    { NLR_CTL_SUB_LEFT, 2, 0, 0x4 },
    { NLR_CTL_FN1, 3, 0, 0x10 | 0x20 }, /* two contacts, one control */
};

/* A settings store in host memory: four groups of 48 bytes, items of 24. */
static uint8_t groups[4 * 48];
static uint8_t items[8 * 24];
static uint8_t store[64];

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }

static struct nlr_platform_services services(void)
{
    struct nlr_platform_services s = {
        .controls = controls,
        .control_count = sizeof controls / sizeof *controls,
        .dial_word = { 2, 3, 0 }, /* words 1 and 2 */
        .dial_sign = { 1, -1, 1 },
        .prop_groups = groups,
        .prop_group_count = 4,
        .prop_group_bytes = 48,
        .group_live_at = 0,
        .group_first_at = 24,
        .group_items_at = 26,
        .item_size_at = 4,
        .prop_items = items,
        .prop_item_count = 8,
        .prop_item_bytes = 24,
        .item_ram_at = 8,
        .prop_ram_lo = (uint64_t)(uintptr_t)store,
        .prop_ram_hi = (uint64_t)(uintptr_t)store + sizeof store,
    };
    return s;
}

static void store_setup(void)
{
    memset(groups, 0, sizeof groups);
    memset(items, 0, sizeof items);
    memset(store, 0, sizeof store);
    /* group 1: items 0..2 at item records 2..4 */
    put32(groups + 48 * 1, 0x100);
    put16(groups + 48 * 1 + 24, 2);
    put16(groups + 48 * 1 + 26, 3);
    /* group 2 is not in use */
    put16(groups + 48 * 2 + 24, 5);
    put16(groups + 48 * 2 + 26, 1);
    put32(items + 24 * 2 + 4, 4);
    put64(items + 24 * 2 + 8, (uint64_t)(uintptr_t)store);
    put32(items + 24 * 3 + 4, 8);
    put64(items + 24 * 3 + 8, (uint64_t)(uintptr_t)(store + 8));
    /* group 3 runs past the end of the item table: 0x0300 is its last
     * record, 0x0301 would be the ninth */
    put32(groups + 48 * 3, 0x100);
    put16(groups + 48 * 3 + 24, 7);
    put16(groups + 48 * 3 + 26, 3);
    put32(items + 24 * 7 + 4, 4);
    put64(items + 24 * 7 + 8, (uint64_t)(uintptr_t)(store + 16));
    /* item 0x0102 points outside the store */
    put32(items + 24 * 4 + 4, 4);
    put64(items + 24 * 4 + 8, (uint64_t)(uintptr_t)(store + 62));
}

static void test_routes(void)
{
    struct nlr_platform p;
    nlr_platform_reset(&p);
    struct nlr_platform_services s = services();
    uint32_t masks[4];

    nlr_platform_take_input(&p, 1);
    CHECK(p.active == 1);
    CHECK(!(p.route_hide & BIT(NLR_CTL_HALF)) && (p.route_report & BIT(NLR_CTL_HALF)));
    CHECK((p.route_hide & BIT(NLR_CTL_UP)) && (p.route_report & BIT(NLR_CTL_UP)));
    nlr_platform_hide_masks(&s, p.route_hide, 0, 0x200, masks, 4);
    /* everything hidden but the shutter and the power bit */
    CHECK(masks[0] == ~((1u << 31) | (1u << 30) | 0x200u));
    CHECK(masks[1] == ~0u && masks[2] == ~0u && masks[3] == ~0u);

    uint32_t to_camera[] = { NLR_CTL_UP, NLR_CTL_FN1 };
    CHECK(nlr_platform_route(&p, to_camera, 2, NLR_ROUTE_CAMERA) == 0);
    CHECK(!(p.route_report & BIT(NLR_CTL_UP)) && !(p.route_hide & BIT(NLR_CTL_UP)));
    nlr_platform_hide_masks(&s, p.route_hide, 0, 0x200, masks, 4);
    CHECK(masks[0] == ~((1u << 31) | (1u << 30) | 0x200u | 0x20u));
    CHECK(masks[3] == ~0x30u);

    uint32_t both[] = { NLR_CTL_OK };
    CHECK(nlr_platform_route(&p, both, 1, NLR_ROUTE_BOTH) == 0);
    CHECK((p.route_report & BIT(NLR_CTL_OK)) && !(p.route_hide & BIT(NLR_CTL_OK)));
    uint32_t back[] = { NLR_CTL_HALF };
    CHECK(nlr_platform_route(&p, back, 1, NLR_ROUTE_PROGRAM) == 0);
    CHECK(p.route_hide & BIT(NLR_CTL_HALF));

    /* a program over the menu keeps the shutter as well */
    struct nlr_platform q;
    nlr_platform_reset(&q);
    nlr_platform_take_input(&q, 0);
    CHECK(q.route_hide == ~UINT64_C(0) && q.route_report == ~UINT64_C(0));

    uint32_t bad[] = { 64 };
    uint64_t before = p.route_hide;
    CHECK(nlr_platform_route(&p, bad, 1, NLR_ROUTE_CAMERA) == -NLR_API_EINVAL);
    CHECK(nlr_platform_route(&p, both, 1, 3) == -NLR_API_EINVAL);
    CHECK(p.route_hide == before);
}

static void test_scan_and_ring(void)
{
    struct nlr_platform p;
    nlr_platform_reset(&p);
    struct nlr_platform_services s = services();
    struct nlr_event ev;
    uint32_t banks[4] = { 0x20, 0, 0, 0x10 };
    int32_t dials[4] = { 0, 2, -1, 0 };

    /* Not taken: the held state follows, nothing is queued. */
    uint64_t held = nlr_platform_held(&s, banks, 4);
    CHECK(held == (BIT(NLR_CTL_UP) | BIT(NLR_CTL_FN1)));
    nlr_platform_scan(&p, &s, held, dials, 4, 5);
    CHECK(nlr_platform_pop(&p, &ev) == 0);

    nlr_platform_take_input(&p, 1);
    banks[0] = 0;          /* UP released */
    banks[1] = 1;          /* OK pressed */
    held = nlr_platform_held(&s, banks, 4);
    nlr_platform_scan(&p, &s, held, dials, 4, 9);
    CHECK(nlr_platform_pop(&p, &ev) == 1 && ev.type == NLR_EV_CONTROL &&
          ev.code == NLR_CTL_UP && ev.value == 0 && ev.t_ms == 9);
    CHECK(nlr_platform_pop(&p, &ev) == 1 && ev.code == NLR_CTL_OK && ev.value == 1);
    CHECK(nlr_platform_pop(&p, &ev) == 1 && ev.type == NLR_EV_DIAL &&
          ev.code == NLR_CTL_DIAL_MAIN && ev.value == 2);
    CHECK(nlr_platform_pop(&p, &ev) == 1 && ev.type == NLR_EV_DIAL &&
          ev.code == NLR_CTL_DIAL_SUB && ev.value == 1);
    CHECK(nlr_platform_pop(&p, &ev) == 0);

    /* A control routed to the camera is not reported. */
    uint32_t cam[] = { NLR_CTL_OK, NLR_CTL_DIAL_MAIN };
    CHECK(nlr_platform_route(&p, cam, 2, NLR_ROUTE_CAMERA) == 0);
    banks[1] = 0;
    held = nlr_platform_held(&s, banks, 4);
    nlr_platform_scan(&p, &s, held, dials, 4, 10);
    CHECK(nlr_platform_pop(&p, &ev) == 1 && ev.code == NLR_CTL_DIAL_SUB);
    CHECK(nlr_platform_pop(&p, &ev) == 0);

    /* Overflow: the ring keeps what fits, then reports one overflow and
     * drops the rest of the incomplete history. */
    for (uint32_t n = 0; n < NLR_PLATFORM_EVENTS + 3; n++) {
        struct nlr_event e = { .type = NLR_EV_CONTROL, .code = NLR_CTL_UP, .value = (int32_t)(n & 1) };
        int r = nlr_platform_push(&p, &e);
        CHECK(n < NLR_PLATFORM_EVENTS ? r == 0 : r == -NLR_API_EOVERFLOW);
    }
    CHECK(nlr_platform_pop(&p, &ev) == 1 && ev.type == NLR_EV_OVERFLOW);
    CHECK(nlr_platform_pop(&p, &ev) == 0);
}

static void test_timers(void)
{
    struct nlr_platform p;
    nlr_platform_reset(&p);
    struct nlr_event ev;
    CHECK(nlr_platform_timer_wait(&p, 0) == UINT32_MAX);
    int a = nlr_platform_timer_start(&p, 100, 7, 1000);
    int b = nlr_platform_timer_start(&p, 30, 8, 1000);
    CHECK(a == 0 && b == 1);
    CHECK(nlr_platform_timer_wait(&p, 1000) == 30);
    CHECK(nlr_platform_timer_due(&p, 1029, &ev) == 0);
    CHECK(nlr_platform_timer_due(&p, 1030, &ev) == 1 && ev.type == NLR_EV_TIMER &&
          ev.code == 1 && ev.value == 8);
    CHECK(nlr_platform_timer_wait(&p, 1030) == 30);
    /* far behind: one tick, then the period again from now */
    CHECK(nlr_platform_timer_due(&p, 5000, &ev) == 1 && ev.code == 0);
    CHECK(nlr_platform_timer_due(&p, 5000, &ev) == 1 && ev.code == 1);
    CHECK(nlr_platform_timer_due(&p, 5000, &ev) == 0);
    CHECK(nlr_platform_timer_wait(&p, 5000) == 30);
    CHECK(nlr_platform_timer_stop(&p, b) == 0);
    CHECK(nlr_platform_timer_stop(&p, b) == -NLR_API_ENOENT);
    CHECK(nlr_platform_timer_wait(&p, 5000) == 100);
    for (int n = 0; n < (int)NLR_TIMERS_MAX - 1; n++)
        CHECK(nlr_platform_timer_start(&p, 10, 0, 0) >= 0);
    CHECK(nlr_platform_timer_start(&p, 10, 0, 0) == -NLR_API_EBUSY);
    CHECK(nlr_platform_timer_start(&p, 0, 0, 0) == -NLR_API_EINVAL);
    /* wrap of the millisecond clock */
    nlr_platform_reset(&p);
    CHECK(nlr_platform_timer_start(&p, 20, 1, 0xfffffff0u) == 0);
    CHECK(nlr_platform_timer_due(&p, 0xfffffffeu, &ev) == 0);
    CHECK(nlr_platform_timer_due(&p, 4, &ev) == 1);
}

static void test_props(void)
{
    struct nlr_platform p;
    nlr_platform_reset(&p);
    struct nlr_platform_services s = services();
    const volatile uint8_t *value;
    uint32_t size;
    struct nlr_event ev;
    store_setup();

    CHECK(nlr_platform_prop(&s, 0x0100, &value, &size) == 0 && size == 4 &&
          value == store);
    CHECK(nlr_platform_prop(&s, 0x0101, &value, &size) == 0 && size == 8 &&
          value == store + 8);
    CHECK(nlr_platform_prop(&s, 0x0102, &value, &size) == -NLR_API_ENOENT);
    CHECK(nlr_platform_prop(&s, 0x0103, &value, &size) == -NLR_API_ENOENT);
    CHECK(nlr_platform_prop(&s, 0x0200, &value, &size) == -NLR_API_ENOENT);
    CHECK(nlr_platform_prop(&s, 0x0400, &value, &size) == -NLR_API_ENOENT);
    CHECK(nlr_platform_prop(&s, 0x0300, &value, &size) == 0 && value == store + 16);
    CHECK(nlr_platform_prop(&s, 0x0301, &value, &size) == -NLR_API_ENOENT);
    CHECK(nlr_platform_prop(&s, 0x10000, &value, &size) == -NLR_API_EINVAL);
    struct nlr_platform_services none = { 0 };
    CHECK(nlr_platform_prop(&none, 0x0100, &value, &size) == -NLR_API_ENOSYS);

    uint16_t ids[] = { 0x0100, 0x0101 };
    uint16_t wrong[] = { 0x0100, 0x0103 };
    CHECK(nlr_platform_watch(&p, &s, ids, 2) == 0 && p.watch_count == 2);
    CHECK(nlr_platform_watch(&p, &s, wrong, 2) == -NLR_API_ENOENT && p.watch_count == 2);
    CHECK(nlr_platform_watch_poll(&p, &s, 100, &ev) == 0);
    store[0] = 9;          /* not looked at again for 20 ms */
    CHECK(nlr_platform_watch_poll(&p, &s, 110, &ev) == 0);
    CHECK(nlr_platform_watch_poll(&p, &s, 121, &ev) == 1 && ev.type == NLR_EV_PROP &&
          ev.code == 0x0100 && ev.value == 9);
    store[12] = 1;         /* a byte past the first word still counts */
    CHECK(nlr_platform_watch_poll(&p, &s, 121, &ev) == 1 && ev.code == 0x0101 && ev.value == 0);
    CHECK(nlr_platform_watch_poll(&p, &s, 121, &ev) == 0);
    CHECK(nlr_platform_watch(&p, &s, 0, 0) == 0 && p.watch_count == 0);
    CHECK(nlr_platform_watch_poll(&p, &s, 500, &ev) == 0);
}

static void test_cards(void)
{
    static uint8_t volumes[2 * 224];
    struct nlr_platform_services s = {
        .volumes = volumes, .volume_count = 2, .volume_bytes = 224,
        .volume_state = 0x60, .mounted = 1, .card_slots = 2,
        .card_letters = { 'A', 'B' },
    };
    struct nlr_platform p;
    struct nlr_event ev;
    nlr_platform_reset(&p);
    memset(volumes, 0, sizeof volumes);
    CHECK(nlr_platform_card(&s, 0) == 0 && nlr_platform_card(&s, 1) == 0);
    CHECK(nlr_platform_card(&s, 2) == -NLR_API_EINVAL);
    struct nlr_platform_services none = { 0 };
    CHECK(nlr_platform_card(&none, 0) == -NLR_API_ENOSYS);
    CHECK(nlr_platform_card_slot(&s, 'B') == 1 && nlr_platform_card_slot(&s, 'C') == -1);
    /* B: mounted as the first volume: found by name, not position */
    memcpy(volumes, "B:", 3);
    volumes[0x60] = 1;
    CHECK(nlr_platform_card(&s, 1) == 1 && nlr_platform_card(&s, 0) == 0);
    volumes[0x60] = 2; /* error state */
    CHECK(nlr_platform_card(&s, 1) == 0);
    volumes[0x60] = 1;
    /* the first look learns; changes come one per call */
    CHECK(nlr_platform_card_poll(&p, &s, 1000, &ev) == 0);
    memcpy(volumes + 224, "A:", 3);
    volumes[224 + 0x60] = 1;
    CHECK(nlr_platform_card_poll(&p, &s, 1050, &ev) == 0); /* not due */
    CHECK(nlr_platform_card_poll(&p, &s, 1100, &ev) == 1 && ev.type == NLR_EV_CARD &&
          ev.code == 0 && ev.value == 1);
    memset(volumes, 0, 224);
    volumes[224 + 0x60] = 0;
    CHECK(nlr_platform_card_poll(&p, &s, 1100, &ev) == 1 && ev.code == 0 && ev.value == 0);
    CHECK(nlr_platform_card_poll(&p, &s, 1100, &ev) == 1 && ev.code == 1 && ev.value == 0);
    CHECK(nlr_platform_card_poll(&p, &s, 1100, &ev) == 0);
}

static void test_touch_eye_dials(void)
{
    struct nlr_platform p;
    struct nlr_event ev;
    nlr_platform_reset(&p);
    struct nlr_platform_services s = services();
    s.touch_record_bytes = 28;
    uint8_t rec[28] = {0};
    /* not taken: nothing queued, the camera sees it */
    rec[5] = 1;
    CHECK(nlr_platform_touch(&p, &s, rec, 1) == 0 && !nlr_platform_touch_pop(&p, &ev));
    nlr_platform_take_input(&p, 1);
    rec[10] = 0x10; rec[11] = 0x02; rec[12] = 0x34; /* x 0x210, y 0x34 */
    CHECK(nlr_platform_touch(&p, &s, rec, 2) == 1);   /* hidden from the camera */
    CHECK(nlr_platform_touch_pop(&p, &ev) && ev.type == NLR_EV_TOUCH &&
          ev.code == NLR_TOUCH_DOWN && ev.x == 0x210 && ev.y == 0x34);
    CHECK(nlr_platform_touch(&p, &s, rec, 3) == 1);
    CHECK(nlr_platform_touch_pop(&p, &ev) && ev.code == NLR_TOUCH_MOVE);
    /* the release: the panel says 0,0 once the finger is off; the event
     * says where it was */
    rec[5] = 0;
    rec[10] = rec[11] = rec[12] = 0;
    CHECK(nlr_platform_touch(&p, &s, rec, 4) == 1);
    CHECK(nlr_platform_touch_pop(&p, &ev) && ev.code == NLR_TOUCH_UP &&
          ev.x == 0x210 && ev.y == 0x34);
    CHECK(nlr_platform_touch(&p, &s, rec, 5) == 1 && !nlr_platform_touch_pop(&p, &ev));
    /* a full queue of moves: the release still gets in */
    rec[5] = 1;
    for (int n = 0; n < 20; n++)
        nlr_platform_touch(&p, &s, rec, 6);
    rec[5] = 0;
    nlr_platform_touch(&p, &s, rec, 7);
    int got = 0, up = 0;
    while (nlr_platform_touch_pop(&p, &ev)) {
        got++;
        up = ev.code == NLR_TOUCH_UP;
    }
    CHECK(got == 16 && up);
    /* routed to both: reported and the camera sees it too */
    uint32_t touch[] = { NLR_CTL_TOUCH };
    CHECK(nlr_platform_route(&p, touch, 1, NLR_ROUTE_BOTH) == 0);
    rec[5] = 1;
    CHECK(nlr_platform_touch(&p, &s, rec, 8) == 0 && nlr_platform_touch_pop(&p, &ev));

    /* eye: the first look learns; a change reports */
    uint32_t eye = 0xffffffffu;
    s.eye_state = &eye;
    nlr_platform_reset(&p);
    CHECK(!nlr_platform_eye_poll(&p, &s, 10, &ev));
    eye = 1; /* the sensor's very first report, seen while watching */
    CHECK(nlr_platform_eye_poll(&p, &s, 61, &ev) && ev.type == NLR_EV_EYE && ev.value == 1);
    CHECK(!nlr_platform_eye_poll(&p, &s, 200, &ev));
    eye = 0;
    CHECK(!nlr_platform_eye_poll(&p, &s, 220, &ev)); /* not due yet */
    CHECK(nlr_platform_eye_poll(&p, &s, 251, &ev) && ev.value == 0);
    nlr_platform_reset(&p);
    CHECK(!nlr_platform_eye_poll(&p, &s, 10, &ev)); /* learned 0, silently */

    /* the grip's dial adds to the main dial */
    nlr_platform_reset(&p);
    nlr_platform_take_input(&p, 1);
    s.dial_word[0] = 1; s.dial_alt[0] = 3; s.dial_sign[0] = 1;
    s.dial_word[1] = 0; s.dial_alt[1] = 0;
    int32_t dials[4] = { 1, 0, 2, 0 };
    nlr_platform_scan(&p, &s, 0, dials, 4, 9);
    CHECK(nlr_platform_pop(&p, &ev) == 1 && ev.code == NLR_CTL_DIAL_MAIN && ev.value == 3);
    CHECK(nlr_platform_pop(&p, &ev) == 0);
}

static void test_names(void)
{
    static const struct nlr_platform_point points[] = {
        { "store.changed", 0x1000, { 1, 2, 3, 4 }, 0, 1 },
        { "isp.m1.load", 0x2000, { 5, 6, 7, 8 }, 0, 2 },
    };
    static const struct nlr_platform_table tables[] = {
        { "gui.palette", 0x3000, 561 * 4, NLR_TABLE_POINTER, 0x1234, 0, 0x4000 },
    };
    static const struct nlr_platform_function functions[] = { { "menu.leave", (void *)0x5000 } };
    static const struct nlr_platform_device devices[] = { { "i2c:imu", 3, 0x68, 0x38000, 0 } };
    struct nlr_platform_services s = {
        .points = points, .point_count = 2, .tables = tables, .table_count = 1,
        .functions = functions, .function_count = 1, .devices = devices, .device_count = 1,
    };
    CHECK(nlr_platform_find_point(&s, "isp.m1.load") == 1);
    CHECK(nlr_platform_find_point(&s, "isp.m1") == -1);
    CHECK(nlr_platform_find_point(&s, "isp.m1.load.x") == -1);
    CHECK(nlr_platform_find_table(&s, "gui.palette") == 0);
    CHECK(nlr_platform_find_table(&s, "store.changed") == -1);
    CHECK(nlr_platform_find_function(&s, "menu.leave") == 0);
    CHECK(nlr_platform_find_device(&s, "i2c:imu") == 0);
    CHECK(nlr_platform_find_device(&s, 0) == -1);
    struct nlr_platform_services none = { 0 };
    CHECK(nlr_platform_find_point(&none, "store.changed") == -1);
    /* the IEEE CRC-32 of "123456789" */
    CHECK(nlr_platform_crc32((const uint8_t *)"123456789", 9) == 0xcbf43926u);
}

static void test_posted(void)
{
    struct nlr_platform p;
    struct nlr_event ev;
    nlr_platform_reset(&p);
    CHECK(nlr_platform_posted(&p, &ev) == 0);
    for (uint32_t n = 0; n < 40; n++) {
        struct nlr_event e = { .type = NLR_EV_POSTED, .code = (uint16_t)n, .value = (int32_t)n };
        int r = nlr_platform_post(&p, &e);
        CHECK(n < 32 ? r == 0 : r == -NLR_API_EOVERFLOW);
    }
    for (uint32_t n = 0; n < 32; n++)
        CHECK(nlr_platform_posted(&p, &ev) == 1 && ev.code == n);
    CHECK(nlr_platform_posted(&p, &ev) == 0);
    /* a slot reserved but not yet written is not read */
    __atomic_store_n(&p.ptail, p.ptail + 1u, __ATOMIC_RELEASE);
    CHECK(nlr_platform_posted(&p, &ev) == 0);
    p.posted[p.phead & 31u].ev.code = 77;
    __atomic_store_n(&p.posted[p.phead & 31u].seq, p.phead + 1u, __ATOMIC_RELEASE);
    CHECK(nlr_platform_posted(&p, &ev) == 1 && ev.code == 77);
    /* wrap around the 32 slots many times */
    for (uint32_t round = 0; round < 100; round++) {
        struct nlr_event e = { .type = NLR_EV_POSTED, .value = (int32_t)round };
        CHECK(nlr_platform_post(&p, &e) == 0);
        CHECK(nlr_platform_posted(&p, &ev) == 1 && ev.value == (int32_t)round);
    }
}

/* A bundle as the build writes it: two files, BOOT and a program. */
static uint32_t bundle_build(uint8_t *b, uint32_t cap)
{
    memset(b, 0, cap);
    const char *boot = "lvui\n";
    const char *prog = "NPLD-program-bytes";
    uint32_t count = 2, at = 0x80;
    memcpy(b, "NLBB", 4);
    b[4] = 1; b[6] = 32;
    put32(b + 8, count);
    const char *names[] = { "BOOT", "LVUI.NLB" };
    const char *data[] = { boot, prog };
    for (uint32_t i = 0; i < count; i++) {
        uint8_t *e = b + 0x20 + 32 * i;
        uint32_t len = (uint32_t)strlen(data[i]);
        memcpy(e, names[i], strlen(names[i]));
        put32(e + 16, at);
        put32(e + 20, len);
        memcpy(b + at, data[i], len);
        put32(e + 24, nlr_platform_crc32(b + at, len));
        at = (at + len + 63u) & ~63u;
    }
    put32(b + 12, at);
    put32(b + 16, nlr_platform_crc32(b + 0x20, 32 * count));
    return at;
}

static void test_bundle(void)
{
    static uint8_t b[512];
    uint32_t total = bundle_build(b, sizeof b);
    const uint8_t *file;
    uint32_t size;
    char name[NLR_BUNDLE_NAME_MAX + 1];
    CHECK(nlr_bundle_count(b, sizeof b) == 2);
    CHECK(nlr_bundle_count(b, total) == 2);
    CHECK(nlr_bundle_count(b, total - 1) == 0);     /* past the span it may use */
    CHECK(nlr_bundle_entry(b, sizeof b, 1, name, &file, &size) == 0 &&
          !strcmp(name, "LVUI.NLB") && size == 18 && !memcmp(file, "NPLD", 4));
    CHECK(nlr_bundle_entry(b, sizeof b, 2, name, &file, &size) == -NLR_API_ENOENT);
    CHECK(nlr_bundle_find(b, sizeof b, "boot", 1, &file, &size) == 0 && size == 5 &&
          !memcmp(file, "lvui\n", 5));
    CHECK(nlr_bundle_find(b, sizeof b, "LVUI.NLB", 1, &file, &size) == 0);
    CHECK(nlr_bundle_find(b, sizeof b, "LVUI", 1, &file, &size) == -NLR_API_ENOENT);
    CHECK(nlr_bundle_find(b, sizeof b, "ENABLED", 1, &file, &size) == -NLR_API_ENOENT);
    /* a file whose bytes changed is not found when verified */
    b[0xc0] ^= 1;
    CHECK(nlr_bundle_find(b, sizeof b, "LVUI.NLB", 1, &file, &size) == -NLR_API_EIO);
    CHECK(nlr_bundle_find(b, sizeof b, "LVUI.NLB", 0, &file, &size) == 0);
    b[0xc0] ^= 1;
    /* a changed table, version, magic or padding: no bundle at all */
    b[0x20] = 'X';
    CHECK(nlr_bundle_count(b, sizeof b) == 0);
    bundle_build(b, sizeof b);
    b[4] = 2;
    CHECK(nlr_bundle_count(b, sizeof b) == 0);
    bundle_build(b, sizeof b);
    b[0x15] = 1;
    CHECK(nlr_bundle_count(b, sizeof b) == 0);
    memset(b, 0, sizeof b); /* the all-zero gap of a stock module */
    CHECK(nlr_bundle_count(b, sizeof b) == 0);
    CHECK(nlr_bundle_count(0, 0) == 0);
}

/* platform_caps follows what is declared, part by part: nothing without a platform table; controls only with a
 * carrier that scans (here the exit callback, as on the Z 8) and the scan
 * geometry; dials only with dial words and dial bytes; prop_set only with
 * the setter; touch only with all three of its fields; EVF never. */
static void none(void *object) { (void)object; }
static void touch_fn(uint32_t a, void *b) { (void)a; (void)b; }
static uint64_t set_fn(uint32_t tagged, uint32_t value) { return (uint64_t)tagged + value; }
static void w_init(void *w, void (*entry)(void *, uint32_t), uint32_t mask,
                   struct nlr_task_config *c)
{ (void)w; (void)entry; (void)mask; (void)c; }
static void w_start(void *w) { (void)w; }
static int32_t f_set(void *flag, uint32_t bits) { (void)flag; (void)bits; return 0; }

static void test_caps(void)
{
    static void (*slot)(void *) = none;
    static const struct nlr_exit_services exit_carrier = {.input_callback = &slot};
    static const struct nlr_platform_scan scan = {.bank_base = 8, .bank_stride = 20,
                                                  .banks = 3, .dial_offset = 0x58,
                                                  .dial_bytes = 16};
    static const volatile uint32_t colour[2], alpha[2], eye;
    static const uint8_t volumes[16];
    static void (*touch_slot)(uint32_t, void *);
    struct nlr_program_services program = {0};
    struct nlr_services svc = {0};
    CHECK(nlr_platform_caps(0) == 0);
    CHECK(nlr_platform_caps(&svc) == 0); /* no platform table at all */

    struct nlr_platform_services s = {0};
    svc.platform = &s;
    CHECK(nlr_platform_caps(&svc) == NLR_CAP_RESERVED);

    /* controls without a carrier, then without the scan, then both */
    s.controls = controls;
    s.control_count = sizeof controls / sizeof *controls;
    CHECK(!(nlr_platform_caps(&svc) & NLR_CAP_CONTROLS));
    svc.exit = &exit_carrier;
    CHECK(!(nlr_platform_caps(&svc) & NLR_CAP_CONTROLS));
    s.scan = &scan;
    CHECK(nlr_platform_caps(&svc) == (NLR_CAP_CONTROLS | NLR_CAP_RESERVED));
    /* dial words are the declaration (Z 8: none yet) */
    s.dial_word[0] = 1;
    CHECK(nlr_platform_caps(&svc) & NLR_CAP_DIALS);
    s.dial_word[0] = 0;

    /* the screen needs both scanout words */
    svc.program = &program;
    program.scanout_colour = colour;
    CHECK(!(nlr_platform_caps(&svc) & NLR_CAP_SCREEN));
    program.scanout_alpha = alpha;
    CHECK(nlr_platform_caps(&svc) & NLR_CAP_SCREEN);

    /* props without and with the setter */
    s = services();
    s.dial_word[0] = s.dial_word[1] = 0;
    s.scan = &scan;
    uint32_t caps = nlr_platform_caps(&svc);
    CHECK((caps & NLR_CAP_PROPS) && !(caps & NLR_CAP_PROP_SET));
    s.prop_set = set_fn;
    CHECK(nlr_platform_caps(&svc) & NLR_CAP_PROP_SET);

    /* tasks need all three task services */
    svc.worker_init = w_init;
    svc.worker_start = w_start;
    CHECK(!(nlr_platform_caps(&svc) & NLR_CAP_TASKS));
    svc.flag_set = f_set;
    CHECK(nlr_platform_caps(&svc) & NLR_CAP_TASKS);

    /* card, touch (all three fields), eye */
    s.volumes = volumes;
    s.volume_count = 1;
    CHECK(!(nlr_platform_caps(&svc) & NLR_CAP_CARD));
    s.card_slots = 1;
    CHECK(nlr_platform_caps(&svc) & NLR_CAP_CARD);
    s.touch_slot = &touch_slot;
    s.touch_original = touch_fn;
    CHECK(!(nlr_platform_caps(&svc) & NLR_CAP_TOUCH));
    s.touch_record_bytes = 14;
    CHECK(nlr_platform_caps(&svc) & NLR_CAP_TOUCH);
    s.eye_state = &eye;
    caps = nlr_platform_caps(&svc);
    CHECK(caps == (NLR_CAP_CONTROLS | NLR_CAP_SCREEN | NLR_CAP_PROPS | NLR_CAP_PROP_SET |
                   NLR_CAP_TASKS | NLR_CAP_CARD | NLR_CAP_TOUCH | NLR_CAP_EYE |
                   NLR_CAP_RESERVED));
    CHECK(!(caps & NLR_CAP_EVF) && !(caps & NLR_CAP_DIALS));
}

int main(void)
{
    test_caps();
    test_bundle();
    test_posted();
    test_names();
    test_cards();
    test_touch_eye_dials();
    test_routes();
    test_scan_and_ring();
    test_timers();
    test_props();
    if (failures) {
        printf("%d platform checks failed\n", failures);
        return 1;
    }
    printf("platform behavior tests passed\n");
    return 0;
}
