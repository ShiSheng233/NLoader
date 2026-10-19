#include "nlr/bitmap.h"
#include "nlr/runtime.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static struct nlr_runtime runtime;
static uint8_t gui_worker[NLR_WORKER_SIZE];
static uint8_t window[16];
static uint8_t other_window[16];
static uint32_t task_id = 7;
static int32_t task_result;
static void *active_window = window;
static uint64_t surface = 17;
static uint32_t calls, cleaned;
static uint32_t change_after, fail_allocate;
static uint16_t native_width, native_height;
static struct nlr_bitmap_services bitmap;

static int32_t allocate(uint32_t bytes, void **out)
{
    if (fail_allocate)
        return NLR_NOT_READY;
    *out = malloc(bytes);
    return *out ? NLR_OK : NLR_NOT_READY;
}
static int32_t release(void *p) { free(p); return 0; }
static uint32_t index_get(void) { return 0; }
static void *window_get(void) { return active_window; }
static int32_t task_get(uint32_t *out)
{ *out = task_result ? 0 : task_id; return task_result; }
static int32_t surface_get(uint32_t selector, uint64_t *out)
{ assert(selector == 0); *out = surface; return 0; }
static void registry(uint32_t type, uint32_t id, void **out)
{ assert(type == 0); *out = id == 7 ? gui_worker : 0; }
static void clean(void *pixels, uint32_t bytes)
{ assert(!((uintptr_t)pixels & 63u)); assert(bytes == 1024); cleaned++; }

const struct nlr_services nlr_services = {
    .alloc = allocate, .release = release, .registry_lookup = registry,
    .bitmap = &bitmap,
};
/* The allocation entry (core/exec.c) for a build without heap books. */
void *nlr_alloc_whole(const struct nlr_services *s, uint32_t bytes)
{ void *block = 0; return s->alloc(bytes, &block) == 0 ? block : 0; }
struct nlr_runtime *nlr_runtime_find(const struct nlr_services *s, uint32_t *named)
{ assert(s == &nlr_services); if (named) *named = 1; return &runtime; }

static uint64_t wide(const uint8_t *p, uint32_t at)
{ uint64_t v; memcpy(&v, p + at, 8); return v; }
static uint16_t half(const uint8_t *p, uint32_t at)
{ return (uint16_t)(p[at] | (uint16_t)p[at + 1] << 8); }
static void put(uint8_t *p, uint32_t at, uint64_t v, uint32_t bytes)
{ memcpy(p + at, &v, bytes); }

static int32_t original(void *descriptor)
{
    uint8_t *d = descriptor;
    calls++;
    if (d && d[0] != 1) {
        native_width = half(d, 0x20);
        native_height = half(d, 0x22);
    }
    if (d && d[0] == 1) {
        assert(wide(d, 0x18) == surface);
        assert(half(d, 0x10) == 16 && half(d, 0x12) == 16);
        /* Native ABI: +20/+22 are the whole target dimensions, +28..2e
         * crop the source, and +30..36 position/size the target rectangle. */
        assert(half(d, 0x20) >= 148 && half(d, 0x22) >= 148);
        assert(half(d, 0x20) == native_width && half(d, 0x22) == native_height);
        assert(!half(d, 0x28) && !half(d, 0x2a));
        assert(half(d, 0x2c) == 16 && half(d, 0x2e) == 16);
        assert(half(d, 0x30) == 20 && half(d, 0x32) == 20);
        assert(half(d, 0x34) == 128 && half(d, 0x36) == 128);
        assert(d[0x3c] == 255);
        /* Blend-table index and every unknown field stay zero. */
        assert(wide(d, 0x4c) == 0);
        const uint32_t *pixels = (void *)(uintptr_t)wide(d, 8);
        assert(!((uintptr_t)pixels & 63u) && cleaned == 1);
        if (bitmap.pattern == 1) {
            assert(pixels[0] == UINT32_MAX && pixels[4] == UINT32_C(0x88888888));
        } else {
            const uint8_t *rgba = (const void *)pixels;
            const uint8_t red[4] = {255, 0, 0, 255};
            const uint8_t green[4] = {0, 255, 0, 255};
            const uint8_t blue[4] = {0, 0, 255, 255};
            assert(!memcmp(rgba, red, 4));
            assert(!memcmp(rgba + 6 * 4, green, 4));
            assert(!memcmp(rgba + 12 * 4, blue, 4));
        }
    } else if (change_after == 1) {
        active_window = other_window;
    } else if (change_after == 2) {
        surface++;
    } else if (change_after == 3) {
        task_id = 9;
    } else if (change_after == 4) {
        /* Shared observations are not permission to draw. */
        struct nlr_bitmap_probe *p = runtime.bitmap_probe;
        p->window = bitmap.window_id;
        p->task = p->gui_task = 7;
        p->target = p->after_surface = surface;
        active_window = other_window;
    }
    return 23; /* Preserve a nonzero original value; do not invent success. */
}

static void reset(void)
{
    if (runtime.bitmap_probe) {
        struct nlr_bitmap_probe *p = runtime.bitmap_probe;
        free(p->allocation);
    }
    memset(&runtime, 0, sizeof runtime);
    memset(gui_worker, 0, sizeof gui_worker);
    put(gui_worker, NLR_WORKER_ID_OFFSET, 7, 4);
    memcpy(gui_worker + NLR_WORKER_NAME_OFFSET, "APPMENU", 8);
    put(gui_worker, NLR_WORKER_SELF_OFFSET, (uintptr_t)gui_worker, 8);
    put(window, 2, 1493, 2);
    bitmap = (struct nlr_bitmap_services){
        .blit = original, .current_index = index_get,
        .current_surface = surface_get, .current_window = window_get,
        .current_task = task_get, .clean_source = clean,
        .window = window, .gui_task_name = "APPMENU", .window_id = 1493,
        .pattern = 1,
    };
    task_id = 7; task_result = 0; active_window = window; surface = 17;
    calls = cleaned = change_after = fail_allocate = 0;
}

int main(void)
{
    uint8_t d[0x58] = {0};
    d[0] = 2; d[0x10] = d[0x12] = d[0x2c] = d[0x2e] = 4;
    put(d, 0x18, 17, 8);
    put(d, 0x20, 960, 2); put(d, 0x22, 640, 2);
    reset();
    assert(nlr_bitmap_observe(d) == 23 && calls == 2 && cleaned == 1);
    struct nlr_bitmap_probe *p = runtime.bitmap_probe;
    assert(p->submitted == 1 && p->completed == 1 && p->gui_calls == 1);
    assert(nlr_bitmap_observe(d) == 23 && calls == 4 && cleaned == 1);
    reset(); bitmap.pattern = 2;
    assert(nlr_bitmap_observe(d) == 23 && calls == 2 && cleaned == 1);
    for (uint32_t dimension = 0; dimension < 2; dimension++) {
        reset(); put(d, 0x20 + dimension * 2u, 147, 2);
        assert(nlr_bitmap_observe(d) == 23 && calls == 1);
        assert(((struct nlr_bitmap_probe *)runtime.bitmap_probe)->submitted == 0);
        put(d, 0x20 + dimension * 2u, dimension ? 640 : 960, 2);
    }
    reset(); put(d, 0x20, 148, 2); put(d, 0x22, 148, 2);
    assert(nlr_bitmap_observe(d) == 23 && calls == 2);
    put(d, 0x20, 960, 2); put(d, 0x22, 640, 2);
    for (uint32_t mutation = 1; mutation <= 4; mutation++) {
        reset(); change_after = mutation;
        assert(nlr_bitmap_observe(d) == 23 && calls == 1);
        assert(((struct nlr_bitmap_probe *)runtime.bitmap_probe)->submitted == 0);
    }
    reset(); bitmap.pattern = 0;
    assert(nlr_bitmap_observe(d) == 23 && calls == 1);
    reset(); task_result = -25;
    assert(nlr_bitmap_observe(d) == 23 && calls == 1 && !runtime.bitmap_probe);
    reset(); gui_worker[NLR_WORKER_NAME_OFFSET] = 'X';
    assert(nlr_bitmap_observe(d) == 23 && calls == 1 && !runtime.bitmap_probe);
    reset(); fail_allocate = 1;
    assert(nlr_bitmap_observe(d) == 23 && calls == 1 && !runtime.bitmap_probe);
    reset(); bitmap.current_task = 0;
    assert(nlr_bitmap_observe(d) == 23 && calls == 1 && !runtime.bitmap_probe);
    reset(); d[0x10] = 0;
    assert(nlr_bitmap_observe(d) == 23 && calls == 1);
    reset();
    puts("bitmap owner and immutable DMA source checks passed");
    return 0;
}
