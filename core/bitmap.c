#include "nlr/bitmap.h"
#include "nlr/runtime.h"

extern const struct nlr_services nlr_services;

static uint16_t half(const uint8_t *p, uint32_t at)
{
    return (uint16_t)(p[at] | (uint16_t)p[at + 1] << 8);
}

static uint64_t wide(const uint8_t *p, uint32_t at)
{
    uint64_t result = 0;
    for (uint32_t n = 0; n < 8; n++)
        result |= (uint64_t)p[at + n] << (n * 8);
    return result;
}

static void put_half(uint8_t *p, uint32_t at, uint16_t value)
{
    p[at] = (uint8_t)value;
    p[at + 1] = (uint8_t)(value >> 8);
}

static void put_wide(uint8_t *p, uint32_t at, uint64_t value)
{
    for (uint32_t n = 0; n < 8; n++)
        p[at + n] = (uint8_t)(value >> (n * 8));
}

static struct nlr_bitmap_probe *probe(struct nlr_runtime *r, uint32_t pattern)
{
    if (r->bitmap_probe)
        return r->bitmap_probe;
    void *allocation = nlr_alloc_whole(&nlr_services,
                                       sizeof(struct nlr_bitmap_probe) + 63u);
    if (!allocation)
        return 0;
    struct nlr_bitmap_probe *p = (void *)(((uintptr_t)allocation + 63u) &
                                         ~(uintptr_t)63u);
    uint8_t *bytes = (uint8_t *)p;
    for (uint32_t n = 0; n < sizeof *p; n++)
        bytes[n] = 0;
    p->magic = NLR_BITMAP_TRACE_MAGIC;
    p->allocation = allocation;
    for (uint32_t y = 0; y < NLR_BITMAP_SOURCE_SIDE; y++) {
        for (uint32_t x = 0; x < NLR_BITMAP_SOURCE_SIDE; x++) {
            uint32_t pixel = ((x / 4u + y / 4u) & 1u) ?
                                  UINT32_C(0x88888888) : UINT32_MAX;
            if (pattern == 2u)
                pixel = x < 5u ? UINT32_C(0xff0000ff) :
                        x < 11u ? UINT32_C(0xff00ff00) :
                                  UINT32_C(0xffff0000);
            p->pixels[y * NLR_BITMAP_SOURCE_SIDE + x] = pixel;
        }
    }
    nlr_services.bitmap->clean_source(p->pixels, sizeof p->pixels);
    r->bitmap_probe = p;
    return p;
}

int32_t nlr_bitmap_observe(void *descriptor)
{
    const struct nlr_bitmap_services *s = nlr_services.bitmap;
    if (!s || !s->blit)
        return NLR_NOT_READY;
    if (!s->current_index || !s->current_surface || !s->current_window ||
        !s->current_task || !s->clean_source || !s->window || !s->gui_task_name)
        return s->blit(descriptor);
    uint32_t task = 0;
    int32_t task_result = s->current_task(&task);
    void *object = 0;
    if (task_result == 0 && task && nlr_services.registry_lookup)
        nlr_services.registry_lookup(NLR_REGISTRY_TYPE_TASK, task, &object);
    uint32_t gui_task = 0;
    if (object && !((uintptr_t)object & 7u)) {
        const uint8_t *worker = object;
        uint32_t name = 0;
        while (name < NLR_TASK_NAME_SIZE &&
               worker[NLR_WORKER_NAME_OFFSET + name] ==
                   (uint8_t)s->gui_task_name[name])
            name++;
        if (name == NLR_TASK_NAME_SIZE &&
            (uint32_t)wide(worker, NLR_WORKER_ID_OFFSET) == task &&
            wide(worker, NLR_WORKER_SELF_OFFSET) ==
            (uintptr_t)object)
            gui_task = task;
    }
    /* The task name is an audited native task name, not its event-flag name.
     * Only this one GUI owner may allocate or modify the diagnostic record. */
    struct nlr_runtime *r = gui_task ? nlr_runtime_find(&nlr_services, 0) : 0;
    struct nlr_bitmap_probe *p = r && descriptor ? probe(r, s->pattern) : 0;
    void *window = s->current_window();
    uint32_t index = s->current_index();
    uint64_t target = descriptor ? wide(descriptor, 0x18) : 0;
    uint32_t extents = descriptor && half(descriptor, 0x10) &&
        half(descriptor, 0x12) && half(descriptor, 0x2c) && half(descriptor, 0x2e);
    uint16_t target_width = descriptor ? half(descriptor, 0x20) : 0;
    uint16_t target_height = descriptor ? half(descriptor, 0x22) : 0;
    if (p) {
        const uint8_t *d = descriptor;
        p->calls++;
        p->index = index;
        p->window_object = (uintptr_t)window;
        p->window = p->window_object == (uintptr_t)s->window ?
                        half(s->window, 2u) : UINT32_MAX;
        p->task = task;
        p->task_result = task_result;
        p->gui_task = gui_task;
        p->task_object = (uintptr_t)object;
        p->target = target;
        for (uint32_t n = 0; n < sizeof p->descriptor; n++)
            p->descriptor[n] = d[n];
        if (p->window == s->window_id)
            p->nloader_calls++;
        if (p->task && p->task == p->gui_task)
            p->gui_calls++;
    }
    int32_t original = s->blit(descriptor);
    if (!p)
        return original;
    p->original_result = original;
    uint64_t after_surface = 0;
    int32_t surface_result = s->current_surface(0u, &after_surface);
    uint32_t after_task = 0;
    int32_t after_task_result = s->current_task(&after_task);
    p->after_surface = after_surface;
    p->surface_result = surface_result;
    if (!s->pattern || s->pattern > 2u ||
        surface_result != 0 || !target || target != after_surface || index >= 33u ||
        window != s->window || half(window, 2u) != s->window_id ||
        s->current_window() != window || !task || task != gui_task ||
        task_result != 0 || after_task_result != 0 || after_task != task)
        return original;
    /* A well-formed native descriptor alone is not GUI ownership proof.
     * Require the source and target extents from the real original call too. */
    if (!extents || target_width < 20u + NLR_BITMAP_TARGET_SIDE ||
        target_height < 20u + NLR_BITMAP_TARGET_SIDE)
        return original;
    uint8_t draw[0x58] = {0};
    draw[0] = 1; /* Independently checked native format mapping: 4 bytes/pixel. */
    put_wide(draw, 8u, (uint64_t)(uintptr_t)p->pixels);
    put_half(draw, 0x10, NLR_BITMAP_SOURCE_SIDE);
    put_half(draw, 0x12, NLR_BITMAP_SOURCE_SIDE);
    put_wide(draw, 0x18, after_surface);
    put_half(draw, 0x20, target_width);
    put_half(draw, 0x22, target_height);
    put_half(draw, 0x2c, NLR_BITMAP_SOURCE_SIDE);
    put_half(draw, 0x2e, NLR_BITMAP_SOURCE_SIDE);
    put_half(draw, 0x30, 20u);
    put_half(draw, 0x32, 20u);
    put_half(draw, 0x34, NLR_BITMAP_TARGET_SIDE);
    put_half(draw, 0x36, NLR_BITMAP_TARGET_SIDE);
    draw[0x3c] = 255u;
    p->submitted++;
    s->blit(draw);
    p->completed++; /* Returned from the native waits, not a pixel pass flag. */
    return original;
}
