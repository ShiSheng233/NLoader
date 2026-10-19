#ifndef NLR_BITMAP_H
#define NLR_BITMAP_H

#include <stdint.h>

/* Optional diagnostic services. All pins, original-call identity and native
 * context accessors must be checked against the selected firmware profile. */
struct nlr_bitmap_services {
    int32_t (*blit)(void *descriptor);
    uint32_t (*current_index)(void);
    int32_t (*current_surface)(uint32_t selector, uint64_t *out);
    void *(*current_window)(void);
    int32_t (*current_task)(uint32_t *out);
    void (*clean_source)(void *pixels, uint32_t bytes);
    const void *window;
    const char *gui_task_name; /* Native worker-family eight-byte name. */
    uint32_t window_id;
    uint32_t pattern; /* 0: observe only, 1: monochrome checker, 2: RGB bars */
};

#define NLR_BITMAP_SOURCE_SIDE 16u
#define NLR_BITMAP_TARGET_SIDE 128u
#define NLR_BITMAP_TRACE_MAGIC UINT64_C(0x314550414d544942)

/* Diagnostic observations are boot-owned and never allocated in XIP.
 * Source pixels remain immutable after initialization and are deliberately
 * retained for this boot; this is not a general graphics ownership API. */
struct nlr_bitmap_probe {
    uint64_t magic;
    void *allocation;
    uint32_t calls;
    uint32_t nloader_calls;
    uint32_t gui_calls;
    uint32_t submitted;
    uint32_t completed;
    uint32_t index;
    uint32_t window;
    uint32_t task;
    uint32_t gui_task;
    int32_t task_result;
    uint64_t task_object;
    uint64_t window_object;
    int32_t original_result;
    int32_t surface_result;
    uint64_t target;
    uint64_t after_surface;
    uint8_t descriptor[0x58];
    _Alignas(64) uint32_t pixels[NLR_BITMAP_SOURCE_SIDE * NLR_BITMAP_SOURCE_SIDE];
};
_Static_assert(__builtin_offsetof(struct nlr_bitmap_probe, pixels) % 64u == 0u,
               "DMA source owns complete cache lines");

/* Preserves the real original drawing call and its return. A diagnostic draw
 * is restricted to a verified GUI-task call for the NLoader window and the
 * same still-current target; no worker or host framebuffer writes occur. */
int32_t nlr_bitmap_observe(void *descriptor);

#endif
