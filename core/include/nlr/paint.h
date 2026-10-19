#ifndef NLR_PAINT_H
#define NLR_PAINT_H
#include <stdint.h>

/* A diagnostic on an actual native text-draw call. The original mutable
 * draw object is never treated as a bitmap descriptor or retained. */
struct nlr_paint_services {
    int32_t (*text_draw)(void *widget, void *draw, uint32_t a, uint32_t b);
    int32_t (*blit)(void *bitmap_descriptor);
    uint32_t (*current_index)(void);
    int32_t (*current_surface)(uint32_t selector, uint64_t *out);
    void *(*current_window)(void);
    int32_t (*current_task)(uint32_t *out);
    void (*clean_source)(void *pixels, uint32_t bytes);
    void *(*widget_root)(void *widget);
    const uint8_t *(*surface_record)(uint32_t type, uint32_t group, uint32_t index);
    const void *window;
    const char *task_name; /* Exactly eight bytes, including native padding. */
    uint32_t window_id;
    uint32_t pattern; /* 0: trace, 1: checker, 2: RGB bars. */
    uint32_t surface_group; /* Exact independently checked native group. */
    uint32_t full_screen; /* Destination covers the real record dimensions. */
};

#define NLR_PAINT_MAGIC UINT64_C(0x3145434152544e50)
struct nlr_paint_probe {
    uint64_t magic;
    void *allocation;
    uint32_t calls, nloader_calls, submitted, completed;
    uint32_t task, index, root_type, root_group, root_index;
    int32_t task_result, original_result, surface_result;
    uint64_t task_object, window_object, widget, draw, root;
    uint64_t record, target, after_surface;
    uint32_t a, b;
    _Alignas(64) uint32_t pixels[256];
};

int32_t nlr_paint_text_observe(void *widget, void *draw, uint32_t a, uint32_t b);
#endif
