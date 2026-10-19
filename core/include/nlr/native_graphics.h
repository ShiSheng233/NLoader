#ifndef NLR_NATIVE_GRAPHICS_H
#define NLR_NATIVE_GRAPHICS_H

#include "nlr/graphics.h"

typedef int32_t (*nlr_native_canvas_draw)(void *widget, void *rectangle,
                                         void *abort_callback);

/* All native pointers come from independently checked profile bindings. */
struct nlr_native_graphics_services {
    const void *window;
    uint32_t window_id, canvas_id, row_first, row_count;
    uint32_t destination_x, destination_y, destination_width, destination_height;
    uint32_t surface_type, surface_group, surface_index;
    const void *surface_record_address;
    const char *gui_task_name;
    const volatile uint32_t *gui_state;
    int32_t (*current_task)(uint32_t *out);
    void (*registry_lookup)(uint32_t type, uint32_t id, void **out);
    void *(*current_window)(void);
    void *(*widget_find)(uint32_t id, void *container);
    void *(*widget_root)(void *widget);
    nlr_native_canvas_draw (*get_draw)(void *widget);
    void (*set_draw)(void *widget, nlr_native_canvas_draw draw);
    int32_t (*set_dirty)(void *widget, uint32_t dirty);
    uint32_t (*get_visible)(void *widget);
    void (*set_visible)(void *widget, uint32_t visible);
    nlr_native_canvas_draw original_draw;
    void (*window_render)(void *window);
    nlr_native_canvas_draw render_widget; /* original locked context dispatch */
    void (*display_refresh)(int32_t (*abort_callback)(void), uint32_t mode,
                             uint32_t flags);
    int32_t (*display_abort)(void);
    int32_t (*submit)(uint32_t mask, void *request);
    int32_t (*queue_task)(void); /* positive original graphics queue task ID */
    void (*fence)(void);
    int32_t (*blit)(void *descriptor);
    uint32_t (*current_index)(void);
    int32_t (*current_surface)(uint32_t selector, uint64_t *out);
    const uint8_t *(*surface_record)(uint32_t type, uint32_t group, uint32_t index);
    /* Original list-row operation includes the row's background and arrow
     * children; the generic visibility setter only changes the parent. */
    void (*row_hide)(void *window, uint32_t row, uint32_t hidden);
    void (*row_dirty)(void *row, uint32_t dirty);
    uint32_t surface_width, surface_height;
};

/* GUI-owned provider state, resident with runtime. No pixel pointer is kept
 * outside one synchronous render call. The getter below must find this same
 * object from the actual native callback/submit observer, never a global
 * mutable XIP slot. */
struct nlr_native_graphics {
    struct nlr_graphics *graphics;
    void *canvas;
    nlr_native_canvas_draw saved_draw;
    void *rows[64];
    uint64_t visible_rows;
    uint32_t rows_hidden;
    uint32_t rendering;
    uint64_t owner;
    const struct nlr_graphics_frame *frame;
    uint32_t *started;
    uint32_t callback_calls, draws, submit_calls, submits;
    int32_t queue_task;
    int32_t result;
    uint32_t built_rows; /* membership confirmed in the native GUI callback */
};

extern const struct nlr_native_graphics_services nlr_native_graphics_services;
/* Implemented by the runtime bridge; returns a boot-owned object or NULL. */
struct nlr_native_graphics *nlr_native_graphics_context(void);
/* Read the current, checked native page declaration on its GUI owner.
 * Zero refuses an invalid count; fixed pages retain the declared capacity. */
uint32_t nlr_native_graphics_row_count(void *window);

int32_t nlr_native_graphics_gui_owner(void *context);
int32_t nlr_native_graphics_current_window(void *context, uint64_t owner);
int32_t nlr_native_graphics_render(void *context, uint64_t owner,
                                   const struct nlr_graphics_frame *frame,
                                   uint32_t *started);
/* GUI slot4 after original construction; repeated calls are idempotent.
 * Normal loader page re-entry calls slot4 again for the new native objects. */
int nlr_native_graphics_install(struct nlr_native_graphics *context, void *window);
/* GUI-only, before original page destruction or when returning from an app.
 * It touches only a freshly re-found self canvas and the same row objects. */
int nlr_native_graphics_restore(struct nlr_native_graphics *context, void *window);
/* After the original page refresh, re-find its actual rows and repaint them
 * with the self canvas already inert. Visibility remains page-owned. */
int nlr_native_graphics_redraw_menu(struct nlr_native_graphics *context, void *window);
int32_t nlr_native_graphics_canvas(void *widget, void *rectangle, void *abort_callback);
/* A stock commit returned `result` (the platform's commit observer,
 * nlr_platform_gui_commit, which owns the commit call sites): 1 when the
 * loader was rendering its own canvas -- the commit is that frame's and is
 * counted here -- and 0 when it is the stock GUI's own. */
int nlr_native_graphics_commit_seen(struct nlr_native_graphics *c, int32_t result);

#endif
