#include "nlr/native_graphics.h"
#include "nlr/services.h"

static uint32_t word(const void *memory, uint32_t offset)
{
    const uint8_t *p = memory;
    return (uint32_t)p[offset] | (uint32_t)p[offset + 1u] << 8 |
        (uint32_t)p[offset + 2u] << 16 | (uint32_t)p[offset + 3u] << 24;
}

static uint64_t wide(const void *memory, uint32_t offset)
{
    return (uint64_t)word(memory, offset) | (uint64_t)word(memory, offset + 4u) << 32;
}

static void put(uint8_t *p, uint32_t offset, uint64_t value, uint32_t count)
{
    for (uint32_t n = 0; n < count; n++)
        p[offset + n] = (uint8_t)(value >> (8u * n));
}

static int ready(void)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    return s->window && s->canvas_id && s->row_count && s->row_count <= 64u &&
        s->gui_task_name && s->gui_state && s->current_task && s->registry_lookup &&
        s->current_window && s->widget_find && s->widget_root && s->get_draw &&
        s->set_draw && s->set_dirty && s->get_visible && s->set_visible &&
        s->original_draw && s->row_hide && s->row_dirty && s->window_render && s->render_widget && s->display_refresh && s->display_abort &&
        s->submit && s->queue_task && s->fence && s->blit && s->current_index && s->current_surface &&
        s->surface_record && s->surface_record_address && s->surface_type == 1u &&
        s->surface_group == 1u && s->surface_index == 2u &&
        s->surface_width == 640u && s->surface_height == 422u &&
        s->destination_x < 632u && s->destination_y < 422u &&
        s->destination_width && s->destination_width <= 632u - s->destination_x &&
        s->destination_height && s->destination_height <= 422u - s->destination_y;
}

int32_t nlr_native_graphics_gui_owner(void *context)
{
    (void)context;
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (!ready())
        return NLR_GRAPHICS_NOT_READY;
    uint32_t task = 0;
    void *object = 0;
    if (s->current_task(&task) || !task)
        return NLR_GRAPHICS_OWNER;
    s->registry_lookup(NLR_REGISTRY_TYPE_TASK, task, &object);
    if (!object || ((uintptr_t)object & 7u) || word(object, 0) != task ||
        wide(object, NLR_WORKER_SELF_OFFSET) != (uintptr_t)object)
        return NLR_GRAPHICS_OWNER;
    const uint8_t *bytes = object;
    for (uint32_t n = 0; n < NLR_TASK_NAME_SIZE; n++)
        if (bytes[NLR_WORKER_NAME_OFFSET + n] != (uint8_t)s->gui_task_name[n])
            return NLR_GRAPHICS_OWNER;
    return NLR_GRAPHICS_OK;
}

static void *find_canvas(void)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (*s->gui_state != 1u || s->current_window() != s->window ||
        (word(s->window, 0) >> 16) != s->window_id)
        return 0;
    void *widget = s->widget_find(s->canvas_id, (uint8_t *)s->window + 0x18u);
    if (!widget || ((uintptr_t)widget & 7u) || word(widget, 0) != s->canvas_id ||
        (word(widget, 4) & 0xffffu) != 4u || word(widget, 0xcu) != 1u ||
        word(widget, 0x10u) != (s->destination_x | s->destination_y << 16) ||
        word(widget, 0x14u) != ((s->destination_x + s->destination_width) |
                              (s->destination_y + s->destination_height) << 16) ||
        !wide(s->window, 0x20u) ||
        (uintptr_t)s->widget_root(widget) != wide(s->window, 0x20u))
        return 0;
    return widget;
}

/* The native declaration and actual widget membership must agree. Missing
 * rows inside the current build and extra owned rows beyond it both refuse;
 * a dynamic page is never permission to ignore arbitrary lookup failures. */
static int checked_rows(struct nlr_native_graphics *c, void *canvas,
                         uint32_t match_snapshot, uint32_t *out)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    uint32_t count = nlr_native_graphics_row_count((void *)s->window);
    if (!count || count > s->row_count || (match_snapshot && count != c->built_rows))
        return NLR_GRAPHICS_OWNER;
    for (uint32_t n = 0; n < s->row_count; n++) {
        void *row = s->widget_find(s->row_first + n, (uint8_t *)s->window + 0x18u);
        if (n >= count) {
            if (row) return NLR_GRAPHICS_OWNER;
        } else if (!row || row == canvas || word(row, 0) != s->row_first + n ||
                   s->get_visible(row) > 1u || (match_snapshot && row != c->rows[n]))
            return NLR_GRAPHICS_OWNER;
    }
    if (nlr_native_graphics_row_count((void *)s->window) != count)
        return NLR_GRAPHICS_OWNER;
    *out = count;
    return NLR_GRAPHICS_OK;
}

int nlr_native_graphics_install(struct nlr_native_graphics *c, void *window)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (!c || window != s->window || nlr_native_graphics_gui_owner(c))
        return NLR_GRAPHICS_OWNER;
    if (c->rendering)
        return NLR_GRAPHICS_BUSY;
    void *canvas = find_canvas();
    if (!canvas)
        return NLR_GRAPHICS_NOT_READY;
    nlr_native_canvas_draw original = s->get_draw(canvas);
    if (original != s->original_draw &&
        !(original == nlr_native_graphics_canvas && c->canvas == canvas &&
          c->saved_draw == s->original_draw))
        return NLR_GRAPHICS_OWNER;
    uint32_t count = 0;
    int result = checked_rows(c, canvas, c->rows_hidden, &count);
    if (result) return result;
    if (c->rows_hidden) return NLR_GRAPHICS_OK;
    /* A re-created native widget has its original callback again. Discard
     * old addresses without dereferencing widgets already destroyed by the
     * original page transition. */
    c->canvas = canvas;
    c->saved_draw = s->original_draw;
    c->rows_hidden = 0;
    c->visible_rows = 0;
    for (uint32_t n = 0; n < 64u; n++)
        c->rows[n] = n < count ? s->widget_find(s->row_first + n,
                        (uint8_t *)s->window + 0x18u) : 0;
    c->built_rows = count;
    s->set_visible(canvas, 0);
    s->set_draw(canvas, nlr_native_graphics_canvas);
    return s->get_draw(canvas) == nlr_native_graphics_canvas ?
        NLR_GRAPHICS_OK : NLR_GRAPHICS_IO;
}

static int hide_rows(struct nlr_native_graphics *c)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    uint32_t count = 0;
    int result = checked_rows(c, c->canvas, 1u, &count);
    if (result) return result;
    if (c->rows_hidden)
        return NLR_GRAPHICS_OK;
    uint64_t visible = 0;
    for (uint32_t n = 0; n < count; n++) {
        void *row = s->widget_find(s->row_first + n, (uint8_t *)s->window + 0x18u);
        if (!row || row == c->canvas || word(row, 0) != s->row_first + n)
            return NLR_GRAPHICS_OWNER;
        c->rows[n] = row;
        uint32_t shown = s->get_visible(row);
        if (shown > 1u)
            return NLR_GRAPHICS_OWNER;
        if (shown)
            visible |= UINT64_C(1) << n;
    }
    c->visible_rows = visible;
    c->rows_hidden = 1;
    /* A list row owns background and arrow children. The generic setter
     * only changes its parent's visibility, leaving those children on the
     * overlay. Use the original list operation for the complete row. */
    for (uint32_t n = 0; n < count; n++) {
        s->row_hide((void *)s->window, n, 1);
        /* The original hide operation clears dirty on the parent and all
         * children. Re-arm that same complete group so the next native
         * tree render erases its old raster before drawing the canvas. */
        s->row_dirty(c->rows[n], 1);
    }
    return NLR_GRAPHICS_OK;
}

int32_t nlr_native_graphics_current_window(void *context, uint64_t owner)
{
    struct nlr_native_graphics *c = context;
    if (!c || !c->graphics || !owner || nlr_native_graphics_gui_owner(c))
        return NLR_GRAPHICS_OWNER;
    struct nlr_graphics_snapshot snapshot;
    if (nlr_graphics_snapshot(c->graphics, &snapshot))
        return NLR_GRAPHICS_BUSY;
    if (snapshot.owner != owner || snapshot.phase != NLR_GRAPHICS_DRAWING ||
        !snapshot.gui_active || !snapshot.waiter_active)
        return NLR_GRAPHICS_OWNER;
    if (find_canvas() != c->canvas || !c->canvas) return NLR_GRAPHICS_CANCELLED;
    uint32_t count = 0;
    return checked_rows(c, c->canvas, 1u, &count);
}

int32_t nlr_native_graphics_canvas(void *widget, void *rectangle, void *abort_callback)
{
    struct nlr_native_graphics *c = nlr_native_graphics_context();
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (!c || nlr_native_graphics_gui_owner(c) || widget != c->canvas || find_canvas() != widget)
        return 1;
    if (!c->rendering) {
        /* Hidden stock image callbacks paint a background too. Outside an
         * explicit frame this canvas must preserve both the previous frame
         * and normal menu rows, which share the content surface. */
        s->set_dirty(widget, 0);
        return 1;
    }
    (void)rectangle;
    c->callback_calls++;
    if (!c->frame || !c->started || c->result ||
        (abort_callback && ((int32_t (*)(void))abort_callback)()))
        return 1;
    if (c->queue_task <= 0 || s->queue_task() != c->queue_task) {
        c->result = NLR_GRAPHICS_NOT_READY;
        return 1;
    }
    void *root = s->widget_root(widget);
    if (!root || ((uintptr_t)root & 7u) ||
        (uintptr_t)root != wide(s->window, 0x20u) ||
        word(root, 0x108) != s->surface_type || word(root, 0x10c) != s->surface_group ||
        word(root, 0x110) != s->surface_index) {
        c->result = NLR_GRAPHICS_OWNER;
        return 1;
    }
    const uint8_t *record = s->surface_record(s->surface_type, s->surface_group, s->surface_index);
    uint64_t current = 0;
    if (record != s->surface_record_address || !record ||
        s->current_surface(0, &current) || !current || wide(record, 0x28) != current ||
        s->current_index() >= 33u || (word(record, 8) & 0xffffu) != s->surface_width ||
        (word(record, 8) >> 16) != s->surface_height) {
        c->result = NLR_GRAPHICS_OWNER;
        return 1;
    }
    _Alignas(8) uint8_t descriptor[0x58] = {0};
    put(descriptor, 0, 1, 4);
    put(descriptor, 8, (uintptr_t)c->frame->pixels, 8);
    put(descriptor, 0x10, c->frame->width, 2);
    put(descriptor, 0x12, c->frame->height, 2);
    put(descriptor, 0x18, current, 8);
    put(descriptor, 0x20, s->surface_width, 2);
    put(descriptor, 0x22, s->surface_height, 2);
    put(descriptor, 0x2c, c->frame->width, 2);
    put(descriptor, 0x2e, c->frame->height, 2);
    put(descriptor, 0x30, s->destination_x, 2);
    put(descriptor, 0x32, s->destination_y, 2);
    put(descriptor, 0x34, s->destination_width, 2);
    put(descriptor, 0x36, s->destination_height, 2);
    put(descriptor, 0x3c, 255, 4);
    *c->started = 1;
    /* The audited wrapper forces zero at its common normal return. It is
     * not a propagated drawing-status code; this check only rejects a
     * violated original return contract. Completion additionally requires
     * the live queued path, its native wait and observed display submission. */
    if (s->blit(descriptor))
        c->result = NLR_GRAPHICS_IO;
    else if (s->queue_task() != c->queue_task)
        c->result = NLR_GRAPHICS_NOT_READY;
    else {
        s->fence();
        uint64_t after = 0;
        if (nlr_native_graphics_gui_owner(c) || find_canvas() != widget ||
            s->widget_root(widget) != root || s->current_surface(0, &after) || after != current ||
            s->queue_task() != c->queue_task)
            c->result = NLR_GRAPHICS_OWNER;
        else
            c->draws++;
    }
    s->set_dirty(widget, 0);
    return 1;
}

int nlr_native_graphics_commit_seen(struct nlr_native_graphics *c, int32_t result)
{
    if (!c || !c->rendering)
        return 0;
    if (!nlr_native_graphics_gui_owner(c) && find_canvas() == c->canvas) {
        c->submit_calls++;
        if (result & 1)
            c->submits++;
        else
            c->result = NLR_GRAPHICS_IO;
    }
    return 1;
}

int32_t nlr_native_graphics_render(void *context, uint64_t owner,
                                   const struct nlr_graphics_frame *frame,
                                   uint32_t *started)
{
    struct nlr_native_graphics *c = context;
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (!started)
        return NLR_GRAPHICS_ARGUMENT;
    *started = 0;
    if (!frame || !frame->pixels || ((uintptr_t)frame->pixels & 63u) ||
        frame->width != 320u || frame->height != 200u || frame->stride_bytes != 1280u ||
        frame->format != NLR_GRAPHICS_RGBA8 || !frame->sequence)
        return NLR_GRAPHICS_ARGUMENT;
    int result = nlr_native_graphics_current_window(c, owner);
    if (result)
        return result;
    struct nlr_graphics_snapshot snapshot;
    if (nlr_graphics_snapshot(c->graphics, &snapshot) ||
        snapshot.frame.pixels != frame->pixels || snapshot.frame.sequence != frame->sequence)
        return NLR_GRAPHICS_OWNER;
    if (c->rendering || s->get_draw(c->canvas) != nlr_native_graphics_canvas)
        return NLR_GRAPHICS_OWNER;
    c->queue_task = s->queue_task();
    if (c->queue_task <= 0)
        return NLR_GRAPHICS_NOT_READY;
    result = hide_rows(c);
    if (result)
        return result;
    /* Hidden rows may still paint their old backgrounds. Clear those via
     * the original tree first, then draw the self canvas last through the
     * original locked/context-setting wrapper. No later row paint can erase
     * this frame before the native display submission. */
    s->set_visible(c->canvas, 0);
    s->window_render((void *)s->window);
    if (find_canvas() != c->canvas || nlr_native_graphics_gui_owner(c))
        return NLR_GRAPHICS_CANCELLED;
    c->rendering = 1;
    c->owner = owner;
    c->frame = frame;
    c->started = started;
    c->callback_calls = c->draws = c->submit_calls = c->submits = 0;
    c->result = 0;
    s->set_visible(c->canvas, 1);
    s->set_dirty(c->canvas, 1);
    if (!(s->render_widget(c->canvas, 0, (void *)s->display_abort) & 1))
        c->result = NLR_GRAPHICS_IO;
    if (!c->result && c->callback_calls && c->draws && !s->display_abort()) {
        s->display_refresh(s->display_abort, 3u, 7u);
        if (s->queue_task() == c->queue_task)
            s->fence();
        else
            c->result = NLR_GRAPHICS_NOT_READY;
    }
    result = c->result;
    if (!result && (!c->callback_calls || !c->draws || !c->submit_calls ||
                    c->submits != c->submit_calls))
        result = NLR_GRAPHICS_IO;
    if (!result && (nlr_native_graphics_gui_owner(c) || find_canvas() != c->canvas ||
                    s->queue_task() != c->queue_task))
        result = NLR_GRAPHICS_OWNER;
    c->rendering = 0;
    c->frame = 0;
    c->started = 0;
    return result;
}

int nlr_native_graphics_restore(struct nlr_native_graphics *c, void *window)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (!c || window != s->window || nlr_native_graphics_gui_owner(c))
        return NLR_GRAPHICS_OWNER;
    if (c->rendering)
        return NLR_GRAPHICS_BUSY;
    void *canvas = find_canvas();
    if (!canvas || canvas != c->canvas)
        return NLR_GRAPHICS_CANCELLED;
    if (s->get_draw(canvas) != nlr_native_graphics_canvas || c->saved_draw != s->original_draw)
        return NLR_GRAPHICS_OWNER;
    uint32_t count = 0;
    int result = checked_rows(c, canvas, 1u, &count);
    if (result) return result;
    s->set_visible(canvas, 0);
    s->set_draw(canvas, c->saved_draw);
    if (c->rows_hidden) {
        /* Erase the application raster once, while the original hidden
         * image callback owns this canvas. Later normal page refreshes
         * reinstall our inert callback before rendering the menu rows. */
        s->set_dirty(canvas, 1);
        if (!(s->render_widget(canvas, 0, (void *)s->display_abort) & 1))
            return NLR_GRAPHICS_IO;
        s->fence();
    }
    if (c->rows_hidden)
        for (uint32_t n = 0; n < count; n++) {
            s->row_hide(window, n, ((uint32_t)(c->visible_rows >> n) & 1u) ^ 1u);
        }
    c->rows_hidden = 0;
    c->canvas = 0;
    c->saved_draw = 0;
    c->owner = 0;
    c->built_rows = 0;
    return NLR_GRAPHICS_OK;
}

int nlr_native_graphics_redraw_menu(struct nlr_native_graphics *c, void *window)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (!c || c->rendering || c->rows_hidden)
        return NLR_GRAPHICS_BUSY;
    int result = nlr_native_graphics_install(c, window);
    if (result)
        return result;
    /* The original refresh may consume row dirty bits while restoring the
     * page. Only after its final canvas callback is known do we re-arm the
     * current row groups; never reuse row addresses from the departed app. */
    for (uint32_t n = 0; n < c->built_rows; n++) {
        void *row = s->widget_find(s->row_first + n, (uint8_t *)window + 0x18u);
        if (!row || row == c->canvas || word(row, 0) != s->row_first + n ||
            s->get_visible(row) > 1u)
            return NLR_GRAPHICS_OWNER;
        c->rows[n] = row;
    }
    s->set_dirty(c->canvas, 0);
    for (uint32_t n = 0; n < c->built_rows; n++)
        /* Hidden rows retain old rectangles, which may now overlap a
         * visible row. Preserve the native hide operation's clean child
         * state so their background cannot erase the restored menu. */
        if (s->get_visible(c->rows[n]))
            s->row_dirty(c->rows[n], 1);
    s->window_render(window);
    if (nlr_native_graphics_gui_owner(c) || find_canvas() != c->canvas || s->display_abort())
        return NLR_GRAPHICS_CANCELLED;
    s->display_refresh(s->display_abort, 3u, 7u);
    return NLR_GRAPHICS_OK;
}
