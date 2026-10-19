#include "nlr/runtime.h"
#include "nlr/graphics_runtime.h"
#include "nlr/native_card_internal.h"
#include "nlr/time.h"

#if NLR_HAS_GRAPHICS
extern const struct nlr_services nlr_services;
extern const struct nlr_menu_page nlr_menu_page;

struct nlr_native_graphics *nlr_native_graphics_context(void)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    return r ? &r->native_graphics : 0;
}

uint32_t nlr_native_graphics_row_count(void *window)
{
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    const struct nlr_menu_page *p = &nlr_menu_page;
    if (window != s->window || !p->row_count || p->row_count != s->row_count)
        return 0;
    uint32_t count = p->row_count;
    if (p->page_count) {
        if (!p->stay_next || ((uintptr_t)p->page_count & 1u)) return 0;
        /* The page record moves into the runtime when the loader's own
         * window (keyboard, caution box) takes its window-table entry
         * (menu_page.c own_install); its count is read where it is now,
         * never from the entry the keyboard's window record occupies. */
        const volatile uint16_t *word = (const volatile uint16_t *)p->page_count;
        uintptr_t at = (uintptr_t)p->page_count, base = (uintptr_t)p->page_record;
        struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
        if (r && base && __atomic_load_n(&r->own.ready, __ATOMIC_ACQUIRE) &&
            at >= base && at + 2u <= base + NLR_MENU_PAGE_BYTES)
            word = (const volatile uint16_t *)(r->own.page_record + (at - base));
        count = *word;
    }
    return count && count <= p->row_count ? count : 0;
}

static struct nlr_runtime *owner_runtime(void *context)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    return r && &r->native_graphics == context ? r : 0;
}

static int32_t worker_owner(void *context, uint64_t owner)
{
    struct nlr_runtime *r = owner_runtime(context);
    uint32_t task = 0;
    const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
    if (!r || !owner || owner != r->graphics_owner || !s->current_task ||
        s->current_task(&task) || task != nlr_le32(r->load.worker.opaque) ||
        r->load.program_kind != NLR_KIND_FOREGROUND ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 2 ||
        !__atomic_load_n(&r->load.program.jump_armed, __ATOMIC_ACQUIRE))
        return NLR_GRAPHICS_OWNER;
    return 0;
}

static int32_t allocate_source(void *context, uint32_t bytes, void **out)
{
    (void)context;
    *out = nlr_alloc_whole(&nlr_services, bytes);
    return *out ? NLR_OK : NLR_NOT_READY;
}
static int32_t release_source(void *context, void *allocation)
{ (void)context; return nlr_services.release(allocation); }
static int32_t clean_source(void *context, void *pixels, uint32_t bytes)
{
    (void)context;
    if (!pixels || ((uintptr_t)pixels & 63u) || bytes != NLR_GRAPHICS_BYTES ||
        !nlr_services.cache_after_read)
        return NLR_GRAPHICS_ARGUMENT;
    nlr_services.cache_after_read(pixels, bytes);
    return 0;
}
static int32_t raw_clock(void *context, uint64_t *out)
{ (void)context; return nlr_time_clock(nlr_services.time, out); }
static int32_t raw_sleep(void *context, uint32_t ms)
{ (void)context; return nlr_time_sleep(nlr_services.time, ms, 0, 0); }

static int32_t wake_gui(void *context)
{
    struct nlr_runtime *r = owner_runtime(context);
    const struct nlr_native_card_services *s = r ? r->load.svc->native_card : 0;
    if (!s || !s->menu.callee || !s->menu.wake_mask || !r->load.svc->flag_set)
        return NLR_GRAPHICS_NOT_READY;
    void *reference = s->menu.callee();
    if (!nlr_native_card_ram_span(s, (uintptr_t)reference, sizeof(uint64_t)))
        return NLR_GRAPHICS_NOT_READY;
    uintptr_t flag = (uintptr_t)nlr_native_card_u64(reference);
    if (!nlr_native_card_ram_span(s, flag, NLR_WORKER_SIZE))
        return NLR_GRAPHICS_NOT_READY;
    return r->load.svc->flag_set((void *)flag, s->menu.wake_mask);
}

void nlr_graphics_runtime_init(struct nlr_runtime *r)
{
    r->native_graphics.graphics = &r->graphics;
    struct nlr_graphics_services *s = &r->graphics_services;
    s->context = &r->native_graphics;
    s->worker_owner = worker_owner;
    s->gui_owner = nlr_native_graphics_gui_owner;
    s->current_window = nlr_native_graphics_current_window;
    s->allocate = allocate_source;
    s->release = release_source;
    s->clean_source = clean_source;
    s->wake_gui = wake_gui;
    s->clock_ms = raw_clock;
    s->sleep_ms = raw_sleep;
    s->render = nlr_native_graphics_render;
    s->timeout_ms = 1000u;
}

void *nlr_graphics_page_install(void *window)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (r) {
        int result = nlr_native_graphics_install(&r->native_graphics, window);
        __atomic_store_n(&r->graphics_canvas_ready, result == 0, __ATOMIC_RELEASE);
        if (result) nlr_trace_record(&r->load, 'G', result);
    }
    return window;
}

void *nlr_graphics_page_leave(void *window)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (r) {
        __atomic_store_n(&r->graphics_canvas_ready, 0u, __ATOMIC_RELEASE);
        nlr_graphics_gui_cancel(&r->graphics);
        if (r->native_graphics.canvas) {
            int result = nlr_native_graphics_restore(&r->native_graphics, window);
            if (result) nlr_trace_record(&r->load, 'G', result);
        }
    }
    return window;
}

void nlr_graphics_runtime_list_published(struct nlr_runtime *r)
{
    if (r && r->graphics_services.wake_gui)
        (void)r->graphics_services.wake_gui(r->graphics_services.context);
}

void nlr_graphics_runtime_checkpoint(struct nlr_runtime *r)
{
    if (!r || nlr_native_graphics_gui_owner(&r->native_graphics))
        return;
    /* A program's list that came after the page stopped following the
     * program's start: shown now, on the page's own window only. */
    {
        const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
        if (s->current_window && s->current_window() == s->window) {
            int shown = nlr_page_show_late_list(r, (const void *)s->window);
            if (shown != NLR_NOT_READY)
                nlr_journal(r->load.journal, "page took the program's list: %d", shown);
        }
    }
    /* The menu was redrawn for a program that had given the screen back
     * but not yet ended (below), so its row had no outcome. The worker
     * wakes this task once the end is published (load.c complete_attempt);
     * the page is then rebuilt once, if it is still the one shown. */
    if (r->outcome_redraw &&
        __atomic_load_n(&r->graphics_restore_pending, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0) {
        const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
        r->outcome_redraw = 0;
        if (s->current_window() == s->window && !r->detail_view && !r->recovery_view) {
            int result = nlr_page_rebuild_outcome(r, (const void *)s->window);
            nlr_journal(r->load.journal, "page rebuilt for the outcome: %d", result);
            if (result) nlr_trace_record(&r->load, 'G', result);
        }
    }
    if (__atomic_load_n(&r->graphics_restore_pending, __ATOMIC_ACQUIRE) == 1u) {
        struct nlr_graphics_snapshot snapshot;
        if (nlr_graphics_snapshot(&r->graphics, &snapshot) || snapshot.gui_active || snapshot.waiter_active)
            return;
        int result = snapshot.phase == NLR_GRAPHICS_UNCERTAIN_FRAME ? NLR_GRAPHICS_UNCERTAIN : 0;
        const struct nlr_native_graphics_services *s = &nlr_native_graphics_services;
        if (!result && r->native_graphics.canvas)
            result = nlr_native_graphics_restore(&r->native_graphics, (void *)s->window);
        if (!result && s->current_window() == s->window) {
            uint32_t detail = r->detail_view, recovery = r->recovery_view;
            r->detail_view = r->recovery_view = 0;
            r->show_check = 1;
            nlr_page_prepare_redraw(r);
            if (nlr_menu_page.page_refresh)
                nlr_menu_page.page_refresh((void *)s->window);
            result = nlr_native_graphics_redraw_menu(&r->native_graphics, (void *)s->window);
            if (result) {
                /* Preserve the existing failure detail when original
                 * reconstruction/redraw did not establish a restored menu. */
                r->detail_view = detail;
                r->recovery_view = recovery;
                r->show_check = 1;
            }
            __atomic_store_n(&r->graphics_canvas_ready, result == 0, __ATOMIC_RELEASE);
            /* The worker publishes the end only after this restore: the
             * page just drawn cannot show the outcome yet. */
            if (!result)
                r->outcome_redraw = 1;
        }
        r->graphics_restore_result = result;
        __atomic_store_n(&r->graphics_restore_pending, result ? 3u : 2u, __ATOMIC_RELEASE);
        return;
    }
    nlr_graphics_gui_consume(&r->graphics);
}

int nlr_graphics_runtime_cleanup(struct nlr_runtime *r)
{
    struct nlr_graphics_snapshot snapshot;
    if (!r || nlr_graphics_snapshot(&r->graphics, &snapshot))
        return NLR_EXEC_RESTORE;
    if (!snapshot.allocation)
        return NLR_OK;
    if (snapshot.phase == NLR_GRAPHICS_UNCERTAIN_FRAME || snapshot.gui_active || snapshot.waiter_active)
        return NLR_EXEC_RESTORE;
    uint64_t start = 0;
    if (raw_clock(0, &start))
        return NLR_EXEC_RESTORE;
    __atomic_store_n(&r->graphics_restore_pending, 1u, __ATOMIC_RELEASE);
    if (wake_gui(&r->native_graphics))
        return NLR_EXEC_RESTORE;
    for (uint32_t n = 0; n < 1000u; n++) {
        uint32_t result = __atomic_load_n(&r->graphics_restore_pending, __ATOMIC_ACQUIRE);
        if (result == 2u) {
            __atomic_store_n(&r->graphics_restore_pending, 0u, __ATOMIC_RELEASE);
            return nlr_graphics_cleanup(&r->graphics, r->graphics_owner) == 0 ? NLR_OK : NLR_EXEC_RESTORE;
        }
        if (result == 3u)
            return NLR_EXEC_RESTORE;
        uint64_t now = 0;
        if (raw_clock(0, &now) || now < start || now - start >= 1000u || raw_sleep(0, 1u))
            return NLR_EXEC_RESTORE;
    }
    return NLR_EXEC_RESTORE;
}
#endif
