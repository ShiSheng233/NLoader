#include "nlr/graphics.h"

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum delivery { DELIVER_NONE, DELIVER_WAKE, DELIVER_SLEEP, DELIVER_CANCEL, DELIVER_THREAD };

struct fixture {
    struct nlr_graphics state;
    struct nlr_graphics_services services;
    uint64_t owner, now;
    uint32_t offset, allocations, releases, clean_calls, wake_calls, sleep_calls, render_calls;
    uint32_t worker_allowed, gui_allowed, started, freeze_clock, backwards_clock;
    uint32_t clock_calls, clock_fail_at, stop_lock, began_thread;
    int32_t allocation_result, release_result, clean_result, wake_result;
    int32_t sleep_result, window_result, render_result;
    uint32_t allocation_returns_owner_on_error;
    enum delivery delivery;
    void *backing, *allocation;
    uint32_t allocation_bytes;
    uint8_t expected_pixel;
    uint32_t render_entered, release_render;
    pthread_t gui_thread;
    int gui_result;
};

static int32_t worker_owner(void *context, uint64_t owner)
{
    struct fixture *f = context;
    return f->worker_allowed && owner == f->owner ? 0 : -1;
}

static int32_t gui_owner(void *context)
{
    return ((struct fixture *)context)->gui_allowed ? 0 : -1;
}

static int32_t current_window(void *context, uint64_t owner)
{
    struct fixture *f = context;
    assert(owner == f->owner);
    return f->window_result;
}

static int32_t allocate(void *context, uint32_t bytes, void **out)
{
    struct fixture *f = context;
    assert(!f->allocation);
    assert(bytes == NLR_GRAPHICS_BYTES + 63u);
    f->allocations++;
    *out = 0;
    if (!f->allocation_result || f->allocation_returns_owner_on_error) {
        f->backing = malloc(bytes + 127u);
        assert(f->backing);
        uintptr_t base = ((uintptr_t)f->backing + 63u) & ~(uintptr_t)63u;
        f->allocation = (void *)(base + f->offset);
        f->allocation_bytes = bytes;
        memset(f->allocation, 0xa5, bytes);
        *out = f->allocation;
    }
    return f->allocation_result;
}

static int32_t release(void *context, void *allocation)
{
    struct fixture *f = context;
    assert(allocation && allocation == f->allocation);
    f->releases++;
    if (f->release_result)
        return f->release_result;
    free(f->backing);
    f->backing = f->allocation = 0;
    return 0;
}

static int32_t clean_source(void *context, void *pixels, uint32_t bytes)
{
    struct fixture *f = context;
    assert(bytes == NLR_GRAPHICS_BYTES && !(bytes & 63u));
    assert(!((uintptr_t)pixels & 63u));
    assert((uintptr_t)pixels >= (uintptr_t)f->allocation);
    assert((uintptr_t)pixels + bytes <= (uintptr_t)f->allocation + f->allocation_bytes);
    f->clean_calls++;
    return f->clean_result;
}

static int32_t render(void *context, uint64_t owner,
                       const struct nlr_graphics_frame *frame, uint32_t *started)
{
    struct fixture *f = context;
    assert(owner == f->owner);
    assert(frame->width == 320 && frame->height == 200 && frame->stride_bytes == 1280);
    assert(frame->format == NLR_GRAPHICS_RGBA8 && frame->sequence);
    assert(frame->pixels == f->state.frame.pixels);
    assert(f->clean_calls > f->render_calls);
    f->render_calls++;
    *started = f->started;
    struct nlr_graphics_frame denied;
    memset(&denied, 0x5a, sizeof denied);
    assert(nlr_graphics_begin(&f->state, &f->services, owner, &denied) == NLR_GRAPHICS_BUSY);
    assert(nlr_graphics_cleanup(&f->state, owner) == NLR_GRAPHICS_BUSY);
    assert(nlr_graphics_gui_cancel(&f->state) == NLR_GRAPHICS_BUSY);
    assert(nlr_graphics_gui_consume(&f->state) == NLR_GRAPHICS_BUSY);
    if (f->delivery == DELIVER_THREAD) {
        __atomic_store_n(&f->render_entered, 1u, __ATOMIC_RELEASE);
        while (!__atomic_load_n(&f->release_render, __ATOMIC_ACQUIRE))
            sched_yield(); /* Harness-controlled outstanding native operation. */
    }
    const uint8_t *pixels = frame->pixels;
    for (uint32_t n = 0; n < NLR_GRAPHICS_BYTES; n++)
        assert(pixels[n] == f->expected_pixel);
    return f->render_result;
}

static void *gui_thread(void *context)
{
    struct fixture *f = context;
    f->gui_result = nlr_graphics_gui_consume(&f->state);
    return 0;
}

static int32_t wake_gui(void *context)
{
    struct fixture *f = context;
    f->wake_calls++;
    struct nlr_graphics_frame denied;
    assert(nlr_graphics_begin(&f->state, &f->services, f->owner, &denied) == NLR_GRAPHICS_BUSY);
    assert(nlr_graphics_cleanup(&f->state, f->owner) == NLR_GRAPHICS_BUSY);
    if (f->stop_lock)
        __atomic_store_n(&f->state.lock, 1u, __ATOMIC_RELEASE);
    if (f->delivery == DELIVER_WAKE)
        f->gui_result = nlr_graphics_gui_consume(&f->state);
    else if (f->delivery == DELIVER_CANCEL) {
        assert(nlr_graphics_gui_cancel(&f->state) == NLR_GRAPHICS_OK);
        assert(nlr_graphics_gui_consume(&f->state) == NLR_GRAPHICS_BUSY);
    }
    return f->wake_result;
}

static int32_t clock_ms(void *context, uint64_t *out)
{
    struct fixture *f = context;
    f->clock_calls++;
    *out = f->backwards_clock && f->clock_calls > 1 ? f->now - 1u : f->now;
    return f->clock_calls == f->clock_fail_at ? -41 : 0;
}

static int32_t sleep_ms(void *context, uint32_t milliseconds)
{
    struct fixture *f = context;
    assert(milliseconds == 1);
    f->sleep_calls++;
    if (!f->freeze_clock)
        f->now += milliseconds;
    if (f->delivery == DELIVER_SLEEP)
        f->gui_result = nlr_graphics_gui_consume(&f->state);
    if (f->delivery == DELIVER_THREAD && !f->began_thread) {
        f->began_thread = 1;
        assert(pthread_create(&f->gui_thread, 0, gui_thread, f) == 0);
        while (!__atomic_load_n(&f->render_entered, __ATOMIC_ACQUIRE))
            sched_yield();
    }
    return f->sleep_result;
}

static void init(struct fixture *f)
{
    memset(f, 0, sizeof *f);
    f->owner = 19;
    f->now = 100;
    f->offset = 8;
    f->worker_allowed = f->gui_allowed = f->started = 1;
    f->delivery = DELIVER_WAKE;
    f->expected_pixel = 0x3e;
    f->services = (struct nlr_graphics_services){
        .context = f,
        .worker_owner = worker_owner,
        .gui_owner = gui_owner,
        .current_window = current_window,
        .allocate = allocate,
        .release = release,
        .clean_source = clean_source,
        .wake_gui = wake_gui,
        .clock_ms = clock_ms,
        .sleep_ms = sleep_ms,
        .render = render,
        .timeout_ms = 4,
    };
}

static void write_frame(struct fixture *f)
{
    struct nlr_graphics_frame frame;
    assert(nlr_graphics_begin(&f->state, &f->services, f->owner, &frame) == 0);
    assert(frame.pixels && frame.width == 320 && frame.height == 200);
    assert(!((uintptr_t)frame.pixels & 63u));
    memset(frame.pixels, f->expected_pixel, NLR_GRAPHICS_BYTES);
}

static void dispose_test_storage(struct fixture *f)
{
    /* Only the host test owns this allocation after its fake native users
     * have joined. Production code must retain the uncertain allocation. */
    assert(!f->began_thread || __atomic_load_n(&f->release_render, __ATOMIC_ACQUIRE));
    free(f->backing);
    f->backing = f->allocation = 0;
}

static void alignment_and_repeat(void)
{
    for (uint32_t offset = 0; offset < 64; offset++) {
        struct fixture f;
        init(&f);
        f.offset = offset;
        struct nlr_graphics_frame frame;
        assert(nlr_graphics_begin(&f.state, &f.services, f.owner, &frame) == 0);
        for (uint32_t n = 0; n < NLR_GRAPHICS_BYTES; n++)
            assert(((uint8_t *)frame.pixels)[n] == 0);
        assert(nlr_graphics_cleanup(&f.state, f.owner + 1u) == NLR_GRAPHICS_OWNER);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == 0);
        assert(f.releases == 1);
    }
    for (enum delivery d = DELIVER_WAKE; d <= DELIVER_SLEEP; d++) {
        struct fixture f;
        init(&f);
        f.delivery = d;
        for (uint32_t n = 1; n <= 3; n++) {
            write_frame(&f);
            struct nlr_graphics_frame denied;
            assert(nlr_graphics_begin(&f.state, &f.services, f.owner, &denied) == NLR_GRAPHICS_BUSY);
            assert(nlr_graphics_end(&f.state, f.owner + 1) == NLR_GRAPHICS_OWNER);
            assert(nlr_graphics_end(&f.state, f.owner) == 0);
            assert(f.render_calls == n && f.state.completed_sequence == n);
            assert(f.state.phase == NLR_GRAPHICS_IDLE && !f.state.waiter_active);
            assert(nlr_graphics_end(&f.state, f.owner) == NLR_GRAPHICS_BUSY);
            f.expected_pixel++;
        }
        assert(f.allocations == 1 && !f.releases);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == 0 && f.releases == 1);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == 0 && f.releases == 1);
        f.owner++;
        write_frame(&f);
        assert(nlr_graphics_end(&f.state, f.owner) == 0);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == 0 && f.releases == 2);
    }
}

static void refusals_and_safe_cancellation(void)
{
    struct fixture f;
    struct nlr_graphics_frame frame;
    init(&f);
    f.services.render = 0;
    assert(nlr_graphics_begin(&f.state, &f.services, f.owner, &frame) == NLR_GRAPHICS_NOT_READY);
    assert(!f.allocations);
    init(&f);
    f.worker_allowed = 0;
    assert(nlr_graphics_begin(&f.state, &f.services, f.owner, &frame) == NLR_GRAPHICS_OWNER);
    assert(!f.allocations);
    init(&f);
    assert(nlr_graphics_begin(&f.state, &f.services, 0, &frame) == NLR_GRAPHICS_ARGUMENT);
    f.allocation_result = -20;
    assert(nlr_graphics_begin(&f.state, &f.services, f.owner, &frame) == NLR_GRAPHICS_IO);
    assert(!f.state.owner && !f.state.allocation);
    f.allocation_result = 0;
    write_frame(&f);
    f.clean_result = -22;
    assert(nlr_graphics_end(&f.state, f.owner) == NLR_GRAPHICS_IO);
    assert(!f.wake_calls && !f.render_calls);
    assert(nlr_graphics_cleanup(&f.state, f.owner) == 0);

    for (uint32_t mode = 0; mode < 5; mode++) {
        init(&f);
        if (mode == 0)
            f.window_result = NLR_GRAPHICS_CANCELLED;
        else if (mode == 1)
            f.delivery = DELIVER_CANCEL;
        else if (mode == 2) {
            f.delivery = DELIVER_NONE;
            f.wake_result = -21;
        } else if (mode == 3)
            f.started = 0;
        else
            f.window_result = -25;
        write_frame(&f);
        int result = nlr_graphics_end(&f.state, f.owner);
        assert(result == (mode < 2 ? NLR_GRAPHICS_CANCELLED : NLR_GRAPHICS_IO));
        assert(!f.state.uncertain && !f.state.gui_active && !f.state.waiter_active);
        assert(f.render_calls == (mode == 3 ? 1u : 0u));
        assert(!f.state.completed_sequence);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == 0 && f.releases == 1);
    }
    init(&f);
    write_frame(&f);
    f.clock_fail_at = 1;
    assert(nlr_graphics_end(&f.state, f.owner) == NLR_GRAPHICS_IO);
    assert(!f.wake_calls);
    assert(nlr_graphics_cleanup(&f.state, f.owner) == 0);
}

static void uncertain_sources_are_retained(void)
{
    for (uint32_t mode = 0; mode < 9; mode++) {
        struct fixture f;
        init(&f);
        if (mode == 0)
            f.render_result = -30;
        else if (mode == 1)
            f.render_result = NLR_GRAPHICS_CANCELLED;
        else {
            f.delivery = DELIVER_NONE;
            if (mode == 3)
                f.sleep_result = -31;
            else if (mode == 4)
                f.clock_fail_at = 2;
            else if (mode == 5)
                f.backwards_clock = 1;
            else if (mode == 6)
                f.freeze_clock = 1;
            else if (mode == 7) {
                f.delivery = DELIVER_WAKE;
                f.gui_allowed = 0;
            } else if (mode == 8)
                f.stop_lock = 1;
        }
        write_frame(&f);
        assert(nlr_graphics_end(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
        if (f.stop_lock)
            __atomic_store_n(&f.state.lock, 0u, __ATOMIC_RELEASE);
        struct nlr_graphics_snapshot snapshot;
        assert(nlr_graphics_snapshot(&f.state, &snapshot) == 0);
        assert(snapshot.phase == NLR_GRAPHICS_UNCERTAIN_FRAME);
        assert(snapshot.result == NLR_GRAPHICS_UNCERTAIN);
        assert(snapshot.owner == f.owner && snapshot.allocation == f.allocation);
        assert(snapshot.completed_sequence == 0);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
        assert(!f.releases);
        struct nlr_graphics_frame frame;
        assert(nlr_graphics_begin(&f.state, &f.services, f.owner, &frame) == NLR_GRAPHICS_UNCERTAIN);
        assert(nlr_graphics_gui_consume(&f.state) != 0);
        dispose_test_storage(&f);
    }
}

static void late_native_return_cannot_clear_timeout(void)
{
    struct fixture f;
    init(&f);
    f.delivery = DELIVER_THREAD;
    write_frame(&f);
    assert(nlr_graphics_end(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
    assert(f.state.gui_active && f.state.allocation == f.allocation);
    assert(nlr_graphics_cleanup(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
    assert(!f.releases);
    __atomic_store_n(&f.release_render, 1u, __ATOMIC_RELEASE);
    assert(pthread_join(f.gui_thread, 0) == 0);
    assert(f.gui_result == NLR_GRAPHICS_UNCERTAIN);
    assert(!f.state.gui_active && !f.state.completed_sequence);
    assert(f.state.backend_result == NLR_GRAPHICS_UNCERTAIN);
    assert(nlr_graphics_cleanup(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
    assert(!f.releases);
    dispose_test_storage(&f);
}

static void release_failure_retains_original_owner(void)
{
    for (uint32_t allocation_failure = 0; allocation_failure < 2; allocation_failure++) {
        struct fixture f;
        init(&f);
        f.release_result = -50;
        if (allocation_failure) {
            f.allocation_result = -51;
            f.allocation_returns_owner_on_error = 1;
            struct nlr_graphics_frame frame;
            assert(nlr_graphics_begin(&f.state, &f.services, f.owner, &frame) == NLR_GRAPHICS_UNCERTAIN);
        } else {
            write_frame(&f);
            assert(nlr_graphics_end(&f.state, f.owner) == 0);
            assert(nlr_graphics_cleanup(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
        }
        assert(f.releases == 1 && f.state.allocation == f.allocation);
        assert(f.state.allocation_bytes == NLR_GRAPHICS_BYTES + 63u);
        assert(nlr_graphics_cleanup(&f.state, f.owner) == NLR_GRAPHICS_UNCERTAIN);
        assert(f.releases == 1);
        dispose_test_storage(&f);
    }
}

int main(void)
{
    alignment_and_repeat();
    refusals_and_safe_cancellation();
    uncertain_sources_are_retained();
    late_native_return_cannot_clear_timeout();
    release_failure_retains_original_owner();
    puts("graphics frame ownership and completion checks passed");
    return 0;
}
