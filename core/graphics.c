#include "nlr/graphics.h"

static int lock_state(struct nlr_graphics *state)
{
    uint32_t empty = 0;
    return __atomic_compare_exchange_n(&state->lock, &empty, 1u, 0,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static void unlock_state(struct nlr_graphics *state)
{
    __atomic_store_n(&state->lock, 0u, __ATOMIC_RELEASE);
}

static int services_ready(const struct nlr_graphics_services *s)
{
    return s && s->worker_owner && s->gui_owner && s->current_window &&
        s->allocate && s->release && s->clean_source && s->wake_gui &&
        s->clock_ms && s->sleep_ms && s->render && s->timeout_ms;
}

static int uncertain(const struct nlr_graphics *state)
{
    return __atomic_load_n(&state->uncertain, __ATOMIC_ACQUIRE) != 0;
}

/* Caller holds the lock. This state is terminal for the current boot:
 * a later native return cannot turn uncertain source use into permission to
 * free it. A separate independently established recovery would be needed. */
static int retain_uncertain(struct nlr_graphics *state, int32_t backend)
{
    int already_uncertain = uncertain(state);
    __atomic_store_n(&state->uncertain, 1u, __ATOMIC_RELEASE);
    state->phase = NLR_GRAPHICS_UNCERTAIN_FRAME;
    state->result = NLR_GRAPHICS_UNCERTAIN;
    if (!already_uncertain)
        state->backend_result = backend;
    return NLR_GRAPHICS_UNCERTAIN;
}

static void clear_owned(struct nlr_graphics *state)
{
    state->phase = NLR_GRAPHICS_EMPTY;
    state->owner = 0;
    state->sequence = 0;
    state->completed_sequence = 0;
    state->allocation = 0;
    state->allocation_bytes = 0;
    state->frame.pixels = 0;
    state->frame.width = state->frame.height = state->frame.stride_bytes = 0;
    state->frame.format = 0;
    state->frame.sequence = 0;
    state->services = 0;
    state->render_started = 0;
    state->result = state->backend_result = 0;
}

static int allocate_source(struct nlr_graphics *state)
{
    const struct nlr_graphics_services *s = state->services;
    uint32_t bytes = NLR_GRAPHICS_BYTES + NLR_GRAPHICS_CACHE_LINE - 1u;
    int32_t result = s->allocate(s->context, bytes, &state->allocation);
    if (state->allocation)
        state->allocation_bytes = bytes;
    uintptr_t base = (uintptr_t)state->allocation;
    if (result || !base || base > UINTPTR_MAX - bytes) {
        if (state->allocation) {
            int32_t released = s->release(s->context, state->allocation);
            if (released)
                return retain_uncertain(state, released);
        }
        clear_owned(state);
        return NLR_GRAPHICS_IO;
    }
    uintptr_t aligned = (base + NLR_GRAPHICS_CACHE_LINE - 1u) &
        ~(uintptr_t)(NLR_GRAPHICS_CACHE_LINE - 1u);
    state->frame.pixels = (void *)aligned;
    state->frame.width = NLR_GRAPHICS_WIDTH;
    state->frame.height = NLR_GRAPHICS_HEIGHT;
    state->frame.stride_bytes = NLR_GRAPHICS_STRIDE;
    state->frame.format = NLR_GRAPHICS_RGBA8;
    uint8_t *pixels = state->frame.pixels;
    for (uint32_t n = 0; n < NLR_GRAPHICS_BYTES; n++)
        pixels[n] = 0;
    return NLR_GRAPHICS_OK;
}

int nlr_graphics_begin(struct nlr_graphics *state,
                        const struct nlr_graphics_services *services,
                        uint64_t owner, struct nlr_graphics_frame *out)
{
    if (!state || !out || !owner)
        return NLR_GRAPHICS_ARGUMENT;
    if (!services_ready(services))
        return NLR_GRAPHICS_NOT_READY;
    if (services->worker_owner(services->context, owner))
        return NLR_GRAPHICS_OWNER;
    if (!lock_state(state))
        return NLR_GRAPHICS_BUSY;
    int result = NLR_GRAPHICS_OK;
    if (uncertain(state))
        result = NLR_GRAPHICS_UNCERTAIN;
    else if (state->owner &&
             (state->owner != owner || state->services != services))
        result = NLR_GRAPHICS_OWNER;
    else if (state->waiter_active || state->gui_active ||
             (state->phase != NLR_GRAPHICS_EMPTY && state->phase != NLR_GRAPHICS_IDLE))
        result = NLR_GRAPHICS_BUSY;
    else {
        if (!state->allocation) {
            state->owner = owner;
            state->services = services;
            result = allocate_source(state);
        }
        if (!result) {
            state->phase = NLR_GRAPHICS_WRITING;
            state->result = state->backend_result = 0;
            state->render_started = 0;
            *out = state->frame;
        }
    }
    unlock_state(state);
    return result;
}

/* Poll and acknowledge under one lock, so cleanup cannot race the worker's
 * final access to the source or GUI bookkeeping. */
static int poll_end(struct nlr_graphics *state, int *done)
{
    *done = 0;
    if (!lock_state(state))
        return NLR_GRAPHICS_BUSY;
    int result = NLR_GRAPHICS_BUSY;
    if (uncertain(state)) {
        state->phase = NLR_GRAPHICS_UNCERTAIN_FRAME;
        state->waiter_active = 0;
        result = NLR_GRAPHICS_UNCERTAIN;
        *done = 1;
    } else if (state->phase == NLR_GRAPHICS_COMPLETE ||
               state->phase == NLR_GRAPHICS_CANCELLED_FRAME) {
        result = state->result;
        state->phase = NLR_GRAPHICS_IDLE;
        state->waiter_active = 0;
        *done = 1;
    }
    unlock_state(state);
    return result;
}

static int fail_wait(struct nlr_graphics *state, int32_t backend)
{
    /* Even a stalled lock cannot let later cleanup free a source after the
     * worker stopped observing it. The sticky flag is checked under every
     * subsequent ownership transition. */
    if (!lock_state(state)) {
        __atomic_store_n(&state->uncertain, 1u, __ATOMIC_RELEASE);
        return NLR_GRAPHICS_UNCERTAIN;
    }
    int result;
    if (!uncertain(state) && (state->phase == NLR_GRAPHICS_COMPLETE ||
                             state->phase == NLR_GRAPHICS_CANCELLED_FRAME)) {
        result = state->result;
        state->phase = NLR_GRAPHICS_IDLE;
    } else {
        result = retain_uncertain(state, backend);
    }
    state->waiter_active = 0;
    unlock_state(state);
    return result;
}

int nlr_graphics_end(struct nlr_graphics *state, uint64_t owner)
{
    if (!state || !owner)
        return NLR_GRAPHICS_ARGUMENT;
    if (!lock_state(state))
        return NLR_GRAPHICS_BUSY;
    const struct nlr_graphics_services *s = state->services;
    int result = NLR_GRAPHICS_OK;
    uint64_t start = 0;
    if (state->owner != owner || !services_ready(s) ||
        s->worker_owner(s->context, owner))
        result = NLR_GRAPHICS_OWNER;
    else if (uncertain(state))
        result = NLR_GRAPHICS_UNCERTAIN;
    else if (state->phase != NLR_GRAPHICS_WRITING || state->waiter_active || state->gui_active)
        result = NLR_GRAPHICS_BUSY;
    else if (state->sequence == UINT64_MAX)
        result = NLR_GRAPHICS_NOT_READY;
    else if (s->clock_ms(s->context, &start) ||
             s->clean_source(s->context, state->frame.pixels, NLR_GRAPHICS_BYTES))
        result = NLR_GRAPHICS_IO;
    if (result) {
        unlock_state(state);
        return result;
    }
    state->frame.sequence = ++state->sequence;
    state->phase = NLR_GRAPHICS_QUEUED;
    state->waiter_active = 1;
    state->render_started = 0;
    state->result = NLR_GRAPHICS_BUSY;
    unlock_state(state);

    int32_t wake_result = s->wake_gui(s->context);
    if (wake_result) {
        /* Cancelling under the same transition lock proves no consumer can
         * acquire this failed notification afterwards. A consumer already
         * using the source instead needs the normal bounded drain below. */
        if (lock_state(state)) {
            if (!uncertain(state) && state->phase == NLR_GRAPHICS_QUEUED) {
                state->phase = NLR_GRAPHICS_CANCELLED_FRAME;
                state->result = NLR_GRAPHICS_IO;
                state->backend_result = wake_result;
            }
            unlock_state(state);
        }
    }
    uint32_t sleeps = 0;
    for (;;) {
        int done;
        result = poll_end(state, &done);
        if (done)
            return result;
        uint64_t now = 0;
        int32_t clock_result = s->clock_ms(s->context, &now);
        /* A frozen clock must not turn this bounded service into an
         * infinite wait. Each successful raw sleep promises at least 1 ms;
         * exhausting that observation budget is also uncertain. */
        if (clock_result || now < start || now - start >= s->timeout_ms ||
            sleeps >= s->timeout_ms)
            return fail_wait(state, clock_result ? clock_result : NLR_GRAPHICS_UNCERTAIN);
        int32_t sleep_result = s->sleep_ms(s->context, 1u);
        if (sleep_result)
            return fail_wait(state, sleep_result);
        sleeps++;
    }
}

static int gui_ready_locked(struct nlr_graphics *state)
{
    if (!services_ready(state->services))
        return NLR_GRAPHICS_NOT_READY;
    if (state->services->gui_owner(state->services->context))
        return NLR_GRAPHICS_OWNER;
    if (uncertain(state))
        return NLR_GRAPHICS_UNCERTAIN;
    if (state->phase != NLR_GRAPHICS_QUEUED || state->gui_active || !state->waiter_active)
        return NLR_GRAPHICS_BUSY;
    return NLR_GRAPHICS_OK;
}

int nlr_graphics_gui_cancel(struct nlr_graphics *state)
{
    if (!state)
        return NLR_GRAPHICS_ARGUMENT;
    if (!lock_state(state))
        return NLR_GRAPHICS_BUSY;
    int result = gui_ready_locked(state);
    if (!result) {
        state->phase = NLR_GRAPHICS_CANCELLED_FRAME;
        state->result = NLR_GRAPHICS_CANCELLED;
    }
    unlock_state(state);
    return result;
}

int nlr_graphics_gui_consume(struct nlr_graphics *state)
{
    if (!state)
        return NLR_GRAPHICS_ARGUMENT;
    if (!lock_state(state))
        return NLR_GRAPHICS_BUSY;
    int result = gui_ready_locked(state);
    if (result) {
        unlock_state(state);
        return result;
    }
    const struct nlr_graphics_services *s = state->services;
    uint64_t owner = state->owner;
    struct nlr_graphics_frame frame = state->frame;
    state->phase = NLR_GRAPHICS_DRAWING;
    state->gui_active = 1;
    unlock_state(state);

    uint32_t started = 0;
    result = s->current_window(s->context, owner);
    if (!result)
        result = s->render(s->context, owner, &frame, &started);
    int32_t backend = result;
    if (result || !started)
        result = started ? NLR_GRAPHICS_UNCERTAIN :
            (result == NLR_GRAPHICS_CANCELLED ? result : NLR_GRAPHICS_IO);
    if (!lock_state(state)) {
        __atomic_store_n(&state->uncertain, 1u, __ATOMIC_RELEASE);
        return NLR_GRAPHICS_UNCERTAIN;
    }
    state->gui_active = 0;
    state->render_started = started != 0;
    if (!uncertain(state))
        state->backend_result = backend;
    if (uncertain(state) || result == NLR_GRAPHICS_UNCERTAIN) {
        result = retain_uncertain(state, backend);
    } else {
        state->result = result;
        state->phase = result ? NLR_GRAPHICS_CANCELLED_FRAME : NLR_GRAPHICS_COMPLETE;
        if (!result)
            state->completed_sequence = frame.sequence;
    }
    unlock_state(state);
    return result;
}

int nlr_graphics_cleanup(struct nlr_graphics *state, uint64_t owner)
{
    if (!state || !owner)
        return NLR_GRAPHICS_ARGUMENT;
    if (!lock_state(state))
        return NLR_GRAPHICS_BUSY;
    int result = NLR_GRAPHICS_OK;
    if (state->owner && state->owner != owner)
        result = NLR_GRAPHICS_OWNER;
    else if (uncertain(state))
        result = NLR_GRAPHICS_UNCERTAIN;
    else if (state->waiter_active || state->gui_active ||
             (state->phase != NLR_GRAPHICS_EMPTY && state->phase != NLR_GRAPHICS_IDLE &&
              state->phase != NLR_GRAPHICS_WRITING && state->phase != NLR_GRAPHICS_COMPLETE &&
              state->phase != NLR_GRAPHICS_CANCELLED_FRAME))
        result = NLR_GRAPHICS_BUSY;
    else if (state->allocation) {
        const struct nlr_graphics_services *s = state->services;
        if (!s || !s->release)
            result = retain_uncertain(state, NLR_GRAPHICS_NOT_READY);
        else {
            int32_t released = s->release(s->context, state->allocation);
            if (released)
                result = retain_uncertain(state, released);
            else
                clear_owned(state);
        }
    }
    unlock_state(state);
    return result;
}

int nlr_graphics_snapshot(struct nlr_graphics *state,
                           struct nlr_graphics_snapshot *out)
{
    if (!state || !out)
        return NLR_GRAPHICS_ARGUMENT;
    if (!lock_state(state))
        return NLR_GRAPHICS_BUSY;
    out->phase = uncertain(state) ? NLR_GRAPHICS_UNCERTAIN_FRAME : state->phase;
    out->waiter_active = state->waiter_active;
    out->gui_active = state->gui_active;
    out->render_started = state->render_started;
    out->result = uncertain(state) ? NLR_GRAPHICS_UNCERTAIN : state->result;
    out->backend_result = state->backend_result;
    out->owner = state->owner;
    out->sequence = state->sequence;
    out->completed_sequence = state->completed_sequence;
    out->allocation = state->allocation;
    out->allocation_bytes = state->allocation_bytes;
    out->frame = state->frame;
    unlock_state(state);
    return NLR_GRAPHICS_OK;
}
