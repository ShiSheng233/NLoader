#include "nlr/input.h"
#include "nlr/api.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>

static const struct nlr_input_binding bindings[] = {
    {NLR_INPUT_KEY_UP, 0, 0x2a}, {NLR_INPUT_KEY_DOWN, 0, 0x15},
    {NLR_INPUT_KEY_LEFT, 0, 0x43}, {NLR_INPUT_KEY_RIGHT, 0, 0x8c},
    {NLR_INPUT_KEY_OK, 1, 1}, {NLR_INPUT_KEY_PLAYBACK, 1, 2},
};
static const struct nlr_input_services services = {
    .bindings = bindings, .count = sizeof bindings / sizeof bindings[0],
    .reserved = {0, 0xc000, 0},
};

static void mapping(void)
{
    uint32_t masks[3] = {55, 55, 55}, held = 99;
    assert(!nlr_input_suppression_masks(&services, masks));
    assert(masks[0] == 255 && masks[1] == 3 && !masks[2]);
    const uint32_t diagonal[3] = {8, 0xc001, 0};
    assert(!nlr_input_map(&services, diagonal, &held));
    assert(held == (NLR_INPUT_KEY_UP | NLR_INPUT_KEY_RIGHT | NLR_INPUT_KEY_OK));
    const uint32_t unrelated[3] = {1u << 31, 0xc000, 1u << 30};
    assert(!nlr_input_map(&services, unrelated, &held) && !held);
    struct nlr_input_binding bad[] = {{NLR_INPUT_KEY_OK, 1, 0x8001}};
    struct nlr_input_services broken = services;
    broken.bindings = bad;
    broken.count = 1;
    held = 99;
    assert(nlr_input_map(&broken, diagonal, &held) == -NLR_API_EINVAL && held == 99);
    bad[0].bank = 3;
    assert(nlr_input_map(&broken, diagonal, &held) == -NLR_API_EINVAL);
    broken = services;
    broken.count = 13;
    assert(nlr_input_suppression_masks(&broken, masks) == -NLR_API_EINVAL);
    assert(nlr_input_map(0, diagonal, &held) == -NLR_API_ENOSYS);
}

static void lifecycle_and_overflow(void)
{
    struct nlr_input_state state;
    nlr_input_init(&state);
    uint32_t owner = 0;
    struct nlr_input_event event = {77, 88};
    assert(!nlr_input_begin(&state, NLR_INPUT_KEY_OK, &owner) && owner == 1);
    assert(nlr_input_raw(&state, owner) == NLR_INPUT_KEY_OK);
    assert(nlr_input_poll(&state, owner, &event) == 0 && event.key == 77);
    assert(!nlr_input_publish(&state, owner, NLR_INPUT_KEY_UP | NLR_INPUT_KEY_OK));
    assert(nlr_input_poll(&state, owner, &event) == 1);
    assert(event.key == NLR_INPUT_KEY_UP && event.pressed == 1);
    assert(!nlr_input_publish(&state, owner, 0));
    assert(nlr_input_poll(&state, owner, &event) == 1 && event.key == NLR_INPUT_KEY_UP && !event.pressed);
    assert(nlr_input_poll(&state, owner, &event) == 1 && event.key == NLR_INPUT_KEY_OK && !event.pressed);
    for (uint32_t n = 0; n < 32; n++)
        assert(!nlr_input_publish(&state, owner, n & 1u ? 0 : NLR_INPUT_KEY_LEFT));
    assert(nlr_input_publish(&state, owner, NLR_INPUT_KEY_RIGHT) == -NLR_API_EOVERFLOW);
    assert(nlr_input_raw(&state, owner) == NLR_INPUT_KEY_RIGHT);
    assert(nlr_input_poll(&state, owner, &event) == -NLR_API_EOVERFLOW);
    assert(nlr_input_poll(&state, owner, &event) == 0);
    assert(!nlr_input_publish(&state, owner, 0));
    assert(nlr_input_poll(&state, owner, &event) == 1 && event.key == NLR_INPUT_KEY_RIGHT && !event.pressed);
    uint32_t next = 0;
    assert(!nlr_input_publish(&state, owner, NLR_INPUT_KEY_LEFT));
    assert(!nlr_input_begin(&state, NLR_INPUT_KEY_DOWN, &next) && next == 2);
    assert(nlr_input_poll(&state, next, &event) == 0);
    assert(nlr_input_publish(&state, owner, NLR_INPUT_KEY_LEFT) == -NLR_API_EBUSY);
    assert(nlr_input_raw(&state, next) == NLR_INPUT_KEY_DOWN && !nlr_input_raw(&state, owner));
    nlr_input_end(&state, owner);
    assert(nlr_input_raw(&state, next) == NLR_INPUT_KEY_DOWN);
    nlr_input_end(&state, next);
    assert(nlr_input_poll(&state, next, &event) == -NLR_API_EBUSY);
    state.next_owner = UINT32_MAX;
    assert(nlr_input_begin(&state, 0, &next) == -NLR_API_EOVERFLOW);
    assert(!state.active_owner);
}

static void cursor_wrap_and_late_slot(void)
{
    struct nlr_input_state state;
    nlr_input_init(&state);
    state.write_sequence = state.read_sequence = UINT32_MAX;
    uint32_t owner;
    assert(!nlr_input_begin(&state, 0, &owner));
    assert(!nlr_input_publish(&state, owner, NLR_INPUT_KEY_OK));
    struct nlr_input_event event;
    assert(nlr_input_poll(&state, owner, &event) == 1 && event.key == NLR_INPUT_KEY_OK);
    assert(state.write_sequence == 0 && state.read_sequence == 0);
    uint32_t next;
    assert(!nlr_input_begin(&state, 0, &next));
    /* A producer preempted immediately before its cursor publication may
     * commit this old tagged slot after begin sampled the previous cursor. */
    state.slots[0] = (struct nlr_input_slot){owner, {NLR_INPUT_KEY_UP, 1}};
    __atomic_store_n(&state.write_sequence, 1u, __ATOMIC_RELEASE);
    assert(!nlr_input_publish(&state, next, NLR_INPUT_KEY_DOWN));
    assert(nlr_input_poll(&state, next, &event) == 1 && event.key == NLR_INPUT_KEY_DOWN);
    assert(nlr_input_poll(&state, next, &event) == 0);
}

static struct nlr_input_state concurrent;
static void focus_request_ownership(void)
{
    struct nlr_input_state state;
    uint32_t owner, next;
    struct nlr_input_event event = {99, 99};
    nlr_input_init(&state);
    assert(!nlr_input_begin(&state, 0, &owner));
    assert(!nlr_input_publish(&state, owner, NLR_INPUT_KEY_UP));
    assert(!nlr_input_focus_lost(&state, owner));
    uint64_t stale = state.resync_request;
    assert(!nlr_input_focus_lost(&state, owner));
    uint64_t current = state.resync_request;
    nlr_input_focus_observed(&state, owner, stale);
    assert(state.resync_request == current);
    assert(nlr_input_poll(&state, owner, &event) == -NLR_API_EBUSY);
    assert(!nlr_input_raw(&state, owner) && event.key == 99);
    assert(!nlr_input_publish(&state, owner, NLR_INPUT_KEY_UP));
    nlr_input_focus_observed(&state, owner, current);
    assert(nlr_input_poll(&state, owner, &event) == -NLR_API_EOVERFLOW);
    assert(nlr_input_raw(&state, owner) == NLR_INPUT_KEY_UP);
    assert(!nlr_input_poll(&state, owner, &event) && event.key == 99);
    assert(!nlr_input_focus_lost(&state, owner));
    stale = state.resync_request;
    assert(!nlr_input_begin(&state, 0, &next) && !state.resync_request);
    assert(!nlr_input_focus_lost(&state, next));
    current = state.resync_request;
    nlr_input_focus_observed(&state, owner, stale);
    nlr_input_end(&state, owner);
    assert(state.resync_request == current && state.active_owner == next);
    assert(!nlr_input_publish(&state, next, NLR_INPUT_KEY_DOWN));
    nlr_input_focus_observed(&state, next, current);
    assert(nlr_input_poll(&state, next, &event) == -NLR_API_EOVERFLOW);
    assert(nlr_input_raw(&state, next) == NLR_INPUT_KEY_DOWN);
    state.next_resync = UINT32_MAX;
    assert(nlr_input_focus_lost(&state, next) == -NLR_API_EOVERFLOW);
    assert(!state.active_owner && !state.resync_request);
}
static uint32_t finished;
static void *producer(void *unused)
{
    (void)unused;
    while (!__atomic_load_n(&finished, __ATOMIC_ACQUIRE)) {
        uint32_t owner = __atomic_load_n(&concurrent.active_owner, __ATOMIC_ACQUIRE);
        if (!owner)
            continue;
        int result = nlr_input_publish(&concurrent, owner, owner & 1u ? NLR_INPUT_KEY_UP : NLR_INPUT_KEY_DOWN);
        assert(result == 0 || result == -NLR_API_EBUSY || result == -NLR_API_EOVERFLOW);
    }
    return 0;
}
static void concurrent_owner_changes(void)
{
    nlr_input_init(&concurrent);
    pthread_t thread;
    assert(!pthread_create(&thread, 0, producer, 0));
    for (uint32_t n = 0; n < 2000; n++) {
        uint32_t owner;
        assert(!nlr_input_begin(&concurrent, 0, &owner));
        sched_yield();
        struct nlr_input_event event;
        int result = nlr_input_poll(&concurrent, owner, &event);
        assert(result == 0 || result == 1 || result == -NLR_API_EOVERFLOW);
        uint32_t expected = owner & 1u ? NLR_INPUT_KEY_UP : NLR_INPUT_KEY_DOWN;
        if (result == 1)
            assert(event.key == expected && event.pressed == 1);
        uint32_t raw = nlr_input_raw(&concurrent, owner);
        assert(!raw || raw == expected);
    }
    __atomic_store_n(&finished, 1u, __ATOMIC_RELEASE);
    assert(!pthread_join(thread, 0));
}

int main(void)
{
    mapping();
    lifecycle_and_overflow();
    cursor_wrap_and_late_slot();
    focus_request_ownership();
    concurrent_owner_changes();
    puts("input queue, mapping and ownership tests passed");
    return 0;
}
