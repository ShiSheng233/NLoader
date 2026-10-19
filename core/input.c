#include "nlr/input.h"
#include "nlr/api.h"

_Static_assert(__atomic_always_lock_free(8, 0), "input snapshots must never take a lock");
_Static_assert(sizeof(struct nlr_input_event) == 8, "input event ABI");
_Static_assert((NLR_INPUT_QUEUE_SIZE & (NLR_INPUT_QUEUE_SIZE - 1u)) == 0,
               "input ring capacity is a power of two");

static int current_owner(const struct nlr_input_state *state, uint32_t owner)
{
    return state && owner &&
        __atomic_load_n(&state->active_owner, __ATOMIC_ACQUIRE) == owner;
}

void nlr_input_init(struct nlr_input_state *state)
{
    if (!state)
        return;
    for (uint32_t n = 0; n < sizeof *state; n++)
        ((uint8_t *)state)[n] = 0;
}

int nlr_input_begin(struct nlr_input_state *state, uint32_t seed, uint32_t *owner)
{
    if (!state || !owner || (seed & ~NLR_INPUT_KEYS))
        return -NLR_API_EINVAL;
    __atomic_store_n(&state->active_owner, 0u, __ATOMIC_RELEASE);
    if (state->next_owner == UINT32_MAX)
        return -NLR_API_EOVERFLOW;
    uint32_t next = ++state->next_owner;
    __atomic_store_n(&state->raw_state, (uint64_t)next << 32 | seed, __ATOMIC_RELEASE);
    /* Never reset the producer's cursor: an old in-flight producer may
     * finish a tagged slot after this snapshot. poll will reject its tag. */
    uint32_t written = __atomic_load_n(&state->write_sequence, __ATOMIC_ACQUIRE);
    __atomic_store_n(&state->read_sequence, written, __ATOMIC_RELEASE);
    __atomic_store_n(&state->overflow_owner, 0u, __ATOMIC_RELEASE);
    state->next_resync = 0;
    __atomic_store_n(&state->resync_request, UINT64_C(0), __ATOMIC_RELEASE);
    *owner = next;
    __atomic_store_n(&state->active_owner, next, __ATOMIC_RELEASE);
    return 0;
}

void nlr_input_end(struct nlr_input_state *state, uint32_t owner)
{
    if (!state || !owner)
        return;
    uint32_t expected = owner;
    if (__atomic_compare_exchange_n(&state->active_owner, &expected, 0u, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        uint64_t request = __atomic_load_n(&state->resync_request, __ATOMIC_ACQUIRE);
        if ((uint32_t)(request >> 32) == owner)
            __atomic_compare_exchange_n(&state->resync_request, &request, UINT64_C(0), 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
}

int nlr_input_focus_lost(struct nlr_input_state *state, uint32_t owner)
{
    if (!current_owner(state, owner))
        return -NLR_API_EBUSY;
    if (state->next_resync == UINT32_MAX) {
        nlr_input_end(state, owner); /* Never reuse a same-owner request tag. */
        return -NLR_API_EOVERFLOW;
    }
    uint64_t request = (uint64_t)owner << 32 | ++state->next_resync;
    __atomic_store_n(&state->resync_request, request, __ATOMIC_RELEASE);
    uint32_t written = __atomic_load_n(&state->write_sequence, __ATOMIC_ACQUIRE);
    __atomic_store_n(&state->read_sequence, written, __ATOMIC_RELEASE);
    return 0;
}

void nlr_input_focus_observed(struct nlr_input_state *state, uint32_t owner,
                               uint64_t captured_request)
{
    if (!current_owner(state, owner) || !captured_request ||
        (uint32_t)(captured_request >> 32) != owner)
        return;
    /* Publish the resync error before allowing the consumer to resume. A
     * callback captured before a newer loss cannot acknowledge that loss. */
    __atomic_store_n(&state->overflow_owner, owner, __ATOMIC_RELEASE);
    __atomic_compare_exchange_n(&state->resync_request, &captured_request, UINT64_C(0), 0,
                                  __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

int nlr_input_publish(struct nlr_input_state *state, uint32_t owner, uint32_t held)
{
    if (held & ~NLR_INPUT_KEYS)
        return -NLR_API_EINVAL;
    if (!current_owner(state, owner))
        return -NLR_API_EBUSY;
    uint64_t previous = __atomic_load_n(&state->raw_state, __ATOMIC_ACQUIRE);
    if ((uint32_t)(previous >> 32) != owner)
        return -NLR_API_EBUSY;
    uint64_t next = (uint64_t)owner << 32 | held;
    /* Exactly one attempt: the only competing writer is a new owner. A
     * failed compare means stale work; it must never overwrite the new seed. */
    if (!__atomic_compare_exchange_n(&state->raw_state, &previous, next, 0,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -NLR_API_EBUSY;
    uint32_t changed = (uint32_t)previous ^ held;
    int result = 0;
    for (uint32_t bit = 1; bit <= NLR_INPUT_KEY_ZOOM_OUT; bit <<= 1) {
        if (!(changed & bit))
            continue;
        if (!current_owner(state, owner))
            return -NLR_API_EBUSY;
        uint32_t written = __atomic_load_n(&state->write_sequence, __ATOMIC_RELAXED);
        uint32_t read = __atomic_load_n(&state->read_sequence, __ATOMIC_ACQUIRE);
        if ((uint32_t)(written - read) >= NLR_INPUT_QUEUE_SIZE) {
            __atomic_store_n(&state->overflow_owner, owner, __ATOMIC_RELEASE);
            result = -NLR_API_EOVERFLOW;
            continue;
        }
        struct nlr_input_slot *slot = &state->slots[written & (NLR_INPUT_QUEUE_SIZE - 1u)];
        slot->owner = owner;
        slot->event.key = bit;
        slot->event.pressed = (held & bit) != 0;
        if (!current_owner(state, owner))
            return -NLR_API_EBUSY;
        __atomic_store_n(&state->write_sequence, written + 1u, __ATOMIC_RELEASE);
    }
    return current_owner(state, owner) ? result : -NLR_API_EBUSY;
}

int nlr_input_poll(struct nlr_input_state *state, uint32_t owner,
                   struct nlr_input_event *event)
{
    if (!event)
        return -NLR_API_EINVAL;
    if (!current_owner(state, owner))
        return -NLR_API_EBUSY;
    if (__atomic_load_n(&state->resync_request, __ATOMIC_ACQUIRE))
        return -NLR_API_EBUSY;
    uint32_t overflow = owner;
    if (__atomic_compare_exchange_n(&state->overflow_owner, &overflow, 0u, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        uint32_t written = __atomic_load_n(&state->write_sequence, __ATOMIC_ACQUIRE);
        __atomic_store_n(&state->read_sequence, written, __ATOMIC_RELEASE);
        return -NLR_API_EOVERFLOW;
    }
    /* A stale owner can finish at most its bounded batch; never let a
     * producer keep this consumer call alive by continuously publishing. */
    for (uint32_t n = 0; n < NLR_INPUT_QUEUE_SIZE; n++) {
        uint32_t read = __atomic_load_n(&state->read_sequence, __ATOMIC_RELAXED);
        uint32_t written = __atomic_load_n(&state->write_sequence, __ATOMIC_ACQUIRE);
        if (read == written)
            return 0;
        const struct nlr_input_slot *slot = &state->slots[read & (NLR_INPUT_QUEUE_SIZE - 1u)];
        uint32_t tag = slot->owner;
        struct nlr_input_event next = slot->event;
        __atomic_store_n(&state->read_sequence, read + 1u, __ATOMIC_RELEASE);
        if (!current_owner(state, owner))
            return -NLR_API_EBUSY;
        if (tag == owner) {
            *event = next;
            return 1;
        }
    }
    return 0;
}

uint32_t nlr_input_raw(const struct nlr_input_state *state, uint32_t owner)
{
    if (!current_owner(state, owner) ||
        __atomic_load_n(&state->resync_request, __ATOMIC_ACQUIRE))
        return 0;
    uint64_t raw = __atomic_load_n(&state->raw_state, __ATOMIC_ACQUIRE);
    return (uint32_t)(raw >> 32) == owner && current_owner(state, owner)
               ? (uint32_t)raw : 0;
}

static int bindings_valid(const struct nlr_input_services *services)
{
    if (!services || !services->bindings || !services->count)
        return -NLR_API_ENOSYS;
    if (services->count > NLR_INPUT_BINDINGS_MAX ||
        !(services->reserved[0] | services->reserved[1] | services->reserved[2]))
        return -NLR_API_EINVAL;
    uint32_t seen = 0;
    for (uint32_t n = 0; n < services->count; n++) {
        const struct nlr_input_binding *binding = &services->bindings[n];
        uint32_t key = binding->key;
        if (!key || (key & (key - 1u)) || (key & ~NLR_INPUT_KEYS) ||
            (seen & key) || binding->bank >= 3u || !binding->mask ||
            (binding->mask & services->reserved[binding->bank]))
            return -NLR_API_EINVAL;
        seen |= key;
    }
    return 0;
}

int nlr_input_map(const struct nlr_input_services *services,
                  const uint32_t banks[3], uint32_t *held)
{
    if (!banks || !held)
        return -NLR_API_EINVAL;
    int result = bindings_valid(services);
    if (result)
        return result;
    uint32_t mapped = 0;
    for (uint32_t n = 0; n < services->count; n++) {
        const struct nlr_input_binding *binding = &services->bindings[n];
        if (banks[binding->bank] & binding->mask)
            mapped |= binding->key;
    }
    *held = mapped;
    return 0;
}

int nlr_input_suppression_masks(const struct nlr_input_services *services,
                                 uint32_t masks[3])
{
    if (!masks)
        return -NLR_API_EINVAL;
    int result = bindings_valid(services);
    if (result)
        return result;
    uint32_t native[3] = {0, 0, 0};
    for (uint32_t n = 0; n < services->count; n++)
        native[services->bindings[n].bank] |= services->bindings[n].mask;
    for (uint32_t n = 0; n < 3; n++)
        masks[n] = native[n];
    return 0;
}
