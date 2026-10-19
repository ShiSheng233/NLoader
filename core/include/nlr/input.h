#ifndef NLR_INPUT_H
#define NLR_INPUT_H

#include <stdint.h>
#include "nlr/api.h"

#define NLR_INPUT_KEY_UP (1u << 0)
#define NLR_INPUT_KEY_DOWN (1u << 1)
#define NLR_INPUT_KEY_LEFT (1u << 2)
#define NLR_INPUT_KEY_RIGHT (1u << 3)
#define NLR_INPUT_KEY_OK (1u << 4)
#define NLR_INPUT_KEY_PLAYBACK (1u << 5)
#define NLR_INPUT_KEY_AF_ON (1u << 6)
#define NLR_INPUT_KEY_DISP (1u << 7)
#define NLR_INPUT_KEY_FN1 (1u << 8)
#define NLR_INPUT_KEY_FN2 (1u << 9)
#define NLR_INPUT_KEY_ZOOM_IN (1u << 10)
#define NLR_INPUT_KEY_ZOOM_OUT (1u << 11)

#define NLR_INPUT_KEYS   ((1u << 12) - 1u)
#define NLR_INPUT_QUEUE_SIZE 32u
#define NLR_INPUT_BINDINGS_MAX 12u

struct nlr_input_event {
    uint32_t key;
    uint32_t pressed;
};

struct nlr_input_binding {
    uint32_t key;
    uint32_t bank;
    /* One or more physical bits in one bank; diagonal directions can map
     * into both corresponding SDK keys. MENU/DELETE are never allowed. */
    uint32_t mask;
};

struct nlr_input_services {
    const struct nlr_input_binding *bindings;
    uint32_t count;
    uint32_t reserved[3]; /* profile-verified loader-only physical controls */
    int32_t (*current_task)(uint32_t *out);
};

struct nlr_input_slot {
    uint32_t owner;
    struct nlr_input_event event;
};

/* One producer owns write_sequence and the slots; one consumer owns
 * read_sequence and begin/end. The producer never waits for the consumer.
 * Owner zero is inactive; owner numbers are never reused within a boot. */
struct nlr_input_state {
    uint32_t active_owner;
    uint32_t next_owner;
    uint32_t read_sequence;
    uint32_t write_sequence;
    uint32_t overflow_owner;
    uint32_t next_resync; /* consumer-owned, reset only for a new owner */
    _Alignas(8) uint64_t raw_state; /* high32 owner, low32 SDK held bitmap */
    uint64_t resync_request; /* high32 owner, low32 unique focus-loss request */
    struct nlr_input_slot slots[NLR_INPUT_QUEUE_SIZE];
};

void nlr_input_init(struct nlr_input_state *state);
/* Consumer-side lifecycle. seed is the last observed physical bitmap; it
 * does not enqueue launch-button presses into the new application's queue. */
int nlr_input_begin(struct nlr_input_state *state, uint32_t seed, uint32_t *owner);
void nlr_input_end(struct nlr_input_state *state, uint32_t owner);
/* Consumer drops old history on focus loss. Only a producer observation
 * captured after that request may acknowledge it; both tags reject old work. */
int nlr_input_focus_lost(struct nlr_input_state *state, uint32_t owner);
void nlr_input_focus_observed(struct nlr_input_state *state, uint32_t owner,
                               uint64_t captured_request);
/* Input producer supplies its captured owner token; a late token is refused.
 * Overflow still updates raw state, then reports -EOVERFLOW to both callers.
 * poll discards incomplete queued history when reporting that overflow. */
int nlr_input_publish(struct nlr_input_state *state, uint32_t owner, uint32_t held);
int nlr_input_poll(struct nlr_input_state *state, uint32_t owner,
                   struct nlr_input_event *event);
uint32_t nlr_input_raw(const struct nlr_input_state *state, uint32_t owner);
/* Pure bounded mapping; outputs stay unchanged on an invalid declaration. */
int nlr_input_map(const struct nlr_input_services *services,
                  const uint32_t banks[3], uint32_t *held);
int nlr_input_suppression_masks(const struct nlr_input_services *services,
                                 uint32_t masks[3]);

#endif
