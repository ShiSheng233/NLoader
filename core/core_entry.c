#include "nlr/runtime.h"
#include "nlr/stage0.h"

/*
 * The dev core's entry (nlr/stage0.h). This file is
 * only in CORE.NLC, the loader built position independent and loaded from
 * the card by the module's stage 0: stage 0 calls nlr_core_entry once, then
 * the core's turn on every turn of the boot checkpoint, after the stock
 * call it makes itself. A turn is what the module's checkpoint entry does
 * in a loader build (boot_autoload.c) without that call: find or make the
 * runtime, and give the boot's pass its chance.
 */

extern const struct nlr_services nlr_services;

/* Milliseconds from the architectural counter, on any task. */
static uint32_t core_ms(void)
{
    uint64_t ticks, hz;
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(ticks));
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(hz));
    if (hz < 1000u)
        return 0;
    return (uint32_t)((ticks / hz) * 1000u + ((ticks % hz) * 1000u) / hz);
}

/* Ten seconds after the core's runtime first ran, on its own clock: tell
 * stage 0 the start went well, once. Called from every turn and from the
 * loop a turn stays in while a shell holds the stock GUI (runtime.c
 * boot_hold_wait), so a core whose shell never gives the turn back still
 * reports; a core that stops the camera before then never does, and the
 * next boot starts the camera stock. */
void nlr_core_alive(struct nlr_runtime *r)
{
    struct nlr_stage0_handshake *h = r ? r->stage0 : 0;
    if (!h || h->reported)
        return;
    uint32_t now = core_ms();
    if (!r->stage0_since) {
        r->stage0_since = now | 1u;
        return;
    }
    if (now - r->stage0_since < NLR_STAGE0_GOOD_MS)
        return;
    h->reported = 1;
    if (h->started_well)
        h->started_well();
}

static void core_turn(struct nlr_stage0_handshake *handshake)
{
    uint32_t named = 0;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, &named);
    /* A named worker without a runtime is an earlier attempt that failed
     * half way; making another would leak one per turn (runtime.c). */
    if (!r && !named)
        r = nlr_runtime_attach(&nlr_services, NLR_ARENA_BYTES, 0);
    if (!r)
        return;
    r->stage0 = handshake;
    nlr_core_alive(r);
    nlr_runtime_boot_checkpoint(r, nlr_file_store());
}

int32_t nlr_core_entry(struct nlr_stage0_handshake *handshake)
{
    if (!handshake || handshake->magic != NLR_STAGE0_MAGIC ||
        handshake->version != NLR_STAGE0_VERSION)
        return 1;
    handshake->turn = core_turn;
    handshake->core_abi = NLR_ABI_VERSION;
    return 0;
}
