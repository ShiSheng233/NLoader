#ifndef NLR_STAGE0_H
#define NLR_STAGE0_H

#include <stdint.h>

#include "nlr/exec.h"
#include "nlr/services.h"

/*
 * Dev firmware: the module carries only stage 0, and
 * the loader itself -- the core -- comes from the card as NLOADER/CORE.NLC,
 * so a loader change is a file copy, not a reflash.
 *
 * Stage 0 is the boot checkpoint and nothing else it could do without:
 * the stock call it replaces, DISP at power-on, the card's answer, a
 * failed-start mark, the core's checks, and the execution blocks the core
 * runs from. It never changes once flashed, so everything here is the
 * contract between a frozen stage 0 and every core built after it.
 *
 * The core is an NPLD version 3 resource extension whose description says
 * `id=core` and `stage0=<NLR_STAGE0_VERSION>`. Stage 0 calls its entry once,
 * on the stock GUI task, with a struct nlr_stage0_handshake in x0; the
 * entry checks magic and version, fills in `turn` and returns 0. From then
 * on stage 0 calls `turn` on every turn of the checkpoint, after the stock
 * call, and the core does there what the loader in the module did before:
 * its own runtime, the autoload pass, the boot program.
 */

#define NLR_STAGE0_MAGIC   0x304c4e53u /* "SNL0" */
#define NLR_STAGE0_VERSION 1u
#define NLR_STAGE0_CORE_PATH NLR_CARD_ROOT "CORE.NLC"
#define NLR_STAGE0_MARK_PATH NLR_CARD_ROOT "CORERUN"
/* A core larger than this is refused before anything is allocated for it:
 * the core runs from one 2 MiB block (exec.c's flat layout), and the file
 * adds its header, description and relocations. */
#define NLR_STAGE0_CORE_MAX (5u << 20)
/* How often the card is asked whether it is there yet: on turns 1, 2, 4,
 * 8, ... up to this many asks, then the boot goes on as a stock one. */
#define NLR_STAGE0_CARD_ASKS 12u

struct nlr_stage0_handshake {
    uint32_t magic;            /* NLR_STAGE0_MAGIC */
    uint32_t version;          /* NLR_STAGE0_VERSION */
    /* Filled in by the core's entry: its per-turn function (given this
     * handshake each turn), and the ABI of the API table it hands its
     * programs. */
    void (*turn)(struct nlr_stage0_handshake *handshake);
    /* Filled in by stage 0: records on the card that this start went
     * well, so the next boot starts the core again. The core calls it once,
     * after it has run NLR_STAGE0_GOOD_MS on its own clock -- from its own
     * loops, because a shell keeps the turn for as long as it runs. */
    void (*started_well)(void);
    uint32_t core_abi;
    uint32_t reported;         /* the core called started_well */
};

/* A core runs this long before it reports that it started well. */
#define NLR_STAGE0_GOOD_MS 10000u

/* The core side of the report (core_entry.c; only in CORE.NLC): called on
 * every turn and from the loops a turn can stay in. */
struct nlr_runtime;
void nlr_core_alive(struct nlr_runtime *r);

/* Where stage 0 is this boot (state.phase). */
enum {
    NLR_STAGE0_NEW = 0,     /* nothing decided */
    NLR_STAGE0_WAITING,     /* the card has not answered yet */
    NLR_STAGE0_RUNNING,     /* the core runs: every turn goes to it */
    NLR_STAGE0_STOCK,       /* this boot stays stock: `why` says why */
};

/* Why a boot stayed stock (state.why). */
enum {
    NLR_STAGE0_WHY_NONE = 0,
    NLR_STAGE0_WHY_ESCAPE,      /* DISP held at power-on */
    NLR_STAGE0_WHY_NO_CARD,     /* the card never answered */
    NLR_STAGE0_WHY_NO_CORE,     /* no CORE.NLC */
    NLR_STAGE0_WHY_SKIPPED,     /* the last core start never got far */
    NLR_STAGE0_WHY_IO,          /* reading it failed */
    NLR_STAGE0_WHY_REFUSED,     /* not a core this stage 0 runs */
    NLR_STAGE0_WHY_MEMORY,      /* no memory for it */
    NLR_STAGE0_WHY_START,       /* its blocks or its entry failed */
};

/* What the last start mark (CORERUN) says to do: a core that was started
 * ("run") and never reported that it ran well is not started again on the
 * next boot (which writes "skipped"); the boot after tries again. */
#define NLR_STAGE0_MARK_START 0u
#define NLR_STAGE0_MARK_SKIP  1u
uint32_t nlr_stage0_mark_says(const uint8_t *mark, uint32_t bytes);

/* Check a core file in memory and lay out its segments for the executor:
 * NPLD version 3, the generic 64-byte header, kind 1, description with
 * id=core and stage0=NLR_STAGE0_VERSION, every CRC and every relocation
 * entry in bounds. NLR_OK, or NLR_FORMAT / NLR_BOUNDS / NLR_CHECKSUM /
 * NLR_REFUSED (a valid file that is not a core for this stage 0). */
int nlr_stage0_check(const uint8_t *file, uint32_t bytes,
                     struct nlr_program_segments *out);

#endif
