#include "nlr/runtime.h"

/* The boot checkpoint's entry (profile [boot_hooks.autoload]). The build
 * points one stock call at it: a call the firmware makes by itself, from
 * early in every boot and on every turn of a task that may read the card.
 * On the Z 6III that is the live-view GUI task's event-flag getter, about
 * 17 turns a second; the menu task, where the NLoader page lives, does not
 * run until the menu is opened. The entry makes the same call, returns
 * what it returned, and in between gives this boot's autoload pass its
 * chance to open (runtime.c), so that enabled extensions load without
 * anyone opening the NLoader page.
 *
 * Its first turn makes the runtime the page would have made -- the worker,
 * the arena, the input hook -- and asks the card nothing for it. Every
 * later turn only finds that runtime again. */

#if defined(NLR_STAGE_EXEC)
extern const struct nlr_services nlr_services;

void *nlr_boot_autoload_checkpoint(void)
{
    void *original = nlr_boot_autoload.callee();
    uint32_t named = 0;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, &named);
    /* A named worker without a runtime is an earlier attempt that failed
     * half way; making another would leak one per turn (runtime.c). */
    if (!r && !named)
        r = nlr_runtime_attach(&nlr_services, NLR_ARENA_BYTES, 0);
    if (r)
        nlr_runtime_boot_checkpoint(r, nlr_file_store());
    return original;
}
#endif
