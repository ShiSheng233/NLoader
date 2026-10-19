/* Deliberately never polls input or calls exit: interruption belongs to the
 * loader, not to application cooperation or the unavailable input API. */
#include "nlr.h"

int32_t nlr_app_main(const struct nlr_api *api)
{
    if (!api || api->abi < 2u)
        return -NLR_API_EINVAL;
    for (;;)
        __asm__ volatile("nop");
}
