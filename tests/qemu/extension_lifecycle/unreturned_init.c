/* QEMU-only resource diagnostic: register once and never complete init.
 * The owned runner must stop the VM after its bounded observation window;
 * this fixture must not be installed on a physical camera. No timer, sleep,
 * firmware address, writable static data or foreground exit is used. */
#include "nlr.h"

int32_t nlr_extension_init(const struct nlr_api *api)
{
    if (!api || api->abi < 2u)
        return -NLR_API_EINVAL;
    if (!api->menu_register)
        return -NLR_API_ENOSYS;

    const struct nlr_menu_test_item item = {
        .label_id = 0x379u,
        .item_id = 0x7ffau,
    };
    int result = api->menu_register(&item);
    if (result != 0)
        return result < 0 ? result : -NLR_API_EIO;

    for (;;)
        __asm__ volatile("nop" ::: "memory");
}
