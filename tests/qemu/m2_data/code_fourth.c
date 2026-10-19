#include "nlr.h"

int32_t nlr_extension_init(const struct nlr_api *api)
{
    if (!api || api->abi < 2u)
        return 1;
    const struct nlr_menu_test_item item = {0x379u, 0x7ff7u};
    return api->menu_register(&item);
}
