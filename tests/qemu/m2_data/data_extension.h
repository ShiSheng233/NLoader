#include "data_checks.h"

#ifndef NLR_DATA_ITEM_ID
#error "Each diagnostic extension needs its own test item"
#endif

int32_t nlr_extension_init(const struct nlr_api *api)
{
    if (!api || api->abi < 2u)
        return 1;
    int result = check_data();
    if (result)
        return result;
    const struct nlr_menu_test_item item = {0x379u, NLR_DATA_ITEM_ID};
    return api->menu_register(&item);
}
