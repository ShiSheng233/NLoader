/* Separate NLB entries exercise ordered init and a registered partial failure.
 * Build with NLR_TEST_ITEM_ID and NLR_TEST_INIT_RESULT per declaration. */
#include "nlr.h"

#ifndef NLR_TEST_ITEM_ID
#error "NLR_TEST_ITEM_ID must identify this fixture's own row"
#endif
#ifndef NLR_TEST_INIT_RESULT
#error "NLR_TEST_INIT_RESULT must declare this fixture's return status"
#endif

int32_t nlr_extension_init(const struct nlr_api *api)
{
    if (!api || api->abi < 2u || !api->menu_register)
        return -NLR_API_ENOSYS;
    const struct nlr_menu_test_item item = {
        .label_id = 0x379u,
        .item_id = NLR_TEST_ITEM_ID,
    };
    int result = api->menu_register(&item);
    if (result != 0)
        return result;
    return NLR_TEST_INIT_RESULT;
}
