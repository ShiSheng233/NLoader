#include "data_checks.h"

int32_t nlr_app_main(const struct nlr_api *api)
{
    if (!api || api->abi < 2u)
        return 1;
    int result = check_data();
    if (result)
        return result;
    if (api->ui_draw_text(0, 0, relocated_message) != 0)
        return 26;
    int fd = api->fs_open("MODE.TXT", 0);
    if (fd < 0)
        return 27;
    char mode = 0;
    int received = api->fs_read(fd, &mode, 1);
    int closed = api->fs_close(fd);
    if (received != 1 || closed != 0)
        return 28;
    if (mode == 'E') {
        api->exit(0);
        return 29;
    }
    if (mode == 'H')
        for (;;) {
            /* The loader's real exit chord must stop this program. */
            api->ui_draw_text(0, 0, relocated_message);
            for (volatile uint32_t n = 0; n < 1000000u; n++) {}
        }
    return mode == 'R' ? 0 : 30;
}
