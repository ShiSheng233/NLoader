/* A finite diagnostic loop using only real read-only SDK file services.
 * No firmware addresses, host control files or direct entry calls. */
#include "nlr.h"

int32_t nlr_app_main(const struct nlr_api *api)
{
    uint8_t buffer[1024];
    if (!api || api->abi < 2u)
        return 1;
    if (api->ui_draw_text(0, 0, "File service loop") != 0)
        return 2;
    for (uint32_t iteration = 0; iteration < 100000u; iteration++) {
        int fd = api->fs_open("FIO.TXT", 0);
        if (fd < 0)
            return 3;
        int got = api->fs_read(fd, buffer, sizeof buffer);
        int closed = api->fs_close(fd);
        if (got != (int)sizeof buffer || closed != 0)
            return 4;
        for (uint32_t n = 0; n < sizeof buffer; n++)
            if (buffer[n] != (uint8_t)(n & 0xffu))
                return 5;
    }
    /* A missing exit attempt reaches this explicit diagnostic failure. */
    return 6;
}
