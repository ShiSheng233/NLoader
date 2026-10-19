#include "nlr.h"

enum { SLOTS = 16, BLOCK_BYTES = 64 };

int32_t nlr_app_main(const struct nlr_api *api)
{
    if (!api || api->abi < 2u)
        return 1;
    char mode[2] = {0, 0};
    int fd = api->fs_open("MODE.TXT", 0);
    if (fd < 0)
        return 40;
    int received = api->fs_read(fd, mode, sizeof mode);
    int closed = api->fs_close(fd);
    if (received != (int)sizeof mode || closed != 0)
        return 41;

    const char *message;
    if (mode[0] == 'A') {
        uint8_t *blocks[SLOTS];
        if (api->mem_alloc(BLOCK_BYTES, 1) != 0)
            return 42;
        for (uint32_t n = 0; n < SLOTS; n++) {
            blocks[n] = api->mem_alloc(BLOCK_BYTES, 0);
            if (!blocks[n])
                return 50 + (int32_t)n;
            for (uint32_t k = 0; k < n; k++)
                if (blocks[k] == blocks[n])
                    return 66;
            blocks[n][0] = (uint8_t)(0x80u + n);
        }
        if (api->mem_alloc(BLOCK_BYTES, 0) != 0)
            return 67;
        api->mem_free(blocks[3]);
        blocks[3] = api->mem_alloc(BLOCK_BYTES, 0);
        if (!blocks[3])
            return 68;
        for (uint32_t n = 0; n < SLOTS; n++)
            if (n != 3 && blocks[3] == blocks[n])
                return 70;
        blocks[3][0] = 0x5au;
        for (uint32_t n = 0; n < SLOTS; n++)
            if (n != 3 && blocks[n][0] != (uint8_t)(0x80u + n))
                return 69;
        if (blocks[3][0] != 0x5au || api->mem_alloc(BLOCK_BYTES, 0) != 0)
            return 71;
        /* Deliberately leave all sixteen owned objects for loader cleanup. */
        message = "Allocation slots OK";
    } else if (mode[0] == 'F') {
        int handles[SLOTS];
        for (uint32_t n = 0; n < SLOTS; n++) {
            handles[n] = api->fs_open("MODE.TXT", 0);
            if (handles[n] < 0)
                return 80 + (int32_t)n;
            for (uint32_t k = 0; k < n; k++)
                if (handles[k] == handles[n])
                    return 96;
        }
        if (api->fs_open("MODE.TXT", 0) != -NLR_API_EBUSY)
            return 97;
        if (api->fs_close(handles[3]) != 0)
            return 98;
        handles[3] = api->fs_open("MODE.TXT", 0);
        if (handles[3] < 0)
            return 99;
        for (uint32_t n = 0; n < SLOTS; n++)
            if (n != 3 && handles[3] == handles[n])
                return 106;
        if (api->fs_open("MODE.TXT", 0) != -NLR_API_EBUSY)
            return 107;
        /* Leave sixteen handles for the loader's real close path. */
        message = "File slots OK";
    } else if (mode[0] == 'U') {
        if (api->ui_present() != -NLR_API_ENOSYS ||
            api->gfx_begin(0) != -NLR_API_ENOSYS ||
            api->gfx_end() != -NLR_API_ENOSYS ||
            api->input_poll(0) != -NLR_API_ENOSYS || api->input_raw() != 0)
            return 100;
        if (api->fs_open("../OUTSIDE", 0) != -NLR_API_EINVAL ||
            api->fs_open("B:\\OUTSIDE", 0) != -NLR_API_EINVAL ||
            api->fs_open("MODE.TXT", 1) != -NLR_API_EINVAL)
            return 101;
        message = "API refusal checks OK";
    } else {
        return 102;
    }
    if (api->ui_draw_text(0, 0, message) != 0)
        return 103;
    if (mode[1] == 'E') {
        api->exit(0);
        return 104;
    }
    if (mode[1] == 'H')
        for (;;) {
            api->ui_draw_text(0, 0, message);
            for (volatile uint32_t n = 0; n < 1000000u; n++) {}
        }
    return mode[1] == 'R' ? 0 : 105;
}
