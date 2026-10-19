/* ABI 4 resource extension: it writes a line to the card and installs a
 * hook, then returns and stays resident. Its code block keeps the handler
 * alive, which is what makes a hook outlive the program that asked for it;
 * the foreground fixture then finds the hook still installed.
 *
 * Returns 0 when it loaded, or 10..14 for the step that failed. */

#include "nlr.h"

#include "target.h"

static uint64_t replace_handler(uint64_t value)
{
    (void)value;
    return NLR_TEST_REPLACE;
}

static const char log_path[] = "EXTLOG.TXT";
static const char log_text[] = "hook extension loaded\n";

int32_t nlr_extension_init(const struct nlr_api *api)
{
    if (!api || api->abi != NLR_ABI_VERSION)
        return -NLR_API_EINVAL;
    if (!api->fs_write || !api->code_hook)
        return -NLR_API_ENOSYS;

    uint32_t length = (uint32_t)sizeof log_text - 1u;
    int fd = api->fs_open(log_path, NLR_OPEN_WRITE);
    if (fd < 0)
        return 10;
    int written = api->fs_write(fd, log_text, length);
    if (api->fs_close(fd) != 0)
        return 11;
    if (written != (int)length)
        return 12;

    int hooked = api->code_hook((void *)NLR_TEST_TARGET, nlr_test_expect,
                                (void *)replace_handler);
    if (hooked != 0) {
        api->log("ext: hook %d", hooked);
        return 13;
    }
    if (nlr_test_call(1) != NLR_TEST_REPLACE)
        return 14;
    api->ui_draw_text(0, 0, "ext: hook installed");
    return 0;
}
