/* QEMU-only M2-T3.2 diagnostic, not part of the formal SDK example set.
 * Publishes increasing text through the real API table until
 * STOP.TXT exists in the loader's configured directory, then returns 0.
 * Never mount or edit the backing image from the host while QEMU is running.
 * The bounded volatile delay keeps individual values visible for capture;
 * it is not a timing API or production sample.
 */
#include "nlr.h"

static const char stop_path[] = "STOP.TXT";
#define DELAY_ITERATIONS 10000000u

int32_t nlr_app_main(const struct nlr_api *api)
{
    char text[] = "QEMU counter: 000";
    uint32_t counter;

    if (api == 0 || api->abi < 2u)
        return 1;

    for (counter = 1u; ; counter = (counter + 1u) % 1000u) {
        volatile uint32_t delay;
        int result;
        int fd = api->fs_open(stop_path, 0);

        if (fd >= 0) {
            if (api->fs_close(fd) != 0)
                return 4;
            return 0;
        }

        text[14] = (char)('0' + counter / 100u);
        text[15] = (char)('0' + (counter / 10u) % 10u);
        text[16] = (char)('0' + counter % 10u);
        result = api->ui_draw_text(0, 0, text);
        if (result != 0)
            return 2;
        result = api->ui_present();
        /* Present is not wired yet; native OK refreshes the result row. */
        if (result != 0 && result != -NLR_API_ENOSYS)
            return 3;
        for (delay = 0u; delay < DELAY_ITERATIONS; ++delay) {
            /* Intentional diagnostic-only delay, never a firmware call. */
        }
    }
}
