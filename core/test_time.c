#include "nlr/time.h"
#include "nlr/api.h"
#include <stdio.h>

/* time.c's clock reads the model's services; this harness has none, so the
 * shared clock falls back to the architectural counter (host: zero). */
const struct nlr_services nlr_services = { 0 };

static int failures;
#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s\n", __LINE__, #x); failures++; } } while (0)
static uint64_t current;
static uint32_t reads, waits, checkpoints, requested[1100];
static uint32_t clock_failure, delay_failure, early, frozen, backwards;
static int32_t clock_read(uint64_t *out)
{
    reads++;
    if (reads == clock_failure) {
        *out = 999;
        return -25;
    }
    *out = current;
    return 0;
}
static int32_t delay(uint32_t ms)
{
    CHECK(ms && ms <= 10 && waits < 1100);
    requested[waits++] = ms;
    if (waits == delay_failure)
        return -25;
    if (backwards)
        current--;
    else if (!frozen)
        current += early && waits == 1 ? 0 : ms;
    return 0;
}
static void checkpoint(void *context)
{
    CHECK(context == &current);
    checkpoints++;
}
static const struct nlr_time_services services = {clock_read, delay};
static void reset(void)
{
    current = 100;
    reads = waits = checkpoints = 0;
    clock_failure = delay_failure = early = frozen = backwards = 0;
}
static int sleep_for(uint32_t ms)
{
    return nlr_time_sleep(&services, ms, checkpoint, &current);
}
int main(void)
{
    reset();
    uint64_t output = 123;
    CHECK(nlr_time_clock(0, &output) == -NLR_API_ENOSYS && output == 123);
    CHECK(nlr_time_clock(&services, 0) == -NLR_API_EINVAL);
    CHECK(nlr_time_clock(&services, &output) == 0 && output == 100);
    clock_failure = reads + 1;
    CHECK(nlr_time_clock(&services, &output) == -NLR_API_EIO && output == 100);
    struct nlr_time_services incomplete = {clock_read, 0};
    CHECK(nlr_time_sleep(&incomplete, 1, checkpoint, &current) == -NLR_API_ENOSYS);
    CHECK(nlr_time_sleep(0, 0, checkpoint, &current) == -NLR_API_ENOSYS);

    reset();
    CHECK(sleep_for(0) == 0 && checkpoints == 1 && !waits && !reads);
    CHECK(sleep_for(1001) == -NLR_API_EINVAL && !waits && !reads);
    CHECK(sleep_for(UINT32_MAX) == -NLR_API_EINVAL && !waits && !reads);
    reset();
    CHECK(sleep_for(17) == 0 && current == 117 && waits == 2);
    CHECK(requested[0] == 10 && requested[1] == 7 && checkpoints == 3);
    reset();
    early = 1;
    CHECK(sleep_for(1) == 0 && current == 101 && waits == 2);
    CHECK(requested[0] == 1 && requested[1] == 1);
    reset();
    frozen = 1;
    CHECK(sleep_for(17) == -NLR_API_EIO && waits == NLR_TIME_STALL_LIMIT);
    CHECK(checkpoints == waits + 1);
    reset();
    backwards = 1;
    CHECK(sleep_for(1) == -NLR_API_EIO && waits == 1);
    reset();
    delay_failure = 1;
    CHECK(sleep_for(17) == -NLR_API_EIO && waits == 1 && checkpoints == 2);
    reset();
    clock_failure = 1;
    CHECK(sleep_for(17) == -NLR_API_EIO && waits == 0);
    reset();
    clock_failure = 2;
    CHECK(sleep_for(17) == -NLR_API_EIO && waits == 1);
    reset();
    current = UINT64_MAX - 10;
    CHECK(sleep_for(10) == 0 && current == UINT64_MAX);
    reset();
    current = UINT64_MAX;
    CHECK(sleep_for(1) == -NLR_API_EIO && waits == 1);
    reset();
    CHECK(sleep_for(1000) == 0 && waits == 100 && current == 1100);
    if (failures)
        return 1;
    puts("time service behavior tests passed");
    return 0;
}
