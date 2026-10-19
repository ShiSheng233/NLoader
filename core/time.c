#include "nlr/time.h"
#include "nlr/api.h"

/* The bindings carry the model's service addresses. */
extern const struct nlr_services nlr_services;

/* The architectural counter: CNTVCT_EL0 ticks at CNTFRQ_EL0 on every core
 * and is readable from the worker's exception level, so time needs no
 * firmware service. Host builds (the tests) have no such counter. */
static uint64_t counter_ticks(void)
{
#if defined(__aarch64__) && !defined(NLR_HOST_TEST)
    uint64_t v;
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

static uint64_t counter_hz(void)
{
#if defined(__aarch64__) && !defined(NLR_HOST_TEST)
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

/* Milliseconds since the camera started, from any task: no program state
 * is touched, so the input task's hooks may ask too (both the program
 * input hook and the exit callback run the platform pass). */
uint32_t nlr_clock_ms(void)
{
    uint32_t result = 0;
    if (nlr_services.time) {
        uint64_t now = 0;
        if (!nlr_time_clock(nlr_services.time, &now)) result = (uint32_t)now;
    } else {
        uint64_t hz = counter_hz();
        if (hz >= 1000u && hz <= UINT64_MAX / 1000u) {
            uint64_t ticks = counter_ticks();
            result = (uint32_t)((ticks / hz) * 1000u + ((ticks % hz) * 1000u) / hz);
        }
    }
    return result;
}

int nlr_time_clock(const struct nlr_time_services *services, uint64_t *out)
{
    if (!out)
        return -NLR_API_EINVAL;
    if (!services || !services->clock_ms)
        return -NLR_API_ENOSYS;
    uint64_t value = 0;
    if (services->clock_ms(&value) != NLR_OK)
        return -NLR_API_EIO;
    *out = value;
    return 0;
}

int nlr_time_sleep(const struct nlr_time_services *services, uint32_t ms,
                    void (*checkpoint)(void *), void *context)
{
    if (checkpoint)
        checkpoint(context);
    if (ms > NLR_TIME_SLEEP_MAX_MS)
        return -NLR_API_EINVAL;
    if (!services || !services->clock_ms || !services->delay_ms)
        return -NLR_API_ENOSYS;
    if (!ms)
        return 0;
    uint64_t start = 0;
    if (nlr_time_clock(services, &start) != 0)
        return -NLR_API_EIO;
    uint64_t previous = start;
    uint32_t stalled = 0;
    for (;;) {
        uint64_t elapsed = previous - start;
        if (elapsed >= ms)
            return 0;
        uint32_t remaining = ms - (uint32_t)elapsed;
        uint32_t chunk = remaining < NLR_TIME_WAIT_CHUNK_MS
                             ? remaining : NLR_TIME_WAIT_CHUNK_MS;
        int result = services->delay_ms(chunk);
        if (checkpoint)
            checkpoint(context);
        if (result != NLR_OK)
            return -NLR_API_EIO;
        uint64_t now = 0;
        if (nlr_time_clock(services, &now) != 0 || now < previous)
            return -NLR_API_EIO;
        /* A phase boundary can produce a short first wait. Measure elapsed
         * time instead of adding requested delays; repeated lack of progress
         * fails rather than spinning forever on a broken provider. */
        stalled = now == previous ? stalled + 1u : 0u;
        if (stalled >= NLR_TIME_STALL_LIMIT)
            return -NLR_API_EIO;
        previous = now;
    }
}
