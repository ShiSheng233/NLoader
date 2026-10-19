#ifndef NLR_TIME_H
#define NLR_TIME_H

#include "nlr/services.h"

#define NLR_TIME_SLEEP_MAX_MS 1000u
#define NLR_TIME_WAIT_CHUNK_MS 10u
#define NLR_TIME_STALL_LIMIT 4u

/* checkpoint runs only between completed native calls; the API wrapper
 * uses it to honor foreground exit without abandoning a native wait. */
int nlr_time_clock(const struct nlr_time_services *services, uint64_t *out);
int nlr_time_sleep(const struct nlr_time_services *services, uint32_t ms,
                    void (*checkpoint)(void *), void *context);
/* Milliseconds since the camera started, from any task (api.c): the input
 * task's hooks may ask, so it touches no program state. */
uint32_t nlr_clock_ms(void);

#endif
