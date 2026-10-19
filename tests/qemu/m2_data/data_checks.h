#ifndef NLR_QEMU_DATA_CHECKS_H
#define NLR_QEMU_DATA_CHECKS_H

#include "nlr.h"

/* Volatile objects force real relocated reads/writes. Each fresh load must
 * restore the initialized word and clear the complete BSS array. */
static volatile uint32_t initialized_word = 0x13579bdfu;
static volatile uint32_t zero_words[37];

static uint32_t transform(uint32_t value)
{
    return (value ^ 0xa5963c5au) + 0x311u;
}

/* Both targets are in the image, while these pointer objects are writable
 * data: the independent file audit must find real ABS64 relocations. */
static uint32_t (* volatile relocated_function)(uint32_t) = transform;
static const char * volatile relocated_message = "DATA BSS relocation OK";

static int check_data(void)
{
    if (initialized_word != 0x13579bdfu)
        return 20;
    for (uint32_t n = 0; n < 37; n++)
        if (zero_words[n] != 0)
            return 21;
    if (relocated_function(initialized_word) != 0xb6c1aa96u)
        return 22;
    if (relocated_message[0] != 'D' || relocated_message[21] != 'K')
        return 23;
    initialized_word = 0x2468ace0u;
    for (uint32_t n = 0; n < 37; n++)
        zero_words[n] = 0x10203040u + n;
    for (uint32_t n = 0; n < 37; n++)
        if (zero_words[n] != 0x10203040u + n)
            return 24;
    return initialized_word == 0x2468ace0u ? 0 : 25;
}

#endif
