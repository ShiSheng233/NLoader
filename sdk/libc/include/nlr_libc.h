#ifndef NLR_LIBC_H
#define NLR_LIBC_H
/* The program side of the libc: the API table it runs on, the arena it
 * allocates from, and the console ring a debugger can find by its magic. */
#include <stddef.h>
#include <stdint.h>

struct nlr_api;
extern const struct nlr_api *nlr_libc_api;

/* Take the malloc arena: `want` bytes, stepping down by a quarter to no
 * less than `floor`. 0 on success. */
int nlr_libc_arena(size_t want, size_t floor);
size_t nlr_libc_arena_size(void);

#define NLR_CONSOLE_MAGIC UINT64_C(0x454c4f534e4f434e) /* "NCONSOLE" */
struct nlr_console {
    uint64_t magic;
    uint32_t head;          /* bytes ever written; text[head % size] next */
    uint32_t reserved;
    char text[16384];
};
extern struct nlr_console nlr_console;

#endif
