#pragma once
#include <stdarg.h>
#include <stdint.h>

/* The loader's own log (core/journal.c): what it decided and saw, in lines
 * a person can read off the card -- the boot pass, the programs it started
 * and how they ended, the input it took from the camera and what it let
 * through, the screen it lent and what the display showed meanwhile.
 *
 * Lines are kept in RAM, in a ring any task may add to at any time (the
 * input task's hook included): nothing waits, nothing touches the card.
 * nlr_journal_flush appends what is new to the model's journal file
 * (services `journal_path`); without one the log stays in RAM. */

struct nlr_services;

#define NLR_JOURNAL_LINES 256u
#define NLR_JOURNAL_TEXT 56u
/* The file grows across boots, so the boot a crash ended can be read after
 * the next start; past this size the next boot starts it afresh. */
#define NLR_JOURNAL_FILE_MAX (512u << 10)

struct nlr_journal_line {
    uint32_t seq;  /* the line's number + 1 once written, 0 while it is */
    uint32_t ms;   /* when, on the clock programs see (time_ms) */
    char text[NLR_JOURNAL_TEXT];
};

struct nlr_journal {
    uint32_t tail;       /* lines taken so far */
    uint32_t sent;       /* lines dealt with by a flush */
    uint32_t lost;       /* overwritten before a flush got to them */
    uint32_t busy;       /* a flush is running */
    uint32_t flushed_at; /* clock at the last flush */
    uint32_t opened;     /* this boot's first write went to the file */
    uint32_t failures;   /* writes that did not reach the card */
    uint32_t held;       /* atomic: nothing goes to the card (switch off) */
    struct nlr_journal_line line[NLR_JOURNAL_LINES];
    char out[NLR_JOURNAL_LINES * (NLR_JOURNAL_TEXT + 12u) + 128u];
};

/* Add a line: printf-like with %d %u %x %s %c and the l / ll forms of the
 * numbers; the text is cut at NLR_JOURNAL_TEXT - 1 bytes. A null journal
 * takes nothing. */
void nlr_journal(struct nlr_journal *j, const char *fmt, ...);

/* The formatter itself (also for tests): the text's full length; at most
 * cap - 1 bytes are written, NUL-terminated. */
uint32_t nlr_journal_format(char *out, uint32_t cap, const char *fmt, va_list ap);

/* Append the lines not yet written to the journal file, no more often than
 * every `every_ms` (0: now). NLR_OK when there was nothing to do or it was
 * written, NLR_BUSY when another task is flushing, NLR_NOT_READY without a
 * file, NLR_IO when the card refused (the lines wait for the next flush). */
int nlr_journal_flush(struct nlr_journal *j, const struct nlr_services *svc,
                      uint32_t every_ms);

/* Hold the card writes (1) or let them go again (0). Held, a flush writes
 * nothing and answers NLR_OK; the lines stay in the ring, so a release
 * writes what the ring still has (older ones counted as lost). The loader
 * holds them while the NLoader switch is off: that boot writes nothing on
 * the card (runtime.c autoload_open). */
void nlr_journal_hold(struct nlr_journal *j, uint32_t held);

/* Milliseconds since the camera started, the clock programs see (core/time.c). */
uint32_t nlr_clock_ms(void);
