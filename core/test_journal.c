/* Host tests for the loader's own log (core/journal.c): the formatter, the
 * ring and its lost lines, and the flush to a file appended across boots. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nlr/journal.h"
#include "nlr/services.h"

static int failures;
#define CHECK(c)                                                            \
    do {                                                                    \
        if (!(c)) {                                                         \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);            \
            failures++;                                                     \
        }                                                                   \
    } while (0)

static uint32_t clock_now;
uint32_t nlr_clock_ms(void)
{
    return clock_now;
}

/* ---- one file on a card ---------------------------------------------------- */

#define FILE_CAP (256u << 10)
static char file_data[FILE_CAP];
static uint32_t file_size, file_exists, file_pos, fake_size;
static int opens_rw, opens_create, open_fail, write_fail, card_gone;
/* a line another task adds while a flush is writing */
static struct nlr_journal *inject;

static int32_t m_open(const char *path, uint32_t flags, uint32_t mode)
{
    (void)mode;
    if (card_gone || strcmp(path, "A:\\NLOADER\\LOADER.LOG"))
        return -1;
    if (flags == 2u) { /* read and write an existing file */
        opens_rw++;
        if (!file_exists || open_fail)
            return -1;
        file_pos = 0;
        return 3;
    }
    if (flags == 1u) { /* create or truncate */
        opens_create++;
        file_exists = 1;
        file_size = 0;
        file_pos = 0;
        fake_size = 0;
        return 3;
    }
    return -1;
}

static int32_t m_seek(int32_t fd, int32_t whence, uint32_t offset, uint32_t *pos)
{
    if (fd != 3 || whence != 2 || offset)
        return -1;
    file_pos = file_size;
    *pos = fake_size ? fake_size : file_size;
    return 0;
}

static int32_t m_write(int32_t fd, const void *buf, uint32_t bytes, uint32_t *done)
{
    if (fd != 3 || write_fail)
        return -1;
    if (inject) {
        struct nlr_journal *j = inject;
        inject = 0;
        nlr_journal(j, "added during the write");
    }
    uint32_t take = bytes > 700u ? 700u : bytes; /* short writes, as cards do */
    if (file_pos + take > FILE_CAP)
        return -1;
    memcpy(file_data + file_pos, buf, take);
    file_pos += take;
    if (file_pos > file_size)
        file_size = file_pos;
    *done = take;
    return 0;
}

static int32_t m_close(int32_t fd)
{
    return fd == 3 ? 0 : -1;
}

static struct nlr_services svc;

static void card_reset(void)
{
    memset(file_data, 0, sizeof file_data);
    file_size = file_exists = file_pos = fake_size = 0;
    opens_rw = opens_create = open_fail = write_fail = card_gone = 0;
    memset(&svc, 0, sizeof svc);
    svc.file_open = m_open;
    svc.file_seek = m_seek;
    svc.file_write = m_write;
    svc.file_close = m_close;
    svc.file_open_rw = 2u;
    svc.file_open_write = 1u;
    svc.journal_path = "A:\\NLOADER\\LOADER.LOG";
}

static uint32_t count_lines(void)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < file_size; i++)
        n += file_data[i] == '\n';
    return n;
}

static int file_has(const char *text)
{
    file_data[file_size < FILE_CAP ? file_size : FILE_CAP - 1u] = 0;
    return strstr(file_data, text) != 0;
}

static struct nlr_journal *journal_new(void)
{
    struct nlr_journal *j = calloc(1, sizeof *j);
    if (!j)
        abort();
    return j;
}

/* ---- the formatter ------------------------------------------------------------- */

static uint32_t fmt(char *out, uint32_t cap, const char *f, ...)
{
    va_list ap;
    va_start(ap, f);
    uint32_t n = nlr_journal_format(out, cap, f, ap);
    va_end(ap);
    return n;
}

static void test_format(void)
{
    char out[64];
    fmt(out, sizeof out, "%d %u %x %s %c %%", -42, 4000000000u, 0xbeefu, "ab", 'Z');
    CHECK(!strcmp(out, "-42 4000000000 beef ab Z %"));
    fmt(out, sizeof out, "%lx %ld %llu", 0x123456789abull, -5ll, 18446744073709551615ull);
    CHECK(!strcmp(out, "123456789ab -5 18446744073709551615"));
    fmt(out, sizeof out, "%d %s", (int)0x80000000, (const char *)0);
    CHECK(!strcmp(out, "-2147483648 (null)"));
    /* cut at the buffer, the full length reported */
    char small[8];
    uint32_t n = fmt(small, sizeof small, "%s", "0123456789");
    CHECK(n == 10 && !strcmp(small, "0123456"));
    /* an unknown conversion and a lone % at the end */
    fmt(out, sizeof out, "a%qb%");
    CHECK(!strcmp(out, "a?b"));
}

/* ---- the ring and the file ------------------------------------------------- */

static void test_flush(void)
{
    card_reset();
    struct nlr_journal *j = journal_new();
    /* no file named: nothing written, nothing taken from the card */
    nlr_journal(j, "one");
    svc.journal_path = 0;
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_NOT_READY && !opens_rw && !opens_create);
    svc.journal_path = "A:\\NLOADER\\LOADER.LOG";
    /* the boot's first flush starts the file when there is none */
    clock_now = 1234;
    nlr_journal(j, "two %d", 2);
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK);
    CHECK(opens_create == 1 && count_lines() == 2);
    CHECK(file_has("       0 one\n") && file_has("    1234 two 2\n"));
    /* nothing new: the card is not asked */
    int before = opens_rw;
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && opens_rw == before);
    /* every_ms keeps a flush from coming sooner */
    nlr_journal(j, "three");
    clock_now = 2000;
    CHECK(nlr_journal_flush(j, &svc, 2000u) == NLR_OK && count_lines() == 2);
    clock_now = 3300;
    CHECK(nlr_journal_flush(j, &svc, 2000u) == NLR_OK && count_lines() == 3);
    /* later flushes append, and never create: a file that does not open
     * is a failure, not a reason to start it again */
    open_fail = 1;
    nlr_journal(j, "four");
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_IO && j->failures == 1);
    CHECK(opens_create == 1 && count_lines() == 3);
    open_fail = 0;
    nlr_journal(j, "five");
    /* the line a failed flush held waited for this one */
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && count_lines() == 5);
    CHECK(file_has("four\n") && file_has("five\n"));
    free(j);

    /* the next boot appends to what the last one left */
    j = journal_new();
    nlr_journal(j, "next boot");
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && opens_create == 1 && count_lines() == 6);
    free(j);

    /* a file past the limit is started afresh by a boot's first flush */
    j = journal_new();
    fake_size = NLR_JOURNAL_FILE_MAX + 1u;
    nlr_journal(j, "fresh");
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && opens_create == 2 && count_lines() == 1);
    free(j);

    /* no card: the boot's first flush fails, and so does its create */
    j = journal_new();
    card_gone = 1;
    nlr_journal(j, "no card");
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_IO && j->failures == 1);
    free(j);
}

static void test_lost(void)
{
    card_reset();
    struct nlr_journal *j = journal_new();
    for (uint32_t n = 0; n < NLR_JOURNAL_LINES + 44u; n++)
        nlr_journal(j, "line %u", n);
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK);
    CHECK(count_lines() == NLR_JOURNAL_LINES + 1u);
    CHECK(file_has("(44 lines lost before this)") && !file_has("line 43\n") &&
          file_has("line 44\n") && file_has("line 299\n"));
    CHECK(j->lost == 44u);
    /* a slot still being written stops the flush there */
    nlr_journal(j, "done");
    nlr_journal(j, "half");
    j->line[(j->tail - 1u) % NLR_JOURNAL_LINES].seq = 0;
    uint32_t lines = count_lines();
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && count_lines() == lines + 1u);
    CHECK(file_has("done") && !file_has("half"));
    j->line[(j->tail - 1u) % NLR_JOURNAL_LINES].seq = j->tail;
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && file_has("half"));
    /* a long line is cut to the slot */
    nlr_journal(j, "%s", "0123456789012345678901234567890123456789012345678901234567890123456789");
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK &&
          file_has(" 0123456789012345678901234567890123456789012345678901234\n"));
    /* a line added while the flush writes goes out with this flush, not
     * the next one */
    inject = j;
    nlr_journal(j, "before");
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && file_has("before\n") &&
          file_has("added during the write\n") && j->sent == j->tail);
    /* a null journal takes nothing and never crashes */
    nlr_journal(0, "nothing");
    CHECK(nlr_journal_flush(0, &svc, 0) == NLR_NOT_READY);
    free(j);
}

/* Held (the NLoader switch off): a flush asks the card nothing and keeps
 * the lines; released, the next flush writes what the ring still has. */
static void test_hold(void)
{
    card_reset();
    struct nlr_journal *j = journal_new();
    nlr_journal_hold(j, 1u);
    nlr_journal(j, "boot");
    nlr_journal(j, "pass stopped: -8");
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK);
    CHECK(!opens_rw && !opens_create && !file_exists && !file_size && j->sent == 0);
    CHECK(nlr_journal_flush(j, &svc, 2000u) == NLR_OK && !opens_rw && !opens_create);
    nlr_journal_hold(j, 0u);
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && opens_create == 1 && count_lines() == 2);
    CHECK(file_has("pass stopped: -8\n"));
    nlr_journal_hold(j, 2u); /* any nonzero holds */
    nlr_journal(j, "later");
    int before = opens_rw + opens_create;
    CHECK(nlr_journal_flush(j, &svc, 0) == NLR_OK && opens_rw + opens_create == before);
    CHECK(count_lines() == 2);
    nlr_journal_hold(0, 1u); /* a null journal: nothing to hold */
    free(j);
}

int main(void)
{
    test_format();
    test_flush();
    test_lost();
    test_hold();
    if (failures) {
        printf("%d journal checks failed\n", failures);
        return 1;
    }
    printf("journal behavior tests passed\n");
    return 0;
}
