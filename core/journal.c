#include "nlr/journal.h"
#include "nlr/services.h"

/* The loader's own log (nlr/journal.h).
 *
 * Adding a line takes the next slot of the ring with one atomic add and
 * marks it written with its number once the text is in: any task may add,
 * none waits, and a flush running meanwhile stops at the first slot not yet
 * written. A slot written again before a flush reached it (more than
 * NLR_JOURNAL_LINES lines between two flushes) is counted as lost, and the
 * file says how many.
 *
 * A flush that cannot write keeps its lines for the next one (the ring may
 * still overwrite them, and then they count as lost).
 *
 * The file is appended to across boots, so the boot a crash ended can be
 * read after the next start; each boot begins with a line saying so. The
 * first flush of a boot that finds the file past NLR_JOURNAL_FILE_MAX
 * starts it afresh. Only that first flush may create the file: a later
 * open that fails is a failure, never a reason to truncate what this boot
 * already wrote. */

static void put(char *out, uint32_t *n, uint32_t cap, char c)
{
    if (*n + 1u < cap)
        out[*n] = c;
    (*n)++;
}

static void put_number(char *out, uint32_t *n, uint32_t cap,
                       unsigned long long v, unsigned base)
{
    char digits[24];
    uint32_t k = 0;
    do {
        uint32_t d = (uint32_t)(v % base);
        digits[k++] = (char)(d < 10u ? '0' + d : 'a' + d - 10u);
        v /= base;
    } while (v && k < sizeof digits);
    while (k)
        put(out, n, cap, digits[--k]);
}

uint32_t nlr_journal_format(char *out, uint32_t cap, const char *fmt, va_list ap)
{
    uint32_t n = 0;
    if (!out || !cap)
        return 0;
    for (const char *p = fmt ? fmt : ""; *p; p++) {
        if (*p != '%') {
            put(out, &n, cap, *p);
            continue;
        }
        p++;
        int wide = 0;
        while (*p == 'l') {
            wide = 1;
            p++;
        }
        switch (*p) {
        case 'd': {
            long long v = wide ? va_arg(ap, long long) : (long long)va_arg(ap, int);
            unsigned long long magnitude = (unsigned long long)v;
            if (v < 0) {
                put(out, &n, cap, '-');
                magnitude = 0ull - magnitude;
            }
            put_number(out, &n, cap, magnitude, 10u);
            break;
        }
        case 'u':
        case 'x': {
            unsigned long long v = wide ? va_arg(ap, unsigned long long)
                                        : (unsigned long long)va_arg(ap, unsigned);
            put_number(out, &n, cap, v, *p == 'u' ? 10u : 16u);
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            for (s = s ? s : "(null)"; *s; s++)
                put(out, &n, cap, *s);
            break;
        }
        case 'c':
            put(out, &n, cap, (char)va_arg(ap, int));
            break;
        case '%':
            put(out, &n, cap, '%');
            break;
        case 0:
            p--; /* a lone % at the end */
            break;
        default:
            put(out, &n, cap, '?');
            break;
        }
    }
    out[n < cap ? n : cap - 1u] = 0;
    return n;
}

void nlr_journal(struct nlr_journal *j, const char *fmt, ...)
{
    if (!j)
        return;
    uint32_t index = __atomic_fetch_add(&j->tail, 1u, __ATOMIC_ACQ_REL);
    struct nlr_journal_line *l = &j->line[index % NLR_JOURNAL_LINES];
    __atomic_store_n(&l->seq, 0u, __ATOMIC_RELEASE);
    l->ms = nlr_clock_ms();
    va_list ap;
    va_start(ap, fmt);
    (void)nlr_journal_format(l->text, sizeof l->text, fmt, ap);
    va_end(ap);
    __atomic_store_n(&l->seq, index + 1u, __ATOMIC_RELEASE);
}

/* `line` as "   12345 text\n" at out + used; the new length. */
static uint32_t render(char *out, uint32_t used, uint32_t cap, uint32_t ms,
                       const char *text)
{
    char stamp[12];
    uint32_t k = 0;
    put_number(stamp, &k, sizeof stamp, ms, 10u);
    if (k >= sizeof stamp)
        k = sizeof stamp - 1u;
    for (uint32_t pad = k; pad < 8u; pad++)
        put(out, &used, cap, ' ');
    for (uint32_t i = 0; i < k; i++)
        put(out, &used, cap, stamp[i]);
    put(out, &used, cap, ' ');
    for (uint32_t i = 0; i < NLR_JOURNAL_TEXT && text[i]; i++)
        put(out, &used, cap, text[i]);
    put(out, &used, cap, '\n');
    return used < cap ? used : cap;
}

static uint32_t render_note(char *out, uint32_t used, uint32_t cap, uint32_t ms,
                            const char *fmt, ...)
{
    char text[NLR_JOURNAL_TEXT];
    va_list ap;
    va_start(ap, fmt);
    (void)nlr_journal_format(text, sizeof text, fmt, ap);
    va_end(ap);
    return render(out, used, cap, ms, text);
}

/* Write `bytes` at the end of the journal file (the boot's first write may
 * start it). */
static int append(struct nlr_journal *j, const struct nlr_services *s,
                  const char *data, uint32_t bytes)
{
    if (!s->file_open || !s->file_write || !s->file_close)
        return NLR_NOT_READY;
    int32_t fd = -1;
    if (s->file_open_rw && s->file_seek) {
        fd = s->file_open(s->journal_path, s->file_open_rw, 0);
        if (fd >= 0) {
            uint32_t size = 0;
            if (s->file_seek(fd, 2, 0, &size) != 0) {
                (void)s->file_close(fd);
                return NLR_IO;
            }
            if (!j->opened && size > NLR_JOURNAL_FILE_MAX) {
                (void)s->file_close(fd);
                fd = -1;
            }
        }
    }
    if (fd < 0) {
        /* only the boot's first write starts the file */
        if (j->opened || !s->file_open_write)
            return NLR_IO;
        fd = s->file_open(s->journal_path, s->file_open_write,
                          s->file_create_attributes);
        if (fd < 0)
            return NLR_IO;
    }
    /* out of the data cache before the card fetches it */
    if (bytes && s->cache_clean)
        s->cache_clean((void *)(uintptr_t)data, bytes);
    int result = NLR_OK;
    uint32_t written = 0;
    while (result == NLR_OK && written < bytes) {
        uint32_t done = 0;
        if (s->file_write(fd, data + written, bytes - written, &done) != 0 ||
            done == 0 || done > bytes - written)
            result = NLR_IO;
        else
            written += done;
    }
    if (s->file_close(fd) != 0 && result == NLR_OK)
        result = NLR_IO;
    if (result == NLR_OK)
        j->opened = 1;
    return result;
}

static int flush_once(struct nlr_journal *j, const struct nlr_services *s,
                      uint32_t every_ms, int *wrote);

/* A task that finds another flushing leaves its lines to it: the one
 * flushing looks again once it is done, so a line added meanwhile does not
 * wait for the next flush (there may be none: the camera may be about to
 * stop). */
void nlr_journal_hold(struct nlr_journal *j, uint32_t held)
{
    if (j)
        __atomic_store_n(&j->held, held ? 1u : 0u, __ATOMIC_RELEASE);
}

int nlr_journal_flush(struct nlr_journal *j, const struct nlr_services *s,
                      uint32_t every_ms)
{
    int wrote = 0;
    int result = flush_once(j, s, every_ms, &wrote);
    for (uint32_t again = 0; result == NLR_OK && wrote && again < 3u &&
         __atomic_load_n(&j->tail, __ATOMIC_ACQUIRE) != j->sent; again++)
        result = flush_once(j, s, 0, &wrote);
    return result;
}

static int flush_once(struct nlr_journal *j, const struct nlr_services *s,
                      uint32_t every_ms, int *wrote)
{
    *wrote = 0;
    if (!j || !s || !s->journal_path)
        return NLR_NOT_READY;
    if (__atomic_load_n(&j->held, __ATOMIC_ACQUIRE))
        return NLR_OK;
    uint32_t now = nlr_clock_ms();
    uint32_t tail = __atomic_load_n(&j->tail, __ATOMIC_ACQUIRE);
    if (tail == j->sent || (every_ms && now - j->flushed_at < every_ms))
        return NLR_OK;
    uint32_t idle = 0;
    if (!__atomic_compare_exchange_n(&j->busy, &idle, 1u, 0, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return NLR_BUSY;
    uint32_t from = j->sent, used = 0, lost = 0;
    const uint32_t cap = (uint32_t)sizeof j->out;
    if (tail - from > NLR_JOURNAL_LINES) {
        lost += tail - from - NLR_JOURNAL_LINES;
        from = tail - NLR_JOURNAL_LINES;
    }
    uint32_t k = from;
    for (; k != tail; k++) {
        const struct nlr_journal_line *l = &j->line[k % NLR_JOURNAL_LINES];
        uint32_t seq = __atomic_load_n(&l->seq, __ATOMIC_ACQUIRE);
        if (seq != k + 1u) {
            if (seq && seq - (k + 1u) < 0x80000000u) {
                lost++; /* written again by a later line */
                continue;
            }
            break; /* still being written: the next flush takes it */
        }
        char text[NLR_JOURNAL_TEXT];
        for (uint32_t i = 0; i < NLR_JOURNAL_TEXT; i++)
            text[i] = l->text[i];
        text[NLR_JOURNAL_TEXT - 1u] = 0;
        uint32_t ms = l->ms;
        if (__atomic_load_n(&l->seq, __ATOMIC_ACQUIRE) != k + 1u) {
            lost++;
            continue;
        }
        used = render(j->out, used, cap - 64u, ms, text);
    }
    if (lost)
        used = render_note(j->out, used, cap, now, "(%u lines lost before this)", lost);
    int result = used ? append(j, s, j->out, used) : NLR_OK;
    if (result == NLR_OK) {
        j->lost += lost;
        j->sent = k;
        *wrote = used != 0;
    } else {
        /* kept for the next flush; the ring may overwrite them meanwhile */
        j->failures++;
    }
    j->flushed_at = now;
    __atomic_store_n(&j->busy, 0u, __ATOMIC_RELEASE);
    return result;
}
