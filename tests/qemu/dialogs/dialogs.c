/*
 * dialogs: the Z 8 QEMU fixture for the camera's keyboard (ui_input) and
 * caution box (ui_caution), hosted on a plain ui_list page -- the page the
 * Z 8 already draws, so the fixture needs no row kinds (ABI 6 ui_rows).
 *
 *   Name: <text>     OK opens the keyboard on the text; save keeps it
 *   Question         a Yes / No caution, the cursor on No
 *   Message          a caution with OK only
 *   <last result>    what the last OK did
 *
 * The message is longer than the box takes (50 bytes), so its cut shows.
 * Back leaves. Every answer is also appended to APPS/DIALOGS.LOG, so the
 * card carries the program's own view of each step beside the screenshots.
 * The state lives on the stack (no writable static data).
 */
#include "nlr.h"

#define NAME_MAX 32u
#define LINE_MAX 48u

void *memset(void *dst, int c, unsigned long n)
{
    unsigned char *d = dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}

void *memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--)
        *d++ = *s++;
    return dst;
}

/* Copy `s` after `at` bytes of `d` (`size` bytes, always terminated). */
static uint32_t put(char *d, uint32_t size, uint32_t at, const char *s)
{
    while (s && *s && at + 1u < size)
        d[at++] = *s++;
    d[at] = 0;
    return at;
}

static uint32_t put_int(char *d, uint32_t size, uint32_t at, int32_t v)
{
    char digits[12];
    uint32_t n = 0;
    uint32_t u = v < 0 ? (uint32_t)-v : (uint32_t)v;
    do {
        digits[n++] = (char)('0' + u % 10u);
        u /= 10u;
    } while (u && n < sizeof digits);
    if (v < 0 && at + 1u < size)
        d[at++] = '-';
    while (n && at + 1u < size)
        d[at++] = digits[--n];
    d[at] = 0;
    return at;
}

static void log_line(const struct nlr_api *api, const char *line)
{
    uint32_t len = 0;
    while (line[len])
        len++;
    int fd = api->fs_open("APPS/DIALOGS.LOG", NLR_OPEN_UPDATE);
    if (fd < 0)
        fd = api->fs_open("APPS/DIALOGS.LOG", NLR_OPEN_WRITE);
    if (fd < 0)
        return;
    api->fs_seek(fd, 0, NLR_SEEK_END);
    api->fs_write(fd, line, len);
    api->fs_write(fd, "\n", 1);
    api->fs_close(fd);
}

/* "<what> <result> [<text>]" into `note` and the log. */
static void report(const struct nlr_api *api, char *note, const char *what,
                   int32_t result, const char *text)
{
    uint32_t at = put(note, LINE_MAX, 0, what);
    at = put(note, LINE_MAX, at, " ");
    if (result == (int32_t)NLR_LIST_BACK)
        at = put(note, LINE_MAX, at, "back");
    else
        at = put_int(note, LINE_MAX, at, result);
    if (text) {
        at = put(note, LINE_MAX, at, " ");
        put(note, LINE_MAX, at, text);
    }
    log_line(api, note);
}

/* Four labels into a table on the caller's stack, filled at run time (a
 * constant table of pointers would be writable static data). */
__attribute__((noinline)) static void four(const char **t, const char *a,
                                           const char *b, const char *c,
                                           const char *d)
{
    t[0] = a;
    t[1] = b;
    t[2] = c;
    t[3] = d;
}

int32_t nlr_app_main(const struct nlr_api *api)
{
    if (!api || api->abi < 6u || !api->ui_list || !api->ui_input ||
        !api->ui_caution || !api->fs_open)
        return 1;
    char name[NAME_MAX];
    char row0[LINE_MAX];
    char note[LINE_MAX];
    put(name, NAME_MAX, 0, "NL");
    put(note, LINE_MAX, 0, "Ready");
    log_line(api, "start");
    uint32_t selected = 0;
    for (;;) {
        put(row0, LINE_MAX, put(row0, LINE_MAX, 0, "Name: "), name);
        const char *rows[4];
        four(rows, row0, "Question", "Message", note);
        int32_t r = api->ui_list("Dialogs", rows, 4, selected);
        if (r == NLR_LIST_BACK) {
            log_line(api, "done");
            return 0;
        }
        if (r < 0) {
            report(api, note, "list", r, 0);
            return 2;
        }
        selected = (uint32_t)r;
        if (r == 0) {
            char text[NAME_MAX];
            put(text, NAME_MAX, 0, name);
            int32_t got = api->ui_input("Name", text, NAME_MAX, NLR_INPUT_ASCII);
            if (got >= 0)
                put(name, NAME_MAX, 0, text);
            report(api, note, "input", got, name);
        } else if (r == 1) {
            int32_t got = api->ui_caution(
                "Keep this name?\nYes keeps it, No resets it.", NLR_CAUTION_YES_NO);
            if (got == 0)
                put(name, NAME_MAX, 0, "NL");
            report(api, note, "question", got, name);
        } else if (r == 2) {
            /* 61 bytes: the box keeps the first 50 ("...itself, tru") and
             * breaks the line longer than 28 at its last space. */
            int32_t got = api->ui_caution(
                "The caution box is drawn by the camera itself, truncated here",
                NLR_CAUTION_OK);
            report(api, note, "message", got, 0);
        }
    }
}
