/* ABI 5 card-write acceptance program for a native-card model (Z8).
 *
 * Every step records what it saw and the record is written to CARDW.LOG
 * (a later run writes CARDW2.LOG beside it), so the card itself carries the
 * evidence. The returned value is the first step that did not behave, or 0.
 *
 *   1 first run: CARDW.TXT is created with NLR_OPEN_WRITE, 20000 bytes in
 *     one call -- more than one native request carries -- and read back
 *   2 later run: the first run's CARDW.TXT is still there, byte for byte;
 *     NLR_OPEN_UPDATE then overwrites its first 16 bytes in place, and the
 *     whole file reads back with only those bytes changed
 *   3 the refusals: the loader's own files for writing (-EACCES), a second
 *     spelling of one (-EINVAL), and a read of them still allowed
 *   4 the firmware-code channel, which this model does not declare yet:
 *     every call answers -ENOSYS
 */

#include "nlr.h"

#define DATA_BYTES 20000u
#define UPDATE_BYTES 16u

static const char data_path[] = "CARDW.TXT";
static const char log_path[] = "CARDW.LOG";
static const char log_path_2[] = "CARDW2.LOG";

static uint8_t pattern(uint32_t n)
{
    return (uint8_t)(n * 7u + 3u + (n >> 8));
}

#define RECORD_BYTES 640u
struct record {
    char text[RECORD_BYTES];
    uint32_t used;
    int32_t failed;
};

static void put_text(struct record *r, const char *text)
{
    while (*text && r->used < RECORD_BYTES - 1u)
        r->text[r->used++] = *text++;
}

static void put_hex(struct record *r, uint64_t value)
{
    char digits[16];
    uint32_t n = 0;
    do {
        uint32_t digit = (uint32_t)(value & 15u);
        digits[n++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
        value >>= 4;
    } while (value && n < sizeof digits);
    while (n)
        if (r->used < RECORD_BYTES - 1u)
            r->text[r->used++] = digits[--n];
        else
            n--;
}

static void expect(struct record *r, int32_t step, int64_t seen, int64_t wanted,
                   const char *name)
{
    put_text(r, name);
    put_text(r, " ");
    if (seen < 0) {
        put_text(r, "-");
        put_hex(r, (uint64_t)-seen);
    } else {
        put_hex(r, (uint64_t)seen);
    }
    put_text(r, seen == wanted ? "\n" : " FAIL\n");
    if (seen != wanted && !r->failed)
        r->failed = step;
}

/* The whole file into `buffer` (DATA_BYTES + 1 so a longer file shows),
 * or a negative error. */
static int read_all(const struct nlr_api *api, const char *path, uint8_t *buffer)
{
    int fd = api->fs_open(path, NLR_OPEN_READ);
    if (fd < 0)
        return fd;
    uint32_t total = 0;
    while (total < DATA_BYTES + 1u) {
        int got = api->fs_read(fd, buffer + total, DATA_BYTES + 1u - total);
        if (got <= 0)
            break;
        total += (uint32_t)got;
    }
    api->fs_close(fd);
    return (int)total;
}

/* 0 when buffer holds the pattern, with the first `changed` bytes 0xA5. */
static uint32_t mismatches(const uint8_t *buffer, uint32_t changed)
{
    uint32_t bad = 0;
    for (uint32_t n = 0; n < DATA_BYTES; n++)
        if (buffer[n] != (n < changed ? 0xa5u : pattern(n)))
            bad++;
    return bad;
}

int32_t nlr_app_main(const struct nlr_api *api)
{
    if (!api || api->abi < 5 || !api->fs_write) {
        if (api)
            api->ui_draw_text(0, 0, "cardw: no ABI 5 table");
        return 1;
    }
    struct record rec;
    rec.used = 0;
    rec.failed = 0;
    expect(&rec, 0, api->abi, api->abi, "abi");
    uint8_t *buffer = api->mem_alloc(DATA_BYTES + 1u, 0);
    if (!buffer) {
        api->ui_draw_text(0, 0, "cardw: no memory");
        return 1;
    }

    int existing = read_all(api, data_path, buffer);
    int later = existing >= 0;
    expect(&rec, 0, later, later, "later");
    if (!later) {
        /* 1: create, one large write, read back. */
        for (uint32_t n = 0; n < DATA_BYTES; n++)
            buffer[n] = pattern(n);
        int fd = api->fs_open(data_path, NLR_OPEN_WRITE);
        expect(&rec, 1, fd >= 0, 1, "create.open");
        if (fd >= 0) {
            expect(&rec, 1, api->fs_write(fd, buffer, DATA_BYTES), DATA_BYTES,
                   "create.write");
            expect(&rec, 1, api->fs_close(fd), 0, "create.close");
        }
        for (uint32_t n = 0; n < DATA_BYTES + 1u; n++)
            buffer[n] = 0;
        expect(&rec, 1, read_all(api, data_path, buffer), DATA_BYTES, "create.read");
        expect(&rec, 1, mismatches(buffer, 0), 0, "create.compare");
    } else {
        /* 2: the earlier run's file, then an in-place update. */
        expect(&rec, 2, existing, DATA_BYTES, "kept.size");
        uint32_t changed = buffer[0] == 0xa5u ? UPDATE_BYTES : 0;
        expect(&rec, 2, changed, changed, "kept.updated_before");
        expect(&rec, 2, mismatches(buffer, changed), 0, "kept.compare");
        uint8_t update[UPDATE_BYTES];
        for (uint32_t n = 0; n < UPDATE_BYTES; n++)
            update[n] = 0xa5u;
        int fd = api->fs_open(data_path, NLR_OPEN_UPDATE);
        expect(&rec, 2, fd >= 0, 1, "update.open");
        if (fd >= 0) {
            expect(&rec, 2, api->fs_write(fd, update, UPDATE_BYTES), UPDATE_BYTES,
                   "update.write");
            expect(&rec, 2, api->fs_close(fd), 0, "update.close");
        }
        for (uint32_t n = 0; n < DATA_BYTES + 1u; n++)
            buffer[n] = 0;
        expect(&rec, 2, read_all(api, data_path, buffer), DATA_BYTES, "update.read");
        expect(&rec, 2, mismatches(buffer, UPDATE_BYTES), 0, "update.compare");
    }

    /* 3: what writing refuses, and what reading still allows. */
    static const char *const own[] = {
        "STATE.NLS", "MANIFEST", "SAFE_MODE", "ENABLED", "AUTOLOAD_PENDING",
    };
    for (uint32_t n = 0; n < sizeof own / sizeof own[0]; n++) {
        expect(&rec, 3, api->fs_open(own[n], NLR_OPEN_WRITE), -NLR_API_EACCES,
               own[n]);
        expect(&rec, 3, api->fs_open(own[n], NLR_OPEN_UPDATE), -NLR_API_EACCES,
               own[n]);
    }
    expect(&rec, 3, api->fs_open("./STATE.NLS", NLR_OPEN_WRITE), -NLR_API_EINVAL,
           "dot.state");
    expect(&rec, 3, api->fs_open("MANIFEST.", NLR_OPEN_WRITE), -NLR_API_EINVAL,
           "trail.manifest");
    int manifest = api->fs_open("MANIFEST", NLR_OPEN_READ);
    expect(&rec, 3, manifest >= 0, 1, "manifest.read");
    if (manifest >= 0)
        api->fs_close(manifest);

    /* 4: the code channel is not declared for this model. */
    static const uint8_t word[4] = {0x1f, 0x20, 0x03, 0xd5};
    expect(&rec, 4, api->code_patch((void *)0x40200000UL, word, 4),
           -NLR_API_ENOSYS, "code.patch");
    expect(&rec, 4, api->code_hook((void *)0x40200000UL, word, (void *)read_all),
           -NLR_API_ENOSYS, "code.hook");
    expect(&rec, 4, api->code_unhook((void *)0x40200000UL), -NLR_API_ENOSYS,
           "code.unhook");
    expect(&rec, 0, rec.failed, 0, "failed");

    /* The record itself goes out through the same channel and is checked. */
    const char *path = later ? log_path_2 : log_path;
    uint32_t length = rec.used;
    int fd = api->fs_open(path, NLR_OPEN_WRITE);
    int written = fd < 0 ? fd : api->fs_write(fd, rec.text, length);
    int closed = fd < 0 ? fd : api->fs_close(fd);
    int back = read_all(api, path, buffer);
    int same = back == (int)length;
    for (uint32_t n = 0; same && n < length; n++)
        same = buffer[n] == (uint8_t)rec.text[n];
    api->mem_free(buffer);
    if (written != (int)length || closed != 0 || !same) {
        api->log("cardw: log %d %d %d", written, closed, back);
        api->ui_draw_text(0, 0, "cardw: log write failed");
        return rec.failed ? rec.failed : 9;
    }
    if (rec.failed) {
        api->log("cardw: step %d", rec.failed);
        api->ui_draw_text(0, 0, "cardw: see CARDW.LOG");
        return rec.failed;
    }
    api->log("cardw: ok %d", later);
    api->ui_draw_text(0, 0, later ? "cardw ok: kept + updated" : "cardw ok: created");
    return 0;
}
