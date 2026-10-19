#include "wad.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static uint8_t file_bytes[2048];
static uint32_t stored_size, position, chunk_size, reads, seeks, closes;
static uint32_t failure_read, zero_read, oversized_read;
static int reported_size, open_error, seek_error, wrong_seek, close_error, opened;
static char shown[32], logged[64];

static void put_word(uint32_t at, uint32_t value)
{
    for (uint32_t n = 0; n < 4; n++)
        file_bytes[at + n] = (uint8_t)(value >> (n * 8));
}

static void entry(uint32_t index, uint32_t offset, uint32_t size, const char *name)
{
    uint32_t at = 64u + index * 16u;
    put_word(at, offset);
    put_word(at + 4u, size);
    memset(file_bytes + at + 8u, 0, 8);
    memcpy(file_bytes + at + 8u, name, strlen(name));
}

static void fixture(void)
{
    memset(file_bytes, 0, sizeof file_bytes);
    memcpy(file_bytes, "IWAD", 4);
    put_word(4, 4);
    put_word(8, 64);
    memcpy(file_bytes + 12, "older", 5);
    memcpy(file_bytes + 32, "lastDATA", 8);
    entry(0, 12, 5, "DUP");
    entry(1, INT32_MAX, 0, "EMPTY");
    entry(2, 33, 4, "OVERLAP");
    entry(3, 32, 8, "DUP");
    stored_size = reported_size = 128;
    position = chunk_size = reads = seeks = closes = 0;
    failure_read = zero_read = oversized_read = 0;
    open_error = seek_error = wrong_seek = close_error = opened = 0;
    shown[0] = logged[0] = 0;
}

static int file_open(const char *path, uint32_t mode)
{
    assert(strcmp(path, "DOOM.WAD") == 0);
    assert(mode == 0);
    assert(!opened);
    if (open_error)
        return -NLR_API_EIO;
    opened = 1;
    return 7;
}

static int file_seek(int fd, int64_t offset, int whence)
{
    assert(opened && fd == 7);
    seeks++;
    if (seek_error)
        return -NLR_API_EIO;
    if (whence == NLR_SEEK_END) {
        assert(offset == 0);
        return reported_size;
    }
    assert(whence == NLR_SEEK_SET && offset >= 0 && offset <= INT32_MAX);
    position = (uint32_t)offset;
    return wrong_seek ? (int)position + 1 : (int)position;
}

static int file_read(int fd, void *buffer, uint32_t size)
{
    assert(opened && fd == 7 && size && buffer);
    reads++;
    if (reads == failure_read)
        return -NLR_API_EIO;
    if (reads == zero_read)
        return 0;
    if (reads == oversized_read)
        return (int)size + 1;
    if (position >= stored_size)
        return -NLR_API_EIO;
    uint32_t count = stored_size - position;
    if (count > size)
        count = size;
    if (chunk_size && count > chunk_size)
        count = chunk_size;
    memcpy(buffer, file_bytes + position, count);
    position += count;
    return (int)count;
}

static int file_close(int fd)
{
    assert(opened && fd == 7);
    closes++;
    if (close_error)
        return -1;
    opened = 0;
    return 0;
}

static int draw_text(int x, int y, const char *text)
{
    assert(x == 0 && y == 0);
    assert(strlen(text) < sizeof shown);
    strcpy(shown, text);
    return 0;
}

static void log_text(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int size = vsnprintf(logged, sizeof logged, format, args);
    va_end(args);
    assert(size >= 0 && size <= (int)NLR_API_LOG_MAX);
}

static const struct nlr_api api = {
    .abi = NLR_ABI_VERSION,
    .fs_open = file_open,
    .fs_read = file_read,
    .fs_seek = file_seek,
    .fs_close = file_close,
    .ui_draw_text = draw_text,
    .log = log_text,
};

static void expect_open_result(int expected)
{
    struct nlr_wad wad;
    nlr_wad_init(&wad);
    assert(nlr_wad_open(&wad, &api, "DOOM.WAD") == expected);
    if (expected) {
        assert(!wad.ready);
        assert(closes == (open_error ? 0u : 1u));
        assert(!opened);
    } else {
        assert(wad.ready && opened);
        assert(nlr_wad_close(&wad) == NLR_WAD_OK);
        assert(!opened);
    }
}

static void valid_and_random_access(void)
{
    for (uint32_t is_patch = 0; is_patch < 2; is_patch++) {
        fixture();
        file_bytes[0] = is_patch ? 'P' : 'I';
        chunk_size = 3;
        struct nlr_wad wad;
        nlr_wad_init(&wad);
        assert(nlr_wad_open(&wad, &api, "DOOM.WAD") == NLR_WAD_OK);
        assert(wad.lump_count == 4 && wad.file_size == 128);
        assert(reads > 20); /* forced short reads were retried */
        assert(nlr_wad_open(&wad, &api, "DOOM.WAD") == NLR_WAD_BUSY);
        uint32_t index = UINT32_MAX;
        assert(nlr_wad_find(&wad, "dup", &index) == NLR_WAD_OK && index == 3);
        assert(nlr_wad_find(&wad, "missing", &index) == NLR_WAD_NOT_FOUND && index == 3);
        assert(nlr_wad_find(&wad, "123456789", &index) == NLR_WAD_ARGUMENT);
        assert(nlr_wad_find(&wad, "", &index) == NLR_WAD_ARGUMENT);
        assert(nlr_wad_find(&wad, "A\n", &index) == NLR_WAD_ARGUMENT);
        uint8_t buffer[12];
        memset(buffer, 0x5a, sizeof buffer);
        assert(nlr_wad_read(&wad, index, 1, buffer + 2, 5) == NLR_WAD_OK);
        assert(memcmp(buffer + 2, "astDA", 5) == 0);
        assert(buffer[1] == 0x5a && buffer[7] == 0x5a);
        assert(nlr_wad_read(&wad, 0, 0, buffer, 5) == NLR_WAD_OK);
        assert(memcmp(buffer, "older", 5) == 0);
        assert(nlr_wad_read(&wad, 0, 4, buffer, 2) == NLR_WAD_BOUNDS);
        assert(nlr_wad_read(&wad, 0, UINT32_MAX, buffer, 1) == NLR_WAD_BOUNDS);
        assert(nlr_wad_read(&wad, 0, 0, buffer, UINT32_MAX) == NLR_WAD_BOUNDS);
        assert(nlr_wad_read(&wad, 4, 0, buffer, 1) == NLR_WAD_BOUNDS);
        assert(nlr_wad_read(&wad, 0, 0, 0, 1) == NLR_WAD_ARGUMENT);
        assert(nlr_wad_read(&wad, 1, 0, 0, 0) == NLR_WAD_OK);
        assert(nlr_wad_read(&wad, 0, 5, 0, 0) == NLR_WAD_OK);
        /* A changed directory is checked again before a payload read. */
        put_word(64, 126);
        assert(nlr_wad_read(&wad, 0, 0, buffer, 1) == NLR_WAD_BOUNDS);
        assert(nlr_wad_close(&wad) == NLR_WAD_OK);
        assert(nlr_wad_close(&wad) == NLR_WAD_OK && closes == 1);
        assert(nlr_wad_read(&wad, 0, 0, buffer, 1) == NLR_WAD_ARGUMENT);
    }
    fixture();
    memcpy(file_bytes, "PWAD", 4);
    put_word(4, 0);
    put_word(8, 12);
    reported_size = stored_size = 12;
    expect_open_result(NLR_WAD_OK);
    fixture();
    entry(0, 12, 5, "EIGHTCHR");
    struct nlr_wad wad;
    nlr_wad_init(&wad);
    assert(nlr_wad_open(&wad, &api, "DOOM.WAD") == 0);
    uint32_t index = UINT32_MAX;
    assert(nlr_wad_find(&wad, "eightchr", &index) == 0 && index == 0);
    assert(nlr_wad_close(&wad) == 0);
}

static void malformed_files(void)
{
    fixture(); open_error = 1; expect_open_result(NLR_WAD_OPEN);
    fixture(); reported_size = stored_size = 11; expect_open_result(NLR_WAD_BOUNDS);
    fixture(); file_bytes[0] = 'X'; expect_open_result(NLR_WAD_FORMAT);
    fixture(); put_word(4, UINT32_MAX); expect_open_result(NLR_WAD_FORMAT);
    fixture(); put_word(8, UINT32_MAX); expect_open_result(NLR_WAD_FORMAT);
    fixture(); put_word(4, 0x10000001u); expect_open_result(NLR_WAD_BOUNDS);
    fixture(); put_word(8, 129); expect_open_result(NLR_WAD_BOUNDS);
    fixture(); put_word(8, 65); expect_open_result(NLR_WAD_BOUNDS);
    fixture(); put_word(64, UINT32_MAX); expect_open_result(NLR_WAD_FORMAT);
    fixture(); put_word(68, UINT32_MAX); expect_open_result(NLR_WAD_FORMAT);
    fixture(); put_word(64, 127); expect_open_result(NLR_WAD_BOUNDS);
    fixture(); put_word(64, INT32_MAX); put_word(68, INT32_MAX);
    expect_open_result(NLR_WAD_BOUNDS);
    fixture(); put_word(4, NLR_WAD_MAX_LUMPS + 1u);
    reported_size = 64 + (NLR_WAD_MAX_LUMPS + 1u) * 16;
    expect_open_result(NLR_WAD_LIMIT);
    fixture(); stored_size = 127; expect_open_result(NLR_WAD_IO);
    fixture(); failure_read = 1; expect_open_result(NLR_WAD_IO);
    fixture(); failure_read = 2; expect_open_result(NLR_WAD_IO);
    fixture(); zero_read = 1; expect_open_result(NLR_WAD_IO);
    fixture(); oversized_read = 1; expect_open_result(NLR_WAD_IO);
    fixture(); seek_error = 1; expect_open_result(NLR_WAD_IO);
    fixture(); wrong_seek = 1; expect_open_result(NLR_WAD_IO);
}

static void chunk_boundary(void)
{
    fixture();
    put_word(4, 65);
    reported_size = stored_size = 64 + 65 * 16;
    for (uint32_t n = 0; n < 65; n++)
        entry(n, 12, 5, "DUP");
    struct nlr_wad wad;
    nlr_wad_init(&wad);
    assert(nlr_wad_open(&wad, &api, "DOOM.WAD") == 0 && reads == 4);
    uint32_t index = 0;
    assert(nlr_wad_find(&wad, "DUP", &index) == 0 && index == 64);
    assert(nlr_wad_close(&wad) == 0);
    fixture();
    put_word(4, 65);
    reported_size = stored_size = 64 + 65 * 16;
    for (uint32_t n = 0; n < 65; n++)
        entry(n, 12, 5, "DUP");
    entry(64, stored_size, 1, "LASTBAD");
    expect_open_result(NLR_WAD_BOUNDS);
}

static void close_and_app_results(void)
{
    fixture();
    assert(nlr_app_main(&api) == 0);
    assert(strcmp(shown, "WAD ready") == 0 && !opened && closes == 1);
    /* Independent fixed FNV results for "older" and "lastDATA". */
    assert(strcmp(logged, "W 4 1a7c1461 f5ea00c9") == 0);
    fixture();
    put_word(4, 0);
    assert(nlr_app_main(&api) == 0);
    assert(strcmp(logged, "W 0 0 0") == 0);
    fixture();
    failure_read = 5; /* first payload, after header, directory, two entry reads */
    assert(nlr_app_main(&api) == NLR_WAD_IO);
    assert(strcmp(shown, "WAD rejected") == 0 && !opened && closes == 1);
    fixture();
    close_error = 1;
    assert(nlr_app_main(&api) == NLR_WAD_CLOSE);
    assert(strcmp(shown, "WAD rejected") == 0 && opened && closes == 1);
    fixture();
    file_bytes[0] = 'X';
    close_error = 1;
    struct nlr_wad wad;
    nlr_wad_init(&wad);
    assert(nlr_wad_open(&wad, &api, "DOOM.WAD") == NLR_WAD_CLOSE);
    assert(!wad.ready && opened && wad.fd == 7 && closes == 1);
    close_error = 0;
    assert(nlr_wad_close(&wad) == 0 && !opened && closes == 2);
    fixture();
    file_bytes[0] = 'X'; close_error = 1;
    assert(nlr_app_main(&api) == NLR_WAD_CLOSE && closes == 1);
    fixture();
    struct nlr_api broken = api;
    broken.fs_read = 0;
    nlr_wad_init(&wad);
    assert(nlr_wad_open(&wad, &broken, "DOOM.WAD") == NLR_WAD_API);
    assert(!opened && !closes);
    assert(nlr_app_main(0) == NLR_WAD_API);
}

static void abi_prefix_compatibility(void)
{
    for (uint32_t version = 0; version <= NLR_ABI_VERSION + 1u; version++) {
        fixture();
        struct nlr_api candidate = api;
        candidate.abi = version;
        struct nlr_wad wad;
        nlr_wad_init(&wad);
        int expected = version < 2u ? NLR_WAD_API : NLR_WAD_OK;
        assert(nlr_wad_open(&wad, &candidate, "DOOM.WAD") == expected);
        if (version >= 2u)
            assert(nlr_wad_close(&wad) == NLR_WAD_OK);
        else
            assert(!opened && !reads && !closes);
        fixture();
        assert(nlr_app_main(&candidate) == expected);
    }
}

int main(void)
{
    abi_prefix_compatibility();
    valid_and_random_access();
    malformed_files();
    chunk_boundary();
    close_and_app_results();
    puts("WAD tests passed");
    return 0;
}
