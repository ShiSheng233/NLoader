#include "nlr.h"
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nlr_file;
typedef struct nlr_file LFILE;
extern const struct nlr_api *nlr_libc_api;
extern int nlr_test_errno;
extern int nlr_libc_arena(size_t, size_t);
extern size_t nlr_libc_arena_size(void);
extern void *nlr_test_malloc(size_t);
extern void *nlr_test_calloc(size_t, size_t);
extern void *nlr_test_realloc(void *, size_t);
extern void nlr_test_free(void *);
extern int nlr_test_snprintf(char *, size_t, const char *, ...);
extern int nlr_test_sscanf(const char *, const char *, ...);
extern long nlr_test_strtol(const char *, char **, int);
extern unsigned long nlr_test_strtoul(const char *, char **, int);
extern double nlr_test_strtod(const char *, char **);
extern LFILE *nlr_test_stdin;
extern LFILE *nlr_test_stdout;
extern LFILE *nlr_test_fopen(const char *, const char *);
extern int nlr_test_fclose(LFILE *);
extern size_t nlr_test_fread(void *, size_t, size_t, LFILE *);
extern int nlr_test_fseek(LFILE *, long, int);
extern long nlr_test_ftell(LFILE *);
extern int nlr_test_feof(LFILE *);
extern int nlr_test_ferror(LFILE *);
extern void nlr_test_clearerr(LFILE *);
extern int nlr_test_fprintf(LFILE *, const char *, ...);
extern int nlr_test_fputs(const char *, LFILE *);
extern int nlr_test_fputc(int, LFILE *);
static _Alignas(16) unsigned char arena[512];
static unsigned allocation_calls, read_calls, close_calls;
static long position;
static int open_handle, fail_close, bad_read, bad_seek;
static const char contents[] = "0123456789";

static void *allocate(uint32_t bytes, uint32_t attrs)
{
    assert(!attrs);
    ++allocation_calls;
    return bytes == sizeof arena ? arena : NULL;
}
static void release(void *p) { assert(p == arena); }
static int file_open(const char *path, uint32_t mode)
{
    assert(!mode && !open_handle);
    if (strcmp(path, "DOOM.WAD"))
        return -NLR_API_EIO;
    open_handle = 1;
    position = 0;
    return 7;
}
static int file_read(int fd, void *out, uint32_t n)
{
    assert(fd == 7 && open_handle && n > 0);
    ++read_calls;
    if (bad_read)
        return (int)n + 1;
    long remaining = 10 - position;
    if (remaining <= 0)
        return 0;
    if (n > 3u)
        n = 3u;
    if (n > (unsigned long)remaining)
        n = (uint32_t)remaining;
    memcpy(out, contents + position, n);
    position += n;
    return (int)n;
}
static int file_seek(int fd, int64_t offset, int whence)
{
    assert(fd == 7 && open_handle && (whence == 0 || whence == 2));
    int64_t target = offset + (whence == 2 ? 10 : 0);
    if (target < 0 || target > INT_MAX)
        return -NLR_API_EINVAL;
    position = (long)target;
    return (int)target + bad_seek;
}
static int file_close(int fd)
{
    assert(fd == 7 && open_handle);
    ++close_calls;
    if (fail_close)
        return -1;
    open_handle = 0;
    return 0;
}
static void log_line(const char *fmt, ...) { assert(!strcmp(fmt, "%s")); }

int main(void)
{
    struct nlr_api api = {.abi = 4,
                         .mem_alloc = allocate,
                         .mem_free = release,
                         .fs_open = file_open,
                         .fs_read = file_read,
                         .fs_seek = file_seek,
                         .fs_close = file_close,
                         .log = log_line};
    nlr_libc_api = &api;
    assert(nlr_libc_arena(100, 1) == -1 && allocation_calls == 0);
    assert(nlr_libc_arena(100, 200) == -1 && allocation_calls == 0);
    assert(nlr_libc_arena((size_t)UINT32_MAX + 1, 512) == -1);
    /* 1024, 768, 576, then the exact permitted floor, which used to be skipped. */
    assert(nlr_libc_arena(1024, 512) == 0 && allocation_calls == 4);
    assert(nlr_libc_arena_size() == 512);
    assert(nlr_libc_arena(512, 512) == -1 && allocation_calls == 4);
    assert(!nlr_test_malloc(SIZE_MAX - 10));
    assert(!nlr_test_calloc(SIZE_MAX, 2));
    unsigned char *block = nlr_test_calloc(17, 3);
    assert(block);
    for (unsigned i = 0; i < 51; ++i)
        assert(block[i] == 0);
    memcpy(block, "alive", 6);
    assert(!nlr_test_realloc(block, SIZE_MAX) && !strcmp((char *)block, "alive"));
    assert(!nlr_test_realloc(block, 0));
    block = nlr_test_malloc(400);
    assert(block);
    nlr_test_free(block);

    char text[128];
    assert(nlr_test_snprintf(text, sizeof text, "%.100u", 1u) == 100);
    assert(strlen(text) == 100 && text[99] == '1' && text[0] == '0');
    assert(nlr_test_snprintf(text, 4, "%.100u", 1u) == 100 && !strcmp(text, "000"));
    assert(nlr_test_snprintf(text, sizeof text, "%.0u", 0u) == 0 && !text[0]);
    assert(nlr_test_snprintf(text, sizeof text, "%*u", -5, 3u) == 5 && !strcmp(text, "3    "));
    assert(nlr_test_snprintf(text, sizeof text, "%*u", INT_MIN, 3u) == -1);
    assert(nlr_test_snprintf(text, sizeof text, "%99999999999u", 3u) == -1);

    long number = 0;
    double real = 0;
    short small = 0;
    unsigned octal = 0;
    char bounded[4] = {0}, following = 0;
    assert(nlr_test_sscanf("123456789012 1.25 -12 17 abcZ", "%ld %lf %hd %o %3s%c",
                          &number, &real, &small, &octal, bounded, &following) == 6);
    assert(number == 123456789012L && real == 1.25 && small == -12 && octal == 15);
    assert(!strcmp(bounded, "abc") && following == 'Z');
    assert(nlr_test_sscanf("20 11", "%*d %d", &octal) == 1 && octal == 11);
    const char *invalid = " +x";
    char *end;
    assert(nlr_test_strtol(invalid, &end, 10) == 0 && end == invalid);
    assert(nlr_test_strtod(invalid, &end) == 0 && end == invalid);
    assert(nlr_test_strtol("-9223372036854775808", &end, 10) == LONG_MIN && !*end);
    assert(nlr_test_strtoul("18446744073709551615", &end, 10) == ULONG_MAX && !*end);
    assert(nlr_test_strtoul("-18446744073709551616", &end, 10) == ULONG_MAX && !*end);

    assert(!nlr_test_fopen("DOOM.WAD", "rb+"));
    assert(!nlr_test_fopen("DOOM.WAD", ""));
    assert(!nlr_test_fopen("missing", "rb") && nlr_test_errno == NLR_API_EIO);
    LFILE *file = nlr_test_fopen("DOOM.WAD", "rb");
    assert(file);
    assert(nlr_test_fread(text, 1, 10, file) == 10 && read_calls == 4);
    assert(!memcmp(text, contents, 10) && !nlr_test_feof(file));
    assert(nlr_test_fread(text, 1, 1, file) == 0 && nlr_test_feof(file));
    assert(nlr_test_fseek(file, 20, SEEK_SET) == 0);
    unsigned previous_reads = read_calls;
    assert(nlr_test_fread(text, 1, 1, file) == 0 && read_calls == previous_reads);
    assert(nlr_test_fseek(NULL, 1, SEEK_CUR) == -1);
    assert(nlr_test_fseek(file, LONG_MAX, SEEK_CUR) == -1);
    assert(nlr_test_fseek(file, 0, 99) == -1);
    assert(nlr_test_fseek(file, 0, SEEK_SET) == 0);
    assert(nlr_test_fread(text, SIZE_MAX, 2, file) == 0 && nlr_test_ferror(file));
    nlr_test_clearerr(file);
    assert(!nlr_test_ferror(file));
    bad_read = 1;
    assert(nlr_test_fread(text, 1, 1, file) == 0 && nlr_test_ferror(file));
    bad_read = 0;
    bad_seek = 1;
    assert(nlr_test_fseek(file, 3, SEEK_SET) == -1 && nlr_test_ftell(file) == 0);
    bad_seek = 0;
    assert(nlr_test_fprintf(file, "no writes") == EOF && nlr_test_ferror(file));
    assert(nlr_test_fputs("no writes", file) == EOF);
    assert(nlr_test_fputc('x', file) == EOF);
    assert(nlr_test_fprintf(nlr_test_stdin, "no writes") == EOF);
    assert(nlr_test_fprintf(nlr_test_stdout, "ok\n") == 3);
    fail_close = 1;
    assert(nlr_test_fclose(file) == EOF && open_handle);
    fail_close = 0;
    assert(nlr_test_fclose(file) == 0 && !open_handle && close_calls == 2);
    puts("NLoader libc: allocation, formatting, scanning and read-only file regressions passed");
    return 0;
}
