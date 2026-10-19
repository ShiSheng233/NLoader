/*
 * A small freestanding C library for programs running under NLoader.
 *
 * Everything that touches the outside world goes through the loader's API
 * table (nlr_libc_api, set by the program's entry before anything else):
 * memory comes from one arena taken with api->mem_alloc, files are the
 * loader's read-only card channel, stdout/stderr land in a console ring in
 * program memory (nlr_console, readable from a debugger) and, a line at a
 * time, in the loader's log. Nothing here names a firmware address.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "nlr.h"
#include "nlr_libc.h"

const struct nlr_api *nlr_libc_api;
int errno;

/* ---- memory and strings ------------------------------------------------- */

void *memcpy(void *d, const void *s, size_t n)
{
    uint8_t *dp = d;
    const uint8_t *sp = s;

    if (!(((uintptr_t)dp | (uintptr_t)sp) & 7)) {
        for (; n >= 8; n -= 8, dp += 8, sp += 8)
            *(uint64_t *)dp = *(const uint64_t *)sp;
    }
    while (n--)
        *dp++ = *sp++;
    return d;
}

void *memmove(void *d, const void *s, size_t n)
{
    uint8_t *dp = d;
    const uint8_t *sp = s;

    if (dp == sp || n == 0)
        return d;
    if (dp < sp || dp >= sp + n)
        return memcpy(d, s, n);
    while (n--)
        dp[n] = sp[n];
    return d;
}

void *memset(void *d, int c, size_t n)
{
    uint8_t *dp = d;
    uint64_t v = (uint8_t)c;

    v |= v << 8;
    v |= v << 16;
    v |= v << 32;
    while (n && ((uintptr_t)dp & 7)) {
        *dp++ = (uint8_t)c;
        n--;
    }
    for (; n >= 8; n -= 8, dp += 8)
        *(uint64_t *)dp = v;
    while (n--)
        *dp++ = (uint8_t)c;
    return d;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;

    for (; n; n--, x++, y++)
        if (*x != *y)
            return *x - *y;
    return 0;
}

void *memchr(const void *s, int c, size_t n)
{
    const uint8_t *p = s;

    for (; n; n--, p++)
        if (*p == (uint8_t)c)
            return (void *)p;
    return 0;
}

size_t strlen(const char *s)
{
    const char *p = s;

    while (*p)
        p++;
    return (size_t)(p - s);
}

size_t strnlen(const char *s, size_t n)
{
    size_t i = 0;

    while (i < n && s[i])
        i++;
    return i;
}

char *strcpy(char *d, const char *s)
{
    char *r = d;

    while ((*d++ = *s++))
        ;
    return r;
}

char *strncpy(char *d, const char *s, size_t n)
{
    size_t i = 0;

    for (; i < n && s[i]; i++)
        d[i] = s[i];
    for (; i < n; i++)
        d[i] = 0;
    return d;
}

char *strcat(char *d, const char *s)
{
    strcpy(d + strlen(d), s);
    return d;
}

char *strncat(char *d, const char *s, size_t n)
{
    char *p = d + strlen(d);

    while (n-- && *s)
        *p++ = *s++;
    *p = 0;
    return d;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (; n; n--, a++, b++) {
        if (*a != *b || !*a)
            return (unsigned char)*a - (unsigned char)*b;
    }
    return 0;
}

int strcasecmp(const char *a, const char *b)
{
    while (*a && tolower((unsigned char)*a) == tolower((unsigned char)*b))
        a++, b++;
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

int strncasecmp(const char *a, const char *b, size_t n)
{
    for (; n; n--, a++, b++) {
        int x = tolower((unsigned char)*a), y = tolower((unsigned char)*b);

        if (x != y || !x)
            return x - y;
    }
    return 0;
}

char *strchr(const char *s, int c)
{
    for (;; s++) {
        if (*s == (char)c)
            return (char *)s;
        if (!*s)
            return 0;
    }
}

char *strrchr(const char *s, int c)
{
    const char *r = 0;

    for (;; s++) {
        if (*s == (char)c)
            r = s;
        if (!*s)
            return (char *)r;
    }
}

char *strstr(const char *h, const char *n)
{
    size_t k = strlen(n);

    if (!k)
        return (char *)h;
    for (; *h; h++)
        if (!strncmp(h, n, k))
            return (char *)h;
    return 0;
}

size_t strspn(const char *s, const char *a)
{
    size_t i = 0;

    while (s[i] && strchr(a, s[i]))
        i++;
    return i;
}

size_t strcspn(const char *s, const char *r)
{
    size_t i = 0;

    while (s[i] && !strchr(r, s[i]))
        i++;
    return i;
}

char *strtok(char *s, const char *d)
{
    static char *next;

    if (s)
        next = s;
    if (!next)
        return 0;
    next += strspn(next, d);
    if (!*next)
        return next = 0;
    s = next;
    next += strcspn(next, d);
    if (*next)
        *next++ = 0;
    else
        next = 0;
    return s;
}

char *strdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = malloc(n);

    return d ? memcpy(d, s, n) : 0;
}

char *strerror(int e)
{
    (void)e;
    return "error";
}

/* ---- numbers ------------------------------------------------------------- */

static unsigned long parse_integer(const char *s, char **end, int base,
                                   int *negative, int *overflow_out, unsigned long limit)
{
    const char *original = s;
    unsigned long v = 0;
    int any = 0, overflow = 0;

    *negative = 0;
    *overflow_out = 0;
    if (base && (base < 2 || base > 36)) {
        errno = EINVAL;
        if (end)
            *end = (char *)original;
        return 0;
    }

    while (isspace((unsigned char)*s))
        s++;
    if (*s == '-' || *s == '+')
        *negative = *s++ == '-';
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] | 32) == 'x' &&
        isxdigit((unsigned char)s[2])) {
        s += 2;
        base = 16;
    } else if (base == 0) {
        base = s[0] == '0' ? 8 : 10;
    }
    for (;; s++) {
        int d = isdigit((unsigned char)*s) ? *s - '0'
              : isalpha((unsigned char)*s) ? (*s | 32) - 'a' + 10 : 99;

        if (d >= base)
            break;
        any = 1;
        if (v > (limit - (unsigned)d) / (unsigned)base)
            overflow = 1;
        else if (!overflow)
            v = v * (unsigned)base + (unsigned)d;
    }
    if (end)
        *end = (char *)(any ? s : original);
    if (overflow) {
        *overflow_out = 1;
        errno = ERANGE;
        return limit;
    }
    return v;
}

long strtol(const char *s, char **end, int base)
{
    int negative, overflow;
    const unsigned long maximum = (~0ul) >> 1;
    /* A magnitude one above LONG_MAX is valid only for the negative case. */
    unsigned long v = parse_integer(s, end, base, &negative, &overflow, maximum + 1ul);
    if (!negative && v > maximum) {
        errno = ERANGE;
        return (long)maximum;
    }
    if (negative && v == maximum + 1ul)
        return -((long)maximum) - 1;
    return negative ? -(long)v : (long)v;
}

unsigned long strtoul(const char *s, char **end, int base)
{
    int negative, overflow;
    unsigned long v = parse_integer(s, end, base, &negative, &overflow, ~0ul);
    return negative && !overflow ? 0ul - v : v;
}

double strtod(const char *s, char **end)
{
    const char *original = s;
    double v = 0, scale = 1, sign = 1;
    int any = 0;

    while (isspace((unsigned char)*s))
        s++;
    if (*s == '-' || *s == '+')
        sign = *s++ == '-' ? -1 : 1;
    while (isdigit((unsigned char)*s)) {
        any = 1;
        v = v * 10 + (*s++ - '0');
    }
    if (*s == '.') {
        s++;
        while (isdigit((unsigned char)*s)) {
            any = 1;
            scale /= 10;
            v += (*s++ - '0') * scale;
        }
    }
    if (end)
        *end = (char *)(any ? s : original);
    return sign * v;
}

int atoi(const char *s) { return (int)strtol(s, 0, 10); }
long atol(const char *s) { return strtol(s, 0, 10); }
double atof(const char *s) { return strtod(s, 0); }
int abs(int v) { return v < 0 ? -v : v; }
long labs(long v) { return v < 0 ? -v : v; }

static uint32_t rand_state = 1;
int rand(void)
{
    rand_state = rand_state * 1103515245u + 12345u;
    return (int)(rand_state >> 1);
}
void srand(unsigned seed) { rand_state = seed; }

void qsort(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *))
{
    uint8_t *b = base;

    /* Insertion sort: the program's arrays are small. */
    for (size_t i = 1; i < n; i++) {
        for (size_t j = i; j > 0 && cmp(b + (j - 1) * size, b + j * size) > 0; j--) {
            uint8_t *x = b + (j - 1) * size, *y = b + j * size;

            for (size_t k = 0; k < size; k++) {
                uint8_t t = x[k];

                x[k] = y[k];
                y[k] = t;
            }
        }
    }
}

/* ---- the arena allocator ------------------------------------------------- */

/* One block from the loader, carved first-fit. Every chunk carries a
 * 16-byte header; free chunks are kept in address order and merged. */
struct chunk {
    size_t size;            /* bytes including this header */
    struct chunk *next;     /* free list only */
};
#define CHUNK_HDR 16u
#define CHUNK_MIN 32u

static struct chunk *free_list;
static size_t arena_bytes;

int nlr_libc_arena(size_t want, size_t floor)
{
    if (!nlr_libc_api || !nlr_libc_api->mem_alloc || !nlr_libc_api->mem_free ||
        floor < CHUNK_MIN + 15u || floor > want || want > UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }
    if (arena_bytes) {
        errno = EBUSY;
        return -1;
    }
    for (size_t n = want;;) {
        void *p = nlr_libc_api->mem_alloc((uint32_t)n, 0);

        if (p) {
            uintptr_t a = ((uintptr_t)p + 15) & ~(uintptr_t)15;
            struct chunk *c = (struct chunk *)a;

            c->size = (n - (a - (uintptr_t)p)) & ~(size_t)15;
            c->next = 0;
            free_list = c;
            arena_bytes = c->size;
            return 0;
        }
        if (n == floor)
            break;
        size_t next = n - n / 4;
        n = next < floor ? floor : next;
    }
    errno = ENOMEM;
    return -1;
}

size_t nlr_libc_arena_size(void)
{
    return arena_bytes;
}

/* A block from the highest free chunk that fits, cut from that chunk's
 * top: large long-lived blocks gather at the top of the pool and leave the
 * low chunks to the small ones (z63). free() takes it as any other. */
void *nlr_libc_malloc_high(size_t n)
{
    if (n > SIZE_MAX - CHUNK_HDR - 15u) {
        errno = ENOMEM;
        return 0;
    }
    size_t need = (n + CHUNK_HDR + 15) & ~(size_t)15;
    struct chunk **pp, **best = 0, *c;

    if (need < CHUNK_MIN)
        need = CHUNK_MIN;
    for (pp = &free_list; (c = *pp); pp = &c->next)
        if (c->size >= need)
            best = pp;
    if (!best) {
        errno = ENOMEM;
        return 0;
    }
    c = *best;
    if (c->size - need >= CHUNK_MIN) {
        c->size -= need;
        c = (struct chunk *)((uint8_t *)c + c->size);
        c->size = need;
    } else {
        *best = c->next;
    }
    return (uint8_t *)c + CHUNK_HDR;
}

/* Bytes on the free list, and the largest free chunk (z63 diagnostics). */
size_t nlr_libc_free_bytes(size_t *largest)
{
    size_t total = 0, big = 0;
    for (struct chunk *c = free_list; c; c = c->next) {
        total += c->size;
        if (c->size > big)
            big = c->size;
    }
    if (largest)
        *largest = big;
    return total;
}

void *malloc(size_t n)
{
    if (n > SIZE_MAX - CHUNK_HDR - 15u) {
        errno = ENOMEM;
        return 0;
    }
    size_t need = (n + CHUNK_HDR + 15) & ~(size_t)15;
    struct chunk **pp, *c;

    if (need < CHUNK_MIN)
        need = CHUNK_MIN;
    for (pp = &free_list; (c = *pp); pp = &c->next) {
        if (c->size < need)
            continue;
        if (c->size - need >= CHUNK_MIN) {
            struct chunk *rest = (struct chunk *)((uint8_t *)c + need);

            rest->size = c->size - need;
            rest->next = c->next;
            *pp = rest;
            c->size = need;
        } else {
            *pp = c->next;
        }
        return (uint8_t *)c + CHUNK_HDR;
    }
    errno = ENOMEM;
    return 0;
}

void free(void *p)
{
    struct chunk *c, **pp, *prev = 0;

    if (!p)
        return;
    c = (struct chunk *)((uint8_t *)p - CHUNK_HDR);
    for (pp = &free_list; *pp && *pp < c; pp = &(*pp)->next)
        prev = *pp;
    c->next = *pp;
    *pp = c;
    if (c->next && (uint8_t *)c + c->size == (uint8_t *)c->next) {
        c->size += c->next->size;
        c->next = c->next->next;
    }
    if (prev && (uint8_t *)prev + prev->size == (uint8_t *)c) {
        prev->size += c->size;
        prev->next = c->next;
    }
}

void *calloc(size_t n, size_t size)
{
    if (size && n > SIZE_MAX / size) {
        errno = ENOMEM;
        return 0;
    }
    void *p = malloc(n * size);

    return p ? memset(p, 0, n * size) : 0;
}

void *realloc(void *p, size_t n)
{
    struct chunk *c;
    void *q;

    if (!p)
        return malloc(n);
    if (!n) {
        free(p);
        return 0;
    }
    c = (struct chunk *)((uint8_t *)p - CHUNK_HDR);
    if (c->size - CHUNK_HDR >= n)
        return p;
    q = malloc(n);
    if (q) {
        memcpy(q, p, c->size - CHUNK_HDR);
        free(p);
    }
    return q;
}

/* ---- formatted output ---------------------------------------------------- */

struct out {
    char *buf;
    size_t cap, len;
};

static void put(struct out *o, char c)
{
    if (o->len + 1 < o->cap)
        o->buf[o->len] = c;
    o->len++;
}

static void put_num(struct out *o, unsigned long long v, int base, int upper,
                    int neg, int width, int zero, int left, int prec)
{
    char tmp[24];
    int n = 0;
    int64_t pad;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";

    do {
        tmp[n++] = digits[v % (unsigned)base];
        v /= (unsigned)base;
    } while (v);
    if (!v && n == 1 && tmp[0] == '0' && prec == 0)
        n = 0;
    int zeros = prec > n ? prec - n : 0;
    pad = (int64_t)width - n - zeros - neg;
    if (!left && !zero)
        while (pad-- > 0)
            put(o, ' ');
    if (neg)
        put(o, '-');
    if (!left && zero)
        while (pad-- > 0)
            put(o, '0');
    while (zeros-- > 0)
        put(o, '0');
    while (n)
        put(o, tmp[--n]);
    if (left)
        while (pad-- > 0)
            put(o, ' ');
}

int vsnprintf(char *s, size_t cap, const char *fmt, va_list ap)
{
    struct out o = { s, cap, 0 };

    for (; *fmt; fmt++) {
        int left = 0, zero = 0, width = 0, prec = -1, lng = 0;

        if (*fmt != '%') {
            put(&o, *fmt);
            continue;
        }
        fmt++;
        for (;; fmt++) {
            if (*fmt == '-')
                left = 1;
            else if (*fmt == '0')
                zero = 1;
            else if (*fmt != '+' && *fmt != ' ' && *fmt != '#')
                break;
        }
        if (*fmt == '*') {
            width = va_arg(ap, int);
            fmt++;
            if (width == INT32_MIN) {
                errno = EOVERFLOW;
                return -1;
            }
            if (width < 0) {
                left = 1;
                width = -width;
            }
        } else {
            while (isdigit((unsigned char)*fmt)) {
                if (width > (INT32_MAX - (*fmt - '0')) / 10) {
                    errno = EOVERFLOW;
                    return -1;
                }
                width = width * 10 + (*fmt++ - '0');
            }
        }
        if (*fmt == '.') {
            fmt++;
            prec = 0;
            if (*fmt == '*') {
                prec = va_arg(ap, int);
                fmt++;
            } else {
                while (isdigit((unsigned char)*fmt)) {
                    if (prec > (INT32_MAX - (*fmt - '0')) / 10) {
                        errno = EOVERFLOW;
                        return -1;
                    }
                    prec = prec * 10 + (*fmt++ - '0');
                }
            }
        }
        while (*fmt == 'l' || *fmt == 'h' || *fmt == 'z' || *fmt == 'j' || *fmt == 't') {
            if (*fmt == 'l' || *fmt == 'z' || *fmt == 'j' || *fmt == 't')
                lng++;
            fmt++;
        }
        switch (*fmt) {
        case 'd':
        case 'i': {
            long long v = lng ? va_arg(ap, long long) : va_arg(ap, int);

            put_num(&o, v < 0 ? -(unsigned long long)v : (unsigned long long)v,
                    10, 0, v < 0, width, zero, left, prec);
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        case 'o': {
            unsigned long long v = lng ? va_arg(ap, unsigned long long)
                                       : va_arg(ap, unsigned);

            put_num(&o, v, *fmt == 'u' ? 10 : *fmt == 'o' ? 8 : 16,
                    *fmt == 'X', 0, width, zero, left, prec);
            break;
        }
        case 'p':
            put(&o, '0');
            put(&o, 'x');
            put_num(&o, (uintptr_t)va_arg(ap, void *), 16, 0, 0, 0, 0, 0, -1);
            break;
        case 'c':
            put(&o, (char)va_arg(ap, int));
            break;
        case 'f':
        case 'g': {
            double v = va_arg(ap, double);
            unsigned long long ip;
            int p = prec < 0 ? 6 : prec, neg = v < 0;

            if (neg)
                v = -v;
            ip = (unsigned long long)v;
            put_num(&o, ip, 10, 0, neg, 0, 0, 0, -1);
            if (p) {
                put(&o, '.');
                v -= (double)ip;
                while (p--) {
                    v *= 10;
                    put(&o, (char)('0' + (int)v % 10));
                }
            }
            break;
        }
        case 's': {
            const char *t = va_arg(ap, const char *);
            int n;

            if (!t)
                t = "(null)";
            n = (int)strnlen(t, prec < 0 ? (size_t)-1 : (size_t)prec);
            if (!left)
                for (int k = n; k < width; k++)
                    put(&o, ' ');
            for (int k = 0; k < n; k++)
                put(&o, t[k]);
            if (left)
                for (int k = n; k < width; k++)
                    put(&o, ' ');
            break;
        }
        case '%':
            put(&o, '%');
            break;
        default:
            put(&o, '%');
            if (*fmt)
                put(&o, *fmt);
            else
                fmt--;
        }
    }
    if (cap)
        s[o.len < cap ? o.len : cap - 1] = 0;
    return (int)o.len;
}

int vsprintf(char *s, const char *fmt, va_list ap)
{
    return vsnprintf(s, (size_t)-1 / 2, fmt, ap);
}

int snprintf(char *s, size_t n, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vsnprintf(s, n, fmt, ap);
    va_end(ap);
    return r;
}

int sprintf(char *s, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vsprintf(s, fmt, ap);
    va_end(ap);
    return r;
}

/* The console: a ring in program memory, findable by its magic, and each
 * finished line copied to the loader's log. */
struct nlr_console nlr_console = { NLR_CONSOLE_MAGIC, 0, 0, { 0 } };
static char line[NLR_API_LOG_MAX + 1];
static unsigned line_len;
static int output_allowed(FILE *f);

static void console_put(char c)
{
    nlr_console.text[nlr_console.head % sizeof nlr_console.text] = c;
    nlr_console.head++;
    if (c == '\n' || line_len == NLR_API_LOG_MAX) {
        line[line_len] = 0;
        if (line_len && nlr_libc_api)
            nlr_libc_api->log("%s", line);
        line_len = 0;
        if (c == '\n')
            return;
    }
    line[line_len++] = c;
}

int vfprintf(FILE *f, const char *fmt, va_list ap)
{
    if (!output_allowed(f)) {
        return EOF;
    }
    char buf[256];
    int n = vsnprintf(buf, sizeof buf, fmt, ap);

    for (int i = 0; buf[i]; i++)
        console_put(buf[i]);
    return n;
}

int vprintf(const char *fmt, va_list ap) { return vfprintf(stdout, fmt, ap); }

int printf(const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vfprintf(stdout, fmt, ap);
    va_end(ap);
    return r;
}

int fprintf(FILE *f, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vfprintf(f, fmt, ap);
    va_end(ap);
    return r;
}

int fputs(const char *s, FILE *f)
{
    if (!output_allowed(f)) {
        return EOF;
    }
    while (*s)
        console_put(*s++);
    return 0;
}

int puts(const char *s)
{
    fputs(s, stdout);
    console_put('\n');
    return 0;
}

int fputc(int c, FILE *f)
{
    if (!output_allowed(f)) {
        return EOF;
    }
    console_put((char)c);
    return c;
}

int putchar(int c) { return fputc(c, stdout); }

/* sscanf: %d %i %u %o %x %s %c %f and literal text, which is what the
 * program's configuration parsing asks of it. */
int sscanf(const char *s, const char *fmt, ...)
{
    va_list ap;
    int count = 0;

    va_start(ap, fmt);
    for (; *fmt; fmt++) {
        if (isspace((unsigned char)*fmt)) {
            while (isspace((unsigned char)*s))
                s++;
            continue;
        }
        if (*fmt != '%') {
            if (*s != *fmt)
                break;
            s++;
            continue;
        }
        fmt++;
        if (*fmt == '%') {
            if (*s++ != '%')
                break;
            continue;
        }
        int suppress = *fmt == '*', width = 0, length = 0;
        if (suppress)
            fmt++;
        while (isdigit((unsigned char)*fmt)) {
            if (width > (INT32_MAX - 9) / 10)
                width = INT32_MAX;
            else
                width = width * 10 + *fmt - '0';
            fmt++;
        }
        if (*fmt == 'l') {
            length = 1;
            if (*++fmt == 'l') {
                length = 2;
                fmt++;
            }
        } else if (*fmt == 'h') {
            length = -1;
            if (*++fmt == 'h') {
                length = -2;
                fmt++;
            }
        }
        if (*fmt != 'c')
            while (isspace((unsigned char)*s))
                s++;
        if (!*s)
            break;
        if (*fmt == 'd' || *fmt == 'i' || *fmt == 'u' || *fmt == 'o' || *fmt == 'x') {
            char *end;
            char limited[128];
            const char *number = s;
            if (width) {
                size_t n = strnlen(s, (size_t)width);
                if (n >= sizeof limited)
                    break;
                memcpy(limited, s, n);
                limited[n] = 0;
                number = limited;
            }
            int base = *fmt == 'x' ? 16 : *fmt == 'o' ? 8 : *fmt == 'i' ? 0 : 10;
            int unsign = *fmt == 'u' || *fmt == 'o' || *fmt == 'x';
            unsigned long value = unsign ? strtoul(number, &end, base)
                                         : (unsigned long)strtol(number, &end, base);

            if (end == number)
                break;
            if (!suppress) {
                if (unsign) {
                    if (length == 2) *va_arg(ap, unsigned long long *) = value;
                    else if (length == 1) *va_arg(ap, unsigned long *) = value;
                    else if (length == -1) *va_arg(ap, unsigned short *) = (unsigned short)value;
                    else if (length == -2) *va_arg(ap, unsigned char *) = (unsigned char)value;
                    else *va_arg(ap, unsigned *) = (unsigned)value;
                } else {
                    if (length == 2) *va_arg(ap, long long *) = (long)value;
                    else if (length == 1) *va_arg(ap, long *) = (long)value;
                    else if (length == -1) *va_arg(ap, short *) = (short)value;
                    else if (length == -2) *va_arg(ap, signed char *) = (signed char)value;
                    else *va_arg(ap, int *) = (int)value;
                }
            }
            s += end - number;
        } else if (*fmt == 'f') {
            char *end;
            double v = strtod(s, &end);

            if (end == s)
                break;
            if (!suppress) {
                if (length == 1) *va_arg(ap, double *) = v;
                else *va_arg(ap, float *) = (float)v;
            }
            s = end;
        } else if (*fmt == 's') {
            char *d = suppress ? 0 : va_arg(ap, char *);
            if (!width)
                width = INT32_MAX;

            while (width-- && *s && !isspace((unsigned char)*s)) {
                if (d)
                    *d++ = *s;
                s++;
            }
            if (d)
                *d = 0;
        } else if (*fmt == 'c') {
            if (!width)
                width = 1;
            if (strnlen(s, (size_t)width) < (size_t)width)
                break;
            if (!suppress)
                memcpy(va_arg(ap, char *), s, (size_t)width);
            s += width;
        } else {
            break;
        }
        if (!suppress)
            count++;
    }
    va_end(ap);
    return count;
}

/* ---- files: the loader's card channel ------------------------------------ */

struct nlr_file {
    int fd;
    long pos, size;
    int eof, err;
};

static struct nlr_file console_file = { -1, 0, 0, 0, 0 };
static struct nlr_file input_file = { -1, 0, 0, 0, 0 };
FILE *stdin = &input_file, *stdout = &console_file, *stderr = &console_file;

static int output_allowed(FILE *f)
{
    if (f == stdout || f == stderr)
        return 1;
    if (f)
        f->err = 1;
    errno = EACCES;
    return 0;
}

FILE *fopen(const char *path, const char *mode)
{
    struct nlr_file *f;
    int fd, size;

    if (!path || !mode || (strcmp(mode, "r") && strcmp(mode, "rb")) ||
        !nlr_libc_api || !nlr_libc_api->fs_open) {
        errno = mode && *mode != 'r' ? EACCES : EINVAL;
        return 0;
    }
    fd = nlr_libc_api->fs_open(path, 0);
    if (fd < 0) {
        errno = fd < -1 ? -fd : EIO;
        return 0;
    }
    size = nlr_libc_api->fs_seek(fd, 0, NLR_SEEK_END);
    if (size < 0 || nlr_libc_api->fs_seek(fd, 0, NLR_SEEK_SET) != 0 ||
        !(f = malloc(sizeof *f))) {
        nlr_libc_api->fs_close(fd);
        errno = EIO;
        return 0;
    }
    f->fd = fd;
    f->pos = 0;
    f->size = size;
    f->eof = f->err = 0;
    return f;
}

int fclose(FILE *f)
{
    int r = 0;

    if (!f || f == &console_file || f == &input_file)
        return 0;
    if (nlr_libc_api->fs_close(f->fd) != 0) {
        f->err = 1;
        errno = EIO;
        return EOF; /* Keep the live handle available for a retry. */
    }
    free(f);
    return r;
}

size_t fread(void *buf, size_t size, size_t n, FILE *f)
{
    if (!size || !n)
        return 0;
    if (!f || f == &console_file || f == &input_file) {
        errno = EBADF;
        return 0;
    }
    if (!buf || n > SIZE_MAX / size) {
        f->err = 1;
        errno = EOVERFLOW;
        return 0;
    }
    if (f->pos >= f->size) {
        f->eof = 1;
        return 0;
    }
    size_t request = size * n, done = 0;
    size_t remaining = (size_t)(f->size - f->pos);
    size_t want = request < remaining ? request : remaining;
    while (done < want) {
        size_t part = want - done;
        if (part > 65536u)
            part = 65536u;
        int got = nlr_libc_api->fs_read(f->fd, (uint8_t *)buf + done,
                                      (uint32_t)part);

        if (got <= 0 || (size_t)got > part) {
            f->err = 1;
            errno = EIO;
            break;
        }
        done += (size_t)got;
        f->pos += got;
    }
    if (done == want && want < request)
        f->eof = 1;
    return size ? done / size : 0;
}

size_t fwrite(const void *buf, size_t size, size_t n, FILE *f)
{
    if (!size || !n)
        return 0;
    if (!buf || n > SIZE_MAX / size) {
        errno = EOVERFLOW;
        return 0;
    }
    if (f == stdout || f == stderr) {
        const char *p = buf;

        for (size_t i = 0; i < size * n; i++)
            console_put(p[i]);
        return n;
    }
    if (f)
        f->err = 1;
    errno = EACCES;
    return 0;
}

int fseek(FILE *f, long off, int whence)
{
    if (!f || f == &console_file || f == &input_file) {
        errno = EBADF;
        return -1;
    }
    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) {
        errno = EINVAL;
        return -1;
    }
    long base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? f->pos : f->size;
    if (off < -base || off > INT32_MAX - base) {
        errno = EOVERFLOW;
        return -1;
    }
    long to = base + off;
    int r;

    r = nlr_libc_api->fs_seek(f->fd, to, NLR_SEEK_SET);
    if (r < 0 || r != to) {
        f->err = 1;
        errno = EIO;
        return -1;
    }
    f->pos = to;
    f->eof = 0;
    return 0;
}

long ftell(FILE *f) { return f ? f->pos : -1; }
int fflush(FILE *f) { (void)f; return 0; }
int feof(FILE *f) { return f ? f->eof : 1; }
int ferror(FILE *f) { return f ? f->err : 1; }
void clearerr(FILE *f) { if (f) f->eof = f->err = 0; }

int fgetc(FILE *f)
{
    unsigned char c;

    return fread(&c, 1, 1, f) == 1 ? c : EOF;
}

char *fgets(char *s, int n, FILE *f)
{
    int i = 0;

    while (i < n - 1) {
        int c = fgetc(f);

        if (c == EOF)
            break;
        s[i++] = (char)c;
        if (c == '\n')
            break;
    }
    if (!i)
        return 0;
    s[i] = 0;
    return s;
}

int remove(const char *path) { (void)path; errno = EACCES; return -1; }
int rename(const char *a, const char *b) { (void)a; (void)b; errno = EACCES; return -1; }
int mkdir(const char *path, mode_t mode) { (void)path; (void)mode; errno = EACCES; return -1; }
int unlink(const char *path) { (void)path; errno = EACCES; return -1; }

int stat(const char *path, struct stat *st)
{
    FILE *f = fopen(path, "rb");

    if (!f)
        return -1;
    st->st_size = f->size;
    st->st_mode = 0;
    fclose(f);
    return 0;
}

int access(const char *path, int mode)
{
    FILE *f;

    if (mode & W_OK)
        return -1;
    f = fopen(path, "rb");
    if (!f)
        return -1;
    fclose(f);
    return 0;
}

int isatty(int fd) { (void)fd; return 0; }
char *getcwd(char *buf, size_t n) { if (n) buf[0] = 0; return buf; }

/* ---- process ------------------------------------------------------------- */

char *getenv(const char *name) { (void)name; return 0; }
int system(const char *cmd) { (void)cmd; return -1; }
int atexit(void (*fn)(void)) { (void)fn; return 0; }

void exit(int code)
{
    nlr_libc_api->exit(code);
    for (;;)
        ;
}

void abort(void)
{
    exit(99);
}

void nlr_assert_fail(const char *expr, const char *file, int line_no)
{
    printf("assert %s %s:%d\n", expr, file, line_no);
    exit(98);
}

time_t time(time_t *t)
{
    if (t)
        *t = 0;
    return 0;
}
