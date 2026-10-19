/* The two channels that only the camera had exercised: the loader's own
 * state on an ordinary card (core/file_store.c) and the firmware-code
 * channel (core/hook.c). Both are driven here against mock services, with
 * no loader, no page and no worker, so each refusal is visible on its own.
 *
 * The body keeps one writable alias of the pages its text runs from, and a
 * patch is written through that alias; the two are the same memory there,
 * which no host can reproduce. The mock keeps them apart and makes the
 * clean carry the bytes across — so a patch that forgot its cache
 * maintenance would be invisible to instruction fetch here exactly as it
 * would be on the camera. */

#include "nlr/runtime.h"

#include <stdio.h>
#include <string.h>

static unsigned failures;

#define CHECK(cond)                                    \
    do {                                               \
        if (!(cond)) {                                 \
            printf("FAIL %d: %s\n", __LINE__, #cond);  \
            failures++;                                \
        }                                              \
    } while (0)

/* Synthetic permission encodings: the core only has to tell the two
 * semantics apart, and must not bake in one model's values. */
#define MOCK_FLAG_W 0x21u
#define MOCK_FLAG_X 0x34u

/* ---- card mock ----------------------------------------------------------- */

#define MOCK_FILE_MAX 64u

struct mock_file {
    const char *path;
    uint8_t data[MOCK_FILE_MAX];
    uint32_t len;
    int present;
};

static struct mock_file card_files[] = {
    { NLR_MANIFEST_PATH, { 0 }, 0, 1 },
    { NLR_AUTOLOAD_PENDING_PATH, { 0 }, 0, 0 },
    { NLR_SAFE_MODE_PATH, { 0 }, 0, 0 },
    { NLR_ENABLED_PATH, { 0 }, 0, 0 },
    { NLR_CARD_ROOT "APPS\\NOTE.TXT", { 0 }, 0, 0 },
    { NLR_CARD_ROOT "BOOT", { 0 }, 0, 0 },
};

static int read_fail, close_fail, write_fail, open_fail;
static uint32_t clean_bytes, opens, writes;

static struct mock_file *find_file(const char *path)
{
    for (uint32_t n = 0; n < sizeof card_files / sizeof card_files[0]; n++)
        if (strcmp(card_files[n].path, path) == 0)
            return &card_files[n];
    return 0;
}

static struct {
    int used;
    struct mock_file *file;
    uint32_t position;
} handles[4];

static int32_t mock_open(const char *path, uint32_t flags, uint32_t mode)
{
    struct mock_file *f = find_file(path);
    opens++;
    if (open_fail || !f)
        return -1;
    if (!f->present) {
        /* Creating is the write access the loader's marker needs; the
         * model's own flags say so, and nothing else creates a file. */
        if (flags != 0x301u || mode != 0x20u)
            return -1;
        f->present = 1;
        f->len = 0;
    } else if (flags == 0x301u) {
        f->len = 0; /* create+truncate */
    }
    for (uint32_t n = 0; n < sizeof handles / sizeof handles[0]; n++)
        if (!handles[n].used) {
            handles[n].used = 1;
            handles[n].file = f;
            handles[n].position = 0;
            return (int32_t)n;
        }
    return -1;
}

static int32_t mock_read(int32_t fd, void *buf, uint32_t bytes,
                         uint32_t *out_read)
{
    if (fd < 0 || fd >= (int32_t)(sizeof handles / sizeof handles[0]) ||
        !handles[fd].used || read_fail)
        return -1;
    struct mock_file *f = handles[fd].file;
    uint32_t left = f->len - handles[fd].position;
    uint32_t count = bytes < left ? bytes : left;
    memcpy(buf, f->data + handles[fd].position, count);
    handles[fd].position += count;
    *out_read = count;
    return count ? 0 : -1;
}

static int32_t mock_seek(int32_t fd, int32_t whence, uint32_t offset,
                         uint32_t *out_position)
{
    if (fd < 0 || fd >= (int32_t)(sizeof handles / sizeof handles[0]) ||
        !handles[fd].used)
        return -1;
    struct mock_file *f = handles[fd].file;
    handles[fd].position = whence == NLR_SEEK_END ? f->len + offset : offset;
    *out_position = handles[fd].position;
    return 0;
}

static int32_t mock_write(int32_t fd, const void *buf, uint32_t bytes,
                          uint32_t *out_written)
{
    if (fd < 0 || fd >= (int32_t)(sizeof handles / sizeof handles[0]) ||
        !handles[fd].used || write_fail)
        return -1;
    struct mock_file *f = handles[fd].file;
    if (handles[fd].position + bytes > MOCK_FILE_MAX)
        return -1;
    memcpy(f->data + handles[fd].position, buf, bytes);
    handles[fd].position += bytes;
    if (handles[fd].position > f->len)
        f->len = handles[fd].position;
    *out_written = bytes;
    writes++;
    return 0;
}

static int32_t mock_close(int32_t fd)
{
    if (fd < 0 || fd >= (int32_t)(sizeof handles / sizeof handles[0]) ||
        !handles[fd].used)
        return -1;
    handles[fd].used = 0;
    return close_fail ? -1 : 0;
}

static void mock_cache(void *addr, uint32_t len)
{
    (void)addr;
    (void)len;
}

static void mock_cache_clean(void *addr, uint32_t len)
{
    (void)addr;
    clean_bytes += len;
}

/* ---- the firmware-code channel's mock ------------------------------------ */

static _Alignas(NLR_EXEC_PAGE_SIZE) uint8_t mock_text[NLR_EXEC_PAGE_SIZE];
static _Alignas(NLR_EXEC_PAGE_SIZE) uint8_t mock_alias[NLR_EXEC_PAGE_SIZE];
/* A program's code block, and a resident extension's: where a handler is
 * allowed to live. */
static _Alignas(NLR_EXEC_PAGE_SIZE) uint8_t mock_program_block[256];
static _Alignas(NLR_EXEC_PAGE_SIZE) uint8_t mock_resident_block[256];

static const char code_manager = 'm';
static uint32_t code_clean_calls, code_invalidate_calls;
static int code_translate_fail, code_query_fail, code_translate_identity;
static uint32_t code_alias_flags = MOCK_FLAG_W;
static uint32_t code_text_flags = MOCK_FLAG_X;
static uint32_t code_other_flags = MOCK_FLAG_X;
static uint32_t code_cacheable_answer = 1;

static int inside_mock(const void *address, const void *base, uint32_t bytes)
{
    uintptr_t a = (uintptr_t)address, b = (uintptr_t)base;
    return a >= b && a < b + bytes;
}

static int32_t code_translate(const volatile void *manager, uintptr_t address,
                              uint64_t *out_physical)
{
    CHECK(manager == &code_manager);
    if (code_translate_fail || !inside_mock((const void *)address, mock_text,
                                            sizeof mock_text))
        return -1;
    /* The Z 8 maps its text windows back onto the NOR at times: the
     * translation then succeeds and names the code address itself. */
    if (code_translate_identity) {
        *out_physical = address;
        return 0;
    }
    *out_physical = (uint64_t)(uintptr_t)mock_alias +
                    (address - (uintptr_t)mock_text);
    return 0;
}

static int32_t code_query(void *address, uint32_t *out_flags)
{
    if (code_query_fail)
        return -1;
    *out_flags = inside_mock(address, mock_alias, sizeof mock_alias)
                     ? code_alias_flags
                     : inside_mock(address, mock_text, sizeof mock_text)
                           ? code_text_flags
                           : code_other_flags;
    return 0;
}

static uint32_t code_cacheable(void *address)
{
    (void)address;
    return code_cacheable_answer;
}

/* On the body this writes the alias back to memory the code side reads; in
 * the mock it is what makes the written bytes appear in the text at all. */
static void code_clean(void *address, uint32_t bytes)
{
    code_clean_calls++;
    CHECK(inside_mock(address, mock_alias, sizeof mock_alias));
    uintptr_t offset = (uintptr_t)address - (uintptr_t)mock_alias;
    CHECK(offset + bytes <= sizeof mock_alias);
    memcpy(mock_text + offset, mock_alias + offset, bytes);
}

static void code_invalidate(void *address, uint64_t bytes)
{
    (void)bytes;
    code_invalidate_calls++;
    CHECK(inside_mock(address, mock_text, sizeof mock_text));
}

static struct nlr_code_services code_services;

const struct nlr_services nlr_services = {
    .abi = 1,
    .file_open = mock_open,
    .file_read = mock_read,
    .file_seek = mock_seek,
    .file_close = mock_close,
    .file_write = mock_write,
    .file_open_rw = 2,
    .file_open_write = 0x301,
    .file_create_attributes = 0x20,
    .cache_before_read = mock_cache,
    .cache_after_read = mock_cache,
    .cache_clean = mock_cache_clean,
    .code = &code_services,
};

static struct nlr_runtime runtime;

static void reset_card(void)
{
    for (uint32_t n = 0; n < sizeof card_files / sizeof card_files[0]; n++) {
        card_files[n].len = 0;
        card_files[n].present = strcmp(card_files[n].path,
                                       NLR_MANIFEST_PATH) == 0;
        memset(card_files[n].data, 0, sizeof card_files[n].data);
    }
    memset(handles, 0, sizeof handles);
    read_fail = close_fail = write_fail = open_fail = 0;
    clean_bytes = opens = writes = 0;
}

static void set_file(const char *path, const char *content, uint32_t len)
{
    struct mock_file *f = find_file(path);
    CHECK(f != 0);
    if (!f)
        return;
    f->present = 1;
    f->len = len;
    memcpy(f->data, content, len);
}

/* ---- the ordinary-card store --------------------------------------------- */

static void store_reports_presence_only_when_the_card_answers(void)
{
    reset_card();
    const struct nlr_card_store *store = nlr_file_store();
    CHECK(store && store->probe && store->replace && store->remove);
    if (!store)
        return;
    uint32_t present = 9;

    /* Absence is only established by a card that answers for MANIFEST --
     * or, on a card with none, for BOOT or ENABLED. */
    CHECK(store->probe(NLR_SAFE_MODE_PATH, &present) == NLR_OK && !present);
    set_file(NLR_SAFE_MODE_PATH, "", 0);
    CHECK(store->probe(NLR_SAFE_MODE_PATH, &present) == NLR_OK && present);
    find_file(NLR_SAFE_MODE_PATH)->present = 0;
    find_file(NLR_MANIFEST_PATH)->present = 0;
    CHECK(store->probe(NLR_SAFE_MODE_PATH, &present) == NLR_IO);
    find_file(NLR_CARD_ROOT "BOOT")->present = 1;
    present = 9;
    CHECK(store->probe(NLR_SAFE_MODE_PATH, &present) == NLR_OK && !present);
    /* a file is never its own anchor */
    find_file(NLR_CARD_ROOT "BOOT")->present = 0;
    CHECK(store->probe(NLR_CARD_ROOT "BOOT", &present) == NLR_IO);
    find_file(NLR_ENABLED_PATH)->present = 1;
    present = 9;
    CHECK(store->probe(NLR_SAFE_MODE_PATH, &present) == NLR_OK && !present);
    find_file(NLR_ENABLED_PATH)->present = 0;
    find_file(NLR_MANIFEST_PATH)->present = 1;

    /* The marker: there while it is empty, gone once it holds its cleared
     * byte, and -- the direction that matters -- still there when it opens
     * and cannot be read. */
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          !present);
    set_file(NLR_AUTOLOAD_PENDING_PATH, "", 0);
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          present);
    set_file(NLR_AUTOLOAD_PENDING_PATH, "C", 1);
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          !present);
    read_fail = 1;
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          present);
    read_fail = 0;
    /* Anything else in it is a marker too, whatever it says. */
    set_file(NLR_AUTOLOAD_PENDING_PATH, "CC", 2);
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          present);
    set_file(NLR_AUTOLOAD_PENDING_PATH, "x", 1);
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          present);
    /* A marker whose close fails is an IO error, not an answer. */
    set_file(NLR_AUTOLOAD_PENDING_PATH, "C", 1);
    close_fail = 1;
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_IO);
    close_fail = 0;
    CHECK(store->probe(0, &present) == NLR_NOT_READY);
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, 0) == NLR_NOT_READY);
}

static void store_writes_only_the_marker(void)
{
    reset_card();
    const struct nlr_card_store *store = nlr_file_store();
    if (!store)
        return;
    uint32_t present = 9;

    /* Starting a pass: the marker is created empty and nothing else is
     * ever written through this store, because nothing else could be
     * written atomically. */
    CHECK(store->replace(NLR_AUTOLOAD_PENDING_PATH, 0, 0) == NLR_OK);
    CHECK(find_file(NLR_AUTOLOAD_PENDING_PATH)->present);
    CHECK(find_file(NLR_AUTOLOAD_PENDING_PATH)->len == 0 && !writes);
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          present);
    CHECK(store->replace(NLR_ENABLED_PATH, (const uint8_t *)"one\n", 4) ==
          NLR_NOT_READY);
    CHECK(store->replace(NLR_AUTOLOAD_PENDING_PATH, (const uint8_t *)"C", 1) ==
          NLR_NOT_READY);
    CHECK(store->replace(0, 0, 0) == NLR_NOT_READY);
    CHECK(!find_file(NLR_ENABLED_PATH)->present);

    /* Ending it: one cleared byte, written back out of the data cache
     * first, and the pass reads as finished afterwards. */
    CHECK(store->remove(NLR_AUTOLOAD_PENDING_PATH) == NLR_OK);
    CHECK(find_file(NLR_AUTOLOAD_PENDING_PATH)->len == 1);
    CHECK(find_file(NLR_AUTOLOAD_PENDING_PATH)->data[0] == 'C');
    CHECK(clean_bytes == 1 && writes == 1);
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          !present);
    CHECK(store->remove(NLR_ENABLED_PATH) == NLR_NOT_READY);
    CHECK(store->remove(0) == NLR_NOT_READY);

    /* A write that fails leaves the marker as it was: empty, which is the
     * pending answer, so an interrupted pass is never missed. */
    CHECK(store->replace(NLR_AUTOLOAD_PENDING_PATH, 0, 0) == NLR_OK);
    write_fail = 1;
    CHECK(store->remove(NLR_AUTOLOAD_PENDING_PATH) == NLR_IO);
    write_fail = 0;
    CHECK(store->probe(NLR_AUTOLOAD_PENDING_PATH, &present) == NLR_OK &&
          present);
}

/* ---- the firmware-code channel ------------------------------------------- */

/* ADD X0, X0, #1 / RET / MOV X8, #0xd350 / LDRB W9, [X0] -- four movable
 * instructions, the shape a hook needs. */
static const uint32_t target_words[4] = {
    0x91000400u, 0xd65f03c0u, 0xd29a6a08u, 0x39400009u
};

static void put_word(uint8_t *at, uint32_t word)
{
    for (uint32_t n = 0; n < 4u; n++)
        at[n] = (uint8_t)(word >> (8u * n));
}

static uint32_t get_word(const uint8_t *at)
{
    return (uint32_t)at[0] | (uint32_t)at[1] << 8 | (uint32_t)at[2] << 16 |
           (uint32_t)at[3] << 24;
}

static uint64_t text_at(uint32_t offset)
{
    return (uint64_t)(uintptr_t)mock_text + offset;
}

static void reset_code(void)
{
    memset(mock_text, 0, sizeof mock_text);
    memset(mock_alias, 0, sizeof mock_alias);
    memset(&runtime.hooks, 0, sizeof runtime.hooks);
    memset(runtime.resident, 0, sizeof runtime.resident);
    runtime.load.svc = &nlr_services;
    runtime.load.state = 0;
    memset(&runtime.load.program, 0, sizeof runtime.load.program);
    code_services = (struct nlr_code_services){
        .text_lo = (uint64_t)(uintptr_t)mock_text,
        .text_hi = (uint64_t)(uintptr_t)mock_text + sizeof mock_text,
        .alias_lo = (uint64_t)(uintptr_t)mock_alias,
        .alias_hi = (uint64_t)(uintptr_t)mock_alias + sizeof mock_alias,
        .manager = &code_manager,
        .translate = code_translate,
        .query = code_query,
        .cacheable = code_cacheable,
        .clean = code_clean,
        .invalidate = code_invalidate,
        .flag_writable = MOCK_FLAG_W,
        .flag_executable = MOCK_FLAG_X,
        .unaligned_literals = 1,
    };
    code_clean_calls = code_invalidate_calls = 0;
    code_translate_fail = code_query_fail = code_translate_identity = 0;
    code_alias_flags = MOCK_FLAG_W;
    code_text_flags = MOCK_FLAG_X;
    code_other_flags = MOCK_FLAG_X;
    code_cacheable_answer = 1;
    for (uint32_t n = 0; n < 4u; n++)
        put_word(mock_text + 64u + 4u * n, target_words[n]);
}

/* A program is running and its code block is this one. */
static void running_program(uint8_t *block, uint32_t bytes)
{
    runtime.load.state = 2;
    runtime.load.program.code_page = block;
    runtime.load.program.region_bytes = bytes;
}

static void patch_replaces_whole_instructions_in_one_line(void)
{
    reset_code();
    const uint32_t replacement = 0xd503201fu; /* NOP */
    uint8_t bytes[8];
    put_word(bytes, replacement);
    put_word(bytes + 4, replacement);

    CHECK(nlr_code_patch(&code_services, text_at(64), bytes, 8) == NLR_OK);
    CHECK(get_word(mock_text + 64) == replacement);
    CHECK(get_word(mock_text + 68) == replacement);
    CHECK(get_word(mock_text + 72) == target_words[2]);
    CHECK(code_clean_calls == 1 && code_invalidate_calls == 1);

    /* Whole instructions, aligned, inside the window and inside one cache
     * line; nothing else is written. */
    CHECK(nlr_code_patch(&code_services, text_at(64), bytes, 0) == NLR_BOUNDS);
    CHECK(nlr_code_patch(&code_services, text_at(64), bytes, 6) == NLR_BOUNDS);
    CHECK(nlr_code_patch(&code_services, text_at(64),
                         bytes, NLR_CODE_PATCH_MAX + 4u) == NLR_BOUNDS);
    CHECK(nlr_code_patch(&code_services, text_at(66), bytes, 4) == NLR_BOUNDS);
    CHECK(nlr_code_patch(&code_services, text_at(60), bytes, 8) == NLR_BOUNDS);
    CHECK(nlr_code_patch(&code_services, text_at(0) - 4, bytes, 4) ==
          NLR_BOUNDS);
    CHECK(nlr_code_patch(&code_services, code_services.text_hi, bytes, 4) ==
          NLR_BOUNDS);
    CHECK(nlr_code_patch(&code_services, text_at(64), 0, 4) == NLR_BOUNDS);
    CHECK(code_clean_calls == 1);

    /* Everything the window promises is checked before a byte is written:
     * the translation, the alias's permission, the code's own, and that
     * the alias is memory this body's cache maintenance acts on. */
    code_translate_fail = 1;
    CHECK(nlr_code_patch(&code_services, text_at(96), bytes, 4) == NLR_IO);
    code_translate_fail = 0;
    /* A page that translates outside the alias band (the text back on its
     * read-only medium) is refused, and nothing is written or cleaned. */
    uint32_t cleans = code_clean_calls;
    code_translate_identity = 1;
    CHECK(nlr_code_patch(&code_services, text_at(96), bytes, 4) == NLR_BOUNDS);
    code_translate_identity = 0;
    CHECK(code_clean_calls == cleans);
    code_alias_flags = MOCK_FLAG_X;
    CHECK(nlr_code_patch(&code_services, text_at(96), bytes, 4) == NLR_IO);
    code_alias_flags = MOCK_FLAG_W;
    code_text_flags = MOCK_FLAG_W;
    CHECK(nlr_code_patch(&code_services, text_at(96), bytes, 4) == NLR_IO);
    code_text_flags = MOCK_FLAG_X;
    code_cacheable_answer = 0;
    CHECK(nlr_code_patch(&code_services, text_at(96), bytes, 4) == NLR_IO);
    code_cacheable_answer = 1;
    code_query_fail = 1;
    CHECK(nlr_code_patch(&code_services, text_at(96), bytes, 4) == NLR_IO);
    code_query_fail = 0;
    CHECK(get_word(mock_text + 96) == 0 && code_clean_calls == 1);

    /* A model without the channel, and one whose two encodings are the
     * same word, cannot be told what a patch means. */
    struct nlr_code_services broken = code_services;
    broken.translate = 0;
    CHECK(nlr_code_patch(&broken, text_at(64), bytes, 4) == NLR_NOT_READY);
    broken = code_services;
    broken.flag_writable = broken.flag_executable;
    CHECK(nlr_code_patch(&broken, text_at(64), bytes, 4) == NLR_NOT_READY);
    CHECK(nlr_code_patch(0, text_at(64), bytes, 4) == NLR_NOT_READY);
}

static void hook_detours_only_what_it_can_put_back(void)
{
    reset_code();
    running_program(mock_program_block, sizeof mock_program_block);
    uint64_t handler = (uint64_t)(uintptr_t)mock_program_block;
    uint8_t expect[NLR_CODE_HOOK_BYTES];
    for (uint32_t n = 0; n < 4u; n++)
        put_word(expect + 4u * n, target_words[n]);

    /* The firmware has to hold exactly the bytes the program was built
     * against. */
    uint8_t wrong[NLR_CODE_HOOK_BYTES];
    memcpy(wrong, expect, sizeof wrong);
    wrong[0] ^= 1u;
    CHECK(nlr_code_hook(&runtime, text_at(64), wrong, handler) == NLR_FORMAT);
    CHECK(!runtime.hooks.count && get_word(mock_text + 64) == target_words[0]);

    /* A handler has to be executable code the loader owns. */
    code_other_flags = MOCK_FLAG_W;
    CHECK(nlr_code_hook(&runtime, text_at(64), expect, handler) == NLR_BOUNDS);
    code_other_flags = MOCK_FLAG_X;
    CHECK(nlr_code_hook(&runtime, text_at(64), expect,
                        (uint64_t)(uintptr_t)&failures) == NLR_BOUNDS);
    CHECK(nlr_code_hook(&runtime, text_at(64), expect, handler + 1u) ==
          NLR_BOUNDS);
    CHECK(nlr_code_hook(&runtime, text_at(64), expect, 0) == NLR_BOUNDS);
    CHECK(nlr_code_hook(&runtime, 0, expect, handler) == NLR_BOUNDS);
    CHECK(nlr_code_hook(&runtime, text_at(64), 0, handler) == NLR_BOUNDS);
    CHECK(!runtime.hooks.count);

    /* The four instructions the detour overwrites have to be ones a
     * handler could run from somewhere else. */
    const uint32_t immovable[] = {
        0x14000004u, /* B      */
        0x54000040u, /* B.EQ   */
        0x90000000u, /* ADRP   */
        0xb4000040u, /* CBZ    */
        0x37080040u, /* TBNZ   */
        0x58000040u, /* LDR literal */
    };
    for (uint32_t n = 0; n < sizeof immovable / sizeof immovable[0]; n++) {
        uint8_t words[NLR_CODE_HOOK_BYTES];
        memcpy(words, expect, sizeof words);
        put_word(words + 8, immovable[n]);
        put_word(mock_text + 72, immovable[n]);
        CHECK(nlr_code_hook(&runtime, text_at(64), words, handler) ==
              NLR_FORMAT);
        CHECK(!runtime.hooks.count);
    }
    put_word(mock_text + 72, target_words[2]);

    /* The detour itself: load the handler's address from behind the two
     * instructions and branch to it. */
    CHECK(nlr_code_hook(&runtime, text_at(64), expect, handler) == NLR_OK);
    CHECK(get_word(mock_text + 64) == 0x58000050u);
    CHECK(get_word(mock_text + 68) == 0xd61f0200u);
    CHECK(get_word(mock_text + 72) == (uint32_t)handler);
    CHECK(get_word(mock_text + 76) == (uint32_t)(handler >> 32));
    CHECK(runtime.hooks.count == 1);
    CHECK(runtime.hooks.slot[0].target == text_at(64));
    CHECK(runtime.hooks.slot[0].handler == handler);
    CHECK(runtime.hooks.slot[0].owner_base ==
          (uint64_t)(uintptr_t)mock_program_block);
    CHECK(runtime.hooks.slot[0].owner_bytes == sizeof mock_program_block);

    /* One hook per target, and no more records than there are slots. */
    CHECK(nlr_code_hook(&runtime, text_at(64), expect, handler) == NLR_BUSY);
    for (uint32_t n = 1; n < NLR_CODE_HOOKS_MAX; n++) {
        uint32_t offset = 64u * (n + 1u);
        for (uint32_t w = 0; w < 4u; w++)
            put_word(mock_text + offset + 4u * w, target_words[w]);
        CHECK(nlr_code_hook(&runtime, text_at(offset), expect, handler) ==
              NLR_OK);
    }
    uint32_t full = 64u * (NLR_CODE_HOOKS_MAX + 1u);
    for (uint32_t w = 0; w < 4u; w++)
        put_word(mock_text + full + 4u * w, target_words[w]);
    CHECK(runtime.hooks.count == NLR_CODE_HOOKS_MAX);
    CHECK(nlr_code_hook(&runtime, text_at(full), expect, handler) == NLR_BUSY);
    CHECK(get_word(mock_text + full) == target_words[0]);

    /* Unhooking puts the original bytes back, and only a target this
     * loader hooked can be unhooked. */
    CHECK(nlr_code_unhook(&runtime, text_at(64)) == NLR_OK);
    for (uint32_t w = 0; w < 4u; w++)
        CHECK(get_word(mock_text + 64u + 4u * w) == target_words[w]);
    CHECK(runtime.hooks.count == NLR_CODE_HOOKS_MAX - 1u);
    CHECK(nlr_code_unhook(&runtime, text_at(64)) == NLR_FORMAT);
    CHECK(nlr_code_unhook(&runtime, 0) == NLR_FORMAT);

    /* A target that is not 8-byte aligned depends on the body: the
     * handler's address sits at a 4-byte-aligned offset then. */
    reset_code();
    running_program(mock_program_block, sizeof mock_program_block);
    for (uint32_t w = 0; w < 4u; w++)
        put_word(mock_text + 132u + 4u * w, target_words[w]);
    code_services.unaligned_literals = 0;
    CHECK(nlr_code_hook(&runtime, text_at(132), expect, handler) ==
          NLR_BOUNDS);
    code_services.unaligned_literals = 1;
    CHECK(nlr_code_hook(&runtime, text_at(132), expect, handler) == NLR_OK);
    CHECK(nlr_code_unhook(&runtime, text_at(132)) == NLR_OK);
}

static void hooks_go_with_the_memory_they_point_into(void)
{
    reset_code();
    uint8_t expect[NLR_CODE_HOOK_BYTES];
    for (uint32_t n = 0; n < 4u; n++)
        put_word(expect + 4u * n, target_words[n]);
    for (uint32_t w = 0; w < 4u; w++)
        put_word(mock_text + 128u + 4u * w, target_words[w]);

    /* A resident extension's block is the other place a handler may live;
     * that block is never given back, so its hook stays. */
    runtime.resident[0].used = 1;
    runtime.resident[0].kind = NLR_KIND_RESOURCE_EXTENSION;
    runtime.resident[0].code_block = mock_resident_block;
    runtime.resident[0].code_bytes = sizeof mock_resident_block;
    uint64_t resident_handler = (uint64_t)(uintptr_t)mock_resident_block + 16u;
    CHECK(nlr_code_hook(&runtime, text_at(128), expect, resident_handler) ==
          NLR_OK);
    CHECK(runtime.hooks.slot[0].owner_base ==
          (uint64_t)(uintptr_t)mock_resident_block);

    /* And a foreground program's, which is released when it ends. */
    running_program(mock_program_block, sizeof mock_program_block);
    uint64_t handler = (uint64_t)(uintptr_t)mock_program_block;
    CHECK(nlr_code_hook(&runtime, text_at(64), expect, handler) == NLR_OK);
    CHECK(runtime.hooks.count == 2);

    /* Releasing the program's block takes its hook with it -- the program
     * never asked for that -- and leaves the resident one alone. */
    CHECK(nlr_code_unhook_region(&runtime, mock_program_block,
                                 sizeof mock_program_block) == NLR_OK);
    CHECK(runtime.hooks.count == 1);
    for (uint32_t w = 0; w < 4u; w++)
        CHECK(get_word(mock_text + 64u + 4u * w) == target_words[w]);
    CHECK(get_word(mock_text + 128u) == 0x58000050u);
    CHECK(runtime.hooks.slot[0].target == text_at(128));

    /* Nothing of this program's is in that block the second time. */
    CHECK(nlr_code_unhook_region(&runtime, mock_program_block,
                                 sizeof mock_program_block) == NLR_OK);
    CHECK(runtime.hooks.count == 1);
    CHECK(nlr_code_unhook_region(&runtime, 0, 0) == NLR_OK);
    CHECK(nlr_code_unhook_region(0, mock_program_block, 4) == NLR_NOT_READY);

    /* A hook that cannot be put back keeps its record and says so, which
     * is what stops the caller from freeing the memory under it. */
    running_program(mock_program_block, sizeof mock_program_block);
    for (uint32_t w = 0; w < 4u; w++)
        put_word(mock_text + 192u + 4u * w, target_words[w]);
    CHECK(nlr_code_hook(&runtime, text_at(192), expect, handler) == NLR_OK);
    code_translate_fail = 1;
    CHECK(nlr_code_unhook_region(&runtime, mock_program_block,
                                 sizeof mock_program_block) == NLR_IO);
    CHECK(runtime.hooks.count == 2);
    code_translate_fail = 0;
    code_translate_identity = 1;
    CHECK(nlr_code_unhook_region(&runtime, mock_program_block,
                                 sizeof mock_program_block) == NLR_BOUNDS);
    CHECK(runtime.hooks.count == 2);
    code_translate_identity = 0;
    CHECK(nlr_code_unhook_region(&runtime, mock_program_block,
                                 sizeof mock_program_block) == NLR_OK);
    CHECK(runtime.hooks.count == 1);
}

int main(void)
{
    store_reports_presence_only_when_the_card_answers();
    store_writes_only_the_marker();
    patch_replaces_whole_instructions_in_one_line();
    hook_detours_only_what_it_can_put_back();
    hooks_go_with_the_memory_they_point_into();
    if (failures) {
        printf("%u failure(s)\n", failures);
        return 1;
    }
    puts("store and code channel tests passed");
    return 0;
}
