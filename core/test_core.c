/* Host behavior tests for the load, runtime, directory and page layers. The
 * mock table implements the normalized service contract from nlr/services.h
 * and records what the core did; a firmware-side behavior difference shows
 * up here first. No firmware image, key material, device or address literal
 * is involved. */
/* Deterministic interleave seam for the pending text slot: defined before
 * the headers so the inline reader in this translation unit calls the hook
 * after every payload load; the camera builds keep the no-op default. */
static void text_seam_step(void);
#define NLR_TEXT_READ_PAUSE() text_seam_step()
#include "nlr/api.h"
#include "nlr/menu.h"
#include "nlr/runtime.h"

#include <stdio.h>
#include <string.h>

#define TEST_PATH NLR_PROGRAM_ROOT "APPS\\PROBE.NLB"
#define ARENA_CAP 0x10000u

static int failures;

#define CHECK(cond)                                    \
    do {                                               \
        if (!(cond)) {                                 \
            printf("FAIL %d: %s\n", __LINE__, #cond);  \
            failures++;                                \
        }                                              \
    } while (0)

/* ---- pending text seam --------------------------------------------------- */

/* The hook stands in for the worker task: each call performs one complete
 * publish (odd generation, payload stores, even generation) of the
 * alternating A/B text, exactly where the reader is inside its scan. That
 * makes every interleaving below deterministic — no timing involved. */
static struct nlr_text_slot *text_seam_slot;
static int text_seam_active;
static uint32_t text_seam_publishes; /* publishes left in the script */
static uint32_t text_seam_turn;      /* alternates the A/B contents */
static uint32_t text_seam_fires;     /* publishes the hook performed */

static char text_a[NLR_SLOT_TEXT_MAX + 1];
static char text_b[NLR_SLOT_TEXT_MAX + 1];

/* The bounded packing nlr_text_publish uses, spelled out so the tests can
 * place a publish at an exact point of the reader's scan. */
static void text_store_payload(struct nlr_text_slot *t, const char *s)
{
    uint32_t length = 0;
    while (s[length] && length < NLR_SLOT_TEXT_MAX)
        length++;
    uint32_t words = (length + 1u + 7u) / 8u;
    for (uint32_t w = 0; w < words; w++) {
        uint64_t value = 0;
        for (uint32_t b = 0; b < 8; b++) {
            uint32_t index = w * 8u + b;
            uint8_t byte = 0;
            if (index < length)
                byte = (uint8_t)s[index];
            value |= (uint64_t)byte << (8 * b);
        }
        __atomic_store_n(&t->words[w], value, __ATOMIC_RELEASE);
    }
}

static void text_seam_texts_init(void)
{
    memset(text_a, 'A', NLR_SLOT_TEXT_MAX);
    text_a[NLR_SLOT_TEXT_MAX] = 0;
    memset(text_b, 'B', NLR_SLOT_TEXT_MAX);
    text_b[NLR_SLOT_TEXT_MAX] = 0;
}

static void text_seam_step(void)
{
    if (!text_seam_active || !text_seam_slot)
        return;
    text_seam_fires++;
    uint32_t generation = __atomic_load_n(&text_seam_slot->generation,
                                          __ATOMIC_RELAXED);
    __atomic_store_n(&text_seam_slot->generation, generation + 1u,
                     __ATOMIC_RELEASE);
    text_store_payload(text_seam_slot,
                       (text_seam_turn++ & 1u) ? text_b : text_a);
    __atomic_store_n(&text_seam_slot->generation, generation + 2u,
                     __ATOMIC_RELEASE);
    if (text_seam_publishes && --text_seam_publishes == 0)
        text_seam_active = 0;
}

/* The page and the runtime read the mock table and task config through the
 * extern symbols; declared before first use, defined further below. */
extern const struct nlr_services nlr_services;
extern const struct nlr_task_config nlr_task_config;
extern const struct nlr_api nlr_api;

/* ---- kernel storage mock ------------------------------------------------ */

/* Line-aligned, so the allocator below controls where blocks fall relative
 * to cache lines; a bare char array on this host may be 4-byte aligned. */
static _Alignas(NLR_CACHE_LINE) uint8_t alloc_pool[0x40000];
static size_t alloc_used;
static int alloc_fail_countdown; /* -1 disables; 0 fails this call */
static uint32_t alloc_calls, release_calls;
static uint32_t probe_call_count;
/* Every block handed out since the last reset, so cache maintenance can be
 * checked against what the caller actually owns. */
static uintptr_t alloc_start[64];
static uint32_t alloc_size[64], alloc_count;

static int inside_allocation(uintptr_t start, uintptr_t end)
{
    for (uint32_t i = 0; i < alloc_count; i++)
        if (start >= alloc_start[i] && end <= alloc_start[i] + alloc_size[i])
            return 1;
    return 0;
}

static int32_t mock_alloc(uint32_t bytes, void **out)
{
    alloc_calls++;
    if (alloc_fail_countdown == 0) {
        alloc_fail_countdown = -1;
        *out = 0;
        return -1;
    }
    if (alloc_fail_countdown > 0)
        alloc_fail_countdown--;
    /* The family contract requires worker objects to be 8-byte aligned, so
     * the mock allocator must honor that too. Like the camera's heap (a
     * QEMU runtime block sat 0x20 past a line), blocks start mid-line, so a
     * buffer that is not placed on whole lines shares them with its
     * neighbours. */
    size_t base = ((alloc_used + NLR_CACHE_LINE - 1) & ~(size_t)(NLR_CACHE_LINE - 1)) + 0x20;
    if (base > sizeof alloc_pool || (size_t)bytes > sizeof alloc_pool - base) {
        *out = 0;
        return -1;
    }
    /* Poison so a missing zeroing is observable. */
    memset(alloc_pool + base, 0xa5, bytes);
    *out = alloc_pool + base;
    alloc_used = base + (((size_t)bytes + 7) & ~(size_t)7);
    if (alloc_count < sizeof alloc_start / sizeof alloc_start[0]) {
        alloc_start[alloc_count] = (uintptr_t)*out;
        alloc_size[alloc_count++] = bytes;
    }
    return 0;
}

static int32_t mock_release(void *ptr)
{
    (void)ptr; /* bump allocator; the count is what the tests observe */
    release_calls++;
    return 0;
}

/* Synthetic permission encodings, matching test_exec.c: host tests must not
 * bake in one model's values. */
#define MOCK_EXEC_FLAG_W 0x21u
#define MOCK_EXEC_FLAG_X 0x34u

static int32_t mock_exec_audit(void *page, uint32_t bytes, uint32_t flags)
{
    CHECK((uintptr_t)page % NLR_EXEC_PAGE_SIZE == 0);
    CHECK(bytes == NLR_EXEC_PAGE_SIZE);
    CHECK(flags == MOCK_EXEC_FLAG_W || flags == MOCK_EXEC_FLAG_X);
    return 0;
}

/* protect calls of one run: RW, RX, then the restore to RW. A test sets the
 * call that fails, counted from the last reset. */
static uint32_t exec_protect_calls, exec_protect_fail_at;

static int32_t mock_exec_protect(void *page, uint64_t bytes, uint32_t flags)
{
    if (++exec_protect_calls == exec_protect_fail_at)
        return -1;
    return mock_exec_audit(page, (uint32_t)bytes, flags);
}

static int32_t mock_exec_clean(void *page, uint32_t bytes)
{
    return mock_exec_audit(page, bytes, MOCK_EXEC_FLAG_W);
}

static int32_t mock_exec_invalidate(void *page, uint64_t bytes)
{
    CHECK(bytes == NLR_PROBE_IMAGE_SIZE);
    CHECK((uintptr_t)page % NLR_EXEC_PAGE_SIZE == 0);
    return 0;
}

static uint64_t mock_exec_call(void *entry, uint64_t challenge)
{
    CHECK((uintptr_t)entry % NLR_EXEC_PAGE_SIZE == 0);
    probe_call_count++;
    return nlr_probe_response(challenge);
}

const struct nlr_exec_services nlr_exec_services = {
    .region_bytes = NLR_EXEC_PAGE_SIZE,
    .flag_writable = MOCK_EXEC_FLAG_W, .flag_executable = MOCK_EXEC_FLAG_X,
    .allocate = mock_alloc, .release = mock_release, .audit = mock_exec_audit,
    .protect = mock_exec_protect, .clean = mock_exec_clean,
    .invalidate_code = mock_exec_invalidate, .call = mock_exec_call,
};

/* ---- card file mock ----------------------------------------------------- */

static uint8_t card[0x10000];
static uint32_t card_len;
/* The directory is a second file on the same card, so a test can make one
 * present and the other missing. */
static uint8_t card_manifest[0x4000];
static uint32_t card_manifest_len;
static int card_manifest_present;
static const uint8_t *card_enabled_data;
static uint32_t card_enabled_bytes;
static int open_fail, seek_fail, close_fail, fail_next_read;
static int safe_mode_present;
/* The NLoader switch and the boot program's file:
 * absent unless a case writes them. */
static const char *card_master, *card_boot_id;
static uint32_t read_max = 0x1000;
static uint32_t manifest_opens;
/* Every open of something other than the flag and the directory is a
 * program file; the last one's path shows how the check built it. */
static uint32_t program_opens;
static char program_path[NLR_PATH_BYTES];
/* A program's settings file (<name>.SET), the one file the core writes. */
static uint8_t card_settings[256];
static uint32_t card_settings_len;
static int card_settings_present, write_fail;
static uint32_t settings_writes, last_open_flags;

static struct mock_fd {
    int used;
    uint32_t position;
    const uint8_t *data;
    uint8_t *writable;
    uint32_t len;
} fds[8];

static int is_settings_path(const char *path)
{
    size_t n = strlen(path);
    return n > 4 && strcmp(path + n - 4, ".SET") == 0;
}

static int32_t mock_open(const char *path, uint32_t flags, uint32_t mode)
{
    (void)mode;
    last_open_flags = flags;
    if (open_fail)
        return -1;
    /* The disable flag exists only when a test says so; opening it otherwise
     * must fail like the real filesystem so the load proceeds. */
    if (strcmp(path, NLR_SAFE_MODE_PATH) == 0) {
        if (!safe_mode_present)
            return -1;
    }
    const uint8_t *data = card;
    uint8_t *writable = 0;
    uint32_t len = card_len;
    if (is_settings_path(path)) {
        if (!card_settings_present)
            return -1;
        data = writable = card_settings;
        len = card_settings_len;
    } else if (strcmp(path, NLR_MANIFEST_PATH) == 0) {
        manifest_opens++;
        if (!card_manifest_present)
            return -1;
        data = card_manifest;
        len = card_manifest_len;
    } else if (strcmp(path, NLR_ENABLED_PATH) == 0) {
        if (!card_enabled_data)
            return -1;
        data = card_enabled_data;
        len = card_enabled_bytes;
    } else if (strcmp(path, NLR_MASTER_PATH) == 0 ||
               strcmp(path, NLR_BOOT_PATH) == 0) {
        const char *text = strcmp(path, NLR_MASTER_PATH) == 0 ? card_master
                                                              : card_boot_id;
        if (!text)
            return -1;
        data = (const uint8_t *)text;
        len = (uint32_t)strlen(text);
    } else if (strcmp(path, NLR_SAFE_MODE_PATH) != 0) {
        program_opens++;
        snprintf(program_path, sizeof program_path, "%s", path);
    }
    for (unsigned n = 0; n < sizeof fds / sizeof fds[0]; n++) {
        if (!fds[n].used) {
            fds[n].used = 1;
            fds[n].position = 0;
            fds[n].data = data;
            fds[n].writable = writable;
            fds[n].len = len;
            return (int32_t)n;
        }
    }
    return -1;
}

static int32_t mock_read(int32_t fd, void *buf, uint32_t bytes, uint32_t *out_read)
{
    struct mock_fd *f = &fds[fd];
    if (fail_next_read)
        return -1;
    uint32_t remaining = f->len - f->position;
    uint32_t count = bytes;
    if (count > read_max)
        count = read_max;
    if (count > remaining)
        count = remaining;
    memcpy(buf, f->data + f->position, count);
    f->position += count;
    *out_read = count;
    return 0;
}

static int32_t mock_seek(int32_t fd, int32_t whence, uint32_t offset,
                         uint32_t *out_position)
{
    struct mock_fd *f = &fds[fd];
    if (seek_fail)
        return -1;
    if (whence == NLR_SEEK_END)
        f->position = f->len;
    else if (whence == NLR_SEEK_SET)
        f->position = offset;
    else
        return -1;
    *out_position = f->position;
    return 0;
}

static int32_t mock_write(int32_t fd, const void *buf, uint32_t bytes,
                          uint32_t *out_written)
{
    struct mock_fd *f = &fds[fd];
    if (write_fail || !f->writable || f->position + bytes > f->len)
        return -1;
    memcpy(f->writable + f->position, buf, bytes);
    f->position += bytes;
    *out_written = bytes;
    settings_writes++;
    return 0;
}

static int32_t mock_close(int32_t fd)
{
    fds[fd].used = 0;
    return close_fail ? -1 : 0;
}

static uint32_t cache_before_calls, cache_after_calls;

/* The firmware's pre-read call invalidates whole lines from the rounded-down
 * start to the rounded-up end. Every range must start on a line, and a heap
 * buffer's lines must all belong to the caller's own block. */
static void mock_cache_before(void *addr, uint32_t len)
{
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = (start + len + NLR_CACHE_LINE - 1) & ~(uintptr_t)(NLR_CACHE_LINE - 1);
    CHECK(start % NLR_CACHE_LINE == 0);
    if (start >= (uintptr_t)alloc_pool && start < (uintptr_t)alloc_pool + sizeof alloc_pool)
        CHECK(inside_allocation(start, end));
    cache_before_calls++;
}

static void mock_cache_after(void *addr, uint32_t len)
{
    (void)addr;
    (void)len;
    cache_after_calls++;
}

/* ---- worker family and registry mock ------------------------------------ */

static uint8_t worker2_obj[0x200] __attribute__((aligned(8)));
static uint8_t wrong_svc_obj[0x200] __attribute__((aligned(8)));
static uint8_t decoy_obj[0x200] __attribute__((aligned(8)));
static void *registry_table[NLR_REGISTRY_IDS + 1];
static void (*worker_callback)(void *, uint32_t);
static int worker_init_silent;

static void mock_registry(uint32_t type, uint32_t id, void **out)
{
    *out = (type == NLR_REGISTRY_TYPE_TASK && id <= NLR_REGISTRY_IDS)
               ? registry_table[id]
               : 0;
}

static void fill_worker(void *worker, uint32_t id,
                        void (*callback)(void *, uint32_t))
{
    uint8_t *w = worker;
    /* Only the family-sized worker object is cleared: for the real runtime
     * the rest of the struct holds loader state that must survive. */
    memset(w, 0, NLR_WORKER_SIZE);
    uint64_t self = (uint64_t)(uintptr_t)w;
    uint32_t flag_id = id + 1;
    uint64_t callback_value = (uint64_t)(uintptr_t)callback;
    const void *table = &nlr_services;
    memcpy(w + NLR_WORKER_ID_OFFSET, &id, 4);
    memcpy(w + NLR_WORKER_NAME_OFFSET, "NLOADER", 8);
    memcpy(w + NLR_WORKER_SELF_OFFSET, &self, 8);
    memcpy(w + NLR_WORKER_FLAG_OFFSET, &flag_id, 4);
    memcpy(w + NLR_WORKER_CALLBACK_OFFSET, &callback_value, 8);
    memcpy(w + offsetof(struct nlr_runtime, load.svc), &table, sizeof table);
}

static void mock_worker_init(void *worker, void (*callback)(void *, uint32_t),
                             uint32_t mask, struct nlr_task_config *config)
{
    (void)mask;
    if (worker_init_silent)
        return;
    worker_callback = callback;
    fill_worker(worker, 5, callback);
    /* The firmware task creator registers the task object; the mock mirrors
     * that so registry discovery behaves like the body. */
    registry_table[5] = worker;
    config->assigned_id = 5;
}

static void mock_worker_start(void *worker)
{
    (void)worker;
}

/* A two-argument callback that is ours in shape but not in identity; used to
 * build registry lookalikes that must be rejected. */
static void decoy_callback(void *self, uint32_t events)
{
    (void)self;
    (void)events;
}

static int flag_set_fail;
static uint32_t flag_set_mask;
static const void *flag_set_target;

/* ---- page text channel mock --------------------------------------------- */

#define PAGE_CONTAINER 0x18u

static int widget_find_calls, text_store_calls, text_bind_calls;
static uint32_t widget_find_id, stored_slot, stored_format, bound_slot;
static const void *widget_find_container;
static const void *bound_widget;
static char stored_text[64];
static char slot_text[300][64];
static uint32_t hidden_rows[64];
static uint32_t hide_calls;
static int widget_find_fails;
static uint8_t page_widget; /* stands in for the firmware's widget object */
/* Call logs for the NLoader page, which looks up and binds twice on entry. */
static uint32_t found_ids[4], bound_slots[4];
static int widget_show_calls;
static const void *shown_widget;
static uint32_t shown_visible;

static void *mock_widget_find(uint32_t id, void *container)
{
    if (widget_find_calls < 4)
        found_ids[widget_find_calls] = id;
    widget_find_calls++;
    widget_find_id = id;
    widget_find_container = container;
    return widget_find_fails ? 0 : &page_widget;
}

static void mock_text_store(const char *text, uint32_t slot, uint32_t format)
{
    text_store_calls++;
    stored_slot = slot;
    stored_format = format;
    /* The original writer copies out of the caller's buffer; copying here the
     * same way is what makes a stack-buffer lifetime mistake visible. */
    snprintf(stored_text, sizeof stored_text, "%s", text);
    if (slot < 300)
        snprintf(slot_text[slot], sizeof slot_text[slot], "%s", text);
}

static void mock_text_bind(void *widget, uint32_t slot)
{
    if (text_bind_calls < 4)
        bound_slots[text_bind_calls] = slot;
    text_bind_calls++;
    bound_widget = widget;
    bound_slot = slot;
}

static void mock_widget_show(void *widget, uint32_t visible)
{
    widget_show_calls++;
    shown_widget = widget;
    shown_visible = visible;
}

/* Menu-data-equivalent page table; the page entry reads this symbol. */
#define OWN_TITLE_WIDGET 0x15adu
#define OWN_TITLE_SLOT   297u
#define OWN_TITLE_FORMAT 3u
#define OWN_TITLE_TEXT   "NLoader"
#define OWN_ROW_WIDGET   0x38c5u
#define OWN_ROW_SLOT     251u
#define OWN_ROW_STYLE    4u
#define OWN_ROW_TEXT     "NLoader page"
/* Not the Z8 value on purpose: the page must leave whatever the bindings
 * carry, never a code of its own. */
#define OWN_REENTER      0x6a1u
#define OWN_REFRESH      0x6a2u
#ifdef NLR_TEST_PAGE_REBUILD
/* The stock in-place rebuild: actions stay, and the page is built at the
 * view's own length. The firmware enters the page inside the rebuild; the
 * cases here enter it themselves after the action, as they do without. */
#define OWN_ACTION_NEXT OWN_STAY
static uint32_t rebuild_calls, present_calls, rebuild_type, rebuild_id;
static const uint8_t present_source_marker;
static void mock_page_rebuild(uint32_t type, uint32_t id)
{
    rebuild_calls++;
    rebuild_type = type;
    rebuild_id = id;
}
static void mock_present(const void *source, uint32_t a, uint32_t b)
{
    CHECK(source == &present_source_marker && a == 3u && b == 7u);
    CHECK(present_calls < rebuild_calls);
    present_calls++;
}
#else
#define OWN_ACTION_NEXT OWN_REENTER
#endif
#ifdef NLR_TEST_NATIVE_PAGE_REFRESH
static int native_refresh_enabled;
static uint32_t refresh_calls, refresh_old_rows, refresh_new_rows;
static void *refresh_window;

static void mock_page_refresh(void *window)
{
    /* Existing cases explicitly enter after their action. This additional
     * case exercises the synchronous native refresh boundary instead. */
    if (!native_refresh_enabled)
        return;
    refresh_calls++;
    refresh_window = window;
    refresh_old_rows = refresh_new_rows = 0;
    for (uint32_t row = 0; row < 64; row++)
        refresh_old_rows += !hidden_rows[row];
    nlr_page_enter(window);
    for (uint32_t row = 0; row < 64; row++)
        refresh_new_rows += !hidden_rows[row];
}
#endif
static const uint32_t own_row_slots[64] = {
    251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249
};
static void mock_row_hide(void *window, uint32_t row_index, uint32_t hidden)
{
    /* The stock function indexes item records before it reads the ID. */
    CHECK(window != 0 && row_index < 64);
    if (row_index < 64)
        hidden_rows[row_index] = hidden;
    hide_calls++;
}
/* The page record's item count the page sizes before each build. */
static uint16_t mock_page_count;
#define OWN_STAY 0x712u
/* The module's item records (flash on a body) and the page record, whose
 * items pointer the page repoints at its own copy for rows of the camera's
 * kinds, and whose flags take the skip flag then. */
#define OWN_ROW_FLAGS 0x101240u
#define OWN_PAGE_FLAGS 0x80001002u
#define OWN_SWITCH_FLAGS 0x20800005u
#define OWN_SWITCH_ON 0x133bu
#define OWN_SWITCH_OFF 0x133cu
#define OWN_SELECT_FLAGS 0x02000009u
#define OWN_SELECT_FORMAT 0x46u
#define OWN_SELECT_STYLE 0x004c004cu
#define OWN_ITEM_STYLES 0x00040004u
#define OWN_SKIP_FLAG 0x00800000u
#define OWN_WIDGET_TABLE 0x48u
static _Alignas(8) uint8_t mock_module_records[64 * NLR_MENU_ITEM_BYTES];
/* The page record is built into a window-table entry (96 bytes), which
 * the keyboard's window takes once the record has moved; the list's own
 * window record points at it. */
static _Alignas(8) uint8_t mock_page_record[NLR_MENU_WINDOW_BYTES];
static _Alignas(8) uint8_t mock_list_window[NLR_MENU_WINDOW_BYTES];
static uint32_t mock_table_object;
static uint32_t mock_row_widgets[64];
static uint32_t switch_states[64];     /* 0 untouched, 1 off, 2 on */
static uint32_t disabled_rows[64];

static void *mock_row_get(void *table, uint32_t row, uint32_t zero)
{
    CHECK(table == &mock_table_object && zero == 0 && row < 64);
    return row < 64 ? &mock_row_widgets[row] : 0;
}

static void mock_switch_set(void *row, uint32_t on)
{
    uint32_t index = (uint32_t)((uint32_t *)row - mock_row_widgets);
    if (index < 64)
        switch_states[index] = on ? 2u : 1u;
}

/* The page disables a row it has just looked up by its widget id. */
static void mock_widget_enable(void *widget, uint32_t enabled)
{
    uint32_t row = widget_find_id - OWN_ROW_WIDGET;
    /* NLR_TEST_ENABLE_INVERTED declares a (widget, disabled) primitive,
     * as the Z 8 has: the page then passes 1 to grey a row. */
#ifdef NLR_TEST_ENABLE_INVERTED
    CHECK(widget == &page_widget && enabled == 1u && row < 64);
#else
    CHECK(widget == &page_widget && !enabled && row < 64);
#endif
    if (row < 64)
        disabled_rows[row] = 1;
}

/* The stock keyboard the page clones: its window, page, event table and
 * handler block, and the engine's entry points. */
#define KBD_WINDOW 0x65bu
#define KBD_BACK 0x713u
#define KBD_PARENT 0x5f00ull
#define KBD_EVENTS 6u
static _Alignas(8) uint8_t mock_kbd_window[NLR_MENU_WINDOW_BYTES];
static _Alignas(8) uint8_t mock_kbd_page[NLR_MENU_PAGE_BYTES];
static _Alignas(8) uint8_t mock_kbd_events[KBD_EVENTS * NLR_MENU_EVENT_BYTES];
static const uint64_t mock_kbd_handlers[NLR_MENU_HANDLERS] = {
    0x5100u, 0x5108u, 0x5110u, 0x5118u, 0x5120u,
};
static const uint32_t kbd_codes[KBD_EVENTS] = {0x2ab, 0x2db, 0x2dc, 0x338, 0x2dd, 0x3f2};
static const uint32_t kbd_nexts[KBD_EVENTS] = {1, 0x712, 0x713, 0x713, 7, 0x712};
static struct {
    uint32_t opens, shown;
    char text[NLR_INPUT_MAX + 1];
    uint32_t charset, field, rows, length;
    void *window;
    uint32_t take_result;
    const char *typed;
} kbd;

static void mock_input_open(const void *params, void *window)
{
    const struct nlr_input_params *in = params;
    kbd.opens++;
    snprintf(kbd.text, sizeof kbd.text, "%s", in->text);
    kbd.charset = in->charset;
    kbd.field = in->field;
    kbd.rows = in->rows;
    kbd.length = in->length;
    kbd.window = window;
    CHECK(in->validator == 0 && in->pad == 0 && in->zero == 0);
}

/* As the engine does: at most the entry's length, NUL-padded to one past. */
static uint32_t mock_input_take(char *text)
{
    if (kbd.take_result & 1u)
        strncpy(text, kbd.typed, kbd.length + 1u);
    return kbd.take_result;
}

static void mock_input_shown(void *window, uint32_t zero)
{
    CHECK(window == kbd.window && zero == 0);
    kbd.shown++;
}

/* The stock Yes / No popup the caution box clones: its window, page, two
 * items with an event table each, handler block; the panel and cursor
 * calls it makes. */
#define CAU_PARENT 0x5f10ull
#define CAU_YES 0x5401u
#define CAU_NO 0x5402u
#define CAU_EVENTS 5u
#define CAU_SLOT 248u
#define CAU_FORMAT 3u
#define CAU_PANEL 0x4dc4u
#define CAU_OK_LABEL 0x625u
#define CAU_NO_ITEM 0x2b50u
static _Alignas(8) uint8_t mock_caution_window[NLR_MENU_WINDOW_BYTES];
static _Alignas(8) uint8_t mock_caution_page[NLR_MENU_PAGE_BYTES];
static _Alignas(8) uint8_t mock_caution_items[2 * NLR_MENU_ITEM_BYTES];
static _Alignas(8) uint8_t mock_caution_events[2][CAU_EVENTS * NLR_MENU_EVENT_BYTES];
static uint64_t mock_caution_tables[2];
static const uint64_t mock_caution_handlers[NLR_MENU_HANDLERS] = {
    0x5500u, 0x5508u, 0x5510u, 0, 0,
};
static const uint32_t cau_codes[CAU_EVENTS] = {0x2ab, 0x2b3, 0x2b2, 0x338, 0x3f2};
static struct {
    uint32_t calls, slots[4], modes[4];
    void *panel;
    uint32_t cursor_calls, cursor_item;
    void *cursor_window;
} cau;

static void mock_panel_text(void *panel, uint32_t slot, uint32_t mode)
{
    if (cau.calls < 4) {
        cau.slots[cau.calls] = slot;
        cau.modes[cau.calls] = mode;
    }
    cau.calls++;
    cau.panel = panel;
}

static void mock_cursor_set(void *window, uint32_t item)
{
    cau.cursor_calls++;
    cau.cursor_window = window;
    cau.cursor_item = item;
}

const struct nlr_menu_page nlr_menu_page = {
    .title_widget = OWN_TITLE_WIDGET,
    .title_slot = OWN_TITLE_SLOT,
    .title_format = OWN_TITLE_FORMAT,
    .row_widget = OWN_ROW_WIDGET,
    .row_slot = OWN_ROW_SLOT,
    .row_style = OWN_ROW_STYLE,
    .container_offset = PAGE_CONTAINER,
    .title_text = OWN_TITLE_TEXT,
    .row_text = OWN_ROW_TEXT,
    .widget_find = mock_widget_find,
    .text_store = mock_text_store,
    .text_bind = mock_text_bind,
    .widget_show = mock_widget_show,
    .row_count = 64,
    .row_slots = own_row_slots,
    .selected_offset = 0x32,
    .row_hide = mock_row_hide,
    .reenter_next = OWN_REENTER,
    .page_count = &mock_page_count,
    .stay_next = OWN_STAY,
    .page_items = (void **)(mock_page_record + NLR_MENU_PAGE_ITEMS),
    .switch_flags = OWN_SWITCH_FLAGS,
    .switch_on = OWN_SWITCH_ON,
    .switch_off = OWN_SWITCH_OFF,
    .select_flags = OWN_SELECT_FLAGS,
    .select_format = OWN_SELECT_FORMAT,
    .select_style = OWN_SELECT_STYLE,
    .skip_flag = OWN_SKIP_FLAG,
    .widget_table = OWN_WIDGET_TABLE,
    .row_get = mock_row_get,
    .switch_set = mock_switch_set,
    .widget_enable = mock_widget_enable,
#ifdef NLR_TEST_ENABLE_INVERTED
    .widget_enable_inverted = 1,
#endif
    .page_record = mock_page_record,
    .page_window = mock_list_window,
    .input_window = KBD_WINDOW,
    .back_nav = KBD_BACK,
    .input_template = mock_kbd_window,
    .input_page = mock_kbd_page,
    .input_events = mock_kbd_events,
    .input_event_count = KBD_EVENTS,
    .input_save = 0x2dc,
    .input_menu = 0x2ab,
    .input_back = 0x338,
    .input_help = 0x2dd,
    .input_handlers = mock_kbd_handlers,
    .input_open = mock_input_open,
    .input_take = mock_input_take,
    .input_shown = mock_input_shown,
    .caution_template = mock_caution_window,
    .caution_page = mock_caution_page,
    .caution_items = mock_caution_items,
    .caution_tables = mock_caution_tables,
    .caution_count_yes = CAU_EVENTS,
    .caution_count_no = CAU_EVENTS,
    .caution_handlers = mock_caution_handlers,
    .caution_yes = CAU_YES,
    .caution_no = CAU_NO,
    .caution_panel = CAU_PANEL,
    .caution_slot = CAU_SLOT,
    .caution_format = CAU_FORMAT,
    .caution_ok_label = CAU_OK_LABEL,
    .caution_no_item = CAU_NO_ITEM,
    .panel_text = mock_panel_text,
    .cursor_set = mock_cursor_set,
#ifdef NLR_TEST_PAGE_REBUILD
    .page_rebuild = mock_page_rebuild,
    .present = mock_present,
    .present_source = &present_source_marker,
    .present_a = 3,
    .present_b = 7,
#endif
#ifdef NLR_TEST_NATIVE_PAGE_REFRESH
    .page_refresh = mock_page_refresh,
    .refresh_next = OWN_REFRESH,
#endif
};

/* The labels of the Setup page's two rows, and the Setup page itself as
 * the loader's pages see it (bindings-equivalent). The pages are on only
 * in the case built for them; every other case keeps the one NLoader list. */
const struct nlr_menu_prefill nlr_menu_prefill = {
    .text = OWN_TITLE_TEXT,
    .apps_text = "Apps",
};
static _Alignas(8) uint8_t mock_setup_items[52 * NLR_MENU_ITEM_BYTES];
static _Alignas(8) uint8_t mock_setup_record[NLR_MENU_PAGE_BYTES];
/* The Setup window record: its built-rows table (OWN_WIDGET_TABLE) is
 * null while the window is not built. */
static _Alignas(8) uint8_t mock_setup_window[NLR_MENU_WINDOW_BYTES];
#ifdef NLR_TEST_PAGES
#define TEST_PAGES 1u
#else
#define TEST_PAGES 0u
#endif
/* The Setup cursor setting (a stand-in for the firmware's store): the
 * stock getter and setter the redirected calls reach. 50 stock rows,
 * NLoader after them, Firmware version at 48; window cursor at 0x32 and
 * scroll at 0x58, as on the Z 8. */
#define MOCK_CURSOR_SETTING 0x4904u
#define MOCK_CURSOR_OFFSET 0x32u
#define MOCK_SCROLL_OFFSET 0x58u
static uint32_t mock_cursor_value;
static uint32_t mock_cursor_other;
static uint32_t mock_cursor_last_id;
static uint32_t mock_cursor_get(uint32_t id)
{
    mock_cursor_last_id = id;
    return id == MOCK_CURSOR_SETTING ? mock_cursor_value : mock_cursor_other;
}
static uint32_t mock_cursor_put(uint32_t id, uint32_t value)
{
    mock_cursor_last_id = id;
    if (id == MOCK_CURSOR_SETTING)
        mock_cursor_value = value;
    else
        mock_cursor_other = value;
    return 1;
}
const struct nlr_menu_setup nlr_menu_setup = {
    .pages = TEST_PAGES,
    .apps_first = 1,
    .fields = mock_setup_record + 0x10,
    .items = mock_setup_items,
    .version = "9.9.9",
    .module = "736ceaac",
    .window = mock_setup_window,
    .cursor_setting = MOCK_CURSOR_SETTING,
    .stock_rows = 50,
    .entry_index = 50,
    .version_row = 48,
    .cursor_offset = MOCK_CURSOR_OFFSET,
    .scroll_offset = MOCK_SCROLL_OFFSET,
    .cursor_get = mock_cursor_get,
    .cursor_set = mock_cursor_put,
};

static int32_t mock_flag_set(void *flag, uint32_t mask)
{
    flag_set_target = flag;
    flag_set_mask = mask;
    return flag_set_fail ? -1 : 0;
}

static uint32_t page_publish_calls;
static int32_t page_publish_result;

static int32_t mock_page_publish(void *context,
                                 const struct nlr_menu_test_item *item)
{
    (void)context;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r && r->load.state == 0);
    CHECK(item->label_id == 0x379u && item->item_id == 0x7ffdu);
    page_publish_calls++;
    return page_publish_result;
}

static const struct nlr_resource_services page_resources = {
    .publish = mock_page_publish,
};

/* The page reads this table through the extern symbol, so the mock wears
 * the real bindings name. */
/* The GUI's current screen (profile table "gui.screen.current"): a
 * stand-in for the live-view object's address, whose CRC the table's stock
 * CRC is, unless a test puts the camera in a menu. */
static uint64_t mock_screen = 0x123456780ull;
static const struct nlr_platform_table mock_tables[] = {
    { "gui.screen.current", (uint64_t)(uintptr_t)&mock_screen, 8, NLR_TABLE_RAM,
      0x194081b6u, 0, 0 },
};
static const struct nlr_platform_services mock_platform = {
    .tables = mock_tables,
    .table_count = 1,
};

const struct nlr_services nlr_services = {
    .abi = 1,
    .platform = &mock_platform,
    .alloc = mock_alloc,
    .release = mock_release,
    .worker_init = mock_worker_init,
    .worker_start = mock_worker_start,
    .flag_set = mock_flag_set,
    .file_open = mock_open,
    .file_read = mock_read,
    .file_seek = mock_seek,
    .file_close = mock_close,
    .file_write = mock_write,
    .file_open_rw = 0x2,
    .cache_before_read = mock_cache_before,
    .cache_after_read = mock_cache_after,
    .registry_lookup = mock_registry,
    .resources = &page_resources,
};

/* Bindings-equivalent task config; create() and find() both read it. */
const struct nlr_task_config nlr_task_config = {
    .core = 3,
    .priority = 20,
    .stack_bytes = 0x8000,
    .name = {'N', 'L', 'O', 'A', 'D', 'E', 'R', 0},
};

/* ---- card content ------------------------------------------------------- */

static uint32_t test_crc32(const uint8_t *p, uint32_t n)
{
    uint32_t c = ~0u;
    while (n--) {
        c ^= *p++;
        for (unsigned b = 0; b < 8; b++)
            c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
    }
    return ~c;
}

struct card_spec {
    uint32_t image_len;
    uint32_t bss;
    uint32_t entry;
    uint32_t abi;
    uint32_t flags;
    uint32_t version;
    uint32_t header_size;
    uint32_t crc_xor;
    int drop_magic;
    int32_t file_delta; /* file length = header + image + delta */
};

static void build_card(const struct card_spec *spec)
{
    uint8_t header[32];
    card_len = 0;
    memset(header, 0, sizeof header);
    if (!spec->drop_magic)
        memcpy(header, "NPLD", 4);
    header[4] = (uint8_t)spec->version;
    header[5] = (uint8_t)(spec->version >> 8);
    header[6] = (uint8_t)spec->header_size;
    header[7] = (uint8_t)(spec->header_size >> 8);
    memcpy(header + 8, &spec->flags, 4);
    memcpy(header + 0xc, &spec->image_len, 4);
    memcpy(header + 0x10, &spec->bss, 4);
    memcpy(header + 0x14, &spec->entry, 4);
    memcpy(header + 0x18, &spec->abi, 4);
    uint32_t image_len = spec->image_len;
    if (image_len <= sizeof card) {
        uint8_t *image = card + 32;
        for (uint32_t n = 0; n < image_len; n++)
            image[n] = (uint8_t)(n * 7 + 3);
        uint32_t crc = test_crc32(image, image_len) ^ spec->crc_xor;
        memcpy(header + 0x1c, &crc, 4);
        memcpy(card, header, 32);
        card_len = 32 + image_len;
    } else {
        /* Too large for the card buffer on purpose: the loader must reject
         * the declared size before reading the image. */
        memcpy(card, header, 32);
        card_len = 32 + 16;
    }
    if (spec->file_delta >= 0) {
        memset(card + card_len, 0, (uint32_t)spec->file_delta);
        card_len += (uint32_t)spec->file_delta;
    } else if ((uint32_t)-spec->file_delta <= card_len) {
        card_len += (uint32_t)spec->file_delta;
    }
}

static struct card_spec valid_spec(uint32_t image_len)
{
    struct card_spec spec = {0};
    spec.image_len = image_len;
    spec.version = 1;
    spec.header_size = 32;
    spec.abi = 1;
    return spec;
}

/* ---- scenarios ---------------------------------------------------------- */

static void reset_mocks(void)
{
    for (uint32_t k = 0; k < 64; k++) {
        uint8_t *rec = mock_module_records + k * NLR_MENU_ITEM_BYTES;
        memset(rec, 0, NLR_MENU_ITEM_BYTES);
        *(uint32_t *)rec = 0x100u + k;                       /* its slot */
        *(uint32_t *)(rec + NLR_MENU_ITEM_FLAGS) = OWN_ROW_FLAGS;
        *(uint32_t *)(rec + NLR_MENU_ITEM_VALUE) = 0xffffu;
        *(uint32_t *)(rec + NLR_MENU_ITEM_STYLE) = OWN_ITEM_STYLES;
    }
    memset(mock_page_record, 0, sizeof mock_page_record);
    *(uint32_t *)mock_page_record = OWN_PAGE_FLAGS;
    *(void **)(mock_page_record + NLR_MENU_PAGE_ITEMS) = mock_module_records;
    memset(mock_list_window, 0, sizeof mock_list_window);
    *(uint16_t *)mock_list_window = 2;
    *(uint16_t *)(mock_list_window + NLR_MENU_WINDOW_ID) = 0x65a;
    *(void **)(mock_list_window + NLR_MENU_WINDOW_PAGE) = mock_page_record;
    memset(mock_kbd_window, 0, sizeof mock_kbd_window);
    *(uint16_t *)mock_kbd_window = 2;
    *(uint16_t *)(mock_kbd_window + NLR_MENU_WINDOW_ID) = 0x2e4;
    *(uint64_t *)(mock_kbd_window + NLR_MENU_WINDOW_PARENT) = KBD_PARENT;
    *(const void **)(mock_kbd_window + NLR_MENU_WINDOW_HANDLERS) = mock_kbd_handlers;
    *(void **)(mock_kbd_window + NLR_MENU_WINDOW_PAGE) = mock_kbd_page;
    for (uint32_t n = 0; n < NLR_MENU_PAGE_BYTES; n++)
        mock_kbd_page[n] = (uint8_t)(0x40u + n);
    *(void **)(mock_kbd_page + NLR_MENU_PAGE_EVENTS) = 0;
    memset(mock_kbd_events, 0, sizeof mock_kbd_events);
    for (uint32_t k = 0; k < KBD_EVENTS; k++) {
        uint8_t *event = mock_kbd_events + k * NLR_MENU_EVENT_BYTES;
        *(uint32_t *)event = kbd_codes[k];
        *(uint64_t *)(event + NLR_MENU_EVENT_ACTION) = 0x5200u + k;
        *(uint64_t *)(event + NLR_MENU_EVENT_GUARD) = k == 4 ? 0x5300u : 0;
        *(uint32_t *)(event + NLR_MENU_EVENT_NEXT) = kbd_nexts[k];
    }
    memset(&kbd, 0, sizeof kbd);
    kbd.take_result = 1;
    kbd.typed = "";
    memset(mock_caution_window, 0, sizeof mock_caution_window);
    *(uint16_t *)mock_caution_window = 2;
    *(uint16_t *)(mock_caution_window + NLR_MENU_WINDOW_ID) = 0x5a;
    *(uint64_t *)(mock_caution_window + NLR_MENU_WINDOW_PARENT) = CAU_PARENT;
    for (uint32_t n = 0; n < NLR_MENU_PAGE_BYTES; n++)
        mock_caution_page[n] = (uint8_t)(0x80u + n);
    *(uint16_t *)(mock_caution_page + NLR_MENU_PAGE_COUNT) = 2;
    memset(mock_caution_items, 0, sizeof mock_caution_items);
    for (uint32_t k = 0; k < 2; k++) {
        uint8_t *item = mock_caution_items + k * NLR_MENU_ITEM_BYTES;
        *(uint32_t *)item = 0x46u + k;                       /* Yes, No */
        *(uint32_t *)(item + 0x18) = 0x2b4fu + k;
        for (uint32_t e = 0; e < CAU_EVENTS; e++) {
            uint8_t *event = mock_caution_events[k] + e * NLR_MENU_EVENT_BYTES;
            memset(event, 0, NLR_MENU_EVENT_BYTES);
            *(uint32_t *)event = cau_codes[e];
            uint64_t action = cau_codes[e] == 0x2b3 ? (k ? CAU_NO : CAU_YES)
                            : cau_codes[e] == 0x2b2 ? CAU_NO
                            : cau_codes[e] == 0x2ab ? 0x5600u : 0;
            *(uint64_t *)(event + NLR_MENU_EVENT_ACTION) = action;
            *(uint64_t *)(event + NLR_MENU_EVENT_GUARD) = cau_codes[e] == 0x2b2 ? 0x5700u : 0;
            *(uint32_t *)(event + NLR_MENU_EVENT_NEXT) =
                cau_codes[e] == 0x2ab ? 1u : cau_codes[e] == 0x338 ? 0x713u : 0x712u;
        }
        mock_caution_tables[k] = (uint64_t)(uintptr_t)mock_caution_events[k];
    }
    memset(&cau, 0, sizeof cau);
    memset(switch_states, 0, sizeof switch_states);
    memset(disabled_rows, 0, sizeof disabled_rows);
    card_settings_present = write_fail = 0;
    card_master = card_boot_id = 0;
    settings_writes = last_open_flags = 0;
    mock_page_count = 0;
    alloc_used = 0;
    alloc_fail_countdown = -1;
    alloc_calls = release_calls = 0;
    alloc_count = 0;
    exec_protect_calls = exec_protect_fail_at = 0;
    probe_call_count = 0;
    open_fail = seek_fail = close_fail = fail_next_read = 0;
    safe_mode_present = 0;
#ifdef NLR_TEST_NATIVE_PAGE_REFRESH
    native_refresh_enabled = 0;
    refresh_calls = refresh_old_rows = refresh_new_rows = 0;
    refresh_window = 0;
#endif
#ifdef NLR_TEST_PAGE_REBUILD
    rebuild_calls = present_calls = rebuild_type = rebuild_id = 0;
#endif
    card_manifest_present = 0;
    card_enabled_data = 0;
    card_enabled_bytes = 0;
    manifest_opens = program_opens = 0;
    memset(program_path, 0, sizeof program_path);
    read_max = 0x1000;
    cache_before_calls = cache_after_calls = 0;
    memset(fds, 0, sizeof fds);
    memset(registry_table, 0, sizeof registry_table);
    worker_callback = 0;
    worker_init_silent = 0;
    flag_set_fail = 0;
    flag_set_mask = 0;
    widget_find_calls = text_store_calls = text_bind_calls = 0;
    widget_find_id = stored_slot = stored_format = bound_slot = 0;
    widget_find_container = bound_widget = 0;
    widget_find_fails = 0;
    memset(stored_text, 0, sizeof stored_text);
    memset(slot_text, 0, sizeof slot_text);
    memset(hidden_rows, 0, sizeof hidden_rows);
    hide_calls = 0;
    memset(found_ids, 0, sizeof found_ids);
    memset(bound_slots, 0, sizeof bound_slots);
    widget_show_calls = 0;
    shown_widget = 0;
    shown_visible = 0;
    text_seam_slot = 0;
    text_seam_active = 0;
    text_seam_publishes = 0;
    text_seam_turn = 0;
    text_seam_fires = 0;
}

static const char task_name[NLR_TASK_NAME_SIZE] = {'N', 'L', 'O', 'A', 'D', 'E', 'R', 0};

/* Returns the newest trace entry; fails the CHECK at the caller otherwise. */
static int trace_last(struct nlr_load *l, char *tag, int32_t *value)
{
    if (!l || l->trace.count == 0)
        return 0;
    const union nlr_trace_entry *e =
        &l->trace.entries[(l->trace.count - 1) & (NLR_TRACE_SLOTS - 1)];
    *tag = (char)(e->seq_tag & 0xFF);
    *value = e->value;
    return 1;
}

static struct nlr_task_config default_task(void)
{
    struct nlr_task_config task = {0};
    task.core = 3;
    task.priority = 20;
    task.stack_bytes = 0x8000;
    memcpy(task.name, task_name, sizeof task_name);
    return task;
}

static void valid_runtime_flow(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);

    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);
    CHECK(r != 0);
    CHECK(worker_callback == nlr_load_event);
    uint32_t named = 0;
    CHECK(nlr_runtime_find(&nlr_services, &named) == r);
    CHECK(named == 1);

    uint32_t allocs_after_create = alloc_calls;
    struct nlr_runtime *attached =
        nlr_runtime_attach(&nlr_services, ARENA_CAP, &named);
    CHECK(attached == r);
    CHECK(named == 1);
    CHECK(alloc_calls == allocs_after_create); /* no duplicate construction */

    /* The worker path: a queued attempt runs when the firmware delivers the
     * event, against the program the caller selected. */
    r->load.path = TEST_PATH;
    CHECK(nlr_load_enqueue_once(&r->load) == NLR_OK);
    CHECK(flag_set_mask == 1);
    /* The set must target the in-place flag object at worker+0x38. */
    CHECK(flag_set_target == r->load.worker.opaque + NLR_WORKER_FLAG_OFFSET);
    /* While queued, an attempt in the caller's task must not start too. */
    CHECK(nlr_load_now(&r->load) == NLR_BUSY);
    /* The firmware worker would deliver this event; the test delivers it. */
    nlr_load_event(r, 1);
    CHECK(r->load.last_result == NLR_OK);
    CHECK(r->load.state == 0);
    CHECK(r->load.image_bytes == 16);
    CHECK(r->load.entry_offset == 0);
    CHECK(r->load.bss_bytes == 0);
    CHECK(r->load.abi_version == 1);
    CHECK(r->load.stage == 'V');
    char tag = 0;
    int32_t value = 0;
    CHECK(trace_last(&r->load, &tag, &value));
    CHECK(tag == 'E' && value == NLR_OK);
    nlr_load_event(r, 1); /* idle again: must be ignored */
    CHECK(r->load.last_result == NLR_OK);

    /* The same attempt in the caller's task, as the page runs it. */
    CHECK(nlr_load_now(&r->load) == NLR_OK);
    CHECK(r->load.state == 0);
    CHECK(trace_last(&r->load, &tag, &value));
    CHECK(tag == 'E' && value == NLR_OK);
}

static void chunked_read_crosses_cache_chunks(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(0x2100);
    build_card(&spec);

    static _Alignas(NLR_CACHE_LINE) uint8_t arena[ARENA_CAP];
    struct nlr_load l = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_OK);
    l.path = TEST_PATH;
    read_max = 0x300;
    CHECK(nlr_load_file(&l) == NLR_OK);
    CHECK(l.image_bytes == 0x2100);
    /* One invalidate/clean pair per disjoint 0x1000 chunk: the header plus
     * three image chunks -> 4 pairs. */
    CHECK(cache_before_calls == 4);
    CHECK(cache_after_calls == 4);
}

static void expects(int want_result, char want_stage, const char *what)
{
    static _Alignas(NLR_CACHE_LINE) uint8_t arena[ARENA_CAP];
    struct nlr_load l = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_OK);
    l.path = TEST_PATH;
    int result = nlr_load_file(&l);
    if (result != want_result || (char)l.stage != want_stage) {
        printf("FAIL %s: result %d stage %c (want %d %c)\n", what, result,
               (char)l.stage, want_result, want_stage);
        failures++;
    }
    /* The trace must end on the same terminal step the caller observes. */
    char tag = 0;
    int32_t value = 0;
    if (trace_last(&l, &tag, &value)) {
        if (tag != want_stage || value != want_result) {
            printf("FAIL %s: trace %c %d (want %c %d)\n", what, tag, value,
                   want_stage, want_result);
            failures++;
        }
    } else {
        printf("FAIL %s: trace empty\n", what);
        failures++;
    }
}

static void format_rejections(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    spec.version = 2;
    build_card(&spec);
    expects(NLR_FORMAT, 'V', "header_version 2");

    spec = valid_spec(16);
    spec.header_size = 31;
    build_card(&spec);
    expects(NLR_FORMAT, 'V', "header_size");

    spec = valid_spec(16);
    spec.flags = 1;
    build_card(&spec);
    expects(NLR_FORMAT, 'V', "unknown flags");

    spec = valid_spec(16);
    spec.bss = 4;
    build_card(&spec);
    expects(NLR_FORMAT, 'V', "bss in load stage");

    spec = valid_spec(16);
    spec.drop_magic = 1;
    build_card(&spec);
    expects(NLR_FORMAT, 'V', "magic");
}

static void bounds_rejections(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    spec.file_delta = -1; /* file shorter than header + image */
    build_card(&spec);
    expects(NLR_BOUNDS, 'V', "file size mismatch");

    spec = valid_spec(16);
    spec.entry = 1; /* unaligned */
    build_card(&spec);
    expects(NLR_BOUNDS, 'V', "unaligned entry");

    spec = valid_spec(16);
    spec.entry = 16; /* beyond the image */
    build_card(&spec);
    expects(NLR_BOUNDS, 'V', "entry out of bounds");

    spec = valid_spec(2); /* image too small to hold an entry */
    spec.file_delta = 2;  /* file long enough to pass the size sanity check */
    build_card(&spec);
    expects(NLR_BOUNDS, 'V', "image below minimum");

    spec = valid_spec(0x20000); /* beyond the arena */
    build_card(&spec);
    expects(NLR_BOUNDS, 'V', "image beyond capacity");
}

static void checksum_and_io_paths(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    spec.crc_xor = 1;
    build_card(&spec);
    expects(NLR_CHECKSUM, 'K', "crc mismatch");

    reset_mocks();
    open_fail = 1;
    build_card(&spec);
    expects(NLR_IO, 'O', "open failure");

    reset_mocks();
    seek_fail = 1;
    build_card(&spec);
    expects(NLR_IO, 'S', "seek failure");

    reset_mocks();
    fail_next_read = 1;
    build_card(&spec);
    expects(NLR_IO, 'H', "header read failure");

    reset_mocks();
    close_fail = 1;
    spec = valid_spec(16); /* a verified image whose close then fails */
    build_card(&spec);
    /* A completed load that cannot close is a failure with no published
     * image: the caller must not treat the bytes as verified. */
    static _Alignas(NLR_CACHE_LINE) uint8_t arena[ARENA_CAP];
    struct nlr_load l = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_OK);
    l.path = TEST_PATH;
    CHECK(nlr_load_file(&l) == NLR_IO);
    CHECK(l.stage == 'C');
    CHECK(l.image_bytes == 0 && l.entry_offset == 0 && l.bss_bytes == 0);
}

static void safe_mode_disables_loading(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    safe_mode_present = 1;
    static _Alignas(NLR_CACHE_LINE) uint8_t arena[ARENA_CAP];
    struct nlr_task_config task = default_task();

    struct nlr_load l = {0};
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_OK);
    l.path = TEST_PATH;
    CHECK(nlr_load_file(&l) == NLR_DISABLED);
    CHECK(l.stage == 'M');
    CHECK(l.image_bytes == 0 && l.entry_offset == 0 && l.bss_bytes == 0);
    char tag = 0;
    int32_t value = 0;
    CHECK(trace_last(&l, &tag, &value));
    /* The record carries the presence store's answer (load_safe_guard), the
     * same on every body: the flag is there. */
    CHECK(tag == 'M' && value == NLR_DISABLED);
    for (unsigned n = 0; n < sizeof fds / sizeof fds[0]; n++)
        CHECK(!fds[n].used); /* the flag file was closed immediately */

    /* A found flag whose close fails is an IO failure, not a confirmed
     * disabled result, and no payload is opened or read afterward. */
    close_fail = 1;
    uint32_t opened = program_opens, reads = cache_before_calls;
    CHECK(nlr_load_file(&l) == NLR_IO);
    CHECK(l.stage == 'M');
    CHECK(trace_last(&l, &tag, &value) && tag == 'M' && value == NLR_IO);
    CHECK(program_opens == opened && cache_before_calls == reads);
    CHECK(l.image_bytes == 0 && l.header_bytes == 0);
    close_fail = 0;

    /* Without the flag the same payload loads normally. */
    safe_mode_present = 0;
    struct nlr_load l2 = {0};
    CHECK(nlr_load_init(&l2, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_OK);
    l2.path = TEST_PATH;
    CHECK(nlr_load_file(&l2) == NLR_OK);
    CHECK(l2.image_bytes == 16);
}

static void not_ready_and_busy(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    static _Alignas(NLR_CACHE_LINE) uint8_t arena[ARENA_CAP];
    struct nlr_task_config task = default_task();

    struct nlr_load l = {0};
    CHECK(nlr_load_init(&l, 0, arena, ARENA_CAP, &task) == NLR_NOT_READY);
    CHECK(nlr_load_init(&l, &nlr_services, 0, ARENA_CAP, &task) ==
          NLR_NOT_READY);
    CHECK(nlr_load_init(&l, &nlr_services, arena, 16, &task) ==
          NLR_NOT_READY);
    struct nlr_task_config bad = task;
    bad.priority = 0;
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &bad) ==
          NLR_NOT_READY);
    bad = task;
    bad.core = NLR_TASK_CORE_MAX + 1;
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &bad) ==
          NLR_NOT_READY);
    bad = task;
    bad.stack_bytes = 0;
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &bad) ==
          NLR_NOT_READY);

    /* A load without a selected program has nothing to open. */
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_OK);
    CHECK(nlr_load_file(&l) == NLR_NOT_READY);
    l.path = TEST_PATH;
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_BUSY); /* re-init of a live worker is refused */
    CHECK(nlr_load_enqueue_once(&l) == NLR_OK);
    CHECK(nlr_load_enqueue_once(&l) == NLR_BUSY); /* double enqueue refused */
    nlr_load_event(&l, 1);
    CHECK(l.last_result == NLR_OK);
}

static void flag_failure_rewinds_state(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    static _Alignas(NLR_CACHE_LINE) uint8_t arena[ARENA_CAP];
    struct nlr_load l = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_OK);
    l.path = TEST_PATH;
    flag_set_fail = 1;
    CHECK(nlr_load_enqueue_once(&l) == NLR_IO);
    CHECK(l.state == 0); /* rewound so a retry is possible */
    char tag = 0;
    int32_t value = 0;
    CHECK(trace_last(&l, &tag, &value));
    CHECK(tag == 'Q' && value == NLR_IO);
    flag_set_fail = 0;
    CHECK(nlr_load_enqueue_once(&l) == NLR_OK);
    nlr_load_event(&l, 1);
    CHECK(l.last_result == NLR_OK);
    CHECK(trace_last(&l, &tag, &value));
    CHECK(tag == 'E' && value == NLR_OK);
}

static void partial_construction_is_kept(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    worker_init_silent = 1; /* kernel built nothing; ids stay zero */

    struct nlr_load l = {0};
    static _Alignas(NLR_CACHE_LINE) uint8_t arena[ARENA_CAP];
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&l, &nlr_services, arena, ARENA_CAP, &task) ==
          NLR_PARTIAL);

    struct nlr_runtime *r = 0;
    uint32_t allocs_before = alloc_calls, releases_before = release_calls;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) ==
          NLR_PARTIAL);
    CHECK(r != 0); /* retained: kernel-side references may exist */
    /* runtime struct, program arena, directory buffer */
    CHECK(alloc_calls == allocs_before + 3);
    CHECK(release_calls == releases_before); /* nothing was unwound */
    char tag = 0;
    int32_t value = 0;
    CHECK(trace_last(&r->load, &tag, &value));
    CHECK(tag == 'N' && value == NLR_PARTIAL);

    /* A later attempt whose arena allocation fails unwinds completely. */
    worker_init_silent = 0;
    r = 0;
    alloc_fail_countdown = 1; /* the struct allocates, the arena fails */
    allocs_before = alloc_calls;
    releases_before = release_calls;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) ==
          NLR_NOT_READY);
    CHECK(r == 0);
    /* The arena was never allocated, so only the struct is released and the
     * directory buffer is never requested. */
    CHECK(release_calls == releases_before + 1);
    CHECK(alloc_calls == allocs_before + 2);
}

static void registry_ambiguity_and_decoys(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);

    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);

    /* A lookalike with our name but a different callback must be counted as
     * named yet rejected. */
    fill_worker(decoy_obj, 7, decoy_callback);
    registry_table[7] = decoy_obj;
    /* A named object with our shape but a foreign service table must be
     * rejected by the service filter while still being counted. */
    fill_worker(wrong_svc_obj, 11, nlr_load_event);
    const struct nlr_services *foreign = 0;
    memcpy(wrong_svc_obj + offsetof(struct nlr_runtime, load.svc), &foreign,
           sizeof foreign);
    registry_table[11] = wrong_svc_obj;
    uint32_t named = 0;
    CHECK(nlr_runtime_find(&nlr_services, &named) == r);
    CHECK(named == 3); /* ours, the callback lookalike, the foreign table */

    /* Two complete matches are ambiguous; attach must refuse and must not
     * construct a third runtime. The second match gets the highest id so the
     * count above is complete before the scan aborts. */
    uint32_t allocs_before = alloc_calls;
    fill_worker(worker2_obj, 21, nlr_load_event);
    registry_table[21] = worker2_obj;
    named = 0;
    CHECK(nlr_runtime_find(&nlr_services, &named) == 0);
    CHECK(named == 4);
    CHECK(nlr_runtime_attach(&nlr_services, ARENA_CAP, &named) == 0);
    CHECK(alloc_calls == allocs_before);
}

/* The bindings normally carry the camera identity; the tests supply the
 * same shape so the directory gate has something to compare against. */
const struct nlr_identity nlr_identity = { "z8", "3.11" };

/* ---- card directory (MANIFEST) ----------------------------------------- */

/* The parser keeps offsets into the buffer, so the tests compare the text it
 * points at rather than copies of it. */
static int entry_is(const struct nlr_manifest *m, uint32_t index,
                    const char *id, const char *name, const char *file,
                    uint32_t kind, uint32_t min_abi)
{
    if (index >= m->count)
        return 0;
    const struct nlr_manifest_entry *e = &m->entries[index];
    return e->kind == kind && e->min_abi == min_abi &&
           e->id_len == strlen(id) &&
           memcmp(m->buffer + e->id_off, id, e->id_len) == 0 &&
           e->name_len == strlen(name) &&
           memcmp(m->buffer + e->name_off, name, e->name_len) == 0 &&
           e->file_len == strlen(file) &&
           memcmp(m->buffer + e->file_off, file, e->file_len) == 0;
}

static struct nlr_manifest manifest;

static int parse_text(const char *text)
{
    return nlr_manifest_parse(&manifest, (const uint8_t *)text,
                              (uint32_t)strlen(text));
}

static void manifest_accepts_a_well_formed_directory(void)
{
    /* Comments, blank lines, CRLF endings, spaces around the separators and
     * an omitted support column all appear in hand-written files. */
    static const char text[] =
        "# id | kind | name | file | min_abi | model/firmware\r\n"
        "\r\n"
        "menu_extension | resource_extension | Menu extension | "
        "APPS/MENU.NLB | 2 | z8/3.11\r\n"
        "hello|foreground|Hello|APPS/HELLO.NLB|1\n"
        "   doom | foreground | DOOM | APPS\\DOOM.NLB | 2 | z8/3.11, z6iii/2.00\n";
    CHECK(parse_text(text) == NLR_OK);
    CHECK(manifest.error == NLR_MF_OK);
    CHECK(manifest.count == 3);
    CHECK(entry_is(&manifest, 0, "menu_extension", "Menu extension",
                   "APPS/MENU.NLB", NLR_KIND_RESOURCE_EXTENSION, 2));
    CHECK(entry_is(&manifest, 1, "hello", "Hello", "APPS/HELLO.NLB",
                   NLR_KIND_FOREGROUND, 1));
    CHECK(entry_is(&manifest, 2, "doom", "DOOM", "APPS\\DOOM.NLB",
                   NLR_KIND_FOREGROUND, 2));
    /* Line numbers count comments and blanks so a report matches the file. */
    CHECK(manifest.entries[0].line == 3);
    CHECK(manifest.entries[1].line == 4);
    CHECK(manifest.entries[2].line == 5);
    CHECK(manifest.entries[1].support_len == 0);
    CHECK(manifest.entries[2].support_len == strlen("z8/3.11, z6iii/2.00"));
    /* No verdict before the gate runs. */
    CHECK(manifest.entries[0].gate == NLR_GATE_UNKNOWN);

    /* Empty directory: zero entries is a legitimate state, not an error. */
    CHECK(parse_text("# nothing here\n") == NLR_OK);
    CHECK(manifest.count == 0);
    CHECK(manifest.error == NLR_MF_OK);
}

static void manifest_rejects_every_malformed_line(void)
{
    static const struct {
        const char *text;
        uint32_t reason;
        uint32_t line;
        int result;
    } cases[] = {
        {"a | foreground | A\n", NLR_MF_FIELDS, 1, NLR_FORMAT},
        {"a | foreground | A | APPS/A.NLB | 1 | z8/3.11 | extra\n",
         NLR_MF_FIELDS, 1, NLR_FORMAT},
        {" | foreground | A | APPS/A.NLB | 1\n", NLR_MF_ID, 1, NLR_FORMAT},
        {"a b | foreground | A | APPS/A.NLB | 1\n", NLR_MF_ID, 1, NLR_FORMAT},
        /* kind is mandatory and closed (PLAN 6.2). */
        {"a |  | A | APPS/A.NLB | 1\n", NLR_MF_KIND, 1, NLR_FORMAT},
        {"a | plugin | A | APPS/A.NLB | 1\n", NLR_MF_KIND, 1, NLR_FORMAT},
        {"a | Foreground | A | APPS/A.NLB | 1\n", NLR_MF_KIND, 1, NLR_FORMAT},
        {"a | foreground |  | APPS/A.NLB | 1\n", NLR_MF_NAME, 1, NLR_FORMAT},
        {"a | foreground | 0123456789012345678901234 | APPS/A.NLB | 1\n",
         NLR_MF_NAME, 1, NLR_FORMAT},
        /* The display path is the stock ASCII writer; a byte it cannot draw
         * is refused instead of reaching the screen. */
        {"a | foreground | \xe4\xb8\xad | APPS/A.NLB | 1\n", NLR_MF_NAME, 1,
         NLR_FORMAT},
        {"a | foreground | A | HELLO.NLB | 1\n", NLR_MF_FILE, 1, NLR_FORMAT},
        {"a | foreground | A | APPS/../BOOT.NLB | 1\n", NLR_MF_FILE, 1,
         NLR_FORMAT},
        {"a | foreground | A | B:\\APPS\\A.NLB | 1\n", NLR_MF_FILE, 1,
         NLR_FORMAT},
        {"a | foreground | A | APPS/A.NLB | \n", NLR_MF_ABI, 1, NLR_FORMAT},
        {"a | foreground | A | APPS/A.NLB | two\n", NLR_MF_ABI, 1, NLR_FORMAT},
        {"a | foreground | A | APPS/A.NLB | 1 | z8\n", NLR_MF_SUPPORT, 1,
         NLR_FORMAT},
        {"a | foreground | A | APPS/A.NLB | 1 | /3.11\n", NLR_MF_SUPPORT, 1,
         NLR_FORMAT},
        {"a | foreground | A | APPS/A.NLB | 1 | z8/3.11,\n", NLR_MF_SUPPORT, 1,
         NLR_FORMAT},
        {"a | foreground | A | APPS/A.NLB | 1 | z8/3/11\n", NLR_MF_SUPPORT, 1,
         NLR_FORMAT},
        /* A repeated id would make two rows indistinguishable. */
        {"a | foreground | A | APPS/A.NLB | 1\n"
         "A | foreground | B | APPS/B.NLB | 1\n",
         NLR_MF_DUPLICATE, 2, NLR_FORMAT},
    };
    for (unsigned n = 0; n < sizeof cases / sizeof cases[0]; n++) {
        int result = parse_text(cases[n].text);
        if (result != cases[n].result || manifest.error != cases[n].reason ||
            manifest.error_line != cases[n].line) {
            printf("FAIL manifest case %u: result %d error %u line %u\n", n,
                   result, manifest.error, manifest.error_line);
            failures++;
        }
        /* A rejected file yields no partial list. */
        CHECK(manifest.count == 0);
    }

    /* At most 64 entries (PLAN 6.2); the 65th is reported with its line. */
    static char many[65 * 48];
    uint32_t used = 0;
    for (unsigned n = 0; n < 65; n++)
        used += (uint32_t)snprintf(many + used, sizeof many - used,
                                   "id%02u | foreground | N%02u | APPS/A.NLB | 1\n",
                                   n, n);
    CHECK(nlr_manifest_parse(&manifest, (const uint8_t *)many, used) ==
          NLR_BOUNDS);
    CHECK(manifest.error == NLR_MF_COUNT);
    CHECK(manifest.error_line == 65);
}

/* Lines added from programs that describe themselves (from `listed` on)
 * may repeat an id listed before: kept, gated DUPLICATE, never usable; the
 * same repeat inside MANIFEST still rejects the whole file. */
static void manifest_keeps_discovered_duplicates(void)
{
    static const char text[] =
        "a | foreground | A | APPS/A.NLB | 1\n"
        "b | foreground | B | APPS/B.NLB | 1\n"
        "A | foreground | Again | APPS/C.NLB | 1\n";
    uint32_t listed = (uint32_t)(strchr(strchr(text, '\n') + 1, '\n') + 1 - text);
    CHECK(nlr_manifest_parse_listed(&manifest, (const uint8_t *)text,
                                    (uint32_t)strlen(text), listed) == NLR_OK);
    CHECK(manifest.count == 3 && manifest.entries[2].gate == NLR_GATE_DUPLICATE);
    CHECK(nlr_manifest_gate(&manifest, "z8", "3.11") == NLR_OK);
    CHECK(manifest.entries[0].gate == NLR_GATE_OK && manifest.entries[1].gate == NLR_GATE_OK);
    CHECK(manifest.entries[2].gate == NLR_GATE_DUPLICATE && manifest.usable == 2);
    CHECK(nlr_manifest_parse_listed(&manifest, (const uint8_t *)text,
                                    (uint32_t)strlen(text), (uint32_t)strlen(text)) == NLR_FORMAT);
    CHECK(manifest.error == NLR_MF_DUPLICATE && manifest.error_line == 3);
}

static void manifest_gate_reports_each_entry(void)
{
    static const char text[] =
        "old | foreground | Old | APPS/OLD.NLB | 99\n"
        "any | foreground | Any | APPS/ANY.NLB | 2\n"
        "mine | foreground | Mine | APPS/MINE.NLB | 2 | Z8/3.11\n"
        "other | foreground | Other | APPS/OTHER.NLB | 2 | z6iii/2.00\n";
    CHECK(parse_text(text) == NLR_OK);
    CHECK(nlr_manifest_gate(&manifest, "z8", "3.11") == NLR_OK);
    CHECK(manifest.entries[0].gate == NLR_GATE_ABI);
    CHECK(manifest.entries[1].gate == NLR_GATE_OK);  /* no declaration */
    CHECK(manifest.entries[2].gate == NLR_GATE_OK);  /* case-insensitive */
    CHECK(manifest.entries[3].gate == NLR_GATE_MODEL);
    CHECK(manifest.usable == 2);
    /* Without an identity a declaration cannot be confirmed, so it is
     * reported as unknown rather than assumed to match. */
    CHECK(nlr_manifest_gate(&manifest, 0, 0) == NLR_OK);
    CHECK(manifest.entries[1].gate == NLR_GATE_OK);
    CHECK(manifest.entries[2].gate == NLR_GATE_UNKNOWN);
    CHECK(manifest.usable == 1);
}

static void manifest_read_paths(void)
{
    static _Alignas(NLR_CACHE_LINE) uint8_t buffer[NLR_MANIFEST_BYTES];
    static const char text[] =
        "hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n";
    struct nlr_trace trace;
    memset(&trace, 0, sizeof trace);
    card_manifest_len = (uint32_t)strlen(text);
    memcpy(card_manifest, text, card_manifest_len);
    card_manifest_present = 1;
    manifest_opens = 0;

    /* SAFE_MODE is the first card operation: the directory is never opened. */
    safe_mode_present = 1;
    CHECK(nlr_manifest_read(&manifest, &nlr_services, buffer, sizeof buffer,
                            &trace) == NLR_DISABLED);
    CHECK(manifest_opens == 0);
    CHECK(trace.count == 1);
    CHECK((trace.entries[0].seq_tag & 0xff) == 'M' && trace.entries[0].value == 0);
    close_fail = 1;
    uint32_t reads_before_guard = cache_before_calls;
    CHECK(nlr_manifest_read(&manifest, &nlr_services, buffer, sizeof buffer,
                            &trace) == NLR_IO);
    CHECK(manifest_opens == 0 && cache_before_calls == reads_before_guard);
    CHECK(manifest.count == 0 && manifest.bytes == 0 && manifest.buffer == 0);
    uint32_t last = (uint32_t)(trace.count - 1) & (NLR_TRACE_SLOTS - 1);
    CHECK((trace.entries[last].seq_tag & 0xff) == 'C' &&
          trace.entries[last].value == -1);
    close_fail = 0;
    safe_mode_present = 0;

    /* A missing card and a missing file are indistinguishable here, so the
     * reader reports "cannot read" without naming a cause. */
    card_manifest_present = 0;
    CHECK(nlr_manifest_read(&manifest, &nlr_services, buffer, sizeof buffer,
                            &trace) == NLR_IO);
    CHECK(manifest.count == 0);
    card_manifest_present = 1;

    /* Larger than the buffer: refused, never truncated. */
    card_manifest_len = NLR_CACHE_LINE + 1;
    CHECK(nlr_manifest_read(&manifest, &nlr_services, buffer, NLR_CACHE_LINE,
                            &trace) == NLR_BOUNDS);
    CHECK(manifest.error == NLR_MF_SIZE);
    CHECK(manifest.bytes == 0);
    card_manifest_len = (uint32_t)strlen(text);

    /* A failed read leaves no list behind. */
    fail_next_read = 1;
    CHECK(nlr_manifest_read(&manifest, &nlr_services, buffer, sizeof buffer,
                            &trace) == NLR_IO);
    fail_next_read = 0;
    CHECK(manifest.count == 0);

    /* The full path: read in chunks, parsed, then gated. */
    read_max = 16; /* force several short reads */
    uint32_t before = cache_before_calls, after = cache_after_calls;
    CHECK(nlr_manifest_read(&manifest, &nlr_services, buffer, sizeof buffer,
                            &trace) == NLR_OK);
    read_max = 0x1000;
    CHECK(manifest.bytes == card_manifest_len);
    CHECK(manifest.count == 1);
    CHECK(entry_is(&manifest, 0, "hello", "Hello", "APPS/HELLO.NLB",
                   NLR_KIND_FOREGROUND, 2));
    /* One invalidation for the one chunk, however short the reads: a second
     * one would discard the line holding the bytes already received. */
    CHECK(cache_before_calls == before + 1 && cache_after_calls == after + 1);
    CHECK(nlr_manifest_gate(&manifest, "z8", "3.11") == NLR_OK);
    CHECK(manifest.usable == 1);

    /* A rejected directory on the card reports its line, and the entry list
     * stays empty. */
    static const char bad[] =
        "hello | foreground | Hello | APPS/HELLO.NLB | 2\n"
        "broken | widget | Broken | APPS/B.NLB | 2\n";
    card_manifest_len = (uint32_t)strlen(bad);
    memcpy(card_manifest, bad, card_manifest_len);
    CHECK(nlr_manifest_read(&manifest, &nlr_services, buffer, sizeof buffer,
                            &trace) == NLR_FORMAT);
    CHECK(manifest.error == NLR_MF_KIND);
    CHECK(manifest.error_line == 2);
    CHECK(manifest.count == 0);
    card_manifest_present = 0;
}

static void set_manifest(const char *text)
{
    card_manifest_len = (uint32_t)strlen(text);
    memcpy(card_manifest, text, card_manifest_len);
    card_manifest_present = 1;
}

#if defined(NLR_TEST_NATIVE_PAGE_REFRESH) && defined(NLR_STAGE_LOAD_ONLY)
static void native_refresh_keeps_the_menu_context_and_reflows_rows(void)
{
    reset_mocks();
    _Alignas(8) uint8_t window[0x60] = {0};
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2\n"
                 "other | foreground | Other | APPS/OTHER.NLB | 2\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    uint32_t directory_reads = manifest_opens;
    *(uint16_t *)(window + 0x32) = 1;
    /* Unrelated native window state belongs to the original menu engine. */
    window[0x40] = 0xa7;
    native_refresh_enabled = 1;
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    nlr_page_row_action(&nav);
    CHECK(nav.window == window && nav.code == 0x286 && nav.next == OWN_REENTER);
    CHECK(refresh_calls == 1 && refresh_window == window);
    CHECK(refresh_old_rows == 2 && refresh_new_rows == 3);
    CHECK(r->show_check == 1);
    /* The original reentry reconstructs widgets/images after the native
     * refresh cleared the previous view. It must not rerun card checks. */
    nlr_page_enter(nav.window);
    CHECK(r->show_check == 0 && r->detail_view && r->checked == 1);
    CHECK(window[0x40] == 0xa7 && *(uint16_t *)(window + 0x32) == 0);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "Other") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Other: OK") == 0);
    CHECK(!hidden_rows[2] && hidden_rows[3]);
    CHECK(manifest_opens == directory_reads && program_opens == 1);
    CHECK(probe_call_count == 0 && !r->load.program.entry_started);

    /* A result-only refresh keeps the same rows and selection, and reads
     * neither the directory nor the already checked program again. */
    *(uint16_t *)(window + 0x32) = 1;
    nlr_page_row_action(&nav);
    CHECK(refresh_calls == 2 && refresh_old_rows == 3 && refresh_new_rows == 3);
    CHECK(r->show_check == 1);
    nlr_page_enter(nav.window);
    CHECK(r->show_check == 0 && r->detail_view && r->checked == 1);
    CHECK(*(uint16_t *)(window + 0x32) == 1);
    CHECK(manifest_opens == directory_reads && program_opens == 1);

    nav.code = 0x285;
    nlr_page_back_action(&nav);
    CHECK(refresh_calls == 3 && refresh_old_rows == 3 && refresh_new_rows == 2);
    CHECK(nav.next == OWN_REENTER && nav.window == window);
    CHECK(r->show_check == 1);
    nlr_page_enter(nav.window);
    CHECK(r->show_check == 0 && !r->detail_view);
    CHECK(*(uint16_t *)(window + 0x32) == 1 && window[0x40] == 0xa7);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "NLoader") == 0);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Hello") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Other") == 0 && hidden_rows[2]);
    CHECK(manifest_opens == directory_reads && program_opens == 1);

    /* A second program can immediately reopen a fresh detail; leaving the
     * list itself retains the original Back target and needs no refresh. */
    nav.next = 0x68d;
    nlr_page_back_action(&nav);
    CHECK(nav.next == 0x68d && refresh_calls == 3);
    *(uint16_t *)(window + 0x32) = 0;
    nav.code = 0x286;
    nlr_page_row_action(&nav);
    CHECK(refresh_calls == 4 && refresh_old_rows == 2 && refresh_new_rows == 3);
    CHECK(r->show_check == 1);
    nlr_page_enter(nav.window);
    CHECK(r->show_check == 0 && r->detail_view && r->checked == 0);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "Hello") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Hello: OK") == 0);
    CHECK(manifest_opens == directory_reads && program_opens == 2);
    CHECK(probe_call_count == 0 && !r->load.program.entry_started);
    nlr_page_row_action(0);
    nlr_page_back_action(0);
    CHECK(refresh_calls == 4);
    native_refresh_enabled = 0;
}
#endif

/* PLAN 4.3 in the caller's task: the directory is read, gated and kept, and
 * a check opens the selected entry's file after SAFE_MODE. Refusals that
 * need no card access leave the card untouched. */
static void runtime_reads_the_directory_and_checks_a_program(void)
{
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n"
                 "future | foreground | Future | APPS\\F.NLB | 10 | z8/3.11\n");
    struct nlr_runtime *r = nlr_runtime_attach(&nlr_services, ARENA_CAP, 0);
    CHECK(r != 0);
    if (!r)
        return;
    /* Nothing is read before the page asks. */
    CHECK(r->directory_result == NLR_NOT_READY);
    CHECK(manifest_opens == 0 && program_opens == 0);
    CHECK(nlr_runtime_check(r, 0) == NLR_NOT_READY);
    CHECK(program_opens == 0);

    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    CHECK(r->directory.count == 2 && r->directory.usable == 1);
    CHECK(r->directory.entries[1].gate == NLR_GATE_ABI);
    CHECK(r->checked == NLR_NO_CHECK);
    char tag = 0;
    int32_t value = 0;
    CHECK(trace_last(&r->load, &tag, &value) && tag == 'G' && value == 1);

    /* The file column is relative to the program root and may use either
     * separator; the card path uses the firmware's. */
    CHECK(nlr_runtime_check(r, 0) == NLR_OK);
    CHECK(strcmp(program_path, NLR_PROGRAM_ROOT "APPS\\HELLO.NLB") == 0);
    CHECK(r->checked == 0 && r->check_result == NLR_OK);
    CHECK(r->load.image_bytes == 16 && r->load.state == 0);
    CHECK(trace_last(&r->load, &tag, &value) && tag == 'E' && value == NLR_OK);

    /* The gate's refusal and an index past the end touch nothing. */
    uint32_t opens = program_opens;
    CHECK(nlr_runtime_check(r, 1) == NLR_REFUSED);
    CHECK(r->checked == 1 && r->check_result == NLR_REFUSED);
    CHECK(nlr_runtime_check(r, 2) == NLR_BOUNDS);
    CHECK(program_opens == opens);

    /* A damaged file is reported with its cause. */
    spec.crc_xor = 1;
    build_card(&spec);
    CHECK(nlr_runtime_check(r, 0) == NLR_CHECKSUM);
    spec.crc_xor = 0;
    build_card(&spec);

    /* SAFE_MODE set after the directory was read still stops the check
     * before the program file is opened. */
    safe_mode_present = 1;
    opens = program_opens;
    CHECK(nlr_runtime_check(r, 0) == NLR_DISABLED);
    CHECK(program_opens == opens);
    safe_mode_present = 0;

    /* The worker shares the loading state: no check while it is busy. */
    r->load.path = r->path;
    CHECK(nlr_load_enqueue_once(&r->load) == NLR_OK);
    CHECK(nlr_runtime_check(r, 0) == NLR_BUSY);
    nlr_load_event(r, 1);
    CHECK(nlr_runtime_check(r, 0) == NLR_OK);

    /* A new read replaces the list, so the old check no longer applies. */
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    CHECK(r->checked == NLR_NO_CHECK && r->check_result == NLR_NOT_READY);

    /* SAFE_MODE is the first card operation of the directory read, and a
     * directory that was not read cannot be checked against. */
    safe_mode_present = 1;
    manifest_opens = 0;
    CHECK(nlr_runtime_read_directory(r) == NLR_DISABLED);
    CHECK(manifest_opens == 0);
    CHECK(nlr_runtime_check(r, 0) == NLR_NOT_READY);
    safe_mode_present = 0;
    card_manifest_present = 0;
    CHECK(nlr_runtime_read_directory(r) == NLR_IO);
    CHECK(nlr_runtime_check(r, 0) == NLR_NOT_READY);
}

/* NLoader's page entry titles the page in every stage the way stock pages
 * title themselves from a text slot: look up, store the entry text with the
 * title format, bind, show. The page stage writes a status line into its
 * row; from load-only on the entry reads the card and the row names the
 * first program or why there is none. */
static void page_enter_titles_the_page_and_fills_the_row(void)
{
    static _Alignas(8) uint8_t window[0x60];

    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    CHECK(nlr_page_enter(window) == window);
    CHECK(found_ids[0] == OWN_TITLE_WIDGET);
    CHECK(widget_find_container == window + PAGE_CONTAINER);
    CHECK(bound_slots[0] == OWN_TITLE_SLOT);
    CHECK(widget_show_calls == 1 && shown_widget == &page_widget && shown_visible == 1);
    CHECK(hide_calls >= 63);
#if defined(NLR_STAGE_LOAD_ONLY) || defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    /* The row write comes last, so the mocks hold its store. */
    CHECK(widget_find_calls == 2 && text_bind_calls == 2 && text_store_calls == 2);
    CHECK(found_ids[1] == OWN_ROW_WIDGET);
    CHECK(widget_find_id == OWN_ROW_WIDGET && hide_calls == 64);
    CHECK(stored_slot == OWN_ROW_SLOT && stored_format == OWN_ROW_STYLE);
    CHECK(strcmp(stored_text, "Hello") == 0);
    CHECK(bound_slots[1] == OWN_ROW_SLOT);
    CHECK(manifest_opens == 1 && program_opens == 0); /* no check on entry */
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0 && r->directory_result == NLR_OK);
    char tag = 0;
    int32_t value = 0;
    /* One record for the drawing: one row written, its widget bound. */
    CHECK(r && trace_last(&r->load, &tag, &value) && tag == 'B' && value == (1 << 16 | 1));

    /* Every entry reads the card again without constructing again, and
     * each outcome is named. */
    uint32_t allocs = alloc_calls;
    safe_mode_present = 1;
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "DISABLED (SAFE_MODE)") == 0);
    safe_mode_present = 0;
    card_manifest_present = 0;
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "Cannot read MANIFEST") == 0);
    set_manifest("# programs\n\nhello | widget | Hello | APPS/H.NLB | 2\n");
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "MANIFEST line 3: bad kind") == 0);
    set_manifest("# no programs yet\n");
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "MANIFEST: no programs") == 0);
    set_manifest("future | foreground | Future | APPS/F.NLB | 10\n");
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "Future: blocked") == 0);
    set_manifest("other | foreground | Other | APPS/O.NLB | 2 | z6iii/2.00\n");
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "Other: blocked") == 0);
    CHECK(alloc_calls == allocs);

    /* A failed row lookup still writes the slot; the trace says the widget
     * was not re-bound. */
    widget_find_fails = 1;
    text_bind_calls = 0;
    nlr_page_enter(window);
    CHECK(text_bind_calls == 0);
    CHECK(strcmp(stored_text, "Other: blocked") == 0);
    CHECK(r && trace_last(&r->load, &tag, &value) && tag == 'B' && value == 1 << 16);
    widget_find_fails = 0;

    /* A full list adds one drawing record after the card steps, so the ring
     * still holds the directory read: A attach, F file, P parse, G gate, B. */
    char full[8192];
    uint32_t used = 0;
    for (uint32_t i = 0; i < 64; i++)
        used += (uint32_t)snprintf(full + used, sizeof full - used,
            "p%u | foreground | Program %u | APPS/P%u.NLB | 2\n", i, i, i);
    set_manifest(full);
    uint64_t before = r ? r->load.trace.count : 0;
    nlr_page_enter(window);
    CHECK(r && r->load.trace.count == before + 5);
    const char steps[] = "AFPGB";
    for (uint32_t i = 0; r && i < 5; i++) {
        const union nlr_trace_entry *e =
            &r->load.trace.entries[(before + i) & (NLR_TRACE_SLOTS - 1)];
        CHECK((char)(e->seq_tag & 0xff) == steps[i]);
    }
    CHECK(r && trace_last(&r->load, &tag, &value) && value == (64 << 16 | 64));

    /* Without a runtime there is nothing to read with; the row says so. */
    reset_mocks();
    alloc_fail_countdown = 0;
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "NLoader unavailable") == 0);
    CHECK(manifest_opens == 0);
#elif defined(NLR_STAGE_PAGE)
    /* The row's label with the found/not-found marker; no card access. */
    CHECK(widget_find_calls == 2 && text_bind_calls == 2 && text_store_calls == 2);
    CHECK(found_ids[1] == OWN_ROW_WIDGET);
    CHECK(stored_slot == OWN_ROW_SLOT && stored_format == OWN_ROW_STYLE);
    CHECK(strcmp(stored_text, OWN_ROW_TEXT " W") == 0);
    CHECK(widget_find_id == OWN_ROW_WIDGET && bound_slots[1] == OWN_ROW_SLOT);
    CHECK(alloc_calls == 0 && manifest_opens == 0);

    /* Lookups that fail store no title and bind or show nothing; the row
     * slot still says what happened. */
    reset_mocks();
    widget_find_fails = 1;
    CHECK(nlr_page_enter(window) == window);
    CHECK(text_bind_calls == 0 && widget_show_calls == 0 && text_store_calls == 1);
    CHECK(stored_slot == OWN_ROW_SLOT);
    CHECK(strcmp(stored_text, OWN_ROW_TEXT " X") == 0);
#else
    /* hook-only stage: the title only; the row keeps its prefilled label. */
    CHECK(widget_find_calls == 1 && text_bind_calls == 1 && text_store_calls == 1);
    CHECK(widget_find_id == OWN_TITLE_WIDGET);
    CHECK(stored_slot == OWN_TITLE_SLOT && stored_format == OWN_TITLE_FORMAT);
    CHECK(strcmp(stored_text, OWN_TITLE_TEXT) == 0);
    CHECK(alloc_calls == 0 && manifest_opens == 0);
#endif

    /* No window, no container: nothing is looked up or written. */
    reset_mocks();
    CHECK(nlr_page_enter(0) == 0);
    CHECK(widget_find_calls == 0 && text_bind_calls == 0 && text_store_calls == 0);
    CHECK(widget_show_calls == 0 && alloc_calls == 0);
}

/* The pending text slot's atomic protocol, exercised directly: a writer
 * stepping inside the reader's scan must never leave a mixed text adopted,
 * a writer that outpaces every attempt makes the read fall back to "no
 * text", and every adopted text is complete. The seam fires the simulated
 * writer after each payload load, so the interleavings are deterministic. */
static void text_slot_protocol_survives_interleaved_writes(void)
{
    static struct nlr_text_slot slot;
    char text[NLR_SLOT_TEXT_MAX + 2];

    text_seam_texts_init();
    text_seam_slot = &slot;
    text_seam_active = 0;

    /* A quiet slot: the seeded text reads back as published. */
    memset(&slot, 0, sizeof slot);
    text_store_payload(&slot, text_a);
    __atomic_store_n(&slot.generation, 2u, __ATOMIC_RELEASE);
    CHECK(nlr_text_read(&slot, text) == NLR_SLOT_TEXT_MAX);
    CHECK(memcmp(text, text_a, NLR_SLOT_TEXT_MAX) == 0);
    CHECK(text[NLR_SLOT_TEXT_MAX] == 0);

    /* One publish lands after the first payload load: the copy in flight
     * mixes old and new bytes, the generation check discards it, and the
     * retry adopts the complete new text. */
    text_store_payload(&slot, text_a);
    __atomic_store_n(&slot.generation, 4u, __ATOMIC_RELEASE);
    text_seam_active = 1;
    text_seam_publishes = 1; /* publishes B once, on the first payload load */
    text_seam_turn = 1;
    text_seam_fires = 0;
    CHECK(nlr_text_read(&slot, text) == NLR_SLOT_TEXT_MAX);
    CHECK(text_seam_fires == 1); /* the publish really interleaved */
    CHECK(memcmp(text, text_b, NLR_SLOT_TEXT_MAX) == 0);
    CHECK(text[NLR_SLOT_TEXT_MAX] == 0);

    /* An odd generation means a writer is mid-publish: no complete text
     * exists, so the read falls back immediately. */
    text_store_payload(&slot, text_a);
    __atomic_store_n(&slot.generation, 9u, __ATOMIC_RELEASE);
    text_seam_active = 0;
    CHECK(nlr_text_read(&slot, text) == 0);
    CHECK(text[0] == 0);

    /* A writer that keeps publishing through every attempt exhausts the
     * retries: the read reports no text rather than a torn one, and once
     * the writer stops the last published text reads complete. */
    text_store_payload(&slot, text_a);
    __atomic_store_n(&slot.generation, 8u, __ATOMIC_RELEASE);
    text_seam_active = 1;
    text_seam_publishes = 64;
    text_seam_turn = 0;
    text_seam_fires = 0;
    CHECK(nlr_text_read(&slot, text) == 0);
    CHECK(text[0] == 0);
    text_seam_active = 0;
    text_seam_publishes = 0;
    CHECK(nlr_text_read(&slot, text) == NLR_SLOT_TEXT_MAX);
    uint32_t last = text[0];
    CHECK((last == 'A' || last == 'B') &&
          memcmp(text, last == 'A' ? text_a : text_b,
                 NLR_SLOT_TEXT_MAX) == 0);

    /* A writer alternating A and B at every payload load, for read budgets
     * from quiet to outpacing: whatever the read adopts is a complete A
     * string or a complete B string, never a mixture; outpaced reads fall
     * back to no text. */
    text_store_payload(&slot, text_a);
    __atomic_store_n(&slot.generation, 12u, __ATOMIC_RELEASE);
    for (uint32_t budget = 0; budget <= 35u; budget += 7u) {
        text_seam_active = budget != 0;
        text_seam_publishes = budget;
        text_seam_turn = 0;
        uint32_t read = nlr_text_read(&slot, text);
        if (read == 0) {
            CHECK(text[0] == 0);
            continue;
        }
        CHECK(read == NLR_SLOT_TEXT_MAX);
        CHECK(memcmp(text, text_a, NLR_SLOT_TEXT_MAX) == 0 ||
              memcmp(text, text_b, NLR_SLOT_TEXT_MAX) == 0);
    }
    text_seam_active = 0;
    text_seam_publishes = 0;
    text_seam_slot = 0;
}

#if defined(NLR_STAGE_LOAD_ONLY) || defined(NLR_STAGE_PREPARE_ONLY) || \
    defined(NLR_STAGE_EXEC)
/* The result row drains the pending program text while the program runs
 * (M2-T4, PLAN 5.6): the program's text wins over the standing status, an
 * empty slot keeps the status, and once the run ends — normally or as a
 * refusal — the standard result text wins, so a leftover text can never
 * mask an error. */
static void page_drains_program_text_into_the_result_row(void)
{
    static _Alignas(8) uint8_t window[0x60];
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    CHECK(nlr_page_enter(window) == window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    /* The result row (describe_check) renders in the detail view only. */
    r->detail_view = 1;
    r->checked = 0;

    /* The result row (detail row 1) is what the checks read back; the
     * mock keeps every row's slot text separately. */
#define RESULT_ROW slot_text[own_row_slots[1]]

    /* A queued run that has not drawn yet has nothing to say: no status
     * row, the page is the operation and back. */
    r->program_pending = 1;
    __atomic_store_n(&r->load.state, 1, __ATOMIC_RELEASE);
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "Back to list") == 0 && hidden_rows[2]);

    /* The program draws: the next redraw shows its text instead. */
    CHECK(nlr_api.ui_draw_text(0, 0, "Hi from the program") == 0);
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "Hi from the program") == 0);

    /* A long draw is truncated to the row capacity, and a later draw
     * replaces it (latest-wins). */
    char long_text[NLR_SLOT_TEXT_MAX + 9];
    for (uint32_t n = 0; n < sizeof long_text - 1; n++)
        long_text[n] = (char)('a' + n % 26);
    long_text[sizeof long_text - 1] = 0;
    CHECK(nlr_api.ui_draw_text(0, 0, long_text) == 0);
    nlr_page_enter(window);
    CHECK(strlen(RESULT_ROW) == NLR_SLOT_TEXT_MAX);
    CHECK(strncmp(RESULT_ROW, long_text, NLR_SLOT_TEXT_MAX) == 0);
    CHECK(nlr_api.ui_draw_text(0, 0, "newer text") == 0);
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "newer text") == 0);

    /* A refused run never shows program text: the state reads 0, and the
     * standard result — here a budget refusal — wins over whatever is
     * still pending in the slot. show_check re-enters the detail view the
     * way the OK action does; an entry without it would go back to the
     * list instead of the result row. */
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    r->load.last_result = NLR_EXEC_BUDGET;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "Program memory budget exhausted") == 0);

    /* The heap could not give the blocks whole (phase A): said so, with
     * what the program asks for -- its one region here. Any other phase
     * keeps naming the step. */
    r->load.last_result = NLR_NOT_READY;
    r->load.program.phase = 'A';
    r->load.data_bytes = r->load.bss_bytes = 0;
    r->show_check = 1;
    nlr_page_enter(window);
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    CHECK(strcmp(RESULT_ROW, "Not enough camera memory (needs 4 KiB)") == 0);
    r->load.bss_bytes = 16;
    r->load.last_result = NLR_BOUNDS;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "Not enough camera memory (needs 8 KiB)") == 0);
#else
    /* No executor in this rung: the step is named as before. */
    CHECK(strcmp(RESULT_ROW, "Program refused at stage A") == 0);
#endif
    r->load.bss_bytes = 0;
    r->load.last_result = NLR_NOT_READY;
    r->load.program.phase = 'W';
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "Program refused at stage W") == 0);
    r->load.program.phase = 0;

    /* A finished run restores the standard result text as well. */
    r->load.last_result = NLR_OK;
    r->load.program.returned = 1;
    r->show_check = 1;
    nlr_page_enter(window);
#ifdef NLR_STAGE_PREPARE_ONLY
    CHECK(strcmp(RESULT_ROW, "Application preparation passed") == 0);
#else
    /* A clean return says nothing new, but the status row the program's
     * text opened stays for the visit (the page is not entered again
     * shorter) and says what happened last; a non-zero exit and a stop say
     * more. */
    CHECK(strcmp(RESULT_ROW, "Application returned") == 0 && r->status_kept);
    r->load.program.exit_code = 3;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "Application exited (code 3)") == 0 && !hidden_rows[2]);
    r->load.program.exit_code = 0;
    r->load.program.exit_requested = 1;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(RESULT_ROW, "Application stopped") == 0);
    r->load.program.exit_requested = 0;
#endif

    /* Genuine release notifications are consumed by the GUI dispatcher,
     * including an early release while an SDK service is still draining. */
    struct nlr_menu_nav nav = {window, 0, 0x68d};
    CHECK(nlr_page_exit_guard() == 0);
    nlr_page_exit_action(&nav);
    CHECK(nav.next == 0x68d);
    __atomic_store_n(&r->load.state, 2u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->load.program.api_active, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->exit_notify, 1u, __ATOMIC_RELEASE);
    CHECK(nlr_page_exit_guard() == 0); /* Generic no-key is not MENU release. */
    nlr_page_exit_action(&nav);
    CHECK(r->exit_notify == 1u);
    __atomic_store_n(&r->exit_release_seen, 1u, __ATOMIC_RELEASE);
    CHECK(nlr_page_exit_guard() == 1);
    nlr_page_exit_action(&nav);
    CHECK(nav.next == OWN_ACTION_NEXT && !r->detail_view);
    CHECK(!r->exit_notify && r->load.state == 2u &&
          r->load.program.api_active == 1u);
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Hello") == 0);
    r->detail_view = 1;
    __atomic_store_n(&r->exit_uncertain, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->exit_notify, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->exit_release_seen, 1u, __ATOMIC_RELEASE);
    nlr_page_exit_action(&nav);
    CHECK(r->detail_view && !r->exit_notify);
    nlr_page_enter(window);
    CHECK(strncmp(RESULT_ROW,
                  "Application stop uncertain; effective reboot required",
                  NLR_SLOT_TEXT_MAX) == 0);
    __atomic_store_n(&r->exit_uncertain, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->load.program.api_active, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->load.state, 0u, __ATOMIC_RELEASE);
#undef RESULT_ROW
}
#endif

#if defined(NLR_STAGE_LOAD_ONLY)
/* An entry from outside the page: the Setup row's open records run the
 * open action (which goes back to the list and sizes the page), then the
 * dispatcher builds the page and calls its entry. */
static void external_entry(uint8_t *window)
{
    struct nlr_menu_nav open = {window, 0x2b3, 0x65a};
    nlr_page_open_action(&open);
    nlr_page_enter(window);
}

static const char *ok_then_enter(struct nlr_menu_nav *nav)
{
    nlr_page_row_action(nav);
    nlr_page_enter(nav->window);
    return slot_text[own_row_slots[1]];
}
#endif

#if defined(NLR_STAGE_LOAD_ONLY)
/* A row action means the row on screen: details drawn as open and back,
 * then the state grows a status line before the user presses OK on the
 * second row. That is still back, not the status row now at its index. */
static void row_action_uses_the_rows_drawn(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    external_entry(window);
    CHECK(strcmp(ok_then_enter(&nav), "Back to list") == 0);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r && r->detail_view && r->detail_shown == 2);
    r->check_result = NLR_IO;      /* a status the screen does not show yet */
    *(uint16_t *)(window + 0x32) = 1;
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(r && !r->detail_view && nav.next == OWN_ACTION_NEXT);
}
#endif

#if defined(NLR_STAGE_EXEC)
static void set_settings(const char *text)
{
    card_settings_len = (uint32_t)strlen(text);
    memcpy(card_settings, text, card_settings_len);
    card_settings_present = 1;
}

/* Settings remain readable, but the incomplete write/close path must not
 * claim a durable save. A visible refusal and unchanged card/cache apply
 * even when the raw mock writer would otherwise acknowledge the request. */
static void program_settings_on_the_page(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("fm | foreground | Files | APPS/FM.NLB | 2 | z8/3.11\n");
    set_settings("card|Start card|Choose,A:,B:|0\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    *(uint16_t *)(window + 0x32) = 0;
    nlr_page_row_action(&nav);
    CHECK(mock_page_count == 3); /* sized with its Settings row */
    nlr_page_enter(window);
    CHECK(r->detail_view && r->settings.count == 1);
    CHECK(strcmp(r->settings.path, NLR_PROGRAM_ROOT "APPS\\FM.SET") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Settings") == 0);
    CHECK(strcmp(slot_text[own_row_slots[2]], "Back to list") == 0);

    *(uint16_t *)(window + 0x32) = 1;
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    nlr_page_enter(window);
    CHECK(r->settings_view);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Start card: Choose") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Read-only: saving unavailable") == 0);
    CHECK(strcmp(slot_text[own_row_slots[2]], "Back") == 0);

    uint32_t flags_before = last_open_flags;
    uint8_t card_before[sizeof card_settings];
    memcpy(card_before, card_settings, sizeof card_before);
    *(uint16_t *)(window + 0x32) = 0;
    nlr_page_row_action(&nav);
    nlr_page_enter(window);
    CHECK(r->settings.save_result == NLR_NOT_READY);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Start card: Choose") == 0);
    CHECK(!settings_writes && last_open_flags == flags_before);
    CHECK(!memcmp(card_before, card_settings, sizeof card_before));
    CHECK(nlr_settings_find(r, "card") == 0 && nlr_settings_find(r, "car") == -1);
    write_fail = 1;
    nlr_page_row_action(&nav);
    nlr_page_enter(window);
    CHECK(!settings_writes && nlr_settings_find(r, "card") == 0);
    CHECK(!memcmp(card_before, card_settings, sizeof card_before));
    write_fail = 0;
    CHECK(nlr_settings_set(r, 0, 1) == NLR_NOT_READY);
    CHECK(nlr_settings_set(r, 0, 9) == NLR_BOUNDS);
    CHECK(!settings_writes && nlr_settings_find(r, "card") == 0);

    nav.next = 0x68d;
    nlr_page_back_action(&nav);
    nlr_page_enter(window);
    CHECK(!r->settings_view && r->detail_view);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Settings") == 0);

    /* Malformed files: a value past the choices, no final newline. */
    set_settings("card|Start card|A:,B:|7\n");
    r->settings.entry = 0;
    nlr_settings_load(r);
    CHECK(r->settings.count == 0);
    set_settings("card|Start card|A:,B:|1");
    r->settings.entry = 0;
    nlr_settings_load(r);
    CHECK(r->settings.count == 0);
    card_settings_present = 0;
    r->settings.entry = 0;
    nlr_settings_load(r);
    CHECK(r->settings.count == 0);
}
#endif

#if defined(NLR_STAGE_EXEC)
/* A program's native list (ui_list) on the page: its title and rows, the
 * cursor on its row, OK and back handed to the program, a shorter next
 * list drawn on the longer page with empty rows, and the details back once
 * the program is over. No program answers here (no sleep service), so
 * every hand-over leaves the page as it is. */
static void program_list_on_the_page(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    r->detail_view = 1;
    r->checked = 0;
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    snprintf(r->list.title, sizeof r->list.title, "A:\\");
    snprintf(r->list.rows[0], sizeof r->list.rows[0], "DCIM");
    snprintf(r->list.rows[1], sizeof r->list.rows[1], "NIKON");
    snprintf(r->list.rows[2], sizeof r->list.rows[2], "NLOADER");
    r->list.count = 3;
    r->list.selected = 1;
    r->list.seq = 5;
    r->list_view = 1;
    r->show_check = 1;
    mock_page_count = 3;
    r->page_max = 3;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "A:\\") == 0);
    CHECK(strcmp(slot_text[own_row_slots[0]], "DCIM") == 0);
    CHECK(strcmp(slot_text[own_row_slots[2]], "NLOADER") == 0 && hidden_rows[3]);
    CHECK(r->list.shown == 5 && *(uint16_t *)(window + 0x32) == 1);

    /* OK on a row hands it over; the program is still working. */
    *(uint16_t *)(window + 0x32) = 2;
    uint32_t answered = r->list.choice_seq;
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(r->list.choice == 2 && r->list.choice_seq == answered + 1);
    CHECK(nav.next == OWN_STAY && r->list_view);

    /* Its next list is shorter: re-entered, the page stays three rows
     * long; rebuilt in place on a cleared layer, it is one row long. */
    snprintf(r->list.rows[0], sizeof r->list.rows[0], "100NZ6_3");
    r->list.count = 1;
    r->list.selected = 0;
    r->list.seq = 6;
    nav.next = 0x68d;
    *(uint16_t *)window = 2;
    *(uint16_t *)(window + NLR_MENU_WINDOW_ID) = 0x5c9;
    nlr_page_row_action(&nav); /* not drawn yet: only redraws */
    CHECK(r->list.choice_seq == answered + 1 && nav.next == OWN_ACTION_NEXT);
#ifdef NLR_TEST_PAGE_REBUILD
    CHECK(mock_page_count == 1 && r->page_max == 1);
    CHECK(rebuild_calls == 1 && present_calls == 1);
    CHECK(rebuild_type == 2 && rebuild_id == 0x5c9);
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "100NZ6_3") == 0);
    CHECK(!hidden_rows[0] && hidden_rows[1] && hidden_rows[2]);
#else
    CHECK(mock_page_count == 3);
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "100NZ6_3") == 0);
    CHECK(slot_text[own_row_slots[2]][0] == 0 && !hidden_rows[2] && hidden_rows[3]);
#endif

    /* An empty row only redraws; back goes to the program. */
    *(uint16_t *)(window + 0x32) = 2;
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(r->list.choice_seq == answered + 1 && nav.next == OWN_ACTION_NEXT);
    nav.next = 0x68d;
    nlr_page_back_action(&nav);
    CHECK(r->list.choice == NLR_LIST_BACK && r->list.choice_seq == answered + 2);

    /* The program is over: the next action shows the details again. */
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(!r->list_view && nav.next == OWN_ACTION_NEXT);
}

/* A program that publishes its first list after the page stopped
 * following its start (Files reads its directory first): the page shows
 * it at the next row action instead of acting on the row under the
 * cursor, and the action after that is the program's. The menu's turn
 * takes it the same way when the page has a rebuild. */
static void late_program_list_is_taken(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    /* the program runs, the page left it: its list comes now */
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    r->list_view = 0;
    r->detail_view = 0;
    snprintf(r->list.title, sizeof r->list.title, "NLoader files");
    snprintf(r->list.rows[0], sizeof r->list.rows[0], "APPS");
    snprintf(r->list.rows[1], sizeof r->list.rows[1], "MANIFEST");
    r->list.count = 2;
    r->list.selected = 0;
    r->list.shown = 8;
    r->list.seq = 9;
    __atomic_store_n(&r->io.list_active, 1u, __ATOMIC_RELEASE);
    uint32_t answered = r->list.choice_seq;
    *(uint16_t *)(window + 0x32) = 0;
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(r->list_view && r->list.choice_seq == answered);
    mock_page_count = 2;
    r->page_max = 2;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "NLoader files") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "MANIFEST") == 0);
    CHECK(r->list.shown == 9);
    /* now OK is the program's choice */
    *(uint16_t *)(window + 0x32) = 1;
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(r->list.choice == 1 && r->list.choice_seq == answered + 1);
    /* no list waiting, or one already shown: nothing to take */
    CHECK(nlr_page_show_late_list(r, window) == NLR_NOT_READY);
    r->list_view = 0;
    r->list.seq = 10;
#ifdef NLR_TEST_PAGE_REBUILD
    uint32_t rebuilds = rebuild_calls;
    *(uint16_t *)window = 2;
    *(uint16_t *)(window + NLR_MENU_WINDOW_ID) = 0x5c9;
    CHECK(nlr_page_show_late_list(r, window) == NLR_OK);
    CHECK(r->list_view && rebuild_calls == rebuilds + 1);
#else
    CHECK(nlr_page_show_late_list(r, window) == NLR_NOT_READY && !r->list_view);
#endif
    __atomic_store_n(&r->io.list_active, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
}

static uint32_t record_word(const void *records, uint32_t row, uint32_t at)
{
    return *(const uint32_t *)((const uint8_t *)records + row * NLR_MENU_ITEM_BYTES + at);
}

static void *page_items_now(void)
{
    return *(void **)(mock_page_record + NLR_MENU_PAGE_ITEMS);
}

/* ABI 6 row kinds. A plain list leaves the module's records in the page
 * record; the first page of row kinds moves the page onto the runtime's
 * copy and gives it the skip flag. Before each build every row takes its
 * kind's words -- a switch the switch flags (no > mark) and its ON / OFF
 * picture, a row with a choice the text-value flags and its value slot in
 * the upper half, a text row no > mark, a greyed entry its own -- and
 * after the build the page stores the values, sets the switches and
 * disables the text and greyed rows. Rows beyond the 32 stay hidden, and
 * the next plain list puts every row's own words back. The module's
 * records are never written. */
static void program_rows_on_the_page(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    CHECK(r->io.list_rows == 1);
    uint8_t module_before[sizeof mock_module_records];
    memcpy(module_before, mock_module_records, sizeof module_before);

    r->detail_view = 1;
    r->checked = 0;
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    r->list_view = 1;
    r->list.rows_view = 0;
    r->list.count = 3;
    nlr_page_prepare_redraw(r);
    CHECK(page_items_now() == mock_module_records && !r->items.installed);
    CHECK(*(uint32_t *)mock_page_record == OWN_PAGE_FLAGS);

    static const uint8_t kinds[5] = {NLR_ROW_SWITCH, NLR_ROW_SWITCH, NLR_ROW_SELECT,
                                     NLR_ROW_TEXT, NLR_ROW_ENTRY};
    static const uint8_t flags[5] = {NLR_ROW_ON, 0, 0, 0, NLR_ROW_GREYED};
    static const char *const labels[5] = {"Log3G10 at start", "Other switch", "Curve",
                                          "Now: stock N-Log", "Greyed"};
    r->list.rows_view = 1;
    r->list.count = 5;
    for (uint32_t k = 0; k < 5; k++) {
        r->list.kinds[k] = kinds[k];
        r->list.row_flags[k] = flags[k];
        snprintf(r->list.rows[k], sizeof r->list.rows[k], "%s", labels[k]);
        r->list.values[k][0] = 0;
    }
    snprintf(r->list.values[2], sizeof r->list.values[2], "LOG3G10.CRV");
    mock_page_count = 40;                 /* a longer list was built before */
    r->page_max = 40;
    nlr_page_prepare_redraw(r);
    void *records = r->items.records;
    CHECK(r->items.installed && page_items_now() == records);
    CHECK(*(uint32_t *)mock_page_record == (OWN_PAGE_FLAGS | OWN_SKIP_FLAG));
    CHECK(record_word(records, 0, NLR_MENU_ITEM_FLAGS) ==
          ((OWN_ROW_FLAGS & ~NLR_MENU_ITEM_MARK) | OWN_SWITCH_FLAGS));
    CHECK(record_word(records, 0, NLR_MENU_ITEM_VALUE) == OWN_SWITCH_ON);
    CHECK(record_word(records, 1, NLR_MENU_ITEM_VALUE) == OWN_SWITCH_OFF);
    CHECK(record_word(records, 2, NLR_MENU_ITEM_FLAGS) == (OWN_ROW_FLAGS | OWN_SELECT_FLAGS));
    CHECK(record_word(records, 2, NLR_MENU_ITEM_VALUE) == own_row_slots[NLR_ROWS_MAX + 2]);
    CHECK(record_word(records, 2, NLR_MENU_ITEM_STYLE) == OWN_SELECT_STYLE);
    CHECK(record_word(records, 1, NLR_MENU_ITEM_STYLE) == OWN_ITEM_STYLES);
    CHECK(record_word(records, 3, NLR_MENU_ITEM_FLAGS) == (OWN_ROW_FLAGS & ~NLR_MENU_ITEM_MARK));
    CHECK(record_word(records, 3, NLR_MENU_ITEM_VALUE) == 0xffffu);
    CHECK(record_word(records, 4, NLR_MENU_ITEM_FLAGS) == OWN_ROW_FLAGS);
    CHECK(record_word(records, 5, NLR_MENU_ITEM_FLAGS) == OWN_ROW_FLAGS);
    CHECK(record_word(records, 63, 0) == 0x100u + 63u); /* its own slot */
    CHECK(memcmp(module_before, mock_module_records, sizeof module_before) == 0);
    /* The value is in its slot before the build binds it. */
    CHECK(strcmp(slot_text[own_row_slots[NLR_ROWS_MAX + 2]], "LOG3G10.CRV") == 0);

    /* The build is done: the page's entry finishes the rows. */
    *(void **)(window + OWN_WIDGET_TABLE) = &mock_table_object;
    r->list.seq++;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Log3G10 at start") == 0);
    CHECK(strcmp(slot_text[own_row_slots[NLR_ROWS_MAX + 2]], "LOG3G10.CRV") == 0);
    CHECK(switch_states[0] == 2 && switch_states[1] == 1 && !switch_states[2]);
    CHECK(disabled_rows[3] && disabled_rows[4]);
    CHECK(!disabled_rows[0] && !disabled_rows[1] && !disabled_rows[2]);
    CHECK(!hidden_rows[31] && hidden_rows[NLR_ROWS_MAX] && hidden_rows[39]);
    /* The rows beyond the 32 are never written: they hold the values. */
    CHECK(strcmp(slot_text[own_row_slots[NLR_ROWS_MAX + 2]], "LOG3G10.CRV") == 0);

    /* A plain list again: every row its own, on the runtime's copy. */
    r->list.rows_view = 0;
    nlr_page_prepare_redraw(r);
    for (uint32_t k = 0; k < 64; k++) {
        CHECK(record_word(records, k, NLR_MENU_ITEM_FLAGS) == OWN_ROW_FLAGS);
        CHECK(record_word(records, k, NLR_MENU_ITEM_VALUE) == 0xffffu);
        CHECK(record_word(records, k, NLR_MENU_ITEM_STYLE) == OWN_ITEM_STYLES);
    }
    CHECK(page_items_now() == records);
}

static uint64_t event_word(const struct nlr_runtime *r, uint32_t k, uint32_t at)
{
    return *(const uint64_t *)(r->own.kbd_events + k * NLR_MENU_EVENT_BYTES + at);
}

static uint32_t event_next(const struct nlr_runtime *r, uint32_t k)
{
    return *(const uint32_t *)(r->own.kbd_events + k * NLR_MENU_EVENT_BYTES +
                               NLR_MENU_EVENT_NEXT);
}

/* ABI 6 keyboard. The Setup page's open record moves the page record out
 * of the window-table entry it was built into -- the list's window follows
 * it -- and installs the keyboard's window there: the stock keyboard's
 * type and parent, the core's handler block (its entry, the template's
 * other slots) and page (the stock page on the core's event table: save,
 * MENU and back are the core's, help does nothing, the rest the
 * engine's). A program's text entry is a one-row list whose OK opens the
 * keyboard with the program's text and limits; save hands the text over
 * once, MENU gives up, and either goes back to the page. */
static void program_input_on_the_page(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    _Alignas(8) uint8_t keyboard[NLR_MENU_WINDOW_BYTES] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    struct nlr_menu_nav key = {keyboard, 0x2dc, KBD_BACK};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");

    /* A table that is not the one the build left gets no keyboard. */
    uint8_t built[NLR_MENU_WINDOW_BYTES];
    memcpy(built, mock_page_record, sizeof built);
    *(void **)(mock_list_window + NLR_MENU_WINDOW_PAGE) = mock_kbd_page;
    struct nlr_menu_nav open = {window, 0x2b3, 0x65a};
    nlr_page_open_action(&open);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    CHECK(!r->own.ready && memcmp(built, mock_page_record, sizeof built) == 0);
    *(void **)(mock_list_window + NLR_MENU_WINDOW_PAGE) = mock_page_record;

    nlr_page_open_action(&open);
    CHECK(r->own.ready);
    CHECK(memcmp(r->own.page_record, built, NLR_MENU_PAGE_BYTES) == 0);
    CHECK(*(void **)(mock_list_window + NLR_MENU_WINDOW_PAGE) == r->own.page_record);
    CHECK(*(uint16_t *)mock_page_record == 2 &&
          *(uint16_t *)(mock_page_record + NLR_MENU_WINDOW_ID) == KBD_WINDOW);
    CHECK(*(uint64_t *)(mock_page_record + NLR_MENU_WINDOW_PARENT) == KBD_PARENT);
    CHECK(*(void **)(mock_page_record + NLR_MENU_WINDOW_HANDLERS) == r->own.kbd_handlers);
    CHECK(*(void **)(mock_page_record + NLR_MENU_WINDOW_PAGE) == r->own.kbd_page);
    CHECK(*(uint64_t *)(mock_page_record + 0x30) == 0 &&
          *(uint64_t *)(mock_page_record + 0x58) == 0);
    CHECK(r->own.kbd_handlers[0] == (uint64_t)(uintptr_t)nlr_keyboard_enter);
    for (uint32_t k = 1; k < NLR_MENU_HANDLERS; k++)
        CHECK(r->own.kbd_handlers[k] == mock_kbd_handlers[k]);
    for (uint32_t n = 0; n < NLR_MENU_PAGE_BYTES; n++)
        if (n < NLR_MENU_PAGE_EVENTS || n >= NLR_MENU_PAGE_EVENTS + 8u)
            CHECK(r->own.kbd_page[n] == mock_kbd_page[n]);
    CHECK(*(void **)(r->own.kbd_page + NLR_MENU_PAGE_EVENTS) == r->own.kbd_tables);
    CHECK(r->own.kbd_tables[0] == (uint64_t)(uintptr_t)r->own.kbd_events);
    CHECK(event_word(r, 0, NLR_MENU_EVENT_ACTION) == (uint64_t)(uintptr_t)nlr_own_cancel_action &&
          event_next(r, 0) == KBD_BACK);
    CHECK(event_word(r, 1, NLR_MENU_EVENT_ACTION) == 0x5201u && event_next(r, 1) == 0x712);
    CHECK(event_word(r, 2, NLR_MENU_EVENT_ACTION) == (uint64_t)(uintptr_t)nlr_keyboard_save_action &&
          event_next(r, 2) == KBD_BACK);
    CHECK(event_word(r, 3, NLR_MENU_EVENT_ACTION) == (uint64_t)(uintptr_t)nlr_own_cancel_action);
    CHECK(event_word(r, 4, NLR_MENU_EVENT_ACTION) == 0 &&
          event_word(r, 4, NLR_MENU_EVENT_GUARD) == 0 && event_next(r, 4) == OWN_STAY);
    CHECK(memcmp(r->own.kbd_events + 5 * NLR_MENU_EVENT_BYTES,
                 mock_kbd_events + 5 * NLR_MENU_EVENT_BYTES, NLR_MENU_EVENT_BYTES) == 0);
    /* Once per boot: opening the page again leaves it all as it is. */
    uint8_t installed[NLR_MENU_WINDOW_BYTES];
    memcpy(installed, mock_page_record, sizeof installed);
    nlr_page_open_action(&open);
    CHECK(memcmp(installed, mock_page_record, sizeof installed) == 0);
    /* The page's words are the moved record's from now on. */
    r->detail_view = 1;
    r->checked = 0;
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    r->list_view = 1;
    r->list.rows_view = 1;
    r->list.count = 1;
    r->list.kinds[0] = NLR_ROW_SWITCH;
    nlr_page_prepare_redraw(r);
    CHECK(r->items.installed &&
          *(void **)(r->own.page_record + NLR_MENU_PAGE_ITEMS) == r->items.records);
    CHECK(*(uint32_t *)r->own.page_record == (OWN_PAGE_FLAGS | OWN_SKIP_FLAG));
    CHECK(memcmp(installed, mock_page_record, sizeof installed) == 0);

    /* The program's text entry, as ui_input publishes it. */
    snprintf(r->list.title, sizeof r->list.title, "Name");
    snprintf(r->list.rows[0], sizeof r->list.rows[0], "Name");
    r->list.kinds[0] = NLR_ROW_SELECT;
    snprintf(r->list.values[0], sizeof r->list.values[0], "NIKON");
    r->list.dialog = NLR_OWN_KEYBOARD;
    snprintf(r->own.text, sizeof r->own.text, "NIKON");
    r->own.length = 36;
    r->own.charset = NLR_INPUT_ASCII;
    r->list.seq = 5;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Name") == 0 && r->list.shown == 5);
    /* OK opens the keyboard; nothing goes to the program yet. */
    uint32_t answered = r->list.choice_seq;
    nlr_page_row_action(&nav);
    CHECK(nav.next == KBD_WINDOW && r->own.open && r->own.seq == 5);
    CHECK(r->list.choice_seq == answered);
    CHECK(nlr_keyboard_enter(keyboard) == keyboard && kbd.opens == 1 && kbd.shown == 1);
    CHECK(strcmp(kbd.text, "NIKON") == 0 && kbd.length == 36 && kbd.rows == 2 &&
          kbd.charset == NLR_INPUT_ASCII && kbd.field == NLR_INPUT_FIELD &&
          kbd.window == keyboard);
    /* Save: the text, once, and back to the page. */
    kbd.typed = "Z6III";
    nlr_keyboard_save_action(&key);
    CHECK(key.next == KBD_BACK && !r->own.open && r->own.answered == 5);
    CHECK(r->list.choice == 5 && r->list.choice_seq == answered + 1);
    CHECK(strcmp(r->own.taken, "Z6III") == 0);
    /* OK on the answered entry only draws the page again. */
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(nav.next == OWN_ACTION_NEXT && r->list.choice_seq == answered + 1);

    /* The next entry: 254 characters fill 15 rows; MENU gives up. */
    r->own.length = NLR_INPUT_MAX;
    r->own.charset = NLR_INPUT_UPPER;
    r->list.seq = 6;
    nlr_page_enter(window);
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(nav.next == KBD_WINDOW && r->own.seq == 6);
    nlr_keyboard_enter(keyboard);
    CHECK(kbd.rows == 15 && kbd.length == NLR_INPUT_MAX && kbd.charset == NLR_INPUT_UPPER);
    key.next = KBD_BACK;
    nlr_own_cancel_action(&key);
    CHECK(key.next == KBD_BACK && r->list.choice == (int32_t)NLR_LIST_BACK &&
          r->list.choice_seq == answered + 2 && !r->own.open);

    /* Refused by the engine: the keyboard stays, still open. */
    r->list.seq = 7;
    nlr_page_enter(window);
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    kbd.take_result = 0;
    key.next = KBD_BACK;
    nlr_keyboard_save_action(&key);
    CHECK(key.next == OWN_STAY && r->own.open && r->list.choice_seq == answered + 2);
    kbd.take_result = 1;
    /* The program moved on meanwhile: the save answers nothing. */
    r->list.seq = 8;
    nlr_keyboard_save_action(&key);
    CHECK(key.next == KBD_BACK && !r->own.open && r->list.choice_seq == answered + 2);

    /* Back on the entry's row goes to the program as a list's back. */
    nlr_page_enter(window);
    nav.next = 0x68d;
    nlr_page_back_action(&nav);
    CHECK(r->list.choice == (int32_t)NLR_LIST_BACK && r->list.choice_seq == answered + 3);

    /* The program is over: the keyboard's save shows the details. */
    r->list.seq = 9;
    nlr_page_enter(window);
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    nlr_keyboard_save_action(&key);
    CHECK(key.next == KBD_BACK && !r->list_view && r->list.choice_seq == answered + 3);
    /* With no entry open the keyboard is an empty one. */
    nlr_keyboard_enter(keyboard);
    CHECK(kbd.text[0] == 0 && kbd.length == 2u * NLR_INPUT_FIELD_ROW && kbd.rows == 2);
}

static uint64_t caution_word(const struct nlr_runtime *r, uint32_t item,
                             uint32_t k, uint32_t at)
{
    return *(const uint64_t *)(r->own.caution_events[item] + k * NLR_MENU_EVENT_BYTES + at);
}

static uint32_t caution_next(const struct nlr_runtime *r, uint32_t item, uint32_t k)
{
    return *(const uint32_t *)(r->own.caution_events[item] + k * NLR_MENU_EVENT_BYTES +
                               NLR_MENU_EVENT_NEXT);
}

/* ABI 6 caution box, on the keyboard's window id. Installed with the
 * keyboard: the stock popup's page on the core's items and event tables,
 * where Yes and No (wherever the template's own actions are) and MENU and
 * back are the core's. A program's caution opens it with the window
 * record naming the box's records; its entry puts the text in the slot,
 * turns the panel to it through mode 1, and puts a question's cursor on
 * No. A message has one button, labelled OK, whose No keys do nothing;
 * the keyboard afterwards takes the window back. */
static void program_caution_on_the_page(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    _Alignas(8) uint8_t box[NLR_MENU_WINDOW_BYTES] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    struct nlr_menu_nav key = {box, 0x2b3, KBD_BACK};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    struct nlr_menu_nav open = {window, 0x2b3, 0x65a};
    nlr_page_open_action(&open);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    CHECK(r->own.ready && r->own.caution_ready);
    CHECK(*(void **)(r->own.caution_page + NLR_MENU_PAGE_ITEMS) == r->own.caution_items);
    CHECK(*(void **)(r->own.caution_page + NLR_MENU_PAGE_EVENTS) == r->own.caution_tables);
    CHECK(memcmp(r->own.caution_page, mock_caution_page, NLR_MENU_PAGE_ITEMS) == 0);
    CHECK(memcmp(r->own.caution_items, mock_caution_items, sizeof mock_caution_items) == 0);
    for (uint32_t k = 0; k < 2; k++) {
        CHECK(r->own.caution_tables[k] == (uint64_t)(uintptr_t)r->own.caution_events[k]);
        CHECK(caution_word(r, k, 0, NLR_MENU_EVENT_ACTION) ==
                  (uint64_t)(uintptr_t)nlr_own_cancel_action &&
              caution_next(r, k, 0) == KBD_BACK);
        CHECK(caution_word(r, k, 1, NLR_MENU_EVENT_ACTION) ==
                  (uint64_t)(uintptr_t)(k ? nlr_caution_no_action : nlr_caution_yes_action) &&
              caution_next(r, k, 1) == KBD_BACK);
        CHECK(caution_word(r, k, 2, NLR_MENU_EVENT_ACTION) ==
                  (uint64_t)(uintptr_t)nlr_caution_no_action &&
              caution_word(r, k, 2, NLR_MENU_EVENT_GUARD) == 0);
        CHECK(caution_word(r, k, 3, NLR_MENU_EVENT_ACTION) ==
              (uint64_t)(uintptr_t)nlr_own_cancel_action);
        CHECK(memcmp(r->own.caution_events[k] + 4 * NLR_MENU_EVENT_BYTES,
                     mock_caution_events[k] + 4 * NLR_MENU_EVENT_BYTES,
                     NLR_MENU_EVENT_BYTES) == 0);
    }
    CHECK(r->own.caution_handlers[0] == (uint64_t)(uintptr_t)nlr_caution_enter);
    for (uint32_t k = 1; k < NLR_MENU_HANDLERS; k++)
        CHECK(r->own.caution_handlers[k] == mock_caution_handlers[k]);

    /* A question, as ui_caution publishes it. */
    r->detail_view = 1;
    r->checked = 0;
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    r->list_view = 1;
    r->list.rows_view = 0;
    r->list.count = 1;
    snprintf(r->list.title, sizeof r->list.title, "Delete it?");
    snprintf(r->list.rows[0], sizeof r->list.rows[0], "Delete it?");
    r->list.dialog = NLR_OWN_CAUTION;
    snprintf(r->own.message, sizeof r->own.message, "Delete it?\nIt cannot be undone.");
    r->own.buttons = NLR_CAUTION_YES_NO;
    r->list.seq = 5;
    r->show_check = 1;
    nlr_page_enter(window);
    uint32_t answered = r->list.choice_seq;
    nlr_page_row_action(&nav);
    CHECK(nav.next == KBD_WINDOW && r->own.open == NLR_OWN_CAUTION && r->own.seq == 5);
    CHECK(*(void **)(mock_page_record + NLR_MENU_WINDOW_HANDLERS) == r->own.caution_handlers);
    CHECK(*(void **)(mock_page_record + NLR_MENU_WINDOW_PAGE) == r->own.caution_page);
    CHECK(*(uint64_t *)(mock_page_record + NLR_MENU_WINDOW_PARENT) == CAU_PARENT);
    CHECK(*(uint16_t *)(r->own.caution_page + NLR_MENU_PAGE_COUNT) == 2);
    CHECK(*(uint32_t *)r->own.caution_items == 0x46u);
    CHECK(nlr_caution_enter(box) == box);
    CHECK(strcmp(slot_text[CAU_SLOT], "Delete it?\nIt cannot be undone.") == 0);
    CHECK(widget_find_id == CAU_PANEL && widget_find_container == box + PAGE_CONTAINER);
    CHECK(cau.calls == 2 && cau.panel == &page_widget);
    CHECK(cau.slots[0] == 0 && cau.modes[0] == 1 && cau.slots[1] == CAU_SLOT && cau.modes[1] == 3);
    CHECK(cau.cursor_calls == 1 && cau.cursor_window == box && cau.cursor_item == CAU_NO_ITEM);
    nlr_caution_yes_action(&key);
    CHECK(key.next == KBD_BACK && r->list.choice == 1 && r->list.choice_seq == answered + 1);
    CHECK(!r->own.open && r->own.answered == 5);

    /* No, on the next question. */
    r->list.seq = 6;
    nlr_page_enter(window);
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    key.next = KBD_BACK;
    nlr_caution_no_action(&key);
    CHECK(key.next == KBD_BACK && r->list.choice == 0 && r->list.choice_seq == answered + 2);

    /* A message: one button, labelled OK; its No keys do nothing, MENU
     * gives up, OK answers. */
    r->own.buttons = NLR_CAUTION_OK;
    r->list.seq = 7;
    nlr_page_enter(window);
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    CHECK(nav.next == KBD_WINDOW);
    CHECK(*(uint16_t *)(r->own.caution_page + NLR_MENU_PAGE_COUNT) == 1);
    CHECK(*(uint32_t *)r->own.caution_items == CAU_OK_LABEL);
    cau.cursor_calls = 0;
    nlr_caution_enter(box);
    CHECK(cau.cursor_calls == 0);
    key.next = KBD_BACK;
    nlr_caution_no_action(&key);
    CHECK(key.next == OWN_STAY && r->own.open && r->list.choice_seq == answered + 2);
    nlr_own_cancel_action(&key);
    CHECK(key.next == KBD_BACK && r->list.choice == (int32_t)NLR_LIST_BACK &&
          r->list.choice_seq == answered + 3);
    r->list.seq = 8;
    nlr_page_enter(window);
    nav.next = 0x68d;
    nlr_page_row_action(&nav);
    nlr_caution_yes_action(&key);
    CHECK(r->list.choice == 1 && r->list.choice_seq == answered + 4);

    /* The keyboard takes the window back, with nothing of the box's last
     * build: a cursor left on No would index past the keyboard's one
     * item. */
    r->list.dialog = NLR_OWN_KEYBOARD;
    r->list.seq = 9;
    nlr_page_enter(window);
    nav.next = 0x68d;
    *(uint16_t *)(mock_page_record + 0x30) = 2;
    *(uint16_t *)(mock_page_record + 0x32) = 1;
    *(uint16_t *)(mock_page_record + 0x58) = 1;
    nlr_page_row_action(&nav);
    CHECK(*(uint16_t *)(mock_page_record + 0x30) == 0 &&
          *(uint16_t *)(mock_page_record + 0x32) == 0 &&
          *(uint16_t *)(mock_page_record + 0x58) == 0);
    CHECK(*(uint16_t *)mock_page_record == 2 &&
          *(uint16_t *)(mock_page_record + NLR_MENU_WINDOW_ID) == KBD_WINDOW);
    CHECK(nav.next == KBD_WINDOW && r->own.open == NLR_OWN_KEYBOARD);
    CHECK(*(void **)(mock_page_record + NLR_MENU_WINDOW_HANDLERS) == r->own.kbd_handlers);
    CHECK(*(void **)(mock_page_record + NLR_MENU_WINDOW_PAGE) == r->own.kbd_page);
    CHECK(*(uint64_t *)(mock_page_record + NLR_MENU_WINDOW_PARENT) == KBD_PARENT);
}
#endif

#if !defined(NLR_STAGE_PREPARE_ONLY) && !defined(NLR_STAGE_EXEC)
static void row_action_checks_the_row_program(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n"
                 "ext | resource_extension | Extension | APPS/E.NLB | 2\n");
#if defined(NLR_STAGE_LOAD_ONLY)
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Hello") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Extension") == 0);
    CHECK(!hidden_rows[0] && !hidden_rows[1] && hidden_rows[2]);
    uint32_t reads = manifest_opens;
    /* A clean check leaves the status row out: open, then back. The row
     * action sizes the page for the two rows before the re-entry builds it. */
    nlr_page_row_action(&nav);
    CHECK(mock_page_count == 2);
    nlr_page_enter(nav.window);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Back to list") == 0);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "Hello") == 0);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Open application (check only)") == 0);
    CHECK(program_opens == 1 && manifest_opens == reads);
    CHECK(hidden_rows[2] && !hidden_rows[1]);
    spec.crc_xor = 1;
    build_card(&spec);
    CHECK(strcmp(ok_then_enter(&nav), "CRC mismatch") == 0);
    spec = valid_spec(16);
    spec.file_delta = -1;
    build_card(&spec);
    CHECK(strcmp(ok_then_enter(&nav), "bad size") == 0);
    spec = valid_spec(16);
    build_card(&spec);
    fail_next_read = 1;
    CHECK(strcmp(ok_then_enter(&nav), "read error") == 0);
    fail_next_read = 0;
    open_fail = 1;
    CHECK(strcmp(ok_then_enter(&nav), "cannot open") == 0);
    open_fail = 0;
    safe_mode_present = 1;
    CHECK(strcmp(ok_then_enter(&nav), "DISABLED (SAFE_MODE)") == 0);
    safe_mode_present = 0;
    /* The failures opened the status row; within the same visit a clean
     * check keeps it and says so. */
    CHECK(strcmp(ok_then_enter(&nav), "Hello: OK") == 0);

    /* Back restores the selected list position; a second Back keeps the
     * stock target and exits instead of trapping the user in our window. */
    nav.code = 0x285; nav.next = 0x68d;
    nlr_page_back_action(&nav);
    CHECK(nav.next == OWN_ACTION_NEXT);
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "NLoader") == 0);
    CHECK(*(uint16_t *)(window + 0x32) == 0);
    nav.next = 0x68d;
    nlr_page_back_action(&nav);
    CHECK(nav.next == 0x68d);

    /* Selecting row one checks its file, not the first listed file. */
    *(uint16_t *)(window + 0x32) = 1;
    nav.code = 0x286; nav.next = 0x68d;
    CHECK(strcmp(ok_then_enter(&nav), "Back to list") == 0);
    CHECK(nav.next == OWN_ACTION_NEXT);
    CHECK(strcmp(program_path, NLR_PROGRAM_ROOT "APPS\\E.NLB") == 0);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Extension settings (check only)") == 0);
    *(uint16_t *)(window + 0x32) = 1; /* back, the second of two rows */
    nlr_page_row_action(&nav);
    nlr_page_enter(window);
    CHECK(*(uint16_t *)(window + 0x32) == 1);
#ifdef NLR_TEST_PAGE_REBUILD
    /* Rebuilt in place on a cleared layer: the two-row list is two rows. */
    CHECK(mock_page_count == 2 && !hidden_rows[1] && hidden_rows[2]);
#else
    /* The same window never shrinks: the failures above built three rows,
     * so the two-row list ends in an empty one. */
    CHECK(mock_page_count == 3 && !hidden_rows[2] && hidden_rows[3]);
    CHECK(slot_text[own_row_slots[2]][0] == 0);
#endif

    /* A fresh external entry rereads the directory and clamps the cursor;
     * the open action sizes the page for the list first. */
    set_manifest("future | foreground | Future | APPS/F.NLB | 10\n");
    external_entry(window);
    CHECK(*(uint16_t *)(window + 0x32) == 0 && mock_page_count == 1);
    uint32_t opens = program_opens;
    CHECK(strcmp(ok_then_enter(&nav), "needs newer NLoader") == 0);
    CHECK(program_opens == opens);
    /* The menu reopening on the details keeps them: their rows were built. */
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[1]], "needs newer NLoader") == 0);
    set_manifest("# none\n");
    external_entry(window);
    CHECK(strcmp(stored_text, "MANIFEST: no programs") == 0);
    CHECK(!hidden_rows[0] && hidden_rows[1]);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2\n");
    nlr_page_row_action(&nav);
    nlr_page_enter(window);
    CHECK(strcmp(stored_text, "Hello") == 0);

    /* Every supported cardinality has exactly that many selectable rows. */
    const uint32_t counts[] = {0, 1, 2, 3, 6, 7, 63, 64};
    char manifest[8192];
    for (uint32_t c = 0; c < sizeof counts / sizeof counts[0]; c++) {
        uint32_t size = 0, count = counts[c];
        manifest[0] = 0;
        for (uint32_t i = 0; i < count; i++)
            size += (uint32_t)snprintf(manifest + size, sizeof manifest - size,
                "p%u | foreground | Program %u | APPS/P%u.NLB | 2\n", i, i, i);
        set_manifest(manifest);
        *(uint16_t *)(window + 0x32) = 63;
        external_entry(window);
        CHECK(mock_page_count == (count ? count : 1));
        for (uint32_t i = 0; i < 64; i++)
            CHECK(hidden_rows[i] == (i >= (count ? count : 1)));
        CHECK(*(uint16_t *)(window + 0x32) < (count ? count : 1));
    }
    CHECK(strcmp(slot_text[own_row_slots[63]], "Program 63") == 0);
    CHECK(strcmp(ok_then_enter(&nav), "Back to list") == 0);
    CHECK(strcmp(program_path, NLR_PROGRAM_ROOT "APPS\\P63.NLB") == 0);
    nav.next = 0x68d;
    nlr_page_back_action(&nav);
    nlr_page_enter(window);
    CHECK(*(uint16_t *)(window + 0x32) == 63);
    reset_mocks();
    struct nlr_menu_nav empty = {0, 0x286, 0x68d};
    nlr_page_row_action(&empty);
    nlr_page_row_action(0);
    nlr_page_back_action(0);
    CHECK(text_store_calls == 0 && alloc_calls == 0);
#else
    nlr_page_row_action(&nav);
    nlr_page_back_action(&nav);
    CHECK(text_store_calls == 0 && alloc_calls == 0 && manifest_opens == 0);
#endif
}
#endif

#if defined(NLR_STAGE_LOAD_ONLY)
static void long_detail_names_preserve_failure_reasons_and_back_cursor(void)
{
    const char name[] = "WWWWWWWWWWWWWWWWWWWWWWWW";
    const struct {
        uint32_t minimum_abi;
        const char *models;
        uint32_t crc_xor;
        int result;
        const char *reason;
    } cases[] = {
        {2, "z8/3.11", 0, NLR_OK, 0},
        {2, "z8/3.11", 1, NLR_CHECKSUM, "CRC mismatch"},
        {NLR_ABI_VERSION + 1u, "z8/3.11", 0, NLR_REFUSED, "needs newer NLoader"},
        {2, "z6iii/2.00", 0, NLR_REFUSED, "not for this camera"},
        {2, "z8/3.10", 0, NLR_REFUSED, "not for this camera"},
    };
    CHECK(strlen(name) == 24);
    for (uint32_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        for (uint32_t cursor = 0; cursor <= 1; cursor++) {
            _Alignas(8) uint8_t window[0x60] = {0};
            struct nlr_menu_nav nav = {window, 0x286, 0x68d};
            reset_mocks();
            struct card_spec spec = valid_spec(16);
            spec.crc_xor = cases[c].crc_xor;
            build_card(&spec);
            char manifest[256];
            char wide[128];
            snprintf(wide, sizeof wide,
                     "wide | foreground | %s | APPS/WIDE.NLB | %u | %s\n", name,
                     cases[c].minimum_abi, cases[c].models);
            const char *first =
                "first | foreground | First | APPS/FIRST.NLB | 2 | z8/3.11\n";
            snprintf(manifest, sizeof manifest, "%s%s", cursor ? first : wide,
                     cursor ? wide : first);
            set_manifest(manifest);
            nlr_page_enter(window);
            struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
            CHECK(r && r->directory.count == 2);
            char expected_list[40];
            snprintf(expected_list, sizeof expected_list, "%s%s", name,
                     cases[c].result == NLR_REFUSED ? ": blocked" : "");
            CHECK(strcmp(slot_text[own_row_slots[cursor]], expected_list) == 0);
            *(uint16_t *)(window + 0x32) = (uint16_t)cursor;
            /* A clean check has no status row: row 1 is back. */
            const char *expected = cases[c].reason ? cases[c].reason : "Back to list";
            CHECK(strcmp(ok_then_enter(&nav), expected) == 0);
            CHECK(strcmp(slot_text[OWN_TITLE_SLOT], name) == 0);
            CHECK(r && r->checked == cursor && r->check_result == cases[c].result &&
                  r->detail_view && r->list_cursor == cursor);
            CHECK(program_opens == (cases[c].result == NLR_REFUSED ? 0u : 1u));
            if (cases[c].result == NLR_REFUSED)
                CHECK(r && !r->path[0]);
            else
                CHECK(strcmp(program_path, NLR_PROGRAM_ROOT "APPS\\WIDE.NLB") == 0);
            CHECK(r && !r->load.state && !r->load.probe.prepared &&
                  !r->load.probe.entry_started && !r->load.program.prepared &&
                  !r->load.program.entry_started && !r->autoload.phase);
            for (uint32_t i = 0; r && i < NLR_RESIDENT_MAX; i++)
                CHECK(!r->resident[i].used);
            nav.code = 0x285;
            nav.next = 0x68d;
            nlr_page_back_action(&nav);
            CHECK(nav.next == OWN_ACTION_NEXT);
            nlr_page_enter(window);
            CHECK(r && !r->detail_view && r->list_cursor == cursor);
            CHECK(*(uint16_t *)(window + 0x32) == cursor);
            CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "NLoader") == 0);
            CHECK(strcmp(slot_text[own_row_slots[cursor]], expected_list) == 0);
        }
    }
}
#endif

static void probe_v2_loading_and_kind_rejections(void)
{
    static const uint8_t file[64] = {
        'N', 'P', 'L', 'D', 2, 0, 48, 0,
        1, 0, 0, 0, 16, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0x87, 0xea, 0x73, 0x7f,
        2, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x00, 0x44, 0xc0, 0x93, 0x00, 0x34, 0x00, 0xca,
        0x00, 0x44, 0x0c, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    };
    reset_mocks();
    memcpy(card, file, sizeof(file));
    card_len = sizeof(file);
    _Alignas(NLR_CACHE_LINE) uint8_t arena[64];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof(arena), &task) == NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;
    read_max = 3;
    CHECK(nlr_load_file(&load) == NLR_OK);
    CHECK(load.header_bytes == 48 && load.image_bytes == 16);
    CHECK(memcmp(load.header, file, 48) == 0);
    CHECK(memcmp(load.arena, file + 48, 16) == 0);
    CHECK(cache_before_calls == 3 && cache_after_calls == 3);
    CHECK(!load.probe.entry_started && !load.probe.returned);

    const uint32_t rejected_kinds[] = {NLR_KIND_NONE, NLR_KIND_RESOURCE_EXTENSION, 3};
    for (unsigned i = 0; i < sizeof(rejected_kinds) / sizeof(rejected_kinds[0]); i++) {
        load.manifest_kind = rejected_kinds[i];
        CHECK(nlr_load_file(&load) == NLR_FORMAT);
        CHECK(!load.header_bytes && !load.image_bytes && !load.probe.entry_started);
    }
    load.manifest_kind = NLR_KIND_FOREGROUND;
    const uint32_t rejected_fields[] = {24, 32, 36, 40, 44};
    for (unsigned i = 0; i < sizeof(rejected_fields) / sizeof(rejected_fields[0]); i++) {
        memcpy(card, file, sizeof(file));
        card[rejected_fields[i]] ^= 1;
        CHECK(nlr_load_file(&load) == NLR_FORMAT);
        CHECK(!load.header_bytes && !load.image_bytes);
    }
    memcpy(card, file, sizeof(file));
    card[48] ^= 1;
    uint32_t checksum = test_crc32(card + 48, 16);
    memcpy(card + 28, &checksum, 4);
    CHECK(nlr_load_file(&load) != NLR_OK);
    CHECK(!load.header_bytes && !load.image_bytes && !load.probe.entry_started);
    memcpy(card, file, sizeof(file));
    card_len = 63;
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    /* Cut inside the extended header: the common fields already fix the
     * length, so this is a size error, not a failed read. */
    card_len = 40;
    CHECK(nlr_load_file(&load) == NLR_BOUNDS && load.stage == 'V');
    card_len = 65;
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    card_len = sizeof(file);
    close_fail = 1;
    CHECK(nlr_load_file(&load) == NLR_IO);
    CHECK(!load.header_bytes && !load.image_bytes);
}

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
static struct nlr_runtime *probe_runtime_fixture(void)
{
    static const uint8_t file[64] = {
        'N', 'P', 'L', 'D', 2, 0, 48, 0,
        1, 0, 0, 0, 16, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0x87, 0xea, 0x73, 0x7f,
        2, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x00, 0x44, 0xc0, 0x93, 0x00, 0x34, 0x00, 0xca,
        0x00, 0x44, 0x0c, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    };
    reset_mocks();
    memcpy(card, file, sizeof(file));
    card_len = sizeof(file);
    set_manifest("probe | foreground | Probe | APPS/PROBE.NLB | 2 | z8/3.11\n"
                 "other | foreground | Other | APPS/OTHER.NLB | 2 | z8/3.11\n");
    struct nlr_runtime *runtime = 0;
    CHECK(nlr_runtime_create(&runtime, &nlr_services, ARENA_CAP) == NLR_OK);
    CHECK(runtime != 0);
    CHECK(nlr_runtime_read_directory(runtime) == NLR_OK);
    return runtime;
}

static void queued_probe_execution_rechecks_current_card(void)
{
#ifdef NLR_STAGE_PREPARE_ONLY
    const uint32_t mode = 1, calls_per_run = 0;
#else
    const uint32_t mode = 2, calls_per_run = 1;
#endif
    struct nlr_runtime *r = probe_runtime_fixture();
    CHECK(nlr_runtime_start_probe(r, 0, mode) == NLR_OK);
    CHECK(r->load.state == 1 && r->load.probe_mode == mode && r->probe_pending);
    CHECK(!probe_call_count && !r->load.probe_attempted);
    CHECK(program_opens == 1 && manifest_opens == 1);
    char queued_path[NLR_PATH_BYTES];
    snprintf(queued_path, sizeof(queued_path), "%s", r->path);
    CHECK(nlr_runtime_start_probe(r, 1, mode) == NLR_BUSY);
    CHECK(nlr_runtime_check(r, 1) == NLR_BUSY);
    CHECK(nlr_runtime_read_directory(r) == NLR_BUSY);
    CHECK(strcmp(r->path, queued_path) == 0 && strcmp(r->probe_id, "probe") == 0);
    CHECK(r->load.probe_mode == mode && r->load.state == 1);
    CHECK(program_opens == 1 && manifest_opens == 1 && !probe_call_count);
    CHECK(nlr_load_now(&r->load) == NLR_NOT_READY);
    CHECK(r->load.state == 1 && !probe_call_count);
    nlr_load_event(&r->load, 2);
    CHECK(r->load.state == 1 && !probe_call_count);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && r->load.state == 0);
    CHECK(r->load.probe_attempted && !r->load.probe_mode && r->load.probe.prepared);
    CHECK(program_opens == 2 && manifest_opens == 2);
    CHECK(probe_call_count == calls_per_run);
    CHECK(r->load.probe.entry_started == calls_per_run);
    CHECK(r->load.probe.returned == calls_per_run);
    CHECK(!r->load.probe.allocation);
    if (calls_per_run)
        CHECK(r->load.probe.response == r->load.probe.expected);
    uint64_t first_challenge = r->load.probe.challenge;
    CHECK(nlr_runtime_start_probe(r, 0, mode) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && r->load.probe.challenge != first_challenge);
    CHECK(probe_call_count == 2 * calls_per_run);

    /* The "past the ABI" line below names NLR_ABI_VERSION + 1. */
    _Static_assert(NLR_ABI_VERSION == 9u, "update the past-the-ABI manifest line");
    const char *changed_manifests[] = {
        "probe | resource_extension | Probe | APPS/PROBE.NLB | 2\n",
        "probe | foreground | Probe | APPS/NEW.NLB | 2\n",
        "replacement | foreground | Probe | APPS/PROBE.NLB | 2\n",
        "probe | foreground | Probe | APPS/PROBE.NLB | 10\n", /* past the ABI */
        "probe | foreground | Probe | APPS/PROBE.NLB | 2 | z6iii/2.00\n",
        "# removed\n",
    };
    for (unsigned i = 0; i < sizeof(changed_manifests) / sizeof(changed_manifests[0]); i++) {
        r = probe_runtime_fixture();
        CHECK(nlr_runtime_start_probe(r, 0, mode) == NLR_OK);
        set_manifest(changed_manifests[i]);
        nlr_load_event(&r->load, 1);
        CHECK(r->load.last_result == NLR_REFUSED && r->load.state == 0);
        CHECK(program_opens == 1 && manifest_opens == 2 && !probe_call_count);
        CHECK(!r->load.probe.entry_started && r->load.probe_attempted);
        CHECK(strcmp(r->path, queued_path) == 0);
        CHECK(r->directory.count == 2); /* GUI snapshot was not overwritten */
    }

    r = probe_runtime_fixture();
    CHECK(nlr_runtime_start_probe(r, 0, mode) == NLR_OK);
    safe_mode_present = 1;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_DISABLED);
    CHECK(program_opens == 1 && manifest_opens == 1 && !probe_call_count);

    r = probe_runtime_fixture();
    CHECK(nlr_runtime_start_probe(r, 0, mode) == NLR_OK);
    card_manifest_present = 0;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_IO && program_opens == 1 && !probe_call_count);

    r = probe_runtime_fixture();
    CHECK(nlr_runtime_start_probe(r, 0, mode) == NLR_OK);
    struct card_spec old_format = valid_spec(16);
    build_card(&old_format);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_FORMAT && program_opens == 2 && !probe_call_count);

    r = probe_runtime_fixture();
    flag_set_fail = 1;
    CHECK(nlr_runtime_start_probe(r, 0, mode) == NLR_IO);
    CHECK(!r->load.state && !r->load.probe_mode && !r->probe_pending);
    nlr_load_event(&r->load, 1);
    CHECK(!probe_call_count && manifest_opens == 1);

    r = probe_runtime_fixture();
#ifdef NLR_STAGE_PREPARE_ONLY
    CHECK(nlr_runtime_start_probe(r, 0, 2) == NLR_REFUSED);
    CHECK(program_opens == 0 && !probe_call_count);
#else
    CHECK(nlr_runtime_start_probe(r, 0, 1) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && r->load.probe.prepared && !probe_call_count);
#endif
}
#endif

/* The heap only promises 8-byte alignment and the camera's blocks start
 * mid-line, while the pre-read call invalidates whole lines: every card
 * buffer sits on whole lines inside its own block, and a caller-supplied
 * buffer that does not is refused before the card is touched. */
static void runtime_card_buffers_own_whole_lines(void)
{
    reset_mocks();
    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);
    CHECK(r != 0);
    if (!r)
        return;
    /* struct, arena, directory: the raw blocks are not line-aligned. */
    CHECK(alloc_count == 3 && alloc_start[1] % NLR_CACHE_LINE != 0 &&
          alloc_start[2] % NLR_CACHE_LINE != 0);
    CHECK((uintptr_t)r->load.arena % NLR_CACHE_LINE == 0);
    CHECK((uintptr_t)r->directory_buffer % NLR_CACHE_LINE == 0);
    CHECK(inside_allocation((uintptr_t)r->load.arena,
                            (uintptr_t)r->load.arena + ARENA_CAP));
    CHECK(inside_allocation((uintptr_t)r->directory_buffer,
                            (uintptr_t)r->directory_buffer + NLR_MANIFEST_BYTES));

    static _Alignas(NLR_CACHE_LINE) uint8_t lines[2 * NLR_CACHE_LINE];
    struct nlr_load l = {0};
    struct nlr_task_config task = default_task();
    worker_callback = 0;
    CHECK(nlr_load_init(&l, &nlr_services, lines + 8, NLR_CACHE_LINE, &task) ==
          NLR_NOT_READY);
    CHECK(nlr_load_init(&l, &nlr_services, lines, NLR_CACHE_LINE + 8, &task) ==
          NLR_NOT_READY);
    CHECK(!worker_callback);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2\n");
    uint32_t opens = manifest_opens;
    CHECK(nlr_manifest_read(&manifest, &nlr_services, lines + 32, NLR_CACHE_LINE, 0) ==
          NLR_NOT_READY);
    CHECK(nlr_manifest_read(&manifest, &nlr_services, lines, NLR_CACHE_LINE + 8, 0) ==
          NLR_NOT_READY);
    CHECK(manifest_opens == opens);
    card_manifest_present = 0;
}

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
static const char *result_row(struct nlr_menu_nav *nav, uint32_t selected)
{
    *(uint16_t *)((uint8_t *)nav->window + 0x32) = (uint16_t)selected;
    nlr_page_row_action(nav);
    nlr_page_enter(nav->window);
    return slot_text[own_row_slots[1]];
}

static void operation_type_survives_worker_header_reinitialization(void)
{
#ifdef NLR_STAGE_EXEC
    const char *program = "Open application", *probe = "Run return probe";
#else
    const char *program = "Prepare application", *probe = "Prepare return probe";
#endif
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    struct nlr_runtime *r = probe_runtime_fixture();
    CHECK(nlr_runtime_check(r, 0) == NLR_OK);
    r->detail_view = r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], probe) == 0);

    r->load.header_bytes = NLR_GENERIC_HEADER_SIZE;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], program) == 0);
    r->program_pending = 1;
    r->load.header_bytes = 0;
    r->load.state = 2;
    r->show_check = 1;
    uint32_t opens = program_opens, calls = probe_call_count;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], program) == 0);
    result_row(&nav, 0);
    CHECK(program_opens == opens && probe_call_count == calls && r->load.state == 2);

    r->load.state = 0;
    r->load.program.code_allocation = window;
    r->show_check = 1;
    nlr_page_enter(window);
    result_row(&nav, 0);
    CHECK(r->check_result == NLR_EXEC_RESTORE && r->load.state == 0);
    CHECK(r->load.program.code_allocation == window && r->program_pending);
    CHECK(program_opens == opens && probe_call_count == calls);
    CHECK(strcmp(slot_text[own_row_slots[0]], program) == 0);
    r->load.program.code_allocation = 0;

    /* A failed generic reread lost its live header. Retry must still use
     * the generic executor, which rejects the replacement probe file,
     * instead of silently queueing the closed probe ABI. */
    r->load.state = 0;
    r->check_result = r->load.last_result = NLR_IO;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], program) == 0);
    result_row(&nav, 0);
    CHECK(r->check_result == NLR_FORMAT && r->load.state == 0 && !r->load.probe_mode);
    CHECK(program_opens == opens + 1 && probe_call_count == calls);

    r->program_pending = 0;
    r->probe_pending = 1;
    r->load.header_bytes = NLR_GENERIC_HEADER_SIZE;
    r->load.state = 2;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], probe) == 0);
    r->load.state = 0;
    r->load.header_bytes = 0;
    result_row(&nav, 0);
    CHECK(r->load.state == 1 && r->load.probe_mode && !r->load.program_mode);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.state == 0 && r->load.probe_attempted);

    const uint32_t unknown_headers[] = {0, NPLD_HEADER_SIZE, 40};
    for (uint32_t n = 0; n < sizeof unknown_headers / sizeof unknown_headers[0]; n++) {
        r->program_pending = r->probe_pending = 0;
        /* Legacy v1 and an incomplete/unknown header are not the closed probe. */
        r->load.header_bytes = unknown_headers[n];
        r->show_check = 1;
        nlr_page_enter(window);
        CHECK(strcmp(slot_text[own_row_slots[0]], "Check application again") == 0);
        opens = program_opens;
        result_row(&nav, 0);
        CHECK(program_opens == opens + 1 && r->load.state == 0);
        CHECK(!r->program_pending && !r->probe_pending);
        CHECK(strcmp(slot_text[own_row_slots[0]], probe) == 0);
    }

    r->load.header_bytes = NLR_GENERIC_HEADER_SIZE;
    r->load.state = 2;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Check application again") == 0);
    r->load.state = 0;
    r->program_pending = r->probe_pending = 1;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Operation unavailable") == 0);
    opens = program_opens;
    result_row(&nav, 0);
    CHECK(program_opens == opens && r->load.state == 0);
    CHECK(r->program_pending && r->probe_pending);
}

#ifdef NLR_STAGE_PREPARE_ONLY
static void generic_preparation_result_does_not_report_exit(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_runtime *r = probe_runtime_fixture();
    CHECK(nlr_runtime_check(r, 0) == NLR_OK);
    r->load.header_bytes = NLR_GENERIC_HEADER_SIZE;
    r->program_pending = 1;
    r->probe_pending = 0;
    r->load.program.prepared = 1;
    r->load.program.entry_started = r->load.program.returned = 0;
    r->detail_view = r->show_check = 1;
    r->load.state = 0;
    r->load.last_result = NLR_OK;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Application preparation passed") == 0);
    CHECK(r->load.program.prepared && !r->load.program.entry_started && !r->load.program.returned);

    /* A previous successful preparation cannot hide a retained allocation
     * or an error on a later attempt. The result view changes no ownership. */
    r->load.program.code_allocation = window;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Application cleanup failed; restart required") == 0);
    CHECK(r->load.program.code_allocation == window);
    r->load.program.code_allocation = 0;
    r->load.last_result = NLR_IO;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Cannot read program or MANIFEST") == 0);
    r->load.last_result = NLR_DISABLED;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[1]], "DISABLED (SAFE_MODE)") == 0);
    CHECK(r->load.program.prepared && !r->load.program.entry_started && !r->load.program.returned);
}
#endif

/* The details page drives the probe: the operation row queues the worker,
 * the result row refreshes, and each outcome is named. A cleanup failure
 * keeps its region and its record: later runs are refused without touching
 * the card, and the page keeps saying so even after other checks. */
static void probe_page_flow_and_kept_cleanup_failure(void)
{
#ifdef NLR_STAGE_EXEC
    const uint32_t mode = 2;
    const char *operation = "Run return probe", *success = "Probe returned correctly";
#else
    const uint32_t mode = 1;
    const char *operation = "Prepare return probe", *success = "Probe preparation passed";
#endif
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    struct nlr_runtime *r = probe_runtime_fixture();
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Probe") == 0);
    /* A clean check has no status row: row 1 is back. */
    CHECK(strcmp(result_row(&nav, 0), "Back to list") == 0);
    CHECK(nav.next == OWN_ACTION_NEXT);
    CHECK(strcmp(slot_text[own_row_slots[0]], operation) == 0);

    /* Operation: queued, the result row selected, shown as running. */
    CHECK(strcmp(result_row(&nav, 0), "Probe running; OK to refresh") == 0);
    CHECK(r->load.state == 1 && *(uint16_t *)(window + 0x32) == 1);
    nlr_load_event(&r->load, 1);
    CHECK(strcmp(result_row(&nav, 1), success) == 0);
    char tag = 0;
    int32_t value = 0;
    CHECK(trace_last(&r->load, &tag, &value) && tag == 'B' && value == (3 << 16 | 3));

    /* The file changes after the request: the worker's load names its own
     * stage instead of the recheck's. */
    result_row(&nav, 0);
    card_len = 40;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_BOUNDS);
    CHECK(strcmp(result_row(&nav, 1), "Probe file refused at stage V") == 0);
    card_len = 64;

    /* Restore fails: the region is kept and the failure shown. */
    result_row(&nav, 0);
    exec_protect_fail_at = exec_protect_calls + 3;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_RESTORE && r->load.probe.allocation);
    CHECK(strcmp(result_row(&nav, 1), "Probe cleanup failed; restart required") == 0);
    struct nlr_probe_state kept = r->load.probe;
    uint32_t opens = program_opens, reads = manifest_opens, calls = probe_call_count;
    uint32_t protects = exec_protect_calls;

    /* Another run is refused before anything is checked or queued, and the
     * record of the failed attempt stays as it was. */
    CHECK(strcmp(result_row(&nav, 0), "Probe cleanup failed; restart required") == 0);
    CHECK(r->load.state == 0 && !r->load.probe_mode);
    CHECK(program_opens == opens && manifest_opens == reads);
    CHECK(probe_call_count == calls && exec_protect_calls == protects);
    CHECK(memcmp(&kept, &r->load.probe, sizeof kept) == 0);

    /* Checking another program replaces last_result; the probe's details
     * still show the kept failure once its operation is chosen again. */
    nav.code = 0x285;
    nav.next = 0x68d;
    nlr_page_back_action(&nav);
    nlr_page_enter(window);
    nav.code = 0x286;
    CHECK(strcmp(result_row(&nav, 1), "Back to list") == 0);
    CHECK(r->load.last_result == NLR_OK);
    nav.code = 0x285;
    nlr_page_back_action(&nav);
    nlr_page_enter(window);
    nav.code = 0x286;
    CHECK(strcmp(result_row(&nav, 0), "Back to list") == 0);
    CHECK(strcmp(result_row(&nav, 0), "Probe cleanup failed; restart required") == 0);
    CHECK(probe_call_count == calls && memcmp(&kept, &r->load.probe, sizeof kept) == 0);

    /* Even a request that was already queued keeps the record intact. */
    r->load.probe_mode = mode;
    r->load.state = 1;
    opens = program_opens;
    reads = manifest_opens;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_RESTORE && r->load.state == 0);
    CHECK(program_opens == opens && manifest_opens == reads && probe_call_count == calls);
    CHECK(memcmp(&kept, &r->load.probe, sizeof kept) == 0);
}
#endif

/* ENABLED is independent of list order and compatibility: selection records
 * IDs, while the boot flow rechecks compatibility before each execution. */
static void enabled_parse_matrix(void)
{
    struct nlr_manifest m;
    static const char directory[] =
        "one | resource_extension | One | APPS/ONE.NLB | 2\n"
        "app | foreground | App | APPS/APP.NLB | 2\n"
        "two | resource_extension | Two | APPS/TWO.NLB | 99\n";
    CHECK(nlr_manifest_parse(&m, (const uint8_t *)directory,
                             sizeof directory - 1) == NLR_OK);
    static const struct {
        const char *text;
        uint32_t error, line, count;
    } cases[] = {
        {"", NLR_EN_OK, 0, 0},
        {"\n\r\n", NLR_EN_OK, 0, 0},
        {"two\none\n", NLR_EN_OK, 0, 2},
        {"TWO\r\nONE", NLR_EN_OK, 0, 2},
        {"one\n\n", NLR_EN_OK, 0, 1},
        {"one\nONE", NLR_EN_DUPLICATE, 2, 0},
        {"app", NLR_EN_KIND, 1, 0},
        {"missing", NLR_EN_UNKNOWN, 1, 0},
        {"one\ntwo\napp", NLR_EN_KIND, 3, 0},
        {" one", NLR_EN_ID, 1, 0},
        {"one ", NLR_EN_ID, 1, 0},
        {"one\ttwo", NLR_EN_ID, 1, 0},
        {"one\r", NLR_EN_ID, 1, 0},
        {"# comment", NLR_EN_ID, 1, 0},
        {"\xef\xbb\xbfone", NLR_EN_ID, 1, 0},
        {"\xe4\xb8\xad", NLR_EN_ID, 1, 0},
        {"012345678901234567890123456789012", NLR_EN_ID, 1, 0},
    };
    for (uint32_t n = 0; n < sizeof cases / sizeof cases[0]; n++) {
        struct nlr_enabled e = {0};
        int result = nlr_enabled_parse(&e, &m, (const uint8_t *)cases[n].text,
                                       (uint32_t)strlen(cases[n].text));
        CHECK(result == (cases[n].error ? NLR_FORMAT : NLR_OK));
        CHECK(e.error == cases[n].error && e.error_line == cases[n].line);
        CHECK(e.count == cases[n].count);
        if (e.count == 2) {
            CHECK(e.index[0] == 2 && e.index[1] == 0);
            CHECK(strcmp(e.id[0], "two") == 0 && strcmp(e.id[1], "one") == 0);
        }
    }
    struct nlr_enabled e;
    const uint8_t nul[] = {'o', 'n', 'e', 0, '\n'};
    CHECK(nlr_enabled_parse(&e, &m, nul, sizeof nul) == NLR_FORMAT);
    CHECK(e.error == NLR_EN_ID && !e.count);
    CHECK(nlr_enabled_parse(&e, &m, nul, NLR_ENABLED_BYTES + 1) == NLR_BOUNDS);
    CHECK(e.error == NLR_EN_SIZE);
}

static void enabled_bounds_and_roundtrip(void)
{
    char directory[8192], text[NLR_ENABLED_BYTES];
    uint32_t used = 0, selected = 0;
    for (uint32_t n = 0; n < NLR_MANIFEST_MAX_ENTRIES; n++) {
        used += (uint32_t)snprintf(directory + used, sizeof directory - used,
            "id%02u | resource_extension | E | APPS/E.NLB | 2\n", n);
        selected += (uint32_t)snprintf(text + selected, sizeof text - selected,
                                       "id%02u\n", 63u - n);
    }
    struct nlr_manifest m;
    struct nlr_enabled e, parsed;
    CHECK(nlr_manifest_parse(&m, (const uint8_t *)directory, used) == NLR_OK);
    CHECK(nlr_enabled_parse(&e, &m, (const uint8_t *)text, selected) == NLR_OK);
    CHECK(e.count == 64 && e.index[0] == 63 && e.index[63] == 0);
    uint8_t output[NLR_ENABLED_BYTES];
    uint32_t bytes = 99;
    memset(output, 0xa5, sizeof output);
    CHECK(nlr_enabled_encode(&e, &m, output, selected - 1, &bytes) == NLR_BOUNDS);
    CHECK(bytes == 0 && output[0] == 0xa5);
    CHECK(nlr_enabled_encode(&e, &m, output, selected, &bytes) == NLR_OK);
    CHECK(bytes == selected && memcmp(output, text, selected) == 0);
    CHECK(nlr_enabled_parse(&parsed, &m, output, bytes) == NLR_OK);
    CHECK(parsed.count == e.count);
    for (uint32_t n = 0; n < e.count; n++)
        CHECK(strcmp(parsed.id[n], e.id[n]) == 0);
    strcpy(e.id[1], e.id[0]);
    CHECK(nlr_enabled_encode(&e, &m, output, sizeof output, &bytes) == NLR_FORMAT);
    e.count = 65;
    CHECK(nlr_enabled_encode(&e, &m, output, sizeof output, &bytes) == NLR_BOUNDS);
    e.count = 0;
    CHECK(nlr_enabled_encode(&e, &m, 0, 0, &bytes) == NLR_OK && !bytes);
    static const char longest[] = "abcdefghijklmnopqrstuvwxyz012345";
    used = (uint32_t)snprintf(directory, sizeof directory,
        "%s | resource_extension | E | APPS/E.NLB | 2\n", longest);
    CHECK(nlr_manifest_parse(&m, (const uint8_t *)directory, used) == NLR_OK);
    CHECK(nlr_enabled_parse(&e, &m, (const uint8_t *)longest, 32) == NLR_OK);
    CHECK(nlr_enabled_encode(&e, &m, output, 33, &bytes) == NLR_OK);
    CHECK(bytes == 33 && memcmp(output, longest, 32) == 0 && output[32] == '\n');
}

static uint8_t enabled_disk[NLR_ENABLED_BYTES];
static uint32_t enabled_disk_bytes, enabled_write_calls;
static int enabled_write_failure, enabled_commit_then_fail;

static int32_t enabled_replace(const char *path, const uint8_t *data,
                                uint32_t bytes)
{
    CHECK(strcmp(path, NLR_ENABLED_PATH) == 0);
    enabled_write_calls++;
    if (!enabled_write_failure || enabled_commit_then_fail) {
        memcpy(enabled_disk, data, bytes);
        enabled_disk_bytes = bytes;
    }
    return enabled_write_failure ? NLR_IO : NLR_OK;
}

static void enabled_save_acknowledgement(void)
{
    static const char text[] =
        "one | resource_extension | One | APPS/E.NLB | 2\n"
        "two | resource_extension | Two | APPS/E.NLB | 2\n"
        "app | foreground | App | APPS/A.NLB | 2\n";
    struct nlr_manifest m;
    struct nlr_enabled saved = {0}, desired = {0};
    struct nlr_card_store store = {.replace = enabled_replace};
    uint8_t buffer[NLR_ENABLED_BYTES];
    CHECK(nlr_manifest_parse(&m, (const uint8_t *)text, sizeof text - 1) == NLR_OK);
    CHECK(nlr_enabled_parse(&desired, &m, (const uint8_t *)"one", 3) == NLR_OK);
    enabled_write_failure = enabled_commit_then_fail = 0;
    enabled_write_calls = 0;
    CHECK(nlr_enabled_save(&saved, &desired, &m, &store, buffer,
                           sizeof buffer) == NLR_OK);
    CHECK(saved.count == 1 && strcmp(saved.id[0], "one") == 0);
    CHECK(enabled_disk_bytes == 4 && memcmp(enabled_disk, "one\n", 4) == 0);
    CHECK(nlr_enabled_parse(&desired, &m, (const uint8_t *)"two\none", 7) == NLR_OK);
    for (uint32_t committed = 0; committed <= 1; committed++) {
        enabled_write_failure = 1;
        enabled_commit_then_fail = (int)committed;
        CHECK(nlr_enabled_save(&saved, &desired, &m, &store, buffer,
                               sizeof buffer) == NLR_IO);
        CHECK(saved.count == 1 && strcmp(saved.id[0], "one") == 0);
        CHECK(enabled_disk_bytes == (committed ? 8u : 4u));
    }
    enabled_write_failure = enabled_commit_then_fail = 0;
    CHECK(nlr_enabled_save(&saved, &desired, &m, &store, buffer,
                           sizeof buffer) == NLR_OK);
    CHECK(saved.count == 2 && strcmp(saved.id[0], "two") == 0);
    /* Refreshing MANIFEST cannot redirect the saved indices to other IDs. */
    static const char reordered[] =
        "app | foreground | App | APPS/A.NLB | 2\n"
        "two | resource_extension | Two | APPS/E.NLB | 2\n"
        "one | resource_extension | One | APPS/E.NLB | 2\n";
    CHECK(nlr_manifest_parse(&m, (const uint8_t *)reordered,
                             sizeof reordered - 1) == NLR_OK);
    CHECK(nlr_enabled_save(&saved, &saved, &m, &store, buffer,
                           sizeof buffer) == NLR_OK);
    CHECK(enabled_disk_bytes == 8 && memcmp(enabled_disk, "two\none\n", 8) == 0);
    uint32_t calls = enabled_write_calls;
    strcpy(desired.id[0], "app");
    CHECK(nlr_enabled_save(&saved, &desired, &m, &store, buffer,
                           sizeof buffer) == NLR_FORMAT);
    CHECK(enabled_write_calls == calls && strcmp(saved.id[0], "two") == 0);
    CHECK(nlr_enabled_save(&saved, &saved, &m, 0, buffer,
                           sizeof buffer) == NLR_NOT_READY);
}

#if defined(NLR_STAGE_LOAD_ONLY) || defined(NLR_STAGE_PREPARE_ONLY) || \
    defined(NLR_STAGE_EXEC)
static void page_consumes_menu_registration_only_when_idle(void)
{
    for (uint32_t failure = 0; failure <= 1; failure++) {
        static _Alignas(8) uint8_t window[0x60];
        reset_mocks();
        page_publish_calls = 0;
        page_publish_result = failure ? NLR_IO : NLR_OK;
        set_manifest("ext | resource_extension | Extension | APPS/E.NLB | 2\n");
        nlr_page_enter(window);
        struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
        CHECK(r != 0);
        if (!r)
            return;
        CHECK(!r->autoload.store && r->autoload.phase == NLR_AUTOLOAD_NEW);
        r->resident[0].used = 1;
        r->resident[0].kind = NLR_KIND_RESOURCE_EXTENSION;
        memcpy(r->resident[0].id, "ext", 4);
        r->menu_registration[0].item =
            (struct nlr_menu_test_item){0x379u, 0x7ffdu};
        memcpy(r->menu_registration[0].owner, "ext", 4);
        r->menu_registration[0].state = NLR_MENU_REG_PENDING;
        r->load.state = 1;
        nlr_page_enter(window);
        CHECK(!page_publish_calls);
        CHECK(r->menu_registration[0].state == NLR_MENU_REG_PENDING);
        r->load.state = 0;
        nlr_page_enter(window);
        CHECK(page_publish_calls == 1);
        CHECK(r->menu_registration[0].state ==
              (failure ? NLR_MENU_REG_UNCERTAIN : NLR_MENU_REG_PUBLISHED));
        CHECK(r->resident[0].uncertain == failure);
        nlr_page_enter(window);
        CHECK(page_publish_calls == 1); /* no duplicate/retry */
        CHECK(!r->autoload.store && r->autoload.phase == NLR_AUTOLOAD_NEW);
    }
}

static void incompatible_resource_rows_prioritize_the_gate_marker(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    reset_mocks();
    set_manifest("blocked | resource_extension | Blocked | APPS/B.NLB | 10\n"
                 "ready | resource_extension | Ready | APPS/R.NLB | 2\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    const struct nlr_card_store store = {0};
    r->autoload.store = &store;
    r->autoload.phase = NLR_AUTOLOAD_DONE;
    r->resident[0].used = r->resident[1].used = 1;
    r->resident[0].kind = r->resident[1].kind = NLR_KIND_RESOURCE_EXTENSION;
    memcpy(r->resident[0].id, "blocked", 8);
    memcpy(r->resident[1].id, "ready", 6);
    r->resident[0].failed = 1;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(r->directory.entries[0].gate == NLR_GATE_ABI);
    CHECK(r->directory.entries[1].gate == NLR_GATE_OK);
    CHECK(strcmp(slot_text[own_row_slots[0]], "Blocked: blocked") == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Ready: loaded") == 0);
    CHECK(!program_opens && !r->load.state && !r->load.program.entry_started);
    CHECK(r->resident[0].failed && r->resident[1].used);
}

static int recovery_pending, recovery_remove_failure;
static uint32_t recovery_remove_calls;

static int32_t recovery_probe(const char *path, uint32_t *present)
{
    /* The lifecycle also asks whether ENABLED is there at all: a card
     * without one has nothing to load, which is not a read failure. */
    CHECK(strcmp(path, NLR_SAFE_MODE_PATH) == 0 ||
          strcmp(path, NLR_AUTOLOAD_PENDING_PATH) == 0 ||
          strcmp(path, NLR_ENABLED_PATH) == 0);
    if (strcmp(path, NLR_SAFE_MODE_PATH) == 0)
        *present = (uint32_t)safe_mode_present;
    else if (strcmp(path, NLR_ENABLED_PATH) == 0)
        *present = card_enabled_data != 0;
    else
        *present = (uint32_t)recovery_pending;
    return NLR_OK;
}

static int32_t recovery_remove(const char *path)
{
    CHECK(strcmp(path, NLR_AUTOLOAD_PENDING_PATH) == 0);
    recovery_remove_calls++;
    if (recovery_remove_failure)
        return NLR_IO;
    recovery_pending = 0;
    return NLR_OK;
}

static const struct nlr_card_store recovery_store = {
    .probe = recovery_probe, .replace = enabled_replace, .remove = recovery_remove,
};

static void page_select_action(struct nlr_menu_nav *nav, uint32_t row)
{
    *(uint16_t *)((uint8_t *)nav->window + 0x32) = (uint16_t)row;
    nlr_page_row_action(nav);
    nlr_page_enter(nav->window);
}

#ifdef NLR_STAGE_EXEC
#define RESOURCE_TEXT(exec_text, legacy_text) exec_text
#else
#define RESOURCE_TEXT(exec_text, legacy_text) legacy_text
#endif

static void page_explicit_recovery_and_extension_statuses(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("one | resource_extension | One | APPS/E.NLB | 2\n"
                 "two | resource_extension | Two | APPS/E.NLB | 2\n"
                 "three | resource_extension | Three | APPS/E.NLB | 2\n");
    memcpy(enabled_disk, "two\none\nthree\n", 14);
    enabled_disk_bytes = card_enabled_bytes = 14;
    card_enabled_data = enabled_disk;
    enabled_write_failure = enabled_commit_then_fail = 0;
    enabled_write_calls = 0;
    recovery_pending = 1;
    recovery_remove_failure = 0;
    recovery_remove_calls = 0;
    page_publish_calls = 0;
    page_publish_result = NLR_OK;
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    r->autoload.store = &recovery_store;
    nlr_page_enter(window);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED && r->recovery_view);
    CHECK(r->saved_enabled.count == 3 && r->autoload.enabled_result == NLR_OK);
#ifdef NLR_STAGE_EXEC
    for (uint32_t row = 0; row < 3; row++) CHECK(strlen(slot_text[own_row_slots[row]]) <= 32);
#endif
    CHECK(strcmp(slot_text[own_row_slots[0]],
                 RESOURCE_TEXT("Recover after reboot", "Recover autoload for next effective reboot")) == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]],
                 RESOURCE_TEXT("Paused: check enabled list", "Autoload paused; correct enabled list first")) == 0);
    nlr_page_enter(window);
    CHECK(recovery_pending && !recovery_remove_calls && !r->load.state);
    recovery_remove_failure = 1;
    page_select_action(&nav, 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Recovery failed; still paused") == 0);
    CHECK(recovery_pending && !r->autoload.recovery_armed && recovery_remove_calls == 1);
    nlr_page_enter(window);
    CHECK(recovery_remove_calls == 1); /* entering is not another user action */
    recovery_remove_failure = 0;
    safe_mode_present = 1;
    page_select_action(&nav, 0);
    CHECK(strcmp(slot_text[own_row_slots[1]],
                 RESOURCE_TEXT("Paused: SAFE_MODE", "Recovery blocked: SAFE_MODE; still paused")) == 0);
    CHECK(recovery_pending && recovery_remove_calls == 1);
    safe_mode_present = 0;
    r->resident[0].used = 1;
    r->resident[0].kind = NLR_KIND_RESOURCE_EXTENSION;
    memcpy(r->resident[0].id, "two", 4);
    r->resident[1].used = r->resident[1].failed = 1;
    r->resident[1].kind = NLR_KIND_RESOURCE_EXTENSION;
    memcpy(r->resident[1].id, "one", 4);
    r->resident[1].uncertain = 1;
    page_select_action(&nav, 0);
    CHECK(strcmp(slot_text[own_row_slots[1]],
                 RESOURCE_TEXT("State uncertain; reboot required", "State uncertain; effective reboot required")) == 0);
    CHECK(recovery_pending && recovery_remove_calls == 1);
    r->resident[1].uncertain = 0;
    r->load.state = 1;
    page_select_action(&nav, 0);
    CHECK(strcmp(slot_text[own_row_slots[1]],
                 RESOURCE_TEXT("Paused: work pending", "Recovery blocked: work pending; still paused")) == 0);
    CHECK(recovery_pending && recovery_remove_calls == 1);
    r->load.state = 0;
    /* Back leaves recovery but does not leave the native NLoader page. */
    page_select_action(&nav, 2);
    CHECK(!r->recovery_view && !r->detail_view);
    CHECK(strcmp(slot_text[own_row_slots[0]], RESOURCE_TEXT("One: failed", "One: failed; possibly partial")) == 0);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Two: loaded") == 0);
    CHECK(strcmp(slot_text[own_row_slots[2]], RESOURCE_TEXT("Three: not run", "Three: not executed")) == 0);
    r->autoload.item[0] = NLR_EXTENSION_INITIALIZING;
    r->load.state = 1;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(slot_text[own_row_slots[1]],
                 RESOURCE_TEXT("Two: init", "Two: initializing; publication pending")) == 0);
    r->load.state = 0;
    r->autoload.item[0] = NLR_EXTENSION_LOADED;
    page_select_action(&nav, 0); /* extension settings, never its init */
    CHECK(r->detail_view && !r->load.state);
#ifdef NLR_STAGE_EXEC
    for (uint32_t row = 0; row < 7; row++) CHECK(strlen(slot_text[own_row_slots[row]]) <= 32);
#endif
    CHECK(strcmp(slot_text[own_row_slots[1]], RESOURCE_TEXT("Now: failed; may be active", "Current: failed; possibly partial")) == 0);
    CHECK(strcmp(slot_text[own_row_slots[2]], "Next reboot: enabled, order 2") == 0);
    page_select_action(&nav, 0); /* remove only the next-boot enabled entry */
    CHECK(strcmp(slot_text[own_row_slots[2]], "Next reboot: disabled") == 0);
    CHECK(enabled_disk_bytes == 10 && memcmp(enabled_disk, "two\nthree\n", 10) == 0);
    CHECK(r->autoload.enabled.count == 3 && r->resident[1].used && r->resident[1].failed);
    enabled_write_failure = 1;
    page_select_action(&nav, 0);
    CHECK(strcmp(slot_text[own_row_slots[2]],
                 RESOURCE_TEXT("Save failed; not confirmed", "Save failed; reboot settings not confirmed")) == 0);
    CHECK(enabled_disk_bytes == 10 && r->saved_enabled.count == 2);
    enabled_write_failure = 0;
    page_select_action(&nav, 0);
    CHECK(strcmp(slot_text[own_row_slots[2]], "Next reboot: enabled, order 3") == 0);
    page_select_action(&nav, 3);
    CHECK(strcmp(slot_text[own_row_slots[2]], "Next reboot: enabled, order 2") == 0);
    page_select_action(&nav, 4);
    CHECK(strcmp(slot_text[own_row_slots[2]], "Next reboot: enabled, order 3") == 0);
    uint32_t saved_bytes = enabled_disk_bytes;
    uint8_t saved[NLR_ENABLED_BYTES];
    memcpy(saved, enabled_disk, saved_bytes);
    page_select_action(&nav, 5); /* opens explicit recovery; does not clear */
    CHECK(r->recovery_view && recovery_pending && recovery_remove_calls == 1);
    page_select_action(&nav, 0);
    CHECK(!recovery_pending && r->autoload.recovery_armed && recovery_remove_calls == 2);
#ifdef NLR_STAGE_EXEC
    CHECK(strcmp(slot_text[own_row_slots[0]], "Recovery set for next reboot") == 0);
#endif
    CHECK(strcmp(slot_text[own_row_slots[1]],
                 RESOURCE_TEXT("Still paused; reboot required", "Recovery armed; effective reboot required")) == 0);
    CHECK(enabled_disk_bytes == saved_bytes && memcmp(enabled_disk, saved, saved_bytes) == 0);
    CHECK(r->resident[0].used && r->resident[1].used && r->resident[1].failed);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED && !r->load.state);
    nlr_page_enter(window);
    CHECK(recovery_remove_calls == 2 && !r->load.state && !page_publish_calls);
    CHECK(nlr_runtime_autoload_begin(r, &recovery_store) == NLR_AUTOLOAD_PAUSED);
    CHECK(nlr_runtime_autoload_step(r) == NLR_AUTOLOAD_PAUSED && !r->load.state);
}

#ifdef NLR_STAGE_EXEC
static void resource_list_markers_keep_full_names_and_detail_warnings(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    const struct nlr_card_store store = {0};
    reset_mocks();
    set_manifest("wide | resource_extension | WWWWWWWWWWWWWWWWWWWWWWWW | APPS/E.NLB | 2\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    r->autoload.store = &store;
    r->autoload.phase = NLR_AUTOLOAD_DONE;
    r->autoload.enabled.count = 1;
    r->autoload.enabled.index[0] = 0;
    memcpy(r->autoload.enabled.id[0], "wide", 5);
    const uint32_t statuses[] = {NLR_EXTENSION_LOADED, NLR_EXTENSION_PARTIAL,
                                NLR_EXTENSION_INITIALIZING, NLR_EXTENSION_NOT_EXECUTED};
    const char *const suffixes[] = {": loaded", ": failed", ": init", ": not run"};
    for (uint32_t n = 0; n < 4; n++) {
        r->autoload.item[0] = (uint8_t)statuses[n];
        r->load.state = 1; /* page refresh must not start another file request */
        r->show_check = 1;
        nlr_page_enter(window);
        const char *label = slot_text[own_row_slots[0]];
        CHECK(strncmp(label, "WWWWWWWWWWWWWWWWWWWWWWWW", 24) == 0);
        CHECK(strcmp(label + 24, suffixes[n]) == 0);
        CHECK(strlen(suffixes[n]) <= 9 && strlen(label) == 24 + strlen(suffixes[n]));
        CHECK(r->autoload.item[0] == statuses[n] && r->autoload.phase == NLR_AUTOLOAD_DONE);
        CHECK(!program_opens && !r->load.program.entry_started && !r->load.probe.entry_started);
    }
    r->load.state = 0;
    r->autoload.item[0] = NLR_EXTENSION_PARTIAL;
    r->checked = 0;
    r->detail_view = r->show_check = 1;
    nlr_page_enter(window);
    CHECK(r->detail_view);
    CHECK(strcmp(slot_text[own_row_slots[1]], "Now: failed; may be active") == 0);
    CHECK(!program_opens && !r->load.state);
}
#endif
#endif

static void native_list_declarations_fail_closed(void)
{
    struct nlr_menu_page page = nlr_menu_page;
    CHECK(nlr_menu_native_list_capacity(&page) == 64u);
    page.page_count = 0;
    CHECK(nlr_menu_native_list_capacity(&page) == 0);
    page = nlr_menu_page;
    page.stay_next = 0;
    CHECK(nlr_menu_native_list_capacity(&page) == 0);
    page = nlr_menu_page;
    page.row_slots = 0;
    CHECK(nlr_menu_native_list_capacity(&page) == 0);
    page = nlr_menu_page;
    page.widget_find = 0;
    CHECK(nlr_menu_native_list_capacity(&page) == 0);
    page = nlr_menu_page;
    page.row_count = 65;
    CHECK(nlr_menu_native_list_capacity(&page) == 0);
    CHECK(nlr_menu_native_list_capacity(0) == 0);
}

#if defined(NLR_STAGE_LOAD_ONLY) || defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
static void original_redraw_prepares_current_view_rows(void)
{
    reset_mocks();
    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);
    if (!r) return;
    r->directory_result = NLR_OK;
    r->directory.count = 11;
    r->detail_view = 0;
    r->page_max = mock_page_count = 3;
    nlr_page_prepare_redraw(r);
    CHECK(mock_page_count == 11 && r->page_max == 11);
    r->directory.count = 2;
    nlr_page_prepare_redraw(r);
    CHECK(mock_page_count == 11 && r->page_max == 11); /* no shorter re-entry */
    nlr_page_prepare_redraw(0);
    CHECK(mock_page_count == 11);
}
#endif

/* A model whose profile names neither the create flags nor the cache
 * entry that writes back: every write access is refused instead of being
 * opened for reading and silently dropping what the program writes, and
 * the loader keeps no state of its own on such a card -- so nothing is
 * ever loaded by itself there. */
static void write_access_refused_without_the_services(void)
{
    CHECK(nlr_api.fs_open("APPS/NOTE.TXT", NLR_OPEN_WRITE) == -NLR_API_ENOSYS);
    CHECK(nlr_api.fs_open("APPS/NOTE.TXT", NLR_OPEN_UPDATE) == -NLR_API_ENOSYS);
    CHECK(nlr_api.fs_open("APPS/NOTE.TXT", 7) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_write(0, "x", 1) == -NLR_API_ENOSYS);
    CHECK(nlr_api.fs_write(-1, "x", 1) == -NLR_API_EBADF);
    CHECK(nlr_file_store() == 0);
}

#if defined(NLR_STAGE_EXEC) && defined(NLR_TEST_PAGES)
/* ---- the loader's own pages ---------------------- */

static const char *row_label(uint32_t row)
{
    return slot_text[own_row_slots[row]];
}

static void open_with(uint8_t *window, void (*open)(struct nlr_menu_nav *))
{
    struct nlr_menu_nav nav = {window, 0x2b3, 0x65a};
    open(&nav);
    CHECK(nav.next == 0x65a); /* the record opens the page */
    nlr_page_enter(window);
}

static void back_from(uint8_t *window, uint32_t *next)
{
    struct nlr_menu_nav nav = {window, 0x2b2, 0x713};
    nlr_page_back_action(&nav);
    *next = nav.next;
    nlr_page_enter(window);
}

/* Apps opens the applications; NLoader its root; OK pushes, back pops to
 * the row the cursor was on, back from the first page leaves to Setup. */
static void loader_pages_stack(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    uint32_t next;
    reset_mocks();
    *(void **)(window + OWN_WIDGET_TABLE) = &mock_table_object;
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n"
                 "ext | resource_extension | Ext | APPS/EXT.NLB | 2 | z8/3.11\n"
                 "old | foreground | Old | APPS/OLD.NLB | 99\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    r->pages.visited = 0;

    open_with(window, nlr_page_open_apps_action);
    CHECK(r->pages.depth == 1 && r->pages.shown && r->list_view && r->list.rows_view);
    CHECK(r->pages.visited == 1);
    CHECK(r->list.count == 2);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "Apps") == 0);
    CHECK(strcmp(row_label(0), "Hello") == 0 && r->list.kinds[0] == NLR_ROW_ENTRY);
    /* not for this loader: greyed, with why, and the cursor not on it */
    CHECK(strcmp(row_label(1), "Old") == 0 && r->list.kinds[1] == NLR_ROW_SELECT &&
          (r->list.row_flags[1] & NLR_ROW_GREYED));
    /* the list keeps the short status; the details the whole reason */
    CHECK(strcmp(r->list.values[1], "newer ABI") == 0);
    CHECK(disabled_rows[1] && !disabled_rows[0]);
    /* a greyed row with a value opens nothing: its > mark goes */
    CHECK(!(record_word(r->items.records, 1, NLR_MENU_ITEM_FLAGS) & NLR_MENU_ITEM_MARK));
    CHECK(record_word(r->items.records, 0, NLR_MENU_ITEM_FLAGS) & NLR_MENU_ITEM_MARK);
    CHECK(*(uint16_t *)(window + 0x32) == 0);
    back_from(window, &next);
    CHECK(next == 0x713 && r->pages.depth == 0 && !r->pages.shown && !r->list_view);

    open_with(window, nlr_page_open_action);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], OWN_TITLE_TEXT) == 0);
    CHECK(r->list.count == 3);
    CHECK(strcmp(row_label(0), "NLoader") == 0 && r->list.kinds[0] == NLR_ROW_SWITCH &&
          (r->list.row_flags[0] & NLR_ROW_ON));
    CHECK(strcmp(row_label(1), "Plugin settings") == 0);
    CHECK(strcmp(row_label(2), "About") == 0);
    CHECK(switch_states[0] == 2); /* the toggle drawn ON */

    /* The switch: off in RAM at once; this card store cannot write it, so
     * the page says it lasts until power off. Stays on the same page. */
    page_select_action(&nav, 0);
    CHECK(nav.next == OWN_ACTION_NEXT);
    CHECK(r->pages.master == 2 && !(r->list.row_flags[0] & NLR_ROW_ON));
    CHECK(r->pages.master_saved == NLR_NOT_READY);
    CHECK(strcmp(row_label(1), "Not saved: lasts until power off") == 0);
    CHECK(r->list.kinds[1] == NLR_ROW_TEXT && disabled_rows[1]);

    /* Plugin settings: every program, with its state */
    page_select_action(&nav, 2);
    CHECK(r->pages.depth == 2 && r->list.count == 3);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "Plugin settings") == 0);
    CHECK(strcmp(row_label(0), "Hello") == 0 && strcmp(r->list.values[0], "app") == 0);
    CHECK(strcmp(row_label(1), "Ext") == 0 && strcmp(r->list.values[1], "off") == 0);
    CHECK(r->list.row_flags[2] & NLR_ROW_GREYED);

    /* a plugin's page: its switch, its state, its details */
    page_select_action(&nav, 1);
    CHECK(r->pages.depth == 3);
    CHECK(strcmp(slot_text[OWN_TITLE_SLOT], "Ext") == 0);
    CHECK(strcmp(row_label(0), "Enabled") == 0 && r->list.kinds[0] == NLR_ROW_SWITCH &&
          !(r->list.row_flags[0] & NLR_ROW_ON));
    CHECK(strcmp(row_label(1), "Now: not executed") == 0);
    CHECK(strcmp(row_label(r->list.count - 1u), "Details") == 0);
    page_select_action(&nav, r->list.count - 1u);
    CHECK(r->pages.depth == 4);
    CHECK(strcmp(row_label(0), "Extension") == 0);
    CHECK(strcmp(row_label(1), "File: APPS/EXT.NLB") == 0);
    CHECK(strcmp(row_label(2), "Needs NLoader ABI 2") == 0);
    CHECK(strcmp(row_label(3), "For: z8/3.11") == 0);

    /* back: one page at a time, the cursor where it was */
    back_from(window, &next);
    CHECK(next == OWN_ACTION_NEXT && r->pages.depth == 3);
    CHECK(*(uint16_t *)(window + 0x32) == r->list.count - 1u);
    back_from(window, &next);
    CHECK(r->pages.depth == 2 && *(uint16_t *)(window + 0x32) == 1);
    back_from(window, &next);
    CHECK(r->pages.depth == 1 && *(uint16_t *)(window + 0x32) == 2);

    /* About */
    page_select_action(&nav, 3);
    CHECK(r->pages.depth == 2);
    CHECK(strcmp(row_label(0), "NLoader 9.9.9, program ABI 9") == 0);
    CHECK(strcmp(row_label(1), "Camera: z8 3.11") == 0);
    CHECK(strcmp(row_label(2), "Firmware module 736ceaac") == 0);
    back_from(window, &next);
    back_from(window, &next);
    CHECK(next == 0x713 && r->pages.depth == 0);

    /* A new opening starts a new stack; the switch keeps its RAM state. */
    open_with(window, nlr_page_open_action);
    CHECK(r->pages.depth == 1 && !(r->list.row_flags[0] & NLR_ROW_ON));
    r->pages.master = 0;
    r->pages.master_changed = 0;
}

/* The switch read from the card, and the boot program's switch. */
static void loader_pages_card_files(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    card_boot_id = "HELLO\n";
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return;
    r->pages.master = 0;
    r->pages.boot_known = 0;
    open_with(window, nlr_page_open_action);
    CHECK(r->list.row_flags[0] & NLR_ROW_ON);
    page_select_action(&nav, 1); /* Plugin settings */
    CHECK(strcmp(r->list.values[0], "at boot") == 0);
    page_select_action(&nav, 0);
    CHECK(strcmp(row_label(0), "Start at boot") == 0 && (r->list.row_flags[0] & NLR_ROW_ON));
    /* turning it off asks the store, which cannot write here: not saved */
    page_select_action(&nav, 0);
    CHECK(r->pages.boot_saved == NLR_NOT_READY && (r->list.row_flags[0] & NLR_ROW_ON));
    CHECK(strcmp(row_label(1), "Not saved") == 0);

    /* A card switched off: nothing is read beyond the switch, and the
     * pages say so. */
    card_master = "off";
    r->pages.master = 0;
    r->pages.master_changed = 0;
    r->pages.depth = 0;
    r->show_check = 0;
    open_with(window, nlr_page_open_apps_action);
    CHECK(r->directory_result == NLR_DISABLED &&
          r->directory.error == NLR_MF_SWITCHED_OFF);
    CHECK(strcmp(row_label(0), "NLoader is off") == 0);
    open_with(window, nlr_page_open_action);
    CHECK(!(r->list.row_flags[0] & NLR_ROW_ON));
    CHECK(strcmp(row_label(1), "Off: nothing was loaded") == 0);
    card_master = "on";
    r->pages.master = 0;
    r->show_check = 0;
    open_with(window, nlr_page_open_action);
    CHECK(r->list.row_flags[0] & NLR_ROW_ON);
    CHECK(r->directory_result == NLR_OK);
}

/* A program opened from Apps shows its own list and ends -- here refused
 * where the executor asks the heap for its blocks. Back on Apps the window
 * is rebuilt for the Apps rows, not for the whole directory (Z8 QEMU
 * sp-003/sp-004: two extensions padded the list with two empty rows), and
 * the row says why in one word; the details keep the whole reason. The
 * plugin list keeps one word per program as well. */
static void loader_pages_return_after_program(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    uint32_t next;
    reset_mocks();
    *(void **)(window + OWN_WIDGET_TABLE) = &mock_table_object;
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n"
                 "ext | resource_extension | Ext | APPS/EXT.NLB | 2 | z8/3.11\n"
                 "ext2 | resource_extension | Ext2 | APPS/EXT2.NLB | 2 | z8/3.11\n"
                 "two | foreground | Two | APPS/TWO.NLB | 2 | z8/3.11\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    open_with(window, nlr_page_open_apps_action);
    CHECK(r->list.count == 2 && mock_page_count == 2);

    /* The program's list was up (as after GO_APP), and the run has ended:
     * refused at phase A, the heap having no whole block for it. */
    r->checked = 0;
    r->program_pending = 1;
    r->probe_pending = 0;
    r->pages.shown = 0;
    r->list_view = 1;
    r->load.last_result = NLR_NOT_READY;
    r->load.program.phase = 'A';
    r->load.data_bytes = r->load.bss_bytes = 0;
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    uint32_t rebuilds = rebuild_calls;
    back_from(window, &next);
    CHECK(next == OWN_ACTION_NEXT && rebuild_calls == rebuilds + 1u);
    CHECK(r->pages.depth == 1 && r->pages.shown && r->list_view);
    CHECK(r->list.count == 2 && mock_page_count == 2 && r->page_max == 2);
    CHECK(strcmp(row_label(0), "Hello") == 0 && r->list.kinds[0] == NLR_ROW_SELECT);
    CHECK(strcmp(r->list.values[0], "memory") == 0);
    CHECK(strcmp(row_label(1), "Two") == 0 && r->list.kinds[1] == NLR_ROW_ENTRY);

    /* A clean return says nothing; a stop, an exit code and the budget one
     * short word each. A run in progress says nothing either: the row is
     * not drawn again when it ends. */
    r->load.last_result = NLR_OK;
    r->load.program.phase = 'R';
    r->load.program.returned = 1;
    r->load.program.exit_code = 0;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(r->list.kinds[0] == NLR_ROW_ENTRY);
    r->load.program.exit_requested = 1;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(r->list.values[0], "ended") == 0);
    r->load.program.exit_requested = 0;
    r->load.program.exit_code = 3;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(r->list.values[0], "exit 3") == 0);
    r->load.program.exit_code = 42; /* two digits would reach the > mark */
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(r->list.values[0], "exit") == 0);
    r->load.last_result = NLR_EXEC_BUDGET;
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(strcmp(r->list.values[0], "limit") == 0);
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(r->list.kinds[0] == NLR_ROW_ENTRY);
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);

    r->load.program.exit_code = 0;
    r->load.program.returned = 0;

    /* The plugin list: one word per program. */
    back_from(window, &next);
    CHECK(next == 0x713 && r->pages.depth == 0);
    open_with(window, nlr_page_open_action);
    page_select_action(&nav, 1); /* Plugin settings */
    CHECK(strcmp(r->list.values[0], "app") == 0 && strcmp(r->list.values[1], "off") == 0 &&
          strcmp(r->list.values[2], "off") == 0);
    r->program_pending = 0;
}

/* The last outcome of each program is kept by id for the boot: once the
 * pages read the directory again (Apps opened anew) or another program is
 * checked, the Apps row keeps its word and the program's Details the full
 * reason, which the list's word alone cannot say. A later clean return of
 * the same id replaces it. */
static void loader_pages_keep_outcome_per_id(void)
{
    _Alignas(8) uint8_t window[0x60] = {0};
    struct nlr_menu_nav nav = {window, 0x286, 0x68d};
    uint32_t next;
    reset_mocks();
    *(void **)(window + OWN_WIDGET_TABLE) = &mock_table_object;
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n"
                 "two | foreground | Two | APPS/TWO.NLB | 2 | z8/3.11\n");
    nlr_page_enter(window);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0);
    if (!r)
        return;
    open_with(window, nlr_page_open_apps_action);
    CHECK(r->list.count == 2);

#ifdef NLR_TEST_PAGE_REBUILD
    /* A program that held the screen gives it back before its end is
     * recorded: the page drawn then has no word for its row. Once the end
     * is published the page is rebuilt in place (the stock rebuild, then
     * present), and the row says it (graphics_runtime.c outcome_redraw). */
    r->checked = 0;
    memcpy(r->program_id, "hello", 6);
    r->program_pending = 1;
    r->load.last_result = NLR_NOT_READY;
    r->load.program.phase = 'A';
    r->load.data_bytes = r->load.bss_bytes = 0;
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    r->show_check = 1;
    nlr_page_enter(window);
    CHECK(r->list.kinds[0] == NLR_ROW_ENTRY);
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    *(uint16_t *)window = 0x1d6;
    *(uint16_t *)(window + NLR_MENU_WINDOW_ID) = 0x5d6;
    uint32_t rebuilds = rebuild_calls, presents = present_calls;
    CHECK(nlr_page_rebuild_outcome(r, window) == NLR_OK);
    CHECK(rebuild_calls == rebuilds + 1u && present_calls == presents + 1u);
    CHECK(rebuild_type == 0x1d6 && rebuild_id == 0x5d6);
    CHECK(r->show_check && r->page_max == 2);
    nlr_page_enter(window); /* the firmware enters it inside the rebuild */
    CHECK(r->list.kinds[0] == NLR_ROW_SELECT && strcmp(r->list.values[0], "memory") == 0);
    CHECK(nlr_page_rebuild_outcome(0, window) == NLR_NOT_READY);
    /* The menu's task waits for a program's first list only while the
     * program does not read the controls itself. */
    CHECK(!nlr_page_program_reads_input(r) && !nlr_page_program_reads_input(0));
    __atomic_store_n(&r->plat.active, 1u, __ATOMIC_RELEASE);
    CHECK(nlr_page_program_reads_input(r));
    __atomic_store_n(&r->plat.active, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->input_owner, 7u, __ATOMIC_RELEASE);
    CHECK(nlr_page_program_reads_input(r));
    __atomic_store_n(&r->input_owner, 0u, __ATOMIC_RELEASE);
    CHECK(nlr_page_rebuild_outcome(r, 0) == NLR_NOT_READY);
    *(uint16_t *)window = 0;
    *(uint16_t *)(window + NLR_MENU_WINDOW_ID) = 0;
#endif

    /* Hello's run ended refused at phase A: the heap had no whole block. */
    r->checked = 0;
    memcpy(r->program_id, "hello", 6);
    r->program_pending = 1;
    r->probe_pending = 0;
    r->pages.shown = 0;
    r->list_view = 1;
    r->load.last_result = NLR_NOT_READY;
    r->load.program.phase = 'A';
    r->load.data_bytes = r->load.bss_bytes = 0;
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    back_from(window, &next);
    CHECK(strcmp(r->list.values[0], "memory") == 0);
    CHECK(!nlr_runtime_outcome_find(r, (const uint8_t *)"hello", 5));

    /* Apps opened anew reads the directory again: the live result is gone,
     * the kept one stays (ids compare as the directory does, any case). */
    back_from(window, &next);
    CHECK(r->pages.depth == 0);
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    CHECK(!r->program_pending);
    const struct nlr_outcome *kept = nlr_runtime_outcome_find(r, (const uint8_t *)"HELLO", 5);
    CHECK(kept && kept->result == NLR_NOT_READY && kept->phase == 'A');
    open_with(window, nlr_page_open_apps_action);
    CHECK(strcmp(row_label(0), "Hello") == 0 && r->list.kinds[0] == NLR_ROW_SELECT);
    CHECK(strcmp(r->list.values[0], "memory") == 0);
    CHECK(r->list.kinds[1] == NLR_ROW_ENTRY);

    /* Hello's Details (NLoader -> Plugin settings -> Hello -> Details):
     * the whole reason. */
    back_from(window, &next);
    open_with(window, nlr_page_open_action);
    page_select_action(&nav, 1); /* Plugin settings */
    CHECK(strcmp(row_label(0), "Hello") == 0);
    page_select_action(&nav, 0);
    CHECK(strcmp(row_label(r->list.count - 1u), "Details") == 0);
    page_select_action(&nav, r->list.count - 1u);
    /* Over two rows at a space, each within one line of the row's font
     * (menu_page.c page_text_bytes), not one row the camera wraps over the
     * row above. */
    int found = 0;
    for (uint32_t k = 0; k + 1u < r->list.count; k++)
        if (strcmp(row_label(k), "Not enough camera memory (needs") == 0 &&
            strcmp(row_label(k + 1u), "4 KiB)") == 0 &&
            r->list.kinds[k] == NLR_ROW_TEXT && r->list.kinds[k + 1u] == NLR_ROW_TEXT)
            found = 1;
    CHECK(found);
    for (uint32_t k = 0; k < r->list.count; k++)
        CHECK(strlen(row_label(k)) <= 32u || r->list.kinds[k] != NLR_ROW_TEXT);

    /* Two is checked and run cleanly; Hello keeps its outcome. */
    r->checked = 1;
    memcpy(r->program_id, "two", 4);
    r->program_pending = 1;
    r->load.last_result = NLR_OK;
    r->load.program.phase = 'R';
    r->load.program.returned = 1;
    r->load.program.exit_code = 0;
    nlr_runtime_outcome_keep(r);
    kept = nlr_runtime_outcome_find(r, (const uint8_t *)"hello", 5);
    CHECK(kept && kept->result == NLR_NOT_READY);
    /* a clean return of Hello replaces its refusal: nothing to say */
    r->checked = 0;
    memcpy(r->program_id, "hello", 6);
    nlr_runtime_outcome_keep(r);
    kept = nlr_runtime_outcome_find(r, (const uint8_t *)"hello", 5);
    CHECK(kept && kept->result == NLR_OK && kept->returned && !kept->memory_bytes);
    /* nothing is kept while a run is in flight */
    memcpy(r->program_id, "two", 4);
    r->load.last_result = NLR_EXEC_BUDGET;
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    nlr_runtime_outcome_keep(r);
    kept = nlr_runtime_outcome_find(r, (const uint8_t *)"two", 3);
    CHECK(kept && kept->result == NLR_OK);
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    r->program_pending = 0;
    r->load.program.returned = 0;
}

/* At a boot switched off, before anyone opened the menu, the Apps row is
 * left out of Setup: the record starts one item and one pointer later and
 * counts one row fewer, once, and only on the build's own arrays. */
static void loader_pages_hide_apps(void)
{
    uint64_t pointers = 0x9000;
    reset_mocks();
    struct card_spec spec = valid_spec(16);
    build_card(&spec);
    set_manifest("hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n");
    struct nlr_runtime *r = nlr_runtime_attach(&nlr_services, ARENA_CAP, 0);
    CHECK(r != 0);
    if (!r)
        return;
    memset(mock_setup_record, 0, sizeof mock_setup_record);
    *(uint64_t *)(mock_setup_record + 0x10) = (uint64_t)(uintptr_t)mock_setup_items;
    *(uint64_t *)(mock_setup_record + 0x18) = pointers;
    *(uint16_t *)(mock_setup_record + 0x20) = 52;
    r->pages.visited = 1;
    r->pages.apps_hidden = 0;
    card_master = "off";
    nlr_runtime_read_directory(r);
    /* opened already this boot: left as it is */
    CHECK(*(uint16_t *)(mock_setup_record + 0x20) == 52);
    r->pages.visited = 0;
    card_master = "on";
    nlr_runtime_read_directory(r);
    CHECK(*(uint16_t *)(mock_setup_record + 0x20) == 52 && !r->pages.apps_hidden);
    card_master = "off";
    /* a menu is up with Setup built: the record and the window's cursor
     * are never changed under it */
    mock_screen = 0x123456788ull;
    *(void **)(mock_setup_window + OWN_WIDGET_TABLE) = &mock_table_object;
    *(uint16_t *)(mock_setup_window + MOCK_CURSOR_OFFSET) = 9;
    nlr_runtime_read_directory(r);
    CHECK(*(uint16_t *)(mock_setup_record + 0x20) == 52 && !r->pages.apps_hidden);
    CHECK(*(uint16_t *)(mock_setup_window + MOCK_CURSOR_OFFSET) == 9);
    /* a menu is up but Setup is not built (the Z 8's boot pass on the menu
     * task, before the menu builds its first page): moved. A cursor the
     * menu already restored there counted the Apps row: NLoader (51,
     * split over cursor and scroll) is now 50. */
    *(void **)(mock_setup_window + OWN_WIDGET_TABLE) = 0;
    *(uint16_t *)(mock_setup_window + MOCK_CURSOR_OFFSET) = 40;
    *(uint16_t *)(mock_setup_window + MOCK_SCROLL_OFFSET) = 11;
    nlr_runtime_read_directory(r);
    CHECK(r->pages.apps_hidden == 1);
    CHECK(*(uint16_t *)(mock_setup_record + 0x20) == 51);
    CHECK(*(uint16_t *)(mock_setup_window + MOCK_CURSOR_OFFSET) == 50 &&
          *(uint16_t *)(mock_setup_window + MOCK_SCROLL_OFFSET) == 0);
    r->pages.apps_hidden = 0;
    *(uint64_t *)(mock_setup_record + 0x10) = (uint64_t)(uintptr_t)mock_setup_items;
    *(uint64_t *)(mock_setup_record + 0x18) = pointers;
    *(uint16_t *)(mock_setup_record + 0x20) = 52;
    /* live view: moved whatever the window says; the Apps row (0) becomes
     * the stock first row */
    *(void **)(mock_setup_window + OWN_WIDGET_TABLE) = &mock_table_object;
    mock_screen = 0x123456780ull;
    *(uint16_t *)(mock_setup_window + MOCK_CURSOR_OFFSET) = 0;
    nlr_runtime_read_directory(r);
    CHECK(r->pages.apps_hidden == 1);
    CHECK(*(uint16_t *)(mock_setup_window + MOCK_CURSOR_OFFSET) == 0);
    *(void **)(mock_setup_window + OWN_WIDGET_TABLE) = 0;
    CHECK(*(uint64_t *)(mock_setup_record + 0x10) ==
          (uint64_t)(uintptr_t)(mock_setup_items + NLR_MENU_ITEM_BYTES));
    CHECK(*(uint64_t *)(mock_setup_record + 0x18) == pointers + 8);
    CHECK(*(uint16_t *)(mock_setup_record + 0x20) == 51);
    nlr_runtime_read_directory(r);
    CHECK(*(uint16_t *)(mock_setup_record + 0x20) == 51);
    /* a record that names other arrays is never moved */
    r->pages.apps_hidden = 0;
    *(uint64_t *)(mock_setup_record + 0x10) = 0x1234;
    *(uint16_t *)(mock_setup_record + 0x20) = 52;
    nlr_runtime_read_directory(r);
    CHECK(*(uint16_t *)(mock_setup_record + 0x20) == 52 && !r->pages.apps_hidden);
    card_master = 0;
    r->pages.master = 0;
}
#endif

/* The Setup cursor: the setting always holds a
 * stock row number. Apps is saved as the stock first row, NLoader as
 * Firmware version, every other row as the stock row it shows; back, the
 * stock first row is the top row and the rest the rows showing them. */
static void set_setup_layout(uint32_t layout)
{
    uint64_t items = (uint64_t)(uintptr_t)mock_setup_items;
    if (layout == NLR_SETUP_APPS_HIDDEN)
        items += NLR_MENU_ITEM_BYTES;
    else if (layout == NLR_SETUP_LAYOUT_UNKNOWN)
        items = 0x1234;
    *(uint64_t *)(mock_setup_record + 0x10) = items;
}
static void set_setup_window(uint32_t cursor, uint32_t scroll)
{
    *(uint16_t *)(mock_setup_window + MOCK_CURSOR_OFFSET) = (uint16_t)cursor;
    *(uint16_t *)(mock_setup_window + MOCK_SCROLL_OFFSET) = (uint16_t)scroll;
}
static void setup_cursor_maps_to_stock_rows(void)
{
    const struct nlr_menu_setup *s = &nlr_menu_setup;
    const uint32_t shown = NLR_SETUP_APPS_SHOWN, hidden = NLR_SETUP_APPS_HIDDEN;
    const uint32_t unknown = NLR_SETUP_LAYOUT_UNKNOWN;
    set_setup_layout(shown);
    CHECK(nlr_setup_layout(s) == shown);
    set_setup_layout(hidden);
    CHECK(nlr_setup_layout(s) == hidden);
    set_setup_layout(unknown);
    CHECK(nlr_setup_layout(s) == unknown);

    /* Apps shown: 0 Apps, 1..50 stock 0..49, 51 NLoader (52 rows). */
    CHECK(nlr_setup_cursor_to_stock(s, shown, 0) == 0);
    CHECK(nlr_setup_cursor_to_stock(s, shown, 1) == 0);
    CHECK(nlr_setup_cursor_to_stock(s, shown, 2) == 1);
    CHECK(nlr_setup_cursor_to_stock(s, shown, 25) == 24);
    CHECK(nlr_setup_cursor_to_stock(s, shown, 49) == 48);
    CHECK(nlr_setup_cursor_to_stock(s, shown, 50) == 49);
    CHECK(nlr_setup_cursor_to_stock(s, shown, 51) == 48);
    /* nothing past the page, and never a number past the stock page */
    CHECK(nlr_setup_cursor_to_stock(s, shown, 52) == 0);
    CHECK(nlr_setup_cursor_to_stock(s, shown, 0xffff) == 0);
    for (uint32_t row = 0; row < 0x20000u; row++)
        CHECK(nlr_setup_cursor_to_stock(s, shown, row) < 50u &&
              nlr_setup_cursor_to_stock(s, hidden, row) < 50u &&
              nlr_setup_cursor_to_stock(s, unknown, row) < 50u);
    CHECK(nlr_setup_cursor_from_stock(s, shown, 0) == 0);
    CHECK(nlr_setup_cursor_from_stock(s, shown, 1) == 2);
    CHECK(nlr_setup_cursor_from_stock(s, shown, 24) == 25);
    CHECK(nlr_setup_cursor_from_stock(s, shown, 48) == 49);
    CHECK(nlr_setup_cursor_from_stock(s, shown, 49) == 50);
    /* a raw 50 or 51 (an unmapped build's NLoader or shifted row) is past
     * the stock page: the top row */
    CHECK(nlr_setup_cursor_from_stock(s, shown, 50) == 0);
    CHECK(nlr_setup_cursor_from_stock(s, shown, 51) == 0);
    /* every row but Apps, the stock first row and NLoader comes back */
    for (uint32_t row = 2; row <= 50; row++)
        CHECK(nlr_setup_cursor_from_stock(s, shown,
                                          nlr_setup_cursor_to_stock(s, shown, row)) == row);

    /* Apps hidden at this boot: 0..49 stock, 50 NLoader (51 rows). */
    CHECK(nlr_setup_cursor_to_stock(s, hidden, 0) == 0);
    CHECK(nlr_setup_cursor_to_stock(s, hidden, 49) == 49);
    CHECK(nlr_setup_cursor_to_stock(s, hidden, 50) == 48);
    CHECK(nlr_setup_cursor_to_stock(s, hidden, 51) == 0);
    for (uint32_t row = 0; row < 50; row++)
        CHECK(nlr_setup_cursor_from_stock(s, hidden, row) == row);
    CHECK(nlr_setup_cursor_from_stock(s, hidden, 50) == 0);

    /* A layout this build did not make: stock numbers only. */
    CHECK(nlr_setup_cursor_to_stock(s, unknown, 49) == 49);
    CHECK(nlr_setup_cursor_to_stock(s, unknown, 50) == 0);
    CHECK(nlr_setup_cursor_from_stock(s, unknown, 7) == 7);
    CHECK(nlr_setup_cursor_from_stock(s, unknown, 51) == 0);

    /* NLoader as the row before Firmware version (entry index 48): 0 Apps,
     * 1..48 stock 0..47, 49 NLoader, 50..51 stock 48..49. */
    struct nlr_menu_setup mid = *s;
    mid.entry_index = 48;
    CHECK(nlr_setup_cursor_to_stock(&mid, shown, 48) == 47);
    CHECK(nlr_setup_cursor_to_stock(&mid, shown, 49) == 48);
    CHECK(nlr_setup_cursor_to_stock(&mid, shown, 50) == 48);
    CHECK(nlr_setup_cursor_to_stock(&mid, shown, 51) == 49);
    CHECK(nlr_setup_cursor_from_stock(&mid, shown, 47) == 48);
    CHECK(nlr_setup_cursor_from_stock(&mid, shown, 48) == 50);
    CHECK(nlr_setup_cursor_from_stock(&mid, shown, 49) == 51);
    CHECK(nlr_setup_cursor_to_stock(&mid, hidden, 48) == 48);
    CHECK(nlr_setup_cursor_to_stock(&mid, hidden, 49) == 48);
    CHECK(nlr_setup_cursor_from_stock(&mid, hidden, 48) == 49);
    struct nlr_menu_setup none = *s;
    none.stock_rows = 0;
    CHECK(nlr_setup_cursor_to_stock(&none, shown, 3) == 0);
    CHECK(nlr_setup_cursor_from_stock(&none, shown, 3) == 0);
    set_setup_layout(shown);
}

/* The redirected calls: the writers store the mapped row, the restore
 * maps it back, and keeps the row the menu closed on while the window
 * still holds it. Other settings pass through. */
static void setup_cursor_save_and_restore(void)
{
    set_setup_layout(NLR_SETUP_APPS_SHOWN);
    mock_cursor_value = 0;
    /* other ids are the stock calls' own */
    CHECK(nlr_setup_cursor_save(0x4903u, 77) == 1);
    CHECK(mock_cursor_other == 77 && mock_cursor_last_id == 0x4903u && mock_cursor_value == 0);
    CHECK(nlr_setup_cursor_restore(0x4903u) == 77);

    /* NLoader (51): saved as Firmware version, restored as NLoader while
     * the window still says 51 */
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 51) == 1);
    CHECK(mock_cursor_value == 48 && mock_cursor_last_id == MOCK_CURSOR_SETTING);
    set_setup_window(51, 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 51);
    /* the same through the cursor/scroll split the save adds up */
    set_setup_window(3, 48);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 51);
    /* a fresh window (power-on): the stock Firmware version row */
    set_setup_window(0, 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 49);
    /* Firmware version itself (49) saves as 48 too and comes back as 49 */
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 49) == 1 && mock_cursor_value == 48);
    set_setup_window(49, 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 49);

    /* Apps (0) and the stock first row (1) both save as 0 */
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 0) == 1 && mock_cursor_value == 0);
    set_setup_window(0, 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 0);
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 1) == 1 && mock_cursor_value == 0);
    set_setup_window(1, 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 1);

    /* a middle row */
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 20) == 1 && mock_cursor_value == 19);
    set_setup_window(7, 13);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 20);
    /* the setting changed meanwhile (the stock lookup writer): mapped */
    mock_cursor_value = 2;
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 3);
    /* a window row past the page never comes back as is */
    set_setup_window(60, 0);
    mock_cursor_value = 0;
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 0);
    /* a raw out-of-range value from elsewhere: the top row */
    set_setup_window(0, 0);
    mock_cursor_value = 51;
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 0);

    /* Apps hidden at this boot: NLoader is row 50 */
    set_setup_layout(NLR_SETUP_APPS_HIDDEN);
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 50) == 1 && mock_cursor_value == 48);
    set_setup_window(50, 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 50);
    set_setup_window(0, 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 48);
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 0) == 1 && mock_cursor_value == 0);
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 0);
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 51) == 1 && mock_cursor_value == 0);

    /* a layout this build did not make: stock numbers only, no window */
    set_setup_layout(NLR_SETUP_LAYOUT_UNKNOWN);
    set_setup_window(51, 0);
    mock_cursor_value = 48;
    CHECK(nlr_setup_cursor_restore(MOCK_CURSOR_SETTING) == 48);
    CHECK(nlr_setup_cursor_save(MOCK_CURSOR_SETTING, 51) == 1 && mock_cursor_value == 0);
    set_setup_layout(NLR_SETUP_APPS_SHOWN);
    set_setup_window(0, 0);
    mock_cursor_value = 0;
}

int main(void)
{
    setup_cursor_maps_to_stock_rows();
    setup_cursor_save_and_restore();
#if defined(NLR_STAGE_EXEC) && defined(NLR_TEST_PAGES)
    loader_pages_hide_apps();
    loader_pages_stack();
    loader_pages_card_files();
    loader_pages_return_after_program();
    loader_pages_keep_outcome_per_id();
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("core behavior tests passed\n");
    return 0;
#endif
#if defined(NLR_STAGE_LOAD_ONLY) || defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    original_redraw_prepares_current_view_rows();
#endif
    native_list_declarations_fail_closed();
    CHECK(page_resources.publish && !page_publish_calls);
    write_access_refused_without_the_services();
    valid_runtime_flow();
    chunked_read_crosses_cache_chunks();
    format_rejections();
    bounds_rejections();
    checksum_and_io_paths();
    safe_mode_disables_loading();
    not_ready_and_busy();
    flag_failure_rewinds_state();
    partial_construction_is_kept();
    registry_ambiguity_and_decoys();
    manifest_accepts_a_well_formed_directory();
    manifest_rejects_every_malformed_line();
    manifest_keeps_discovered_duplicates();
    manifest_gate_reports_each_entry();
    manifest_read_paths();
#if defined(NLR_TEST_NATIVE_PAGE_REFRESH) && defined(NLR_STAGE_LOAD_ONLY)
    native_refresh_keeps_the_menu_context_and_reflows_rows();
#endif
    enabled_parse_matrix();
    enabled_bounds_and_roundtrip();
    enabled_save_acknowledgement();
    runtime_reads_the_directory_and_checks_a_program();
    page_enter_titles_the_page_and_fills_the_row();
    text_slot_protocol_survives_interleaved_writes();
#if defined(NLR_STAGE_LOAD_ONLY) || defined(NLR_STAGE_PREPARE_ONLY) || \
    defined(NLR_STAGE_EXEC)
    page_drains_program_text_into_the_result_row();
    page_consumes_menu_registration_only_when_idle();
    incompatible_resource_rows_prioritize_the_gate_marker();
    page_explicit_recovery_and_extension_statuses();
#ifdef NLR_STAGE_EXEC
    resource_list_markers_keep_full_names_and_detail_warnings();
    program_list_on_the_page();
    late_program_list_is_taken();
    program_rows_on_the_page();
    program_input_on_the_page();
    program_caution_on_the_page();
    program_settings_on_the_page();
#endif
#endif
#if !defined(NLR_STAGE_PREPARE_ONLY) && !defined(NLR_STAGE_EXEC)
    row_action_checks_the_row_program();
#if defined(NLR_STAGE_LOAD_ONLY)
    row_action_uses_the_rows_drawn();
#endif
#endif
#if defined(NLR_STAGE_LOAD_ONLY)
    long_detail_names_preserve_failure_reasons_and_back_cursor();
#endif
    probe_v2_loading_and_kind_rejections();
    runtime_card_buffers_own_whole_lines();
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    queued_probe_execution_rechecks_current_card();
    probe_page_flow_and_kept_cleanup_failure();
    operation_type_survives_worker_header_reinitialization();
#ifdef NLR_STAGE_PREPARE_ONLY
    generic_preparation_result_does_not_report_exit();
#endif
#endif

#if !defined(NLR_STAGE_EXEC)
    CHECK(probe_call_count == 0);
#endif
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("core behavior tests passed\n");
    return 0;
}
