/* Host behavior tests for generic v2 programs (PLAN 6.3 M2-T4): the 64-byte
 * header load path, the two-block execution model with relocations, the
 * api.c service table and the resident-extension ownership record. The mock
 * tables implement the normalized service contract; no firmware, key or
 * device is involved. The exec-stage scenarios are compiled only under
 * NLR_STAGE_PREPARE_ONLY / NLR_STAGE_EXEC, matching where the worker can
 * run programs. */
#include "nlr/api.h"
#include "nlr/runtime.h"
#include "nlr/time.h"

#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include <time.h>

#define TEST_PATH NLR_PROGRAM_ROOT "APPS\\PROG.NLB"
#define NOTE_PATH_REL "APPS/NOTE.TXT"
#define NOTE_PATH_ABS NLR_PROGRAM_ROOT "LOGS\\NOTE.TXT"
#define ARENA_CAP 0x4000u

static int failures;

#define CHECK(cond)                                    \
    do {                                               \
        if (!(cond)) {                                 \
            printf("FAIL %d: %s\n", __LINE__, #cond);  \
            failures++;                                \
        }                                              \
    } while (0)

extern const struct nlr_services nlr_services;
extern const struct nlr_task_config nlr_task_config;
extern const struct nlr_identity nlr_identity;
/* Defined non-const below: budget scenarios change the injected limits. */
extern struct nlr_exec_services nlr_exec_services;
extern const struct nlr_api nlr_api;

/* ---- service mock (loader side) ------------------------------------------ */

static _Alignas(NLR_CACHE_LINE) uint8_t alloc_pool[0x180000];
static size_t alloc_used;
static int alloc_fail_countdown;
static uint32_t alloc_calls, release_calls;
static int loader_release_fail;
static uintptr_t alloc_start[64];
static uint32_t alloc_size[64], alloc_count;
/* A small node at the head of the loader heap's free list, as the stock
 * heap has one after something small was freed: loader_obstacles of them,
 * loader_obstacle_bytes each. A request larger than the node while one is
 * there is the over-wide grant the books exist to prevent. */
static uint32_t loader_obstacles, loader_obstacle_bytes, loader_overasked;

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
    if (loader_obstacles) {
        if (bytes > loader_obstacle_bytes)
            loader_overasked++;
        else
            loader_obstacles--;
    }
    if (alloc_fail_countdown == 0) {
        alloc_fail_countdown = -1;
        *out = 0;
        return -1;
    }
    if (alloc_fail_countdown > 0)
        alloc_fail_countdown--;
    size_t base = ((alloc_used + NLR_CACHE_LINE - 1) &
                   ~(size_t)(NLR_CACHE_LINE - 1)) + 0x20;
    if (base > sizeof alloc_pool || (size_t)bytes > sizeof alloc_pool - base) {
        *out = 0;
        return -1;
    }
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
    (void)ptr;
    release_calls++;
    return loader_release_fail ? -1 : 0;
}

static void *registry_table[NLR_REGISTRY_IDS + 1];

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
    fill_worker(worker, 5, callback);
    registry_table[5] = worker;
    config->assigned_id = 5;
}

static void mock_worker_start(void *worker)
{
    (void)worker;
}

/* Native stop mocks never invoke or unwind the entry. Tests explicitly
 * deliver the reactivated wrapper's event after abandoning its old frames. */
#define EXIT_BANK 1u
#define EXIT_MASK 6u
static void (*input_callback)(void *);
static uint32_t forwarded_input[12];
#ifdef NLR_STAGE_EXEC
static uint32_t input_calls, alternate_input_calls;
#endif
static char stop_events[16];
static uint32_t stop_event_count, stop_release_base;
static int stop_fail, stop_suspended, stop_dead, call_busy;
static int release_during_api;
static jmp_buf busy_context;

static void stop_record(char event, void *worker)
{
    CHECK(worker == registry_table[5]);
    CHECK(nlr_le32(((struct nlr_worker *)worker)->opaque) == 5);
    CHECK(release_calls == stop_release_base);
    if (stop_event_count < sizeof stop_events - 1)
        stop_events[stop_event_count++] = event;
    stop_events[stop_event_count] = 0;
}

static int32_t mock_suspend(void *worker)
{
    stop_record('S', worker);
    if (stop_fail == 1)
        return -1;
    CHECK(!stop_suspended && !stop_dead);
    stop_suspended = 1;
    return 0;
}

static int32_t mock_resume(void *worker)
{
    stop_record('R', worker);
    CHECK(stop_suspended && !stop_dead);
    if (stop_fail == 2)
        return -1;
    stop_suspended = 0;
    return 0;
}

static int32_t mock_terminate(void *worker)
{
    stop_record('T', worker);
    CHECK(stop_suspended && !stop_dead);
    CHECK(!((struct nlr_runtime *)worker)->load.program.api_active);
    if (stop_fail == 3)
        return -1;
    stop_dead = 1;
    return 0;
}

static int32_t mock_restart(void *worker)
{
    stop_record('A', worker);
    CHECK(stop_suspended && stop_dead);
    CHECK(((struct nlr_runtime *)worker)->load.state == 3);
    if (stop_fail == 4)
        return -1;
    stop_dead = stop_suspended = 0;
    return 0;
}

static void original_input(void *combined)
{
#ifdef NLR_STAGE_EXEC
    input_calls++;
#endif
    if (combined)
        memcpy(forwarded_input, combined, sizeof forwarded_input);
}

#ifdef NLR_STAGE_EXEC
static void alternate_input(void *combined)
{
    alternate_input_calls++;
    original_input(combined);
}
#endif

static struct nlr_exit_services exit_services = {
    .bank = EXIT_BANK, .mask = EXIT_MASK,
    .suspend = mock_suspend, .resume = mock_resume,
    .terminate = mock_terminate, .restart = mock_restart,
};

static void send_input(uint32_t current, uint32_t previous,
                        uint32_t changed, uint32_t pressed, uint32_t released)
{
    uint32_t combined[17] = {0x11, 0x22, 0x80, 0, 0x80, 0x80, 0,
                            current, previous, changed, pressed, released,
                            0x10, 0, 0x10, 0x10, 0};
    uint32_t saved[17];
    memcpy(saved, combined, sizeof saved);
    CHECK(input_callback != 0);
    if (input_callback)
        input_callback(combined);
    CHECK(memcmp(combined, saved, sizeof saved) == 0);
    CHECK(memcmp(forwarded_input, saved, 7u * sizeof(uint32_t)) == 0);
}

static int flag_set_fail;
static int32_t mock_flag_set(void *flag, uint32_t mask)
{
    (void)flag; (void)mask;
    if (mask == NLR_LOAD_STOP_EVENT) {
        struct nlr_runtime *r = registry_table[5];
        stop_record('F', r);
        CHECK(!stop_dead && !stop_suspended && r->load.state == 3);
    }
    return flag_set_fail ? -1 : 0;
}

/* ---- card mock ------------------------------------------------------------ */

static uint8_t card[0x100000];
static uint32_t card_len;
static uint8_t card2[0x100000];
static uint32_t card2_len;
static const char *card2_path;
static uint8_t card_manifest[0x4000];
static uint32_t card_manifest_len;
static int card_manifest_present;
/* The api channel's own file, set per scenario. */
static const char *api_file_path;
static uint8_t api_file[0x20];
static uint32_t api_file_len;


static int safe_mode_present, safe_mode_after_program_open;
static uint8_t card_enabled[NLR_ENABLED_BYTES];
static uint32_t card_enabled_len;
static int card_enabled_present, pending_present;
static int probe_fail_at, probe_invalid, probe_calls;
/* The ENABLED probe answers "there" although its read fails: an unreadable
 * file, not a missing one. */
static int probe_enabled_anyway;
static int marker_write_fail, marker_commit_then_fail, marker_remove_fail;
static int settings_write_fail;
static uint32_t marker_writes, marker_removes, settings_writes;
/* NLOADER/BOOT and NLOADER/BOOTRUN (runtime.c boot_program). */
static char card_boot[32], card_bootrun[16];
static uint32_t card_boot_len, card_bootrun_len, bootrun_writes, boot_opens;
static int card_master_off; /* NLOADER/MASTER reads "off" */
static uint32_t master_opens;
static char card_operations[128];
static uint32_t card_operation_count;

static void card_operation(char code)
{
    if (card_operation_count < sizeof card_operations - 1)
        card_operations[card_operation_count++] = code;
    card_operations[card_operation_count] = 0;
}

/* MANIFEST, which only the boot checkpoint asks the store about: a card
 * still mounting cannot answer for it (manifest_ready = 0). */
static int manifest_ready = 1;
static uint32_t manifest_asks;

static int probe_busy; /* the store's one request held elsewhere */
static int32_t store_probe(const char *path, uint32_t *present)
{
    if (probe_busy && strcmp(path, NLR_MANIFEST_PATH) != 0)
        return NLR_BUSY;
    if (strcmp(path, NLR_MANIFEST_PATH) == 0) {
        card_operation('M');
        manifest_asks++;
        if (!manifest_ready)
            return NLR_IO;
        *present = 1;
        return NLR_OK;
    }
    int safe = strcmp(path, NLR_SAFE_MODE_PATH) == 0;
    int enabled = strcmp(path, NLR_ENABLED_PATH) == 0;
    /* ENABLED is only probed when its read failed: the answer separates a
     * card that names nothing from one that cannot be read. */
    card_operation(safe ? 'S' : enabled ? 'L' : 'P');
    if (++probe_calls == probe_fail_at)
        return NLR_IO;
    *present = probe_invalid ? 2u
               : (uint32_t)(safe ? safe_mode_present
                            : enabled ? (card_enabled_present ||
                                         probe_enabled_anyway)
                                      : pending_present);
    return NLR_OK;
}

static int32_t store_replace(const char *path, const uint8_t *data,
                              uint32_t bytes)
{
    if (strcmp(path, NLR_AUTOLOAD_PENDING_PATH) == 0) {
        card_operation('W');
        marker_writes++;
        CHECK(bytes == 0 && data == 0);
        if (!marker_write_fail || marker_commit_then_fail)
            pending_present = 1;
        return marker_write_fail ? NLR_IO : NLR_OK;
    }
    if (strcmp(path, NLR_CARD_ROOT "BOOTRUN") == 0) {
        card_operation('B');
        bootrun_writes++;
        CHECK(bytes < sizeof card_bootrun);
        memcpy(card_bootrun, data, bytes);
        card_bootrun_len = bytes;
        return NLR_OK;
    }
    CHECK(strcmp(path, NLR_ENABLED_PATH) == 0);
    settings_writes++;
    if (settings_write_fail)
        return NLR_IO;
    if (bytes)
        memcpy(card_enabled, data, bytes);
    card_enabled_len = bytes;
    card_enabled_present = 1;
    return NLR_OK;
}

static int32_t store_remove(const char *path)
{
    CHECK(strcmp(path, NLR_AUTOLOAD_PENDING_PATH) == 0);
    card_operation('D');
    marker_removes++;
    if (marker_remove_fail)
        return NLR_IO;
    pending_present = 0;
    return NLR_OK;
}

static const struct nlr_card_store card_store = {
    .probe = store_probe, .replace = store_replace, .remove = store_remove,
};
static int open_fail, seek_fail, close_fail, fail_next_read;
static int stop_on_api_read;
static uint32_t manifest_opens, program_opens;
static char last_open_path[NLR_PATH_BYTES];
static uint32_t read_max = 0x1000;

static struct mock_fd {
    int used;
    uint32_t position;
    const uint8_t *data;
    uint32_t len;
} fds[8];

/* A second task asking to carry the pass while this one is inside a step:
 * the menu task entering the page just as the worker starts an extension.
 * The mock's file operations run inside that step, so this stands in for
 * an interleaving a single-threaded host cannot otherwise produce. */
static int reenter_continue;
static uint32_t reenter_calls;

static uint32_t appledouble_opens;

static int32_t mock_open(const char *path, uint32_t flags, uint32_t mode)
{
    (void)flags;
    (void)mode;
    if (strstr(path, "\\._"))
        appledouble_opens++;
    if (open_fail)
        return -1;
    if (reenter_continue && strcmp(path, NLR_MANIFEST_PATH) == 0) {
        reenter_calls++;
        nlr_runtime_autoload_continue(nlr_runtime_find(&nlr_services, 0));
    }
    if (strcmp(path, NLR_SAFE_MODE_PATH) == 0) {
        if (!safe_mode_present)
            return -1;
    }
    const uint8_t *data = card;
    uint32_t len = card_len;
    if (strcmp(path, NLR_MANIFEST_PATH) == 0) {
        card_operation('M');
        manifest_opens++;
        if (!card_manifest_present)
            return -1;
        data = card_manifest;
        len = card_manifest_len;
    } else if (strcmp(path, NLR_ENABLED_PATH) == 0) {
        card_operation('E');
        if (!card_enabled_present)
            return -1;
        data = card_enabled;
        len = card_enabled_len;
    } else if (strcmp(path, NLR_CARD_ROOT "BOOT") == 0) {
        boot_opens++;
        if (!card_boot_len)
            return -1;
        data = (const uint8_t *)card_boot;
        len = card_boot_len;
    } else if (strcmp(path, NLR_MASTER_PATH) == 0) {
        /* the NLoader switch: absent (on) unless a scenario turns it off */
        master_opens++;
        if (!card_master_off)
            return -1;
        data = (const uint8_t *)"off";
        len = 3;
    } else if (strcmp(path, NLR_CARD_ROOT "BOOTRUN") == 0) {
        boot_opens++;
        if (!card_bootrun_len)
            return -1;
        data = (const uint8_t *)card_bootrun;
        len = card_bootrun_len;
    } else if (strcmp(path, NLR_SAFE_MODE_PATH) != 0) {
        snprintf(last_open_path, sizeof last_open_path, "%s", path);
        if (card2_path && strcmp(path, card2_path) == 0) {
            data = card2;
            len = card2_len;
        } else if (api_file_path && strcmp(path, api_file_path) == 0) {
            data = api_file;
            len = api_file_len;
        } else {
            program_opens++;
            /* SAFE_MODE put on the card while the program is read */
            if (safe_mode_after_program_open)
                safe_mode_present = 1;
        }
    }
    for (unsigned n = 0; n < sizeof fds / sizeof fds[0]; n++) {
        if (!fds[n].used) {
            fds[n].used = 1;
            fds[n].position = 0;
            fds[n].data = data;
            fds[n].len = len;
            return (int32_t)n;
        }
    }
    return -1;
}

static int32_t mock_read(int32_t fd, void *buf, uint32_t bytes,
                         uint32_t *out_read)
{
    if (fd < 0 || fd >= (int32_t)(sizeof fds / sizeof fds[0]))
        return -1;
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
    if (stop_on_api_read && f->data == api_file) {
        struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
        CHECK(r && r->load.program.api_active == 1 && r->load.state == 2);
        CHECK(r && r->load.program.code_allocation &&
              r->load.program.api_allocation[0]);
        if (exit_services.input_callback) {
            stop_release_base = release_calls;
            send_input(EXIT_MASK | 0x80u, 0x80u, EXIT_MASK, EXIT_MASK, 0);
            CHECK(strcmp(stop_events, "SR") == 0);
            CHECK(!r->load.program.returned && r->load.program.api_active == 1);
            if (release_during_api) {
                send_input(4, EXIT_MASK, 2, 0, 2);
                CHECK(forwarded_input[11] == 2 && !forwarded_input[10]);
                CHECK(r->exit_notify && r->exit_swallow);
                CHECK(r->load.program.api_active == 1 &&
                      r->load.program.code_allocation);
                CHECK(release_calls == stop_release_base && !r->load.program.returned);
            }
            if (stop_fail == 2)
                longjmp(busy_context, 1); /* simulated suspended service */
        } else {
            __atomic_store_n(&r->load.program.stop_requested, 1u, __ATOMIC_RELEASE);
        }
    }
    return 0;
}

static int32_t mock_seek(int32_t fd, int32_t whence, uint32_t offset,
                         uint32_t *out_position)
{
    if (fd < 0 || fd >= (int32_t)(sizeof fds / sizeof fds[0]))
        return -1;
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

static int32_t mock_close(int32_t fd)
{
    if (fd < 0 || fd >= (int32_t)(sizeof fds / sizeof fds[0]))
        return -1;
    fds[fd].used = 0;
    return close_fail ? -1 : 0;
}

/* The model's write services (ABI 4). What a program writes lands in
 * written[], and the path it was opened with is in last_open_path. */
static uint8_t written[64];
static uint32_t written_len, write_calls, clean_before_write;
static int write_fail;

static int32_t mock_file_write(int32_t fd, const void *buf, uint32_t bytes,
                               uint32_t *out_written)
{
    if (fd < 0 || fd >= (int32_t)(sizeof fds / sizeof fds[0]) ||
        !fds[fd].used || write_fail)
        return -1;
    write_calls++;
    /* The bytes have to be out of the data cache before the card reads
     * them: the clean comes first, always. */
    CHECK(clean_before_write == write_calls);
    if (bytes > sizeof written - written_len)
        return -1;
    memcpy(written + written_len, buf, bytes);
    written_len += bytes;
    *out_written = bytes;
    return 0;
}

static void mock_cache_clean(void *addr, uint32_t len)
{
    (void)addr;
    (void)len;
    clean_before_write = write_calls + 1u;
}

/* Filled in by reset_code_channel() below; the table needs its address. */
static struct nlr_code_services mock_code_services;
static void reset_code_channel(void);
/* A program's entry asking for a hook into the firmware, with its handler
 * in its own image: what an extension does on purpose, and what a
 * foreground program may do and forget to undo. */
static int call_installs_hook;
static int call_breaks_unhook;
static int hook_install_result;
/* The input task's scan object and the services that describe it: u32[5]
 * banks of current, previous, changed, pressed and released. The escape
 * the autoload lifecycle reads is the first word of bank 0. */
static struct nlr_program_services mock_program_services;
static uint32_t mock_scan_object[16];
/* The platform table, empty (nothing declared) unless a test fills it: the
 * boot escape reads the scan object a body declares here (services.
 * platform.scan) when its scan callback is the exit service's. */
static struct nlr_platform_services mock_platform_services;
static struct nlr_platform_scan mock_platform_scan;

#if defined(NLR_STAGE_EXEC)
static void hold_keys(uint32_t mask)
{
    mock_scan_object[2] = mask;
    mock_program_services.input_object = mock_scan_object;
    mock_program_services.banks = 1;
    mock_program_services.bank_base = 8;
    mock_program_services.bank_stride = 20;
    /* NLR_KEY_DISP is bit 9 of the loader's own key word. */
    mock_program_services.keys[9].bank = 0;
    mock_program_services.keys[9].mask = 0x40u;
}
#endif

static uint32_t cache_before_calls, cache_after_calls;

static void mock_cache_before(void *addr, uint32_t len)
{
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = (start + len + NLR_CACHE_LINE - 1) &
                    ~(uintptr_t)(NLR_CACHE_LINE - 1);
    CHECK(start % NLR_CACHE_LINE == 0);
    if (start >= (uintptr_t)alloc_pool &&
        start < (uintptr_t)alloc_pool + sizeof alloc_pool)
        CHECK(inside_allocation(start, end));
    cache_before_calls++;
}

static void mock_cache_after(void *addr, uint32_t len)
{
    (void)addr;
    (void)len;
    cache_after_calls++;
}

static uint32_t resource_publish_calls;
static int resource_publish_result, resource_menu_context;
static struct nlr_menu_test_item published_item;

static int32_t mock_resource_publish(void *context,
                                     const struct nlr_menu_test_item *item)
{
    (void)context;
    CHECK(resource_menu_context);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r && r->load.state == 0);
    resource_publish_calls++;
    published_item = *item;
    return resource_publish_result;
}

static struct nlr_resource_services resource_services = {
    .publish = mock_resource_publish,
};

/* The model's time service. The clock is the host's monotonic clock, as
 * the counter was; the delay fails, so a program's wait fails as it did
 * with no time service at all -- except under `fake_time`, where the clock
 * is fake_now and each delay moves it on (and calls delay_hook). */
static int fake_time;
static uint64_t fake_now;
static void (*delay_hook)(void);
static int32_t mock_clock(uint64_t *out)
{
    if (fake_time) {
        *out = fake_now;
        return NLR_OK;
    }
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    *out = (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
    return NLR_OK;
}
static int32_t mock_delay(uint32_t ms)
{
    if (!fake_time)
        return NLR_NOT_READY;
    fake_now += ms;
    if (delay_hook)
        delay_hook();
    return NLR_OK;
}
static const struct nlr_time_services mock_time = {mock_clock, mock_delay};

const struct nlr_services nlr_services = {
    .abi = 1,
    .time = &mock_time,
    .alloc = mock_alloc,
    .release = mock_release,
    .worker_init = mock_worker_init,
    .worker_start = mock_worker_start,
    .flag_set = mock_flag_set,
    .file_open = mock_open,
    .file_read = mock_read,
    .file_seek = mock_seek,
    .file_close = mock_close,
    .file_write = mock_file_write,
    .file_open_rw = 2,
    .file_open_write = 0x301,
    .file_create_attributes = 0x20,
    .cache_before_read = mock_cache_before,
    .cache_after_read = mock_cache_after,
    .cache_clean = mock_cache_clean,
    .registry_lookup = mock_registry,
    .resources = &resource_services,
    .exit = &exit_services,
    .program = &mock_program_services,
    .code = &mock_code_services,
    .platform = &mock_platform_services,
};

const struct nlr_task_config nlr_task_config = {
    .core = 3,
    .priority = 20,
    .stack_bytes = 0x8000,
    .name = {'N', 'L', 'O', 'A', 'D', 'E', 'R', 0},
};

const struct nlr_identity nlr_identity = { "z8", "3.11" };

/* The loader's pages are not linked here (core/menu_page.c). */
void nlr_pages_directory_read(struct nlr_runtime *r)
{
    (void)r;
}

/* ---- fixture program ------------------------------------------------------ */

/* The fixture image carries a real ADRP instruction at IMAGE_ADRP_OFFSET
 * with a link-time page difference, plus filler; the relocations and the
 * data segment are what a run must produce. */
#define IMAGE_ADRP_OFFSET 8u
#define IMAGE_LEN 32u
#define DATA_LEN 16u
#define RELOC_MAX 4u

static uint8_t image_fixture[IMAGE_LEN];
static uint8_t data_fixture[DATA_LEN];
static uint32_t reloc_fixture[RELOC_MAX][3]; /* offset, target, kind */
static uint32_t reloc_count;
static uint32_t fixture_image_len = IMAGE_LEN;
static uint32_t fixture_data_len = DATA_LEN;
static uint32_t fixture_bss = 8u;
static uint32_t fixture_entry = 16u;
static uint32_t fixture_abi = 2u;
static uint32_t fixture_flags; /* header flags, 0 for a valid program */
static int fixture_stamp_adrp = 1; /* stamp the default ADRP into the image */
static uint32_t fixture_kind = 2u;

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

static void put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void reset_fixture(void)
{
    for (uint32_t n = 0; n < IMAGE_LEN; n++)
        image_fixture[n] = (uint8_t)(n * 7 + 3);
    for (uint32_t n = 0; n < DATA_LEN; n++)
        data_fixture[n] = (uint8_t)(n * 11 + 5);
    reloc_count = 2;
    /* kind 0 at the ADRP, kind 1 writing a self-pointer into the data. */
    reloc_fixture[0][0] = IMAGE_ADRP_OFFSET;
    reloc_fixture[0][1] = 4u;
    reloc_fixture[0][2] = NLR_RELOC_ADRP;
    reloc_fixture[1][0] = 0u;
    reloc_fixture[1][1] = 12u;
    reloc_fixture[1][2] = NLR_RELOC_ABS64;
    fixture_image_len = IMAGE_LEN;
    fixture_data_len = DATA_LEN;
    fixture_bss = 8u;
    fixture_entry = 16u;
    fixture_abi = 2u;
    fixture_flags = 0;
    fixture_kind = 2u;
    fixture_stamp_adrp = 1;
}

/* One default ADRP instruction encoding with a link-time page difference of
 * 5 pages, so the patched word is provably different from the original. */
static uint32_t adrp_instruction(void)
{
    return 0x90000000u | ((5u & 3u) << 29) | ((5u >> 2) << 5);
}

static void build_program_file_into(uint8_t *target, uint32_t *out_len)
{
    memset(target, 0, 0x9000);
    memcpy(target, "NPLD", 4);
    target[4] = 2; /* header_version */
    target[6] = 64;
    target[7] = 0;
    put32(target + 8, fixture_flags);
    put32(target + 0xc, fixture_image_len);
    put32(target + 0x10, fixture_bss);
    put32(target + 0x14, fixture_entry);
    put32(target + 0x18, fixture_abi);
    put32(target + 0x20, fixture_kind);
    uint32_t reloc_bytes = reloc_count * NLR_RELOC_ENTRY_SIZE;
    put32(target + 0x24, reloc_bytes);
    uint8_t *reloc = target + 64;
    for (uint32_t n = 0; n < reloc_count; n++) {
        put32(reloc + n * 12, reloc_fixture[n][0]);
        put32(reloc + n * 12 + 4, reloc_fixture[n][1]);
        put32(reloc + n * 12 + 8, reloc_fixture[n][2]);
    }
    uint8_t *image = target + 64 + reloc_bytes;
    for (uint32_t n = 0; n < fixture_image_len; n++)
        image[n] = n < IMAGE_LEN ? image_fixture[n] : (uint8_t)(n * 7 + 3);
    if (fixture_stamp_adrp)
        put32(image + IMAGE_ADRP_OFFSET, adrp_instruction());
    uint8_t *data = image + fixture_image_len;
    for (uint32_t n = 0; n < fixture_data_len; n++)
        data[n] = n < DATA_LEN ? data_fixture[n] : (uint8_t)(n * 11 + 5);
    *out_len = 64u + reloc_bytes + fixture_image_len + fixture_data_len;
    put32(target + 0x1c, test_crc32(image, fixture_image_len));
    put32(target + 0x30,
          fixture_data_len ? test_crc32(data, fixture_data_len) : 0);
    put32(target + 0x34, reloc_bytes ? test_crc32(reloc, reloc_bytes) : 0);
}

static void build_program_file(void)
{
    build_program_file_into(card, &card_len);
}

static void set_manifest(const char *text)
{
    uint32_t length = (uint32_t)strlen(text);
    CHECK(length <= sizeof card_manifest);
    memcpy(card_manifest, text, length);
    card_manifest_len = length;
    card_manifest_present = 1;
}

/* ---- execution mock (two blocks) ------------------------------------------ */

/* Synthetic permission encodings, as in the other tests: the core only has
 * to tell the two semantics apart. */
#define MOCK_FLAG_W 0x21u
#define MOCK_FLAG_X 0x34u

static _Alignas(NLR_CACHE_LINE) uint8_t exec_pool[18u << 20];
static size_t exec_used;
static int exec_alloc_fail;
static int exec_release_fail;
/* Per-block permission state; fresh blocks audit as writable. */
static uint8_t *block_pages[8];
static uint32_t block_flags[8];
static uint32_t block_count;
static uint32_t exec_releases;
static void *exec_allocations[8];
static uint32_t exec_allocation_sizes[8];
static uint32_t exec_allocation_released[8];
static uint32_t exec_allocation_count, exec_live_bytes, exec_byte_budget;
static uint32_t exec_allocation_attempts, exec_alloc_fail_at;
static uint32_t exec_alignment_padding[2], exec_alignment_padding_count;
static uint32_t clean_calls, clean_fail_at, audit_calls, audit_fail_at;
static uint32_t block_cleaned[8];
static uint32_t region_bytes = NLR_EXEC_BLOCK_SIZE;

static char events[80];
static unsigned event_count;

static void record(char event)
{
    if (event_count < sizeof events - 1)
        events[event_count++] = event;
    events[event_count] = 0;
}

/* How many of the allocations the model's allocator grants short, and how
 * much it really hands over then: the Z 6III allocator is a stack manager
 * that takes the first node of its free list even when that node is
 * smaller, so the loader has to read its books instead of trusting it.
 * exec_grant_blind makes those books say nothing, which is as good as a
 * short grant: the region cannot be believed. */
static uint32_t exec_short_grants;
static uint32_t exec_short_bytes;
static uint32_t exec_grant_blind;
/* Book mode: blocks are handed out one after another from exec_used, with
 * no guard, exactly where the books (exec_grant_next) say. */
static uint32_t exec_books;
/* The heap changed between the question and the request: however many
 * blocks this says, the probe answers in full and the block really handed
 * over is short anyway, with the allocator's mapping already applied past
 * it. Counted down as they are met. */
static uint32_t exec_grant_race;
static uint32_t grant_calls;
static uint32_t probe_calls_count;

static void reset_exec_pool(void)
{
    exec_used = 0;
    block_count = 0;
    exec_releases = 0;
    exec_allocation_count = exec_live_bytes = 0;
    exec_allocation_attempts = exec_alloc_fail_at = 0;
    exec_alignment_padding_count = 0;
    exec_byte_budget = sizeof exec_pool;
    clean_calls = clean_fail_at = audit_calls = audit_fail_at = 0;
    exec_short_grants = exec_grant_blind = grant_calls = 0;
    exec_grant_race = 0;
    probe_calls_count = 0;
    exec_short_bytes = 0x4000;
    memset(exec_allocation_released, 0, sizeof exec_allocation_released);
    memset(block_cleaned, 0, sizeof block_cleaned);
    event_count = 0;
    events[0] = 0;
    memset(exec_pool, 0xa5, sizeof exec_pool);
}

static int exec_block_index(void *page)
{
    for (uint32_t i = 0; i < block_count; i++)
        if (block_pages[i] == (uint8_t *)page)
            return (int)i;
    return -1;
}

static uint8_t *aligned_page(void *allocation)
{
    return (uint8_t *)(((uintptr_t)allocation + region_bytes - 1u) &
                       ~(uintptr_t)(region_bytes - 1u));
}

/* What the mock allocator would grant now: everything, unless a small
 * obstacle is in the way (exec_short_grants of them, exec_short_bytes
 * each), which is what the model's free list looks like after something
 * small was freed in front of a big node. */
static uint32_t exec_grant_probe(uint32_t bytes)
{
    probe_calls_count++;
    if (exec_grant_blind)
        return 0;
    if (loader_obstacles)
        return loader_obstacle_bytes < bytes ? loader_obstacle_bytes : bytes;
    if (exec_books) {
        size_t left = sizeof exec_pool - exec_used;
        return left < bytes ? (uint32_t)left : bytes;
    }
    if (exec_allocation_count < exec_short_grants)
        return exec_short_bytes < bytes ? exec_short_bytes : bytes;
    return bytes;
}

static uint64_t exec_grant_end(void *allocation)
{
    grant_calls++;
    if (!allocation || exec_grant_blind)
        return 0;
    for (uint32_t n = 0; n < exec_allocation_count; n++)
        if (exec_allocations[n] == allocation) {
            uint32_t bytes = n < exec_short_grants ? exec_short_bytes
                                                   : exec_allocation_sizes[n];
            /* The race hands back less than was asked for, whatever was
             * asked for: the obstacle taken in its own size is overtaken
             * the same way a whole region is. */
            if (exec_grant_race) {
                exec_grant_race--;
                bytes /= 2u;
            }
            return (uint64_t)(uintptr_t)allocation + bytes;
        }
    /* The books cover the loader's heap too: one stock heap backs both. */
    for (uint32_t n = 0; n < alloc_count; n++)
        if (alloc_start[n] == (uintptr_t)allocation)
            return (uint64_t)(uintptr_t)allocation + alloc_size[n];
    return 0;
}

static int32_t exec_allocate(uint32_t bytes, void **out)
{
    record('a');
    exec_allocation_attempts++;
    CHECK(exec_books || bytes == 2u * region_bytes - 1u || bytes == 3u * region_bytes - 1u ||
          bytes == region_bytes + region_bytes / 2u - 1u ||
          bytes == 2u * region_bytes + region_bytes / 2u - 1u ||
          /* the obstacle taken out of the way, in its own size */
          bytes == exec_short_bytes);
    if (exec_alloc_fail || exec_allocation_attempts == exec_alloc_fail_at ||
        bytes > exec_byte_budget - exec_live_bytes) {
        *out = 0;
        return -1;
    }
    if (exec_books) {
        if ((size_t)bytes > sizeof exec_pool - exec_used || exec_allocation_count >= 8u) {
            *out = 0;
            return -1;
        }
        *out = exec_pool + exec_used;
        exec_used += bytes;
        exec_allocations[exec_allocation_count] = *out;
        exec_allocation_sizes[exec_allocation_count++] = bytes;
        exec_live_bytes += bytes;
        /* Every whole region inside the grant is a block the loader may
         * audit and protect. */
        uint8_t *end = (uint8_t *)*out + bytes;
        for (uint8_t *page = aligned_page(*out); page + region_bytes <= end;
             page += region_bytes) {
            CHECK(block_count < 8u);
            if (block_count >= 8u)
                return -1;
            block_pages[block_count] = page;
            block_flags[block_count++] = MOCK_FLAG_W;
        }
        return 0;
    }
    uint32_t padding = exec_allocation_count < exec_alignment_padding_count
                           ? exec_alignment_padding[exec_allocation_count]
                           : region_bytes / 4u;
    CHECK(padding < region_bytes);
    uint8_t *aligned = aligned_page(exec_pool + exec_used + padding);
    size_t base = (size_t)(aligned - exec_pool) - padding;
    if (base > sizeof exec_pool || (size_t)bytes > sizeof exec_pool - base) {
        *out = 0;
        return -1;
    }
    *out = exec_pool + base;
    exec_used = base + bytes;
    CHECK(exec_allocation_count < 8u);
    if (exec_allocation_count >= 8u)
        return -1;
    exec_allocations[exec_allocation_count] = *out;
    exec_allocation_sizes[exec_allocation_count++] = bytes;
    exec_live_bytes += bytes;
    /* A request smaller than one region (the obstacle taken out of the way)
     * carries no page whose permissions the loader would ever change. */
    uint32_t regions = bytes > padding ? (bytes - padding) / region_bytes : 0u;
    for (uint32_t n = 0; n < regions; n++) {
        CHECK(block_count < 8u);
        if (block_count >= 8u)
            return -1;
        uint8_t *page = aligned_page(*out) + n * region_bytes;
        CHECK(page >= (uint8_t *)*out);
        CHECK(page + region_bytes <= (uint8_t *)*out + bytes);
        block_pages[block_count] = page;
        block_flags[block_count] = MOCK_FLAG_W;
        block_count++;
    }
    return 0;
}

static int32_t exec_release(void *allocation)
{
    record('f');
    exec_releases++;
    for (uint32_t n = 0; n < exec_allocation_count; n++) {
        if (exec_allocations[n] != allocation)
            continue;
        CHECK(!exec_allocation_released[n]);
        if (exec_release_fail)
            return -1;
        exec_allocation_released[n] = 1;
        exec_live_bytes -= exec_allocation_sizes[n];
        return 0;
    }
    CHECK(0); /* release must use an original owner, never an aligned region */
    return -1;
}

static int32_t exec_audit(void *page, uint32_t bytes, uint32_t expected)
{
    record('u');
    audit_calls++;
    int index = exec_block_index(page);
    CHECK(index >= 0);
    CHECK(bytes == region_bytes);
    CHECK((uintptr_t)page % region_bytes == 0);
    /* A mapping that is not what was asked for is reported, not asserted:
     * the loader's resident guard exists to meet exactly that. */
    if (index >= 0 && block_flags[index] != expected)
        return -1;
    return audit_calls == audit_fail_at ? -1 : 0;
}

/* protect calls since the reset: the call numbered protect_fail_at fails
 * without changing the mapping, as a partially applied change would. */
static uint32_t protect_calls, protect_fail_at;

static int32_t exec_protect(void *page, uint64_t bytes, uint32_t requested)
{
    int index = exec_block_index(page);
    CHECK(index >= 0);
    CHECK(bytes == region_bytes);
    record(requested == MOCK_FLAG_W ? 'w' : 'x');
    protect_calls++;
    if (protect_fail_at && protect_calls == protect_fail_at)
        return -1;
    if (index >= 0)
        block_flags[index] = requested;
    return 0;
}

static int32_t exec_clean(void *page, uint32_t bytes)
{
    record('c');
    clean_calls++;
    int index = exec_block_index(page);
    CHECK(index >= 0);
    CHECK(bytes == region_bytes);
    if (index >= 0) {
        CHECK(block_flags[index] == MOCK_FLAG_W);
        block_cleaned[index]++;
    }
    return clean_calls == clean_fail_at ? -1 : 0;
}

static int32_t exec_invalidate(void *page, uint64_t bytes)
{
    record('i');
    CHECK(bytes == fixture_image_len);
    CHECK(exec_block_index(page) >= 0);
    return 0;
}

/* Entry-mock scenario state, consumed by the stage-gated run scenarios. */
static uint64_t call_return_value;      /* what the mock entry returns */
static int call_sleeps;                 /* the entry waits once (sleep_ms) */
static int call_waits;                  /* the entry waits in queue_wait(FOREVER) */
static int call_uses_exit;              /* the entry calls api->exit */
static int32_t call_exit_code = 42;
static int exit_returns;                /* api->exit returns (ignored) */
static uint32_t call_count;
static int dispatch_mode, worker_context;
static uint32_t dispatch_calls;
static int call_register_menu, call_duplicate_menu;
static int call_owns_resources;
static int call_cleanup_fails;
static uint32_t after_api_read;
static uint32_t call_api_release_base;
static int registration_result, duplicate_result;
static char initialized_ids[4][NLR_MANIFEST_ID_MAX + 1];
static int32_t exec_extension_call(void *entry, uint64_t api,
                                   int32_t *exit_code, uint32_t *started);

static void reset_mocks(void)
{
    alloc_used = 0;
    alloc_fail_countdown = -1;
    alloc_calls = release_calls = 0;
    loader_release_fail = 0;
    alloc_count = 0;
    loader_obstacles = loader_overasked = 0;
    loader_obstacle_bytes = 0x4000;
    manifest_ready = 1;
    manifest_asks = 0;
    card_boot_len = card_bootrun_len = bootrun_writes = boot_opens = 0;
    protect_calls = protect_fail_at = 0;
    open_fail = seek_fail = close_fail = fail_next_read = 0;
    stop_on_api_read = call_owns_resources = call_cleanup_fails = 0;
    after_api_read = 0;
    call_api_release_base = 0;
    exit_services.input_callback = 0;
    exit_services.release_mask = 0;
    release_during_api = 0;
    input_callback = original_input;
    stop_event_count = stop_release_base = 0;
#ifdef NLR_STAGE_EXEC
    input_calls = alternate_input_calls = 0;
#endif
    memset(forwarded_input, 0, sizeof forwarded_input);
    memset(stop_events, 0, sizeof stop_events);
    stop_fail = stop_suspended = stop_dead = call_busy = 0;
    reenter_continue = 0;
    reenter_calls = 0;
    written_len = write_calls = clean_before_write = write_fail = 0;
    memset(written, 0, sizeof written);
    call_installs_hook = call_breaks_unhook = hook_install_result = 0;
    memset(&mock_program_services, 0, sizeof mock_program_services);
    memset(mock_scan_object, 0, sizeof mock_scan_object);
    memset(&mock_platform_services, 0, sizeof mock_platform_services);
    memset(&mock_platform_scan, 0, sizeof mock_platform_scan);
    reset_code_channel();
    safe_mode_present = 0;
    probe_busy = 0;
    card_manifest_present = 0;
    card_enabled_present = pending_present = 0;
    card_enabled_len = 0;
    probe_calls = probe_fail_at = probe_invalid = probe_enabled_anyway = 0;
    marker_write_fail = marker_commit_then_fail = marker_remove_fail = 0;
    settings_write_fail = 0;
    marker_writes = marker_removes = settings_writes = 0;
    card_operation_count = 0;
    card_operations[0] = 0;
    card_master_off = 0;
    master_opens = 0;
    dispatch_mode = worker_context = 0;
    dispatch_calls = 0;
    call_register_menu = call_duplicate_menu = 0;
    registration_result = duplicate_result = 0;
    resource_publish_calls = 0;
    resource_publish_result = resource_menu_context = 0;
    resource_services.publish = mock_resource_publish;
    memset(&published_item, 0, sizeof published_item);
    memset(initialized_ids, 0, sizeof initialized_ids);
    nlr_exec_services.extension_call = exec_extension_call;
    manifest_opens = program_opens = 0;
    memset(last_open_path, 0, sizeof last_open_path);
    read_max = 0x1000;
    cache_before_calls = cache_after_calls = 0;
    memset(fds, 0, sizeof fds);
    memset(registry_table, 0, sizeof registry_table);
    api_file_path = 0;
    api_file_len = 0;
    card2_path = 0;
    card2_len = 0;
    flag_set_fail = 0;
    exec_alloc_fail = 0;
    exec_release_fail = 0;
    /* The profile limits under test, restored for every scenario. */
    nlr_exec_services.program_budget_blocks = 2u;
    nlr_exec_services.program_max_resident = 1u;
    call_count = 0;
    call_uses_exit = 0;
    exit_returns = 0;
    call_return_value = 0;
    call_sleeps = 0;
}

/* ---- exec services table and entry mock ------------------------------------ */

static void verify_relocations(const uint8_t *code_page,
                               const uint8_t *data_page)
{
    for (uint32_t n = 0; n < reloc_count; n++) {
        uint32_t offset = reloc_fixture[n][0];
        uint32_t target = reloc_fixture[n][1];
        uint32_t kind = reloc_fixture[n][2];
        if (kind == NLR_RELOC_ADRP) {
            uint32_t word = read32(code_page + offset);
            CHECK((word & 0x9f000000u) == 0x90000000u);
            uint32_t field =
                (((word >> 5) & 0x7ffffu) << 2) | ((word >> 29) & 3u);
            uint32_t extended =
                (field & 0x1fffffu) | (field & (1u << 20) ? 0xffe00000u : 0u);
            int64_t decoded = (int32_t)extended;
            int64_t expected =
                (int64_t)(((uintptr_t)data_page + target) >> 12) -
                (int64_t)(((uintptr_t)code_page + offset) >> 12);
            CHECK(decoded == expected);
            CHECK(word != adrp_instruction()); /* really rewritten */
        } else if (kind == NLR_RELOC_ABS64 || kind == NLR_RELOC_ABS64_DATA) {
            uint64_t value = 0;
            for (uint32_t b = 0; b < 8; b++)
                value |= (uint64_t)data_page[offset + b] << (8 * b);
            const uint8_t *base = kind == NLR_RELOC_ABS64 ? code_page : data_page;
            CHECK(value == (uint64_t)(uintptr_t)(base + target));
        }
    }
}

/* ---- the firmware-code channel's mock ------------------------------------ */

/* The body keeps a writable alias of the pages its text runs from, and the
 * two are one memory there. The host cannot do that, so the mock keeps
 * them apart and lets the clean carry the bytes across: a patch that
 * skipped its cache maintenance would be invisible to instruction fetch
 * here exactly as it would be on the camera. A handler lives in the
 * running program's own code block, which is ordinary pool memory, so
 * everything that is not the alias answers "executable". */
static _Alignas(NLR_EXEC_PAGE_SIZE) uint8_t mock_text[NLR_EXEC_PAGE_SIZE];
static _Alignas(NLR_EXEC_PAGE_SIZE) uint8_t mock_alias[NLR_EXEC_PAGE_SIZE];
static const char code_manager = 'm';
static int code_translate_fail;
static uint32_t code_clean_calls;

/* ADD X0, X0, #1 / RET / MOV X8, #0xd350 / LDRB W9, [X0]: four movable
 * instructions at the hook target, 8-byte aligned inside the page. */
static const uint32_t code_target_words[4] = {
    0x91000400u, 0xd65f03c0u, 0xd29a6a08u, 0x39400009u
};
#define CODE_TARGET_OFFSET 64u

static int32_t code_translate(const volatile void *manager, uintptr_t address,
                              uint64_t *out_physical)
{
    CHECK(manager == &code_manager);
    if (code_translate_fail || address < (uintptr_t)mock_text ||
        address >= (uintptr_t)mock_text + sizeof mock_text)
        return -1;
    *out_physical = (uint64_t)(uintptr_t)mock_alias +
                    (address - (uintptr_t)mock_text);
    return 0;
}

static int32_t code_query(void *address, uint32_t *out_flags)
{
    *out_flags = (uintptr_t)address >= (uintptr_t)mock_alias &&
                         (uintptr_t)address <
                             (uintptr_t)mock_alias + sizeof mock_alias
                     ? MOCK_FLAG_W
                     : MOCK_FLAG_X;
    return 0;
}

static uint32_t code_cacheable(void *address)
{
    (void)address;
    return 1;
}

static void code_clean(void *address, uint32_t bytes)
{
    code_clean_calls++;
    uintptr_t offset = (uintptr_t)address - (uintptr_t)mock_alias;
    CHECK(offset + bytes <= sizeof mock_alias);
    memcpy(mock_text + offset, mock_alias + offset, bytes);
}

static void code_invalidate(void *address, uint64_t bytes)
{
    (void)address;
    (void)bytes;
}

static void code_put_word(uint8_t *at, uint32_t word)
{
    for (uint32_t n = 0; n < 4u; n++)
        at[n] = (uint8_t)(word >> (8u * n));
}

#if defined(NLR_STAGE_EXEC)
static uint32_t code_get_word(const uint8_t *at)
{
    return (uint32_t)at[0] | (uint32_t)at[1] << 8 | (uint32_t)at[2] << 16 |
           (uint32_t)at[3] << 24;
}
#endif

static void reset_code_channel(void)
{
    memset(mock_text, 0, sizeof mock_text);
    memset(mock_alias, 0, sizeof mock_alias);
    for (uint32_t n = 0; n < 4u; n++)
        code_put_word(mock_text + CODE_TARGET_OFFSET + 4u * n,
                      code_target_words[n]);
    mock_code_services = (struct nlr_code_services){
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
    code_translate_fail = 0;
    code_clean_calls = 0;
}

/* The load whose spill the entry looks at (spill_released_before_entry):
 * 1 when the entry found it still allocated, 0 when not, -1 unwatched. */
static struct nlr_load *spill_watch;
static int spill_live_at_entry = -1;

static uint64_t exec_call(void *entry, uint64_t challenge)
{
    record('e');
    call_count++;
    if (spill_watch)
        spill_live_at_entry = spill_watch->spill_request != 0;
    /* x0 is the API table, not a probe challenge (PLAN 5.2). */
    CHECK(challenge == (uint64_t)(uintptr_t)&nlr_api);
    if (fixture_kind == NLR_KIND_RESOURCE_EXTENSION)
        CHECK(worker_context && !resource_menu_context);
    CHECK(((const struct nlr_api *)(uintptr_t)challenge)->abi ==
          NLR_ABI_VERSION);
    uint8_t *data_page = 0;
    uint8_t *code_page;
    if (fixture_data_len || fixture_bss) {
        CHECK(block_count >= 2);
        data_page = aligned_page(block_pages[block_count - 1]);
        code_page = aligned_page(block_pages[block_count - 2]);
    } else {
        CHECK(block_count >= 1);
        code_page = aligned_page(block_pages[block_count - 1]);
    }
    CHECK((uint8_t *)entry == code_page + fixture_entry);
    CHECK(block_cleaned[exec_block_index(code_page)] == 1u);
    if (data_page)
        CHECK(block_cleaned[exec_block_index(data_page)] == 1u);
    /* The image is there, with every ADRP word patched. */
    CHECK(memcmp(code_page, image_fixture, IMAGE_ADRP_OFFSET) == 0);
    CHECK(memcmp(code_page + IMAGE_ADRP_OFFSET + 4,
                 image_fixture + IMAGE_ADRP_OFFSET + 4,
                 (fixture_image_len < IMAGE_LEN ? fixture_image_len : IMAGE_LEN) -
                    IMAGE_ADRP_OFFSET - 4) == 0);
    for (uint32_t n = IMAGE_LEN; n < fixture_image_len; n++)
        CHECK(code_page[n] == (uint8_t)(n * 7u + 3u));
    if (data_page) {
        verify_relocations(code_page, data_page);
        /* The data matches the segment, except the bytes an ABS64 entry
         * overwrote with the code pointer. */
        for (uint32_t n = 0; n < fixture_data_len; n++) {
            int patched = 0;
            for (uint32_t k = 0; k < reloc_count; k++)
                if ((reloc_fixture[k][2] == NLR_RELOC_ABS64 ||
                     reloc_fixture[k][2] == NLR_RELOC_ABS64_DATA) &&
                    n >= reloc_fixture[k][0] &&
                    n < reloc_fixture[k][0] + 8)
                    patched = 1;
            if (!patched)
                CHECK(data_page[n] == data_fixture[n]);
        }
        for (uint32_t n = 0; n < fixture_bss; n++)
            CHECK(data_page[fixture_data_len + n] == 0);
    }
    if (call_register_menu) {
        registration_result = nlr_extension_init(&nlr_api);
        if (call_duplicate_menu)
            duplicate_result = nlr_extension_init(&nlr_api);
        if (registration_result != 0)
            return (uint64_t)(uint32_t)registration_result;
    }
    if (call_owns_resources) {
        call_api_release_base = release_calls;
        CHECK(nlr_api.mem_alloc(32, 0) != 0);
        CHECK(nlr_api.mem_alloc(48, 0) != 0);
        int fd = nlr_api.fs_open("APPS/NOTE.TXT", 0);
        CHECK(fd >= 0);
        char byte;
        CHECK(nlr_api.fs_read(fd, &byte, 1) == 1);
        after_api_read++;
        if (call_cleanup_fails)
            close_fail = 1;
        /* Intentionally leave both allocations and the fd to loader cleanup. */
    }
    if (call_busy) {
        /* Represent ordinary computation without executing an infinite host
         * loop or using any SDK polling/exit. Native mocks must prove stop. */
        stop_release_base = release_calls;
        send_input(EXIT_MASK | 0x80u, 0x80u, EXIT_MASK, EXIT_MASK, 0);
        longjmp(busy_context, 1);
    }
    if (call_installs_hook) {
        uint8_t expect[NLR_CODE_HOOK_BYTES];
        for (uint32_t n = 0; n < 4u; n++)
            code_put_word(expect + 4u * n, code_target_words[n]);
        hook_install_result = nlr_api.code_hook(
            mock_text + CODE_TARGET_OFFSET, expect, code_page);
        /* and never removes it; the loader has to. */
        if (call_breaks_unhook)
            code_translate_fail = 1;
    }
    if (call_waits) {
        /* a shell that waits for events from its first second on */
        struct nlr_event ev;
        call_waits = nlr_api.queue_wait(&ev, NLR_QUEUE_FOREVER);
        return 0;
    }
    if (call_sleeps) {
        /* With no wait service in this table the wait fails and ends the
         * program with that error (api.c); what happened before the wait
         * is what the boot record tests look at. */
        nlr_api.sleep_ms(1);
        return 0; /* not reached */
    }
    if (call_uses_exit) {
        nlr_api.exit(call_exit_code);
        if (!exit_returns)
            return 0; /* not reached: api->exit longjmps away */
    }
    return (uint64_t)(uint32_t)call_return_value;
}

static int32_t exec_extension_call(void *entry, uint64_t api,
                                   int32_t *exit_code, uint32_t *started)
{
    dispatch_calls++;
    *started = 0;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0 && r->load.state == 2);
    /* Synchronous worker invocation, not a menu dispatcher. Menu publication
     * cannot consume while the worker is inside init. */
    CHECK(nlr_runtime_menu_publish(r) == NLR_BUSY);
    if (r && r->autoload.phase == NLR_AUTOLOAD_WAITING)
        CHECK(nlr_runtime_autoload_step(r) == NLR_BUSY);
    if (dispatch_mode == 1)
        return NLR_BUSY;
    worker_context = 1;
    *started = 1;
    if (r && call_count < 4)
        snprintf(initialized_ids[call_count], sizeof initialized_ids[0],
                 "%s", r->program_id);
    *exit_code = (int32_t)(uint32_t)exec_call(entry, api);
    CHECK(worker_context);
    worker_context = 0;
    if (dispatch_mode == 3 && r)
        nlr_runtime_autoload_interrupt(r, NLR_AUTOLOAD_INTERRUPTED);
    return dispatch_mode == 2 ? NLR_EXEC_TIMEOUT : NLR_OK;
}

/* Non-const on purpose: the coexistence budget scenarios change the
 * injected limits the way a different profile would. The camera bindings
 * generate a const table from the validated profile; the other translation
 * units only read it. */
struct nlr_exec_services nlr_exec_services = {
    .region_bytes = NLR_EXEC_BLOCK_SIZE,
    .flag_writable = MOCK_FLAG_W,
    .flag_executable = MOCK_FLAG_X,
    /* The profile values under test: two blocks are proven in QEMU, one
     * resident extension until multi-extension coexistence is verified. */
    .program_budget_blocks = 2u,
    .program_max_resident = 1u,
    .allocate = exec_allocate,
    .release = exec_release,
    .audit = exec_audit,
    .protect = exec_protect,
    .clean = exec_clean,
    .invalidate_code = exec_invalidate,
    .call = exec_call,
    .extension_call = exec_extension_call,
    .grant_probe = exec_grant_probe,
    .grant_end = exec_grant_end,
};

/* ---- scenario scaffolding --------------------------------------------------- */

static const char task_name[NLR_TASK_NAME_SIZE] = {'N', 'L', 'O', 'A', 'D', 'E', 'R', 0};

static struct nlr_task_config default_task(void)
{
    struct nlr_task_config task = {0};
    task.core = 3;
    task.priority = 20;
    task.stack_bytes = 0x8000;
    memcpy(task.name, task_name, sizeof task_name);
    return task;
}

/* A runtime over the manifest naming the built program file; the file's
 * declared kind must match the manifest column. */
static struct nlr_runtime *program_fixture(const char *id,
                                           const char *kind_text,
                                           uint32_t file_kind)
{
    reset_mocks();
    reset_exec_pool();
    reset_fixture();
    fixture_kind = file_kind;
    build_program_file();
    char line[128];
    snprintf(line, sizeof line,
             "%s | %s | Prog | APPS/PROG.NLB | 2 | z8/3.11\n", id, kind_text);
    set_manifest(line);
    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);
    CHECK(r != 0);
    if (!r)
        return 0;
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    return r;
}

/* ---- load-stage tests (every stage) ----------------------------------------- */

/* A valid generic v2 file loads into the arena as [reloc][image][data] and
 * every declared segment lands in the load state. */
static void generic_v2_loads_with_segments(void)
{
    reset_fixture();
    reset_mocks();
    reset_exec_pool();
    build_program_file();
    _Alignas(NLR_CACHE_LINE) uint8_t arena[0x4000];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) ==
          NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;
    read_max = 3; /* every read crosses the service's short-read limit */
    CHECK(nlr_load_file(&load) == NLR_OK);
    CHECK(load.header_bytes == 64 && load.image_bytes == IMAGE_LEN);
    CHECK(load.entry_offset == 16u && load.bss_bytes == 8u);
    CHECK(load.data_bytes == DATA_LEN && load.reloc_bytes == 24u);
    CHECK(load.program_kind == NLR_KIND_FOREGROUND);
    CHECK(load.abi_version == 2u);
    CHECK(memcmp(load.header, card, 64) == 0);
    CHECK(memcmp(load.arena, card + 64, 24) == 0);
    CHECK(memcmp(load.arena + 24, card + 88, IMAGE_LEN) == 0);
    CHECK(memcmp(load.arena + 24 + IMAGE_LEN, card + 88 + IMAGE_LEN,
                 DATA_LEN) == 0);
    CHECK(cache_before_calls == 3 && cache_after_calls == 3);
    CHECK(!load.program.code_allocation && !load.program_mode);
}

/* Every structural rejection of the 64-byte header: kind, manifest
 * agreement, ABI, reserved fields, relocation size. */
static void generic_header_rejections(void)
{
    reset_fixture();
    _Alignas(NLR_CACHE_LINE) uint8_t arena[0x4000];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) ==
          NLR_OK);
    load.path = TEST_PATH;

    /* Manifest kind and file kind must agree, in both directions. */
    reset_mocks();
    build_program_file();
    load.manifest_kind = NLR_KIND_FOREGROUND;
    CHECK(nlr_load_file(&load) == NLR_OK);
    load.manifest_kind = NLR_KIND_RESOURCE_EXTENSION;
    CHECK(nlr_load_file(&load) == NLR_FORMAT);
    CHECK(!load.header_bytes && !load.image_bytes);

    reset_mocks();
    fixture_kind = NLR_KIND_RESOURCE_EXTENSION;
    build_program_file();
    CHECK(nlr_load_file(&load) == NLR_OK);
    CHECK(load.program_kind == NLR_KIND_RESOURCE_EXTENSION);

    const uint32_t bad_kinds[] = {0, 3, 0xffffffffu};
    for (unsigned i = 0; i < sizeof bad_kinds / sizeof bad_kinds[0]; i++) {
        reset_mocks();
        fixture_kind = NLR_KIND_FOREGROUND;
        build_program_file();
        put32(card + 0x20, bad_kinds[i]);
        load.manifest_kind = NLR_KIND_FOREGROUND;
        CHECK(nlr_load_file(&load) == NLR_FORMAT);
    }
    /* flags 1 belongs to the 48-byte probe subset only. */
    reset_mocks();
    build_program_file();
    put32(card + 8, 1);
    CHECK(nlr_load_file(&load) == NLR_FORMAT);
    /* A 48-byte header without the probe's flags is not a known shape. */
    reset_mocks();
    build_program_file();
    card[6] = 48;
    card[7] = 0;
    CHECK(nlr_load_file(&load) == NLR_FORMAT);
    const uint32_t reserved_offsets[] = {0x28, 0x2c, 0x38, 0x3c};
    for (unsigned i = 0;
         i < sizeof reserved_offsets / sizeof reserved_offsets[0]; i++) {
        reset_mocks();
        build_program_file();
        card[reserved_offsets[i]] ^= 1;
        CHECK(nlr_load_file(&load) == NLR_FORMAT);
    }
    /* ABI above the runtime's is refused; 0, 1 and 2 are accepted. */
    for (uint32_t abi = 0; abi <= NLR_ABI_VERSION; abi++) {
        reset_mocks();
        fixture_abi = abi;
        build_program_file();
        CHECK(nlr_load_file(&load) == (abi == 0u || abi == 3u ? NLR_FORMAT : NLR_OK));
        if (abi != 0u && abi != 3u) CHECK(load.abi_version == abi);
    }
    reset_mocks();
    fixture_abi = NLR_ABI_VERSION + 1;
    build_program_file();
    CHECK(nlr_load_file(&load) == NLR_FORMAT);
    /* Relocation table size must be a multiple of the 12-byte entry. */
    reset_mocks();
    build_program_file();
    put32(card + 0x24, 11);
    CHECK(nlr_load_file(&load) == NLR_FORMAT);
    /* A manifest kind of 0 (no manifest consulted) cannot match. */
    reset_mocks();
    build_program_file();
    load.manifest_kind = NLR_KIND_NONE;
    CHECK(nlr_load_file(&load) == NLR_FORMAT);
    load.manifest_kind = NLR_KIND_FOREGROUND;
}

/* Bounds: entry, image, data+BSS against one execution block, the whole
 * [reloc][image][data] set against the loader arena, and the file length
 * that states data_size. */
static void generic_bounds_rejections(void)
{
    reset_fixture();
    _Alignas(NLR_CACHE_LINE) uint8_t arena[0x4000];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) ==
          NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;

    reset_mocks();
    build_program_file();
    put32(card + 0x14, 2); /* entry not 4-byte aligned */
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 0x14, IMAGE_LEN); /* entry past the image */
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 0xc, 3); /* image below the minimum */
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 0xc, NLR_EXEC_BLOCK_SIZE + 1); /* image past one block */
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 0x10, NLR_EXEC_BLOCK_SIZE); /* data + bss past one block */
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    card_len -= 1; /* one byte short: data_size shrinks and its CRC fails */
    CHECK(nlr_load_file(&load) == NLR_CHECKSUM);
    reset_mocks();
    build_program_file();
    put32(card + 0x24, 36); /* three entries declared, file cut by 12 */
    card_len -= 12;
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    /* A larger valid segment set uses a separate bounded read buffer. */
    reset_mocks();
    fixture_data_len = ARENA_CAP;
    build_program_file();
    CHECK(nlr_load_file(&load) == NLR_OK && load.spill_request);
    reset_fixture();
    build_program_file();
    CHECK(nlr_load_file(&load) == NLR_OK && !load.spill_request);
    CHECK(load.arena == arena && load.capacity == sizeof arena);
}

/* Full bytes, not just an oversized header: this synthetic file has the
 * same 550968-byte length as the reviewed DOOM input and exceeds both
 * supported base-arena configurations. Neither base capacity is enlarged. */
static void generic_spill_read_buffer_ownership(void)
{
    _Alignas(NLR_CACHE_LINE) uint8_t arena[524288];
    const uint32_t capacities[] = {65536, 524288};
    struct nlr_task_config task = default_task();
    for (uint32_t scenario = 0; scenario < 2; scenario++) {
        reset_mocks();
        reset_fixture();
        struct nlr_load load = {0};
        CHECK(nlr_load_init(&load, &nlr_services, arena, capacities[scenario], &task) == NLR_OK);
        load.path = TEST_PATH;
        load.manifest_kind = NLR_KIND_FOREGROUND;
        fixture_image_len = 550864u;
        build_program_file();
        CHECK(card_len == 550968u && card_len > capacities[scenario]);
        CHECK(nlr_load_file(&load) == NLR_OK);
        uint32_t segments = load.reloc_bytes + load.image_bytes + load.data_bytes;
        CHECK(load.spill_request && load.home_arena == arena);
        CHECK(load.home_capacity == capacities[scenario]);
        CHECK(load.capacity == nlr_cache_lines(segments) && load.spill_bytes == load.capacity + NLR_CACHE_LINE);
        CHECK(!memcmp(load.arena, card + NLR_GENERIC_HEADER_SIZE, segments));
        CHECK(alloc_calls == 1 && !release_calls && !load.spill_uncertain);
        reset_fixture();
        build_program_file();
        CHECK(nlr_load_file(&load) == NLR_OK);
        CHECK(!load.spill_request && !load.home_arena && release_calls == 1);
        CHECK(load.arena == arena && load.capacity == capacities[scenario]);
        fixture_image_len = 550864u;
        build_program_file();
        CHECK(nlr_load_now(&load) == NLR_OK);
        CHECK(!load.spill_request && load.arena == arena && load.capacity == capacities[scenario]);
        CHECK(alloc_calls == 2 && release_calls == 2 && !load.program.entry_started);
    }

    reset_mocks();
    reset_fixture();
    struct nlr_load load = {0};
    CHECK(nlr_load_init(&load, &nlr_services, arena, 65536, &task) == NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;
    fixture_image_len = 550864u;
    build_program_file();
    alloc_fail_countdown = 0;
    CHECK(nlr_load_now(&load) == NLR_NOT_READY);
    CHECK(alloc_calls == 1 && !release_calls && !load.spill_request);
    CHECK(load.arena == arena && load.capacity == 65536 && !load.state);

    reset_mocks();
    reset_fixture();
    build_program_file();
    put32(card + 0x24, 0x100008u); /* first 12-byte multiple over 1 MiB */
    card_len = NLR_GENERIC_HEADER_SIZE + 0x100008u + IMAGE_LEN;
    CHECK(nlr_load_now(&load) == NLR_BOUNDS && !alloc_calls);
    put32(card + 0xc, NLR_EXEC_BLOCK_SIZE);
    card_len = (uint32_t)NLR_LOAD_SPILL_MAX + NLR_GENERIC_HEADER_SIZE + 8u;
    CHECK(nlr_load_now(&load) == NLR_BOUNDS && !alloc_calls);

    reset_mocks();
    reset_fixture();
    fixture_image_len = 550864u;
    build_program_file();
    loader_release_fail = 1;
    CHECK(nlr_load_now(&load) == NLR_EXEC_RESTORE);
    CHECK(load.spill_request && load.spill_uncertain && release_calls == 1);
    CHECK(load.arena == arena && load.home_arena == arena && load.capacity == 65536);
    void *retained = load.spill_request;
    uint32_t calls = program_opens;
    loader_release_fail = 0;
    CHECK(nlr_load_now(&load) == NLR_EXEC_RESTORE);
    CHECK(nlr_load_file(&load) == NLR_EXEC_RESTORE);
    CHECK(nlr_load_enqueue_once(&load) == NLR_EXEC_RESTORE);
    CHECK(load.spill_request == retained && release_calls == 1 && program_opens == calls);
}

/* Memory outside a program's regions is granted whole. With small nodes
 * at the head of the free list, the API's mem_alloc and the loader's spill
 * take them out of the way in their own size, ask for the block only once
 * the books say it fits, and give the nodes back -- the stock heap would
 * otherwise hand over the small node and map the whole request past it.
 * Books that cannot say refuse instead of guessing. The books are read only
 * in the stages that run programs. */
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
static void memory_outside_regions_granted_whole(void)
{
    reset_mocks();
    reset_fixture();
    reset_exec_pool();
    loader_obstacles = 2;
    void *block = nlr_api.mem_alloc(0x10000, 0);
    CHECK(block != 0 && !loader_overasked && !loader_obstacles);
    CHECK(alloc_calls == 3 && release_calls == 2);
    CHECK(inside_allocation((uintptr_t)block, (uintptr_t)block + 0x10000));
    nlr_api.mem_free(block);
    CHECK(release_calls == 3);
    exec_grant_blind = 1;
    CHECK(nlr_api.mem_alloc(0x10000, 0) == 0 && alloc_calls == 3);
    exec_grant_blind = 0;
    /* The loader's own blocks (the details' metadata on the menu task, the
     * runtime, the card's request area) come from the same entry. */
    loader_obstacles = 2;
    loader_overasked = 0;
    uint32_t calls_before = alloc_calls;
    block = nlr_alloc_whole(&nlr_services, 0x10000);
    CHECK(block != 0 && !loader_overasked && !loader_obstacles);
    CHECK(alloc_calls == calls_before + 3u);
    CHECK(inside_allocation((uintptr_t)block, (uintptr_t)block + 0x10000));
    exec_grant_blind = 1;
    CHECK(nlr_alloc_whole(&nlr_services, 0x10000) == 0 && alloc_calls == calls_before + 3u);
    exec_grant_blind = 0;

    _Alignas(NLR_CACHE_LINE) static uint8_t arena[65536];
    struct nlr_task_config task = default_task();
    reset_mocks();
    reset_fixture();
    struct nlr_load load = {0};
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) == NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;
    fixture_image_len = 550864u;
    build_program_file();
    loader_obstacles = 1;
    CHECK(nlr_load_file(&load) == NLR_OK && load.spill_request);
    CHECK(!loader_overasked && !loader_obstacles);
    CHECK(alloc_calls == 2 && release_calls == 1);
    CHECK(inside_allocation((uintptr_t)load.arena, (uintptr_t)load.arena + load.capacity));
    reset_fixture();
    build_program_file();
    CHECK(nlr_load_file(&load) == NLR_OK && !load.spill_request);
}
#endif

/* Checksums over all three segments, including the zero-segment rules. */
static void generic_checksum_rejections(void)
{
    reset_fixture();
    _Alignas(NLR_CACHE_LINE) uint8_t arena[0x4000];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) ==
          NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;

    reset_mocks();
    build_program_file();
    put32(card + 0x1c, test_crc32(card + 88, IMAGE_LEN) ^ 1);
    CHECK(nlr_load_file(&load) == NLR_CHECKSUM);
    reset_mocks();
    build_program_file();
    put32(card + 0x30, test_crc32(card + 88 + IMAGE_LEN, DATA_LEN) ^ 1);
    CHECK(nlr_load_file(&load) == NLR_CHECKSUM);
    reset_mocks();
    build_program_file();
    put32(card + 0x34, test_crc32(card + 64, 24) ^ 1);
    CHECK(nlr_load_file(&load) == NLR_CHECKSUM);
    /* A data CRC declared with no data segment is a checksum failure. */
    reset_mocks();
    build_program_file();
    card_len = 64 + 24 + IMAGE_LEN;
    put32(card + 0x30, 5);
    CHECK(nlr_load_file(&load) == NLR_CHECKSUM);
    /* With the CRC cleared, the BSS-only program is valid. */
    reset_mocks();
    build_program_file();
    card_len = 64 + 24 + IMAGE_LEN;
    put32(card + 0x30, 0);
    CHECK(nlr_load_file(&load) == NLR_OK);
    CHECK(load.data_bytes == 0 && load.bss_bytes == 8);
}

/* Relocation entries are pre-validated before any execution memory exists. */
static void generic_relocation_rejections(void)
{
    reset_fixture();
    _Alignas(NLR_CACHE_LINE) uint8_t arena[0x4000];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) ==
          NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;

    reset_mocks();
    build_program_file();
    put32(card + 64 + 8, 99); /* unknown relocation kind */
    put32(card + 0x34, test_crc32(card + 64, 24));
    CHECK(nlr_load_file(&load) == NLR_FORMAT);
    reset_mocks();
    build_program_file();
    put32(card + 64, IMAGE_LEN); /* ADRP offset past the image */
    put32(card + 0x34, test_crc32(card + 64, 24));
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 64 + 1, 3); /* ADRP offset not 4-byte aligned */
    put32(card + 0x34, test_crc32(card + 64, 24));
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 64 + 4, 24); /* ADRP target past data + bss */
    put32(card + 0x34, test_crc32(card + 64, 24));
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 64 + 12, 24); /* ABS64 write past data + bss */
    put32(card + 0x34, test_crc32(card + 64, 24));
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    reset_mocks();
    build_program_file();
    put32(card + 64 + 16, IMAGE_LEN); /* ABS64 target past the image */
    put32(card + 0x34, test_crc32(card + 64, 24));
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
    /* Relocations with neither data nor BSS cannot point anywhere legal. */
    reset_mocks();
    build_program_file();
    card_len = 64 + 24 + IMAGE_LEN;
    put32(card + 0x30, 0);
    put32(card + 0x10, 0);
    CHECK(nlr_load_file(&load) == NLR_BOUNDS);
}

static void data_pointer_relocation_validation(void)
{
    _Alignas(NLR_CACHE_LINE) uint8_t arena[0x4000];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) == NLR_OK);
    load.path = TEST_PATH;
    load.manifest_kind = NLR_KIND_FOREGROUND;
    /* All permutations preserve the exact file metadata after overlap
     * validation, including equal offsets in different destination segments. */
    const uint32_t entries[3][3] = {
        {IMAGE_ADRP_OFFSET, 4u, NLR_RELOC_ADRP},
        {0u, 12u, NLR_RELOC_ABS64},
        {8u, DATA_LEN + 4u, NLR_RELOC_ABS64_DATA}
    };
    for (uint32_t first = 0; first < 3; first++)
        for (uint32_t second = 0; second < 3; second++) {
            if (first == second) continue;
            reset_fixture(); reset_mocks();
            reloc_count = 3;
            memcpy(reloc_fixture[0], entries[first], sizeof entries[0]);
            memcpy(reloc_fixture[1], entries[second], sizeof entries[0]);
            memcpy(reloc_fixture[2], entries[3u - first - second], sizeof entries[0]);
            build_program_file();
            CHECK(nlr_load_file(&load) == NLR_OK);
            CHECK(memcmp(arena, card + 64, 36) == 0);
        }
    for (uint32_t variant = 0; variant < 6; variant++) {
        reset_fixture(); reset_mocks();
        reloc_count = 3;
        memcpy(reloc_fixture, entries, sizeof entries);
        int expected = NLR_BOUNDS;
        switch (variant) {
        case 0: reloc_fixture[2][1] = DATA_LEN + 8u; break;
        case 1: reloc_fixture[2][0] = DATA_LEN; break;
        case 2: reloc_fixture[2][0] = 1u; break;
        case 3: reloc_fixture[2][0] = 0u; expected = NLR_FORMAT; break;
        case 4:
            memcpy(reloc_fixture[2], entries[0], sizeof entries[0]);
            expected = NLR_FORMAT; break;
        case 5:
            memcpy(reloc_fixture[2], entries[1], sizeof entries[0]);
            reloc_fixture[2][0] = 1u; break;
        }
        build_program_file();
        CHECK(nlr_load_file(&load) == expected);
        CHECK(memcmp(arena, card + 64, 36) == 0);
    }
    /* A nontrivial permutation exercises sorting and exact restoration at
     * scale; duplicate input is refused with its original bytes preserved. */
    for (uint32_t duplicate = 0; duplicate < 2; duplicate++) {
        reset_fixture(); reset_mocks(); build_program_file();
        const uint32_t count = 257u, table_bytes = count * 12u;
        put32(card + 0xc, count * 4u);
        put32(card + 0x10, 0u);
        put32(card + 0x14, 0u);
        put32(card + 0x24, table_bytes);
        for (uint32_t n = 0; n < count; n++) {
            uint32_t offset = ((n * 73u) % count) * 4u;
            if (duplicate && n + 1u == count) offset = 0;
            put32(card + 64 + n * 12u, offset);
            put32(card + 68 + n * 12u, 0u);
            put32(card + 72 + n * 12u, NLR_RELOC_ADRP);
            put32(card + 64 + table_bytes + n * 4u, adrp_instruction());
        }
        memset(card + 64 + table_bytes + count * 4u, 0, 8);
        card_len = 64 + table_bytes + count * 4u + 8u;
        put32(card + 0x1c, test_crc32(card + 64 + table_bytes, count * 4u));
        put32(card + 0x30, test_crc32(card + 64 + table_bytes + count * 4u, 8));
        put32(card + 0x34, test_crc32(card + 64, table_bytes));
        CHECK(nlr_load_file(&load) == (duplicate ? NLR_FORMAT : NLR_OK));
        CHECK(memcmp(arena, card + 64, table_bytes) == 0);
    }
}

/* ADRP patching, directly: legal page differences in both directions, the
 * 21-bit range limit and a non-ADRP instruction. Fabricated data bases only
 * take part in the page arithmetic and are never dereferenced. */
static void adrp_patch_unit(void)
{
    static _Alignas(8) uint8_t code[16];
    uintptr_t base = (uintptr_t)code;
    for (uint32_t n = 0; n < sizeof code; n++)
        code[n] = (uint8_t)(n * 5 + 1);
    put32(code + 0, adrp_instruction());
    /* data two pages after the code page: +2 pages. */
    CHECK(nlr_program_patch_adrp(code, 0,
                                 (const uint8_t *)(base + 2ull * 4096u), 0) ==
          NLR_OK);
    uint32_t word = read32(code);
    CHECK((word & 0x9f000000u) == 0x90000000u);
    uint32_t field = (((word >> 5) & 0x7ffffu) << 2) | ((word >> 29) & 3u);
    CHECK(field == 2);
    /* data one page before the code page: -1 page. */
    CHECK(nlr_program_patch_adrp(code, 0, (const uint8_t *)(base - 4096ull),
                                 0) == NLR_OK);
    word = read32(code);
    field = (((word >> 5) & 0x7ffffu) << 2) | ((word >> 29) & 3u);
    CHECK((field & 0xfffffu) == 0xfffffu && (field & (1u << 20)));
    /* Range: the difference must fit a signed 21-bit page count. */
    CHECK(nlr_program_patch_adrp(
              code, 0, (const uint8_t *)(base + (5ull << 30)), 0) ==
          NLR_BOUNDS);
    /* A non-ADRP instruction stays one after patching: rejected. */
    put32(code + 4, 0xd503201fu); /* NOP: fixed bits are not ADRP's */
    CHECK(nlr_program_patch_adrp(code, 4, (const uint8_t *)(base + 4096ull),
                                 0) == NLR_FORMAT);
    /* A large positive immediate rewrites cleanly. */
    put32(code + 8, adrp_instruction() | (0x7ffffu << 5));
    CHECK(nlr_program_patch_adrp(code, 8, (const uint8_t *)(base + 4096ull),
                                 0) == NLR_OK);
    CHECK(read32(code + 8) != (adrp_instruction() | (0x7ffffu << 5)));
}

/* ---- api table tests (every stage) ------------------------------------------ */

static void api_fs_and_memory_semantics(void)
{
    reset_mocks();
    reset_fixture();
    reset_exec_pool();
    CHECK(nlr_api.abi == NLR_ABI_VERSION);
    CHECK(nlr_api.mem_alloc != 0 && nlr_api.mem_free != 0);
    CHECK(nlr_api.fs_open != 0 && nlr_api.fs_read != 0 &&
          nlr_api.fs_seek != 0 && nlr_api.fs_close != 0);
    CHECK(nlr_api.ui_draw_text != 0 && nlr_api.ui_present != 0);
    CHECK(nlr_api.gfx_begin != 0 && nlr_api.gfx_end != 0);
    CHECK(nlr_api.input_poll != 0 && nlr_api.input_raw != 0);
    CHECK(nlr_api.log != 0 && nlr_api.exit != 0);
    CHECK(nlr_api.menu_register != 0);

    /* Path resolution: relative, absolute with the root prefix, refused
     * traversal, other drives, other modes and over-long paths. */
    api_file_path = NLR_PROGRAM_ROOT "APPS\\NOTE.TXT";
    memcpy(api_file, "note0123456", 11);
    api_file_len = 11;
    int fd = nlr_api.fs_open(NOTE_PATH_REL, 0);
    CHECK(fd >= 0);
    CHECK(strcmp(last_open_path, api_file_path) == 0);
    char buffer[8] = {0};
    CHECK(nlr_api.fs_read(fd, buffer, 4) == 4);
    CHECK(memcmp(buffer, "note", 4) == 0);
    /* A short read is retryable and returns what was read. */
    read_max = 2;
    CHECK(nlr_api.fs_read(fd, buffer, 4) == 2);
    CHECK(nlr_api.fs_read(fd, buffer, 4) == 2);
    read_max = 0x1000;
    CHECK(nlr_api.fs_read(fd, buffer, 4) == 3);
    CHECK(nlr_api.fs_read(fd, buffer, 0) == 0);
    /* An unknown handle is the service's failure, not a bad argument. */
    CHECK(nlr_api.fs_read(999, buffer, 4) == -NLR_API_EIO);
    CHECK(nlr_api.fs_read(fd, 0, 4) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_seek(fd, 0, 0) == 0);
    CHECK(nlr_api.fs_seek(fd, 3, 0) == 3);
    CHECK(nlr_api.fs_seek(fd, 0, 2) == 11);
    CHECK(nlr_api.fs_seek(fd, -1, 0) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_seek(fd, 0, 1) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_close(fd) == 0);

    /* Absolute path with exactly the root prefix is taken as-is. */
    api_file_path = NLR_PROGRAM_ROOT "LOGS\\NOTE.TXT";
    fd = nlr_api.fs_open(NOTE_PATH_ABS, 0);
    CHECK(fd >= 0);
    CHECK(strcmp(last_open_path, api_file_path) == 0);
    CHECK(nlr_api.fs_close(fd) == 0);
    api_file_path = 0;

    const char *rejected_paths[] = {
        "", "../EVIL", "APPS/../../EVIL", "B:\\OTHER\\X", "C:\\NLOADER\\X",
        "/ETC", "\\TMP", NLR_PROGRAM_ROOT "..\\EVIL",
    };
    for (unsigned i = 0;
         i < sizeof rejected_paths / sizeof rejected_paths[0]; i++)
        CHECK(nlr_api.fs_open(rejected_paths[i], 0) == -NLR_API_EINVAL);
    /* The other camera slot is forbidden even for an otherwise identical
     * absolute directory, regardless of the configured slot or root name. */
    char other_card_path[sizeof NOTE_PATH_ABS];
    memcpy(other_card_path, NOTE_PATH_ABS, sizeof other_card_path);
    other_card_path[0] = NLR_PROGRAM_ROOT[0] == 'A' ? 'B' : 'A';
    CHECK(nlr_api.fs_open(other_card_path, 0) == -NLR_API_EINVAL);
    char other_directory_path[sizeof NOTE_PATH_ABS];
    memcpy(other_directory_path, NOTE_PATH_ABS, sizeof other_directory_path);
    other_directory_path[3] = other_directory_path[3] == 'X' ? 'Y' : 'X';
    CHECK(nlr_api.fs_open(other_directory_path, 0) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_open(NLR_PROGRAM_ROOT, 0) == -NLR_API_EINVAL);
    /* ABI 9: the card's DCIM, for reading only. */
    char dcim_file[64];
    snprintf(dcim_file, sizeof dcim_file, "%.3sDCIM\\100NZ6_3\\DSC_0001.NEF", NLR_PROGRAM_ROOT);
    api_file_path = dcim_file;
    fd = nlr_api.fs_open("/DCIM/100NZ6_3/DSC_0001.NEF", NLR_OPEN_READ);
    CHECK(fd >= 0 && strcmp(last_open_path, dcim_file) == 0);
    CHECK(nlr_api.fs_close(fd) == 0);
    uint32_t dcim_writes = write_calls;
    CHECK(nlr_api.fs_open("/DCIM/100NZ6_3/DSC_0001.NEF", NLR_OPEN_WRITE) == -NLR_API_EACCES);
    CHECK(nlr_api.fs_open("/DCIM/100NZ6_3/DSC_0001.NEF", NLR_OPEN_UPDATE) == -NLR_API_EACCES);
    CHECK(write_calls == dcim_writes);
    api_file_path = 0;
    static const char *const dcim_refused[] = {
        "/DCIM", "/DCIM/", "/DCIM/../NLOADER/MANIFEST", "/DCIM/A:B", "/DCIMX/A", "\\NLOADER\\MANIFEST",
    };
    for (unsigned i = 0; i < sizeof dcim_refused / sizeof dcim_refused[0]; i++)
        CHECK(nlr_api.fs_open(dcim_refused[i], NLR_OPEN_READ) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_open(NLR_PROGRAM_ROOT "\\NOTE.TXT", 0) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_open(0, 0) == -NLR_API_EINVAL);
    /* ABI 4 accesses: an undefined mode is refused; a write access goes
     * through the model's own create flags, and what the program writes
     * is cleaned out of the data cache before the card reads it (the mock
     * write checks the order). */
    CHECK(nlr_api.fs_open("APPS/NOTE.TXT", 3) == -NLR_API_EINVAL);
    api_file_path = NLR_PROGRAM_ROOT "APPS\\NOTE.TXT";
    int write_fd = nlr_api.fs_open("APPS/NOTE.TXT", NLR_OPEN_WRITE);
    CHECK(write_fd >= 0);
    CHECK(nlr_api.fs_write(write_fd, "hi", 2) == 2);
    CHECK(written_len == 2 && memcmp(written, "hi", 2) == 0);
    CHECK(nlr_api.fs_write(write_fd, 0, 2) == -NLR_API_EINVAL);
    CHECK(nlr_api.fs_write(write_fd, "x", 0) == 0);
    CHECK(nlr_api.fs_write(-1, "x", 1) == -NLR_API_EBADF);
    CHECK(nlr_api.fs_close(write_fd) == 0);
    int update_fd = nlr_api.fs_open("APPS/NOTE.TXT", NLR_OPEN_UPDATE);
    CHECK(update_fd >= 0);
    CHECK(nlr_api.fs_close(update_fd) == 0);
    api_file_path = 0;

    /* The loader's own files are a program's to read and never to write:
     * MANIFEST and ENABLED decide what runs by itself next boot,
     * SAFE_MODE is the escape that stops it, and the marker is how a pass
     * that crashed the camera is recognized -- a program writing its
     * cleared byte would hide exactly that. The card ignores case, so
     * this does too. */
    static const char *const loader_own[] = {
        "MANIFEST", "ENABLED", "SAFE_MODE", "AUTOLOAD_PENDING",
        "manifest", "Enabled", "safe_mode", "autoload_pending",
        "STATE.NLS", "state.nls", "MASTER", "CORE.NLC", "CORERUN",
        "BOOT", "boot", "BOOTRUN",
        /* the loader's own log: a program could forge its lines */
        "LOADER.LOG", "loader.log", "Loader.Log",
    };
    uint32_t writes_before = write_calls;
    last_open_path[0] = 0;
    for (unsigned i = 0; i < sizeof loader_own / sizeof loader_own[0]; i++) {
        CHECK(nlr_api.fs_open(loader_own[i], NLR_OPEN_WRITE) ==
              -NLR_API_EACCES);
        CHECK(nlr_api.fs_open(loader_own[i], NLR_OPEN_UPDATE) ==
              -NLR_API_EACCES);
    }
    /* Nor under another spelling the filesystem may resolve to the same
     * file: a "." component, an empty one, a trailing dot or space. */
    static const char *const ambiguous[] = {
        "./MANIFEST", ".\\STATE.NLS", "APPS//NOTE.TXT", "MANIFEST.",
        "SAFE_MODE ", "APPS./NOTE.TXT", "APPS/",
    };
    for (unsigned i = 0; i < sizeof ambiguous / sizeof ambiguous[0]; i++) {
        CHECK(nlr_api.fs_open(ambiguous[i], NLR_OPEN_WRITE) == -NLR_API_EINVAL);
        CHECK(nlr_api.fs_open(ambiguous[i], NLR_OPEN_UPDATE) == -NLR_API_EINVAL);
    }
    CHECK(write_calls == writes_before && last_open_path[0] == 0);
    /* Reading them is not refused. */
    card_manifest_present = 1;
    int manifest_fd = nlr_api.fs_open("MANIFEST", NLR_OPEN_READ);
    CHECK(manifest_fd >= 0);
    CHECK(nlr_api.fs_close(manifest_fd) == 0);
    card_manifest_present = 0;
    api_file_path = NLR_PROGRAM_ROOT "LOADER.LOG";
    int log_fd = nlr_api.fs_open("LOADER.LOG", NLR_OPEN_READ);
    CHECK(log_fd >= 0 && strcmp(last_open_path, NLR_PROGRAM_ROOT "LOADER.LOG") == 0);
    CHECK(nlr_api.fs_close(log_fd) == 0);
    api_file_path = 0;
    char long_path[NLR_API_PATH_MAX + 2];
    for (uint32_t n = 0; n < sizeof long_path - 1; n++)
        long_path[n] = 'a';
    long_path[sizeof long_path - 1] = 0;
    CHECK(nlr_api.fs_open(long_path, 0) == -NLR_API_EINVAL);

    /* Memory routes to the service; attrs beyond the defined zero refuse. */
    void *block = nlr_api.mem_alloc(32, 0);
    CHECK(block != 0);
    CHECK(nlr_api.mem_alloc(32, 1) == 0);
    nlr_api.mem_free(block);
    nlr_api.mem_free(0);
    CHECK(alloc_calls == 1 && release_calls == 1);

    /* Unimplemented channels report instead of faking success. ui_draw_text
     * is implemented, so with no discoverable runtime it reports the
     * channel it cannot reach; ui_present still reports the missing
     * redraw trigger. */
    CHECK(nlr_api.ui_draw_text(1, 2, "x") == -NLR_API_EIO);
    CHECK(nlr_api.ui_present() == -NLR_API_ENOSYS);
    CHECK(nlr_api.gfx_begin(0) == -NLR_API_ENOSYS);
    CHECK(nlr_api.gfx_end() == -NLR_API_ENOSYS);
    CHECK(nlr_api.input_poll(0) == -NLR_API_ENOSYS);
    CHECK(nlr_api.input_raw() == 0);
    const struct nlr_menu_test_item item = {0x379u, 0x7ffdu};
    CHECK(nlr_api.menu_register(&item) == -NLR_API_EIO);
}

/* The newest 'T' length entry followed by 't' chunks, walked backwards. */
static uint32_t collect_latest_log(struct nlr_trace *t, int32_t *out_length,
                                   char *out, uint32_t out_bytes)
{
    uint32_t chunks[16];
    uint32_t chunk_total = 0;
    int32_t length = -1;
    uint64_t scanned = 0;
    while (scanned < NLR_TRACE_SLOTS && t->count > scanned) {
        scanned++;
        const union nlr_trace_entry *e =
            &t->entries[(t->count - scanned) & (NLR_TRACE_SLOTS - 1)];
        char tag = (char)(e->seq_tag & 0xFF);
        if (tag == 'T') {
            length = e->value;
            break;
        }
        if (tag == 't' && chunk_total < sizeof chunks / sizeof chunks[0])
            chunks[chunk_total++] = (uint32_t)e->value;
    }
    CHECK(length >= 0);
    *out_length = length;
    uint32_t used = 0;
    for (uint32_t i = chunk_total; i-- > 0;)
        for (uint32_t b = 0; b < 4 && used + 1 < out_bytes; b++)
            out[used++] = (char)(chunks[i] >> (8 * b));
    out[used] = 0;
    return (uint32_t)length < used ? (uint32_t)length : used;
}

static void api_log_writes_bounded_text(void)
{
    reset_mocks();
    reset_fixture();
    reset_exec_pool();
    _Alignas(NLR_CACHE_LINE) uint8_t arena[0x4000];
    struct nlr_load load = {0};
    struct nlr_task_config task = default_task();
    CHECK(nlr_load_init(&load, &nlr_services, arena, sizeof arena, &task) ==
          NLR_OK);
    registry_table[5] = &load.worker;
    nlr_api.log("c=%d %s", 42, "ok");
    int32_t length = 0;
    char text[64];
    uint32_t collected = collect_latest_log(&load.trace, &length, text,
                                            sizeof text);
    CHECK(length == 7);
    CHECK(collected == 7);
    CHECK(memcmp(text, "c=42 ok", 7) == 0);
    /* A longer message is truncated and its full length recorded. */
    load.trace.count = 0;
    nlr_api.log("%s", "0123456789012345678901234567890123456789");
    collected = collect_latest_log(&load.trace, &length, text, sizeof text);
    CHECK(length == 40);
    CHECK(collected == 32);
    CHECK(memcmp(text, "01234567890123456789012345678901", 32) == 0);
    CHECK(text[32] == 0); /* nothing beyond the truncation */
    /* Without a discoverable runtime the message is dropped, not written
     * anywhere else. */
    load.trace.count = 0;
    memset(registry_table, 0, sizeof registry_table);
    nlr_api.log("dropped");
    CHECK(load.trace.count == 0);
}

/* ui_draw_text publishes into the runtime's pending slot: truncated to the
 * row capacity, latest-wins, refused outside a discoverable runtime. */
static void api_ui_draw_text_publishes_pending_text(void)
{
    struct nlr_runtime *r = program_fixture("hello", "foreground",
                                            NLR_KIND_FOREGROUND);
    CHECK(r != 0);
    if (!r)
        return;
    char text[NLR_SLOT_TEXT_MAX + 2];
    /* With nothing running the text has no run to belong to: refused, and
     * the slot is left as it was. */
    uint32_t idle = __atomic_load_n(&r->text.generation, __ATOMIC_ACQUIRE);
    CHECK(nlr_api.ui_draw_text(0, 0, "nobody's") == -NLR_API_EBUSY);
    CHECK(__atomic_load_n(&r->text.generation, __ATOMIC_ACQUIRE) == idle);
    CHECK(nlr_text_read(&r->text, text) == 0);
    /* A run in progress (the worker's state) owns it. */
    __atomic_store_n(&r->load.state, 2, __ATOMIC_RELEASE);
    /* x and y carry no placement in the text channel; the call succeeds. */
    CHECK(nlr_api.ui_draw_text(3, 7, "Hello from hello.c") == 0);
    CHECK(nlr_text_read(&r->text, text) == 18);
    CHECK(strcmp(text, "Hello from hello.c") == 0);

    /* A longer string is truncated to the row capacity. */
    CHECK(nlr_api.ui_draw_text(0, 0, "012345678901234567890123456789"
                                     "012345678901234567890123456789") == 0);
    CHECK(nlr_text_read(&r->text, text) == NLR_SLOT_TEXT_MAX);
    CHECK(text[NLR_SLOT_TEXT_MAX] == 0);
    CHECK(text[0] == '0' && text[NLR_SLOT_TEXT_MAX - 1] == '9');

    /* Latest-wins: repeated calls leave only the last text. */
    CHECK(nlr_api.ui_draw_text(0, 0, "first") == 0);
    CHECK(nlr_api.ui_draw_text(0, 0, "second") == 0);
    CHECK(nlr_api.ui_draw_text(0, 0, "third") == 0);
    CHECK(nlr_text_read(&r->text, text) == 5);
    CHECK(strcmp(text, "third") == 0);

    /* Every publish advances the generation by two and ends even. */
    uint32_t generation = __atomic_load_n(&r->text.generation,
                                          __ATOMIC_ACQUIRE);
    CHECK((generation & 1u) == 0);
    CHECK(nlr_api.ui_draw_text(0, 0, "fourth") == 0);
    CHECK(__atomic_load_n(&r->text.generation, __ATOMIC_ACQUIRE) ==
          generation + 2);

    /* An empty string publishes an empty text: the row will show its
     * status line, not a stale content. */
    CHECK(nlr_api.ui_draw_text(0, 0, "") == 0);
    CHECK(nlr_text_read(&r->text, text) == 0);

    /* A null string is refused without publishing. */
    generation = __atomic_load_n(&r->text.generation, __ATOMIC_ACQUIRE);
    CHECK(nlr_api.ui_draw_text(0, 0, 0) == -NLR_API_EINVAL);
    CHECK(__atomic_load_n(&r->text.generation, __ATOMIC_ACQUIRE) ==
          generation);

    /* The run ends with its text still in the slot; the next start empties
     * it before that program can run, so the earlier text never shows
     * under another program's row (Z8 QEMU sp-014: hello's line on the
     * DOOM row). After the run the call is refused again. */
    CHECK(nlr_api.ui_draw_text(0, 0, "Hello from the upgraded NLoader") == 0);
    __atomic_store_n(&r->load.state, 0, __ATOMIC_RELEASE);
    CHECK(nlr_api.ui_draw_text(0, 0, "too late") == -NLR_API_EBUSY);
    CHECK(nlr_text_read(&r->text, text) > 0 &&
          strncmp(text, "Hello from the upgraded", 23) == 0);
#if defined(NLR_STAGE_EXEC) || defined(NLR_STAGE_PREPARE_ONLY)
#if defined(NLR_STAGE_EXEC)
    const uint32_t mode = 2u;
#else
    const uint32_t mode = 1u;
#endif
    CHECK(nlr_runtime_start_program(r, 0, mode) == NLR_OK);
    CHECK(nlr_text_read(&r->text, text) == 0);
    nlr_load_event(&r->load, 1);
    CHECK(__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0);
#endif

    /* Without a discoverable runtime the text is refused. */
    memset(registry_table, 0, sizeof registry_table);
    CHECK(nlr_api.ui_draw_text(0, 0, "lost") == -NLR_API_EIO);
}

#if defined(NLR_STAGE_EXEC)
#define RUN_MODE 2u
#define CALLS_PER_RUN 1u
#elif defined(NLR_STAGE_PREPARE_ONLY)
#define RUN_MODE 1u
#define CALLS_PER_RUN 0u
#endif

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)

#if defined(NLR_STAGE_EXEC)
/* ---- registry and coexistence budget scenarios (M2-T2) ---------------------- */

/* Forget every record: test teardown, not registry behavior; the blocks the
 * records name are only freed by resetting the pool with them. */
static void registry_teardown(struct nlr_runtime *r)
{
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++)
        r->resident[i].used = 0;
    reset_exec_pool();
}

/* First used record of any kind: what the resident search must not return
 * (foreground records are not resident), plus the foreground reservations
 * the budget counts. */
static const struct nlr_program_record *registry_any(struct nlr_runtime *r,
                                                     const char *id)
{
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++) {
        const struct nlr_program_record *rec = &r->resident[i];
        if (!rec->used)
            continue;
        if (id && strcmp(rec->id, id) != 0)
            continue;
        return rec;
    }
    return 0;
}

/* A program without data, BSS or relocations occupies one block. */
static void fixture_without_data(void)
{
    reloc_count = 0;
    fixture_data_len = 0;
    fixture_bss = 0;
    fixture_stamp_adrp = 0;
}

/* A data-less program of the given kind into the card or the second file. */
static void build_program(uint8_t *target, uint32_t *out_len, uint32_t kind)
{
    reset_fixture();
    fixture_without_data();
    fixture_kind = kind;
    build_program_file_into(target, out_len);
}
#endif /* exec-stage registry scenarios */

#ifndef NLR_STAGE_EXEC
/* Prepared and never entered: a spilled program whose blocks cannot be
 * released keeps its spill too, as uncertain, and every later load and
 * directory read is refused. */
static void spill_survives_uncertain_execution_cleanup(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r) return;
    fixture_image_len = 550864u;
    build_program_file();
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    uint32_t before = release_calls;
    exec_release_fail = 1;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_RESTORE && !r->load.state);
    CHECK(r->load.program.code_allocation && r->load.spill_request && r->load.spill_uncertain);
    /* Only the worker's separate MANIFEST snapshot is released. */
    CHECK(release_calls == before + 1u && r->load.arena == r->load.home_arena);
    void *retained = r->load.spill_request;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_EXEC_RESTORE);
    CHECK(nlr_runtime_read_directory(r) == NLR_EXEC_RESTORE);
    CHECK(r->load.spill_request == retained && release_calls == before + 1u);
}
#else
/* Entered: a spilled program whose blocks cannot be released afterwards.
 * The spill went back before the entry ran, while everything was still
 * certain, so none of it is left to keep: the loader's arena is its own
 * again, and the case is the one without a spill -- the blocks stay
 * recorded and refuse the next start until the state is torn down. */
static void spill_gone_before_uncertain_execution_cleanup(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r) return;
    fixture_image_len = 550864u;
    build_program_file();
    CHECK(card_len > r->load.capacity); /* this file has to spill */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    uint32_t before = release_calls;
    exec_release_fail = 1;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_RESTORE && !r->load.state);
    CHECK(r->load.program.code_allocation && !r->load.spill_request &&
          !r->load.spill_uncertain && !r->load.home_arena);
    /* The spill, at the entry, and the worker's separate MANIFEST snapshot. */
    CHECK(release_calls == before + 2u);
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_EXEC_RESTORE);
    /* Test teardown, not loader recovery. */
    memset(&r->load.program, 0, sizeof r->load.program);
    reset_exec_pool();
}
#endif

static void generic_program_full_flow(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    CHECK(r->load.state == 1 && r->load.program_mode == RUN_MODE);
    CHECK(!call_count && !r->load.program_attempted);
    CHECK(manifest_opens == 1 && program_opens == 1);
    char queued_path[NLR_PATH_BYTES];
    snprintf(queued_path, sizeof queued_path, "%s", r->path);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && r->load.state == 0);
    CHECK(r->load.program_attempted && !r->load.program_mode);
    CHECK(call_count == CALLS_PER_RUN);
    CHECK(strcmp(r->path, queued_path) == 0 &&
          strcmp(r->program_id, "prog") == 0);
#ifdef NLR_STAGE_EXEC
    CHECK(strcmp(events, "auuwuccxuiuewuuf") == 0);
    CHECK(r->load.program.returned && r->load.program.exit_code == 0);
#else
    CHECK(strcmp(events, "auuwuccxuiwuuf") == 0);
    CHECK(r->load.program.prepared && !r->load.program.returned);
#endif
    CHECK(!r->load.program.code_allocation &&
          !r->load.program.data_allocation);
    CHECK(exec_releases == 1 && exec_allocation_count == 1);
    CHECK(exec_allocation_sizes[0] == 2u * region_bytes + region_bytes / 2u - 1u);
    CHECK(!exec_live_bytes && !r->load.program.allocation_bytes);
    CHECK(nlr_runtime_resident_find(r, 0) == 0); /* nothing kept resident */
    /* A second run of the same program works from the cleared state. */
    reset_exec_pool();
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && exec_releases == 1);
    CHECK(call_count == 2 * CALLS_PER_RUN);
}

#ifdef NLR_STAGE_EXEC
/* A program larger than the loader's arena is read through the spill. Once
 * its bytes are in the program's blocks the spill goes back, before the
 * entry runs, instead of staying allocated for the whole run. */
static void spill_released_before_entry(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    fixture_image_len = 550864u;
    build_program_file();
    CHECK(card_len > r->load.capacity); /* this file has to spill */
    spill_watch = &r->load;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
    CHECK(spill_live_at_entry == 0 && !r->load.spill_request);
    spill_watch = 0;
    spill_live_at_entry = -1;
}
#endif

static void data_pointer_relocation_runs(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r) return;
    reloc_count = 3;
    reloc_fixture[2][0] = 8u;
    reloc_fixture[2][1] = DATA_LEN + 4u;
    reloc_fixture[2][2] = NLR_RELOC_ABS64_DATA;
    build_program_file();
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
    CHECK(!r->load.program.code_allocation && !r->load.program.data_allocation);
    CHECK(exec_releases == 1);
}

#ifdef NLR_STAGE_PREPARE_ONLY
/* prepare-only never calls the entry, and mode 2 is refused in this stage. */
static void prepare_only_and_mode_refusal(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_REFUSED);
    CHECK(program_opens == 0 && call_count == 0);
    CHECK(nlr_runtime_start_program(r, 0, 1) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    CHECK(r->load.program.prepared && call_count == 0);
    CHECK(exec_releases == 1);
}
#endif

/* A cleanup that cannot restore the code block keeps the shared allocation and
 * refuses every later run until the state is torn down. */
static void restore_failure_kept_and_refused(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    protect_fail_at = 3; /* the restore's protect is the third call */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_RESTORE);
    CHECK(call_count == CALLS_PER_RUN);
    CHECK(r->load.program.code_allocation != 0);
    CHECK(r->load.program.data_allocation == r->load.program.code_allocation);
    CHECK(r->load.program.allocation_bytes == 2u * region_bytes + region_bytes / 2u - 1u);
    CHECK(exec_releases == 0);
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_EXEC_RESTORE);
    CHECK(!r->load.program_mode && call_count == CALLS_PER_RUN);
    /* Test teardown, not loader recovery. */
    memset(&r->load.program, 0, sizeof r->load.program);
    reset_exec_pool();
}

/* Either clean failure prevents entry. Failures during the resulting
 * restoration, data audit or release retain the single original owner. */
static void cache_clean_failure_ownership(void)
{
    for (uint32_t clean = 1; clean <= 2; clean++) {
        for (uint32_t cleanup_failure = 0; cleanup_failure < 4; cleanup_failure++) {
            struct nlr_runtime *r = program_fixture("prog", "foreground",
                                                    NLR_KIND_FOREGROUND);
            if (!r)
                return;
            clean_fail_at = clean;
            if (cleanup_failure == 1)
                protect_fail_at = 2;
            else if (cleanup_failure == 2)
                audit_fail_at = 5;
            else if (cleanup_failure == 3)
                exec_release_fail = 1;
            CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
            nlr_load_event(&r->load, 1);
            CHECK(!call_count && !r->load.program.prepared);
            CHECK(clean_calls == clean && exec_allocation_count == 1);
            CHECK(block_flags[0] == MOCK_FLAG_W &&
                  block_flags[1] == MOCK_FLAG_W);
            CHECK(r->load.last_result ==
                  (cleanup_failure ? NLR_EXEC_RESTORE : NLR_NOT_READY));
            CHECK(exec_releases ==
                  (cleanup_failure == 0 || cleanup_failure == 3 ? 1u : 0u));
            if (cleanup_failure) {
                CHECK(r->load.program.code_allocation == exec_allocations[0]);
                CHECK(r->load.program.data_allocation == exec_allocations[0]);
                CHECK(r->load.program.allocation_bytes == 2u * region_bytes + region_bytes / 2u - 1u);
                CHECK(exec_live_bytes == r->load.program.allocation_bytes);
                CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_EXEC_RESTORE);
            } else {
                CHECK(!r->load.program.code_allocation &&
                      !r->load.program.data_allocation && !exec_live_bytes);
            }
        }
    }
}

/* Exercise both supported granules, exact-fit and one-byte-short candidates,
 * and a different allocator address on the sole permitted fallback. */
/* A short grant is held, not released, so the next request looks past it;
 * the held blocks go back once a whole region is in hand. Nothing is
 * written into a block whose grant does not cover the region, and when no
 * attempt grants one the run is refused with every block given back. */
static void short_grant_held_and_retried(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    exec_short_grants = 1;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    /* The obstacle was asked for in its own size — never the region's, which
     * would have re-mapped past it — then held while the region was taken,
     * and given back afterwards. */
    CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
    CHECK(exec_allocation_attempts == 2u && exec_allocation_count == 2u);
    CHECK(exec_allocation_sizes[0] == exec_short_bytes);
    CHECK(exec_allocation_sizes[1] > exec_short_bytes);
    CHECK(exec_allocations[0] != exec_allocations[1]);
    CHECK(exec_allocation_released[0] && exec_allocation_released[1]);
    CHECK(probe_calls_count >= 2u && grant_calls >= 1u);
    CHECK(!exec_live_bytes && !r->load.program.code_allocation);

    /* Every attempt short: the run never starts and nothing stays held. */
    r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    exec_short_grants = 8;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_NOT_READY && !call_count);
    /* Every try found another obstacle; each was taken in its own size and
     * every one given back. */
    CHECK(exec_allocation_attempts == NLR_EXEC_GRANT_TRIES);
    CHECK(exec_allocation_sizes[0] == exec_short_bytes);
    CHECK(exec_releases == exec_allocation_count);
    CHECK(!exec_live_bytes && !r->load.program.code_allocation &&
          !r->load.program.prepared && !r->load.program.entry_started);
    CHECK(!clean_calls && !audit_calls);

    /* Books that say nothing are not a licence to use the block. */
    r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    exec_grant_blind = 1;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    /* Books that say nothing: the allocator is not asked at all. */
    CHECK(r->load.last_result == NLR_NOT_READY && !call_count);
    CHECK(!exec_allocation_attempts && !exec_live_bytes);
    CHECK(!r->load.program.code_allocation);

    /* A model without the service keeps the old behaviour: one attempt, no
     * question asked. */
    r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    nlr_exec_services.grant_end = 0;
    nlr_exec_services.grant_probe = 0;
    /* (the fixture's own blocks were granted under the books before) */
    grant_calls = probe_calls_count = 0;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
    CHECK(exec_allocation_attempts == 1u && !grant_calls && !probe_calls_count);
    nlr_exec_services.grant_end = exec_grant_end;
    nlr_exec_services.grant_probe = exec_grant_probe;
}

/* SAFE_MODE that appears while a program is read is asked again before
 * anything runs, on a body without the native card as on the Z 8: the
 * card's presence store decides (load.c load_safe_guard), and with the
 * program's own file just read beside it a failed open is absence. */
/* A start the file check refuses is the program's attempt: its id, the
 * check's result and the file phase, as the budget refusals record theirs,
 * so the list and the details have something to show (a CRC failure on
 * the Z 8's SD card left both pages empty). */
static void file_refusal_recorded_as_attempt(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r) return;
    card[card_len - 1u] ^= 0x5au; /* the image's CRC no longer matches */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_CHECKSUM);
    CHECK(r->program_pending && !r->probe_pending && !r->load.state);
    CHECK(strcmp(r->program_id, "prog") == 0);
    struct nlr_outcome o;
    nlr_runtime_outcome_fill(r, &o);
    CHECK(o.result == NLR_CHECKSUM && o.phase == 'L' && !o.memory_bytes);
    CHECK(!o.returned && !o.exit_requested && !o.exit_code);
    /* kept for the id when the page moves on, as any finished attempt */
    nlr_runtime_outcome_keep(r);
    const struct nlr_outcome *kept =
        nlr_runtime_outcome_find(r, (const uint8_t *)"PROG", 4);
    CHECK(kept && kept->result == NLR_CHECKSUM);
    /* the repaired file starts normally */
    card[card_len - 1u] ^= 0x5au;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(!r->load.state);
}

static void safe_mode_rechecked_after_read(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    uint32_t opens = program_opens;
    safe_mode_after_program_open = 1;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_DISABLED && !call_count);
    CHECK(program_opens == opens + 1 && !r->load.program.code_allocation);
    safe_mode_after_program_open = safe_mode_present = 0;
    /* without it the same program runs */
    r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
}

static void bounded_alignment_allocation(void)
{
    const uint32_t granules[] = {NLR_EXEC_PAGE_SIZE, NLR_EXEC_BLOCK_SIZE};
    for (uint32_t g = 0; g < 2u; g++) {
        region_bytes = nlr_exec_services.region_bytes = granules[g];
        for (uint32_t data = 0; data < 2u; data++) {
            for (uint32_t shape = 0; shape < 5u; shape++) {
                struct nlr_runtime *r = program_fixture("prog", "foreground",
                                                        NLR_KIND_FOREGROUND);
                if (!r)
                    return;
                if (!data) {
                    fixture_data_len = fixture_bss = reloc_count = 0;
                    fixture_stamp_adrp = 0;
                    build_program_file();
                }
                uint32_t padding[] = {0u, region_bytes / 4u,
                                      region_bytes / 2u - 1u,
                                      region_bytes / 2u, region_bytes - 1u};
                exec_alignment_padding_count = 2;
                exec_alignment_padding[0] = padding[shape];
                exec_alignment_padding[1] = shape == 3u ? region_bytes - 1u : 0u;
                uint32_t attempts = shape < 3u ? 1u : 2u;
                CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
                nlr_load_event(&r->load, 1);
                CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
                CHECK(exec_allocation_attempts == attempts &&
                      exec_allocation_count == attempts && exec_releases == attempts);
                uint32_t needed = (data + 1u) * region_bytes;
                CHECK(exec_allocation_sizes[0] == needed + region_bytes / 2u - 1u);
                if (attempts == 2u) {
                    CHECK(exec_allocations[0] != exec_allocations[1]);
                    CHECK(exec_allocation_sizes[1] == needed + region_bytes - 1u);
                }
                CHECK(!exec_live_bytes && !r->load.program.code_allocation &&
                      !r->load.program.data_allocation);
                CHECK(clean_calls == data + 1u);
            }
        }
    }
    region_bytes = nlr_exec_services.region_bytes = NLR_EXEC_BLOCK_SIZE;
}

/* APPS as a Mac leaves it: each program with its AppleDouble companion. */
static uint32_t appledouble_lists;
static uint32_t enumerate_apps(const char *path, uint32_t mask,
                               uint32_t (*each)(const uint8_t *info))
{
    (void)mask;
    appledouble_lists++;
    CHECK(strcmp(path, NLR_PROGRAM_ROOT "APPS") == 0);
    const char *names[] = {"._PROG.NLB", "PROG.NLB", "._DESC.NLB"};
    for (uint32_t n = 0; n < 3; n++) {
        uint8_t info[128] = {0};
        for (uint32_t q = 0; names[n][q]; q++)
            info[16 + q * 2] = (uint8_t)names[n][q];
        if (each(info))
            return 0;
    }
    return 99;
}

/* The loader's own listing of APPS leaves the "._" companions out: none
 * is opened, and the programs are the ones it had. A program's own
 * directory calls are not this listing and still see them. */
static void appledouble_files_left_out_of_the_listing(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    uint32_t count = r->directory.count;
    mock_program_services.fs_enum = enumerate_apps;
    mock_program_services.enum_done = 99;
    mock_program_services.mask_files = 32;
    mock_program_services.attr_directory = 16;
    mock_program_services.info_long = 16;
    mock_program_services.info_long_unit = 2;
    mock_program_services.info_attr = 80;
    mock_program_services.info_size = 88;
    appledouble_lists = 0;
    appledouble_opens = 0;
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    CHECK(appledouble_lists == 1u && appledouble_opens == 0u);
    CHECK(r->directory.count == count);
    char names[4 * NLR_DIRENT_NAME_MAX];
    CHECK(nlr_program_dir_all(r, NLR_PROGRAM_ROOT "APPS", names, 4) == 3);
    CHECK(strcmp(names, "._PROG.NLB") == 0);
    mock_program_services.fs_enum = 0;
}

/* The heap's own aligned entry (allocate_aligned): exactly `bytes` on the
 * boundary, nothing kept around them; refused, or answered off the
 * boundary, as a test asks. */
static uint32_t exec_aligned_mode; /* 0 places, 1 refuses, 2 off the boundary */
static uint32_t exec_aligned_calls;

static int32_t exec_allocate_aligned(uint32_t alignment, uint32_t bytes, void **out)
{
    record('m');
    exec_aligned_calls++;
    CHECK(alignment == region_bytes && bytes % region_bytes == 0);
    *out = 0;
    if (exec_aligned_mode == 1u || exec_allocation_count >= 8u)
        return -1;
    uint8_t *at = aligned_page(exec_pool + exec_used) + (exec_aligned_mode == 2u ? 64u : 0u);
    size_t base = (size_t)(at - exec_pool);
    if (base > sizeof exec_pool || (size_t)bytes > sizeof exec_pool - base)
        return -1;
    *out = at;
    exec_used = base + bytes;
    exec_allocations[exec_allocation_count] = at;
    exec_allocation_sizes[exec_allocation_count++] = bytes;
    exec_live_bytes += bytes;
    for (uint32_t n = 0; exec_aligned_mode == 0u && n < bytes / region_bytes; n++) {
        CHECK(block_count < 8u);
        if (block_count >= 8u)
            return -1;
        block_pages[block_count] = at + n * region_bytes;
        block_flags[block_count++] = MOCK_FLAG_W;
    }
    return 0;
}

/* With the heap's aligned entry the regions are asked for exactly: no
 * slack request, the blocks on the boundary, all of it back after the run.
 * A refusal falls to the slack method (a fragmented heap may still meet
 * its larger request); an answer off the boundary goes straight back. */
static void aligned_entry_places_the_regions(void)
{
    for (uint32_t mode = 0; mode < 3u; mode++) {
        for (uint32_t data = 0; data < 2u; data++) {
            struct nlr_runtime *r = program_fixture("prog", "foreground",
                                                    NLR_KIND_FOREGROUND);
            if (!r)
                return;
            if (!data) {
                fixture_data_len = fixture_bss = reloc_count = 0;
                fixture_stamp_adrp = 0;
                build_program_file();
            }
            nlr_exec_services.grant_end = 0;
            nlr_exec_services.grant_probe = 0;
            nlr_exec_services.allocate_aligned = exec_allocate_aligned;
            exec_aligned_mode = mode;
            exec_aligned_calls = 0;
            uint32_t needed = (data + 1u) * region_bytes;
            CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
            nlr_load_event(&r->load, 1);
            CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
            CHECK(exec_aligned_calls == 1u);
            if (mode == 0u) {
                CHECK(exec_allocation_attempts == 0u && exec_allocation_count == 1u);
                CHECK(exec_allocation_sizes[0] == needed);
                CHECK(((uintptr_t)exec_allocations[0] & (region_bytes - 1u)) == 0);
                CHECK(exec_releases == 1u);
            } else {
                /* the slack method's first request after it */
                uint32_t slack = mode == 2u ? 1u : 0u;
                CHECK(exec_allocation_attempts == 1u);
                CHECK(exec_allocation_count == slack + 1u);
                CHECK(exec_allocation_sizes[slack] == needed + region_bytes / 2u - 1u);
                CHECK(exec_releases == slack + 1u);
            }
            CHECK(!exec_live_bytes && !r->load.program.code_allocation &&
                  !r->load.program.data_allocation);
            nlr_exec_services.allocate_aligned = 0;
            nlr_exec_services.grant_end = exec_grant_end;
            nlr_exec_services.grant_probe = exec_grant_probe;
        }
    }
    exec_aligned_mode = 0;
}

/* The mock heap's next grant, in book mode; exec_books_skew bytes away
 * from where it really is makes books that turn out wrong. */
static uint32_t exec_books_skew;

static uint64_t exec_grant_next(uint64_t *guard)
{
    if (!exec_books || !guard)
        return 0;
    *guard = 0;
    return (uint64_t)(uintptr_t)(exec_pool + exec_used) + exec_books_skew;
}

/* Where the books say where the next grant starts, the regions are placed
 * exactly: a filler takes the bytes in front of the next boundary, the
 * regions take what they need and no slack, and the filler goes back before
 * the program runs. Books that turn out wrong cost nothing: what was taken
 * goes back and the slack method runs, the whole allowance first. */
static void exact_placement_from_the_books(void)
{
    for (uint32_t skew = 0; skew < 2u; skew++) {
        struct nlr_runtime *r = program_fixture("prog", "foreground",
                                                NLR_KIND_FOREGROUND);
        if (!r)
            return;
        nlr_exec_services.grant_next = exec_grant_next;
        exec_books = 1;
        exec_books_skew = skew ? NLR_EXEC_PAGE_SIZE : 0u;
        exec_used = (size_t)(aligned_page(exec_pool) - exec_pool) +
                    region_bytes / 4u + 0x3000u;
        uint8_t *next = exec_pool + exec_used;
        uint8_t *boundary = aligned_page(next);
        uint32_t needed = 2u * region_bytes;
        CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
        nlr_load_event(&r->load, 1);
        CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
        if (!skew) {
            CHECK(exec_allocation_count == 2u);
            CHECK(exec_allocations[0] == next &&
                  exec_allocation_sizes[0] == (uint32_t)(boundary - next));
            CHECK(exec_allocations[1] == boundary &&
                  exec_allocation_sizes[1] == needed);
        } else {
            CHECK(exec_allocation_count == 3u);
            CHECK(exec_allocation_sizes[2] == needed + region_bytes - 1u);
        }
        CHECK(exec_releases == exec_allocation_count && !exec_live_bytes);
        CHECK(!r->load.program.code_allocation && clean_calls == 2u);
        exec_books = exec_books_skew = 0;
        nlr_exec_services.grant_next = 0;
    }
}

/* Allocation failure never causes a larger request. A failed release of a
 * short candidate keeps its exact owner and is never retried or freed twice. */
static void alignment_retry_failure_ownership(void)
{
    for (uint32_t failure = 0; failure < 3u; failure++) {
        struct nlr_runtime *r = program_fixture("prog", "foreground",
                                                NLR_KIND_FOREGROUND);
        if (!r)
            return;
        exec_alignment_padding_count = 2;
        exec_alignment_padding[0] = region_bytes - 1u;
        exec_alignment_padding[1] = 0;
        if (failure == 0)
            exec_alloc_fail_at = 1;
        else if (failure == 1)
            exec_alloc_fail_at = 2;
        else
            exec_release_fail = 1;
        CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
        nlr_load_event(&r->load, 1);
        CHECK(!call_count && !clean_calls && !audit_calls && !protect_calls);
        CHECK(exec_allocation_attempts == (failure == 1 ? 2u : 1u));
        CHECK(exec_releases == (failure == 0 ? 0u : 1u));
        CHECK(r->load.last_result == (failure == 2 ? NLR_EXEC_RESTORE : NLR_NOT_READY));
        if (failure == 2) {
            CHECK(r->load.program.code_allocation == exec_allocations[0]);
            CHECK(r->load.program.allocation_bytes == exec_allocation_sizes[0]);
            CHECK(!r->load.program.code_page && !r->load.program.data_page);
            CHECK(exec_live_bytes == exec_allocation_sizes[0]);
            CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_EXEC_RESTORE);
            CHECK(exec_allocation_attempts == 1 && exec_releases == 1);
        } else {
            CHECK(!exec_live_bytes && !r->load.program.code_allocation);
        }
    }
}

/* A relocation that does not produce a legal ADRP encoding is rejected at
 * execution time, after which both blocks are restored and released. */
static void bad_adrp_rejected_at_exec(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    for (uint32_t n = 0; n < IMAGE_LEN; n++)
        image_fixture[n] = (uint8_t)(n * 7 + 3);
    put32(image_fixture + IMAGE_ADRP_OFFSET, 0xd503201fu); /* NOP */
    fixture_stamp_adrp = 0; /* the builder must not restore the ADRP */
    build_program_file();
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_FORMAT);
    CHECK(call_count == 0);
    CHECK(strcmp(events, "auuwuwuuf") == 0);
    CHECK(exec_releases == 1 && !r->load.program.code_allocation);
}

#endif /* prepare/exec stage scenarios */

#if defined(NLR_STAGE_EXEC)

/* The allocator can still grant short after the probe said it would not:
 * nothing locks the heap between the question and the request, and this
 * allocator maps the whole span it was asked for. When that happens the
 * blocks a resident extension still holds are looked over and whatever
 * permission they lost is put back — the extension's code was executable
 * and must stay so, because the firmware may be inside it. */
/* An extension resident with its code and data blocks, and a code-only
 * foreground program ready to run beside it: the shape each of the cases
 * below starts from. The mock pool is a bump allocator that never reuses
 * what a run gave back, so each case takes a fresh one. */
static struct nlr_runtime *resident_plus_foreground(int *code_index,
                                                    int *data_index)
{
    struct nlr_runtime *r = program_fixture("ext", "resource_extension",
                                            NLR_KIND_RESOURCE_EXTENSION);
    if (!r)
        return 0;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    const struct nlr_program_record *resident =
        nlr_runtime_resident_find(r, "ext");
    CHECK(resident != 0 && resident->code_block && resident->data_block);
    if (!resident)
        return 0;
    *code_index = exec_block_index(resident->code_block);
    *data_index = exec_block_index(resident->data_block);
    CHECK(*code_index >= 0 && *data_index >= 0);
    CHECK(block_flags[*code_index] == MOCK_FLAG_X);
    set_manifest("ext | resource_extension | Ext | APPS/PROG.NLB | 2 | "
                 "z8/3.11\napp | foreground | App | APPS/FO.NLB | 2 | "
                 "z8/3.11\n");
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    fixture_kind = NLR_KIND_FOREGROUND;
    fixture_data_len = fixture_bss = reloc_count = 0;
    fixture_stamp_adrp = 0;
    build_program_file_into(card2, &card2_len);
    card2_path = NLR_PROGRAM_ROOT "APPS\\FO.NLB";
    nlr_exec_services.program_budget_blocks = 4u;
    return r;
}

/* The allocator can still grant short after the probe said it would not:
 * nothing locks the heap between the question and the request, and this
 * allocator maps the whole span it was asked for. When that happens the
 * blocks a resident extension still holds are looked over and whatever
 * permission they lost is put back -- the extension's code was executable
 * and must stay so, because the firmware may be inside it. */
static void short_grant_restores_resident_permissions(void)
{
    int code_index = -1, data_index = -1;

    /* The region the run really wants, overtaken between probe and
     * request. */
    struct nlr_runtime *r = resident_plus_foreground(&code_index, &data_index);
    if (!r)
        return;
    block_flags[code_index] = MOCK_FLAG_W;
    exec_grant_race = 1;
    uint32_t restored_before = r->resident_restored;
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->resident_restored == restored_before + 1u);
    CHECK(block_flags[code_index] == MOCK_FLAG_X);
    CHECK(block_flags[data_index] == MOCK_FLAG_W);
    CHECK(!r->resident_unrepaired);
    /* The short block itself was never used: it was held, the run went on
     * with a block the allocator really granted, and everything the run
     * borrowed went back. */
    CHECK(r->load.last_result == NLR_OK && !r->load.program.code_allocation);
    exec_grant_race = 0;
    nlr_exec_services.program_budget_blocks = 2u;
    registry_teardown(r);

    /* The block taken out of the way, overtaken the same way. It is asked
     * for in its own size so its mapping should stay inside it, but that
     * size came from a probe taken a moment earlier, and the heap is not
     * locked in between: the grant is read back for it too. */
    r = resident_plus_foreground(&code_index, &data_index);
    if (!r)
        return;
    block_flags[code_index] = MOCK_FLAG_W;
    exec_short_grants = exec_allocation_count + 1u;
    exec_grant_race = 1;
    restored_before = r->resident_restored;
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->resident_restored == restored_before + 1u);
    CHECK(block_flags[code_index] == MOCK_FLAG_X && !r->resident_unrepaired);
    CHECK(r->load.last_result == NLR_OK);
    exec_short_grants = 0;
    exec_grant_race = 0;
    nlr_exec_services.program_budget_blocks = 2u;
    registry_teardown(r);

    /* And a repair that does not take is not counted as one: the camera
     * is left with a resident extension whose code is not what the loader
     * put there, and the firmware may be about to call into it. Only the
     * second counter says so. */
    r = resident_plus_foreground(&code_index, &data_index);
    if (!r)
        return;
    block_flags[code_index] = MOCK_FLAG_W;
    exec_grant_race = 1;
    protect_fail_at = protect_calls + 1u;
    restored_before = r->resident_restored;
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->resident_restored == restored_before);
    CHECK(r->resident_unrepaired == 1u);
    CHECK(block_flags[code_index] == MOCK_FLAG_W);
    protect_fail_at = 0;
    exec_grant_race = 0;
    nlr_exec_services.program_budget_blocks = 2u;
    registry_teardown(r);
}

/* A foreground program may hook the firmware, but its handler lives in a
 * block that goes back when it ends. The loader removes what the program
 * left — a detour into freed memory would take the camera down on the
 * next call through that function, long after the program is gone. */
static void foreground_hook_goes_back_with_its_block(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    call_installs_hook = 1;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(hook_install_result == 0);
    CHECK(r->load.last_result == NLR_OK && call_count == CALLS_PER_RUN);
    /* The program never unhooked, and the firmware's bytes are back. */
    CHECK(r->hooks.count == 0);
    for (uint32_t n = 0; n < 4u; n++)
        CHECK(code_get_word(mock_text + CODE_TARGET_OFFSET + 4u * n) ==
              code_target_words[n]);
    CHECK(exec_releases == 1u && !r->load.program.code_allocation);

    /* The same hook, and the channel refuses to put the bytes back: the
     * program's block is kept instead of being released under a live
     * detour, and every later run is refused. */
    r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    call_installs_hook = call_breaks_unhook = 1;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_RESTORE);
    CHECK(r->hooks.count == 1);
    CHECK(code_get_word(mock_text + CODE_TARGET_OFFSET) == 0x58000050u);
    CHECK(!exec_releases && r->load.program.code_allocation);
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_EXEC_RESTORE);
    code_translate_fail = 0;
    call_installs_hook = call_breaks_unhook = 0;
}

/* Foreground returning an error, and api->exit: both clean up like a normal
 * return and surface the status. */
static void foreground_error_and_exit_returns(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    call_return_value = 5;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_APP);
    CHECK(r->load.program.returned && r->load.program.exit_code == 5);
    CHECK(exec_releases == 1 && !r->load.program.code_allocation);
    CHECK(nlr_runtime_resident_find(r, 0) == 0);

    r = program_fixture("prog", "foreground", NLR_KIND_FOREGROUND);
    if (!r)
        return;
    call_uses_exit = 1;
    call_exit_code = 42;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_APP);
    CHECK(r->load.program.exit_requested && r->load.program.exit_code == 42);
    CHECK(r->load.program.returned);
    CHECK(exec_releases == 1 && nlr_runtime_resident_find(r, 0) == 0);
    call_uses_exit = 0;
}

/* An extension that initializes successfully keeps its blocks; the runtime
 * records them, a foreground program can still run afterwards, and a second
 * extension is refused while the slot is used. */
static void extension_kept_and_refused_second(void)
{
    struct nlr_runtime *r = program_fixture("ext", "resource_extension",
                                            NLR_KIND_RESOURCE_EXTENSION);
    if (!r)
        return;
    call_return_value = 0;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    CHECK(r->load.program.kept == 0); /* the loader cleared the state */
    CHECK(exec_releases == 0); /* nothing released for a kept extension */
    CHECK(r->load.program.code_allocation == 0); /* state cleared for reuse */
    const struct nlr_program_record *resident =
        nlr_runtime_resident_find(r, "ext");
    CHECK(resident != 0 && resident->used);
    CHECK(resident->kind == NLR_KIND_RESOURCE_EXTENSION);
    CHECK(resident->abi_version == 2u);
    CHECK(resident->code_block != 0 && resident->data_block != 0);
    CHECK(resident->allocation == exec_allocations[0]);
    CHECK(resident->allocation_bytes == 2u * region_bytes + region_bytes / 2u - 1u);
    CHECK((uint8_t *)resident->data_block ==
          (uint8_t *)resident->code_block + region_bytes);
    CHECK(nlr_runtime_resident_find(r, "other") == 0);
    CHECK(nlr_runtime_resident_find(r, 0) == resident);

    /* A second extension is refused before anything runs. */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_BUSY);
    CHECK(!r->load.program_mode && r->load.state == 0);
    CHECK(call_count == CALLS_PER_RUN);

    /* A foreground program runs anyway: it gets its own blocks, and the
     * resident extension's ownership record survives it. */
    set_manifest("ext | resource_extension | Ext | APPS/PROG.NLB | 2 | "
                 "z8/3.11\napp | foreground | App | APPS/FO.NLB | 2 | "
                 "z8/3.11\n");
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    fixture_kind = NLR_KIND_FOREGROUND;
    build_program_file_into(card2, &card2_len);
    card2_path = NLR_PROGRAM_ROOT "APPS\\FO.NLB";
    /* The default two-block budget is fully spent by the kept extension:
     * the two-block foreground is refused before anything runs, and no
     * record changes. */
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_EXEC_BUDGET);
    CHECK(!r->load.program_mode && r->load.state == 0);
    CHECK(r->load.last_result == NLR_EXEC_BUDGET && r->program_pending);
    CHECK(call_count == CALLS_PER_RUN);
    CHECK(nlr_runtime_resident_find(r, "ext") == resident);
    CHECK(registry_any(r, "app") == 0); /* the refusal registered nothing */
    /* With budget headroom the same foreground runs beside the extension. */
    nlr_exec_services.program_budget_blocks = 4u;
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    CHECK(exec_releases == 1);
    CHECK(call_count == 2 * CALLS_PER_RUN);
    CHECK(nlr_runtime_resident_find(r, "ext") == resident);
    CHECK(resident->code_block != 0 && resident->data_block != 0);
    CHECK(registry_any(r, "app") != 0); /* finished, not yet observed */
    nlr_runtime_settle_records(r);
    CHECK(registry_any(r, "app") == 0);
    nlr_exec_services.program_budget_blocks = 2u;

    /* The kept extension still holds its blocks; release them for teardown
     * by forgetting the record and resetting the pool. */
    registry_teardown(r);
}

/* An allocator with 9 MiB available can hold a data-bearing extension and a
 * code-only foreground with the shared alignment allowance. Two data-bearing
 * programs still exceed this capacity and must fail before the second entry. */
static void data_extension_coexists_under_allocator_limit(void)
{
    struct nlr_runtime *r = program_fixture("ext", "resource_extension",
                                            NLR_KIND_RESOURCE_EXTENSION);
    if (!r)
        return;
    exec_byte_budget = 9u << 20;
    nlr_exec_services.program_budget_blocks = 4u;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && call_count == 1);
    const struct nlr_program_record *resident = nlr_runtime_resident_find(r, "ext");
    CHECK(resident != 0 && resident->allocation != 0);
    if (!resident)
        return;
    struct nlr_program_record kept = *resident;
    uint8_t code_before[IMAGE_LEN], data_before[DATA_LEN + 8u];
    memcpy(code_before, resident->code_block, sizeof code_before);
    memcpy(data_before, resident->data_block, sizeof data_before);
    CHECK(exec_live_bytes == 2u * region_bytes + region_bytes / 2u - 1u);
    set_manifest("ext | resource_extension | Ext | APPS/PROG.NLB | 2 | "
                 "z8/3.11\napp | foreground | App | APPS/FO.NLB | 2 | z8/3.11\n");
    card2_path = NLR_PROGRAM_ROOT "APPS\\FO.NLB";
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);

    /* The refused request leaves the existing allocation and program intact. */
    reset_fixture();
    build_program_file_into(card2, &card2_len);
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_NOT_READY && call_count == 1);
    CHECK(exec_allocation_count == 1 && !exec_releases);
    CHECK(memcmp(resident, &kept, sizeof kept) == 0);
    nlr_runtime_settle_records(r);
    CHECK(registry_any(r, "app") == 0);

    build_program(card2, &card2_len, NLR_KIND_FOREGROUND);
    for (uint32_t attempt = 0; attempt < 2; attempt++) {
        CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
        nlr_load_event(&r->load, 1);
        CHECK(r->load.last_result == NLR_OK && call_count == attempt + 2u);
        CHECK(exec_releases == attempt + 1u && !exec_allocation_released[0]);
        CHECK(exec_live_bytes == kept.allocation_bytes);
        CHECK(memcmp(resident, &kept, sizeof kept) == 0);
        CHECK(memcmp(resident->code_block, code_before, sizeof code_before) == 0);
        CHECK(memcmp(resident->data_block, data_before, sizeof data_before) == 0);
        CHECK(block_flags[0] == MOCK_FLAG_X && block_flags[1] == MOCK_FLAG_W);
        nlr_runtime_settle_records(r);
        CHECK(registry_any(r, "app") == 0);
    }
    registry_teardown(r);
}

/* An extension that reports failure keeps its blocks too (they may already
 * be partially effective); the record marks it, and api->exit from an
 * extension is recorded and ignored. */
static void extension_failure_and_ignored_exit(void)
{
    struct nlr_runtime *r = program_fixture("ext", "resource_extension",
                                            NLR_KIND_RESOURCE_EXTENSION);
    if (!r)
        return;
    call_return_value = 7;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_APP);
    CHECK(exec_releases == 0); /* not released: possibly partially effective */
    CHECK(r->load.program.code_allocation == 0); /* state still cleared */
    const struct nlr_program_record *resident =
        nlr_runtime_resident_find(r, "ext");
    CHECK(resident != 0 && resident->used && resident->failed);
    CHECK(resident->code_block != 0 && resident->data_block != 0);
    /* A failed extension stops later extensions the same way. */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_BUSY);
    registry_teardown(r);

    r = program_fixture("ext", "resource_extension",
                        NLR_KIND_RESOURCE_EXTENSION);
    if (!r)
        return;
    call_return_value = 0;
    call_uses_exit = 1;
    exit_returns = 1; /* the extension's exit request is ignored */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    CHECK(!r->load.program.exit_requested); /* recorded, not followed */
    CHECK(nlr_runtime_resident_find(r, "ext") != 0);
    call_uses_exit = 0;
    exit_returns = 0;
    /* The kept extension still holds its blocks; forget it for teardown. */
    registry_teardown(r);
}

/* The foreground record: registered when the run is queued, untouched by a
 * refusal while it is in flight, cleared at the next observation after the
 * run ended, and its released blocks available again. */
static void foreground_registered_and_cleared(void)
{
    struct nlr_runtime *r = program_fixture("app", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    CHECK(r->load.state == 1);
    const struct nlr_program_record *rec = registry_any(r, "app");
    CHECK(rec != 0);
    CHECK(rec->kind == NLR_KIND_FOREGROUND);
    CHECK(rec->abi_version == 2u && !rec->failed);
    CHECK(rec->code_block == 0 && rec->data_block == 0); /* nothing ran yet */
    CHECK(rec->allocation == 0 && rec->allocation_bytes == 0);
    CHECK(rec->code_bytes == NLR_EXEC_BLOCK_SIZE);
    CHECK(rec->data_bytes == NLR_EXEC_BLOCK_SIZE); /* the fixture has data */
    /* A second start while the run is queued is BUSY and rewrites nothing. */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_BUSY);
    CHECK(registry_any(r, "app") == rec);
    CHECK(rec->code_bytes == NLR_EXEC_BLOCK_SIZE);

    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK && r->load.state == 0);
    CHECK(exec_releases == 1); /* the foreground's single owner was released */
    /* The run itself does not clear the record; the next observation does.
     * The resident search never returns a foreground record. */
    CHECK(registry_any(r, "app") == rec);
    CHECK(nlr_runtime_resident_find(r, "app") == 0);
    nlr_runtime_settle_records(r);
    CHECK(registry_any(r, "app") == 0);
    CHECK(nlr_runtime_resident_find(r, 0) == 0);

    /* The released blocks are available again: the count fell back with the
     * release, not merely with the observation. */
    reset_exec_pool();
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    nlr_runtime_settle_records(r);
    CHECK(registry_any(r, "app") == 0);
    registry_teardown(r);
}

/* The registry/budget matrix: foreground and extension interleave, the
 * budget boundary is exact, one block over is refused in both directions,
 * and residents keep counting after a failed initialization. */
static void budget_and_registry_matrix(void)
{
    reset_mocks();
    reset_exec_pool();
    build_program(card, &card_len, NLR_KIND_RESOURCE_EXTENSION);
    build_program(card2, &card2_len, NLR_KIND_FOREGROUND);
    card2_path = NLR_PROGRAM_ROOT "APPS\\FO.NLB";
    set_manifest("ext | resource_extension | Ext | APPS/PROG.NLB | 2 | "
                 "z8/3.11\napp | foreground | App | APPS/FO.NLB | 2 | "
                 "z8/3.11\n");
    nlr_exec_services.program_max_resident = 2u;
    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);
    CHECK(r != 0);
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);

    /* The data-less extension takes one block; exactly one remains. */
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    const struct nlr_program_record *ext = nlr_runtime_resident_find(r, "ext");
    CHECK(ext != 0 && ext->code_block != 0 && !ext->failed);
    CHECK(ext->code_bytes == NLR_EXEC_BLOCK_SIZE);
    CHECK(ext->data_block == 0 && ext->data_bytes == 0);
    CHECK(exec_releases == 0); /* nothing released for a kept extension */

    /* A two-block foreground is one block over the budget: refused, and
     * the registry is untouched. */
    reset_fixture();
    fixture_kind = NLR_KIND_FOREGROUND;
    build_program_file_into(card2, &card2_len);
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_EXEC_BUDGET);
    CHECK(!r->load.program_mode && r->load.state == 0);
    CHECK(r->load.last_result == NLR_EXEC_BUDGET && r->program_pending);
    CHECK(call_count == CALLS_PER_RUN);
    CHECK(nlr_runtime_resident_find(r, "ext") == ext);
    CHECK(registry_any(r, "app") == 0);

    /* A one-block foreground fits the remaining budget exactly: foreground
     * and extension coexist. */
    build_program(card2, &card2_len, NLR_KIND_FOREGROUND);
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    CHECK(exec_releases == 1); /* only the foreground's code block */
    CHECK(call_count == 2 * CALLS_PER_RUN);
    CHECK(nlr_runtime_resident_find(r, "ext") == ext);
    CHECK(registry_any(r, "app") != 0);
    nlr_runtime_settle_records(r);
    CHECK(registry_any(r, "app") == 0);

    /* A two-block extension is one block over as well. */
    reset_fixture();
    fixture_kind = NLR_KIND_RESOURCE_EXTENSION;
    build_program_file();
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_EXEC_BUDGET);
    CHECK(nlr_runtime_resident_find(r, "ext") == ext);
    CHECK(registry_any(r, "app") == 0);

    /* The released foreground freed its block: the count fell back, and the
     * one-block foreground starts again. */
    build_program(card2, &card2_len, NLR_KIND_FOREGROUND);
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    nlr_runtime_settle_records(r);
    registry_teardown(r);
    nlr_exec_services.program_max_resident = 1u;

    /* A failed initialization is kept and keeps counting (PLAN 5.1): with
     * the two-block budget spent by the failed extension, nothing else
     * starts. */
    r = program_fixture("ext", "resource_extension",
                        NLR_KIND_RESOURCE_EXTENSION);
    if (!r)
        return;
    call_return_value = 5;
    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_EXEC_APP);
    const struct nlr_program_record *failed = nlr_runtime_resident_find(r, "ext");
    CHECK(failed != 0 && failed->failed && failed->code_block != 0);
    build_program(card2, &card2_len, NLR_KIND_FOREGROUND);
    card2_path = NLR_PROGRAM_ROOT "APPS\\FO.NLB";
    set_manifest("ext | resource_extension | Ext | APPS/PROG.NLB | 2 | "
                 "z8/3.11\napp | foreground | App | APPS/FO.NLB | 2 | "
                 "z8/3.11\n");
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_EXEC_BUDGET);
    CHECK(nlr_runtime_resident_find(r, "ext") == failed);
    registry_teardown(r);
}

/* The resident limit spans the whole registry: two extensions fit a raised
 * limit, the third is refused and rewrites nothing, and a foreground still
 * runs beside the residents within the raised budget. */
static void extension_limit_across_slots(void)
{
    reset_mocks();
    reset_exec_pool();
    build_program(card, &card_len, NLR_KIND_RESOURCE_EXTENSION);
    build_program(card2, &card2_len, NLR_KIND_FOREGROUND);
    card2_path = NLR_PROGRAM_ROOT "APPS\\FO.NLB";
    set_manifest("ext1 | resource_extension | E1 | APPS/PROG.NLB | 2 | "
                 "z8/3.11\next2 | resource_extension | E2 | APPS/PROG.NLB | "
                 "2 | z8/3.11\next3 | resource_extension | E3 | "
                 "APPS/PROG.NLB | 2 | z8/3.11\n"
                 "app | foreground | App | APPS/FO.NLB | 2 | z8/3.11\n");
    nlr_exec_services.program_budget_blocks = 4u;
    nlr_exec_services.program_max_resident = 2u;
    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);
    CHECK(r != 0);
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);

    CHECK(nlr_runtime_start_program(r, 0, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    const struct nlr_program_record *first =
        nlr_runtime_resident_find(r, "ext1");
    CHECK(first != 0 && first->code_block != 0);
    CHECK(nlr_runtime_start_program(r, 1, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    const struct nlr_program_record *second =
        nlr_runtime_resident_find(r, "ext2");
    CHECK(second != 0 && second != first);

    /* The limit counts resident extensions, not table slots: the third is
     * refused and neither resident record changes. */
    CHECK(nlr_runtime_start_program(r, 2, RUN_MODE) == NLR_BUSY);
    CHECK(r->load.last_result == NLR_BUSY && r->program_pending);
    CHECK(call_count == 2 * CALLS_PER_RUN);
    CHECK(nlr_runtime_resident_find(r, "ext1") == first);
    CHECK(nlr_runtime_resident_find(r, "ext2") == second);
    CHECK(nlr_runtime_resident_find(r, "ext3") == 0);
    CHECK(nlr_runtime_resident_find(r, 0) == first);

    /* A foreground still runs beside the two residents. */
    CHECK(nlr_runtime_start_program(r, 3, RUN_MODE) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result == NLR_OK);
    CHECK(exec_releases == 1);
    CHECK(nlr_runtime_resident_find(r, "ext1") == first);
    CHECK(nlr_runtime_resident_find(r, "ext2") == second);
    nlr_runtime_settle_records(r);
    CHECK(registry_any(r, "app") == 0);
    registry_teardown(r);
    nlr_exec_services.program_budget_blocks = 2u;
    nlr_exec_services.program_max_resident = 1u;
}

#if defined(NLR_STAGE_EXEC)
static void set_enabled(const char *text)
{
    card_enabled_len = (uint32_t)strlen(text);
    memcpy(card_enabled, text, card_enabled_len);
    card_enabled_present = 1;
}

/* MANIFEST order is intentionally different from the saved init order. */
static struct nlr_runtime *autoload_fixture(void)
{
    reset_mocks();
    reset_exec_pool();
    build_program(card, &card_len, NLR_KIND_RESOURCE_EXTENSION);
    set_manifest(
        "one | resource_extension | One | APPS/PROG.NLB | 2 | z8/3.11\n"
        "three | resource_extension | Three | APPS/PROG.NLB | 2 | z8/3.11\n"
        "two | resource_extension | Two | APPS/PROG.NLB | 2 | z8/3.11\n"
        "app | foreground | App | APPS/APP.NLB | 2 | z8/3.11\n");
    set_enabled("two\none\nthree\n");
    nlr_exec_services.program_budget_blocks = 3;
    nlr_exec_services.program_max_resident = 3;
    struct nlr_runtime *r = 0;
    CHECK(nlr_runtime_create(&r, &nlr_services, ARENA_CAP) == NLR_OK);
    CHECK(r != 0);
    return r;
}

/* NLOADER/BOOT: the foreground program it names starts once the pass has
 * finished (here at once: ENABLED names nothing), BOOTRUN records the start,
 * and a start that never reported back is skipped once. */
/* The fixture's MANIFEST names app APPS/APP.NLB: a foreground image there. */
static void boot_app_image(void)
{
    fixture_kind = NLR_KIND_FOREGROUND;
    fixture_data_len = fixture_bss = reloc_count = 0;
    fixture_stamp_adrp = 0;
    build_program_file_into(card2, &card2_len);
    card2_path = NLR_PROGRAM_ROOT "APPS\\APP.NLB";
}

/* NLOADER/MASTER off: the pass stops before anything on the card is written
 * -- no pending marker, no BOOTRUN, no settings -- and before ENABLED is
 * read; the directory is still listed so the page can say the loader is off.
 * Shared by both bodies: the native card's first STATE.NLS migration sits
 * behind the same check (runtime.c autoload_open). */
static void master_off_writes_nothing(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    boot_app_image();
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    card_master_off = 1;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_DISABLED);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
    CHECK(r->autoload.result == NLR_DISABLED && r->autoload.enabled_result == NLR_DISABLED);
    CHECK(r->directory.error == NLR_MF_SWITCHED_OFF);
    CHECK(!marker_writes && !marker_removes && !settings_writes && !bootrun_writes);
    CHECK(!strchr(card_operations, 'E') && !strchr(card_operations, 'W') &&
          !strchr(card_operations, 'B'));
    CHECK(r->load.state == 0 && !program_opens && !call_count);
    /* the switch is read before the pass asks the store anything */
    CHECK(!probe_calls);
    /* and the loader's own log stays in RAM */
    CHECK(!r->load.journal || __atomic_load_n(&r->load.journal->held, __ATOMIC_ACQUIRE));
    /* a second visit (the page, a later checkpoint) changes nothing */
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_DISABLED);
    CHECK(!marker_writes && !settings_writes && !bootrun_writes);
    registry_teardown(r);

    /* switched back on: the same card runs its pass and boot program */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(master_opens && bootrun_writes == 1);
    registry_teardown(r);
}

static void boot_program_starts_once_the_pass_is_done(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE);
    CHECK(r->autoload.boot_result == NLR_OK && r->autoload.boot_hold == 1);
    CHECK(bootrun_writes == 1 && card_bootrun_len == 3 && memcmp(card_bootrun, "run", 3) == 0);
    CHECK(r->load.state != 0 && r->load.program_mode == 2);
    registry_teardown(r);

    /* The last start never wrote "ok": this boot skips it, once. */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "App\n", 4);
    card_boot_len = 4;
    memcpy(card_bootrun, "run", 3);
    card_bootrun_len = 3;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.boot_result == NLR_AUTOLOAD_PAUSED && !r->autoload.boot_hold);
    CHECK(bootrun_writes == 1 && card_bootrun_len == 7 && memcmp(card_bootrun, "skipped", 7) == 0);
    CHECK(r->load.state == 0 && !program_opens);
    registry_teardown(r);

    /* "ok" (it ran well) starts it again. */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "app", 3);
    card_boot_len = 3;
    memcpy(card_bootrun, "ok", 2);
    card_bootrun_len = 2;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.boot_result == NLR_OK && r->load.state != 0);
    registry_teardown(r);

    /* BOOT naming anything but a foreground program starts nothing. */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "one\n", 4);
    card_boot_len = 4;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(!bootrun_writes && r->load.state == 0 && !r->autoload.boot_hold);
    registry_teardown(r);

    /* No BOOT: nothing written, nothing started. */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(boot_opens == 1 && !bootrun_writes && r->load.state == 0);
    registry_teardown(r);

    /* The stock GUI task, held at the checkpoint while the program runs,
     * goes back to its loop once the program has ended. */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->load.state == 0);
    r->autoload.boot_hold = 1; /* as a program that has just ended leaves it */
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(!r->autoload.boot_hold);
    registry_teardown(r);

    /* A paused boot (the marker left on the card) does not even read BOOT. */
    r = autoload_fixture();
    if (!r)
        return;
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    pending_present = 1;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
    CHECK(!boot_opens && !bootrun_writes && r->load.state == 0);
    registry_teardown(r);
}

/* A store that keeps the boot record in its own journal (the native card's
 * STATE.NLS format 2), here beside the ordinary marker methods the pass
 * needs on this build. Results are queued per set; zero is success. */
static struct nlr_boot_mark journal_mark, journal_written[4];
static int32_t journal_get_result, journal_set_results[4];
static uint32_t journal_gets, journal_sets;

static int32_t journal_get(struct nlr_boot_mark *out)
{
    journal_gets++;
    card_operation('g');
    if (journal_get_result)
        return journal_get_result;
    *out = journal_mark;
    return NLR_OK;
}

static int32_t journal_set(const struct nlr_boot_mark *mark)
{
    uint32_t n = journal_sets++;
    card_operation('s');
    if (n < 4u)
        journal_written[n] = *mark;
    int32_t result = n < 4u ? journal_set_results[n] : NLR_OK;
    if (result == NLR_OK)
        journal_mark = *mark;
    return result;
}

static const struct nlr_card_store journal_store = {
    .probe = store_probe, .replace = store_replace, .remove = store_remove,
    .boot_mark_get = journal_get, .boot_mark_set = journal_set,
};

/* The queue_wait shell: an event comes a second after the good time, and
 * whether the OK was already written then is noted. */
static struct nlr_runtime *wait_runtime;
static uint64_t wait_from;
static uint32_t wait_posted, ok_while_waiting;
static uint32_t activity_calls;
static void count_activity(void) { activity_calls++; }

static void wait_hook(void)
{
    if (!wait_runtime || wait_posted || fake_now - wait_from < NLR_BOOT_GOOD_MS + 1000u)
        return;
    ok_while_waiting = journal_sets == 2 && journal_written[1].mark == NLR_BOOT_MARK_OK;
    struct nlr_event ev = {.type = NLR_EV_TIMER};
    wait_posted = nlr_platform_post(&wait_runtime->plat, &ev) == 0;
}

static struct nlr_runtime *journal_fixture(uint32_t mark, const char *id)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return 0;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "APP\n", 4);
    card_boot_len = 4;
    memset(&journal_mark, 0, sizeof journal_mark);
    memset(journal_written, 0, sizeof journal_written);
    memset(journal_set_results, 0, sizeof journal_set_results);
    journal_mark.mark = mark;
    strcpy(journal_mark.id, id);
    journal_get_result = 0;
    journal_gets = journal_sets = 0;
    return r;
}

/* The boot record reports the start's outcome: OK when the entry ran and
 * the program ended well or was still running after NLR_BOOT_GOOD_MS,
 * FAILED with the result otherwise -- on the worker, once. A store with a
 * journal keeps it there (with the program's id) and BOOTRUN is never
 * touched; an ordinary card keeps the BOOTRUN words. */
static void boot_record_reports_the_outcome(void)
{
    /* BOOTRUN: "run", then "ok" once the program has ended well. */
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_OWED && bootrun_writes == 1);
    nlr_load_event(&r->load, 1);
    CHECK(r->load.state == 0 && r->load.last_result == NLR_OK && r->load.program.entry_started);
    CHECK(bootrun_writes == 2 && card_bootrun_len == 2 && memcmp(card_bootrun, "ok", 2) == 0);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_DONE && r->autoload.boot_record_result == NLR_OK);
    /* nothing more: a later completion or settle writes nothing */
    nlr_runtime_boot_completed(r);
    nlr_runtime_boot_mark_settle(r);
    CHECK(bootrun_writes == 2);
    registry_teardown(r);

    /* BOOTRUN: a program refused at its start (its header check finds the
     * file inconsistent) is "failed" at once, and nothing runs. */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    card2[card2_len - 1u] ^= 1u;
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.boot_result != NLR_OK && !r->autoload.boot_hold && r->load.state == 0);
    CHECK(bootrun_writes == 2 && card_bootrun_len == 6 && memcmp(card_bootrun, "failed", 6) == 0);
    registry_teardown(r);

    /* BOOTRUN: one that the worker cannot read (before its entry) is
     * "failed" when the worker reports back; the next boot tries again. */
    r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK && r->autoload.boot_hold);
    fail_next_read = 1;
    nlr_load_event(&r->load, 1);
    fail_next_read = 0;
    CHECK(r->load.state == 0 && r->load.last_result != NLR_OK && !r->load.program.entry_started);
    CHECK(bootrun_writes == 2 && card_bootrun_len == 6 && memcmp(card_bootrun, "failed", 6) == 0);
    registry_teardown(r);

    /* Journal: RUN with the MANIFEST spelling of the id, before the start
     * is queued; OK after; BOOTRUN never written or read. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(journal_gets == 1 && journal_sets == 1 && !bootrun_writes);
    CHECK(journal_written[0].mark == NLR_BOOT_MARK_RUN && !journal_written[0].result);
    CHECK(strcmp(journal_written[0].id, "app") == 0);
    CHECK(r->autoload.boot_result == NLR_OK && r->autoload.boot_hold && r->load.state != 0);
    nlr_load_event(&r->load, 1);
    CHECK(journal_sets == 2 && journal_written[1].mark == NLR_BOOT_MARK_OK);
    CHECK(strcmp(journal_written[1].id, "app") == 0 && !bootrun_writes);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_DONE);
    registry_teardown(r);

    /* Journal: RUN left by the last boot -- of any program, as BOOTRUN has
     * it -- skips the start once and records SKIPPED; the program file is
     * not opened. */
    r = journal_fixture(NLR_BOOT_MARK_RUN, "other");
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(r->autoload.boot_result == NLR_AUTOLOAD_PAUSED && !r->autoload.boot_hold);
    CHECK(journal_sets == 1 && journal_written[0].mark == NLR_BOOT_MARK_SKIPPED);
    CHECK(strcmp(journal_written[0].id, "app") == 0);
    CHECK(r->load.state == 0 && !program_opens && r->autoload.boot_record == NLR_BOOT_RECORD_DONE);
    registry_teardown(r);
    /* ...and the boot after that starts it (SKIPPED is no RUN). */
    r = journal_fixture(NLR_BOOT_MARK_SKIPPED, "app");
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(r->autoload.boot_result == NLR_OK && journal_written[0].mark == NLR_BOOT_MARK_RUN);
    registry_teardown(r);

    /* Journal: a record that cannot be read guards nothing, so nothing
     * starts and nothing is written. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    journal_get_result = NLR_IO;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(r->autoload.boot_result == NLR_IO && !journal_sets && r->load.state == 0);
    CHECK(!r->autoload.boot_hold && r->autoload.boot_record == NLR_BOOT_RECORD_DONE);
    CHECK(r->autoload.boot_decided);
    registry_teardown(r);

    /* Journal: a RUN that is not confirmed durable (refused, or uncertain:
     * the store's own uncertainty) stops the start before it is queued. */
    for (uint32_t which = 0; which < 2u; which++) {
        r = journal_fixture(NLR_BOOT_MARK_OK, "app");
        if (!r)
            return;
        journal_set_results[0] = which ? -111 /* COMMIT_UNCERTAIN */ : NLR_IO;
        CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
        CHECK(r->autoload.boot_result == journal_set_results[0]);
        CHECK(journal_sets == 1 && r->load.state == 0 && !program_opens);
        CHECK(!r->autoload.boot_hold && !r->plat.shell);
        CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_DONE);
        registry_teardown(r);
    }

    /* Journal: a start refused before it is queued is FAILED at once. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    nlr_exec_services.program_budget_blocks = 0;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(r->autoload.boot_result != NLR_OK && r->load.state == 0 && !r->autoload.boot_hold);
    CHECK(journal_sets == 2 && journal_written[1].mark == NLR_BOOT_MARK_FAILED);
    CHECK(journal_written[1].result == r->autoload.boot_result);
    registry_teardown(r);

    /* Journal: an outcome the store was too busy to take is retried by the
     * next settle, once. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    journal_set_results[1] = NLR_BUSY;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(journal_sets == 2 && r->autoload.boot_record == NLR_BOOT_RECORD_DUE);
    CHECK(journal_mark.mark == NLR_BOOT_MARK_RUN);
    nlr_runtime_boot_mark_settle(r);
    CHECK(journal_sets == 3 && journal_written[2].mark == NLR_BOOT_MARK_OK);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_DONE && journal_mark.mark == NLR_BOOT_MARK_OK);
    nlr_runtime_boot_mark_settle(r);
    CHECK(journal_sets == 3);
    registry_teardown(r);

    /* Journal: a busy store at the start's own record -- its read, then
     * its RUN write -- puts the start off to the next settle instead of
     * skipping the boot program, and the start goes ahead once the store
     * answers. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    journal_get_result = NLR_BUSY;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_START && !r->autoload.boot_decided);
    CHECK(!journal_sets && r->load.state == 0 && r->autoload.boot_result != NLR_BUSY);
    journal_get_result = 0;
    journal_set_results[0] = NLR_BUSY;
    nlr_runtime_boot_mark_settle(r);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_START && !r->autoload.boot_decided);
    CHECK(journal_sets == 1 && r->load.state == 0);
    nlr_runtime_boot_mark_settle(r);
    CHECK(journal_sets == 2 && journal_written[1].mark == NLR_BOOT_MARK_RUN);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_OWED && r->autoload.boot_decided);
    CHECK(r->autoload.boot_result == NLR_OK && r->load.state != 0 && r->autoload.boot_hold);
    nlr_load_event(&r->load, 1);
    CHECK(journal_sets == 3 && journal_written[2].mark == NLR_BOOT_MARK_OK);
    registry_teardown(r);

    /* ...and a store still busy NLR_BOOT_START_WAIT_MS after the first try
     * gives the start up, decided and with the reason, not silently. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    journal_get_result = NLR_BUSY;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_START);
    r->autoload.boot_start_ms = nlr_clock_ms() - NLR_BOOT_START_WAIT_MS;
    nlr_runtime_boot_mark_settle(r);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_DONE && r->autoload.boot_decided);
    CHECK(r->autoload.boot_result == NLR_BUSY && !journal_sets && r->load.state == 0);
    nlr_runtime_boot_mark_settle(r);
    CHECK(journal_gets == 2 && !journal_sets);
    registry_teardown(r);

    /* Journal: still running NLR_BOOT_GOOD_MS after the start is OK, written
     * at the program's wait; its later failure does not overwrite it. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    r->autoload.boot_record_ms = nlr_clock_ms() - NLR_BOOT_GOOD_MS - 1u;
    call_sleeps = 1;
    nlr_load_event(&r->load, 1);
    CHECK(r->load.last_result != NLR_OK); /* the wait failed: no wait service */
    CHECK(journal_sets == 2 && journal_written[1].mark == NLR_BOOT_MARK_OK);
    registry_teardown(r);
    /* Journal: a shell that waits in queue_wait(NLR_QUEUE_FOREVER) from its
     * first second is recorded OK once it has run NLR_BOOT_GOOD_MS -- while
     * it is still waiting, not only at a wait's entry (it never comes back
     * to one) nor only when it ends. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    fixture_abi = 7u; /* queue_wait is ABI 7 */
    boot_app_image();
    fake_time = 1;
    fake_now = 1000u;
    wait_runtime = r;
    wait_from = fake_now;
    wait_posted = ok_while_waiting = 0;
    delay_hook = wait_hook;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    CHECK(journal_sets == 1 && journal_written[0].mark == NLR_BOOT_MARK_RUN);
    call_waits = 1;
    /* ...and while the screen is the program's (here: claimed), its wait
     * tells the camera about user activity once a second, through the
     * body's one activity entry, so standby does not cut it off. */
    mock_platform_scan.bank_base = 8;
    mock_platform_scan.bank_stride = 20;
    mock_platform_scan.banks = 1;
    mock_platform_scan.object = mock_scan_object;
    mock_platform_scan.activity = count_activity;
    mock_platform_services.scan = &mock_platform_scan;
    activity_calls = 0;
    r->plat.claimed = 1;
    nlr_load_event(&r->load, 1);
    r->plat.claimed = 0;
    CHECK(activity_calls >= 10u && activity_calls <= 12u);
    CHECK(wait_posted && ok_while_waiting && call_waits == 1);
    CHECK(journal_sets == 2 && journal_written[1].mark == NLR_BOOT_MARK_OK);
    CHECK(r->autoload.boot_record == NLR_BOOT_RECORD_DONE && r->load.state == 0);
    registry_teardown(r);
    /* The same wait with the screen not the program's: no activity, the
     * camera's standby runs as in stock. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    fixture_abi = 7u;
    boot_app_image();
    fake_now += 1000u;
    wait_from = fake_now;
    wait_posted = 0;
    wait_runtime = r;
    activity_calls = 0;
    call_waits = 1;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(wait_posted && call_waits == 1 && !activity_calls);
    mock_platform_scan.activity = 0;
    mock_platform_services.scan = 0;
    call_waits = 0;
    fixture_abi = 2u;
    delay_hook = 0;
    wait_runtime = 0;
    fake_time = 0;
    registry_teardown(r);
    /* ...and before that time a wait writes nothing; the failure that ends
     * the program is the outcome. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_OK);
    call_sleeps = 1;
    nlr_load_event(&r->load, 1);
    CHECK(journal_sets == 2 && journal_written[1].mark == NLR_BOOT_MARK_FAILED);
    CHECK(journal_written[1].result == r->load.last_result && r->load.last_result != NLR_OK);
    call_sleeps = 0;
    registry_teardown(r);

    /* SAFE_MODE: the pass stops; BOOT is not read, no record written. */
    r = journal_fixture(NLR_BOOT_MARK_NONE, "");
    if (!r)
        return;
    safe_mode_present = 1;
    CHECK(nlr_runtime_autoload_begin(r, &journal_store) == NLR_DISABLED);
    CHECK(!boot_opens && !journal_gets && !journal_sets && r->load.state == 0);
    registry_teardown(r);
}

/* The start-up escape for the native card's checkpoint (no boot hook):
 * the buttons are read before the card, and only once the hook that sees
 * every scan is in. */
static void boot_escape_waits_for_the_scan_hook(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    /* No escape key declared: nothing to wait for. */
    CHECK(nlr_runtime_boot_escape(r) == NLR_OK);
    /* The Z8 shape: the key in services.program.keys, the object under
     * services.platform.scan, the scan carried by the exit callback. */
    mock_program_services.keys[9].bank = 0;
    mock_program_services.keys[9].mask = 0x40u;
    mock_platform_scan.bank_base = 8;
    mock_platform_scan.bank_stride = 20;
    mock_platform_scan.banks = 1;
    mock_platform_scan.object = mock_scan_object;
    mock_platform_services.scan = &mock_platform_scan;
    mock_scan_object[2] = 0x40u; /* DISP held since power-on */
    exit_services.input_callback = &input_callback;
    input_callback = 0; /* the input task has not registered its callback */
    CHECK(nlr_runtime_boot_escape(r) == NLR_NOT_READY);
    CHECK(!r->autoload.boot_escape && !probe_calls && !manifest_opens);
    input_callback = original_input;
    CHECK(nlr_runtime_boot_escape(r) == NLR_DISABLED);
    CHECK(input_callback == nlr_runtime_exit_input && r->exit_original_input == original_input);
    CHECK(r->autoload.boot_escape);
    /* latched: letting go later does not undo it, and the pass's own guard
     * honours it as well (the same rule as the boot checkpoint's) */
    mock_scan_object[2] = 0;
    CHECK(nlr_runtime_boot_escape(r) == NLR_DISABLED);
    CHECK(!probe_calls && !manifest_opens && !marker_writes);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_DISABLED);
    CHECK(!marker_writes && !program_opens);
    registry_teardown(r);

    /* Only a hold at power-on is the escape: a press after
     * NLR_BOOT_ESCAPE_MS of the first look (no card in, the boot still
     * asking) is not latched, so a card put in later still loads. */
    r = autoload_fixture();
    if (!r)
        return;
    mock_program_services.keys[9].bank = 0;
    mock_program_services.keys[9].mask = 0x40u;
    mock_platform_scan.bank_base = 8;
    mock_platform_scan.bank_stride = 20;
    mock_platform_scan.banks = 1;
    mock_platform_scan.object = mock_scan_object;
    mock_platform_services.scan = &mock_platform_scan;
    exit_services.input_callback = &input_callback;
    input_callback = original_input;
    mock_scan_object[2] = 0;
    CHECK(nlr_runtime_boot_escape(r) == NLR_OK && r->autoload.boot_escape_seen);
    r->autoload.boot_escape_from = nlr_clock_ms() - NLR_BOOT_ESCAPE_MS - 1u;
    mock_scan_object[2] = 0x40u;
    CHECK(nlr_runtime_boot_escape(r) == NLR_OK && !r->autoload.boot_escape);
    mock_scan_object[2] = 0;
    CHECK(nlr_runtime_boot_escape(r) == NLR_OK);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_READY && marker_writes == 1);
    registry_teardown(r);

    /* Not held: go on. A slot holding something other than the stock
     * occupant is never taken, and the pass keeps waiting (as boot_step
     * waits for its hook). */
    r = autoload_fixture();
    if (!r)
        return;
    mock_program_services.keys[9].bank = 0;
    mock_program_services.keys[9].mask = 0x40u;
    mock_platform_scan.bank_base = 8;
    mock_platform_scan.bank_stride = 20;
    mock_platform_scan.banks = 1;
    mock_platform_scan.object = mock_scan_object;
    mock_platform_services.scan = &mock_platform_scan;
    exit_services.input_callback = &input_callback;
    input_callback = original_input;
    CHECK(nlr_runtime_boot_escape(r) == NLR_OK && !r->autoload.boot_escape);
    registry_teardown(r);
    reset_mocks();
}

/* The escape that needs no computer: the button held while the loader
 * would start loading answers exactly as SAFE_MODE does, and before the
 * card is asked anything at all. */
static void autoload_escape_key_answers_like_safe_mode(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    hold_keys(0x40u);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_DISABLED);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
    CHECK(!probe_calls && !manifest_opens && !marker_writes);
    CHECK(!pending_present && !call_count && !program_opens);
    CHECK(nlr_runtime_autoload_step(r) == NLR_DISABLED);

    /* Another button is not the escape, and the same card then runs its
     * pass as usual. */
    r = autoload_fixture();
    if (!r)
        return;
    hold_keys(0x80u);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_READY && marker_writes == 1);
    registry_teardown(r);

    /* And a model that cannot say which buttons are held never escapes by
     * accident: no scan object, no keys. */
    r = autoload_fixture();
    if (!r)
        return;
    CHECK(!mock_program_services.input_object);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_READY);
    registry_teardown(r);
}

/* One extension, the way the camera really runs one: a page visit starts
 * the first, and from then on the worker takes in what each extension did
 * and starts the next itself, so there is no moment between two of them
 * for anything else to happen in. After the last one the same worker
 * clears the marker, which is what makes a single page visit enough. */
static void autoload_run_one(struct nlr_runtime *r)
{
    if (r->autoload.phase == NLR_AUTOLOAD_READY)
        CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_WAITING && r->load.state == 1);
    CHECK(nlr_runtime_autoload_step(r) == NLR_BUSY);
    nlr_load_event(&r->load, 1);
}

/* Two tasks ask to carry the pass at once -- the worker after a load, the
 * menu task on a page visit -- and the step they would both take is not
 * one that may be taken twice: both would start the same extension and
 * the loser's busy would stop the pass with its marker still on the card,
 * or both would move past the same one and leave it unloaded. Only one of
 * them steps; the other says it has something new and leaves, and the one
 * holding it looks again before stopping. */
static void autoload_one_driver_at_a_time(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    /* From here every step has a second caller inside it. */
    reenter_continue = 1;
    nlr_runtime_autoload_continue(r);          /* the page visit */
    CHECK(r->autoload.phase == NLR_AUTOLOAD_WAITING && r->load.state == 1);
    for (uint32_t n = 0; n < 3; n++)
        nlr_load_event(&r->load, 1);           /* the worker, three times */
    reenter_continue = 0;
    /* The interleaving really happened, and the pass is untouched by it:
     * three extensions, in the saved order, each exactly once, and the
     * marker cleared by whoever held the pass last. */
    CHECK(reenter_calls > 0);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE && !pending_present);
    CHECK(call_count == 3 && dispatch_calls == 3 && marker_removes == 1);
    CHECK(strcmp(initialized_ids[0], "two") == 0);
    CHECK(strcmp(initialized_ids[1], "one") == 0);
    CHECK(strcmp(initialized_ids[2], "three") == 0);
    for (uint32_t n = 0; n < 3; n++)
        CHECK(r->autoload.item[n] == NLR_EXTENSION_LOADED);
    /* Nothing is left holding it. */
    CHECK(!r->autoload.driver && !r->autoload.pending);
    registry_teardown(r);
}

#if defined(NLR_STAGE_EXEC)
/* The input task's callback slot, which its owner fills while the camera
 * starts: until then the scan the escape is read from may not exist. */
static void (*mock_input_slot)(void *);
static void mock_input_original(void *object)
{
    (void)object;
}

/* A boot checkpoint opens the pass by itself, without the page: once the
 * input hook is in and MANIFEST opens. A card that is still mounting is
 * asked on the turns that are powers of two, and once the pass is open the
 * worker carries it to the end as it does after a page visit. */
static void boot_checkpoint_waits_for_buttons_and_card(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    mock_input_slot = 0;
    mock_program_services.input_slot = &mock_input_slot;
    mock_program_services.input_original = mock_input_original;
    CHECK(nlr_program_io_wanted() && !r->io.hooked);
    /* The slot is still empty: no turn counts and the card is not asked. */
    for (uint32_t n = 0; n < 5; n++)
        nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(!r->io.hooked && !r->autoload.boot_turns && !manifest_asks);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_NEW && !r->autoload.boot_done);
    /* Filled: the hook goes in on the next turn. The card is mounting:
     * asked on turns 1, 2, 4 and 8, and nothing else is asked. */
    mock_input_slot = mock_input_original;
    manifest_ready = 0;
    for (uint32_t n = 0; n < 10; n++)
        nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(r->io.hooked && mock_input_slot == nlr_program_input);
    CHECK(r->autoload.boot_turns == 10 && manifest_asks == 4);
    CHECK(strcmp(card_operations, "MMMM") == 0);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_NEW && !r->autoload.boot_done);
    CHECK(!marker_writes && !call_count);
    /* MANIFEST opens: turn 16 opens the pass and starts the first one. */
    manifest_ready = 1;
    for (uint32_t n = 0; n < 6; n++)
        nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(manifest_asks == 5 && r->autoload.boot_done);
    CHECK(r->autoload.store == &card_store && marker_writes == 1);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_WAITING && r->load.state == 1);
    /* The worker, three times: all three in the saved order, then the
     * marker is cleared -- nobody opened the page. */
    for (uint32_t n = 0; n < 3; n++)
        nlr_load_event(&r->load, 1);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE && !pending_present);
    CHECK(call_count == 3 && marker_removes == 1);
    CHECK(strcmp(initialized_ids[0], "two") == 0);
    CHECK(strcmp(initialized_ids[2], "three") == 0);
    /* Finished for this boot: later turns ask the card nothing. */
    uint32_t operations = card_operation_count;
    for (uint32_t n = 0; n < 100; n++)
        nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(card_operation_count == operations && manifest_asks == 5);
    CHECK(!r->autoload.driver && !r->autoload.pending);
    mock_program_services.input_slot = 0;
    mock_program_services.input_original = 0;
    registry_teardown(r);
}

/* A card that never answers -- none in the slot, or no loader directory --
 * is asked twelve times, the last on turn 2048, and then left alone; the
 * page opens the pass exactly as before. A model whose buttons do not come
 * through the hook does not wait for one. */
static void boot_checkpoint_leaves_a_silent_card_to_the_page(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    CHECK(!nlr_program_io_wanted());
    manifest_ready = 0;
    for (uint32_t n = 0; n < 5000; n++)
        nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(manifest_asks == 12 && r->autoload.boot_turns == 2048);
    CHECK(r->autoload.boot_done && r->autoload.phase == NLR_AUTOLOAD_NEW);
    CHECK(!probe_calls && !marker_writes && !call_count);
    CHECK(!r->autoload.store);
    manifest_ready = 1;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_READY && marker_writes == 1);
    registry_teardown(r);
}

/* The native card's checkpoint (native_card.c menu_turn) opens the pass
 * itself and asks the card on boot_step's turns, counted in time
 * (NLR_BOOT_TURN_MS each from its first turn): powers of two, twelve asks
 * with no card, then none until a page visit allows one more. A card
 * without the loader's directory ends the asking at once. With a release
 * bundle that has a BOOT, the bundle's turn comes at boot turn 64 with no
 * card, or at once for a card without a directory. `step_ms` apart, from
 * clock 5000 on. */
static uint32_t native_asks(struct nlr_runtime *r, uint32_t turns, uint32_t step_ms,
                            int mounted)
{
    uint32_t asks = 0;
    for (uint32_t n = 0; n < turns; n++)
        if (nlr_runtime_boot_ask_due(r, 5000u + n * step_ms)) {
            asks++;
            nlr_runtime_boot_no_card(r, mounted);
        }
    return asks;
}

static void native_checkpoint_asks_like_boot_step(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    /* one turn per boot turn: exactly the Z 6III's asks */
    CHECK(native_asks(r, 5000, NLR_BOOT_TURN_MS, 0) == 12 && r->autoload.boot_turns == 2048);
    CHECK(r->autoload.boot_done && r->autoload.phase == NLR_AUTOLOAD_NEW);
    CHECK(!r->autoload.boot_decided && !r->autoload.boot_bundled && !call_count);
    CHECK(r->autoload.boot_first_ms == 5000u);
    nlr_runtime_boot_ask_again(r);
    CHECK(native_asks(r, 100, NLR_BOOT_TURN_MS, 0) == 1 && r->autoload.boot_done);
    CHECK(r->autoload.boot_turns == 1);
    registry_teardown(r);
    /* turns far apart (15 s, as the emulator's menu checkpoint): each turn
     * that crosses the next power of two asks once; 12 asks are reached
     * only when boot turn 2048 is, about two minutes in, as on the Z 6III */
    r = autoload_fixture();
    if (!r)
        return;
    CHECK(native_asks(r, 7, 15000u, 0) == 5 && !r->autoload.boot_done);
    CHECK(native_asks(r, 1000, 15000u, 0) == 1 && r->autoload.boot_done);
    CHECK(r->autoload.boot_asks == 6 && r->autoload.boot_turns >= 2048);
    registry_teardown(r);

    r = autoload_fixture();
    if (!r)
        return;
    CHECK(native_asks(r, 100, NLR_BOOT_TURN_MS, 1) == 1 && r->autoload.boot_done &&
          r->autoload.boot_turns == 1 && !r->autoload.boot_asks);
    registry_teardown(r);

    /* a bundle whose BOOT names nothing loadable: the turn comes, the boot
     * is decided by what boot_bundle finds, and the asking ends there */
    static _Alignas(8) uint8_t bundle[0x100];
    memset(bundle, 0, sizeof bundle);
    memcpy(bundle, "NLBB", 4);
    bundle[4] = 1;
    bundle[6] = 32;
    put32(bundle + 8, 1);
    memcpy(bundle + 0x20, "BOOT", 4);
    put32(bundle + 0x20 + 16, 0x80);
    put32(bundle + 0x20 + 20, 5);
    memcpy(bundle + 0x80, "none\n", 5);
    put32(bundle + 0x20 + 24, nlr_platform_crc32(bundle + 0x80, 5));
    put32(bundle + 12, 0xc0);
    put32(bundle + 16, nlr_platform_crc32(bundle + 0x20, 32));
#define WITH_BUNDLE()                                       \
    do {                                                    \
        mock_platform_services.bundle = bundle;             \
        mock_platform_services.bundle_bytes = sizeof bundle; \
    } while (0)
    r = autoload_fixture();
    if (r) {
        WITH_BUNDLE();
        CHECK(native_asks(r, 5000, NLR_BOOT_TURN_MS, 0) == 7 && r->autoload.boot_turns == 64);
        CHECK(r->autoload.boot_done && r->autoload.boot_asks == 6 && !call_count);
        registry_teardown(r);
    }
    r = autoload_fixture();
    if (r) {
        WITH_BUNDLE();
        CHECK(native_asks(r, 5000, NLR_BOOT_TURN_MS, 1) == 1 && r->autoload.boot_done &&
              !call_count);
        registry_teardown(r);
    }
    /* DISP latched: the bundle's turn starts nothing */
    r = autoload_fixture();
    if (r) {
        WITH_BUNDLE();
        r->autoload.boot_escape = 1;
        CHECK(native_asks(r, 5000, NLR_BOOT_TURN_MS, 1) == 1 &&
              r->autoload.boot_result == NLR_DISABLED);
        registry_teardown(r);
    }
    /* DISP down at the bundle's turn but not held at power-on (not
     * latched): not the escape, and nothing is decided -- the next ask
     * starts the bundle once DISP is up (Z8 QEMU qemu-fc-202: the press
     * itself brought the turn, and the bundle was skipped for the boot). */
    r = autoload_fixture();
    if (r) {
        WITH_BUNDLE();
        hold_keys(0x40u);
        CHECK(nlr_runtime_boot_ask_due(r, 5000u));
        nlr_runtime_boot_no_card(r, 1);
        CHECK(!r->autoload.boot_done && !r->autoload.boot_decided && !r->autoload.boot_escape);
        CHECK(r->autoload.boot_result != NLR_DISABLED);
        hold_keys(0);
        CHECK(nlr_runtime_boot_ask_due(r, 5000u + 2u * NLR_BOOT_TURN_MS));
        nlr_runtime_boot_no_card(r, 1);
        CHECK(r->autoload.boot_done && r->autoload.boot_result != NLR_DISABLED);
        registry_teardown(r);
    }
#undef WITH_BUNDLE
    /* a busy store at a step: the pass waits for its next step, it does
     * not stop and leave the pending mark (QEMU qemu-ki-019, -022) */
    r = autoload_fixture();
    if (r) {
        manifest_ready = 1;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK &&
              r->autoload.phase == NLR_AUTOLOAD_READY && pending_present);
        probe_busy = 1;
        CHECK(nlr_runtime_autoload_step(r) == NLR_BUSY);
        CHECK(r->autoload.phase == NLR_AUTOLOAD_READY && !r->load.state && !call_count);
        probe_busy = 0;
        CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
        CHECK(r->autoload.phase == NLR_AUTOLOAD_WAITING && r->load.state == 1);
        registry_teardown(r);
    }
    /* the native checkpoint's single step waits for the worker's driver */
    r = autoload_fixture();
    if (r) {
        r->autoload.driver = 1u;
        r->autoload.pending = 0u;
        CHECK(nlr_runtime_autoload_step_owned(r) == NLR_BUSY && r->autoload.pending == 1u);
        CHECK(!call_count && !r->load.state && r->autoload.driver == 1u);
        r->autoload.driver = 0u;
        CHECK(nlr_runtime_autoload_step_owned(r) == NLR_NOT_READY && !r->autoload.driver);
        registry_teardown(r);
    }
    mock_platform_services.bundle = 0;
    mock_platform_services.bundle_bytes = 0;
}

/* DISP held from power-on: the pass opens, the escape answers like
 * SAFE_MODE, and nothing but MANIFEST was asked. */
static void boot_checkpoint_escape_held_from_power_on(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    hold_keys(0x40u);
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(r->autoload.boot_done && r->autoload.phase == NLR_AUTOLOAD_STOPPED);
    CHECK(r->autoload.result == NLR_DISABLED);
    CHECK(manifest_asks == 1 && !probe_calls && !marker_writes);
    CHECK(!call_count && !program_opens && !pending_present);
    registry_teardown(r);
}

/* Two openers: a page visit that opened the pass first leaves the
 * checkpoint nothing to do, and an opener that finds the driver held
 * changes nothing and leaves the pass to the holder. */
static void boot_checkpoint_and_page_open_it_once(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(r->autoload.boot_done && !manifest_asks && marker_writes == 1);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_READY);
    registry_teardown(r);

    r = autoload_fixture();
    if (!r)
        return;
    r->autoload.driver = 1;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_BUSY);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_NEW && !probe_calls && !marker_writes);
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(r->autoload.boot_done && manifest_asks == 1);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_NEW && !marker_writes);
    r->autoload.driver = 0;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_READY && !r->autoload.driver);
    registry_teardown(r);
}

/* The entry the build points the stock call at: it makes that call and
 * returns its value, makes the runtime on the first turn and only finds
 * it on the next, and asks the ordinary card store. */
static uint32_t flag_getter_calls;
static void *mock_flag_getter(void)
{
    flag_getter_calls++;
    return (void *)(uintptr_t)0x5ca1ab1eu;
}
const struct nlr_boot_autoload nlr_boot_autoload = {
    .call_site = 0x1000u,
    .callee = mock_flag_getter,
};

static void boot_checkpoint_entry_keeps_the_stock_call(void)
{
    reset_mocks();
    reset_exec_pool();
    flag_getter_calls = 0;
    CHECK(nlr_runtime_find(&nlr_services, 0) == 0);
    open_fail = 1; /* the card is still mounting */
    CHECK(nlr_boot_autoload_checkpoint() == (void *)(uintptr_t)0x5ca1ab1eu);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    CHECK(r != 0 && flag_getter_calls == 1);
    if (!r)
        return;
    CHECK(r->autoload.boot_asks == 1 && r->autoload.phase == NLR_AUTOLOAD_NEW);
    uint32_t allocations = alloc_calls;
    CHECK(nlr_boot_autoload_checkpoint() == (void *)(uintptr_t)0x5ca1ab1eu);
    CHECK(flag_getter_calls == 2 && alloc_calls == allocations);
    CHECK(nlr_runtime_find(&nlr_services, 0) == r);
    CHECK(r->autoload.boot_turns == 2 && r->autoload.boot_asks == 2);
    open_fail = 0;
    registry_teardown(r);
}

/* ---- the GUI layer while a boot program starts (runtime.c boot_veil_*) ---- */

/* Two alpha planes in the "plane band" the scanout registers point into,
 * and the camera's own services: a sleep and no clock. */
static _Alignas(64) uint8_t veil_planes[2][64 * 4];
static uint32_t veil_scanout[2];
static uint32_t veil_sleeps;
static struct nlr_runtime *veil_runtime;
static uint32_t veil_entry_at, veil_end_at, veil_move_at, veil_late_at;

static void veil_show(uint32_t which)
{
    uintptr_t at = (uintptr_t)veil_planes[which];
    veil_scanout[0] = (uint32_t)at;
    veil_scanout[1] = (uint32_t)((uint64_t)at >> 32);
}

/* What the stock GUI drew: runs and single bytes, as anti-aliased text
 * gives. */
static void veil_draw(uint8_t *plane, uint32_t seed)
{
    for (uint32_t i = 0; i < sizeof veil_planes[0]; i++)
        plane[i] = (i / 16u) % 3u == 0 ? 0 : (i / 16u) % 3u == 1 ? 0xff
                                           : (uint8_t)(i * 7u + seed);
}

static int veil_plane_is(const uint8_t *plane, uint8_t value)
{
    for (uint32_t i = 0; i < sizeof veil_planes[0]; i++)
        if (plane[i] != value)
            return 0;
    return 1;
}

static int veil_plane_drawn(const uint8_t *plane, uint32_t seed)
{
    uint8_t expect[sizeof veil_planes[0]];
    veil_draw(expect, seed);
    return memcmp(plane, expect, sizeof expect) == 0;
}

/* The camera's sleep: counts 10 ms steps; the program's entry runs and the
 * program ends after given numbers of them, the display may move. */
static void veil_sleep(uint32_t ms)
{
    (void)ms;
    veil_sleeps++;
    struct nlr_runtime *r = veil_runtime;
    if (veil_move_at && veil_sleeps == veil_move_at)
        veil_show(1);
    if (veil_late_at && veil_sleeps == veil_late_at)
        memset(veil_planes[0], 0x33, 16); /* a render that lands late */
    if (r && veil_entry_at && veil_sleeps == veil_entry_at) {
        r->load.program.entry_started = 1;
        for (uint32_t i = 0; i < sizeof veil_planes[0]; i++)
            veil_planes[0][i] = 0xee; /* the program draws */
    }
    if (r && veil_end_at && veil_sleeps == veil_end_at)
        __atomic_store_n(&r->load.state, 0u, __ATOMIC_RELEASE);
}

static struct nlr_runtime *veil_fixture(struct nlr_services *copy)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return 0;
    *copy = nlr_services;
    copy->time = 0;
    copy->sleep_ms = veil_sleep;
    r->load.svc = copy;
    veil_runtime = r;
    veil_sleeps = veil_entry_at = veil_end_at = veil_move_at = veil_late_at = 0;
    veil_draw(veil_planes[0], 1);
    veil_draw(veil_planes[1], 2);
    veil_show(0);
    mock_program_services.scanout_alpha = veil_scanout;
    mock_program_services.scanout_high_mask = 0xffffffffu;
    mock_program_services.bus_offset = 0;
    mock_program_services.plane_lo = (uintptr_t)veil_planes;
    mock_program_services.plane_hi = (uintptr_t)veil_planes + sizeof veil_planes;
    mock_program_services.alpha_stride = 64;
    mock_program_services.height = 4;
    return r;
}

static void veil_teardown(struct nlr_runtime *r)
{
    mock_program_services.scanout_alpha = 0;
    mock_program_services.scanout_high_mask = 0;
    mock_program_services.plane_lo = mock_program_services.plane_hi = 0;
    mock_program_services.alpha_stride = 0;
    mock_program_services.height = 0;
    veil_runtime = 0;
    veil_entry_at = veil_end_at = veil_move_at = veil_late_at = 0;
    r->load.program.entry_started = 0;
    registry_teardown(r);
}

/* BOOT names the program, the card is ready on the first turn: the GUI's
 * task reads it inside the checkpoint and the shown plane is cleared as it
 * is read. The program's entry never runs (the worker is not driven here),
 * the hold ends, and the plane goes back as the GUI drew it before the GUI
 * leaves the checkpoint; the copy's room is given back. */
static void boot_veil_clears_while_the_program_is_read(void)
{
    struct nlr_services copy;
    struct nlr_runtime *r = veil_fixture(&copy);
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    manifest_ready = 1;
    uint32_t releases = release_calls;
    veil_end_at = 3;    /* the load gives up three sleeps into the hold */
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(r->autoload.boot_decided && r->autoload.boot_result == NLR_OK);
    CHECK(r->autoload.veil_blanks >= 1 && r->autoload.veil_restored == 1);
    CHECK(veil_plane_drawn(veil_planes[0], 1) && !r->autoload.veil_keep);
    CHECK(!r->autoload.veil_inside && !r->load.chunk_read && !r->autoload.boot_hold);
    CHECK(release_calls > releases);
    veil_teardown(r);
}

/* The hold, on the camera's services (a sleep, no clock): the plane is
 * cleared until the program's entry runs -- and the second buffer too,
 * when the display moves to it -- then the copies are dropped and what the
 * program draws stays. */
static void boot_veil_hold_until_the_entry(void)
{
    struct nlr_services copy;
    struct nlr_runtime *r = veil_fixture(&copy);
    if (!r)
        return;
    veil_move_at = 5;
    veil_entry_at = 30;
    veil_end_at = 60;
    r->autoload.boot_hold = 1;
    r->load.state = 2;
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(veil_sleeps == 60 && !r->autoload.boot_hold);
    /* the first plane: at once, then every 100 ms until the entry */
    CHECK(veil_plane_is(veil_planes[0], 0xee));
    CHECK(veil_plane_is(veil_planes[1], 0));
    CHECK(r->autoload.veil_blanks >= 3 && !r->autoload.veil_restored);
    CHECK(!r->autoload.veil_keep && !r->autoload.veil_inside);
    veil_teardown(r);
}

/* The checkpoint's two halves, as a model with its own checkpoint uses
 * them (the native card's GUI turn): no hold without a program; a hold
 * found on entry lasts until the program ends; a program started during
 * the turn is held on the way out; a screen given back is redrawn once. */
static uint32_t turn_redraws;
static void turn_redraw(void) { turn_redraws++; }

static void boot_turn_halves_hold_and_redraw(void)
{
    struct nlr_services copy;
    struct nlr_runtime *r = veil_fixture(&copy);
    if (!r)
        return;
    struct nlr_platform_services platform = {.gui_redraw = turn_redraw};
    copy.platform = &platform;
    turn_redraws = 0;
    CHECK(!nlr_runtime_boot_turn_enter(r) && r->autoload.veil_inside);
    nlr_runtime_boot_turn_leave(r);
    CHECK(!r->autoload.veil_inside && !veil_sleeps && !turn_redraws);

    r->autoload.boot_hold = 1;
    r->load.state = 2;
    veil_end_at = 20;
    CHECK(nlr_runtime_boot_turn_enter(r) == 1);
    CHECK(veil_sleeps == 20 && !r->autoload.boot_hold && !r->plat.inside);
    nlr_runtime_boot_turn_leave(r);
    CHECK(veil_sleeps == 20 && !r->autoload.veil_inside);

    CHECK(!nlr_runtime_boot_turn_enter(r));
    r->autoload.boot_hold = 1; /* the turn started a shell */
    r->load.state = 2;
    veil_end_at = 35;
    nlr_runtime_boot_turn_leave(r);
    CHECK(veil_sleeps == 35 && !r->autoload.boot_hold && !r->autoload.veil_inside);

    r->plat.redraw = 1;
    CHECK(!nlr_runtime_boot_turn_enter(r));
    nlr_runtime_boot_turn_leave(r);
    CHECK(turn_redraws == 1 && !r->plat.redraw);
    CHECK(!nlr_runtime_boot_turn_enter(r));
    nlr_runtime_boot_turn_leave(r);
    CHECK(turn_redraws == 1);
    veil_teardown(r);
}

/* A GUI turn (services.platform.gui_turns) with the hold declared to
 * settle (services.platform.hold when = "settle", the Z 8's declaration):
 * the stock call always runs and its result comes back; with no runtime
 * or no hold it passes straight through. A shell opened from the menu asks
 * for the hold and closes the menu without waiting on the menu task; while
 * the switch to live view settles no turn holds -- not the first after the
 * menu, not any number of turns after it -- until the GUI commits a frame
 * after a GUI turn ran (live view's first draw). The next turn holds
 * before its stock call until the program ends, and the shell mark goes
 * with it. */
static uint32_t gui_calls, gui_held_on_call, leave_calls;
static struct nlr_runtime *gui_runtime;
static void *gui_callee(void)
{
    gui_calls++;
    if (gui_runtime)
        gui_held_on_call = gui_runtime->plat.inside;
    return &gui_calls;
}
static void menu_leave(void) { leave_calls++; }

static void gui_turn_holds_on_the_live_view_side(void)
{
    gui_runtime = 0;
    gui_calls = leave_calls = 0;
    CHECK(nlr_runtime_gui_turn(0, gui_callee) == &gui_calls && gui_calls == 1);
    nlr_runtime_gui_committed(0);
    struct nlr_services copy;
    struct nlr_runtime *r = veil_fixture(&copy);
    if (!r)
        return;
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls && gui_calls == 2);
    CHECK(!veil_sleeps && !r->autoload.veil_inside && !r->plat.inside);
    nlr_runtime_gui_committed(r); /* nothing settling: no effect */
    CHECK(!r->plat.leaving);

    const struct nlr_platform_function leave = {"menu.leave", (void *)menu_leave};
    struct nlr_platform_services platform = {.functions = &leave, .function_count = 1,
                                             .hold_when = NLR_HOLD_SETTLE};
    copy.platform = &platform;
    r->load.state = 2; /* the shell's start was queued */
    r->plat.turned = 1; /* left over from before the menu opened */
    CHECK(nlr_runtime_shell_open(r) == NLR_OK && leave_calls == 1);
    CHECK(r->plat.shell && r->plat.leaving && !r->plat.turned && r->autoload.boot_hold);
    CHECK(!veil_sleeps && !r->plat.inside);

    /* the menu's own last commit, before any GUI turn: still settling */
    nlr_runtime_gui_committed(r);
    CHECK(r->plat.leaving);
    /* idle's turns, live view's first: none holds */
    gui_runtime = r;
    gui_held_on_call = 1;
    for (uint32_t n = 0; n < 5; n++) {
        CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls);
        CHECK(r->plat.leaving && r->plat.turned && r->autoload.boot_hold && !veil_sleeps);
    }
    CHECK(gui_calls == 7 && !gui_held_on_call);
    /* live view's first frame is committed: the next turn is held */
    nlr_runtime_gui_committed(r);
    CHECK(!r->plat.leaving && r->autoload.boot_hold && !veil_sleeps);
    veil_end_at = 25;
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls && gui_calls == 8);
    CHECK(veil_sleeps == 25 && !gui_held_on_call && !r->plat.inside);
    CHECK(!r->autoload.boot_hold && !r->plat.shell && !r->autoload.veil_inside);
    /* the program ended: later turns pass through */
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls && gui_calls == 9);
    CHECK(veil_sleeps == 25);

    /* a hold asked again once settled (a second claim) is taken at once */
    r->load.state = 2;
    r->autoload.boot_hold = 1;
    veil_end_at = 40;
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls && gui_calls == 10);
    CHECK(veil_sleeps == 40 && !r->autoload.boot_hold);

    /* a screen given back mid-run lets the turn go on at once */
    r->load.state = 2;
    r->autoload.boot_hold = 1;
    r->plat.lent = 1;
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls && gui_calls == 11);
    CHECK(veil_sleeps == 40 && !r->autoload.boot_hold && !r->plat.inside);

    /* a program that ends while the GUI still settles: the mark stays
     * until the GUI settles, then goes without a hold */
    r->plat = (struct nlr_platform){0};
    r->load.state = 2;
    CHECK(nlr_runtime_shell_open(r) == NLR_OK && r->plat.leaving);
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls && r->plat.leaving);
    r->load.state = 0;
    nlr_runtime_gui_committed(r);
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls);
    CHECK(!r->plat.leaving && !r->plat.shell && !r->autoload.boot_hold && veil_sleeps == 40);
    r->plat = (struct nlr_platform){0};
    gui_runtime = 0;
    copy.platform = 0;
    veil_teardown(r);
}

/* The same shell with the hold declared immediate (services.platform.hold
 * when = "immediate", the Z 6III's declaration): nothing waits for a
 * commit -- the very next hold point holds, a GUI turn as the boot
 * checkpoint. With "settle" the boot checkpoint follows the same rule as a
 * GUI turn: it drives the card without the hold until a commit after one
 * of its turns, then holds. The commit observer's report: an accepted
 * stock commit settles the exit, a refused one (bit 0 clear) does not, and
 * a commit before any hold point ran is still the menu's. */
static void hold_when_is_the_profiles_at_every_hold_point(void)
{
    struct nlr_services copy;
    struct nlr_runtime *r = veil_fixture(&copy);
    if (!r)
        return;
    const struct nlr_platform_function leave = {"menu.leave", (void *)menu_leave};
    struct nlr_platform_services platform = {.functions = &leave, .function_count = 1,
                                             .hold_when = NLR_HOLD_IMMEDIATE};
    copy.platform = &platform;
    r->autoload.boot_done = 1; /* the boot pass is over: the checkpoint only holds */
    gui_runtime = r;
    gui_calls = leave_calls = 0;

    /* immediate, at a GUI turn */
    r->load.state = 2;
    CHECK(nlr_runtime_shell_open(r) == NLR_OK && leave_calls == 1);
    CHECK(r->plat.shell && !r->plat.leaving && r->autoload.boot_hold);
    nlr_runtime_commit_seen(r, 1); /* nothing settling: no effect */
    CHECK(!r->plat.leaving && !r->plat.turned);
    veil_end_at = 15;
    gui_held_on_call = 1;
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls && gui_calls == 1);
    CHECK(veil_sleeps == 15 && !gui_held_on_call && !r->plat.turned);
    CHECK(!r->autoload.boot_hold && !r->plat.shell && !r->autoload.veil_inside);

    /* immediate, at the boot checkpoint */
    r->plat = (struct nlr_platform){0};
    r->load.state = 2;
    CHECK(nlr_runtime_shell_open(r) == NLR_OK && !r->plat.leaving);
    veil_end_at = 30;
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(veil_sleeps == 30 && !r->autoload.boot_hold && !r->plat.shell);

    /* settle, at the boot checkpoint */
    platform.hold_when = NLR_HOLD_SETTLE;
    r->plat = (struct nlr_platform){0};
    r->load.state = 2;
    CHECK(nlr_runtime_shell_open(r) == NLR_OK && r->plat.leaving && !r->plat.turned);
    nlr_runtime_commit_seen(r, 1); /* the menu's own last commit */
    CHECK(r->plat.leaving);
    for (uint32_t n = 0; n < 3; n++) {
        nlr_runtime_boot_checkpoint(r, &card_store);
        CHECK(r->plat.leaving && r->plat.turned && r->autoload.boot_hold);
        CHECK(veil_sleeps == 30 && !r->plat.inside);
    }
    nlr_runtime_commit_seen(r, 0); /* a refused commit settles nothing */
    CHECK(r->plat.leaving);
    nlr_runtime_commit_seen(r, 1); /* live view's first frame */
    CHECK(!r->plat.leaving && r->autoload.boot_hold && veil_sleeps == 30);
    veil_end_at = 45;
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(veil_sleeps == 45 && !r->autoload.boot_hold && !r->plat.shell);
    nlr_runtime_commit_seen(0, 1); /* no runtime: nothing */

    /* no hold declared: the shell still opens, settling nothing */
    platform.hold_when = 0;
    r->plat = (struct nlr_platform){0};
    r->load.state = 2;
    CHECK(nlr_runtime_shell_open(r) == NLR_OK && !r->plat.leaving);
    r->load.state = 0;
    CHECK(nlr_runtime_gui_turn(r, gui_callee) == &gui_calls);
    CHECK(!r->plat.shell && !r->autoload.boot_hold && veil_sleeps == 45);

    r->plat = (struct nlr_platform){0};
    r->autoload.boot_done = 0;
    gui_runtime = 0;
    copy.platform = 0;
    veil_teardown(r);
}

/* Named tables (ABI 8, family E): the stock CRC is checked before the
 * first write only, later writes by the same kind of owner stack on it; a
 * pointer table is changed in a RAM copy its slot is pointed at; a repack
 * table is never written (-EACCES); a foreground program's writes are
 * undone when it ends, a resident extension's stay; the other kind of
 * owner is refused; a slot or bytes changed behind the loader's back are
 * refused before anything is written. */
static uint8_t table_stock[64];
static uint8_t table_other[64];
static uint64_t table_slot;
static uint8_t table_ram[16];
static uint8_t table_ram2[16];

static void named_tables_restore_and_refuse(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    for (uint32_t n = 0; n < sizeof table_stock; n++)
        table_stock[n] = table_other[n] = (uint8_t)(n * 7u + 1u);
    for (uint32_t n = 0; n < sizeof table_ram; n++)
        table_ram[n] = table_ram2[n] = (uint8_t)(0xa0u + n);
    table_slot = (uint64_t)(uintptr_t)table_stock;
    const struct nlr_platform_table tables[] = {
        {"t.pointer", (uint64_t)(uintptr_t)&table_slot, sizeof table_stock,
         NLR_TABLE_POINTER, test_crc32(table_stock, sizeof table_stock), 0,
         (uint64_t)(uintptr_t)table_stock},
        {"t.ram", (uint64_t)(uintptr_t)table_ram, sizeof table_ram, NLR_TABLE_RAM,
         test_crc32(table_ram, sizeof table_ram), 0, 0},
        {"t.ram2", (uint64_t)(uintptr_t)table_ram2, sizeof table_ram2, NLR_TABLE_RAM,
         test_crc32(table_ram2, sizeof table_ram2), 0, 0},
        {"t.repack", (uint64_t)(uintptr_t)table_stock, sizeof table_stock,
         NLR_TABLE_REPACK, test_crc32(table_stock, sizeof table_stock), 0, 0},
    };
    mock_platform_services.tables = tables;
    mock_platform_services.table_count = 4;
    CHECK(nlr_runtime_find(&nlr_services, 0) == r);
    r->load.state = 2;
    r->load.program_kind = NLR_KIND_FOREGROUND;

    struct nlr_named n = {0};
    CHECK(nlr_api.named("t.pointer", &n) == 0 && n.kind == NLR_NAMED_TABLE);
    CHECK(n.flags == (NLR_TABLE_POINTER | NLR_NAMED_STOCK) && n.size == 64);
    CHECK(nlr_api.named("t.missing", &n) == -NLR_API_ENOENT);

    /* repack: readable, never written */
    uint8_t got[64];
    CHECK(nlr_api.table_read("t.repack", 0, got, 64) == 0 && !memcmp(got, table_stock, 64));
    uint8_t mark[4] = {0xde, 0xad, 0xbe, 0xef};
    CHECK(nlr_api.table_write("t.repack", 0, mark, 4) == -NLR_API_EACCES);
    CHECK(nlr_api.table_restore("t.repack") == -NLR_API_ENOENT);
    CHECK(!memcmp(table_stock, table_other, 64));

    /* bounds and names */
    CHECK(nlr_api.table_write("t.pointer", 62, mark, 4) == -NLR_API_EINVAL);
    CHECK(nlr_api.table_read("t.pointer", 65, got, 0) == -NLR_API_EINVAL);
    CHECK(nlr_api.table_write("t.missing", 0, mark, 4) == -NLR_API_ENOENT);
    CHECK(table_slot == (uint64_t)(uintptr_t)table_stock);

    /* the first write: the slot moves to a copy, the stock data stays */
    CHECK(nlr_api.table_write("t.pointer", 4, mark, 4) == 0);
    CHECK(table_slot != (uint64_t)(uintptr_t)table_stock);
    CHECK(!memcmp(table_stock, table_other, 64));
    const uint8_t *copy = (const uint8_t *)(uintptr_t)table_slot;
    CHECK(!memcmp(copy + 4, mark, 4) && !memcmp(copy, table_stock, 4) &&
          !memcmp(copy + 8, table_stock + 8, 56));
    CHECK(nlr_api.named("t.pointer", &n) == 0);
    CHECK(n.flags == (NLR_TABLE_POINTER | NLR_NAMED_CHANGED));
    /* stacked: no longer the stock bytes, the same owner adds to them */
    uint8_t mark2[2] = {0x11, 0x22};
    CHECK(nlr_api.table_write("t.pointer", 8, mark2, 2) == 0);
    CHECK(nlr_api.table_read("t.pointer", 0, got, 64) == 0);
    CHECK(!memcmp(got + 4, mark, 4) && !memcmp(got + 8, mark2, 2));
    CHECK((const uint8_t *)(uintptr_t)table_slot == copy);

    /* RAM: written in place, stacked, CRC no longer stock */
    CHECK(nlr_api.table_write("t.ram", 0, mark, 4) == 0 && !memcmp(table_ram, mark, 4));
    CHECK(nlr_api.table_write("t.ram", 4, mark2, 2) == 0 && !memcmp(table_ram + 4, mark2, 2));
    CHECK(nlr_api.named("t.ram", &n) == 0 && n.flags == (NLR_TABLE_RAM | NLR_NAMED_CHANGED));

    /* changed behind the loader's back: refused before writing */
    table_ram2[3] ^= 0xffu;
    CHECK(nlr_api.named("t.ram2", &n) == 0 && n.flags == NLR_TABLE_RAM);
    CHECK(nlr_api.table_write("t.ram2", 0, mark, 1) == -NLR_API_EBUSY);
    CHECK(table_ram2[0] == 0xa0u);
    table_ram2[3] ^= 0xffu;

    /* the other kind of owner: refused, nothing changes */
    r->load.program_kind = NLR_KIND_RESOURCE_EXTENSION;
    CHECK(nlr_api.table_write("t.pointer", 0, mark, 1) == -NLR_API_EBUSY);
    CHECK(nlr_api.table_restore("t.pointer") == -NLR_API_EBUSY);
    CHECK(nlr_api.table_write("t.ram", 0, mark2, 1) == -NLR_API_EBUSY);
    r->load.program_kind = NLR_KIND_FOREGROUND;

    /* the foreground program ends: every write it made is undone */
    nlr_program_io_release(r);
    CHECK(table_slot == (uint64_t)(uintptr_t)table_stock);
    for (uint32_t k = 0; k < sizeof table_ram; k++)
        CHECK(table_ram[k] == (uint8_t)(0xa0u + k));
    CHECK(nlr_api.named("t.pointer", &n) == 0 &&
          n.flags == (NLR_TABLE_POINTER | NLR_NAMED_STOCK));
    CHECK(nlr_api.named("t.ram", &n) == 0 && n.flags == (NLR_TABLE_RAM | NLR_NAMED_STOCK));
    CHECK(nlr_api.table_restore("t.pointer") == -NLR_API_ENOENT);

    /* a later write reuses the parked copy, filled from stock again */
    CHECK(nlr_api.table_write("t.pointer", 0, mark2, 1) == 0);
    CHECK((const uint8_t *)(uintptr_t)table_slot == copy);
    CHECK(copy[0] == 0x11 && !memcmp(copy + 1, table_stock + 1, 63));
    CHECK(nlr_api.table_restore("t.pointer") == 0);
    CHECK(table_slot == (uint64_t)(uintptr_t)table_stock);

    /* a slot pointed elsewhere: neither read nor written */
    table_slot = (uint64_t)(uintptr_t)table_other;
    CHECK(nlr_api.table_read("t.pointer", 0, got, 4) == -NLR_API_EBUSY);
    CHECK(nlr_api.table_write("t.pointer", 0, mark, 4) == -NLR_API_EBUSY);
    CHECK(table_slot == (uint64_t)(uintptr_t)table_other && table_other[0] == 1u);
    table_slot = (uint64_t)(uintptr_t)table_stock;

    /* a resident extension's writes stay when a foreground program ends */
    r->load.program_kind = NLR_KIND_RESOURCE_EXTENSION;
    CHECK(nlr_api.table_write("t.ram", 0, mark, 4) == 0);
    nlr_program_io_release(r);
    CHECK(!memcmp(table_ram, mark, 4));
    CHECK(nlr_api.table_restore("t.ram") == 0 && table_ram[0] == 0xa0u);

    mock_platform_services.tables = 0;
    mock_platform_services.table_count = 0;
    r->load.state = 0;
    registry_teardown(r);
}

/* No BOOT, DISP held, a card that never answers: nothing is cleared,
 * nothing taken from the heap -- the stock GUI's path is the one it always
 * had. */
static void boot_veil_leaves_the_stock_paths_alone(void)
{
    struct nlr_services copy;
    struct nlr_runtime *r = veil_fixture(&copy);
    if (!r)
        return;
    set_enabled("");
    boot_app_image();
    manifest_ready = 1;
    uint32_t allocs = alloc_calls;
    nlr_runtime_boot_checkpoint(r, &card_store);    /* no BOOT */
    CHECK(r->autoload.boot_decided && !r->autoload.boot_hold);
    CHECK(!r->autoload.veil_blanks && alloc_calls == allocs);
    CHECK(veil_plane_drawn(veil_planes[0], 1));
    veil_teardown(r);

    r = veil_fixture(&copy);
    if (!r)
        return;
    memcpy(card_boot, "app\n", 4);
    card_boot_len = 4;
    boot_app_image();
    hold_keys(0x40u);
    for (uint32_t n = 0; n < 4; n++)
        nlr_runtime_boot_checkpoint(r, &card_store);    /* the escape */
    CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED && !r->autoload.veil_blanks);
    CHECK(veil_plane_drawn(veil_planes[0], 1));
    hold_keys(0);
    veil_teardown(r);

    r = veil_fixture(&copy);
    if (!r)
        return;
    manifest_ready = 0;
    for (uint32_t n = 0; n < 40; n++)
        nlr_runtime_boot_checkpoint(r, &card_store);    /* no card */
    CHECK(!r->autoload.veil_blanks && !veil_sleeps);
    CHECK(veil_plane_drawn(veil_planes[0], 1));
    manifest_ready = 1;
    veil_teardown(r);
}

/* No room for the copy, or a buffer outside the plane band: the plane is
 * left as the GUI drew it. */
static void boot_veil_refuses_what_it_cannot_put_back(void)
{
    struct nlr_services copy;
    struct nlr_runtime *r = veil_fixture(&copy);
    if (!r)
        return;
    r->autoload.boot_hold = 1;
    r->load.state = 2;
    veil_end_at = 3;
    alloc_fail_countdown = 0;
    nlr_runtime_boot_checkpoint(r, &card_store);
    alloc_fail_countdown = -1;
    CHECK(!r->autoload.veil_blanks && r->autoload.veil_refused == 1);
    CHECK(veil_plane_drawn(veil_planes[0], 1));
    veil_teardown(r);

    r = veil_fixture(&copy);
    if (!r)
        return;
    mock_program_services.plane_hi = (uintptr_t)veil_planes[0] + 64u;
    r->autoload.boot_hold = 1;
    r->load.state = 2;
    veil_end_at = 3;
    nlr_runtime_boot_checkpoint(r, &card_store);
    CHECK(!r->autoload.veil_blanks && veil_plane_drawn(veil_planes[0], 1));
    veil_teardown(r);
}

/* A plane drawn on after it was cleared: what lands there stays, the rest
 * comes back from the copy -- whether the late render is put back at the
 * end, or folded into the copy by a clear 100 ms later. */
static void boot_veil_keeps_a_late_render(void)
{
    for (uint32_t end = 5; end <= 25; end += 20) {
        struct nlr_services copy;
        struct nlr_runtime *r = veil_fixture(&copy);
        if (!r)
            return;
        r->autoload.boot_hold = 1;
        r->load.state = 2;
        veil_late_at = 3;
        veil_end_at = end;
        nlr_runtime_boot_checkpoint(r, &card_store);
        uint8_t expect[sizeof veil_planes[0]];
        veil_draw(expect, 1);
        memset(expect, 0x33, 16);
        CHECK(r->autoload.veil_restored == 1);
        CHECK(memcmp(veil_planes[0], expect, sizeof expect) == 0);
        CHECK(r->autoload.veil_blanks == (end == 5 ? 1u : 3u));
        veil_teardown(r);
    }
}
#endif

static void autoload_order_and_saved_snapshot(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(strncmp(card_operations, "SPME", 4) == 0);
    CHECK(pending_present && marker_writes == 1 && !call_count);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_READY);
    CHECK(nlr_runtime_read_directory(r) == NLR_BUSY);
    CHECK(nlr_runtime_check(r, 0) == NLR_BUSY);
    CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_BUSY);
    CHECK(nlr_runtime_save_enabled(r, &r->saved_enabled, &card_store) == NLR_BUSY);
    for (uint32_t n = 0; n < 3; n++) {
        autoload_run_one(r);
        CHECK(r->autoload.item[n] == NLR_EXTENSION_LOADED);
        /* The marker stands until the last one has come back, and goes
         * with it: no further visit is needed to clear it. */
        CHECK(call_count == n + 1 && pending_present == (n < 2));
        CHECK(marker_removes == (n == 2));
    }
    CHECK(strcmp(initialized_ids[0], "two") == 0);
    CHECK(strcmp(initialized_ids[1], "one") == 0);
    CHECK(strcmp(initialized_ids[2], "three") == 0);
    CHECK(dispatch_calls == 3 && !exec_releases);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE && !pending_present);
    CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
    CHECK(marker_removes == 1);
    uint32_t operations = card_operation_count;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
    CHECK(call_count == 3 && card_operation_count == operations);
    struct nlr_enabled desired = {0};
    CHECK(nlr_enabled_parse(&desired, &r->directory,
                             (const uint8_t *)"three\none\n", 10) == NLR_OK);
    settings_write_fail = 1;
    CHECK(nlr_runtime_save_enabled(r, &desired, &card_store) == NLR_IO);
    CHECK(r->enabled_save_result == NLR_IO);
    CHECK(r->saved_enabled.count == 3 && card_enabled_len == 14);
    settings_write_fail = 0;
    CHECK(nlr_runtime_save_enabled(r, &desired, &card_store) == NLR_OK);
    CHECK(r->enabled_save_result == NLR_OK && r->saved_enabled.count == 2);
    CHECK(memcmp(card_enabled, "three\none\n", 10) == 0);
    CHECK(r->autoload.enabled.count == 3);
    CHECK(strcmp(r->autoload.enabled.id[0], "two") == 0);
    CHECK(nlr_runtime_resident_find(r, "two") != 0 && call_count == 3);
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK && call_count == 3);
    registry_teardown(r);
}

static void autoload_guard_priority_matrix(void)
{
    static const struct {
        int safe, pending, fail_at, invalid, expected, probes;
    } cases[] = {
        {1, 1, 0, 0, NLR_DISABLED, 1},
        {1, 0, 0, 0, NLR_DISABLED, 1},
        {0, 1, 0, 0, NLR_AUTOLOAD_PAUSED, 2},
        {0, 0, 1, 0, NLR_IO, 1},
        {0, 1, 1, 0, NLR_IO, 1},
        {0, 0, 2, 0, NLR_IO, 2},
        {0, 0, 0, 1, NLR_IO, 1},
    };
    for (uint32_t n = 0; n < sizeof cases / sizeof cases[0]; n++) {
        struct nlr_runtime *r = autoload_fixture();
        if (!r)
            return;
        safe_mode_present = cases[n].safe;
        pending_present = cases[n].pending;
        probe_fail_at = cases[n].fail_at;
        probe_invalid = cases[n].invalid;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == cases[n].expected);
        CHECK(probe_calls == cases[n].probes);
        CHECK(manifest_opens == (cases[n].expected == NLR_AUTOLOAD_PAUSED));
        CHECK(!program_opens && !call_count && !marker_writes);
        if (cases[n].expected == NLR_AUTOLOAD_PAUSED) {
            CHECK(r->autoload.enabled_result == NLR_OK);
            CHECK(r->saved_enabled.count == 3);
        }
        CHECK(card_enabled_len == 14);
        safe_mode_present = pending_present = probe_fail_at = probe_invalid = 0;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == cases[n].expected);
        CHECK(!call_count && !marker_writes);
    }
}

static void autoload_settings_and_marker_failures(void)
{
    for (uint32_t n = 0; n < 11; n++) {
        struct nlr_runtime *r = autoload_fixture();
        if (!r)
            return;
        int expected = NLR_IO;
        switch (n) {
        case 0: card_manifest_present = 0; break;
        /* A card whose ENABLED cannot be read, but is there: unlike a
         * missing one (below) this is a genuine failure. */
        case 1: card_enabled_present = 0; probe_enabled_anyway = 1; break;
        case 2: fail_next_read = 1; break;
        case 3: close_fail = 1; break;
        case 4: set_enabled("app\n"); expected = NLR_FORMAT; break;
        case 5: set_enabled("one\nONE\n"); expected = NLR_FORMAT; break;
        case 6: set_enabled("missing\n"); expected = NLR_FORMAT; break;
        case 7: marker_write_fail = 1; break;
        case 8: marker_write_fail = marker_commit_then_fail = 1; break;
        case 9: probe_fail_at = 5; break;
        case 10: card_enabled_len = NLR_ENABLED_BYTES + 1; expected = NLR_BOUNDS; break;
        }
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == expected);
        CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
        CHECK(!call_count && !program_opens && !dispatch_calls);
        CHECK(!marker_removes);
        if (n == 8 || n == 9)
            CHECK(pending_present);
        CHECK(nlr_runtime_autoload_step(r) == expected);
    }
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    set_enabled("");
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE);
    CHECK(!call_count && !marker_writes && !marker_removes && !pending_present);

    /* No ENABLED at all: the read fails, the reliable probe reports it
     * absent, and a card that names nothing loads nothing without pausing
     * the next boot. Nothing is written, so no marker is left behind. */
    r = autoload_fixture();
    if (!r)
        return;
    card_enabled_present = 0;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE);
    CHECK(r->autoload.enabled.count == 0 && r->saved_enabled.count == 0);
    CHECK(!call_count && !marker_writes && !marker_removes && !pending_present);
    /* SAFE_MODE and the marker probed, MANIFEST read, ENABLED's own read
     * attempted and then its absence established: nothing written. */
    CHECK(strcmp(card_operations, "SPMEL") == 0);
}

static void autoload_interruption_points(void)
{
    /* Synthetic cold resets at the PLAN 7.5 crash boundaries; not evidence
     * of a real camera's effective restart or storage durability. The pass
     * is interrupted before it ends, because once the last extension has
     * come back there is no boundary left: the worker has already cleared
     * the marker (the finished pass is the case below). */
    const uint32_t completed[] = {0, 1, 2};
    for (uint32_t point = 0; point < 3; point++) {
        struct nlr_runtime *r = autoload_fixture();
        if (!r)
            return;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
        for (uint32_t n = 0; n < completed[point]; n++)
            autoload_run_one(r);
        CHECK(nlr_runtime_autoload_interrupt(r, 0) == NLR_AUTOLOAD_INTERRUPTED);
        /* The extension the worker had already queued still runs when the
         * event reaches it, so the pass reports busy until it does; what
         * the interruption left behind is the stopped phase and its
         * reason, and the marker still on the card. */
        CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
        CHECK(r->autoload.result == NLR_AUTOLOAD_INTERRUPTED);
        CHECK(pending_present && !marker_removes && call_count == completed[point]);
        for (uint32_t n = 0; n < completed[point]; n++)
            CHECK(r->autoload.item[n] == NLR_EXTENSION_LOADED);
        /* The one the worker had already queued never ran; the ones after
         * it were never even named. */
        for (uint32_t n = completed[point] + 1u; n < 3; n++)
            CHECK(r->autoload.item[n] == NLR_EXTENSION_NOT_STARTED);
        uint8_t saved[NLR_ENABLED_BYTES];
        uint32_t bytes = card_enabled_len;
        memcpy(saved, card_enabled, bytes);
        int marker = pending_present;
        r = autoload_fixture();
        pending_present = marker;
        memcpy(card_enabled, saved, bytes);
        card_enabled_len = bytes;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
        CHECK(!call_count && manifest_opens == 1 && !marker_writes);
        CHECK(r->saved_enabled.count == 3 && r->autoload.enabled_result == NLR_OK);
        CHECK(card_enabled_len == bytes && memcmp(card_enabled, saved, bytes) == 0);
    }
    /* And the boundary that is not a crash: a pass carried to its end by
     * the worker leaves nothing behind, so the next boot finds no marker,
     * does not pause, and runs the same three again. This is the camera
     * that was switched off right after one page visit. */
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    for (uint32_t n = 0; n < 3; n++)
        autoload_run_one(r);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE && call_count == 3);
    CHECK(!pending_present && marker_removes == 1);
    uint8_t saved[NLR_ENABLED_BYTES];
    uint32_t bytes = card_enabled_len;
    memcpy(saved, card_enabled, bytes);
    registry_teardown(r);
    r = autoload_fixture();
    if (!r)
        return;
    memcpy(card_enabled, saved, bytes);
    card_enabled_len = bytes;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    for (uint32_t n = 0; n < 3; n++)
        autoload_run_one(r);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE && call_count == 3);
    CHECK(!pending_present && marker_removes == 1 && marker_writes == 1);
    registry_teardown(r);
}

static void autoload_partial_failure_matrix(void)
{
    /* Middle failure after success: error, busy menu, started timeout,
     * in-entry interrupt, file/manifest replacement, budget, slots, enqueue. */
    for (uint32_t failure = 0; failure < 9; failure++) {
        struct nlr_runtime *r = autoload_fixture();
        if (!r)
            return;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
        CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
        int expected = NLR_EXEC_APP;
        uint32_t item = NLR_EXTENSION_NOT_EXECUTED;
        /* What decides whether the second extension starts at all is read
         * while the first one is coming back, inside the worker, so those
         * three are armed before it runs. The first has already been
         * started by the step above and is unaffected. */
        if (failure == 6) { nlr_exec_services.program_budget_blocks = 1;
                            expected = NLR_EXEC_BUDGET; }
        if (failure == 7) { nlr_exec_services.program_max_resident = 1;
                            expected = NLR_BUSY; }
        if (failure == 8) { flag_set_fail = 1; expected = NLR_IO; }
        autoload_run_one(r);
        const struct nlr_program_record *first = nlr_runtime_resident_find(r, "two");
        CHECK(first != 0);
        /* The rest happen while the second one is loading or running, and
         * are armed after the worker has queued it. */
        if (failure == 0) { call_return_value = 7; item = NLR_EXTENSION_PARTIAL; }
        if (failure == 1) { dispatch_mode = 1; expected = NLR_BUSY; }
        if (failure == 2) { dispatch_mode = 2; expected = NLR_EXEC_TIMEOUT;
                            item = NLR_EXTENSION_PARTIAL; }
        if (failure == 3) { dispatch_mode = 3; expected = NLR_AUTOLOAD_INTERRUPTED;
                            item = NLR_EXTENSION_LOADED; }
        if (failure == 4) { put32(card + 0x20, NLR_KIND_FOREGROUND);
                            expected = NLR_FORMAT; }
        if (failure == 5) {
            expected = NLR_REFUSED;
            set_manifest("one | resource_extension | One | APPS/PROG.NLB | 99\n"
                         "two | resource_extension | Two | APPS/PROG.NLB | 2\n"
                         "three | resource_extension | Three | APPS/PROG.NLB | 2\n");
        }
        if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 1)
            nlr_load_event(&r->load, 1);
        CHECK(nlr_runtime_autoload_step(r) == expected);
        CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
        CHECK(r->autoload.item[0] == NLR_EXTENSION_LOADED);
        CHECK(r->autoload.item[1] == item);
        CHECK(r->autoload.item[2] == NLR_EXTENSION_NOT_STARTED);
        CHECK(pending_present && !marker_removes);
        CHECK(nlr_runtime_resident_find(r, "two") == first);
        CHECK(first && first->code_block && !first->failed);
        const struct nlr_program_record *middle = nlr_runtime_resident_find(r, "one");
        if (failure == 0 || failure == 2) {
            CHECK(middle && middle->failed && middle->code_block);
            CHECK(middle && middle->uncertain == (failure == 2));
        } else if (failure == 3) {
            CHECK(middle && !middle->failed);
        } else {
            CHECK(middle == 0);
        }
        CHECK(nlr_runtime_resident_find(r, "three") == 0);
        CHECK(call_count == ((failure == 0 || failure == 2 || failure == 3) ? 2u : 1u));
        CHECK(exec_releases == (failure == 1 ? 1u : 0u));
        uint32_t calls = call_count;
        CHECK(nlr_runtime_autoload_step(r) == expected);
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == expected);
        CHECK(call_count == calls && card_enabled_len == 14);
        if (failure == 2) {
            CHECK(nlr_runtime_start_program(r, 3, 2) == NLR_EXEC_TIMEOUT);
            CHECK(nlr_runtime_read_directory(r) == NLR_EXEC_TIMEOUT);
            CHECK(nlr_runtime_check(r, 0) == NLR_EXEC_TIMEOUT);
            CHECK(nlr_runtime_save_enabled(r, &r->saved_enabled,
                                           &card_store) == NLR_EXEC_TIMEOUT);
        }
        registry_teardown(r);
    }
}

static void autoload_worker_guards_and_clear_failure(void)
{
    for (uint32_t failure = 0; failure < 4; failure++) {
        struct nlr_runtime *r = autoload_fixture();
        if (!r)
            return;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
        CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
        int expected = NLR_DISABLED;
        if (failure == 0) safe_mode_present = 1;
        if (failure == 1) { probe_fail_at = probe_calls + 1; expected = NLR_IO; }
        if (failure == 2) { nlr_runtime_autoload_interrupt(r, 0);
                            expected = NLR_AUTOLOAD_INTERRUPTED; }
        if (failure == 3) { nlr_exec_services.extension_call = 0;
                            expected = NLR_NOT_READY; }
        nlr_load_event(&r->load, 1);
        CHECK(nlr_runtime_autoload_step(r) == expected);
        CHECK(!call_count && !exec_releases && pending_present);
        CHECK(r->autoload.item[0] == NLR_EXTENSION_NOT_EXECUTED);
        CHECK(r->autoload.item[1] == NLR_EXTENSION_NOT_STARTED);
    }
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    /* The clear is the worker's last act of the pass, so the card has to
     * be made to refuse it before the last extension comes back. */
    marker_remove_fail = 1;
    for (uint32_t n = 0; n < 3; n++)
        autoload_run_one(r);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
    CHECK(pending_present && marker_removes == 1 && call_count == 3);
    for (uint32_t n = 0; n < 3; n++)
        CHECK(r->autoload.item[n] == NLR_EXTENSION_LOADED);
    marker_remove_fail = 0;
    CHECK(nlr_runtime_autoload_step(r) == NLR_IO);
    CHECK(marker_removes == 1);
    registry_teardown(r);
}

static int menu_consume(struct nlr_runtime *r)
{
    resource_menu_context = 1;
    int result = nlr_runtime_menu_publish(r);
    resource_menu_context = 0;
    return result;
}

static void autoload_menu_publication_contract(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    set_enabled("two\n");
    call_register_menu = call_duplicate_menu = 1;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
    nlr_load_event(&r->load, 1);
    CHECK(registration_result == 0 && duplicate_result == -NLR_API_EBUSY);
    CHECK(r->menu_registration[0].state == NLR_MENU_REG_PENDING);
    CHECK(r->menu_registration[0].item.label_id == 0x379u);
    CHECK(r->menu_registration[0].item.item_id == 0x7ffdu);
    CHECK(strcmp(r->menu_registration[0].owner, "two") == 0);
    CHECK(nlr_runtime_extension_status(r, 2) == NLR_EXTENSION_INITIALIZING);
    /* Without consumption, lifecycle observations cannot acknowledge a
     * resource step, start another init, or clear the durable marker. */
    for (uint32_t observation = 0; observation < 32; observation++) {
        CHECK(nlr_runtime_autoload_step(r) == NLR_BUSY);
        CHECK(r->autoload.phase == NLR_AUTOLOAD_WAITING && !r->autoload.next);
        CHECK(r->autoload.item[0] == NLR_EXTENSION_INITIALIZING);
        CHECK(call_count == 1 && pending_present && !marker_removes);
        CHECK(!resource_publish_calls);
    }
    CHECK(menu_consume(r) == NLR_OK);
    CHECK(resource_publish_calls == 1 && published_item.label_id == 0x379u);
    CHECK(r->menu_registration[0].state == NLR_MENU_REG_PUBLISHED);
    CHECK(nlr_runtime_extension_status(r, 2) == NLR_EXTENSION_LOADED);
    CHECK(menu_consume(r) == NLR_OK && resource_publish_calls == 1);
    CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_CLEAR && pending_present);
    CHECK(r->autoload.item[0] == NLR_EXTENSION_LOADED);
    CHECK(nlr_runtime_autoload_step(r) == NLR_OK);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_DONE && !pending_present);
    CHECK(marker_removes == 1 && !exec_releases);
    registry_teardown(r);
}

static void autoload_menu_publication_failure(void)
{
    for (uint32_t failure = 0; failure < 3; failure++) {
        struct nlr_runtime *r = autoload_fixture();
        if (!r)
            return;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
        autoload_run_one(r);
        const struct nlr_program_record *first = nlr_runtime_resident_find(r, "two");
        call_register_menu = 1;
        if (failure == 1)
            call_return_value = 7;
        if (failure == 2)
            resource_services.publish = 0;
        /* The worker has already queued the second extension; these knobs
         * are read when it runs, on the event below. */
        nlr_load_event(&r->load, 1);
        int expected = failure ? NLR_EXEC_APP : NLR_EXEC_TIMEOUT;
        if (!failure) {
            CHECK(nlr_runtime_autoload_step(r) == NLR_BUSY);
            resource_publish_result = NLR_IO;
            CHECK(menu_consume(r) == NLR_EXEC_TIMEOUT);
            CHECK(r->menu_registration[0].state == NLR_MENU_REG_UNCERTAIN);
            CHECK(r->menu_registration[0].result == NLR_IO);
            CHECK(menu_consume(r) == NLR_EXEC_TIMEOUT && resource_publish_calls == 1);
        } else {
            CHECK(nlr_runtime_autoload_step(r) == NLR_EXEC_APP);
            CHECK(menu_consume(r) == NLR_OK);
            CHECK(resource_publish_calls == (failure == 1));
            CHECK(registration_result == (failure == 1 ? 0 : -NLR_API_ENOSYS));
        }
        CHECK(nlr_runtime_autoload_step(r) == expected);
        CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
        CHECK(r->autoload.item[0] == NLR_EXTENSION_LOADED);
        CHECK(r->autoload.item[1] == NLR_EXTENSION_PARTIAL);
        CHECK(r->autoload.item[2] == NLR_EXTENSION_NOT_STARTED);
        CHECK(first && !first->failed && !first->uncertain);
        const struct nlr_program_record *middle = nlr_runtime_resident_find(r, "one");
        CHECK(middle && middle->failed && middle->code_block);
        CHECK(middle && middle->uncertain == !failure);
        CHECK(call_count == 2 && pending_present && !marker_removes && !exec_releases);
        CHECK(nlr_runtime_autoload_step(r) == expected && call_count == 2);
        if (!failure) {
            CHECK(nlr_runtime_start_program(r, 3, 2) == NLR_EXEC_TIMEOUT);
            CHECK(nlr_runtime_check(r, 0) == NLR_EXEC_TIMEOUT);
            CHECK(nlr_runtime_read_directory(r) == NLR_EXEC_TIMEOUT);
            CHECK(nlr_runtime_save_enabled(r, &r->saved_enabled,
                                           &card_store) == NLR_EXEC_TIMEOUT);
        }
        registry_teardown(r);
        r = autoload_fixture();
        pending_present = 1;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
        CHECK(!call_count && manifest_opens == 1 && !program_opens);
    }
}

static void autoload_explicit_recovery_for_next_boot(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    pending_present = 1;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
    CHECK(r->saved_enabled.count == 3 && !call_count && !marker_removes);
    uint8_t original[NLR_ENABLED_BYTES];
    memcpy(original, card_enabled, card_enabled_len);
    uint32_t bytes = card_enabled_len;
    for (uint32_t n = 0; n < 8; n++) {
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
        CHECK(nlr_runtime_autoload_step(r) == NLR_AUTOLOAD_PAUSED);
        CHECK(pending_present && !call_count && !marker_removes);
    }
    CHECK(nlr_runtime_autoload_recover(r) == NLR_OK);
    CHECK(r->autoload.recovery_result == NLR_OK && r->autoload.recovery_armed);
    CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
    CHECK(!pending_present && marker_removes == 1 && !marker_writes);
    CHECK(!call_count && !settings_writes && card_enabled_len == bytes);
    CHECK(memcmp(card_enabled, original, bytes) == 0);
    CHECK(nlr_runtime_autoload_recover(r) == NLR_OK && marker_removes == 1);
    CHECK(nlr_runtime_read_directory(r) == NLR_OK);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
    CHECK(nlr_runtime_autoload_step(r) == NLR_AUTOLOAD_PAUSED && !call_count);
    /* Correct settings while paused/armed; neither current residents nor
     * the attempted order change. Only a synthetic fresh boot applies it. */
    struct nlr_enabled desired = {0};
    CHECK(nlr_enabled_parse(&desired, &r->directory,
                             (const uint8_t *)"three\none\n", 10) == NLR_OK);
    CHECK(nlr_runtime_save_enabled(r, &desired, &card_store) == NLR_OK);
    CHECK(r->autoload.enabled.count == 3 && !call_count);
    memcpy(original, card_enabled, card_enabled_len);
    bytes = card_enabled_len;
    registry_teardown(r);
    r = autoload_fixture();
    memcpy(card_enabled, original, bytes);
    card_enabled_len = bytes;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    CHECK(r->autoload.enabled.count == 2 && marker_writes == 1);
    autoload_run_one(r);
    autoload_run_one(r);
    CHECK(strcmp(initialized_ids[0], "three") == 0);
    CHECK(strcmp(initialized_ids[1], "one") == 0);
    CHECK(nlr_runtime_autoload_step(r) == NLR_OK && !pending_present);
    registry_teardown(r);
}

static void autoload_recovery_preserves_failed_publication(void)
{
    struct nlr_runtime *r = autoload_fixture();
    if (!r)
        return;
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_OK);
    autoload_run_one(r);
    call_register_menu = 1;
    call_return_value = 7;
    nlr_load_event(&r->load, 1);
    CHECK(nlr_runtime_autoload_step(r) == NLR_EXEC_APP);
    CHECK(nlr_runtime_autoload_recover(r) == NLR_BUSY);
    CHECK(pending_present && !marker_removes && !resource_publish_calls);
    CHECK(menu_consume(r) == NLR_OK); /* failed init's queued item still publishes */
    CHECK(resource_publish_calls == 1);
    const struct nlr_program_record *first = nlr_runtime_resident_find(r, "two");
    const struct nlr_program_record *failed = nlr_runtime_resident_find(r, "one");
    CHECK(first && failed && failed->failed && !failed->uncertain);
    struct nlr_program_record first_before = *first, failed_before = *failed;
    struct nlr_menu_registration published_before = r->menu_registration[0];
    CHECK(nlr_runtime_autoload_recover(r) == NLR_OK);
    CHECK(!pending_present && call_count == 2 && !settings_writes);
    CHECK(memcmp(first, &first_before, sizeof first_before) == 0);
    CHECK(memcmp(failed, &failed_before, sizeof failed_before) == 0);
    CHECK(memcmp(&r->menu_registration[0], &published_before,
                 sizeof published_before) == 0);
    CHECK(nlr_runtime_extension_status(r, 2) == NLR_EXTENSION_LOADED);
    CHECK(nlr_runtime_extension_status(r, 0) == NLR_EXTENSION_PARTIAL);
    CHECK(nlr_runtime_extension_status(r, 1) == NLR_EXTENSION_NOT_STARTED);
    CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_EXEC_APP);
    CHECK(nlr_runtime_autoload_step(r) == NLR_EXEC_APP && call_count == 2);
    CHECK(menu_consume(r) == NLR_OK && resource_publish_calls == 1);
    CHECK(card_enabled_len == 14 && memcmp(card_enabled, "two\none\nthree\n", 14) == 0);
    registry_teardown(r);
}

static void autoload_recovery_refusal_matrix(void)
{
    for (uint32_t failure = 0; failure < 14; failure++) {
        struct nlr_runtime *r = autoload_fixture();
        if (!r)
            return;
        pending_present = 1;
        CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
        int expected = NLR_BUSY;
        static const struct nlr_card_store no_remove = {.probe = store_probe};
        switch (failure) {
        case 0: r->load.state = 1; break;
        case 1: r->autoload.phase = NLR_AUTOLOAD_READY; break;
        case 2: r->menu_registration[0].state = NLR_MENU_REG_PENDING; break;
        case 3: r->menu_registration[0].state = NLR_MENU_REG_UNCERTAIN;
                expected = NLR_EXEC_TIMEOUT; break;
        case 4: r->resident[0].used = r->resident[0].uncertain = 1;
                expected = NLR_EXEC_TIMEOUT; break;
        case 5: r->load.program.code_allocation = r; expected = NLR_EXEC_RESTORE; break;
        case 6: r->load.program.data_allocation = r; expected = NLR_EXEC_RESTORE; break;
        case 7: r->load.probe.allocation = r; expected = NLR_EXEC_RESTORE; break;
        case 8: safe_mode_present = 1; expected = NLR_DISABLED; break;
        case 9: probe_fail_at = probe_calls + 1; expected = NLR_IO; break;
        case 10: probe_invalid = 1; expected = NLR_IO; break;
        case 11: marker_remove_fail = 1; expected = NLR_IO; break;
        case 12: r->autoload.store = &no_remove; expected = NLR_NOT_READY; break;
        case 13: r->autoload.phase = NLR_AUTOLOAD_DONE; expected = NLR_REFUSED; break;
        }
        int probes_before = probe_calls;
        CHECK(nlr_runtime_autoload_recover(r) == expected);
        CHECK(r->autoload.recovery_result == expected && !r->autoload.recovery_armed);
        CHECK(!call_count && !marker_writes && !settings_writes && pending_present);
        CHECK(marker_removes == (failure == 11));
        CHECK(card_enabled_len == 14 && memcmp(card_enabled, "two\none\nthree\n", 14) == 0);
        if (failure <= 7 || failure >= 12)
            CHECK(probe_calls == probes_before); /* unsafe state never touches card */
        if (failure == 11) {
            CHECK(r->autoload.phase == NLR_AUTOLOAD_STOPPED);
            CHECK(nlr_runtime_autoload_step(r) == NLR_AUTOLOAD_PAUSED);
            CHECK(nlr_runtime_autoload_begin(r, &card_store) == NLR_AUTOLOAD_PAUSED);
            CHECK(!call_count && marker_removes == 1); /* no automatic retry */
            marker_remove_fail = 0;
            CHECK(nlr_runtime_autoload_recover(r) == NLR_OK);
            CHECK(!pending_present && r->autoload.recovery_armed);
        }
    }
}

static void foreground_api_ownership_and_quiescence(void)
{
    for (uint32_t mode = 0; mode < 4; mode++) {
        struct nlr_runtime *r = program_fixture("prog", "foreground",
                                                NLR_KIND_FOREGROUND);
        if (!r)
            return;
        api_file_path = NLR_PROGRAM_ROOT "APPS\\NOTE.TXT";
        api_file[0] = 'x';
        api_file_len = 1;
        call_owns_resources = 1;
        call_uses_exit = mode == 1;
        call_exit_code = 0;
        stop_on_api_read = mode == 2;
        call_cleanup_fails = mode == 3;
        CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_OK);
        nlr_load_event(&r->load, 1);
        CHECK(!r->load.state && !r->load.program.api_active);
        CHECK(r->load.program.returned && after_api_read == (mode != 2));
        CHECK(r->load.program.exit_requested == (mode == 1 || mode == 2));
        if (mode == 3) {
            CHECK(r->load.last_result == NLR_EXEC_RESTORE);
            CHECK(r->load.program.code_allocation && r->load.program.api_file_used);
            CHECK(r->load.program.api_allocation[0] && !exec_releases);
            CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_EXEC_RESTORE);
            close_fail = 0;
            CHECK(nlr_api_program_cleanup(&r->load.program) == NLR_OK);
        } else {
            CHECK(r->load.last_result == NLR_OK && !r->load.program.code_allocation);
            CHECK(!r->load.program.api_file_used &&
                  release_calls == call_api_release_base + 2);
            for (uint32_t n = 0; n < NLR_APP_ALLOC_MAX; n++)
                CHECK(!r->load.program.api_allocation[n]);
            for (uint32_t n = 0; n < sizeof fds / sizeof fds[0]; n++)
                CHECK(!fds[n].used);
            nlr_runtime_settle_records(r);
            call_owns_resources = call_uses_exit = stop_on_api_read = 0;
            CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_OK);
            nlr_load_event(&r->load, 1);
            CHECK(r->load.last_result == NLR_OK && call_count == 2);
        }
    }
}

static void foreground_api_capacity_preserves_owners(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    r->load.state = 2;
    r->load.program_kind = NLR_KIND_FOREGROUND;
    r->load.program.jump_armed = 1;
    for (uint32_t n = 0; n < NLR_APP_ALLOC_MAX; n++)
        CHECK(nlr_api.mem_alloc(8, 0) != 0);
    uint32_t allocations = alloc_calls;
    CHECK(!nlr_api.mem_alloc(8, 0) && alloc_calls == allocations);
    uint32_t released = release_calls;
    nlr_api.mem_free(r); /* Never release another owner's runtime. */
    CHECK(release_calls == released);
    r->load.program.api_file_used = UINT32_C(0xffff);
    CHECK(nlr_api.fs_open("APPS/NOTE.TXT", 0) == -NLR_API_EBUSY);
    r->load.program.api_file_used = 0;
    r->load.program.api_active = 1;
    CHECK(nlr_api_program_cleanup(&r->load.program) == NLR_EXEC_RESTORE);
    CHECK(release_calls == released && r->load.program.api_allocation[0]);
    r->load.program.api_active = 0;
    CHECK(nlr_api_program_cleanup(&r->load.program) == NLR_OK);
    CHECK(release_calls == released + NLR_APP_ALLOC_MAX);
    r->load.program.jump_armed = r->load.state = 0;
}

static void foreground_exit_callback_drains_api(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    exit_services.input_callback = &input_callback;
    api_file_path = NLR_PROGRAM_ROOT "APPS\\NOTE.TXT";
    api_file[0] = 'x';
    api_file_len = 1;
    call_owns_resources = stop_on_api_read = 1;
    r->detail_view = 1;
    CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_OK);
    CHECK(input_callback == nlr_runtime_exit_input);
    nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
    CHECK(strcmp(stop_events, "SR") == 0);
    CHECK(!r->load.state && !r->load.program.api_active);
    CHECK(r->load.program.exit_requested && r->load.program.returned);
    CHECK(!after_api_read && !r->load.program.code_allocation);
    CHECK(release_calls == call_api_release_base + 2 && exec_releases == 1);
    CHECK(!r->detail_view && r->exit_swallow);
    CHECK(forwarded_input[7] == 0x80 && !forwarded_input[9] &&
          !forwarded_input[10] && !forwarded_input[11]);
    /* One button released is not the end of suppression. The last release
     * is swallowed too, even though the foreground already finished. */
    send_input(2, EXIT_MASK, 4, 0, 4);
    CHECK(r->exit_swallow && !forwarded_input[7] && !forwarded_input[11]);
    send_input(0, 2, 2, 0, 2);
    CHECK(!r->exit_swallow && !forwarded_input[8] && !forwarded_input[11]);
    send_input(EXIT_MASK, 0, EXIT_MASK, EXIT_MASK, 0);
    CHECK(forwarded_input[7] == EXIT_MASK && forwarded_input[10] == EXIT_MASK);
    CHECK(strcmp(stop_events, "SR") == 0); /* idle chord just forwards */
    nlr_runtime_settle_records(r);
    CHECK(!r->program_pending && !registry_any(r, "prog"));
}

static void foreground_real_release_notifies_while_draining(void)
{
    struct nlr_runtime *r = program_fixture("app", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    exit_services.input_callback = &input_callback;
    exit_services.release_mask = 2; /* synthetic mock MENU, full chord is 6 */
    release_during_api = call_owns_resources = stop_on_api_read = 1;
    api_file_path = NLR_PROGRAM_ROOT "APPS\\NOTE.TXT";
    api_file[0] = 'x';
    api_file_len = 1;
    CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_OK);
    nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
    CHECK(strcmp(stop_events, "SR") == 0 && r->exit_notify);
    CHECK(!r->load.state && !r->load.program.code_allocation);
    CHECK(!after_api_read && r->load.program.exit_requested);
    CHECK(forwarded_input[11] == 2 && r->exit_swallow);
    send_input(0, 4, 4, 0, 4); /* DELETE release never reaches native GUI */
    CHECK(!forwarded_input[11] && !r->exit_swallow && r->exit_notify);
    /* Only the GUI consumes notification; completion never manufactures
     * another callback or release edge. */
    CHECK(input_calls == 3);
    __atomic_store_n(&r->exit_notify, 0u, __ATOMIC_RELEASE);
    nlr_runtime_settle_records(r);
    CHECK(!registry_any(r, "app") && !r->exit_notify);
}

static void foreground_busy_loop_stops_and_restarts(void)
{
    for (uint32_t resources = 0; resources < 2; resources++) {
        struct nlr_runtime *r = program_fixture("ext", "resource_extension",
                                                NLR_KIND_RESOURCE_EXTENSION);
        if (!r)
            return;
        CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_OK);
        nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
        const struct nlr_program_record *resident = nlr_runtime_resident_find(r, "ext");
        CHECK(resident != 0);
        struct nlr_program_record kept = *resident;
        set_manifest("ext | resource_extension | Ext | APPS/PROG.NLB | 2 | z8/3.11\n"
                     "app | foreground | App | APPS/FO.NLB | 2 | z8/3.11\n");
        CHECK(nlr_runtime_read_directory(r) == NLR_OK);
        fixture_kind = NLR_KIND_FOREGROUND;
        fixture_data_len = fixture_bss = reloc_count = 0;
        build_program_file_into(card2, &card2_len);
        card2_path = NLR_PROGRAM_ROOT "APPS\\FO.NLB";
        nlr_exec_services.program_budget_blocks = 4;
        exit_services.input_callback = &input_callback;
        /* Native callback registration happens after runtime construction. */
        CHECK(input_callback == original_input);
        call_busy = 1;
        call_owns_resources = (int)resources;
        api_file_path = NLR_PROGRAM_ROOT "APPS\\NOTE.TXT";
        api_file[0] = 'x';
        api_file_len = 1;
        r->detail_view = 1;
        CHECK(nlr_runtime_start_program(r, 1, 2) == NLR_OK);
        CHECK(input_callback == nlr_runtime_exit_input);
        if (setjmp(busy_context) == 0) {
            nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
            CHECK(0); /* busy computation cannot naturally return */
        }
        CHECK(strcmp(stop_events, "STAF") == 0);
        CHECK(r->load.state == 3 && !r->load.program.returned);
        CHECK(r->load.program.code_allocation && !r->load.program.api_active);
        CHECK(!exec_releases && release_calls == stop_release_base);
        CHECK(!r->detail_view && r->exit_swallow && !r->exit_uncertain);
        CHECK(memcmp(resident, &kept, sizeof kept) == 0);
        /* The normal RUN event must never rerun the abandoned program. */
        nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
        CHECK(r->load.state == 3 && call_count == 2 && !exec_releases);
        worker_context = 1;
        nlr_load_event(&r->load, NLR_LOAD_STOP_EVENT);
        worker_context = 0;
        CHECK(!r->load.state && r->load.last_result == NLR_OK);
        CHECK(r->load.program.returned && r->load.program.exit_requested);
        CHECK(!r->load.program.jump_armed && !r->load.program.code_allocation);
        CHECK(!r->load.program.api_file_used && exec_releases == 1);
        CHECK(release_calls == stop_release_base + 2u * resources);
        CHECK(memcmp(resident, &kept, sizeof kept) == 0);
        nlr_runtime_settle_records(r);
        CHECK(!registry_any(r, "app") && !r->program_pending);
        send_input(0, EXIT_MASK, EXIT_MASK, 0, EXIT_MASK);
        CHECK(!r->exit_swallow && !forwarded_input[11]);
        /* Completed stop is consumed once; its diagnostic remains set until
         * the next run. A new check must retain its page on repeated natural
         * GUI observations, rather than replaying the old stop's navigation. */
        CHECK(r->load.program.stop_requested && !r->program_pending);
        CHECK(nlr_runtime_check(r, 1) == NLR_OK);
        r->detail_view = r->show_check = 1;
        nlr_runtime_settle_records(r);
        nlr_runtime_settle_records(r);
        CHECK(r->detail_view && r->show_check && r->checked == 1);
        CHECK(r->load.program.stop_requested && !r->program_pending);
        /* A later native registration cannot silently remove the hook. */
        input_callback = alternate_input;
        call_busy = call_owns_resources = 0;
        CHECK(nlr_runtime_start_program(r, 1, 2) == NLR_OK);
        CHECK(input_callback == nlr_runtime_exit_input);
        CHECK(r->exit_original_input == alternate_input);
        nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
        CHECK(!r->load.state && r->load.last_result == NLR_OK && call_count == 3);
        CHECK(exec_releases == 2 && memcmp(resident, &kept, sizeof kept) == 0);
        send_input(EXIT_MASK, 0, EXIT_MASK, EXIT_MASK, 0);
        CHECK(alternate_input_calls == 1 && forwarded_input[10] == EXIT_MASK);
    }
}

static void foreground_stop_failures_retain_ownership(void)
{
    for (int failure = 1; failure <= 5; failure++) {
        struct nlr_runtime *r = program_fixture("app", "foreground",
                                                NLR_KIND_FOREGROUND);
        if (!r)
            return;
        exit_services.input_callback = &input_callback;
        stop_fail = failure;
        call_busy = 1;
        CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_OK);
        /* Resume failure freezes a real owned SDK file-read frame. */
        call_owns_resources = stop_on_api_read = failure == 2;
        api_file_path = NLR_PROGRAM_ROOT "APPS\\NOTE.TXT";
        api_file[0] = 'x';
        api_file_len = 1;
        flag_set_fail = failure == 5;
        if (setjmp(busy_context) == 0) {
            nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
            CHECK(0);
        }
        CHECK(r->load.program.code_allocation && r->exit_uncertain);
        CHECK(strcmp(stop_events, failure == 1 ? "S" : failure == 2 ? "SR" :
                     failure == 3 ? "ST" : failure == 4 ? "STA" : "STAF") == 0);
        CHECK(r->load.state == (failure >= 4 ? 4u : 2u));
        CHECK(!r->load.program.returned);
        if (failure == 2) {
            CHECK(stop_suspended && r->load.program.api_active == 1);
            CHECK(r->load.program.api_allocation[0] && r->load.program.api_file_used);
        }
        CHECK(!exec_releases && release_calls == stop_release_base);
        CHECK(nlr_runtime_start_program(r, 0, 2) != NLR_OK);
        uint32_t calls = stop_event_count;
        send_input(0, EXIT_MASK, EXIT_MASK, 0, EXIT_MASK);
        send_input(EXIT_MASK, 0, EXIT_MASK, EXIT_MASK, 0);
        CHECK(stop_event_count == calls); /* no uncertain-operation retry */
        nlr_load_event(&r->load, NLR_LOAD_STOP_EVENT);
        CHECK(!exec_releases && release_calls == stop_release_base);
    }
}

static void foreground_hook_forwards_nonforeground_input(void)
{
    struct nlr_runtime *r = program_fixture("app", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    CHECK(input_callback == original_input); /* absent optional slot */
    exit_services.input_callback = &input_callback;
    CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_OK);
    send_input(EXIT_MASK, 0, EXIT_MASK, EXIT_MASK, 0);
    CHECK(!stop_event_count && !r->exit_swallow && forwarded_input[10] == EXIT_MASK);
    r->load.state = 2;
    r->load.program_kind = NLR_KIND_RESOURCE_EXTENSION;
    r->load.program.jump_armed = 1;
    send_input(EXIT_MASK, 0, EXIT_MASK, EXIT_MASK, 0);
    CHECK(!stop_event_count && !r->exit_swallow && forwarded_input[10] == EXIT_MASK);
    r->load.state = 1;
    r->load.program_kind = NLR_KIND_FOREGROUND;
    r->load.program.jump_armed = 0;
    nlr_load_event(&r->load, NLR_LOAD_RUN_EVENT);
    CHECK(!r->load.state && r->load.last_result == NLR_OK);
    send_input(EXIT_MASK, 0, EXIT_MASK, EXIT_MASK, 0);
    CHECK(!stop_event_count && forwarded_input[10] == EXIT_MASK);
}
#endif

#endif /* exec-stage scenarios */

#if !defined(NLR_STAGE_PREPARE_ONLY) && !defined(NLR_STAGE_EXEC)
/* Without an exec stage the worker cannot run programs at all. */
static void start_program_refused_without_exec_stage(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    CHECK(nlr_runtime_start_program(r, 0, 1) == NLR_REFUSED);
    CHECK(nlr_runtime_start_program(r, 0, 2) == NLR_REFUSED);
    CHECK(!r->load.program_mode && !r->load.program_attempted);
}
#endif

/* The registry queries exist in every stage even though only the exec
 * stages can fill the table; on a fresh runtime they report nothing. */
static void empty_registry_queries(void)
{
    struct nlr_runtime *r = program_fixture("prog", "foreground",
                                            NLR_KIND_FOREGROUND);
    if (!r)
        return;
    CHECK(nlr_runtime_resident_find(r, "prog") == 0);
    CHECK(nlr_runtime_resident_find(r, 0) == 0);
    nlr_runtime_settle_records(r); /* nothing held: a clear no-op */
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++)
        r->resident[i].used = 0;
    reset_exec_pool();
}

static void menu_registration_api_guards(void)
{
    struct nlr_runtime *r = program_fixture("ext", "resource_extension",
                                            NLR_KIND_RESOURCE_EXTENSION);
    if (!r)
        return;
    struct nlr_menu_test_item item = {0x379u, 0x7ffdu};
    CHECK(nlr_api.menu_register(&item) == -NLR_API_EINVAL);
    CHECK(nlr_api.menu_register(0) == -NLR_API_EINVAL);
    item.label_id = 0xffffu;
    CHECK(nlr_api.menu_register(&item) == -NLR_API_EINVAL);
    item.label_id = 0x379u;
    r->load.state = 2;
    r->load.program.entry_started = 1;
    r->load.program_kind = NLR_KIND_RESOURCE_EXTENSION;
    memcpy(r->program_id, "ext", 4);
    resource_services.publish = 0;
    CHECK(nlr_api.menu_register(&item) == -NLR_API_ENOSYS);
    resource_services.publish = mock_resource_publish;
    r->load.program_kind = NLR_KIND_FOREGROUND;
    CHECK(nlr_api.menu_register(&item) == -NLR_API_EINVAL);
    r->load.program_kind = NLR_KIND_RESOURCE_EXTENSION;
    CHECK(nlr_api.menu_register(&item) == 0);
    struct nlr_menu_registration original = r->menu_registration[0];
    CHECK(nlr_api.menu_register(&item) == -NLR_API_EBUSY);
    item.item_id++;
    CHECK(nlr_api.menu_register(&item) == -NLR_API_EBUSY);
    CHECK(memcmp(&original, &r->menu_registration[0], sizeof original) == 0);
    memcpy(r->program_id, "other", 6);
    item.item_id = original.item.item_id;
    CHECK(nlr_api.menu_register(&item) == -NLR_API_EBUSY);
    item.item_id++;
    CHECK(nlr_api.menu_register(&item) == 0);
    CHECK(r->menu_registration[1].state == NLR_MENU_REG_PENDING);
    r->load.state = 0;
    CHECK(nlr_runtime_check(r, 0) == NLR_BUSY);
    CHECK(nlr_runtime_read_directory(r) == NLR_BUSY);
    CHECK(nlr_runtime_menu_publish(r) == NLR_EXEC_TIMEOUT);
    CHECK(!resource_publish_calls);
    CHECK(r->menu_registration[0].state == NLR_MENU_REG_UNCERTAIN);
}

int main(void)
{
    /* The exec-side counters exist in every build; reference them here so
     * the stage-gated scenarios are not their only users. */
    reset_mocks();
    CHECK(!manifest_opens && !program_opens && !exec_releases &&
          !call_count && !protect_fail_at && !marker_writes && !dispatch_calls &&
          !after_api_read && !call_api_release_base);
    CHECK(card_store.probe && card_store.replace && card_store.remove);
    generic_v2_loads_with_segments();
    generic_header_rejections();
    generic_bounds_rejections();
    generic_spill_read_buffer_ownership();
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    memory_outside_regions_granted_whole();
#endif
    generic_checksum_rejections();
    generic_relocation_rejections();
    data_pointer_relocation_validation();
    adrp_patch_unit();
    api_fs_and_memory_semantics();
    api_log_writes_bounded_text();
    api_ui_draw_text_publishes_pending_text();
    empty_registry_queries();
    menu_registration_api_guards();
#if defined(NLR_STAGE_EXEC)
#ifdef NLR_STAGE_EXEC
    spill_gone_before_uncertain_execution_cleanup();
#else
    spill_survives_uncertain_execution_cleanup();
#endif
    generic_program_full_flow();
    data_pointer_relocation_runs();
#ifdef NLR_STAGE_EXEC
    spill_released_before_entry();
#endif
    cache_clean_failure_ownership();
    safe_mode_rechecked_after_read();
    file_refusal_recorded_as_attempt();
    bounded_alignment_allocation();
    aligned_entry_places_the_regions();
    appledouble_files_left_out_of_the_listing();
    exact_placement_from_the_books();
    short_grant_held_and_retried();
    short_grant_restores_resident_permissions();
    foreground_hook_goes_back_with_its_block();
    autoload_escape_key_answers_like_safe_mode();
    boot_program_starts_once_the_pass_is_done();
    master_off_writes_nothing();
    boot_record_reports_the_outcome();
    boot_escape_waits_for_the_scan_hook();
    alignment_retry_failure_ownership();
    foreground_error_and_exit_returns();
    extension_kept_and_refused_second();
    data_extension_coexists_under_allocator_limit();
    extension_failure_and_ignored_exit();
    foreground_registered_and_cleared();
    budget_and_registry_matrix();
    extension_limit_across_slots();
    restore_failure_kept_and_refused();
    bad_adrp_rejected_at_exec();
    autoload_one_driver_at_a_time();
    boot_checkpoint_waits_for_buttons_and_card();
    boot_checkpoint_leaves_a_silent_card_to_the_page();
    native_checkpoint_asks_like_boot_step();
    boot_checkpoint_escape_held_from_power_on();
    boot_checkpoint_and_page_open_it_once();
    boot_checkpoint_entry_keeps_the_stock_call();
    boot_veil_clears_while_the_program_is_read();
    boot_veil_hold_until_the_entry();
    boot_turn_halves_hold_and_redraw();
    gui_turn_holds_on_the_live_view_side();
    hold_when_is_the_profiles_at_every_hold_point();
    named_tables_restore_and_refuse();
    boot_veil_leaves_the_stock_paths_alone();
    boot_veil_refuses_what_it_cannot_put_back();
    boot_veil_keeps_a_late_render();
    autoload_order_and_saved_snapshot();
    autoload_guard_priority_matrix();
    autoload_settings_and_marker_failures();
    autoload_interruption_points();
    autoload_partial_failure_matrix();
    autoload_worker_guards_and_clear_failure();
    autoload_menu_publication_contract();
    autoload_menu_publication_failure();
    autoload_explicit_recovery_for_next_boot();
    autoload_recovery_preserves_failed_publication();
    autoload_recovery_refusal_matrix();
    foreground_api_ownership_and_quiescence();
    foreground_api_capacity_preserves_owners();
    foreground_exit_callback_drains_api();
    foreground_real_release_notifies_while_draining();
    foreground_busy_loop_stops_and_restarts();
    foreground_stop_failures_retain_ownership();
    foreground_hook_forwards_nonforeground_input();
#elif defined(NLR_STAGE_PREPARE_ONLY)
#ifdef NLR_STAGE_EXEC
    spill_gone_before_uncertain_execution_cleanup();
#else
    spill_survives_uncertain_execution_cleanup();
#endif
    generic_program_full_flow();
    data_pointer_relocation_runs();
#ifdef NLR_STAGE_EXEC
    spill_released_before_entry();
#endif
    cache_clean_failure_ownership();
    safe_mode_rechecked_after_read();
    file_refusal_recorded_as_attempt();
    bounded_alignment_allocation();
    aligned_entry_places_the_regions();
    appledouble_files_left_out_of_the_listing();
    exact_placement_from_the_books();
    short_grant_held_and_retried();
    alignment_retry_failure_ownership();
    prepare_only_and_mode_refusal();
    restore_failure_kept_and_refused();
    bad_adrp_rejected_at_exec();
#else
    start_program_refused_without_exec_stage();
#endif
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("program behavior tests passed\n");
    return 0;
}
