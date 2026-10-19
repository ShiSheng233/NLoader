/* Host-only failure model. These buffers/callbacks are never production
 * bindings and do not substitute for real-card or QEMU validation. */
#include "nlr/native_card_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The same tests run for either slot's root (decision 15): the harness
 * builds them once with the A: root and once with the B: root, naming the
 * root's drive and the other slot's drive. */
#ifndef NLR_TEST_DRIVE
#define NLR_TEST_DRIVE "A:"
#define NLR_TEST_OTHER "B:"
#endif
#define DRIVE NLR_TEST_DRIVE
#define OTHER NLR_TEST_OTHER

static struct nlr_runtime runtime;
/* Two media entries of 32 bytes: a volume may be bound to either. */
static uint8_t volume[192], device[64], media[64], fcb[256];
static uint8_t journal[8192], arena[65536], flag[128];
static _Alignas(NLR_CACHE_LINE) uint8_t directory[8192];
static uint8_t reply_flag[64], shared_frame[NLR_NATIVE_CARD_FRAME_BYTES];
static void *flag_reference = flag;
static void (*callbacks[2])(void *);
static int mounted, exists, safe, pending, missing_enabled, missing_manifest, lock_depth;
static int no_root, root_stats;
static int volume_depth, timeout_during_callback;
static int lifecycle_read_probe;
static int submit_failure, late, flush_failure, sync_failure, read_failure, write_failure;
static int close_failure, move_extent_after_write;
static int missing_ack;
static uint32_t read_limit, cleaned_bytes;
static const void *cleaned_source;
static int writes, flushes, closes, submissions, wakes, starts, publishes, readiness;
/* The stock slot the media entry names; the per-slot flush must be asked
 * for exactly this one. */
static uint32_t flushed_slot = UINT32_MAX;
static int32_t probe_failure;
static int probe_failure_once;
static int32_t enabled_probe_failure;
static int enabled_read_failure, enabled_open_failure, enabled_opens, enabled_probes, manifest_opens;
static uint32_t file_position;
static int current_file;
/* A program's own file (path_file 5): what reached the low-level open and
 * write, so the test can tell the program path from the state file's. */
static uint8_t program_file[24576];
/* A program file read back in pieces (decision 16). With unaligned_fault
 * the fake does what the Z 8's SD reads were seen to do: a read that starts
 * inside a 512-byte sector returns zeros for the first whole sector after
 * that start. */
static uint8_t big_file[42192];
static int unaligned_fault, big_reads, cur_seeks;
static uint32_t big_read_start[64];
static uint32_t program_bytes, program_open_flags, program_write_calls, program_short;
static void *allocations[64];
static unsigned allocation_count;
static const char manifest[] = "EXT|resource_extension|Extension|APPS/E.NLB|2|z8/3.11\n";
static const char enabled[] = "EXT\n";
const struct nlr_identity nlr_identity = {"z8", "3.11"};

static void put(uint8_t *p, uint64_t x, uint32_t bytes)
{ for (uint32_t n = 0; n < bytes; n++) p[n] = (uint8_t)(x >> (8u * n)); }
static int32_t allocate(uint32_t bytes, void **out)
{
    /* Deliberately eight-byte, rather than 64-byte, alignment. */
    void *raw = malloc((size_t)bytes + 72u);
    assert(raw && allocation_count < 64u);
    allocations[allocation_count++] = raw;
    *out = (uint8_t *)raw + 8u;
    return 0;
}
static int32_t release(void *p) { (void)p; assert(0); return 0; }
static void cache(void *p, uint32_t bytes) { assert(p && bytes <= 8192u); }
/* The order of the maintenance around each program-file read: I the
 * before-read invalidate, R the low-level read, C the after-read clean. */
static char cache_order[256];
static unsigned cache_order_n;
static void order(char c) { if (cache_order_n + 1u < sizeof cache_order) cache_order[cache_order_n++] = c; }
static void cache_invalidate(void *p, uint32_t bytes)
{ cache(p, bytes); if (current_file == 8) order('I'); }
static void cache_clean(void *p, uint32_t bytes)
{ cache(p, bytes); if (current_file == 8) order('C'); }
static void clean(void *p, uint32_t bytes) { cache(p, bytes); cleaned_source = p; cleaned_bytes = bytes; }
static void lock(void *p) { assert(p == media && !lock_depth); lock_depth++; }
static void unlock(void *p) { assert(p == media && lock_depth == 1); lock_depth--; }
static void lock_volume(void) { assert(lock_depth == 1 && !volume_depth); volume_depth++; }
static void unlock_volume(void) { assert(lock_depth == 1 && volume_depth == 1); volume_depth--; }
static int32_t claim(void (*cb)(void *)) { assert(lock_depth && !callbacks[0]); callbacks[0] = cb; return 0; }
static int32_t wait_reply(void *object, uint32_t mask, uint32_t *out_bits)
{ assert(object && mask == 1 && out_bits); if (!missing_ack) *out_bits = mask; return 1; }
static int32_t submit(void *frame)
{
    assert(!lock_depth);
    submissions++;
    uint8_t *p = frame;
    assert(nlr_le32(p) == 1 && nlr_le32(p + 0x108) == 0 && nlr_le32(p + 0x10c) == 31);
    assert(nlr_native_card_u64(p + 0x100) == (uintptr_t)&runtime.native_card->request);
    assert(!((uintptr_t)frame & 63u));
    memcpy(shared_frame, frame, sizeof shared_frame);
    if (!late) callbacks[0]((void *)(uintptr_t)nlr_native_card_u64(p + 0x100));
    uint32_t observed = 0;
    assert(nlr_native_card_reply_observe(reply_flag, 1, &observed) == 1);
    return submit_failure ? -1 : 0;
}
static int32_t volume_index(const char *p) { assert(!strcmp(p, DRIVE)); return mounted ? 0 : -1; }
static int32_t volume_ready(int32_t n) { assert(n == 0); return mounted ? 0 : -1; }
static int32_t fcb_get(int32_t v, int32_t slot, void **out)
{ assert(lock_depth && volume_depth == 1 && v == 0 && slot == 0); *out = fcb; return 0; }
static int path_file(const char *path)
{
    if (!strcmp(path, NLR_CARD_ROOT "STATE.NLS")) return exists ? 1 : -1;
    if (!strcmp(path, NLR_MANIFEST_PATH)) return missing_manifest ? -1 : 2;
    if (!strcmp(path, NLR_ENABLED_PATH)) return missing_enabled ? -1 : 3;
    if (!strcmp(path, NLR_SAFE_MODE_PATH)) return safe ? 4 : -1;
    if (!strcmp(path, NLR_AUTOLOAD_PENDING_PATH)) return pending ? 4 : -1;
    if (!strcmp(path, NLR_CARD_ROOT "OUT.TXT")) return 5;
    if (!strcmp(path, DRIVE "\\DCIM\\100TEST\\A.TXT")) return 6;
    if (!strcmp(path, DRIVE "\\NLOADER")) return no_root ? -1 : 7;
    if (!strcmp(path, NLR_CARD_ROOT "APPS\\BIG.NLB")) return 8;
    return -1;
}
static uint32_t size(void)
{ return current_file == 1 ? 8192u : current_file == 2 ? sizeof manifest - 1u : current_file == 3 ? sizeof enabled - 1u : current_file == 8 ? (uint32_t)sizeof big_file : 0; }
static int32_t open_file(const char *path, uint32_t flags, uint32_t mode)
{
    assert(lock_depth && volume_depth == 1 && !mode);
    if (!strcmp(path, NLR_ENABLED_PATH)) {
        enabled_opens++;
        if (enabled_open_failure) return (int32_t)0x80000011u;
    }
    if (!strcmp(path, NLR_MANIFEST_PATH)) manifest_opens++;
    if (path_file(path) == 5) {
        assert(flags == 0 || flags == 1 || flags == 0x301u);
        program_open_flags = flags;
        if (flags == 0x301u) program_bytes = 0;
        current_file = 5; file_position = 0;
        return 0;
    }
    if (flags == 0x301u) { assert(!exists); exists = 1; }
    else assert(flags == 0 || flags == 1 || flags == 2);
    current_file = path_file(path); file_position = 0;
    if (current_file == 1) {
        /* Native flags0 uses metadata-only stat_lookup, which does not fill
         * last_cluster. Existing-file RW2 runs the full open_lookup and
         * obtains the extent from the current file and volume geometry. */
        uint64_t first = nlr_native_card_u64(fcb + 24);
        uint64_t bytes = nlr_native_card_u64(fcb + 8);
        uint64_t cluster = (uint64_t)nlr_le16(volume + 0x54) * nlr_le32(volume + 0x60);
        uint64_t clusters = (bytes + cluster - 1u) / cluster;
        put(fcb + 32, flags == 0 ? 0 : first + clusters - 1u, 8);
    } else {
        assert(flags == 0); /* legacy/manifest/SDK readonly behavior */
    }
    return current_file < 0 ? (int32_t)0x80000010u : 0;
}
static int32_t stat_file(const char *path, void *out)
{
    assert(lock_depth && volume_depth == 1);
    if (!strcmp(path, NLR_ENABLED_PATH)) {
        enabled_probes++;
        if (enabled_probe_failure) return enabled_probe_failure;
    }
    if (probe_failure) {
        int32_t result = probe_failure;
        if (probe_failure_once) probe_failure = 0;
        return result;
    }
    int file = path_file(path);
    if (file < 0) return (int32_t)0x80000010u;
    memset(out, 0, 0x220);
    put((uint8_t *)out + 0x218, file == 1 ? 8192u : 0, 8);
    if (file == 7) {
        root_stats++;
        ((uint8_t *)out)[0x20e] = 0x10; /* a directory */
    }
    return 0;
}
/* The native seek: from the start, the current position or the end; a
 * negative offset may not go below 0; the new position, or UINT32_MAX. */
static uint32_t seek(int32_t fd, int32_t offset, int32_t whence)
{
    assert(lock_depth && volume_depth == 1 && fd == 0);
    assert(whence == NLR_SEEK_SET || whence == NLR_NATIVE_CARD_SEEK_CUR || whence == NLR_SEEK_END);
    if (whence == NLR_NATIVE_CARD_SEEK_CUR) cur_seeks++;
    uint64_t base = whence == NLR_SEEK_END ? size() : whence == NLR_SEEK_SET ? 0 : file_position;
    if (offset < 0 && base < (uint64_t)-(int64_t)offset) return UINT32_MAX;
    file_position = (uint32_t)(base + (uint64_t)(int64_t)offset);
    return file_position;
}
static int32_t read_file(int32_t fd, void *out, uint32_t bytes, uint32_t *received)
{
    assert(lock_depth && volume_depth == 1 && fd == 0);
    if (timeout_during_callback) {
        __atomic_store_n(&runtime.native_card->uncertain, 1u, __ATOMIC_RELEASE);
        __atomic_store_n(&runtime.native_card->request.state, NLR_NATIVE_CARD_REQUEST_UNCERTAIN, __ATOMIC_RELEASE);
    }
    *received = 0;
    if (read_failure || (current_file == 3 && enabled_read_failure)) return -44;
    uint32_t remaining = file_position < size() ? size() - file_position : 0;
    if (bytes > remaining) bytes = remaining;
    if (read_limit && bytes > read_limit) bytes = read_limit;
    const void *source = current_file == 1 ? (const void *)journal : current_file == 2 ? (const void *)manifest : current_file == 8 ? (const void *)big_file : (const void *)enabled;
    if (file_position > size()) bytes = 0;
    memcpy(out, (const uint8_t *)source + file_position, bytes);
    if (current_file == 8) {
        if (big_reads < 64) big_read_start[big_reads] = file_position;
        big_reads++;
        order('R');
        uint32_t sector = (file_position + 511u) & ~511u;
        if (unaligned_fault && file_position % 512u && sector < file_position + bytes) {
            uint32_t end = sector + 512u < file_position + bytes ? sector + 512u : file_position + bytes;
            memset((uint8_t *)out + (sector - file_position), 0, end - sector);
        }
    }
    file_position += bytes; *received = bytes;
    return 0;
}
static int32_t write_file(int32_t fd, const void *data, uint32_t bytes, uint32_t *written)
{
    if (current_file == 5) {
        assert(lock_depth && volume_depth == 1 && fd == 0);
        assert(cleaned_source == data && cleaned_bytes == bytes);
        assert(data == runtime.native_card->request.data);
        cleaned_source = 0; cleaned_bytes = 0;
        program_write_calls++;
        *written = program_short && bytes > program_short ? program_short : bytes;
        assert(file_position + *written <= sizeof program_file);
        memcpy(program_file + file_position, data, *written);
        file_position += *written;
        if (file_position > program_bytes) program_bytes = file_position;
        return 0;
    }
    assert(lock_depth && volume_depth == 1 && fd == 0 && current_file == 1 && file_position + bytes <= 8192u);
    assert(cleaned_source == data && cleaned_bytes == bytes);
    cleaned_source = 0; cleaned_bytes = 0;
    writes++;
    *written = write_failure ? 64u : bytes;
    memcpy(journal + file_position, data, *written); file_position += *written;
    if (move_extent_after_write) { put(fcb + 24, 8, 8); put(fcb + 32, 8, 8); }
    return write_failure ? -45 : 0;
}
static int32_t close_file(int32_t fd) { assert(lock_depth && volume_depth == 1 && fd == 0); closes++; return close_failure ? -47 : 0; }
static int32_t sync_volume(const char *p) { assert(lock_depth && volume_depth == 1 && !strcmp(p, DRIVE)); return sync_failure ? -46 : 0; }
static int32_t slot_flush(uint32_t slot)
{
    const uint8_t *entry = (const uint8_t *)(uintptr_t)nlr_native_card_u64(volume);
    assert(lock_depth && volume_depth == 1 && slot == nlr_le16(entry));
    flushed_slot = slot;
    flushes++;
    return flush_failure ? -1 : 0;
}
static void *menu_getter(void) { return &flag_reference; }
/* The card task (native_card.c): made by the worker family, woken by its
 * flag. Here it runs at once on the flag, as a task of the loader's
 * priority would; `card_paused` keeps it from running (a card task that
 * has not been scheduled yet), and `card_flag_failure` fails the wake. */
static void (*card_callback)(void *self, uint32_t events);
static void *card_self;
static int card_paused, card_flag_failure, card_tasks;
static void worker_init(void *worker, void (*callback)(void *, uint32_t), uint32_t mask,
                        struct nlr_task_config *config)
{
    assert(mask == 1u && config && config->stack_bytes >= 0x4000u);
    assert(!memcmp(config->name, "NLRCARD", 8));
    card_callback = callback;
    card_self = worker;
    put((uint8_t *)worker + NLR_WORKER_ID_OFFSET, 0x41, 4);
    put((uint8_t *)worker + NLR_WORKER_FLAG_OFFSET, 0x42, 4);
    card_tasks++;
}
static void worker_start(void *worker) { assert(worker == card_self); }
static int32_t wake(void *p, uint32_t mask)
{
    if (card_self && p == (uint8_t *)card_self + NLR_WORKER_FLAG_OFFSET) {
        assert(mask == 1u);
        if (card_flag_failure)
            return -1;
        if (!card_paused)
            card_callback(card_self, mask);
        return 0;
    }
    assert(p == flag && mask == 8); wakes++; return 0;
}
/* The time service's delay (time.c): this model has none, the plain delay
 * below is the one waited with. */
int nlr_time_sleep(const struct nlr_time_services *s, uint32_t ms, void (*c)(void *), void *x)
{ (void)s; (void)ms; (void)c; (void)x; assert(!"no time service here"); return -1; }
/* Whether the caller is one of the loader's tasks (runtime.c): its wait
 * bound is the longer one. */
static int loader_task = 1;
int nlr_runtime_on_loader_task(const struct nlr_runtime *r)
{ assert(r == &runtime); return loader_task; }
/* Whether the caller is the worker itself, which submits its own. */
static int worker_task;
int nlr_runtime_on_worker(const struct nlr_runtime *r)
{ assert(r == &runtime); return worker_task; }
/* The delay a caller waits on: `release_after` sleeps later, a held ticket
 * comes free (its caller collected it) or the card task gets to run. */
static int sleeps, release_after;
static struct nlr_native_card_ticket *release_ticket;
static int release_busy;
static void sleep_ms(uint32_t ms)
{
    assert(ms == 1u);
    sleeps++;
    if (release_after && !--release_after) {
        if (release_busy)
            runtime.native_card->busy = 0;
        else if (release_ticket)
            __atomic_store_n(&release_ticket->state, NLR_NATIVE_CARD_TICKET_FREE,
                             __ATOMIC_RELEASE);
        else if (card_paused) {
            card_paused = 0;
            card_callback(card_self, 1u);
        }
    }
}
static int32_t mount_call(const char *p, void *d, void *params)
{
    assert(!strcmp(p, DRIVE) && d == device && params == media);
    if (lifecycle_read_probe) {
        assert(runtime.native_card->transitions == 1 && !runtime.native_card->bound);
        assert(nlr_native_card_snapshot(&runtime) == NLR_NOT_READY);
        assert(!runtime.native_card->bound && !writes);
    }
    return -73;
}
static int32_t unmount_call(const char *p) { assert(!strcmp(p, DRIVE) || !strcmp(p, OTHER)); return -74; }
static int32_t ready(void *p) { (void)p; return readiness; }
static const struct nlr_resource_services resource_services = {.can_publish = ready};

const struct nlr_native_card_services nlr_native_card_services = {
    .claim = claim, .submit_frame = submit, .callback_table = callbacks,
    .request_bytes = 0x118, .request_volume_offset = 8, .request_user_offset = 0x100,
    .request_callback_offset = 0x108, .request_operation_offset = 0x10c,
    .request_result_offset = 0x110, .request_priority_offset = 0xf0, .operation = 31,
    .mutex = media, .lock = lock, .unlock = unlock, .open = open_file, .read = read_file,
    .write = write_file, .seek = seek, .close = close_file, .stat = stat_file,
    .stat_bytes = 0x220, .not_found = 0x80000010u, .write_flags = 1, .create_flags = 0x301,
    .journal_read_flags = 2,
    .volume_sync = sync_volume, .volume_index = volume_index, .volume_ready = volume_ready,
    .fcb_get = fcb_get, .slot_flush = slot_flush, .clean_source = clean,
    .low_unmount = unmount_call,
    .volume_lock = lock_volume, .volume_unlock = unlock_volume,
    .rpc = {.wait_callee = wait_reply, .reply_flag = reply_flag, .shared_frame = shared_frame},
    .layout = {
        .runtime_ram_start = 1, .runtime_ram_end = UINTPTR_MAX,
        .volume_table = volume, .volume_count = 1, .volume_stride = sizeof volume,
        .volume_device_offset = 0, .volume_state_offset = 0x50, .volume_type_offset = 0x52,
        .volume_sector_bytes_offset = 0x54, .volume_cluster_sectors_offset = 0x60, .exfat_type = 4,
        .media_table = device, .media_count = 2, .media_stride = 32,
        .media_slot_offset = 0, .slot_count = 2,
        .stat_size_offset = 0x218, .stat_attributes_offset = 0x20e,
        .fcb_table = fcb, .fcb_volume_count = 1, .fcb_slot_count = 1,
        .fcb_volume_stride = sizeof fcb, .fcb_slot_stride = sizeof fcb,
        .fcb_flags_offset = 0, .fcb_ready_mask = 1, .fcb_reject_mask = 64,
        .fcb_valid_size_offset = 8, .fcb_data_size_offset = 16,
        .fcb_first_cluster_offset = 24, .fcb_last_cluster_offset = 32, .fcb_no_fat_chain_offset = 40,
    },
    .mount = {.callee = mount_call}, .unmount = {.callee = unmount_call},
    .menu = {.callee = menu_getter, .wake_mask = 8},
};
const struct nlr_services nlr_services = {
    .alloc = allocate, .release = release, .native_card = &nlr_native_card_services,
    .cache_before_read = cache_invalidate, .cache_after_read = cache_clean, .flag_set = wake,
    .resources = &resource_services, .sleep_ms = sleep_ms,
    .worker_init = worker_init, .worker_start = worker_start,
    .file_open = nlr_native_card_file_open, .file_read = nlr_native_card_file_read,
    .file_seek = nlr_native_card_file_seek, .file_close = nlr_native_card_file_close,
};

/* The allocation entry (core/exec.c) for a build without heap books. */
void *nlr_alloc_whole(const struct nlr_services *s, uint32_t bytes)
{ void *block = 0; return s->alloc(bytes, &block) == 0 ? block : 0; }
struct nlr_runtime *nlr_runtime_find(const struct nlr_services *s, unsigned *named)
{ assert(s == &nlr_services); if (named) *named = 1; return &runtime; }
int nlr_runtime_create(struct nlr_runtime **out, const struct nlr_services *s, uint32_t bytes)
{ (void)out; (void)s; (void)bytes; assert(0); return -1; }
/* The loader's directory: MANIFEST's line, or -- on a card without
 * MANIFEST -- the same program as one that describes itself. */
static int directory_reads;
int nlr_runtime_read_directory(struct nlr_runtime *r)
{
    static const char described_ext[] = "EXT | resource_extension | Extension | APPS/E.NLB | 2 | z8/3.11\n";
    const char *text = missing_manifest ? described_ext : manifest;
    uint32_t bytes = missing_manifest ? sizeof described_ext - 1u : sizeof manifest - 1u;
    directory_reads++;
    memcpy(directory, text, bytes);
    int result = nlr_manifest_parse(&r->directory, directory, bytes);
    nlr_manifest_gate(&r->directory, "z8", "3.11");
    r->directory_result = result;
    return result;
}
int nlr_runtime_autoload_begin(struct nlr_runtime *r, const struct nlr_card_store *s)
{ assert(s == nlr_native_card_store()); starts++; r->autoload.phase = NLR_AUTOLOAD_DONE; return 0; }
int nlr_runtime_autoload_interrupt(struct nlr_runtime *r, int32_t reason)
{ r->autoload.phase = NLR_AUTOLOAD_STOPPED; r->autoload.result = reason; return reason; }
int nlr_runtime_autoload_step(struct nlr_runtime *r) { (void)r; return 0; }
int nlr_runtime_autoload_step_owned(struct nlr_runtime *r) { return nlr_runtime_autoload_step(r); }
int nlr_runtime_menu_publish(struct nlr_runtime *r) { (void)r; publishes++; return 0; }
/* The menu task is never a hold point: its checkpoint must not take the
 * boot hold's halves, so the menu's own exit runs as in stock. */
static int turns;
int nlr_runtime_boot_turn_enter(struct nlr_runtime *r)
{ (void)r; assert(!"the menu checkpoint took the boot hold"); return 0; }
void nlr_runtime_boot_turn_leave(struct nlr_runtime *r)
{ (void)r; assert(!"the menu checkpoint took the boot hold"); }
void nlr_runtime_exit_menu_checkpoint(struct nlr_runtime *r) { assert(r == &runtime); turns++; }
/* The start-up escape and the boot record's retry are the runtime's
 * (test_program.c covers them); here only where the checkpoint asks. */
static int escape_answer, settles;
int nlr_runtime_boot_escape(struct nlr_runtime *r) { assert(r == &runtime); return escape_answer; }
/* The ask schedule is the runtime's (test_program.c); here only that the
 * checkpoint asks when it says so and tells it what the card answered. */
static int ask_refused, no_card_calls, no_card_mounted;
uint32_t nlr_clock_ms(void) { return 0; }
int nlr_runtime_boot_ask_due(struct nlr_runtime *r, uint32_t now)
{ (void)now; assert(r == &runtime); return !ask_refused; }
void nlr_runtime_boot_no_card(struct nlr_runtime *r, int m)
{ assert(r == &runtime); no_card_calls++; no_card_mounted = m; }
void nlr_runtime_boot_mark_settle(struct nlr_runtime *r) { assert(r == &runtime); settles++; }

/* Independent reflected CRC-32 for hand-made format 1 records. */
static uint32_t crc32_frame(const uint8_t *frame)
{
    uint32_t crc = UINT32_MAX;
    for (uint32_t n = 0; n < 4096u; n++) {
        crc ^= n >= 32u && n < 36u ? 0u : frame[n];
        for (int bit = 0; bit < 8; bit++)
            crc = crc & 1u ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
    }
    return ~crc;
}

static void reset(int new_journal)
{
    memset(&runtime, 0, sizeof runtime); runtime.load.svc = &nlr_services;
    runtime.load.arena = arena; runtime.load.capacity = sizeof arena;
    memset(callbacks, 0, sizeof callbacks); memset(volume, 0, sizeof volume);
    put(volume, (uintptr_t)device, 8); volume[0x50] = 1; volume[0x52] = 4;
    /* Actual stock neighbors: the type is one byte, while +0x54 is the
     * 512-byte sector size. Reading type as u32 would yield 0x02000004. */
    put(volume + 0x54, 512, 2);
    put(volume + 0x56, 128, 2); put(volume + 0x58, 16, 2);
    put(volume + 0x60, 256, 4);
    put(volume + 0x64, 2048, 4);
    /* Media entry 0 is slot 0, entry 1 slot 1 (stock: one per card slot). */
    memset(device, 0, sizeof device); put(device + 32, 1, 2);
    flushed_slot = UINT32_MAX;
    memset(fcb, 0, sizeof fcb);
    fcb[0] = 1; put(fcb + 8, 8192, 8); put(fcb + 16, 8192, 8);
    put(fcb + 24, 4, 8); put(fcb + 32, 4, 8); fcb[40] = 1;
    mounted = exists = 1; safe = pending = missing_enabled = missing_manifest = lock_depth = volume_depth = 0;
    timeout_during_callback = lifecycle_read_probe = 0;
    submit_failure = late = flush_failure = sync_failure = read_failure = write_failure = 0;
    close_failure = move_extent_after_write = missing_ack = 0;
    read_limit = cleaned_bytes = 0; cleaned_source = 0;
    writes = flushes = closes = submissions = wakes = starts = publishes = 0;
    readiness = 0; probe_failure = probe_failure_once = 0;
    escape_answer = settles = 0;
    card_self = 0; card_callback = 0; card_paused = card_flag_failure = card_tasks = 0;
    loader_task = 1; release_ticket = 0; release_after = sleeps = 0;
    worker_task = release_busy = 0;
    no_root = root_stats = ask_refused = no_card_calls = no_card_mounted = 0;
    directory_reads = 0;
    unaligned_fault = big_reads = cur_seeks = 0;
    enabled_probe_failure = 0; enabled_open_failure = enabled_read_failure = enabled_opens = enabled_probes = manifest_opens = 0;
    if (new_journal) {
        memset(journal, 0, sizeof journal);
        struct nlr_card_state initial = {.generation = 5, .enabled_count = 1};
        memcpy(initial.enabled_id[0], "EXT", 4);
        assert(nlr_card_state_encode(&initial, journal, 4096) == 0);
    }
}

int main(void)
{
    assert(NLR_CARD_ROOT[0] == DRIVE[0] && DRIVE[0] != OTHER[0]);
    reset(1);
    assert(volume[0x52] == 4 && nlr_le32(volume + 0x52) != 4);
    assert(nlr_le32(volume + 0x54) != 512);
    assert(nlr_native_card_u64(volume + 0x60) != 256);
    int32_t readonly = nlr_native_card_file_open(NLR_CARD_ROOT "STATE.NLS", 0, 0);
    assert(readonly == 0 && !nlr_native_card_u64(fcb + 32));
    assert(nlr_native_card_file_close(readonly) == 0);
    assert(nlr_native_card_snapshot(&runtime) == 0 && nlr_native_card_u64(fcb + 32) == 4);
    reset(1);
    nlr_native_card_transaction((void *)1); assert(!submissions);
    assert(nlr_native_card_snapshot(&runtime) == 0);
    assert(runtime.native_card->current.generation == 5);
    assert(!((uintptr_t)runtime.native_card & 63u));
    int result = nlr_native_card_pending(&runtime, 1);
    if (result) fprintf(stderr, "arm=%d phase=%u reason=%llu writes=%d flushes=%d\n", result,
                        runtime.native_card->request.commit.phase,
                        (unsigned long long)runtime.native_card->request.native_reason, writes, flushes);
    if (result) fprintf(stderr, "manifest=%u enabled=%u id=%s count=%u\n",
                        runtime.native_card->request.manifest.error, runtime.native_card->request.legacy.error,
                        runtime.native_card->request.desired.enabled_id[0], runtime.native_card->request.desired.enabled_count);
    assert(result == 0 && writes == 1 && flushes == 1);
    assert(runtime.native_card->current.pending == 1 && runtime.native_card->current.generation == 6);
    assert(nlr_native_card_pending(&runtime, 0) == 0 && runtime.native_card->current.generation == 7);
    /* Only the card task submits, and it
     * gives the request back when the filesystem has answered. A caller
     * that never collects its answer (a starved task: its ticket is DONE
     * and stays so) holds its ticket and nothing else: the next caller is
     * served at once, with no wait at all. */
    {
        struct nlr_native_card_runtime *c = runtime.native_card;
        assert(card_tasks == 1 && c->card_task_started && !c->busy);
        uint32_t seen = 9;
        int before = submissions;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == 0 && !seen);
        c->tickets[0].state = NLR_NATIVE_CARD_TICKET_DONE; /* never collected */
        seen = 9; sleeps = 0;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == 0 && !seen);
        assert(!sleeps && submissions == before + 2 && !c->busy);
        assert(c->tickets[0].state == NLR_NATIVE_CARD_TICKET_DONE);
        c->tickets[0].state = NLR_NATIVE_CARD_TICKET_FREE;
    }
    /* Every ticket held (more callers than tickets): a loader task waits
     * its bound, and gets the first ticket that comes free; past the bound
     * the answer is busy and nothing was asked of the card. */
    {
        struct nlr_native_card_runtime *c = runtime.native_card;
        for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
            c->tickets[n].state = NLR_NATIVE_CARD_TICKET_DONE;
        uint32_t seen = 9;
        int before = submissions;
        sleeps = 0; release_after = 5; release_ticket = &c->tickets[3];
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == 0 && !seen);
        assert(sleeps == 5 && submissions == before + 1);
        c->tickets[3].state = NLR_NATIVE_CARD_TICKET_DONE;
        sleeps = 0; release_after = 0; release_ticket = 0; seen = 9;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == NLR_BUSY && seen == 9);
        assert(sleeps == 3000 && submissions == before + 1);
        assert(nlr_native_card_file_close(0) == NLR_BUSY);
        assert(nlr_native_card_file_open(NLR_CARD_ROOT "STATE.NLS", 0, 0) < 0);
        /* The camera's own tasks (the menu task) wait a short bound only. */
        loader_task = 0; sleeps = 0;
        assert(nlr_native_card_snapshot(&runtime) == NLR_BUSY && sleeps == 250);
        loader_task = 1;
        for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
            c->tickets[n].state = NLR_NATIVE_CARD_TICKET_FREE;
        sleeps = 0;
        assert(nlr_native_card_snapshot(&runtime) == 0 && !sleeps);
    }
    /* The worker submits its own: no ticket, no card task; while the card
     * task holds the request for its transaction, the worker waits for it. */
    {
        struct nlr_native_card_runtime *c = runtime.native_card;
        uint32_t seen = 9;
        int before = submissions;
        worker_task = 1; card_paused = 1;
        for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
            c->tickets[n].state = NLR_NATIVE_CARD_TICKET_DONE;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == 0 && !seen);
        assert(submissions == before + 1 && !c->busy);
        c->busy = 1; release_busy = 1; release_after = 4; sleeps = 0; seen = 9;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == 0 && !seen);
        assert(sleeps == 4 && submissions == before + 2 && !c->busy);
        c->busy = 1; release_after = 0; sleeps = 0; seen = 9;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == NLR_BUSY && seen == 9);
        assert(sleeps == 3000 && submissions == before + 2);
        c->busy = 0; release_busy = 0; worker_task = 0; card_paused = 0;
        for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
            c->tickets[n].state = NLR_NATIVE_CARD_TICKET_FREE;
    }
    /* A ticket the card task has not started within the bound is taken back
     * (nothing asked of the card); one it starts in time is answered. */
    {
        struct nlr_native_card_runtime *c = runtime.native_card;
        uint32_t seen = 9;
        int before = submissions;
        card_paused = 1; sleeps = 0; release_after = 7; release_ticket = 0;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == 0 && !seen);
        assert(sleeps == 7 && submissions == before + 1);
        card_paused = 1; sleeps = 0; release_after = 0; loader_task = 0; seen = 9;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == NLR_BUSY && seen == 9);
        assert(sleeps == 250 && submissions == before + 1);
        for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
            assert(c->tickets[n].state == NLR_NATIVE_CARD_TICKET_FREE);
        card_paused = 0; loader_task = 1;
        card_flag_failure = 1;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == NLR_IO);
        card_flag_failure = 0;
        assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &seen) == 0 && !seen);
    }
    uint32_t present = 77;
    probe_failure = (int32_t)0x80000011u;
    assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &present) == NLR_IO && present == 77);
    probe_failure = 0;
    assert(nlr_native_card_probe(&runtime, NLR_SAFE_MODE_PATH, &present) == 0 && present == 0);
    assert(nlr_native_card_file_open(OTHER "\\NLOADER\\E.NLB", 0, 0) < 0);
    assert(nlr_native_card_file_open(NLR_CARD_ROOT "../E.NLB", 0, 0) < 0);
    /* ABI 9: the card's DCIM on the loader's drive, for reading only */
    {
        int before = submissions;
        int32_t picture = nlr_native_card_file_open(DRIVE "\\DCIM\\100TEST\\A.TXT", 0, 0);
        assert(picture >= 0 && submissions == before + 1);
        assert(nlr_native_card_file_close(picture) == 0);
        before = submissions;
        assert(nlr_native_card_file_open(DRIVE "\\DCIM\\100TEST\\A.TXT", 1, 0) < 0);
        assert(nlr_native_card_file_open(DRIVE "\\DCIM\\100TEST\\A.TXT", 0x301, 0) < 0);
        assert(nlr_native_card_file_open(DRIVE "\\DCIM\\", 0, 0) < 0);
        assert(nlr_native_card_file_open(DRIVE "\\DCIMX\\A.TXT", 0, 0) < 0);
        assert(nlr_native_card_file_open(OTHER "\\DCIM\\A.TXT", 0, 0) < 0);
        assert(nlr_native_card_file_open(DRIVE "\\DCIM\\..\\NLOADER\\STATE.NLS", 0, 0) < 0);
        assert(nlr_native_card_file_open(DRIVE "\\DCIM\\X:\\A.TXT", 0, 0) < 0);
        uint32_t seen = 7;
        assert(nlr_native_card_probe(&runtime, DRIVE "\\DCIM\\100TEST\\A.TXT", &seen) ==
                   NLR_REFUSED && seen == 7);
        assert(submissions == before);
    }
    assert(nlr_native_card_mount_observe(DRIVE, device, media) == -73);
    assert(nlr_native_card_snapshot(&runtime) == NLR_REFUSED);
    assert(nlr_native_card_unmount_observe(DRIVE) == -74);
    assert(nlr_native_card_low_unmount_observe(DRIVE) == -74);
    assert(!runtime.native_card->transitions);
    reset(1); assert(nlr_native_card_attach(&runtime) == 0); lifecycle_read_probe = 1;
    assert(nlr_native_card_mount_observe(DRIVE, device, media) == -73);
    assert(!runtime.native_card->transitions && !runtime.native_card->bound && !writes);
    assert(nlr_native_card_snapshot(&runtime) == 0 && runtime.native_card->bound);

    reset(1); assert(nlr_native_card_snapshot(&runtime) == 0);
    flush_failure = 1;
    assert(nlr_native_card_pending(&runtime, 1) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    int calls = submissions;
    /* the stock per-slot flush's own answer is the reason */
    assert(runtime.native_card->request.native_reason == UINT32_MAX);
    assert(nlr_native_card_pending(&runtime, 1) == NLR_CARD_STATE_COMMIT_UNCERTAIN && submissions == calls);
    reset(0); assert(nlr_native_card_snapshot(&runtime) == 0);
    assert(runtime.native_card->current.generation == 6 && runtime.native_card->current.pending == 1);

    /* One identity and one
     * durability rule for every slot. The volume index is whichever volume
     * entry the slot was bound to (an SD card alone is bound to the first),
     * so it need not equal the slot; the slot comes from the media entry,
     * and the commit flushes exactly that slot. */
    reset(1); put(volume, (uintptr_t)(device + 32), 8);
    assert(nlr_native_card_snapshot(&runtime) == 0);
    assert(runtime.native_card->owner.volume_index == 0 && runtime.native_card->owner.slot == 1);
    assert(nlr_native_card_pending(&runtime, 1) == 0 && writes == 1 && flushes == 1 &&
           flushed_slot == 1);
    reset(1);
    assert(nlr_native_card_pending(&runtime, 1) == NLR_NOT_READY); /* no snapshot yet */
    assert(nlr_native_card_snapshot(&runtime) == 0 && nlr_native_card_pending(&runtime, 1) == 0 &&
           flushed_slot == 0);
    /* a media slot outside the stock slot table is no card of this layout:
     * nothing is read or written */
    reset(1); put(device, 2, 2);
    assert(nlr_native_card_snapshot(&runtime) == NLR_NOT_READY && !writes && !flushes);
    assert(!runtime.native_card->bound);
    /* a volume not mounted, or not exFAT, is no card either */
    reset(1); volume[0x50] = 0;
    assert(nlr_native_card_snapshot(&runtime) == NLR_NOT_READY && !runtime.native_card->bound);
    reset(1); volume[0x52] = 3;
    assert(nlr_native_card_snapshot(&runtime) == NLR_NOT_READY && !runtime.native_card->bound);
    /* a device field that is not exactly one of the media entries */
    reset(1); put(volume, (uintptr_t)(device + 4), 8);
    assert(nlr_native_card_snapshot(&runtime) == NLR_NOT_READY && !runtime.native_card->bound);
    reset(1); put(volume, (uintptr_t)(device + 64), 8);
    assert(nlr_native_card_snapshot(&runtime) == NLR_NOT_READY && !runtime.native_card->bound);
    /* Once bound, the volume rebound to another media entry is another
     * card, even with no lifecycle call observed: refused for the rest of
     * this boot, and nothing is written. */
    reset(1); assert(nlr_native_card_snapshot(&runtime) == 0 && runtime.native_card->bound);
    put(volume, (uintptr_t)(device + 32), 8);
    assert(nlr_native_card_pending(&runtime, 1) == NLR_REFUSED && !writes && !flushes);
    put(volume, (uintptr_t)device, 8);
    assert(nlr_native_card_snapshot(&runtime) == NLR_REFUSED);
    /* An observed unmount and mount of the loader's volume (a card taken out
     * and one put back in the same slot, the same media entry and the same
     * volume) is another card too: the epoch moved. */
    reset(1); assert(nlr_native_card_snapshot(&runtime) == 0);
    assert(nlr_native_card_unmount_observe(DRIVE) == -74);
    assert(nlr_native_card_mount_observe(DRIVE, device, media) == -73);
    assert(nlr_native_card_pending(&runtime, 1) == NLR_REFUSED && !writes && !flushes);
    /* the other slot's lifecycle is not the loader's card */
    reset(1); assert(nlr_native_card_snapshot(&runtime) == 0);
    assert(nlr_native_card_unmount_observe(OTHER) == -74);
    assert(nlr_native_card_pending(&runtime, 1) == 0 && flushes == 1);

    reset(1); assert(nlr_native_card_snapshot(&runtime) == 0); write_failure = 1;
    assert(nlr_native_card_pending(&runtime, 1) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    reset(0); assert(nlr_native_card_snapshot(&runtime) == 0 && runtime.native_card->current.generation == 5);
    reset(1); read_failure = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_IO && !writes);
    reset(1); fcb[40] = 0;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_UNSUPPORTED && !writes);
    reset(1); safe = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_DISABLED && !writes);
    reset(1); probe_failure = (int32_t)0x80000011u;
    assert(nlr_manifest_read(&runtime.directory, &nlr_services, directory, sizeof directory, 0) == NLR_IO);
    assert(submissions == 1 && !closes && !writes);
    reset(1); safe = 1;
    assert(nlr_manifest_read(&runtime.directory, &nlr_services, directory, sizeof directory, 0) == NLR_DISABLED);
    assert(submissions == 1 && !closes && !writes);
    /* the card's one request held elsewhere: busy, nothing asked, and the
     * directory read before left exactly as it was */
    reset(1);
    runtime.directory.count = 3;
    runtime.directory.usable = 2;
    runtime.directory.buffer = directory;
    assert(nlr_native_card_attach(&runtime) == NLR_OK && runtime.native_card);
    for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
        runtime.native_card->tickets[n].state = NLR_NATIVE_CARD_TICKET_DONE;
    assert(nlr_manifest_read(&runtime.directory, &nlr_services, directory, sizeof directory, 0) == NLR_BUSY);
    assert(!submissions && !closes && !writes);
    assert(runtime.directory.count == 3 && runtime.directory.usable == 2 &&
           runtime.directory.buffer == directory);
    for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
        runtime.native_card->tickets[n].state = NLR_NATIVE_CARD_TICKET_FREE;
    reset(1); read_limit = 7;
    assert(nlr_native_card_snapshot(&runtime) == 0 && runtime.native_card->current.generation == 5);
    reset(1); assert(nlr_native_card_snapshot(&runtime) == 0); sync_failure = 1;
    assert(nlr_native_card_pending(&runtime, 1) == NLR_CARD_STATE_COMMIT_UNCERTAIN && !flushes);
    reset(1); assert(nlr_native_card_snapshot(&runtime) == 0); move_extent_after_write = 1;
    assert(nlr_native_card_pending(&runtime, 1) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    reset(1); submit_failure = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    assert(runtime.native_card->request.state == NLR_NATIVE_CARD_REQUEST_UNCERTAIN);
    reset(1); missing_ack = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    assert(runtime.native_card->request.native_submit_result == 0 && !runtime.native_card->request.native_reply_bits);
    assert(runtime.native_card->request.state == NLR_NATIVE_CARD_REQUEST_UNCERTAIN);
    missing_ack = 0;
    uint32_t foreign_ack = 0;
    assert(nlr_native_card_reply_observe(flag, 1, &foreign_ack) == 1 && foreign_ack == 1);
    assert(!runtime.native_card->request.native_reply_bits);

    reset(1); timeout_during_callback = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    assert(runtime.native_card->request.state == NLR_NATIVE_CARD_REQUEST_UNCERTAIN && !writes);

    reset(1); late = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    struct nlr_native_card_request *held = &runtime.native_card->request;
    callbacks[0](held);
    assert(held->state == NLR_NATIVE_CARD_REQUEST_UNCERTAIN && !runtime.native_card->state_valid);
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_COMMIT_UNCERTAIN && submissions == 1);

    reset(1); exists = 0; pending = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_NEEDS_MIGRATION);
    assert(runtime.native_card->current.pending == 1);
    assert(nlr_native_card_commit_state(&runtime, &runtime.native_card->current, NLR_CARD_STATE_MIGRATE) == 0);
    assert(exists && runtime.native_card->current.pending == 1 && runtime.native_card->current.generation == 1);
    reset(1); exists = 0; missing_enabled = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_NEEDS_MIGRATION);
    assert(!exists && !writes && !enabled_opens && enabled_probes == 1);
    assert(runtime.native_card->current.enabled_count == 0 && runtime.native_card->current.pending == 0);
    assert(nlr_native_card_commit_state(&runtime, &runtime.native_card->current, NLR_CARD_STATE_MIGRATE) == 0);
    assert(exists && runtime.native_card->current.generation == 1 && !runtime.native_card->current.enabled_count);
    reset(1); exists = 0; missing_enabled = pending = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_NEEDS_MIGRATION);
    assert(runtime.native_card->current.pending == 1 && !runtime.native_card->current.enabled_count);
    assert(!enabled_opens && enabled_probes == 1);
    assert(nlr_native_card_commit_state(&runtime, &runtime.native_card->current, NLR_CARD_STATE_MIGRATE) == 0);
    assert(runtime.native_card->current.pending == 1 && runtime.native_card->current.generation == 1);
    reset(1); exists = 0; missing_enabled = 1; enabled_probe_failure = (int32_t)0x80000011u;
    assert(nlr_native_card_snapshot(&runtime) == NLR_IO && !exists && !writes && !enabled_opens);
    assert(runtime.native_card->request.native_reason == 0x80000011u);
    reset(1); exists = 0; enabled_read_failure = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_IO && !exists && !writes);
    assert(enabled_opens == 1 && enabled_probes == 1);
    reset(1); exists = 0; enabled_open_failure = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_IO && !exists && !writes);
    assert(enabled_opens == 1 && enabled_probes == 1);
    assert(runtime.native_card->request.native_reason == 0x80000011u);
    reset(1); exists = 0;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_NEEDS_MIGRATION);
    assert(runtime.native_card->current.enabled_count == 1 && !strcmp(runtime.native_card->current.enabled_id[0], "EXT"));
    assert(enabled_opens == 1 && enabled_probes == 1);
    /* A card whose programs describe themselves has no MANIFEST: only the
     * exact native absence lets the fresh card migrate (empty selection);
     * an ENABLED naming an id with no directory to find it in is refused;
     * the loader's own directory (described programs) names it. */
    reset(1); exists = 0; missing_enabled = missing_manifest = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_NEEDS_MIGRATION);
    assert(manifest_opens == 1 && !enabled_opens && !runtime.native_card->current.enabled_count);
    assert(nlr_native_card_commit_state(&runtime, &runtime.native_card->current, NLR_CARD_STATE_MIGRATE) == 0);
    assert(exists && runtime.native_card->current.generation == 1);
    reset(1); exists = 0; missing_manifest = 1;
    assert(nlr_native_card_snapshot(&runtime) != NLR_CARD_STATE_NEEDS_MIGRATION && !exists && !writes);
    reset(1); exists = 0; missing_manifest = 1;
    static const char described[] = "EXT | resource_extension | Extension | APPS/E.NLB | 2 | z8/3.11\n";
    runtime.directory.buffer = (const uint8_t *)described;
    runtime.directory.bytes = sizeof described - 1u;
    runtime.directory_result = NLR_OK;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_NEEDS_MIGRATION);
    assert(runtime.native_card->current.enabled_count == 1 && !strcmp(runtime.native_card->current.enabled_id[0], "EXT"));
    reset(1); exists = 0; missing_manifest = 1; probe_failure = (int32_t)0x80000011u;
    assert(nlr_native_card_snapshot(&runtime) == NLR_IO && !exists && !writes);
    reset(1); exists = 0; missing_enabled = safe = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_DISABLED && !exists && !writes);
    assert(!manifest_opens && !enabled_opens && !enabled_probes);

    /* With a MANIFEST, a program that describes itself and is not named
     * there can be enabled: the names are the loader's directory when it
     * was built on these very MANIFEST bytes, and only MANIFEST's when the
     * directory came from other bytes. */
    {
        static char listed[512];
        static const char desc_line[] =
            "DESC | resource_extension | Described | APPS/D.NLB | 2 | z8/3.11\n";
        struct nlr_enabled both = {.count = 2};
        strcpy(both.id[0], "EXT");
        strcpy(both.id[1], "DESC");
        reset(1);
        assert(nlr_native_card_snapshot(&runtime) == 0);
        assert(nlr_native_card_save_enabled(&runtime, &both) == NLR_FORMAT && writes == 0);
        reset(1);
        memcpy(listed, manifest, sizeof manifest - 1u);
        memcpy(listed + sizeof manifest - 1u, desc_line, sizeof desc_line);
        runtime.directory.buffer = (const uint8_t *)listed;
        runtime.directory.bytes = (uint32_t)(sizeof manifest - 1u + sizeof desc_line - 1u);
        runtime.directory_result = NLR_OK;
        assert(nlr_native_card_snapshot(&runtime) == 0);
        assert(nlr_native_card_save_enabled(&runtime, &both) == 0 && writes == 1);
        assert(runtime.native_card->current.enabled_count == 2 &&
               !strcmp(runtime.native_card->current.enabled_id[1], "DESC"));
        /* the loader's lines may repeat MANIFEST's id as a greyed duplicate */
        {
            static char dup[512];
            static const char again[] =
                "EXT | resource_extension | Again | APPS/X.NLB | 2 | z8/3.11\n";
            uint32_t at = 0;
            memcpy(dup, manifest, sizeof manifest - 1u);
            at += sizeof manifest - 1u;
            memcpy(dup + at, again, sizeof again - 1u);
            at += sizeof again - 1u;
            memcpy(dup + at, desc_line, sizeof desc_line - 1u);
            at += sizeof desc_line - 1u;
            reset(1);
            runtime.directory.buffer = (const uint8_t *)dup;
            runtime.directory.bytes = at;
            runtime.directory_result = NLR_OK;
            assert(nlr_native_card_snapshot(&runtime) == 0);
            assert(nlr_native_card_save_enabled(&runtime, &both) == 0 && writes == 1);
        }
        /* a directory from other MANIFEST bytes is not used */
        reset(1);
        listed[0] = 'X';
        runtime.directory.buffer = (const uint8_t *)listed;
        runtime.directory.bytes = (uint32_t)(sizeof manifest - 1u + sizeof desc_line - 1u);
        runtime.directory_result = NLR_OK;
        assert(nlr_native_card_snapshot(&runtime) == 0);
        assert(nlr_native_card_save_enabled(&runtime, &both) == NLR_FORMAT && writes == 0);
        listed[0] = 'E';
        /* nor one whose read failed */
        reset(1);
        runtime.directory.buffer = (const uint8_t *)listed;
        runtime.directory.bytes = (uint32_t)(sizeof manifest - 1u + sizeof desc_line - 1u);
        runtime.directory_result = NLR_IO;
        assert(nlr_native_card_snapshot(&runtime) == 0);
        assert(nlr_native_card_save_enabled(&runtime, &both) == NLR_FORMAT && writes == 0);
    }

    /* A mounted card without the loader's directory: the snapshot says so
     * before SAFE_MODE or anything else is asked, and nothing is created. */
    reset(1); exists = 0; no_root = 1;
    assert(nlr_native_card_snapshot(&runtime) == NLR_CARD_STATE_NO_DIRECTORY);
    assert(root_stats == 0 && !exists && !writes && !manifest_opens && !enabled_probes);
    assert(nlr_native_card_commit_state(&runtime, &runtime.native_card->current,
                                        NLR_CARD_STATE_MIGRATE) == NLR_CARD_STATE_NO_DIRECTORY);
    assert(!exists && !writes && !runtime.native_card->uncertain);
    reset(1);
    assert(nlr_native_card_snapshot(&runtime) == NLR_OK && root_stats == 1);

    reset(1); mounted = 0; turns = 0;
    assert(nlr_native_card_menu_checkpoint() == &flag_reference && !starts);
    mounted = 1; readiness = NLR_BUSY;
    assert(nlr_native_card_menu_checkpoint() == &flag_reference && !starts);
    readiness = 0;
    assert(nlr_native_card_menu_checkpoint() == &flag_reference && starts == 1);
    nlr_native_card_menu_checkpoint(); assert(starts == 1);
    assert(turns == 4);
    /* The card is asked only on the turns the runtime's schedule allows;
     * what it answered goes back to it: no card, or a card without the
     * loader's directory. Neither opens the pass or writes anything. */
    reset(1); mounted = 0; ask_refused = 1;
    nlr_native_card_menu_checkpoint();
    assert(!submissions && !no_card_calls && runtime.autoload.phase == NLR_AUTOLOAD_NEW);
    ask_refused = 0;
    nlr_native_card_menu_checkpoint();
    assert(submissions == 1 && no_card_calls == 1 && !no_card_mounted && !starts);
    assert(runtime.autoload.phase == NLR_AUTOLOAD_NEW && !runtime.native_card->bound);
    /* A card without MANIFEST and STATE.NLS but with an old ENABLED naming
     * a program that describes itself: the first snapshot cannot resolve
     * the name, so the directory is listed and the snapshot asked again;
     * the pass then opens (sp-007). */
    reset(1); exists = 0; missing_manifest = 1;
    runtime.directory_result = NLR_NOT_READY; /* as a new runtime starts */
    nlr_native_card_menu_checkpoint();
    assert(directory_reads == 1 && starts == 1 && runtime.autoload.phase == NLR_AUTOLOAD_DONE);
    assert(runtime.native_card->current.enabled_count == 1 &&
           !strcmp(runtime.native_card->current.enabled_id[0], "EXT") && !writes);
    reset(1); exists = 0; no_root = 1;
    nlr_native_card_menu_checkpoint();
    assert(submissions == 1 && no_card_calls == 1 && no_card_mounted == 1 && !starts);
    assert(runtime.autoload.phase == NLR_AUTOLOAD_NEW && !exists && !writes);
    reset(1); probe_failure = -44; probe_failure_once = 1;
    nlr_native_card_menu_checkpoint();
    assert(runtime.autoload.phase == NLR_AUTOLOAD_STOPPED && runtime.autoload.result == NLR_IO);
    assert(!starts && submissions == 1 && !probe_failure);
    nlr_native_card_menu_checkpoint(); assert(!starts && submissions == 1);
    /* The menu task waits its short bound for a ticket; busy past it is no
     * stop: the pass stays new, the next turn is asked for and asks again. */
    reset(1); loader_task = 0;
    assert(nlr_native_card_attach(&runtime) == NLR_OK);
    for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
        runtime.native_card->tickets[n].state = NLR_NATIVE_CARD_TICKET_DONE;
    sleeps = 0;
    assert(nlr_native_card_menu_checkpoint() == &flag_reference);
    assert(sleeps == 250 && !submissions && wakes == 1 && !starts);
    assert(runtime.autoload.phase == NLR_AUTOLOAD_NEW);
    for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++)
        runtime.native_card->tickets[n].state = NLR_NATIVE_CARD_TICKET_FREE;
    nlr_native_card_menu_checkpoint();
    assert(starts == 1 && submissions == 1);
    loader_task = 1;
    /* a program loaded ends the turn early; the menu task is not held */
    runtime.load.state = 2; runtime.autoload.boot_hold = 1; turns = 0;
    assert(nlr_native_card_menu_checkpoint() == &flag_reference && turns == 1);
    runtime.autoload.boot_hold = 0;
    runtime.load.state = 0;

    /* The escape is asked before the card: while the scan hook is not in,
     * the pass waits and nothing is submitted; held, the pass stops like
     * SAFE_MODE with nothing read or written. Every turn that reaches the
     * card may retry a boot record a busy journal refused. */
    reset(1); escape_answer = NLR_NOT_READY;
    nlr_native_card_menu_checkpoint();
    assert(!starts && !submissions && runtime.autoload.phase == NLR_AUTOLOAD_NEW && settles == 1);
    escape_answer = NLR_DISABLED;
    nlr_native_card_menu_checkpoint();
    assert(!starts && !submissions && !writes && settles == 2);
    assert(runtime.autoload.phase == NLR_AUTOLOAD_STOPPED);
    assert(runtime.autoload.result == NLR_DISABLED && runtime.autoload.enabled_result == NLR_DISABLED);
    nlr_native_card_menu_checkpoint();
    assert(!starts && !submissions);
    reset(1); escape_answer = NLR_OK;
    nlr_native_card_menu_checkpoint();
    assert(starts == 1 && submissions == 1);

    /* The boot record in the journal (format 2): the store's get and set,
     * each a complete native transaction; replace/remove stay absent. */
    {
        const struct nlr_card_store *store = nlr_native_card_store();
        assert(store->boot_mark_get && store->boot_mark_set);
        assert(!store->replace && !store->remove);
        struct nlr_boot_mark mark;
        reset(1);
        memset(&mark, 0x5a, sizeof mark);
        assert(store->boot_mark_get(&mark) == 0);
        assert(mark.mark == NLR_BOOT_MARK_NONE && !mark.result && !mark.id[0] && !writes);
        struct nlr_boot_mark run = {.mark = NLR_BOOT_MARK_RUN};
        strcpy(run.id, "APP");
        assert(store->boot_mark_set(&run) == 0 && writes == 1 && flushes == 1);
        /* written to the inactive slot, in format 2, and read back */
        const uint8_t *slot = journal + 4096;
        assert(nlr_le32(slot + 8) == NLR_CARD_STATE_FORMAT && nlr_le32(slot + 0x24) == NLR_BOOT_MARK_RUN);
        assert(!memcmp(slot + 0x880, "APP", 4) && nlr_native_card_u64(slot + 16) == 6);
        assert(!memcmp(slot, runtime.native_card->request.readback, 4096));
        assert(runtime.native_card->current.generation == 6 &&
               runtime.native_card->current.enabled_count == 1);
        assert(store->boot_mark_get(&mark) == 0);
        assert(mark.mark == NLR_BOOT_MARK_RUN && !strcmp(mark.id, "APP"));
        /* a page save keeps the record */
        struct nlr_enabled keep = {.count = 1};
        strcpy(keep.id[0], "EXT");
        assert(nlr_native_card_save_enabled(&runtime, &keep) == 0 && writes == 2);
        assert(runtime.native_card->current.boot_mark == NLR_BOOT_MARK_RUN);
        assert(!strcmp(runtime.native_card->current.boot_id, "APP"));
        /* the outcome of that same program (ID folded), then no second one */
        struct nlr_boot_mark ok = {.mark = NLR_BOOT_MARK_OK};
        strcpy(ok.id, "app");
        assert(store->boot_mark_set(&ok) == 0 && writes == 3);
        assert(runtime.native_card->current.boot_mark == NLR_BOOT_MARK_OK &&
               runtime.native_card->current.generation == 8);
        assert(store->boot_mark_set(&ok) == NLR_CARD_STATE_CONFLICT && writes == 3);
        assert(!runtime.native_card->uncertain);
        /* SAFE_MODE refuses before anything is written */
        safe = 1;
        assert(store->boot_mark_set(&run) == NLR_DISABLED && writes == 3);
        assert(store->boot_mark_get(&mark) == NLR_DISABLED);
        safe = 0;
        /* an unconfirmed write is uncertain, and so is everything after */
        reset(1); flush_failure = 1;
        assert(store->boot_mark_set(&run) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
        assert(runtime.native_card->uncertain);
        int calls = submissions;
        assert(store->boot_mark_get(&mark) == NLR_CARD_STATE_COMMIT_UNCERTAIN && submissions == calls);
        assert(store->boot_mark_set(&ok) == NLR_CARD_STATE_COMMIT_UNCERTAIN && submissions == calls);
        reset(1); write_failure = 1;
        assert(store->boot_mark_set(&run) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
        /* A format 1 journal, as an older core left it, reads with no boot
         * record and moves to format 2 with its next commit, whatever it is. */
        reset(1);
        journal[8] = 1;
        uint32_t crc = crc32_frame(journal);
        put(journal + 32, crc, 4);
        assert(nlr_native_card_snapshot(&runtime) == 0);
        assert(runtime.native_card->current.generation == 5 &&
               runtime.native_card->current.boot_mark == NLR_BOOT_MARK_NONE);
        assert(store->boot_mark_get(&mark) == 0 && mark.mark == NLR_BOOT_MARK_NONE);
        assert(nlr_native_card_pending(&runtime, 1) == 0 && writes == 1);
        assert(nlr_le32(journal + 4096 + 8) == NLR_CARD_STATE_FORMAT);
        assert(nlr_le32(journal + 8) == 1); /* the older slot is left as it was */
        assert(runtime.native_card->current.pending == 1);
        /* inside a pass (pending set) the record does not change */
        assert(store->boot_mark_set(&run) == NLR_CARD_STATE_CONFLICT && writes == 1);
        assert(nlr_native_card_pending(&runtime, 0) == 0);
        assert(store->boot_mark_set(&run) == 0 && writes == 3);
    }

    /* A program's write goes through the card owner's transaction: only the
     * state file's two modes with its mode word reach the low-level open,
     * the bytes are cleaned in the request's own buffer, a write larger
     * than one request is split, and a short answer ends it. */
    reset(1);
    int before = submissions;
    assert(nlr_native_card_file_open(NLR_CARD_ROOT "OUT.TXT", 0x101, 0) < 0);
    assert(nlr_native_card_file_open(NLR_CARD_ROOT "OUT.TXT", 0x301, 0x20) < 0);
    assert(nlr_native_card_file_open(NLR_CARD_ROOT "OUT.TXT", 0, 0x20) < 0);
    assert(submissions == before && !runtime.native_card->busy);
    int32_t out = nlr_native_card_file_open(NLR_CARD_ROOT "OUT.TXT", 0x301, 0);
    assert(out == 0 && program_open_flags == 0x301u);
    static uint8_t big[20000];
    for (uint32_t n = 0; n < sizeof big; n++) big[n] = (uint8_t)(n * 7u + 3u);
    uint32_t wrote = 77;
    before = submissions;
    assert(nlr_native_card_file_write(out, big, 0, &wrote) == 0 && !wrote && submissions == before);
    program_write_calls = 0;
    assert(nlr_native_card_file_write(out, big, sizeof big, &wrote) == 0 && wrote == sizeof big);
    assert(program_write_calls == 3 && program_bytes == sizeof big);
    assert(!memcmp(program_file, big, sizeof big));
    program_short = 100;
    assert(nlr_native_card_file_write(out, big, 300, &wrote) == 0 && wrote == 100);
    program_short = 0;
    assert(nlr_native_card_file_write(1 << 16, big, 4, &wrote) == NLR_REFUSED && !wrote);
    assert(nlr_native_card_file_close(out) == 0);
    out = nlr_native_card_file_open(NLR_CARD_ROOT "OUT.TXT", 1, 0);
    assert(out == 0 && program_open_flags == 1u);
    assert(nlr_native_card_file_close(out) == 0);
    assert(!runtime.native_card->uncertain && !writes);
    /* Decision 16: a read never starts inside a sector. The fake zeroes
     * the first whole sector after an unaligned start, as the Z 8's SD
     * reads did; the reads of build/z8-c-20261017/sd-diag (discard `skip`
     * by reading, then read `len` in one call) come back whole, the file
     * is left after the bytes delivered, the end of the file still answers
     * short, and a read after a seek starts where the seek put it. */
    reset(1);
    for (uint32_t n = 0; n < sizeof big_file; n++) big_file[n] = (uint8_t)(n * 13u + (n >> 9) + 1u);
    unaligned_fault = 1;
    static const uint32_t cases[][2] = {
        {0, 4096}, {64, 4096}, {192, 2048}, {512, 2048}, {64, 960}, {100, 1500},
        {4095, 9000}, {41000, 4096}, {42191, 1}, {42192, 16}, {64, 42192},
    };
    static uint8_t piece[sizeof big_file + 64];
    for (uint32_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        int32_t fd = nlr_native_card_file_open(NLR_CARD_ROOT "APPS\\BIG.NLB", 0, 0);
        assert(fd == 0);
        uint32_t skip = cases[c][0], len = cases[c][1], got = 0, part = 0;
        while (skip) {
            assert(nlr_native_card_file_read(fd, piece, skip, &part) == 0 && part);
            assert(!memcmp(piece, big_file + cases[c][0] - skip, part));
            skip -= part;
        }
        big_reads = 0;
        cache_order_n = 0;
        memset(piece, 0xa5, sizeof piece);
        assert(nlr_native_card_file_read(fd, piece, len, &got) == 0);
        /* every request: invalidate, read, then clean and invalidate */
        assert(big_reads && cache_order_n == 4u * (unsigned)big_reads);
        for (unsigned k = 0; k < cache_order_n; k += 4u)
            assert(!memcmp(cache_order + k, "IRCI", 4));
        uint32_t expect = cases[c][0] + len <= sizeof big_file ? len
            : cases[c][0] < sizeof big_file ? (uint32_t)sizeof big_file - cases[c][0] : 0;
        assert(got == expect);
        assert(!memcmp(piece, big_file + cases[c][0], got));
        assert(piece[got] == 0xa5);
        for (int k = 0; k < big_reads && k < 64; k++)
            assert(big_read_start[k] % NLR_NATIVE_CARD_READ_ALIGN == 0);
        /* the position is right after the bytes delivered */
        uint32_t at = 0;
        assert(nlr_native_card_file_seek(fd, NLR_NATIVE_CARD_SEEK_CUR, 0, &at) == 0);
        assert(at == cases[c][0] + got);
        assert(nlr_native_card_file_close(fd) == 0);
    }
    {
        /* seek then read, and a seek past the end reads nothing and stays */
        int32_t fd = nlr_native_card_file_open(NLR_CARD_ROOT "APPS\\BIG.NLB", 0, 0);
        uint32_t at = 0, got = 0;
        assert(nlr_native_card_file_seek(fd, NLR_SEEK_SET, 5000, &at) == 0 && at == 5000);
        assert(nlr_native_card_file_read(fd, piece, 3000, &got) == 0 && got == 3000);
        assert(!memcmp(piece, big_file + 5000, 3000));
        assert(nlr_native_card_file_seek(fd, NLR_SEEK_END, 0, &at) == 0 && at == sizeof big_file);
        assert(nlr_native_card_file_seek(fd, NLR_SEEK_SET, 50000, &at) == 0 && at == 50000);
        assert(nlr_native_card_file_read(fd, piece, 100, &got) == 0 && got == 0);
        assert(nlr_native_card_file_seek(fd, NLR_NATIVE_CARD_SEEK_CUR, 0, &at) == 0 && at == 50000);
        /* a position the native seek does not confirm is an I/O error */
        assert(nlr_native_card_file_seek(fd, NLR_SEEK_SET, 4097, &at) == 0);
        read_failure = 1;
        assert(nlr_native_card_file_read(fd, piece, 100, &got) == NLR_IO && got == 0);
        read_failure = 0;
        assert(nlr_native_card_file_close(fd) == 0);
    }
    unaligned_fault = 0;
    assert(!runtime.native_card->uncertain);
    for (unsigned n = 0; n < allocation_count; n++) free(allocations[n]);
    puts("native card ownership and failure tests passed");
    return 0;
}
