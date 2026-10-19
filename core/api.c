#include "nlr/api.h"

#include <stdarg.h>

#include "nlr/runtime.h"
#include "nlr/time.h"

/* The generated bindings object wears the real name in every build (the
 * page and the runtime read it the same way). */
extern const struct nlr_services nlr_services;

static int root_card_gone(void);
static void named_release(struct nlr_runtime *r);

/* Whether the caller is one of the service tasks task_start made (each
 * records its stack's range as it begins). Their calls are never counted
 * as the running application's (files, memory), and the application's
 * stop never unwinds them. Any other caller keeps the rule it always had. */
static int caller_is_service(const struct nlr_runtime *r)
{
    uint64_t here = (uint64_t)(uintptr_t)__builtin_frame_address(0);
    for (uint32_t n = 0; n < NLR_PLATFORM_TASKS; n++) {
        uint64_t hi = __atomic_load_n(&r->plat.task_stack[n].hi, __ATOMIC_ACQUIRE);
        if (hi && here < hi && here >= r->plat.task_stack[n].lo)
            return 1;
    }
    return 0;
}

static struct nlr_program_state *foreground_state(void)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 2 ||
        r->load.program_kind != NLR_KIND_FOREGROUND ||
        !__atomic_load_n(&r->load.program.jump_armed, __ATOMIC_ACQUIRE) ||
        caller_is_service(r))
        return 0;
    return &r->load.program;
}

/* The old ABI 1/2 prefix includes opaque graphics/input entries, but those
 * versions never established these layouts. Refuse before touching output. */
static int api4_foreground(void)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    return r && r->load.abi_version >= 4u && foreground_state();
}

static void foreground_stop(struct nlr_program_state *p)
{
    p->exit_requested = 1;
    p->exit_code = 0;
    nlr_program_longjmp(p->context, 1);
}

static struct nlr_program_state *service_begin(void)
{
    struct nlr_program_state *p = foreground_state();
    if (p) {
        if (__atomic_load_n(&p->stop_requested, __ATOMIC_ACQUIRE))
            foreground_stop(p);
        __atomic_add_fetch(&p->api_active, 1u, __ATOMIC_RELEASE);
    }
    return p;
}

static void service_end(struct nlr_program_state *p)
{
    if (p && __atomic_sub_fetch(&p->api_active, 1u, __ATOMIC_RELEASE) == 0 &&
        __atomic_load_n(&p->stop_requested, __ATOMIC_ACQUIRE))
        foreground_stop(p);
}

static uint32_t owned_file(const struct nlr_program_state *p, int fd)
{
    for (uint32_t i = 0; i < NLR_APP_FILE_MAX; i++)
        if ((p->api_file_used & (1u << i)) && p->api_file[i] == fd)
            return i;
    return NLR_APP_FILE_MAX;
}

int nlr_api_program_cleanup(struct nlr_program_state *p)
{
    if (!p || __atomic_load_n(&p->api_active, __ATOMIC_ACQUIRE))
        return NLR_EXEC_RESTORE;
    /* Buttons and screen go back to the camera first: nothing below can
     * fail in a way that should keep them. */
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    nlr_program_io_release(r);
    if (r && r->io.gfx_request) {
        if (nlr_services.release(r->io.gfx_request) != NLR_OK)
            return NLR_EXEC_RESTORE;
        r->io.gfx_request = 0;
        r->io.gfx_pixels = r->io.gfx_alpha = 0;
    }
#if NLR_HAS_GRAPHICS
    if (!r || &r->load.program != p || nlr_graphics_runtime_cleanup(r) != NLR_OK)
        return NLR_EXEC_RESTORE;
#endif

    /* Then the firmware's own code. This program's block is about to go
     * back to the allocator, so a detour still pointing into it would send
     * the next firmware call through that function into free memory, and
     * only the power switch would bring the camera back. Whatever the
     * program forgot — or never reached, after an error or a stop — is
     * removed here; a removal that fails keeps the block instead, because
     * NLR_EXEC_RESTORE both retains it and refuses every later run. A
     * resident extension never comes through here: its blocks are kept,
     * and its hooks stay with them. */
    if (r && nlr_code_unhook_region(r, p->code_page, p->region_bytes) != NLR_OK)
        return NLR_EXEC_RESTORE;
    for (uint32_t i = 0; i < NLR_APP_FILE_MAX; i++)
        if (p->api_file_used & (1u << i)) {
            if (nlr_services.file_close(p->api_file[i]) != NLR_OK)
                return NLR_EXEC_RESTORE;
            p->api_file_used &= ~(1u << i);
        }
    for (uint32_t i = 0; i < NLR_APP_ALLOC_MAX; i++)
        if (p->api_allocation[i]) {
            if (nlr_services.release(p->api_allocation[i]) != NLR_OK)
                return NLR_EXEC_RESTORE;
            p->api_allocation[i] = 0;
        }
    return NLR_OK;
}

/* ---- memory -------------------------------------------------------------- */

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
extern const struct nlr_exec_services nlr_exec_services;
#endif

static void *api_mem_alloc(uint32_t size, uint32_t attrs)
{
    if (attrs != 0)
        return 0;
    struct nlr_program_state *p = service_begin();
    uint32_t slot = 0;
    if (p) {
        while (slot < NLR_APP_ALLOC_MAX && p->api_allocation[slot])
            slot++;
        if (slot == NLR_APP_ALLOC_MAX) {
            service_end(p);
            return 0;
        }
    }
    /* The model's heap may answer with less than it was asked for and
     * still map the whole span: where the loader can read its books, a
     * program's block is granted whole, as its code and data blocks are. */
    void *block = nlr_alloc_whole(&nlr_services, size);
    if (p)
        p->api_allocation[slot] = block;
    service_end(p);
    return block;
}

static void api_mem_free(void *block)
{
    if (!block)
        return;
    struct nlr_program_state *p = service_begin();
    uint32_t slot = 0;
    if (p) {
        while (slot < NLR_APP_ALLOC_MAX && p->api_allocation[slot] != block)
            slot++;
        if (slot == NLR_APP_ALLOC_MAX) {
            service_end(p);
            return;
        }
    }
    if (nlr_services.release(block) == NLR_OK && p)
        p->api_allocation[slot] = 0;
    service_end(p);
}

/* ---- files (confined to the configured card root) ----------------------- */

/* Resolve the program's path against the configured root. An absolute path
 * with exactly the root prefix is accepted as-is, everything else is
 * prefixed; separators normalize to the firmware's; traversal, other drive
 * letters and over-long paths are refused. Returns 0 and fills `out`
 * (NLR_PATH_BYTES bytes) or a negative NLR_API_E* value. */
static int api_path_full(const char *path, char *out)
{
    const uint32_t root_len = sizeof NLR_PROGRAM_ROOT - 1u;
    if (!path || !path[0])
        return -NLR_API_EINVAL;
    const char *relative = path;
    uint32_t n = 0;
    while (n < root_len && NLR_PROGRAM_ROOT[n] == path[n])
        n++;
    if (n == root_len)
        relative = path + root_len;
    if (!relative[0] || relative[0] == '/' || relative[0] == '\\')
        return -NLR_API_EINVAL;
    uint32_t length = 0;
    for (const char *p = relative; *p; p++) {
        if (*p == ':')
            return -NLR_API_EINVAL;
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == 0 || p[2] == '/' || p[2] == '\\'))
            return -NLR_API_EINVAL;
        length++;
    }
    if (length > NLR_API_PATH_MAX)
        return -NLR_API_EINVAL;
    for (uint32_t i = 0; i < root_len; i++)
        out[i] = NLR_PROGRAM_ROOT[i];
    for (uint32_t i = 0; i < length; i++)
        out[root_len + i] = relative[i] == '/' ? '\\' : relative[i];
    out[root_len + length] = 0;
    return 0;
}

/* The card's pictures (ABI 9), for a program to show: a path that starts
 * with "/DCIM" or "\\DCIM" names the DCIM folder on the loader's own card,
 * read-only -- fs_open for reading, fs_dir, fs_dir_names; a write there is
 * refused with -NLR_API_EACCES. The rest of the path follows the rules
 * above (no traversal, no drive letter, at most NLR_API_PATH_MAX bytes);
 * every other path that starts with a separator stays refused. Fills `out`
 * (NLR_PATH_BYTES bytes) and returns 1 for a path inside DCIM, 2 for DCIM
 * itself; 0 for a path that is not one (api_path_full decides it), or
 * -NLR_API_EINVAL. */
#define NLR_MEDIA_DIR "DCIM"
static int api_path_media(const char *path, char *out)
{
    static const char dir[] = NLR_MEDIA_DIR;
    const uint32_t dir_len = sizeof dir - 1u;
    if (!path || (path[0] != '/' && path[0] != '\\'))
        return 0;
    for (uint32_t n = 0; n < dir_len; n++)
        if (path[1 + n] != dir[n] && path[1 + n] != dir[n] + ('a' - 'A'))
            return -NLR_API_EINVAL;
    const char *rest = path + 1 + dir_len;
    if (rest[0] && rest[0] != '/' && rest[0] != '\\')
        return -NLR_API_EINVAL;
    if (rest[0])
        rest++;
    /* the drive of the loader's own card: the root up to its first
     * separator ("A:\\") */
    uint32_t drive = 0;
    while (NLR_PROGRAM_ROOT[drive] && NLR_PROGRAM_ROOT[drive] != '\\')
        drive++;
    if (!NLR_PROGRAM_ROOT[drive])
        return -NLR_API_EINVAL;
    drive++;
    uint32_t length = 0;
    for (const char *p = rest; *p; p++) {
        if (*p == ':')
            return -NLR_API_EINVAL;
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == 0 || p[2] == '/' || p[2] == '\\'))
            return -NLR_API_EINVAL;
        length++;
    }
    if (length > NLR_API_PATH_MAX ||
        drive + dir_len + 1u + length + 1u > NLR_PATH_BYTES)
        return -NLR_API_EINVAL;
    uint32_t o = 0;
    for (uint32_t n = 0; n < drive; n++)
        out[o++] = NLR_PROGRAM_ROOT[n];
    for (uint32_t n = 0; n < dir_len; n++)
        out[o++] = dir[n];
    if (length)
        out[o++] = '\\';
    for (uint32_t n = 0; n < length; n++)
        out[o++] = rest[n] == '/' ? '\\' : rest[n];
    out[o] = 0;
    return length ? 1 : 2;
}

/* The loader's own files, which a program may read but never write. They
 * are the camera's safety net: MANIFEST and ENABLED decide what runs by
 * itself next boot, SAFE_MODE is the escape that stops it, and the
 * interruption marker is how a pass that crashed the camera is recognized
 * — a program writing its cleared byte would hide exactly the crash the
 * marker exists to catch. On dev firmware the loader itself and its start
 * record are on the card too, and are stage 0's to write. The card's filesystem ignores case, so this
 * comparison does too; a program cannot slip past it with "manifest". */
static char api_lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c + ('a' - 'A')) : c;
}

/* A path written to must name its file one way only. The exact comparison
 * below would miss "NLOADER\\.\\MANIFEST", an empty component or a name
 * with a trailing dot or space, which a FAT-family filesystem may resolve
 * to the same file; such a spelling is refused for writing. */
static int api_path_plain(const char *full)
{
    const char *component = full + (sizeof NLR_PROGRAM_ROOT - 1u);
    for (const char *p = component;; p++) {
        if (*p && *p != '\\')
            continue;
        uint32_t bytes = (uint32_t)(p - component);
        if (!bytes || (bytes == 1 && component[0] == '.') ||
            p[-1] == '.' || p[-1] == ' ')
            return 0;
        if (!*p)
            return 1;
        component = p + 1;
    }
}

static int api_path_is_loader_own(const char *full)
{
    static const char *const own[] = {
        NLR_MANIFEST_PATH,
        NLR_ENABLED_PATH,
        NLR_SAFE_MODE_PATH,
        NLR_AUTOLOAD_PENDING_PATH,
        /* Where a native-card model keeps the enabled list and the
         * interruption state together. */
        NLR_CARD_ROOT "STATE.NLS",
        /* dev firmware: the core stage 0 loads and its start record */
        NLR_CARD_ROOT "CORE.NLC",
        NLR_CARD_ROOT "CORERUN",
        NLR_MASTER_PATH,
        /* The program the boot starts, and the record that recognizes a
         * boot program that crashed the camera: the same reasons as
         * ENABLED and the marker above. */
        NLR_BOOT_PATH,
        NLR_CARD_ROOT "BOOTRUN",
        /* The loader's own log (core/journal.c): a program writing it
         * could forge the loader's lines -- a stop, a result, a boot
         * record -- that a person reads to learn what happened. */
        NLR_CARD_ROOT "LOADER.LOG",
    };
    for (uint32_t n = 0; n < sizeof own / sizeof *own; n++) {
        uint32_t i = 0;
        while (full[i] && api_lower(full[i]) == api_lower(own[n][i]))
            i++;
        if (!full[i] && !own[n][i])
            return 1;
    }
    return 0;
}

/* The firmware's open flags for a write access, or 0 when this model has no
 * checked way to do it. Reading does not come here: it goes through the
 * plain read the loader itself uses, whose flags the model adapter owns. */
static uint32_t api_open_flags(uint32_t mode)
{
    if (mode == NLR_OPEN_WRITE)
        return nlr_services.file_open_write;
    if (mode == NLR_OPEN_UPDATE)
        return nlr_services.file_open_rw;
    return 0;
}

static int api_fs_open(const char *path, uint32_t mode)
{
    if (root_card_gone())
        return -NLR_API_ENODEV;
    if (mode != NLR_OPEN_READ && mode != NLR_OPEN_WRITE &&
        mode != NLR_OPEN_UPDATE)
        return -NLR_API_EINVAL;
    /* Writing needs both the write service and the model's own flags; a
     * model without them refuses the access instead of opening for reading
     * and silently dropping what the program writes. */
    if (mode != NLR_OPEN_READ &&
        (!nlr_services.file_write || !nlr_services.cache_clean ||
         !api_open_flags(mode)))
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    uint32_t slot = 0;
    if (p) {
        while (slot < NLR_APP_FILE_MAX && (p->api_file_used & (1u << slot)))
            slot++;
        if (slot == NLR_APP_FILE_MAX) {
            service_end(p);
            return -NLR_API_EBUSY;
        }
    }
    char full[NLR_PATH_BYTES];
    int media = api_path_media(path, full);
    if (media < 0 || media == 2 || (!media && api_path_full(path, full) != 0)) {
        service_end(p);
        return -NLR_API_EINVAL;
    }
    if (mode != NLR_OPEN_READ && media) {
        /* the card's DCIM is for reading only (ABI 9) */
        service_end(p);
        return -NLR_API_EACCES;
    }
    if (mode != NLR_OPEN_READ && !api_path_plain(full)) {
        service_end(p);
        return -NLR_API_EINVAL;
    }
    if (mode != NLR_OPEN_READ && api_path_is_loader_own(full)) {
        service_end(p);
        return -NLR_API_EACCES;
    }
    int32_t fd = mode == NLR_OPEN_READ
                     ? nlr_services.file_open(full, 0, 0)
                     : nlr_services.file_open(full, api_open_flags(mode),
                                              nlr_services.file_create_attributes);
    if (p && fd >= 0) {
        p->api_file[slot] = fd;
        p->api_file_used |= 1u << slot;
    }
    service_end(p);
    return fd < 0 ? -NLR_API_EIO : fd;
}

static int api_fs_read(int fd, void *buf, uint32_t len)
{
    if (fd < 0)
        return -NLR_API_EBADF;
    struct nlr_program_state *p = service_begin();
    int result;
    if (p && owned_file(p, fd) == NLR_APP_FILE_MAX)
        result = -NLR_API_EBADF;
    else if (len == 0)
        result = 0;
    else if (!buf)
        result = -NLR_API_EINVAL;
    else {
        uint32_t done = 0;
        result = nlr_services.file_read(fd, buf, len, &done) != NLR_OK ||
                 done == 0 || done > len ? -NLR_API_EIO : (int)done;
    }
    service_end(p);
    return result;
}

static int api_fs_seek(int fd, int64_t off, int whence)
{
    if (fd < 0)
        return -NLR_API_EBADF;
    if (off < 0 || (uint64_t)off > UINT32_MAX ||
        (whence != NLR_SEEK_SET && whence != NLR_SEEK_END))
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    int result;
    uint32_t position = 0;
    if (p && owned_file(p, fd) == NLR_APP_FILE_MAX)
        result = -NLR_API_EBADF;
    else if (nlr_services.file_seek(fd, whence, (uint32_t)off, &position) != NLR_OK)
        result = -NLR_API_EIO;
    else
        result = position > INT32_MAX ? -NLR_API_EOVERFLOW : (int)position;
    service_end(p);
    return result;
}

static int api_fs_write(int fd, const void *buf, uint32_t len)
{
    if (fd < 0)
        return -NLR_API_EBADF;
    /* No declared clean, no write: see below — the bytes could never be
     * guaranteed to reach the card. */
    if (!nlr_services.file_write || !nlr_services.cache_clean)
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    int result;
    if (p && owned_file(p, fd) == NLR_APP_FILE_MAX)
        result = -NLR_API_EBADF;
    else if (len == 0)
        result = 0;
    else if (!buf)
        result = -NLR_API_EINVAL;
    else {
        uint32_t done = 0;
        /* A small write is staged through the filesystem's own sector
         * buffer, but a whole-sector one can be fetched from here by DMA:
         * what the program wrote has to be out of the data cache first.
         * Cleaning covers whole lines, which only writes back whatever
         * else shares them. The model names the entry that writes back;
         * the one a read ends with is not asked for this, because on
         * another body it may discard the lines and the write would be
         * lost without a word. */
        nlr_services.cache_clean((void *)buf, len);
        result = nlr_services.file_write(fd, buf, len, &done) != NLR_OK ||
                 done == 0 || done > len ? -NLR_API_EIO : (int)done;
    }
    service_end(p);
    return result;
}

static int api_fs_close(int fd)
{
    if (fd < 0)
        return -1;
    struct nlr_program_state *p = service_begin();
    uint32_t slot = p ? owned_file(p, fd) : 0;
    int result = p && slot == NLR_APP_FILE_MAX ? -1
        : (nlr_services.file_close(fd) == NLR_OK ? 0 : -1);
    if (p && result == 0)
        p->api_file_used &= ~(1u << slot);
    service_end(p);
    return result;
}

/* ---- text, pixels and input ---------------------------------------------- */

static int api_ui_draw_text(int x, int y, const char *s)
{
    /* The text channel is the result row: there is no placement to honor
     * while the pixel channel is unimplemented, so x and y are ignored. */
    (void)x;
    (void)y;
    if (!s)
        return -NLR_API_EINVAL;
    /* Same registry scan as log and exit: the caller runs in the worker
     * task, and no ambient writable state exists to remember otherwise. */
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return -NLR_API_EIO; /* the channel has nowhere to publish into */
    /* The slot belongs to the run in progress: it starts empty with each
     * start (start_program) and its one writer is that run's task. With
     * nothing running, or from a resident's service task, a text has no
     * run to belong to -- published, it would show under the next
     * program's row -- so it is refused. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0 ||
        caller_is_service(r))
        return -NLR_API_EBUSY;
    struct nlr_program_state *p = service_begin();
    nlr_text_publish(&r->text, s);
    service_end(p);
    return 0;
}

/* ---- program I/O (ABI 4): buttons ---------------------------------------- */

static uint32_t api_time_ms(void);
static void screen_activity(struct nlr_runtime *r);

static const struct nlr_program_services *program_services(void)
{
    return nlr_services.program;
}

static uint32_t *input_bank(const struct nlr_program_services *ps,
                            void *object, uint32_t bank)
{
    return (uint32_t *)((uint8_t *)object + ps->bank_base +
                        bank * ps->bank_stride);
}

/* Hide `mask` of `bank` from the camera: every one of the bank's words. */
static void input_hide(const struct nlr_program_services *ps, void *object,
                       uint32_t bank, uint32_t mask)
{
    uint32_t *w = input_bank(ps, object, bank);
    for (uint32_t i = 0; i < 5; i++)
        w[i] &= ~mask;
}

/* While a program is loaded, each change of a control in the log, and
 * where it went: hidden from the camera, the camera's, or both. A dial's
 * turn is noted at most once a second. Runs on the input task: a line
 * into the RAM ring, nothing else. */
static void journal_controls(struct nlr_runtime *r,
                             const struct nlr_platform_services *pl,
                             uint64_t controls, const uint32_t *banks,
                             uint32_t bank_count, const int32_t *dials,
                             uint32_t dial_words, uint32_t keep_bank,
                             uint32_t keep_mask, int taken)
{
    /* characters, not pointers: no relocation in read-only data */
    static const char NAMES[][13] = {
        "up", "down", "left", "right", "ok", "menu", "play", "delete", "info",
        "disp", "zoom-in", "zoom-out", "af-on", "half", "full", "sub-up",
        "sub-down", "sub-left", "sub-right", "sub-press", "fn1", "fn2", "fn-v",
        "movie", "iso", "exp-comp", "release-mode", "illuminate", "af-on-v",
        "remote-fn",
    };
    struct nlr_platform *plat = &r->plat;
    uint64_t was = plat->journal_held;
    int routed = __atomic_load_n(&plat->active, __ATOMIC_ACQUIRE) && pl;
    uint64_t hide = __atomic_load_n(&plat->route_hide, __ATOMIC_ACQUIRE);
    uint64_t report = __atomic_load_n(&plat->route_report, __ATOMIC_ACQUIRE);
    if (controls != was) {
        plat->journal_held = controls;
        for (uint32_t c = 0; c < 64u; c++) {
            uint64_t bit = UINT64_C(1) << c;
            if (!((controls ^ was) & bit))
                continue;
            const char *to = !taken ? "camera, not taken"
                           : !routed ? "hidden"
                           : (hide & bit) ? ((report & bit) ? "program" : "nobody")
                           : (report & bit) ? "camera+program" : "camera";
            if (c < sizeof NAMES / sizeof NAMES[0])
                nlr_journal(r->load.journal, "%s %s -> %s", NAMES[c],
                            (controls & bit) ? "down" : "up", to);
            else
                nlr_journal(r->load.journal, "ctl %u %s -> %s", c,
                            (controls & bit) ? "down" : "up", to);
        }
    }
    /* bits no control names (nor the power switch): hidden whenever the
     * input is taken; the first 64 changes of a boot, so a status bit that
     * keeps changing cannot fill the log */
    for (uint32_t b = 0; b < bank_count && b < 4u; b++) {
        uint32_t named = b == keep_bank ? keep_mask : 0u;
        for (uint32_t n = 0; pl && pl->controls && n < pl->control_count; n++)
            if (pl->controls[n].bank == b)
                named |= pl->controls[n].mask;
        uint32_t moved = (banks[b] ^ plat->journal_banks[b]) & ~named;
        if (moved && plat->journal_raw_lines < 64u) {
            plat->journal_raw_lines++;
            nlr_journal(r->load.journal, "bank %u bits %x now %x, no control -> %s", b,
                        moved, banks[b] & moved, taken ? "hidden" : "camera, not taken");
        }
        plat->journal_banks[b] = banks[b];
    }
    uint32_t now = nlr_clock_ms();
    for (uint32_t w = 0; w < dial_words; w++)
        if (dials[w] && now - plat->journal_dial_at >= 1000u) {
            plat->journal_dial_at = now;
            nlr_journal(r->load.journal, "dial word %u turns %d%s", w, dials[w],
                        taken ? "" : ", not taken");
        }
}

void nlr_program_journal_scan(struct nlr_runtime *r,
                              const struct nlr_scan_view *view,
                              const void *object, int taken)
{
    if (!r || !r->load.journal || !view || !object || !view->bank_stride ||
        !view->banks || view->banks > 4u ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0)
        return;
    const struct nlr_platform_services *pl = r->load.svc ? r->load.svc->platform : 0;
    const uint8_t *base = (const uint8_t *)object + view->bank_base;
    uint32_t current[4] = {0, 0, 0, 0};
    for (uint32_t b = 0; b < view->banks; b++)
        current[b] = nlr_le32(base + b * view->bank_stride);
    int32_t dials[8] = {0};
    uint32_t dial_words = view->dial_bytes / 4u;
    if (dial_words > 8u)
        dial_words = 8u;
    for (uint32_t w = 0; w < dial_words; w++)
        dials[w] = (int32_t)nlr_le32((const uint8_t *)object + view->dial_offset + 4u * w);
    journal_controls(r, pl, nlr_platform_held(pl, current, view->banks), current,
                     view->banks, dials, dial_words, view->keep_bank, view->keep_mask,
                     taken);
}

/* The input task's per-scan hook: it runs on that task once per scan with
 * the scan object, before the stock occupant of the slot sees it. It keeps
 * the program's view of the buttons, and while a foreground program owns
 * them it blanks everything but the power switch, so the menu underneath
 * never reacts. MENU and DELETE together ask the program to stop; the stop
 * takes effect at its next API call. Bits held when a program ends stay
 * hidden until released, so a held MENU does not open the menu. */
void nlr_program_input(void *object)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    /* The scan object is copied onto this task's stack while the program
     * owns the buttons, so the bound is this buffer's, not a model's: the
     * Z 6III's object has four banks (SW0..SW3), one more than the Z8's.
     * A model that declares more than fits is left alone entirely. */
    uint32_t saved[4][5];
    uint8_t saved_dial[32];
    int restore = ps && object && ps->banks <= 4u && ps->dial_bytes <= sizeof saved_dial;
    if (restore) {
        for (uint32_t b = 0; b < ps->banks; b++)
            for (uint32_t n = 0; n < 5; n++) saved[b][n] = input_bank(ps, object, b)[n];
        for (uint32_t n = 0; n < ps->dial_bytes; n++)
            saved_dial[n] = ((uint8_t *)object)[ps->dial_offset + n];
    }
    if (ps && r && object && restore) {
        struct nlr_program_io *io = &r->io;
        /* the log reads the physical scan, before anything is hidden */
        struct nlr_scan_view view;
        int have_view = nlr_platform_scan_view(r->load.svc, &view);
        if (have_view)
            nlr_program_journal_scan(r, &view, object,
                                     __atomic_load_n(&io->captured, __ATOMIC_ACQUIRE) &&
                                     !__atomic_load_n(&io->list_active, __ATOMIC_ACQUIRE));
        uint32_t keys = 0;
        for (uint32_t i = 0; i < NLR_PROGRAM_KEYS; i++)
            if (ps->keys[i].mask && ps->keys[i].bank < ps->banks &&
                (input_bank(ps, object, ps->keys[i].bank)[0] &
                 ps->keys[i].mask))
                keys |= 1u << i;
        uint32_t changed = keys ^ io->keys;
        /* Every key reaches the program as an event, MENU and DELETE too:
         * together they are the loader's stop, watched below, but a program
         * that owns the screen answers MENU on its own. */
        for (uint32_t i = 0; changed &&
             !__atomic_load_n(&io->list_active, __ATOMIC_ACQUIRE) && i < NLR_PROGRAM_KEYS; i++) {
            if (!(changed & (1u << i)))
                continue;
            uint32_t tail = io->event_tail;
            if (tail - __atomic_load_n(&io->event_head, __ATOMIC_ACQUIRE) <
                NLR_KEY_EVENTS) {
                io->events[tail % NLR_KEY_EVENTS].key = 1u << i;
                io->events[tail % NLR_KEY_EVENTS].down = !!(keys & (1u << i));
                __atomic_store_n(&io->event_tail, tail + 1, __ATOMIC_RELEASE);
            } else __atomic_store_n(&io->event_overflow, 1u, __ATOMIC_RELEASE);
        }
        __atomic_store_n(&io->keys, keys, __ATOMIC_RELEASE);
        int captured = __atomic_load_n(&io->captured, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&io->list_active, __ATOMIC_ACQUIRE);
        if (captured) {
            const uint32_t chord = NLR_KEY_MENU | NLR_KEY_DELETE;
            if ((keys & chord) == chord &&
                __atomic_load_n(&r->load.program.jump_armed, __ATOMIC_ACQUIRE) &&
                !__atomic_exchange_n(&r->load.program.stop_requested, 1u,
                                     __ATOMIC_ACQ_REL))
                nlr_journal(r->load.journal, "MENU+DELETE: the program is asked to stop");
            io->hold = keys;
        } else if (io->hold) {
            io->hold &= keys;
            for (uint32_t i = 0; i < NLR_PROGRAM_KEYS; i++)
                if (io->hold & (1u << i))
                    input_hide(ps, object, ps->keys[i].bank, ps->keys[i].mask);
        }
        /* The platform pass: every control and dial for ABI 7, the hide
         * masks the camera must not see, the activity signal, and the bits
         * a finished program still holds. It runs after this hook's own key
         * reads so the ABI 4 view is the physical one, and before the stock
         * occupant so what it sees is already hidden. */
        if (have_view)
            (void)nlr_platform_input_pass(&r->plat, nlr_services.platform,
                                          &view, object, captured, nlr_clock_ms());
    }
    if (ps && ps->input_original) ps->input_original(object);
    if (restore) {
        for (uint32_t b = 0; b < ps->banks; b++)
            for (uint32_t n = 0; n < 5; n++) input_bank(ps, object, b)[n] = saved[b][n];
        for (uint32_t n = 0; n < ps->dial_bytes; n++)
            ((uint8_t *)object)[ps->dial_offset + n] = saved_dial[n];
    }
}

/* The buttons held at this moment, read from the scan object the input task
 * keeps, without waiting for our hook to see a scan. The autoload escape is
 * the only caller: it has to answer before anything is loaded, which can be
 * the first thing that happens on the menu task. Zero when the model does
 * not name the object. */
uint32_t nlr_program_keys_now(void)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_scan_view view;
    void *object = ps ? ps->input_object : 0;
    uint32_t bank_base = 0, bank_stride = 0, banks = 0;
    if (ps && ps->input_object) {
        bank_base = ps->bank_base;
        bank_stride = ps->bank_stride;
        banks = ps->banks;
    } else if (nlr_platform_scan_view(&nlr_services, &view) && view.object) {
        object = view.object;
        bank_base = view.bank_base;
        bank_stride = view.bank_stride;
        banks = view.banks;
    }
    if (!ps || !object || !bank_stride)
        return 0;
    uint32_t keys = 0;
    for (uint32_t i = 0; i < NLR_PROGRAM_KEYS; i++)
        if (ps->keys[i].mask && ps->keys[i].bank < banks &&
            (nlr_le32((const uint8_t *)object + bank_base +
                      ps->keys[i].bank * bank_stride) &
             ps->keys[i].mask))
            keys |= 1u << i;
    return keys;
}

/* The touch driver's report (ABI 7, nlr/platform.h): every report, on the
 * driver's task. A program that hears about touch gets it as events; one
 * that took it from the camera keeps it from the camera's gesture service,
 * which first gets the release of a finger it saw go down, so it is never
 * left with a finger stuck on the screen. */
static void program_touch(uint32_t code, void *record)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    if (!pl || !pl->touch_original)
        return;
    struct nlr_runtime *r = record ? nlr_runtime_find(&nlr_services, 0) : 0;
    if (r && nlr_platform_touch(&r->plat, pl, record, nlr_clock_ms())) {
        if (__atomic_exchange_n(&r->plat.camera_touch, 0u, __ATOMIC_ACQ_REL)) {
            uint8_t up[64];
            uint32_t bytes = pl->touch_record_bytes < sizeof up
                                 ? pl->touch_record_bytes : (uint32_t)sizeof up;
            for (uint32_t n = 0; n < bytes; n++)
                up[n] = ((const uint8_t *)record)[n];
            up[5] = 0;
            pl->touch_original(code, up);
        }
        return;
    }
    if (r)
        __atomic_store_n(&r->plat.camera_touch,
                         ((const uint8_t *)record)[5] != 0 ? 1u : 0u, __ATOMIC_RELEASE);
    pl->touch_original(code, record);
}

/* The touch slot holds the hook from the first pass on, as the input slot
 * does; only over the stock occupant the profile names. */
static void program_touch_install(struct nlr_runtime *r)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    if (!r || !pl || !pl->touch_slot || !pl->touch_original ||
        __atomic_load_n(&r->plat.touch_installed, __ATOMIC_ACQUIRE))
        return;
    void (*current)(uint32_t, void *) =
        __atomic_load_n(pl->touch_slot, __ATOMIC_ACQUIRE);
    if (current != program_touch) {
        if (current != pl->touch_original)
            return;
        __atomic_store_n(pl->touch_slot, program_touch, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&r->plat.touch_installed, 1u, __ATOMIC_RELEASE);
}

/* Put the hook in the input task's slot, once, and only over the stock
 * occupant the profile names: anything else in the slot is left alone. */
void nlr_program_io_install(struct nlr_runtime *r)
{
    program_touch_install(r);
    const struct nlr_program_services *ps = program_services();
    if (!r || nlr_services.input || !ps || !ps->input_slot || !ps->input_original || r->io.hooked)
        return;
    void (*current)(void *) =
        __atomic_load_n(ps->input_slot, __ATOMIC_ACQUIRE);
    if (current == nlr_program_input) {
        r->io.hooked = 1;
        return;
    }
    if (current != ps->input_original)
        return;
    __atomic_store_n(ps->input_slot, nlr_program_input, __ATOMIC_RELEASE);
    r->io.hooked = 1;
}

int nlr_program_io_wanted(void)
{
    const struct nlr_program_services *ps = program_services();
    return !nlr_services.input && ps && ps->input_slot && ps->input_original;
}

/* The program is done with the buttons and the screen: whatever it still
 * holds stays hidden until released (see nlr_program_input). */
void nlr_program_io_release(struct nlr_runtime *r)
{
    if (!r)
        return;
    __atomic_store_n(&r->io.gfx_active, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->io.captured, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->io.list_active, 0u, __ATOMIC_RELEASE);
    /* ABI 7: routes, timers and watches end with the program. A screen it
     * still had goes back with a full redraw owed by the stock GUI. */
    struct nlr_platform *plat = &r->plat;
    nlr_journal(r->load.journal, "input released: claimed %u shell %u, %u bad presents",
                (unsigned)__atomic_load_n(&plat->claimed, __ATOMIC_ACQUIRE),
                (unsigned)__atomic_load_n(&plat->shell, __ATOMIC_ACQUIRE),
                plat->journal_present_fail);
    plat->journal_present_fail = 0;
    __atomic_store_n(&plat->active, 0u, __ATOMIC_RELEASE);
    for (uint32_t t = 0; t < NLR_TIMERS_MAX; t++)
        plat->timers[t].used = 0;
    plat->watch_count = 0;
    if (__atomic_exchange_n(&plat->claimed, 0u, __ATOMIC_ACQ_REL))
        __atomic_store_n(&plat->redraw, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&plat->lent, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&plat->shell, 0u, __ATOMIC_RELEASE);
    /* what was posted for this program and not read is not the next one's */
    __atomic_store_n(&plat->phead, __atomic_load_n(&plat->ptail, __ATOMIC_ACQUIRE),
                     __ATOMIC_RELEASE);
    /* released with the program's other allocations (cleanup) */
    plat->reserved = 0;
    plat->reserved_bytes = 0;
    named_release(r);
}

static struct nlr_program_io *program_io_for_input(void)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!ps || !r || !r->io.hooked || !foreground_state())
        return 0;
    if (!__atomic_load_n(&r->io.captured, __ATOMIC_ACQUIRE)) {
        /* Taking the buttons starts a fresh event stream. */
        __atomic_store_n(&r->io.event_head,
                         __atomic_load_n(&r->io.event_tail, __ATOMIC_ACQUIRE),
                         __ATOMIC_RELEASE);
        __atomic_store_n(&r->io.event_overflow, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&r->io.captured, 1u, __ATOMIC_RELEASE);
        nlr_journal(r->load.journal, "buttons taken from the camera");
    }
    return &r->io;
}

static int api_input_poll(struct nlr_key_event *ev)
{
    if (!api4_foreground()) return -NLR_API_ENOSYS;
    if (nlr_services.input) {
        struct nlr_program_state *p = service_begin();
        int result = nlr_runtime_input_poll(nlr_runtime_find(&nlr_services, 0), ev);
        service_end(p);
        return result;
    }
    /* A missing channel answers -ENOSYS whatever the argument. */
    const struct nlr_program_services *ps = program_services();
    if (!ps || !ps->input_slot)
        return -NLR_API_ENOSYS;
    if (!ev)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    struct nlr_program_io *io = program_io_for_input();
    int result = -NLR_API_ENOSYS;
    if (io) {
        if (__atomic_exchange_n(&io->event_overflow, 0u, __ATOMIC_ACQ_REL)) {
            __atomic_store_n(&io->event_head,
                __atomic_load_n(&io->event_tail, __ATOMIC_ACQUIRE), __ATOMIC_RELEASE);
            service_end(p);
            return -NLR_API_EOVERFLOW;
        }
        uint32_t head = io->event_head;
        result = 0;
        if (head != __atomic_load_n(&io->event_tail, __ATOMIC_ACQUIRE)) {
            *ev = io->events[head % NLR_KEY_EVENTS];
            __atomic_store_n(&io->event_head, head + 1, __ATOMIC_RELEASE);
            result = 1;
        }
    }
    service_end(p);
    return result;
}

static uint32_t api_input_raw(void)
{
    if (!api4_foreground()) return 0;
    if (nlr_services.input) {
        struct nlr_program_state *p = service_begin();
        uint32_t result = nlr_runtime_input_raw(nlr_runtime_find(&nlr_services, 0));
        service_end(p);
        return result;
    }
    /* The mask cannot carry an error: without the input channel it reports
     * no keys held, never a fabricated pattern. */
    struct nlr_program_state *p = service_begin();
    struct nlr_program_io *io = program_io_for_input();
    /* MENU and DELETE reach the program too: together they are still the
     * loader's stop (the chord is watched where the keys are read), but a
     * program that owns the screen needs MENU on its own. */
    uint32_t keys = io ? __atomic_load_n(&io->keys, __ATOMIC_ACQUIRE) : 0;
    service_end(p);
    return keys;
}

/* ---- program I/O (ABI 4): the screen -------------------------------------- */

/* Cleaning the planes to the display. Program services are bound in the
 * execution stage only, so no other stage ever hands out a surface. These
 * three serve the platform screen (family C) in every build, and the
 * ABI 4 surface where the loader draws no canvas of its own. */
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
extern const struct nlr_exec_services nlr_exec_services;

static int plane_clean(void *address, uint32_t bytes)
{
    return nlr_exec_services.clean(address, bytes);
}
#else
static int plane_clean(void *address, uint32_t bytes)
{
    (void)address;
    (void)bytes;
    return -1;
}
#endif

/* The CPU address of the buffer a scanout register pair names, or 0 when
 * it names none: a bus address below the offset is not one of ours. */
static uint64_t scanout_address(const struct nlr_program_services *ps,
                                const volatile uint32_t *pair)
{
    uint64_t bus = (uint64_t)pair[0] |
                   (uint64_t)(pair[1] & ps->scanout_high_mask) << 32;
    return bus >= ps->bus_offset ? bus - ps->bus_offset : 0;
}

int nlr_program_scanout(uint64_t *colour, uint64_t *alpha)
{
    const struct nlr_program_services *ps = program_services();
    if (!ps || !ps->scanout_colour || !ps->scanout_alpha || !colour || !alpha)
        return NLR_NOT_READY;
    *colour = scanout_address(ps, ps->scanout_colour);
    *alpha = scanout_address(ps, ps->scanout_alpha);
    return NLR_OK;
}

/* A buffer of `bytes` at `address` lies whole inside the plane band. */
static int plane_inside(const struct nlr_program_services *ps,
                        uint64_t address, uint64_t bytes)
{
    return address && !(address & 31u) && address >= ps->plane_lo &&
           address < ps->plane_hi && bytes <= ps->plane_hi - address;
}

#if !NLR_HAS_GRAPHICS
/* Two byte ranges share no byte. */
static int ranges_apart(uint64_t a, uint64_t a_bytes, uint64_t b,
                        uint64_t b_bytes)
{
    return a + a_bytes <= b || b + b_bytes <= a;
}

/* Quadwords, then the tail: the core links no memcpy, and -fno-builtin
 * keeps this a loop. */
static void plane_copy(uint8_t *to, const uint8_t *from, uint32_t bytes)
{
    uint64_t *d = (uint64_t *)(void *)to;
    const uint64_t *s = (const uint64_t *)(const void *)from;
    uint32_t words = bytes / 8u;
    for (uint32_t i = 0; i < words; i++)
        d[i] = s[i];
    for (uint32_t i = words * 8u; i < bytes; i++)
        to[i] = from[i];
}

/* The program draws into the buffer the display controller is showing for
 * the GUI's plane: the GUI is idle under the NLoader page while the program
 * owns the buttons, so nothing redraws over it, and the GUI's next redraw
 * after the program returns restores the page. The registers, not a GUI
 * record, say which buffer that is: the GUI keeps several and rotates, and
 * may rotate once more after this call (the page's own result row redraws
 * as the program starts), which ui_present follows. */
static int native_gfx_begin(struct nlr_surface *out)
{
    /* A missing channel answers -ENOSYS whatever the argument. */
    const struct nlr_program_services *ps = program_services();
    if (!ps || !ps->scanout_colour || !ps->width || !ps->height)
        return -NLR_API_ENOSYS;
    if (!out)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    uint64_t pixel_bytes = (uint64_t)ps->stride * ps->height;
    uint64_t alpha_bytes = (uint64_t)ps->alpha_stride * ps->height;
    uint64_t colour = scanout_address(ps, ps->scanout_colour);
    uint64_t alpha = ps->scanout_alpha ? scanout_address(ps, ps->scanout_alpha)
                                       : 0;
    int result = 0;
    if (!r || !foreground_state() || pixel_bytes > UINT32_MAX ||
        alpha_bytes > UINT32_MAX || !plane_inside(ps, colour, pixel_bytes) ||
        (ps->scanout_alpha && !plane_inside(ps, alpha, alpha_bytes))) {
        result = -NLR_API_EIO;
    } else {
        out->format = NLR_SURFACE_Y0Y1UV_A8;
        out->width = ps->width;
        out->height = ps->height;
        out->stride = ps->stride;
        out->pixels = (uint8_t *)(uintptr_t)colour;
        out->alpha = (uint8_t *)(uintptr_t)alpha;
        out->alpha_stride = alpha ? ps->alpha_stride : 0;
        out->reserved = 0;
        r->io.gfx_pixels = out->pixels;
        r->io.gfx_alpha = out->alpha;
        r->io.gfx_pixel_bytes = (uint32_t)pixel_bytes;
        r->io.gfx_alpha_bytes = alpha ? (uint32_t)alpha_bytes : 0;
        program_io_for_input(); /* the screen implies the buttons */
        __atomic_store_n(&r->io.gfx_active, 1u, __ATOMIC_RELEASE);
    }
    service_end(p);
    return result;
}

static int native_ui_present(void)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!ps || !r || !__atomic_load_n(&r->io.gfx_active, __ATOMIC_ACQUIRE))
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    uint8_t *pixels = r->io.gfx_pixels, *alpha = r->io.gfx_alpha;
    uint32_t pixel_bytes = r->io.gfx_pixel_bytes;
    uint32_t alpha_bytes = r->io.gfx_alpha_bytes;
    /* The frame goes to whichever buffer is shown now: when the GUI has
     * moved the screen off the program's surface, the surface is copied
     * onto the shown buffer, which must be whole, in the band and apart
     * from the surface. */
    uint64_t shown = scanout_address(ps, ps->scanout_colour);
    uint64_t shown_alpha = alpha ? scanout_address(ps, ps->scanout_alpha) : 0;
    uint64_t from = (uintptr_t)pixels, from_alpha = (uintptr_t)alpha;
    if (shown != from && plane_inside(ps, shown, pixel_bytes) &&
        ranges_apart(shown, pixel_bytes, from, pixel_bytes) &&
        (!alpha || ranges_apart(shown, pixel_bytes, from_alpha, alpha_bytes)) &&
        (!alpha || (plane_inside(ps, shown_alpha, alpha_bytes) &&
                    ranges_apart(shown_alpha, alpha_bytes, from, pixel_bytes) &&
                    ranges_apart(shown_alpha, alpha_bytes, from_alpha, alpha_bytes) &&
                    ranges_apart(shown_alpha, alpha_bytes, shown, pixel_bytes)))) {
        plane_copy((uint8_t *)(uintptr_t)shown, pixels, pixel_bytes);
        pixels = (uint8_t *)(uintptr_t)shown;
        if (alpha) {
            plane_copy((uint8_t *)(uintptr_t)shown_alpha, alpha, alpha_bytes);
            alpha = (uint8_t *)(uintptr_t)shown_alpha;
        }
        r->io.gfx_follows++;
    }
    /* The display reads the planes by DMA: what was written must leave the
     * D-cache first. */
    int result = 0;
    if (plane_clean(pixels, pixel_bytes) != 0 ||
        (alpha && plane_clean(alpha, alpha_bytes) != 0))
        result = -NLR_API_EIO;
    screen_activity(r);
    service_end(p);
    return result;
}

#endif

static int api_gfx_begin(struct nlr_surface *out)
{
    if (!api4_foreground()) return -NLR_API_ENOSYS;
#if NLR_HAS_GRAPHICS
    if (!out) return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    int result = -NLR_API_EBUSY;
    if (!p || !r || &r->load.program != p ||
        !__atomic_load_n(&r->graphics_canvas_ready, __ATOMIC_ACQUIRE) ||
        !r->graphics_services.worker_owner ||
        r->graphics_services.worker_owner(r->graphics_services.context, r->graphics_owner))
        result = -NLR_API_EIO;
    else if (!__atomic_load_n(&r->io.gfx_active, __ATOMIC_ACQUIRE)) {
        const uint32_t colour = NLR_GRAPHICS_WIDTH * 2u * NLR_GRAPHICS_HEIGHT;
        const uint32_t alpha = NLR_GRAPHICS_WIDTH * NLR_GRAPHICS_HEIGHT;
        if (!r->io.gfx_request) {
            void *request = nlr_alloc_whole(&nlr_services, colour + alpha + NLR_CACHE_LINE);
            if (request) {
                r->io.gfx_request = request;
                r->io.gfx_pixels = (void *)(((uintptr_t)request + NLR_CACHE_LINE - 1u) &
                    ~(uintptr_t)(NLR_CACHE_LINE - 1u));
                r->io.gfx_alpha = r->io.gfx_pixels + colour;
                r->io.gfx_pixel_bytes = colour;
                r->io.gfx_alpha_bytes = alpha;
                for (uint32_t n = 0; n < colour; n += 4) {
                    r->io.gfx_pixels[n] = r->io.gfx_pixels[n + 1] = 16u;
                    r->io.gfx_pixels[n + 2] = r->io.gfx_pixels[n + 3] = 128u;
                }
                for (uint32_t n = 0; n < alpha; n++) r->io.gfx_alpha[n] = 255u;
            }
        }
        if (!r->io.gfx_request) result = -NLR_API_EIO;
        else {
            *out = (struct nlr_surface){NLR_SURFACE_Y0Y1UV_A8,
                NLR_GRAPHICS_WIDTH, NLR_GRAPHICS_HEIGHT, NLR_GRAPHICS_WIDTH * 2u,
                r->io.gfx_pixels, r->io.gfx_alpha, NLR_GRAPHICS_WIDTH, 0};
            __atomic_store_n(&r->io.gfx_active, 1u, __ATOMIC_RELEASE);
            result = 0;
        }
    }
    service_end(p);
    return result;
#else
    return native_gfx_begin(out);
#endif
}

#if NLR_HAS_GRAPHICS
static uint8_t colour_clip(int value)
{
    return value < 0 ? 0 : value > 255 ? 255 : (uint8_t)value;
}

/* BT.601 limited-range Y0,Y1,U,V pairs to the independently owned native
 * GUI source. The packed application buffer is never a scanout address. */
static void packed_to_rgba(const struct nlr_program_io *io, uint8_t *out)
{
    for (uint32_t n = 0; n < NLR_GRAPHICS_WIDTH * NLR_GRAPHICS_HEIGHT; n += 2) {
        const uint8_t *pair = io->gfx_pixels + n * 2u;
        int u = (int)pair[2] - 128, v = (int)pair[3] - 128;
        for (uint32_t q = 0; q < 2; q++) {
            int y = (int)pair[q] - 16;
            uint8_t *pixel = out + (n + q) * 4u;
            pixel[0] = colour_clip((298 * y + 409 * v + 128) >> 8);
            pixel[1] = colour_clip((298 * y - 100 * u - 208 * v + 128) >> 8);
            pixel[2] = colour_clip((298 * y + 516 * u + 128) >> 8);
            pixel[3] = io->gfx_alpha[n + q];
        }
    }
}
#endif

static int api_ui_present(void)
{
    if (!api4_foreground()) return -NLR_API_ENOSYS;
#if NLR_HAS_GRAPHICS
    struct nlr_program_state *p = service_begin();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!p || !r || &r->load.program != p ||
        !__atomic_load_n(&r->io.gfx_active, __ATOMIC_ACQUIRE)) {
        service_end(p);
        return -NLR_API_EBUSY;
    }
    struct nlr_graphics_frame frame;
    int result = nlr_graphics_begin(&r->graphics, &r->graphics_services,
                                   r->graphics_owner, &frame);
    if (!result) {
        packed_to_rgba(&r->io, frame.pixels);
        result = nlr_graphics_end(&r->graphics, r->graphics_owner);
    }
    service_end(p);
    return result == 0 ? 0 : result == NLR_GRAPHICS_BUSY ? -NLR_API_EBUSY : -NLR_API_EIO;
#else
    return native_ui_present();
#endif
}

static int api_gfx_end(void)
{
    if (!api4_foreground()) return -NLR_API_ENOSYS;
#if !NLR_HAS_GRAPHICS
    const struct nlr_program_services *ps = program_services();
    if (!ps || !ps->scanout_colour) return -NLR_API_ENOSYS;
#endif
    struct nlr_program_state *p = service_begin();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    int result = -NLR_API_EBUSY;
    if (p && r && &r->load.program == p &&
#if NLR_HAS_GRAPHICS
        r->graphics_services.worker_owner &&
        !r->graphics_services.worker_owner(r->graphics_services.context, r->graphics_owner) &&
#endif
        __atomic_load_n(&r->io.gfx_active, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&r->io.gfx_active, 0u, __ATOMIC_RELEASE);
        result = 0;
    }
    service_end(p);
    return result;
}

/* ---- log ------------------------------------------------------------------ */

/* Minimal bounded formatter: the camera build is freestanding (no libc
 * stdio is linked into the blob objects), and the log channel is
 * diagnostic. Supported: %% %s %c %d %i %u %x with the l and ll length
 * modifiers, and %p as an 0x-prefixed pointer; any other conversion writes
 * '?' so a silent mis-format stays visible. */
static void api_log(const char *fmt, ...)
{
    /* total counts every formatted byte (the recorded length), used the
     * bytes that still fit the bounded buffer. */
    char text[NLR_API_LOG_MAX];
    uint32_t used = 0, total = 0;
    struct nlr_program_state *program = service_begin();
    va_list args;
    va_start(args, fmt);
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            if (used < sizeof text)
                text[used++] = *p;
            total++;
            continue;
        }
        p++;
        unsigned long long value = 0;
        unsigned base = 10;
        int is_negative = 0;
        const char *string = 0;
        char single = 0;
        int is_long = 0;
        while (*p == 'l') { /* one l or two: long is 64-bit on this ABI */
            is_long = 1;
            p++;
        }
        switch (*p) {
        case '%':
            if (used < sizeof text)
                text[used++] = '%';
            total++;
            continue;
        case 's':
            string = va_arg(args, const char *);
            if (!string)
                string = "(null)";
            while (*string) {
                if (used < sizeof text)
                    text[used++] = *string;
                string++;
                total++;
            }
            continue;
        case 'c':
            single = (char)va_arg(args, int);
            if (used < sizeof text)
                text[used++] = single;
            total++;
            continue;
        case 'd':
        case 'i': {
            long long v = is_long ? (long long)va_arg(args, long)
                                  : (long long)va_arg(args, int);
            if (v < 0) {
                is_negative = 1;
                value = 0u - (unsigned long long)v; /* no negation overflow */
            } else {
                value = (unsigned long long)v;
            }
            break;
        }
        case 'u':
            value = is_long ? (unsigned long long)va_arg(args, unsigned long)
                            : (unsigned long long)va_arg(args, unsigned int);
            break;
        case 'x':
            base = 16;
            value = is_long ? (unsigned long long)va_arg(args, unsigned long)
                            : (unsigned long long)va_arg(args, unsigned int);
            break;
        case 'p': {
            uintptr_t v = (uintptr_t)va_arg(args, void *);
            value = (unsigned long long)v;
            base = 16;
            if (used < sizeof text)
                text[used++] = '0';
            if (used < sizeof text)
                text[used++] = 'x';
            total += 2;
            break;
        }
        default:
            if (used < sizeof text)
                text[used++] = '?';
            total++;
            continue;
        }
        /* Digits in reverse order, then written back; the buffer takes what
         * still fits, the length counts everything. */
        char digits[24];
        uint32_t count = 0;
        do {
            uint32_t digit = (uint32_t)(value % base);
            digits[count++] =
                (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
            value /= base;
        } while (value && count < sizeof digits);
        if (is_negative) {
            if (used < sizeof text)
                text[used++] = '-';
            total++;
        }
        while (count) {
            if (used < sizeof text)
                text[used++] = digits[--count];
            else
                count--;
            total++;
        }
    }
    va_end(args);
    /* The trace ring is the loader's RAM diagnostic; log text is packed
     * four bytes per entry after the length entry. */
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r) {
        service_end(program);
        return; /* no runtime to record in; log has no error channel */
    }
    nlr_trace_put(&r->load.trace, 'T', (int32_t)total);
    for (uint32_t off = 0; off < used; off += 4) {
        uint32_t chunk = 0;
        uint32_t n = used - off < 4 ? used - off : 4;
        for (uint32_t i = 0; i < n; i++)
            chunk |= (uint32_t)(uint8_t)text[off + i] << (8 * i);
        nlr_trace_put(&r->load.trace, 't', (int32_t)chunk);
    }
    service_end(program);
}

/* ---- lifecycle ------------------------------------------------------------ */

static void api_exit(int code)
{
    /* No ambient writable state is allowed in XIP code, so the running
     * program's context is found through the same registry scan the boot
     * used; log and exit are rare, diagnostic-driven calls. */
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return;
    struct nlr_program_state *p = &r->load.program;
    if (!__atomic_load_n(&p->jump_armed, __ATOMIC_ACQUIRE)) {
        /* Foreground-only interface (PLAN 5.1): a resource extension's exit
         * request is recorded and ignored, never a stop. */
        nlr_trace_put(&r->load.trace, 'Z', code);
        return;
    }
    p->exit_requested = 1;
    p->exit_code = code;
    nlr_journal(r->load.journal, "the program called exit(%d)", code);
    /* Does not return into the application: nlr_program_run resumes and
     * cleans up as for a normal return with this status. */
    nlr_program_longjmp(p->context, 1);
}

/* ---- time (ABI 4) -------------------------------------------------------- */

/* A program that holds the screen (ABI 4 gfx, ABI 7 screen_claim) gives
 * the camera no sign of life by drawing or waiting, and the stock GUI that
 * would count the user's presses is the program's or held: the camera's
 * standby timer (30 s in live view on the Z 8, QEMU) then switched the
 * display off under a boot program that was still waiting, and the
 * program never came back (qemu-ki-082, qemu-fc-039). So, while the screen
 * is the program's, its presents and every step of its waits tell the
 * camera about user activity, once a second at most (the signal allocates
 * a UI message on the Z 8). The signal is the body's one activity entry,
 * however it is declared (nlr_platform_scan_view); once the program has
 * given the screen back or ended, standby runs as in stock. */
static void screen_activity(struct nlr_runtime *r)
{
    if (!r || (!__atomic_load_n(&r->plat.claimed, __ATOMIC_ACQUIRE) &&
               !__atomic_load_n(&r->io.gfx_active, __ATOMIC_ACQUIRE)))
        return;
    struct nlr_scan_view view;
    if (!nlr_platform_scan_view(&nlr_services, &view) || !view.activity)
        return;
    uint32_t now = api_time_ms();
    if (now - r->io.activity_ms < 1000u)
        return;
    r->io.activity_ms = now;
    view.activity();
}

static uint32_t api_time_ms(void)
{
    struct nlr_program_state *p = service_begin();
    uint32_t result = nlr_clock_ms();
    service_end(p);
    return result;
}

/* Every wait yields through a model-owned native service. Z8 retains its
 * measured clock and stall checks; no absent provider causes a busy loop. */
static void boot_alive(const struct nlr_program_state *p);

/* Every step of a wait (sleep_ms in pieces, queue_wait's polls): the stop
 * of a foreground program is honoured here, and a boot program that has
 * been running NLR_BOOT_GOOD_MS is recorded as a good start here too -- a
 * shell that waits in queue_wait(NLR_QUEUE_FOREVER) from its first seconds
 * never comes back to a wait's entry, and the next boot would otherwise
 * find its record still at "run" and skip it. */
static void sleep_checkpoint(void *context)
{
    struct nlr_program_state **p = context;
    service_end(*p);
    *p = service_begin();
    boot_alive(*p);
    if (*p)
        screen_activity(nlr_runtime_find(&nlr_services, 0));
}

/* A wait of the running foreground program is where a boot program's
 * start counts as good once it has run long enough (runtime.c boot record):
 * on the worker it runs on, between its own calls. */
static void boot_alive(const struct nlr_program_state *p)
{
    if (p)
        nlr_runtime_boot_alive(nlr_runtime_find(&nlr_services, 0));
}

static void api_sleep_ms(uint32_t ms)
{
    struct nlr_program_state *p = service_begin();
    int result = 0;
    boot_alive(p);
    if (nlr_services.time) {
        do {
            uint32_t part = ms > 1000u ? 1000u : ms;
            result = nlr_time_sleep(nlr_services.time, part ? part : 1u, sleep_checkpoint, &p);
            if (result) break;
            ms -= part;
        } while (ms);
    } else if (nlr_services.sleep_ms) {
        do {
            uint32_t part = ms > 10u ? 10u : ms;
            nlr_services.sleep_ms(part ? part : 1u);
            sleep_checkpoint(&p);
            ms -= part;
        } while (ms);
    } else result = -NLR_API_ENOSYS;
    if (result) {
        struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
        if (r) nlr_trace_record(&r->load, 'd', result);
    }
    service_end(p);
    /* The void public contract has no error channel. A failed foreground
     * wait therefore ends the application instead of allowing a tight loop
     * to starve the original GUI with an unfulfilled sleep promise. */
    if (result && p) {
        p->exit_requested = 1;
        p->exit_code = result;
        nlr_program_longjmp(p->context, 1);
    }
}

/* ---- directory listing (ABI 4) ------------------------------------------- */

/* One entry per call of the firmware's enumerator, on the filesystem task:
 * count the entries of the running pass and copy out the wanted one. */
/* The entry's name as a path takes it: the long name when it is printable
 * ASCII and fits, else the firmware's own 8.3 name, which always does. */
static void dir_name(const struct nlr_program_services *ps,
                     const uint8_t *info, char *out)
{
    const uint8_t *l = info + ps->info_long;
    uint32_t unit = ps->info_long_unit == 2u ? 2u : 1u;
    uint32_t n = 0;
    for (;; n++) {
        uint32_t c = l[n * unit];
        if (unit == 2u)
            c |= (uint32_t)l[n * unit + 1u] << 8;
        if (!c)
            break;
        if (c < 0x20u || c > 0x7eu || n + 1u >= NLR_DIRENT_NAME_MAX) {
            n = 0;
            break;
        }
        out[n] = (char)c;
    }
    if (n) {
        out[n] = 0;
        return;
    }
    const char *s = (const char *)info + ps->info_short;
    for (; s[n] && n < NLR_DIRENT_NAME_MAX - 1u; n++)
        out[n] = s[n];
    if (s[n]) /* cut: say so */
        out[n - 1] = '~';
    out[n] = 0;
}

static uint32_t dir_each(const uint8_t *info)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!ps || !r || !info || !r->io.dir_out)
        return 1;
    struct nlr_program_io *io = &r->io;
    uint32_t directory = !!(info[ps->info_attr] & ps->attr_directory);
    if (directory != io->dir_directories)
        return 0; /* the other pass reports it */
    char name[NLR_DIRENT_NAME_MAX] = {0};
    dir_name(ps, info, name);
    if (name[0] == '.' && (!name[1] || (name[1] == '.' && !name[2])))
        return 0;
    /* The loader's own listing of programs (nlr_program_dir_all): every
     * name in one pass, into the caller's list. */
    if (io->dir_all) {
        if (io->dir_all_count < io->dir_all_cap) {
            char *to = io->dir_all + io->dir_all_count * NLR_DIRENT_NAME_MAX;
            for (uint32_t n = 0; n < NLR_DIRENT_NAME_MAX; n++)
                to[n] = name[n];
            io->dir_all_count++;
        }
        return io->dir_all_count >= io->dir_all_cap;
    }
    if (io->dir_seen++ != io->dir_want)
        return 0;
    struct nlr_dirent *out = io->dir_out;
    for (uint32_t n = 0; n < NLR_DIRENT_NAME_MAX; n++)
        out->name[n] = name[n];
    uint64_t size = 0;
    for (uint32_t b = 0; b < 8; b++)
        size |= (uint64_t)info[ps->info_size + b] << (8 * b);
    out->size = directory ? 0 : size;
    out->flags = directory ? NLR_DIRENT_DIR : 0;
    out->reserved = 0;
    io->dir_found = 1;
    return 1;
}

/* A directory a program may list: the configured card root (an empty path,
 * or the root itself), a directory below it, or the card's DCIM. 0 and
 * `full` filled, or -NLR_API_EINVAL. */
static int api_dir_path(const char *path, char *full)
{
    const uint32_t root_len = sizeof NLR_PROGRAM_ROOT - 1u;
    uint32_t same = 0;
    while (same < root_len && path[same] == NLR_PROGRAM_ROOT[same]) same++;
    if (!path[0] || (same == root_len && !path[root_len])) {
        for (uint32_t n = 0; n <= root_len; n++) full[n] = NLR_PROGRAM_ROOT[n];
        return 0;
    }
    int media = api_path_media(path, full);
    if (media < 0 || (!media && api_path_full(path, full)))
        return -NLR_API_EINVAL;
    return 0;
}

/* Directory listing stays below the configured card root, or in the card's
 * DCIM. Empty path means that root; directories precede files while the
 * directory is unchanged. */
static int api_fs_dir(const char *path, uint32_t index, struct nlr_dirent *out)
{
    if (root_card_gone())
        return -NLR_API_ENODEV;
    if (!path || !out)
        return -NLR_API_EINVAL;
    char full[NLR_PATH_BYTES];
    if (api_dir_path(path, full))
        return -NLR_API_EINVAL;
    uint32_t len = 0;
    while (len < sizeof full && full[len]) len++;
    if (len >= 128u) return -NLR_API_EINVAL;
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!ps || !ps->fs_enum)
        return -NLR_API_ENOSYS;
    if (!r)
        return -NLR_API_EIO;
    struct nlr_program_state *p = service_begin();
    if (!p) return -NLR_API_EBUSY;
    int result = nlr_program_dir(r, full, index, out);
    service_end(p);
    return result;
}

/* ABI 9: every file name of a directory in one pass, where fs_dir walks it
 * again for each entry. The same directories as fs_dir. */
static int32_t api_fs_dir_names(const char *path, char *names, uint32_t cap)
{
    if (root_card_gone())
        return -NLR_API_ENODEV;
    if (!path || !names || !cap)
        return -NLR_API_EINVAL;
    char full[NLR_PATH_BYTES];
    if (api_dir_path(path, full))
        return -NLR_API_EINVAL;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return -NLR_API_EIO;
    struct nlr_program_state *p = service_begin();
    if (!p)
        return -NLR_API_EBUSY;
    int result = nlr_program_dir_all(r, full, names, cap);
    service_end(p);
    return result;
}

/* The files (never directories) of `full`, every name in one pass of the
 * firmware's enumerator: at most `cap` names of NLR_DIRENT_NAME_MAX bytes
 * into `names`. The count, or a negative error as nlr_program_dir. */
int nlr_program_dir_all(struct nlr_runtime *r, const char *full, char *names,
                        uint32_t cap)
{
    const struct nlr_program_services *ps = program_services();
    if (!ps || !ps->fs_enum)
        return -NLR_API_ENOSYS;
    if (!r || !full || !names || !cap)
        return -NLR_API_EINVAL;
    uint32_t len = 0;
    while (len < 128u && full[len]) len++;
    if (len >= 128u) return -NLR_API_EINVAL;
    struct nlr_program_io *io = &r->io;
    struct nlr_dirent *idle = 0, unused;
    if (!__atomic_compare_exchange_n(&io->dir_out, &idle, &unused, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -NLR_API_EBUSY;
    io->dir_all = names;
    io->dir_all_cap = cap;
    io->dir_all_count = 0;
    io->dir_directories = 0;
    for (uint32_t i = 0; i <= len; i++) io->dir_path[i] = full[i];
    uint32_t result = ps->fs_enum(io->dir_path, ps->mask_files, dir_each);
    int count = (int)io->dir_all_count;
    io->dir_all = 0;
    __atomic_store_n(&io->dir_out, (struct nlr_dirent *)0, __ATOMIC_RELEASE);
    /* A full list stopped the walk: the firmware then answers with its
     * early-stop code, which is no error once the records were filled (as
     * for nlr_program_dir). The Z 8's enumerator gives neither 0 nor
     * enum_done there. */
    if (count > 0 && (uint32_t)count >= cap)
        return count;
    return result == 0 || result == ps->enum_done ? count : -NLR_API_EIO;
}

/* Entry `index` of the directory `full` (a whole card path), directories
 * first: 0, -ENOENT past the last entry, -EBUSY while another listing is
 * running, -ENOSYS without the model's enumerator, -EIO. The loader's own
 * listing (the programs in APPS) and fs_dir share it;
 * the listing in flight is the runtime's, so only one runs at a time. */
int nlr_program_dir(struct nlr_runtime *r, const char *full, uint32_t index,
                    struct nlr_dirent *out)
{
    const struct nlr_program_services *ps = program_services();
    if (!ps || !ps->fs_enum)
        return -NLR_API_ENOSYS;
    if (!r || !full || !out)
        return -NLR_API_EINVAL;
    uint32_t len = 0;
    while (len < 128u && full[len]) len++;
    if (len >= 128u) return -NLR_API_EINVAL;
    struct nlr_program_io *io = &r->io;
    struct nlr_dirent *idle = 0;
    if (!__atomic_compare_exchange_n(&io->dir_out, &idle, out, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -NLR_API_EBUSY;
    io->dir_want = index;
    io->dir_seen = 0;
    io->dir_found = 0;
    uint32_t result = ps->enum_done;
    for (uint32_t pass = 0; pass < 2 && !io->dir_found; pass++) {
        /* Each pass gets a fresh copy: the native enumerator may modify
         * its argument, so its first pass cannot redirect the second. */
        for (uint32_t i = 0; i <= len; i++) io->dir_path[i] = full[i];
        io->dir_directories = pass == 0;
        result = ps->fs_enum(io->dir_path, pass == 0 ? ps->mask_directories
                                                     : ps->mask_files,
                             dir_each);
        if (result != 0 && result != ps->enum_done)
            break;
    }
    int found = (int)io->dir_found;
    __atomic_store_n(&io->dir_out, (struct nlr_dirent *)0, __ATOMIC_RELEASE);
    if (found)
        return 0;
    return result == 0 || result == ps->enum_done ? -NLR_API_ENOENT
                                                   : -NLR_API_EIO;
}

/* ---- native list (ABI 4) -------------------------------------------------- */

/* Copy at most NLR_LIST_TEXT_MAX bytes and terminate; a null text is empty. */
static void list_text(char *to, const char *from)
{
    uint32_t n = 0;
    for (; from && from[n] && n < NLR_LIST_TEXT_MAX; n++)
        to[n] = from[n];
    to[n] = 0;
}

/* The program's request for the loader's own window: a text entry
 * (ui_input: the text it starts with, the most characters of which charset
 * the keyboard takes) or a caution (ui_caution: its text, already broken
 * into lines, and its buttons). */
struct list_dialog {
    uint32_t kind;  /* NLR_OWN_* */
    const char *text;
    uint32_t length;
    uint32_t charset;
    uint32_t buttons;
};

/* The program's list goes to the NLoader page, which draws it with the
 * camera's own rows and answers with the user's choice. Publishing is the
 * seq increment after the copy; the page reads the rows only while the
 * program waits here, and the program writes them only before publishing.
 * A page of row kinds (ABI 6, `kinds` set) carries each row's kind, flags
 * and value with its label; a plain list is labels only. A request for
 * the loader's own window (`dialog`) is a list of one row whose OK opens
 * it -- a text entry's title with the text so far as the value, or a
 * caution's text -- and the page opens it at once when the request comes
 * while it waits for the program. */
static int32_t list_wait(const char *title, const char *const *labels,
                         const struct nlr_row *kinds, uint32_t count,
                         uint32_t selected, const struct list_dialog *dialog)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || !__atomic_load_n(&r->io.list_capacity, __ATOMIC_ACQUIRE) ||
        (!nlr_services.time && !nlr_services.sleep_ms))
        return -NLR_API_ENOSYS;
    if (dialog && (!__atomic_load_n(&r->own.ready, __ATOMIC_ACQUIRE) ||
                   (dialog->kind == NLR_OWN_CAUTION && !r->own.caution_ready)))
        return -NLR_API_ENOSYS;
    if (count > NLR_LIST_ROWS_MAX || count > r->io.list_capacity ||
        (count && !labels && !kinds && !dialog) || (kinds && count > NLR_ROWS_MAX))
        return -NLR_API_EINVAL;
    uint32_t native = 0;
    for (uint32_t i = 0; kinds && i < count; i++) {
        if (kinds[i].kind > NLR_ROW_TEXT ||
            (kinds[i].flags & ~(NLR_ROW_ON | NLR_ROW_GREYED)))
            return -NLR_API_EINVAL;
        native |= kinds[i].kind != NLR_ROW_ENTRY ||
                  (kinds[i].flags & NLR_ROW_GREYED);
    }
    if (native && !__atomic_load_n(&r->io.list_rows, __ATOMIC_ACQUIRE))
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    if (!p) {
        return -NLR_API_ENOSYS; /* foreground programs only */
    }
    if (__atomic_load_n(&r->io.gfx_active, __ATOMIC_ACQUIRE)) {
        service_end(p);
        return -NLR_API_EBUSY;
    }
    list_text(r->list.title, title);
    for (uint32_t i = 0; i < count; i++) {
        list_text(r->list.rows[i], kinds ? kinds[i].label : dialog ? title : labels[i]);
        if (i >= NLR_ROWS_MAX)
            continue;
        r->list.kinds[i] = kinds ? (uint8_t)kinds[i].kind : (uint8_t)NLR_ROW_ENTRY;
        r->list.row_flags[i] = kinds ? (uint8_t)kinds[i].flags : 0;
        list_text(r->list.values[i],
                  kinds && kinds[i].kind == NLR_ROW_SELECT ? kinds[i].value : 0);
    }
    r->list.rows_view = kinds != 0;
    r->list.dialog = dialog ? dialog->kind : 0;
    if (dialog && dialog->kind == NLR_OWN_KEYBOARD) {
        uint32_t n = 0;
        for (; dialog->text && dialog->text[n] && n < dialog->length; n++)
            r->own.text[n] = dialog->text[n];
        r->own.text[n] = 0;
        r->own.length = dialog->length;
        r->own.charset = dialog->charset;
        /* Where the page draws row kinds, the row shows the text so far. */
        if (__atomic_load_n(&r->io.list_rows, __ATOMIC_ACQUIRE)) {
            r->list.rows_view = 1;
            r->list.kinds[0] = NLR_ROW_SELECT;
            list_text(r->list.values[0], r->own.text);
        }
    } else if (dialog) {
        list_text(r->own.message, dialog->text);
        r->own.buttons = dialog->buttons;
    }
    r->list.count = count;
    r->list.selected = selected < count ? selected : 0;
    uint32_t answered = __atomic_load_n(&r->list.choice_seq, __ATOMIC_ACQUIRE);
    __atomic_store_n(&r->io.list_active, 1u, __ATOMIC_RELEASE);
    if (nlr_services.input) nlr_input_focus_lost(&r->input,
        __atomic_load_n(&r->input_owner, __ATOMIC_ACQUIRE));
    else __atomic_store_n(&r->io.event_head,
        __atomic_load_n(&r->io.event_tail, __ATOMIC_ACQUIRE), __ATOMIC_RELEASE);
    __atomic_add_fetch(&r->list.seq, 1u, __ATOMIC_RELEASE);
#if NLR_HAS_GRAPHICS
    /* A page that no longer follows the program takes the list at the
     * menu's next turn (menu_page.c nlr_page_show_late_list). */
    nlr_graphics_runtime_list_published(r);
#endif
    /* The page answers on the menu task; a stop request ends the wait
     * (service_end then leaves the program). */
    while (__atomic_load_n(&r->list.choice_seq, __ATOMIC_ACQUIRE) == answered &&
           !__atomic_load_n(&p->stop_requested, __ATOMIC_ACQUIRE)) {
        if (nlr_services.time) {
            if (nlr_time_sleep(nlr_services.time, 10u, 0, 0)) {
                __atomic_store_n(&r->io.list_active, 0u, __ATOMIC_RELEASE);
                service_end(p);
                return -NLR_API_EIO;
            }
        } else nlr_services.sleep_ms(10u);
    }
    int32_t choice = __atomic_load_n(&r->list.choice, __ATOMIC_ACQUIRE);
    __atomic_store_n(&r->io.list_active, 0u, __ATOMIC_RELEASE);
    service_end(p);
    return choice;
}

static int32_t api_ui_list(const char *title, const char *const *rows,
                           uint32_t count, uint32_t selected)
{
    return list_wait(title, rows, 0, count, selected, 0);
}

static int32_t api_ui_rows(const char *title, const struct nlr_row *rows,
                           uint32_t count, uint32_t selected)
{
    return list_wait(title, 0, rows, count, selected, 0);
}

/* The camera's keyboard, through the page: the text saved comes back in
 * `taken` (written before the answer), and only a save changes `buf`. */
static int32_t api_ui_input(const char *title, char *buf, uint32_t size,
                            uint32_t charset)
{
    if (!buf || size < 2u ||
        (charset != NLR_INPUT_ASCII && charset != NLR_INPUT_UPPER &&
         charset != NLR_INPUT_DIGITS))
        return -NLR_API_EINVAL;
    struct list_dialog input = {
        NLR_OWN_KEYBOARD, buf, size - 1u < NLR_INPUT_MAX ? size - 1u : NLR_INPUT_MAX,
        charset, 0,
    };
    int32_t choice = list_wait(title, 0, 0, 1, 0, &input);
    if (choice < 0 || choice == (int32_t)NLR_LIST_BACK)
        return choice;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    uint32_t n = 0;
    for (; r && n < input.length && n < (uint32_t)choice && r->own.taken[n]; n++)
        buf[n] = r->own.taken[n];
    buf[n] = 0;
    return (int32_t)n;
}

/* A caution's text as the box shows it: at most NLR_CAUTION_MAX bytes, a
 * line longer than NLR_CAUTION_LINE broken at its last space (the box
 * breaks lines only at '\n'), control characters other than '\n' as
 * spaces. */
static void caution_text(char *to, const char *from)
{
    uint32_t n = 0, line = 0, space = NLR_CAUTION_MAX + 1u;
    for (; from && from[n] && n < NLR_CAUTION_MAX; n++) {
        char c = from[n];
        if (c != '\n' && (unsigned char)c < 0x20u)
            c = ' ';
        to[n] = c;
        if (c == '\n') {
            line = 0;
            space = NLR_CAUTION_MAX + 1u;
            continue;
        }
        if (c == ' ')
            space = n;
        if (++line > NLR_CAUTION_LINE && space <= NLR_CAUTION_MAX) {
            to[space] = '\n';
            line = n - space;
            space = NLR_CAUTION_MAX + 1u;
        }
    }
    to[n] = 0;
}

/* The camera's caution box, through the page: 1 for OK or Yes, 0 for No. */
static int32_t api_ui_caution(const char *text, uint32_t buttons)
{
    if (!text || (buttons != NLR_CAUTION_OK && buttons != NLR_CAUTION_YES_NO))
        return -NLR_API_EINVAL;
    char shown[NLR_CAUTION_MAX + 1], row[NLR_CAUTION_MAX + 1];
    caution_text(shown, text);
    /* The row the page offers for a caution left open: the text on one
     * line, as the page's title too. */
    uint32_t n = 0;
    for (; shown[n]; n++)
        row[n] = shown[n] == '\n' ? ' ' : shown[n];
    row[n] = 0;
    struct list_dialog caution = {NLR_OWN_CAUTION, shown, 0, 0, buttons};
    int32_t choice = list_wait(row, 0, 0, 1, 0, &caution);
    if (choice < 0 || choice == (int32_t)NLR_LIST_BACK)
        return choice;
    return choice ? 1 : 0;
}

/* The running program's settings, as its details read them (they are the
 * checked program's: a foreground program starts from its details). */
static int32_t api_setting(const char *key)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return -NLR_API_EIO;
    if (!key)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    if (!p) return -NLR_API_EBUSY;
    int32_t value = r->settings.entry == r->checked + 1u ? nlr_settings_find(r, key) : -1;
    service_end(p);
    return value < 0 ? -NLR_API_ENOENT : value;
}

/* ---- the firmware's own code (ABI 4) ------------------------------------- */

/* core/hook.c owns the mechanism; these wrappers only turn the loader's
 * result codes into the API's errno values. A missing channel answers
 * -ENOSYS whatever the arguments, as every other optional channel does. */
static int code_result(int result)
{
    switch (result) {
    case NLR_OK:
        return 0;
    case NLR_NOT_READY:
        return -NLR_API_ENOSYS;
    case NLR_BOUNDS:
    case NLR_FORMAT:
        return -NLR_API_EINVAL;
    case NLR_BUSY:
        return -NLR_API_EBUSY;
    default:
        return -NLR_API_EIO;
    }
}

static int api_code_patch(void *address, const void *bytes, uint32_t len)
{
    if (!nlr_services.code)
        return -NLR_API_ENOSYS;
    if (!address || !bytes)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    int result = nlr_code_patch(nlr_services.code, (uint64_t)(uintptr_t)address,
                                bytes, len);
    service_end(p);
    return code_result(result);
}

static int api_code_hook(void *target, const void *expect, void *handler)
{
    if (!nlr_services.code)
        return -NLR_API_ENOSYS;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return -NLR_API_EIO;
    if (!target || !expect || !handler)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    int result = nlr_code_hook(r, (uint64_t)(uintptr_t)target, expect,
                               (uint64_t)(uintptr_t)handler);
    service_end(p);
    return result == NLR_FORMAT ? -NLR_API_EINVAL : code_result(result);
}

static int api_code_unhook(void *target)
{
    if (!nlr_services.code)
        return -NLR_API_ENOSYS;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return -NLR_API_EIO;
    if (!target)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    int result = nlr_code_unhook(r, (uint64_t)(uintptr_t)target);
    service_end(p);
    /* Nothing of ours is at that address. */
    return result == NLR_FORMAT ? -NLR_API_ENOENT : code_result(result);
}

/* ---- deferred menu resources --------------------------------------------- */

static int api_menu_register(const struct nlr_menu_test_item *item)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return -NLR_API_EIO;
    switch (nlr_runtime_menu_register(r, item)) {
    case NLR_OK:
        return 0;
    case NLR_BOUNDS:
    case NLR_FORMAT:
    case NLR_REFUSED:
        return -NLR_API_EINVAL;
    case NLR_BUSY:
        return -NLR_API_EBUSY;
    case NLR_NOT_READY:
        return -NLR_API_ENOSYS;
    default:
        return -NLR_API_EIO;
    }
}

/* ---- ABI 7 (nlr/platform.h) ---------------- */

/* The loader's own blocks for the platform (table copies, task records):
 * granted whole, as a program's blocks are -- this body's heap may answer
 * a request with a shorter block and still map the whole span (core/exec.c
 * grant probe). The request pointer is what release() takes. */
static void *platform_alloc(uint32_t bytes)
{
    return nlr_alloc_whole(&nlr_services, bytes);
}

/* The running foreground program's runtime, or 0. */
static struct nlr_runtime *platform_runtime(void)
{
    return api4_foreground() ? nlr_runtime_find(&nlr_services, 0) : 0;
}

/* Whether this body's input task hook can carry ABI 7 (family B): the
 * program input slot (the Z 6III's carrier), or -- for a body whose input
 * task registers one combined callback, which the exit service already
 * holds (the Z 8) -- that callback, installed. */
static int input_carrier(const struct nlr_runtime *r)
{
    if (!r)
        return 0;
    const struct nlr_program_services *ps = r->load.svc->program;
    if (ps && ps->input_slot && ps->input_original)
        return 1;
    return r->load.svc->exit && r->exit_original_input && (!ps || !ps->input_slot);
}

/* The program takes the input: the buttons through the ABI 4 capture, from
 * which on the hook hides them, and the per-control routes. */
static void platform_take(struct nlr_runtime *r)
{
    if (!r || !input_carrier(r))
        return;
    if (r->io.hooked && !program_io_for_input())
        return; /* the program hook owns the capture; nothing to take yet */
    uint32_t was = __atomic_load_n(&r->plat.active, __ATOMIC_ACQUIRE);
    uint32_t shell = __atomic_load_n(&r->plat.shell, __ATOMIC_ACQUIRE);
    nlr_platform_take_input(&r->plat, (int)shell);
    if (!was)
        nlr_journal(r->load.journal, "input taken: all to the program%s",
                    shell ? ", shutter shared" : "");
}

/* Waits through the model's own delay, so the stop of a foreground program
 * is honoured while it waits (sleep_checkpoint). */
static void platform_sleep(struct nlr_program_state **p, uint32_t ms)
{
    if (nlr_services.time)
        (void)nlr_time_sleep(nlr_services.time, ms ? ms : 1u, sleep_checkpoint, p);
    else if (nlr_services.sleep_ms) {
        nlr_services.sleep_ms(ms ? ms : 1u);
        sleep_checkpoint(p);
    }
}

/* The next event: a control, a dial, a due timer or a watched setting that
 * changed. 1 with `ev` filled, 0 when `timeout_ms` passed first, or a
 * negative error. The wait is a few milliseconds at a time on the model's
 * delay: the input task scans about that often, and the stock GUI below the
 * program must get the CPU. */
static int32_t api_queue_wait(struct nlr_event *ev, uint32_t timeout_ms)
{
    struct nlr_runtime *r = platform_runtime();
    if (!r || (!nlr_services.time && !nlr_services.sleep_ms))
        return -NLR_API_ENOSYS;
    if (!ev)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    boot_alive(p);
    platform_take(r);
    uint32_t start = nlr_clock_ms();
    int32_t result = 0;
    for (;;) {
        uint32_t now = nlr_clock_ms();
        if (nlr_platform_pop(&r->plat, ev) == 1 ||
            nlr_platform_touch_pop(&r->plat, ev) ||
            nlr_platform_posted(&r->plat, ev) ||
            nlr_platform_eye_poll(&r->plat, nlr_services.platform, now, ev) ||
            nlr_platform_timer_due(&r->plat, now, ev) ||
            nlr_platform_watch_poll(&r->plat, nlr_services.platform, now, ev) ||
            nlr_platform_card_poll(&r->plat, nlr_services.platform, now, ev)) {
            result = 1;
            break;
        }
        uint32_t spent = now - start;
        if (timeout_ms != NLR_QUEUE_FOREVER && spent >= timeout_ms)
            break;
        uint32_t wait = 4u;
        uint32_t timer = nlr_platform_timer_wait(&r->plat, now);
        if (timer < wait)
            wait = timer;
        if (timeout_ms != NLR_QUEUE_FOREVER && timeout_ms - spent < wait)
            wait = timeout_ms - spent;
        platform_sleep(&p, wait);
    }
    service_end(p);
    return result;
}

static int32_t api_timer_start(uint32_t period_ms, uint32_t tag)
{
    struct nlr_runtime *r = platform_runtime();
    if (!r)
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    int32_t result = nlr_platform_timer_start(&r->plat, period_ms, tag, nlr_clock_ms());
    service_end(p);
    return result;
}

static int32_t api_timer_stop(int32_t timer)
{
    struct nlr_runtime *r = platform_runtime();
    if (!r)
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    int32_t result = nlr_platform_timer_stop(&r->plat, timer);
    service_end(p);
    return result;
}

static int32_t api_input_route(const uint32_t *ctls, uint32_t count, uint32_t route)
{
    struct nlr_runtime *r = platform_runtime();
    if (!r || !nlr_services.platform || !input_carrier(r))
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    platform_take(r);
    int32_t result = __atomic_load_n(&r->plat.active, __ATOMIC_ACQUIRE)
                         ? nlr_platform_route(&r->plat, ctls, count, route)
                         : -NLR_API_EBUSY;
    nlr_journal(r->load.journal, "input_route %u controls (first %u) to %u: %d", count,
                count && ctls ? ctls[0] : 0u, route, result);
    service_end(p);
    return result;
}

/* The controls held at the last scan, as bits 1 << NLR_CTL_*. */
static uint64_t api_input_held(void)
{
    struct nlr_runtime *r = platform_runtime();
    if (!r)
        return 0;
    struct nlr_program_state *p = service_begin();
    uint64_t held = __atomic_load_n(&r->plat.held, __ATOMIC_ACQUIRE);
    service_end(p);
    return held;
}

/* The settings and status store (family D). Reading needs no program
 * context: an extension's or a service's own task may read too. A value of
 * several bytes is copied while the camera may be writing it; a program
 * that needs a consistent multi-word value reads it twice. */
static int32_t api_prop_get(uint32_t id, void *buf, uint32_t cap, uint32_t *size)
{
    const volatile uint8_t *value;
    uint32_t bytes;
    int32_t result = nlr_platform_prop(nlr_services.platform, id, &value, &bytes);
    if (result)
        return result;
    if (!buf)
        return -NLR_API_EINVAL;
    if (size)
        *size = bytes;
    if (cap < bytes)
        return -NLR_API_EOVERFLOW;
    for (uint32_t n = 0; n < bytes; n++)
        ((uint8_t *)buf)[n] = value[n];
    return 0;
}

static int32_t api_prop_info(uint32_t id, struct nlr_prop_info *out)
{
    const volatile uint8_t *value;
    uint32_t bytes;
    int32_t result = nlr_platform_prop(nlr_services.platform, id, &value, &bytes);
    if (result)
        return result;
    if (!out)
        return -NLR_API_EINVAL;
    out->id = (uint16_t)id;
    out->size = (uint16_t)bytes;
    out->flags = NLR_PROP_READ;
    if (nlr_services.platform->prop_set &&
        (bytes <= 4u || nlr_services.platform->prop_set_blob))
        out->flags |= NLR_PROP_WRITE;
    return 0;
}

static int32_t api_prop_watch(const uint16_t *ids, uint32_t count)
{
    struct nlr_runtime *r = platform_runtime();
    if (!r || !nlr_services.platform)
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    int32_t result = nlr_platform_watch(&r->plat, nlr_services.platform, ids, count);
    service_end(p);
    return result;
}

/* A setting written the way the camera's menus write it: the settings service, given the item's tagged id. The tag is
 * what makes the rest of the camera follow -- the in-effect value, the
 * stock GUI, derived values such as frames remaining -- so an id without
 * one is refused rather than stored to no effect; the SDK's table has the
 * tags (nlr_prop_tagged). The service takes its own lock and returns at
 * once; what follows from the change runs on the camera's own tasks. Any
 * program may write, from any of its tasks. */
static int32_t api_prop_set(uint32_t id, const void *value, uint32_t size)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    if (!pl || !pl->prop_set)
        return -NLR_API_ENOSYS;
    if (!(id >> 24) || (id & 0x00ff0000u) || !value || !size)
        return -NLR_API_EINVAL;
    const volatile uint8_t *ram;
    uint32_t bytes;
    int32_t result = nlr_platform_prop(pl, id & 0xffffu, &ram, &bytes);
    if (result)
        return result;
    if (bytes <= 4u ? size > 4u : size != bytes)
        return -NLR_API_EINVAL;
    if (bytes > 4u && !pl->prop_set_blob)
        return -NLR_API_ENOSYS;
    struct nlr_program_state *p = service_begin();
    uint64_t taken;
    if (bytes <= 4u) {
        uint32_t word = 0;
        for (uint32_t n = 0; n < size; n++)
            word |= (uint32_t)((const uint8_t *)value)[n] << (8u * n);
        taken = pl->prop_set(id, word);
    } else {
        taken = pl->prop_set_blob(id, value, size);
    }
    service_end(p);
    struct nlr_runtime *jr = nlr_runtime_find(&nlr_services, 0);
    if (jr)
    {
        uint32_t first = 0;
        for (uint32_t n = 0; n < size && n < 4u; n++)
            first |= (uint32_t)((const uint8_t *)value)[n] << (8u * n);
        nlr_journal(jr->load.journal, "prop_set %x (%u bytes) = %x: %s", id, size, first,
                    (taken & 1u) ? "taken" : "refused");
    }
    return (taken & 1u) ? 0 : -NLR_API_EACCES;
}

/* ---- the screen (family C) ---- */

/* Clean a range to the display in pieces: a range of 0x88000 bytes or
 * more becomes the firmware's whole-cache operation on every core. */
static void platform_clean(uint8_t *address, uint32_t bytes)
{
    while (bytes) {
        uint32_t part = bytes > 0x80000u ? 0x80000u : bytes;
        (void)plane_clean(address, part);
        address += part;
        bytes -= part;
    }
}

/* The stock GUI held at its checkpoint, so nothing it draws lands on the
 * layer: 0 when it already was, 1 when this call had to wait for it.
 * Only the program that holds it already may: the boot program
 * (the shell) from its start, or after it lent the screen back. A program
 * opened from the menu runs over the stock menu, where the GUI's buffers
 * are the menu's: it is refused rather than given buffers the camera is
 * about to draw into. */
/* How long a claim waits for the GUI to reach its hold point is the
 * profile's (services.platform.hold wait_ms, with its evidence there): the
 * hold is taken on the live-view side, never on the menu, and the stock
 * GUI may still be on its way there. No hold declared: a claim that would
 * have to wait is refused at once. */
static int32_t platform_hold(struct nlr_runtime *r, struct nlr_program_state **p)
{
    struct nlr_platform *plat = &r->plat;
    const struct nlr_platform_services *pl = r->load.svc ? r->load.svc->platform : 0;
    uint32_t limit = pl && pl->hold_when ? pl->hold_wait_ms : 0;
    if (!__atomic_load_n(&plat->shell, __ATOMIC_ACQUIRE))
        return -NLR_API_EBUSY;
    if (__atomic_load_n(&plat->inside, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&plat->lent, __ATOMIC_ACQUIRE))
        return 0;
    if (!limit)
        return -NLR_API_EBUSY;
    __atomic_store_n(&plat->lent, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->autoload.boot_hold, 1u, __ATOMIC_RELEASE);
    for (uint32_t waited = 0; !__atomic_load_n(&plat->inside, __ATOMIC_ACQUIRE);
         waited += 10u) {
        if (waited >= limit) {
            /* the GUI never reached its checkpoint: let it go on as it is */
            __atomic_store_n(&plat->lent, 1u, __ATOMIC_RELEASE);
            return -NLR_API_EBUSY;
        }
        platform_sleep(p, 10u);
    }
    return 1;
}

/* A hold that was just taken may follow the stock GUI's last commit by
 * moments: the display service then switches the layer to that frame
 * after the claim has read the shown buffers. The GUI is held, so nothing
 * commits again: once the shown buffers stay the same for the profile's
 * scanout_stable_ms (services.platform.hold, evidence there) they are the
 * ones to draw; never longer than NLR_PLATFORM_SCANOUT_WAIT_MS. */
static void platform_scanout_settle(const struct nlr_runtime *r,
                                    const struct nlr_program_services *ps,
                                    struct nlr_program_state **p)
{
    const struct nlr_platform_services *pl = r->load.svc ? r->load.svc->platform : 0;
    uint32_t want = pl ? pl->scanout_stable_ms : 0;
    uint64_t colour = scanout_address(ps, ps->scanout_colour);
    uint64_t alpha = scanout_address(ps, ps->scanout_alpha);
    uint32_t stable = 0;
    for (uint32_t waited = 0; stable < want &&
                              waited < NLR_PLATFORM_SCANOUT_WAIT_MS;
         waited += 10u) {
        platform_sleep(p, 10u);
        uint64_t c = scanout_address(ps, ps->scanout_colour);
        uint64_t a = scanout_address(ps, ps->scanout_alpha);
        if (c == colour && a == alpha) {
            stable += 10u;
        } else {
            colour = c;
            alpha = a;
            stable = 0;
        }
    }
}

static int32_t api_screen_claim(uint32_t screen, struct nlr_surface *out)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = platform_runtime();
    if (!r || !ps || !ps->scanout_colour || !ps->scanout_alpha || !ps->width ||
        !ps->height)
        return -NLR_API_ENOSYS;
    if (screen == NLR_SCREEN_EVF)
        return -NLR_API_ENOSYS;
    if (screen != NLR_SCREEN_REAR || !out)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    int32_t result = platform_hold(r, &p);
    if (result > 0) {
        platform_scanout_settle(r, ps, &p);
        result = 0;
    }
    uint64_t pixel_bytes = (uint64_t)ps->stride * ps->height;
    uint64_t alpha_bytes = (uint64_t)ps->alpha_stride * ps->height;
    uint64_t colour = scanout_address(ps, ps->scanout_colour);
    uint64_t alpha = scanout_address(ps, ps->scanout_alpha);
    if (!result && (pixel_bytes > UINT32_MAX || alpha_bytes > UINT32_MAX ||
                    !plane_inside(ps, colour, pixel_bytes) ||
                    !plane_inside(ps, alpha, alpha_bytes)))
        result = -NLR_API_EIO;
    if (!result) {
        out->format = NLR_SURFACE_Y0Y1UV_A8;
        out->width = ps->width;
        out->height = ps->height;
        out->stride = ps->stride;
        out->pixels = (uint8_t *)(uintptr_t)colour;
        out->alpha = (uint8_t *)(uintptr_t)alpha;
        out->alpha_stride = ps->alpha_stride;
        out->reserved = 0;
        /* The layer starts transparent: the live picture until the
         * program's first frame, never the stock GUI's last one. */
        uint64_t *clear = (uint64_t *)(uintptr_t)alpha;
        for (uint32_t n = 0; n < (uint32_t)alpha_bytes / 8u; n++)
            clear[n] = 0;
        platform_clean(out->alpha, (uint32_t)alpha_bytes);
        r->plat.colour = colour;
        r->plat.alpha = alpha;
        platform_take(r);
        __atomic_store_n(&r->plat.claimed, 1u, __ATOMIC_RELEASE);
    }
    nlr_journal(r->load.journal, "screen_claim: %d, layer %lx/%lx", result,
                (unsigned long long)colour, (unsigned long long)scanout_address(ps, ps->scanout_alpha));
    service_end(p);
    return result;
}

static int32_t api_screen_present(uint32_t screen, const struct nlr_rect *damage,
                                  uint32_t count)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = platform_runtime();
    if (!r || !ps || !ps->scanout_colour || !ps->scanout_alpha)
        return -NLR_API_ENOSYS;
    if (screen != NLR_SCREEN_REAR || (count && !damage) || count > 256u)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    int32_t result = 0;
    if (!__atomic_load_n(&r->plat.claimed, __ATOMIC_ACQUIRE))
        result = -NLR_API_EBUSY;
    else if (scanout_address(ps, ps->scanout_colour) != r->plat.colour ||
             scanout_address(ps, ps->scanout_alpha) != r->plat.alpha) {
        /* the layer shows another buffer: not the program's to draw */
        result = -NLR_API_EIO;
        uint32_t n = ++r->plat.journal_present_fail;
        if (n <= 3u || !(n % 100u))
            nlr_journal(r->load.journal, "present: layer %lx, the program's %lx (%u)",
                        (unsigned long long)scanout_address(ps, ps->scanout_colour),
                        (unsigned long long)r->plat.colour, n);
    }
    uint8_t *pixels = (uint8_t *)(uintptr_t)r->plat.colour;
    uint8_t *alpha = (uint8_t *)(uintptr_t)r->plat.alpha;
    if (!result && !count) {
        platform_clean(pixels, ps->stride * ps->height);
        platform_clean(alpha, ps->alpha_stride * ps->height);
    }
    for (uint32_t n = 0; !result && n < count; n++) {
        uint32_t x = damage[n].x, y = damage[n].y;
        uint32_t w = damage[n].width, h = damage[n].height;
        if (x >= ps->width || y >= ps->height)
            continue;
        if (w > ps->width - x)
            w = ps->width - x;
        if (h > ps->height - y)
            h = ps->height - y;
        for (uint32_t row = y; row < y + h; row++) {
            platform_clean(pixels + row * ps->stride + x * 2u, w * 2u);
            platform_clean(alpha + row * ps->alpha_stride + x, w);
        }
    }
    if (!result)
        screen_activity(r);
    service_end(p);
    return result;
}

/* The program gives the screen back and runs on: the stock GUI leaves its
 * hold and owes a full redraw (the checkpoint does it on the GUI's task).
 * What the program drew is cleared first, so the camera's own screen is
 * never mixed with it. screen_claim takes it again. */
static int32_t api_screen_release(uint32_t screen)
{
    const struct nlr_program_services *ps = program_services();
    struct nlr_runtime *r = platform_runtime();
    if (!r || !ps || !ps->scanout_alpha)
        return -NLR_API_ENOSYS;
    if (screen != NLR_SCREEN_REAR)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    int32_t result = 0;
    if (!__atomic_exchange_n(&r->plat.claimed, 0u, __ATOMIC_ACQ_REL)) {
        result = -NLR_API_ENOENT;
    } else {
        uint32_t bytes = ps->alpha_stride * ps->height;
        uint64_t *clear = (uint64_t *)(uintptr_t)r->plat.alpha;
        for (uint32_t n = 0; n < bytes / 8u; n++)
            clear[n] = 0;
        platform_clean((uint8_t *)(uintptr_t)r->plat.alpha, bytes);
        __atomic_store_n(&r->plat.redraw, 1u, __ATOMIC_RELEASE);
        __atomic_store_n(&r->plat.lent, 1u, __ATOMIC_RELEASE);
    }
    nlr_journal(r->load.journal, "screen_release: %d", result);
    service_end(p);
    return result;
}

/* ---- tasks (family A) ---- */

/* A service's own task: a worker whose first event runs the program's
 * function once. Workers are the firmware's task-with-event-flag objects,
 * the same the loader runs on itself; their memory is kernel storage that
 * stays for the boot, as the task does. */
struct platform_task {
    struct nlr_worker worker; /* first: the callback is given its address */
    struct nlr_task_config config;
    void (*fn)(void *);
    void *arg;
    uint32_t started;
    uint32_t index;
};

static void platform_task_run(void *self, uint32_t events)
{
    struct platform_task *t = self;
    (void)events;
    if (!t || __atomic_exchange_n(&t->started, 1u, __ATOMIC_ACQ_REL))
        return;
    /* This task's stack, from here down: the API tells the service's
     * calls from the application's by it (caller_is_service). */
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (r && t->index < NLR_PLATFORM_TASKS) {
        uint64_t here = (uint64_t)(uintptr_t)__builtin_frame_address(0);
        /* The frames above this one are the worker loop's (well under 4
         * KiB); the range stops 4 KiB short of the stack's bottom, so a
         * neighbouring task's stack is never taken for this one. */
        r->plat.task_stack[t->index].lo = here - t->config.stack_bytes + 0x1000u;
        __atomic_store_n(&r->plat.task_stack[t->index].hi, here + 0x400u,
                         __ATOMIC_RELEASE);
    }
    t->fn(t->arg);
}

/* Only code that stays for the boot may become a task: a resident
 * extension's, or a service's during its initialization. A foreground
 * program's block goes back when it ends, and a task still running in it
 * would run in freed memory. */
static int task_code_resident(const struct nlr_runtime *r, uint64_t fn)
{
    const struct nlr_program_state *p = &r->load.program;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 2 &&
        r->load.program_kind == NLR_KIND_RESOURCE_EXTENSION &&
        fn >= (uint64_t)(uintptr_t)p->code_page &&
        fn - (uint64_t)(uintptr_t)p->code_page < p->region_bytes)
        return 1;
    for (uint32_t n = 0; n < NLR_RESIDENT_MAX; n++) {
        const struct nlr_program_record *rec = &r->resident[n];
        if (rec->used && rec->code_block &&
            fn >= (uint64_t)(uintptr_t)rec->code_block &&
            fn - (uint64_t)(uintptr_t)rec->code_block < rec->code_bytes)
            return 1;
    }
    return 0;
}

static int32_t api_task_start(void (*fn)(void *), void *arg,
                              uint32_t stack_bytes, uint32_t priority)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || !nlr_services.worker_init || !nlr_services.worker_start ||
        !nlr_services.flag_set)
        return -NLR_API_ENOSYS;
    /* Kernel stacks come from the camera's own heap: a large one has
     * broken a body before (GYROLOG, 192 KiB), so 64 KiB is the limit. */
    if (!fn || priority > 256u || stack_bytes > (64u << 10))
        return -NLR_API_EINVAL;
    if (!task_code_resident(r, (uint64_t)(uintptr_t)fn))
        return -NLR_API_EACCES;
    if (__atomic_load_n(&r->plat.tasks, __ATOMIC_ACQUIRE) >= NLR_PLATFORM_TASKS)
        return -NLR_API_EBUSY;
    void *memory = platform_alloc((uint32_t)sizeof(struct platform_task) + 8u);
    if (!memory)
        return -NLR_API_EIO;
    struct platform_task *t =
        (struct platform_task *)(((uintptr_t)memory + 7u) & ~(uintptr_t)7u);
    for (uint32_t n = 0; n < sizeof *t; n++)
        ((uint8_t *)t)[n] = 0;
    t->config.core = r->load.task.core;
    t->config.priority = priority ? priority : r->load.task.priority;
    t->config.stack_bytes = stack_bytes < 0x4000u ? 0x4000u : stack_bytes;
    const char name[] = "NLRSVC";
    for (uint32_t n = 0; n < sizeof name; n++)
        t->config.name[n] = name[n];
    t->fn = fn;
    t->arg = arg;
    nlr_services.worker_init(&t->worker, platform_task_run, 1u, &t->config);
    uint32_t task_id = nlr_le32(t->worker.opaque + NLR_WORKER_ID_OFFSET);
    uint32_t flag_id = nlr_le32(t->worker.opaque + NLR_WORKER_FLAG_OFFSET);
    /* worker_init cannot report a failure; ids that cannot be real mean no
     * task came of it. The memory is kept: kernel objects may point in. */
    if (!task_id || task_id > NLR_REGISTRY_IDS || !flag_id ||
        flag_id > NLR_REGISTRY_IDS)
        return -NLR_API_EIO;
    t->index = __atomic_fetch_add(&r->plat.tasks, 1u, __ATOMIC_ACQ_REL);
    nlr_journal(r->load.journal, "task_start: task %u, %u KiB stack, priority %u", task_id,
                stack_bytes >> 10, priority);
    nlr_services.worker_start(&t->worker);
    if (nlr_services.flag_set(t->worker.opaque + NLR_WORKER_FLAG_OFFSET, 1u) != NLR_OK)
        return -NLR_API_EIO;
    return (int32_t)task_id;
}

/* The memory a foreground program declared in its description (NPLD v3
 * `memory=`): taken whole at the first call -- which a program makes as it
 * starts, before the camera's heap is cut up further -- and given back
 * with the rest of its allocations. 0 when it declared none, or when the
 * camera has no block that large (bytes then says 0 too). */
static void *api_mem_reserved(uint32_t *bytes)
{
    struct nlr_runtime *r = platform_runtime();
    if (bytes)
        *bytes = 0;
    if (!r)
        return 0;
    if (!r->plat.reserved && r->load.meta_memory) {
        void *block = api_mem_alloc(r->load.meta_memory, 0);
        if (block) {
            r->plat.reserved = block;
            r->plat.reserved_bytes = r->load.meta_memory;
        }
    }
    if (bytes && r->plat.reserved)
        *bytes = r->plat.reserved_bytes;
    return r->plat.reserved;
}

/* Whether card slot `slot` holds a mounted card (the filesystem's own
 * volume table: a card that is in but not mounted yet, or whose volume is
 * in error, serves no file and counts as absent). */
static int32_t api_card_present(uint32_t slot)
{
    return nlr_platform_card(nlr_services.platform, slot);
}

/* The loader's own card is gone: a file call fails at once with -ENODEV
 * instead of asking the filesystem, which answers a removed card with its
 * own errors only after a while. 0 while the card is there, or when the
 * model does not say. */
static int root_card_gone(void)
{
    int slot = nlr_platform_card_slot(nlr_services.platform, NLR_PROGRAM_ROOT[0]);
    return slot >= 0 && nlr_platform_card(nlr_services.platform, (uint32_t)slot) == 0;
}

static uint32_t api_platform_caps(void)
{
    return nlr_platform_caps(&nlr_services);
}

/* ---- ABI 8 (nlr/platform.h) ---------- */

/* A foreground program's table writes are undone when it ends; a resident
 * extension's stay for the boot (its hooks do too). */
static int named_caller_foreground(const struct nlr_runtime *r)
{
    return __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 2 &&
           r->load.program_kind == NLR_KIND_FOREGROUND;
}

/* The table's bytes as they are now: the RAM or code it lives in, or, for
 * a pointer table, whatever its slot points at -- only ever the stock data
 * or the loader's own copy. 0 when the slot points anywhere else. */
static const volatile uint8_t *table_bytes(const struct nlr_platform_table *t,
                                           const struct nlr_platform *plat,
                                           int index)
{
    if (t->cls != NLR_TABLE_POINTER)
        return (const volatile uint8_t *)(uintptr_t)t->address;
    uint64_t now = __atomic_load_n((const uint64_t *)(uintptr_t)t->address,
                                   __ATOMIC_ACQUIRE);
    if (now == t->stock_pointer)
        return (const volatile uint8_t *)(uintptr_t)now;
    for (uint32_t n = 0; n < NLR_PLATFORM_TABLE_SLOTS; n++)
        if (plat->tables[n].used && plat->tables[n].table == (uint32_t)index &&
            now == (uint64_t)(uintptr_t)plat->tables[n].keep)
            return (const volatile uint8_t *)(uintptr_t)now;
    return 0;
}

static int32_t table_slot(const struct nlr_platform *plat, int index)
{
    for (uint32_t n = 0; n < NLR_PLATFORM_TABLE_SLOTS; n++)
        if (plat->tables[n].used && plat->tables[n].table == (uint32_t)index)
            return (int32_t)n;
    return -1;
}

static int32_t api_named(const char *name, struct nlr_named *out)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!pl || !r)
        return -NLR_API_ENOSYS;
    if (!name || !out)
        return -NLR_API_EINVAL;
    struct nlr_named n = {0};
    int i;
    if ((i = nlr_platform_find_point(pl, name)) >= 0) {
        n.kind = NLR_NAMED_POINT;
        n.size = pl->points[i].args;
    } else if ((i = nlr_platform_find_table(pl, name)) >= 0) {
        const struct nlr_platform_table *t = &pl->tables[i];
        n.kind = NLR_NAMED_TABLE;
        n.flags = t->cls;
        n.size = t->size;
        n.crc = t->crc;
        const volatile uint8_t *bytes = table_bytes(t, &r->plat, i);
        if (t->cls == NLR_TABLE_POINTER
                ? bytes == (const volatile uint8_t *)(uintptr_t)t->stock_pointer
                : bytes && nlr_platform_crc32(bytes, t->size) == t->crc)
            n.flags |= NLR_NAMED_STOCK;
        if (table_slot(&r->plat, i) >= 0)
            n.flags |= NLR_NAMED_CHANGED;
    } else if ((i = nlr_platform_find_function(pl, name)) >= 0) {
        n.kind = NLR_NAMED_FUNCTION;
    } else if ((i = nlr_platform_find_device(pl, name)) >= 0) {
        n.kind = NLR_NAMED_DEVICE;
    } else {
        return -NLR_API_ENOENT;
    }
    *out = n;
    return 0;
}

/* The firmware-code channel by name: the profile has the target and the
 * bytes it must hold, the build put the continuation into the loader, and
 * `original` receives it -- calling it is calling the hooked function. The
 * rules of code_hook hold: the handler lives in this program's image, a
 * foreground program's hooks go when it ends. */
static int32_t api_hook_attach(const char *point, void *handler, void **original)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!pl || !r || !nlr_services.code)
        return -NLR_API_ENOSYS;
    if (!point || !handler)
        return -NLR_API_EINVAL;
    int i = nlr_platform_find_point(pl, point);
    if (i < 0)
        return -NLR_API_ENOENT;
    const struct nlr_platform_point *pt = &pl->points[i];
    uint8_t expect[NLR_CODE_HOOK_BYTES];
    for (uint32_t w = 0; w < 4; w++)
        for (uint32_t b = 0; b < 4; b++)
            expect[4 * w + b] = (uint8_t)(pt->expect[w] >> (8 * b));
    struct nlr_program_state *p = service_begin();
    int result = nlr_code_hook(r, pt->target, expect, (uint64_t)(uintptr_t)handler);
    nlr_journal(r->load.journal, "hook_attach %s: %d", point, result);
    service_end(p);
    if (result == NLR_OK && original)
        *original = (void *)pt->continuation;
    return code_result(result);
}

static int32_t api_hook_detach(const char *point)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!pl || !r || !nlr_services.code)
        return -NLR_API_ENOSYS;
    int i = nlr_platform_find_point(pl, point);
    if (i < 0)
        return -NLR_API_ENOENT;
    struct nlr_program_state *p = service_begin();
    int result = nlr_code_unhook(r, pl->points[i].target);
    nlr_journal(r->load.journal, "hook_detach %s: %d", point, result);
    service_end(p);
    return result == NLR_FORMAT ? -NLR_API_ENOENT : code_result(result);
}

static int32_t api_table_read(const char *name, uint32_t offset, void *dst, uint32_t len)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!pl || !r)
        return -NLR_API_ENOSYS;
    int i = nlr_platform_find_table(pl, name);
    if (i < 0)
        return -NLR_API_ENOENT;
    const struct nlr_platform_table *t = &pl->tables[i];
    if (!dst || offset > t->size || len > t->size - offset)
        return -NLR_API_EINVAL;
    const volatile uint8_t *bytes = table_bytes(t, &r->plat, i);
    if (!bytes)
        return -NLR_API_EBUSY; /* the slot points somewhere the loader did not */
    for (uint32_t n = 0; n < len; n++)
        ((uint8_t *)dst)[n] = bytes[offset + n];
    return 0;
}

/* Bytes into a table of the code window: whole words, through the alias,
 * a cache line at a time (code_patch's own rules). */
static int table_text_write(uint64_t at, const uint8_t *src, uint32_t len)
{
    while (len) {
        uint64_t word = at & ~3ull;
        uint64_t line_end = (at | 63u) + 1u;
        uint32_t chunk = (uint32_t)(line_end - at < len ? line_end - at : len);
        uint32_t span = (uint32_t)(((at + chunk + 3u) & ~3ull) - word);
        uint8_t buf[64];
        for (uint32_t n = 0; n < span; n++)
            buf[n] = ((const volatile uint8_t *)(uintptr_t)word)[n];
        for (uint32_t n = 0; n < chunk; n++)
            buf[at - word + n] = src[n];
        int result = nlr_code_patch(nlr_services.code, word, buf, span);
        if (result != NLR_OK)
            return result;
        at += chunk;
        src += chunk;
        len -= chunk;
    }
    return NLR_OK;
}

/* The first write to a table keeps its stock bytes (refusing a table that
 * no longer holds them: another program changed it, or this is not the
 * firmware the profile describes); later writes by the same kind of owner
 * add to it. A pointer table gets a RAM copy of its data, and its slot is
 * pointed at the copy. */
static int32_t api_table_write(const char *name, uint32_t offset, const void *src,
                               uint32_t len)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!pl || !r)
        return -NLR_API_ENOSYS;
    int i = nlr_platform_find_table(pl, name);
    if (i < 0)
        return -NLR_API_ENOENT;
    const struct nlr_platform_table *t = &pl->tables[i];
    if (t->cls == NLR_TABLE_REPACK)
        return -NLR_API_EACCES;
    if (t->cls == NLR_TABLE_TEXT && !nlr_services.code)
        return -NLR_API_ENOSYS;
    if (!src || offset > t->size || len > t->size - offset ||
        t->size > NLR_PLATFORM_TABLE_MAX)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    struct nlr_platform *plat = &r->plat;
    int foreground = named_caller_foreground(r);
    int32_t slot = table_slot(plat, i), result = 0;
    if (slot >= 0 && (int)plat->tables[slot].foreground != foreground) {
        result = -NLR_API_EBUSY;
    } else if (slot < 0) {
        /* A pointer table restored earlier left its copy parked in its
         * slot (the camera may still have been reading it): use it again. */
        for (uint32_t n = 0; n < NLR_PLATFORM_TABLE_SLOTS && slot < 0; n++)
            if (!plat->tables[n].used && plat->tables[n].request &&
                plat->tables[n].table == (uint32_t)i)
                slot = (int32_t)n;
        for (uint32_t n = 0; n < NLR_PLATFORM_TABLE_SLOTS && slot < 0; n++)
            if (!plat->tables[n].used && !plat->tables[n].request)
                slot = (int32_t)n;
        const volatile uint8_t *now = table_bytes(t, plat, i);
        if (slot < 0) {
            result = -NLR_API_EBUSY;
        } else if (!now || nlr_platform_crc32(now, t->size) != t->crc) {
            result = -NLR_API_EBUSY;
        } else {
            void *request = plat->tables[slot].request;
            if (!request)
                request = platform_alloc(t->size + 64u);
            uint8_t *keep = request
                ? (uint8_t *)(((uintptr_t)request + 63u) & ~(uintptr_t)63u) : 0;
            if (!keep) {
                result = -NLR_API_EIO;
            } else {
                for (uint32_t n = 0; n < t->size; n++)
                    keep[n] = now[n];
                plat->tables[slot].table = (uint32_t)i;
                plat->tables[slot].foreground = (uint32_t)foreground;
                plat->tables[slot].bytes = t->size;
                plat->tables[slot].keep = keep;
                plat->tables[slot].request = request;
                __atomic_store_n(&plat->tables[slot].used, 1u, __ATOMIC_RELEASE);
            }
        }
    }
    if (!result && t->cls == NLR_TABLE_POINTER) {
        uint8_t *copy = plat->tables[slot].keep;
        for (uint32_t n = 0; n < len; n++)
            copy[offset + n] = ((const uint8_t *)src)[n];
        __atomic_store_n((uint64_t *)(uintptr_t)t->address,
                         (uint64_t)(uintptr_t)copy, __ATOMIC_RELEASE);
    } else if (!result && t->cls == NLR_TABLE_TEXT) {
        result = code_result(table_text_write(t->address + offset, src, len));
    } else if (!result) {
        volatile uint8_t *at = (volatile uint8_t *)(uintptr_t)t->address;
        for (uint32_t n = 0; n < len; n++)
            at[offset + n] = ((const uint8_t *)src)[n];
    }
    nlr_journal(r->load.journal, "table_write %s +%u (%u bytes): %d", name, offset, len, result);
    service_end(p);
    return result;
}

/* Put a table back as it was before this boot's first write. A pointer
 * table's slot goes back to the stock data; the copy stays allocated (the
 * camera may still be reading it) and is reused by the next write. */
static int table_put_back(struct nlr_platform *plat, uint32_t slot)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    const struct nlr_platform_table *t = &pl->tables[plat->tables[slot].table];
    if (t->cls == NLR_TABLE_POINTER) {
        __atomic_store_n((uint64_t *)(uintptr_t)t->address, t->stock_pointer,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&plat->tables[slot].used, 0u, __ATOMIC_RELEASE);
        return NLR_OK;
    }
    int result = NLR_OK;
    if (t->cls == NLR_TABLE_TEXT)
        result = table_text_write(t->address, plat->tables[slot].keep, t->size);
    else
        for (uint32_t n = 0; n < t->size; n++)
            ((volatile uint8_t *)(uintptr_t)t->address)[n] = plat->tables[slot].keep[n];
    if (result != NLR_OK)
        return result;
    __atomic_store_n(&plat->tables[slot].used, 0u, __ATOMIC_RELEASE);
    if (nlr_services.release(plat->tables[slot].request) == NLR_OK)
        plat->tables[slot].request = 0;
    plat->tables[slot].keep = 0;
    return NLR_OK;
}

static int32_t api_table_restore(const char *name)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!pl || !r)
        return -NLR_API_ENOSYS;
    int i = nlr_platform_find_table(pl, name);
    if (i < 0)
        return -NLR_API_ENOENT;
    int32_t slot = table_slot(&r->plat, i);
    if (slot < 0)
        return -NLR_API_ENOENT;
    if ((int)r->plat.tables[slot].foreground != named_caller_foreground(r))
        return -NLR_API_EBUSY;
    struct nlr_program_state *p = service_begin();
    int result = table_put_back(&r->plat, (uint32_t)slot);
    service_end(p);
    return code_result(result);
}

/* A foreground program's table writes end with it. */
static void named_release(struct nlr_runtime *r)
{
    if (!nlr_services.platform)
        return;
    for (uint32_t n = 0; n < NLR_PLATFORM_TABLE_SLOTS; n++)
        if (r->plat.tables[n].used && r->plat.tables[n].foreground)
            (void)table_put_back(&r->plat, n);
}

static void *api_fw_fn(const char *name)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    int i = nlr_platform_find_function(pl, name);
    return i < 0 ? 0 : pl->functions[i].address;
}

/* One transfer with a device by name: the profile has its bus, address and
 * the client the loader attaches as -- never a client the camera uses
 * itself, whose task would be left waiting. */
static int32_t api_bus_i2c(const char *device, const void *tx, uint32_t txlen,
                           void *rx, uint32_t rxlen)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    if (!pl || !pl->i2c_transfer)
        return -NLR_API_ENOSYS;
    int i = nlr_platform_find_device(pl, device);
    if (i < 0)
        return -NLR_API_ENOENT;
    if ((txlen && !tx) || (rxlen && !rx) || (!txlen && !rxlen) ||
        txlen > 256u || rxlen > 4096u)
        return -NLR_API_EINVAL;
    struct nlr_program_state *p = service_begin();
    const struct nlr_platform_device *d = &pl->devices[i];
    int32_t result = pl->i2c_transfer(d->bank, d->client, d->address, tx, txlen, rx, rxlen);
    service_end(p);
    return result ? -NLR_API_EIO : 0;
}

/* Post an event to the running program's queue from any task -- a hook
 * handler on the firmware's task, a service's task. queue_wait reports it
 * as NLR_EV_POSTED with the code and value given (type and time are set
 * here). Nothing else is done on the caller's task. */
static int32_t api_queue_post(const struct nlr_event *ev)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r)
        return -NLR_API_ENOSYS;
    if (!ev)
        return -NLR_API_EINVAL;
    struct nlr_event post = *ev;
    post.type = NLR_EV_POSTED;
    post.t_ms = nlr_clock_ms();
    return nlr_platform_post(&r->plat, &post);
}

/* Field order and types are the cross-language ABI contract (appendix B);
 * sdk/nlr.h must stay byte-identical. */
const struct nlr_api nlr_api = {
    .abi = NLR_ABI_VERSION,
    .mem_alloc = api_mem_alloc,
    .mem_free = api_mem_free,
    .fs_open = api_fs_open,
    .fs_read = api_fs_read,
    .fs_seek = api_fs_seek,
    .fs_close = api_fs_close,
    .ui_draw_text = api_ui_draw_text,
    .ui_present = api_ui_present,
    .gfx_begin = api_gfx_begin,
    .gfx_end = api_gfx_end,
    .input_poll = api_input_poll,
    .input_raw = api_input_raw,
    .log = api_log,
    .exit = api_exit,
    .menu_register = api_menu_register,
    .time_ms = api_time_ms,
    .sleep_ms = api_sleep_ms,
    .fs_dir = api_fs_dir,
    .ui_list = api_ui_list,
    .ui_rows = api_ui_rows,
    .ui_input = api_ui_input,
    .ui_caution = api_ui_caution,
    .setting = api_setting,
    .fs_write = api_fs_write,
    .code_patch = api_code_patch,
    .code_hook = api_code_hook,
    .code_unhook = api_code_unhook,
    .queue_wait = api_queue_wait,
    .timer_start = api_timer_start,
    .timer_stop = api_timer_stop,
    .input_route = api_input_route,
    .input_held = api_input_held,
    .screen_claim = api_screen_claim,
    .screen_present = api_screen_present,
    .screen_release = api_screen_release,
    .prop_get = api_prop_get,
    .prop_info = api_prop_info,
    .prop_watch = api_prop_watch,
    .prop_set = api_prop_set,
    .task_start = api_task_start,
    .mem_reserved = api_mem_reserved,
    .card_present = api_card_present,
    .platform_caps = api_platform_caps,
    .named = api_named,
    .hook_attach = api_hook_attach,
    .hook_detach = api_hook_detach,
    .table_read = api_table_read,
    .table_write = api_table_write,
    .table_restore = api_table_restore,
    .fw_fn = api_fw_fn,
    .bus_i2c = api_bus_i2c,
    .queue_post = api_queue_post,
    .fs_dir_names = api_fs_dir_names,
};
