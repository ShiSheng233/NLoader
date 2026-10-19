#ifndef NLR_SERVICES_H
#define NLR_SERVICES_H

#include <stddef.h>
#include <stdint.h>

/* Result codes shared by the load and runtime layers. A failed check returns
 * its cause immediately; the ASCII stage kept in the loader records where. */
enum {
    NLR_OK = 0,
    NLR_IO = -1,
    NLR_FORMAT = -2,
    NLR_BOUNDS = -3,
    NLR_CHECKSUM = -4,
    NLR_NOT_READY = -5,
    NLR_BUSY = -6,
    /* Construction failed AFTER worker_init, so a firmware task and an event
     * flag may exist and reference our memory. Distinct from NOT_READY because
     * only this case must not be unwound. */
    NLR_PARTIAL = -7,
    /* The card's SAFE_MODE flag is present: loading is disabled for this
     * boot (PLAN 4.4). The check is the first card operation. */
    NLR_DISABLED = -8,
    /* The directory gate refused the selected program (PLAN 4.3 GATE), so
     * its file was never opened. */
    NLR_REFUSED = -9,
};

/* Worker service family object layout. The profile selects the family; these
 * offsets belong to the family contract, the firmware writes them, and core
 * code must read them only through these names. They are not addresses. */
#define NLR_WORKER_SIZE            0x58
#define NLR_WORKER_ID_OFFSET       0x00 /* u32: registry id of the task object */
#define NLR_WORKER_NAME_OFFSET     0x1d /* NLR_TASK_NAME_SIZE bytes, from config */
#define NLR_WORKER_SELF_OFFSET     0x28 /* u64: starter stores the object pointer */
#define NLR_WORKER_FLAG_OFFSET     0x38 /* u32: registry id of the event flag */
#define NLR_WORKER_CALLBACK_OFFSET 0x48 /* u64: callback stored by worker_init */
#define NLR_TASK_NAME_SIZE         8
#define NLR_REGISTRY_TYPE_TASK     0u
#define NLR_REGISTRY_IDS           0x300u /* inclusive upper bound of the scan */
#define NLR_TASK_CORE_MAX          3u

struct nlr_worker {
    _Alignas(8) uint8_t opaque[NLR_WORKER_SIZE];
};

/* Task description consumed by worker_init; the layout is part of the family
 * contract, and the firmware writes assigned_id back. */
struct nlr_task_config {
    uint32_t core;
    uint32_t priority;
    uint32_t stack_bytes;
    uint8_t option; /* family-defined; keep zero */
    char name[NLR_TASK_NAME_SIZE];
    uint8_t padding[3];
    uint16_t assigned_id;
    uint16_t reserved;
};
_Static_assert(sizeof(struct nlr_task_config) == 0x1c, "task config ABI");
_Static_assert(offsetof(struct nlr_task_config, name) == 0xd, "name ABI");
_Static_assert(offsetof(struct nlr_task_config, assigned_id) == 0x18, "id ABI");

struct nlr_resource_services;
struct nlr_native_card_services;
struct nlr_bitmap_services;
struct nlr_dirent;
struct nlr_program_services;
struct nlr_input_services;
struct nlr_code_services;
struct nlr_platform_services;

/* Optional verified time provider. clock_ms writes boot-relative monotonic
 * milliseconds only on success. delay_ms accepts 1..10 native millisecond
 * ticks and preserves native failure instead of assuming it waited. */
struct nlr_time_services {
    int32_t (*clock_ms)(uint64_t *out);
    int32_t (*delay_ms)(uint32_t ms);
};

/* Optional, verified foreground-stop services. Successful suspend freezes
 * the worker before core inspects SDK ownership; successful terminate proves
 * its old frames cannot run again. restart activates the same task wrapper,
 * not the abandoned entry/context. Every operation returns 0 on success.
 * Combined input banks are u32[5] current/previous/changed/pressed/released,
 * starting at byte 8 + bank * 20. mask is the complete MENU+DELETE chord. */
struct nlr_exit_services {
    void (**input_callback)(void *);
    uint32_t bank;
    uint32_t mask;
    int32_t (*suspend)(void *worker);
    int32_t (*resume)(void *worker);
    int32_t (*terminate)(void *worker);
    int32_t (*restart)(void *worker);
    /* Genuine MENU release may notify the GUI of an accepted exit while SDK
     * draining continues. Profile-owned single bit, subset of mask; zero
     * disables this optional notification without fabricating input. */
    uint32_t release_mask;
    /* Generic native no-key event; it is never physical release evidence. */
    uint32_t menu_release_code;
};

/* Firmware services, injected by the per-model bindings object. Core code
 * never holds firmware addresses; every model difference lives in the
 * bindings and the adapters behind these pointers. File calls are normalized:
 * 0 means success, a negative file_open result means failure. */
struct nlr_services {
    uint32_t abi;
    /* Kernel storage for loader state and the program arena. Core code never
     * assumes zeroed memory; alloc must return at least 8-byte aligned
     * storage because the worker family checks object alignment. */
    int32_t (*alloc)(uint32_t bytes, void **out);
    int32_t (*release)(void *ptr);
    /* Worker/event-flag family: worker_init builds the flag at
     * worker+0x38, stores the callback and mask, and creates the task with
     * the given config; worker_start lets it run. flag_set takes the flag
     * OBJECT pointer (worker+0x38), not a registry id: both studied builds
     * keep the flag object in place inside the worker, and the stock set
     * entry consumes that pointer directly. */
    void (*worker_init)(void *worker, void (*callback)(void *self, uint32_t events),
                        uint32_t mask, struct nlr_task_config *config);
    void (*worker_start)(void *worker);
    int32_t (*flag_set)(void *flag, uint32_t mask);
    /* Card file access. whence 0 = set, 2 = end; out_position is absolute.
     * file_open flags/mode carry no cross-model meaning here: this core
     * passes 0,0 for a plain read, and the model adapter maps that onto the
     * firmware's own conventions (the Z6III PoC needed 0x20 there). */
    int32_t (*file_open)(const char *path, uint32_t flags, uint32_t mode);
    int32_t (*file_read)(int32_t fd, void *buf, uint32_t bytes, uint32_t *out_read);
    int32_t (*file_seek)(int32_t fd, int32_t whence, uint32_t offset,
                         uint32_t *out_position);
    int32_t (*file_close)(int32_t fd);
    /* Write to an open file; only a program's settings file is ever
     * written, in place, opened with file_open_rw (the firmware's flags for
     * an existing file read and written, nothing created or truncated). */
    int32_t (*file_write)(int32_t fd, const void *buf, uint32_t bytes,
                          uint32_t *out_written);
    uint32_t file_open_rw;
    /* The firmware's own flags for "write this file, create it when it is
     * missing, truncate it when it is not", and the attribute word a
     * created file gets. Zero flags mean the model has no checked create
     * path: every write access is then refused (-ENOSYS), and the card
     * store that keeps the loader's own state stays unavailable. */
    uint32_t file_open_write;
    uint32_t file_create_attributes;
    /* D-cache maintenance around bulk card reads. The pre-read call
     * invalidates whole NLR_CACHE_LINE lines, rounding the start down and
     * the end up, so it may only be given ranges of a buffer that starts on
     * a line and owns whole lines; otherwise bytes of whatever shares the
     * first or last line are discarded with it. */
    void (*cache_before_read)(void *addr, uint32_t len);
    void (*cache_after_read)(void *addr, uint32_t len);
    /* Clean to the point of coherency: the entry that writes bytes back
     * out of the data cache for another master about to read them — the
     * card's DMA behind a file write, instruction fetch after a code
     * patch. It is declared apart from the maintenance a read ends with
     * because on another model that one may discard lines rather than
     * write them back, and would lose the write without a word. Null when
     * the profile has not named it; the paths that need it then refuse
     * instead of writing. */
    void (*cache_clean)(void *addr, uint32_t len);
    /* Firmware task registry: object of (type, id), or NULL. The lookup owns
     * bounds checks and clears *out before scanning. */
    void (*registry_lookup)(uint32_t type, uint32_t id, void **out);
    /* Menu-task publication of worker-recorded RAM resource requests. */
    const struct nlr_resource_services *resources;
    /* Absent on production profiles without independently verified pins. */
    const struct nlr_exit_services *exit;
    const struct nlr_native_card_services *native_card;
    const struct nlr_bitmap_services *bitmap;
    const struct nlr_time_services *time;
    const struct nlr_input_services *input;
    /* Optional native menu delay and ABI 4 directory/screen services. */
    void (*sleep_ms)(uint32_t ms);
    const struct nlr_program_services *program;
    /* ABI 4 firmware-code channel; absent leaves its API calls at
     * -ENOSYS. */
    const struct nlr_code_services *code;
    /* ABI 7 (nlr/platform.h): every control, the dials, the settings
     * store; absent leaves those calls at -ENOSYS. */
    const struct nlr_platform_services *platform;
    /* The loader's own log file (nlr/journal.h), a whole card path; null
     * keeps the log in RAM only. */
    const char *journal_path;
};

/* The one way core takes a block from the camera's heap (core/exec.c):
 * granted whole where the model's heap books can be read (the executor's
 * discipline, nlr_exec_grant_alloc: a heap with books may answer with a
 * smaller node and still map the whole span), else the allocator taken at
 * its word. The block goes back with services->release. Null, with nothing
 * held, when the block cannot be had. No other core code calls
 * services->alloc (tests/check_core_alloc.sh). */
void *nlr_alloc_whole(const struct nlr_services *services, uint32_t bytes);

/* The firmware's own code, as the ABI 4 channel changes it. The camera's
 * text runs from DRAM and the mapping service keeps a writable alias of
 * those physical pages, so core never changes a live code page's
 * permissions: it translates the code address, writes through the alias and
 * then does the cache maintenance. Everything here is the profile's. */
struct nlr_code_services {
    /* The code a program may patch, and the alias band its pages must
     * translate into. Both are closed ranges [lo, hi) of runtime
     * addresses; a target outside the first or a translation outside the
     * second is refused. */
    uint64_t text_lo;
    uint64_t text_hi;
    uint64_t alias_lo;
    uint64_t alias_hi;
    /* The mapping manager the translate service takes, and the services
     * themselves: virtual to physical, the permission encoding of a
     * mapped address, and whether an address is cacheable memory. */
    const volatile void *manager;
    int32_t (*translate)(const volatile void *manager, uintptr_t address,
                         uint64_t *out_physical);
    int32_t (*query)(void *address, uint32_t *out_flags);
    uint32_t (*cacheable)(void *address);
    /* Clean the data cache to the point of coherency, and invalidate the
     * instruction cache; the second is broadcast to every core. */
    void (*clean)(void *address, uint32_t bytes);
    void (*invalidate)(void *address, uint64_t bytes);
    /* The permission encodings query reports for the writable alias and
     * for the executable code mapping. */
    uint32_t flag_writable;
    uint32_t flag_executable;
    /* Nonzero when this body runs with SCTLR_EL1.A clear, so a doubleword
     * load from a 4-byte-aligned address is legal. A hook's detour reads
     * the handler's address out of its own last eight bytes; without this
     * only an 8-byte-aligned target can be hooked. The profile declares
     * it: the register says nothing about the moment the hook is taken,
     * and is unreadable where the host tests run. */
    uint32_t unaligned_literals;
};

/* Firmware pieces behind the ABI 4 program API: directory enumeration,
 * the buttons, the screen. Layouts and codes are the profile's; core only
 * follows them. */
struct nlr_program_key {
    uint32_t bank;              /* which input bank holds the button */
    uint32_t mask;              /* its bit in that bank's words */
};
#define NLR_PROGRAM_KEYS 15u    /* one per NLR_KEY_* bit, in bit order */
struct nlr_program_services {
    /* Directory enumeration: the firmware calls `each` once per entry with
     * its file-information record, on the filesystem's own task; `each`
     * returns 0 to go on and 1 to stop. An early-stop result is accepted
     * only after the requested record was filled; `enum_done` means the
     * directory ran out. Other results without a record are errors. */
    uint32_t (*fs_enum)(const char *dir, uint32_t mask,
                        uint32_t (*each)(const uint8_t *info));
    uint32_t enum_done;
    uint32_t mask_directories;  /* enumeration masks: directories, files */
    uint32_t mask_files;
    uint32_t attr_directory;    /* the directory bit of the attribute byte */
    uint16_t info_short;        /* record offsets: 8.3 name (8-bit), long
                                 * name (empty when the 8.3 name is the
                                 * whole name), attribute byte, 64-bit size */
    uint16_t info_long;
    uint16_t info_attr;
    uint16_t info_size;
    uint16_t info_long_unit;    /* bytes a long-name character: 2 is
                                 * UTF-16LE, anything else 8-bit */
    /* The input task's per-scan callback slot, its stock occupant (chained
     * after us), and the scan object's layout: u32[5] banks of current,
     * previous, changed, pressed, released words. */
    void (**input_slot)(void *);
    void (*input_original)(void *);
    /* The scan object the callback is given, for the one reader that has
     * no callback to wait for: the autoload escape, which asks what is
     * held right now. Null leaves that escape unavailable. */
    void *input_object;
    uint32_t bank_base;
    uint32_t bank_stride;
    uint32_t banks;
    uint32_t keep_bank;         /* bits never hidden from the camera (the */
    uint32_t keep_mask;         /* power switch) */
    uint32_t dial_offset;       /* per-scan dial deltas, hidden as well */
    uint32_t dial_bytes;
    struct nlr_program_key keys[NLR_PROGRAM_KEYS];
    /* The rear screen's scanout: the display controller's address registers
     * for the GUI's plane, colour and alpha, each a low word then a high
     * word of which `scanout_high_mask` carries address bits 32 up. They
     * hold bus addresses, `bus_offset` above the CPU's, and name the buffer
     * being shown; it must lie whole inside [plane_lo, plane_hi). */
    const volatile uint32_t *scanout_colour;
    const volatile uint32_t *scanout_alpha;
    uint32_t scanout_high_mask;
    uint64_t bus_offset;
    uint64_t plane_lo;
    uint64_t plane_hi;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t alpha_stride;
    void (*activity)(void);     /* user activity: holds off auto power-off */
};

#define NLR_SEEK_SET 0
#define NLR_SEEK_END 2

/* Data-cache line the maintenance services step through. The allocator
 * promises only 8-byte alignment, so card buffers are placed on a line inside
 * a padded allocation (see nlr_cache_lines). */
#define NLR_CACHE_LINE 64u

/* Bytes of whole lines covering n bytes; n must not exceed
 * UINT32_MAX - NLR_CACHE_LINE + 1. */
static inline uint32_t nlr_cache_lines(uint32_t n)
{
    return (n + NLR_CACHE_LINE - 1u) & ~(NLR_CACHE_LINE - 1u);
}

static inline int nlr_cache_aligned(const void *buffer, uint32_t capacity)
{
    return !((uintptr_t)buffer & (NLR_CACHE_LINE - 1u)) &&
           !(capacity & (NLR_CACHE_LINE - 1u));
}

/* Little-endian readers for on-card headers and firmware-written fields. */
static inline uint32_t nlr_le16(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8;
}

static inline uint32_t nlr_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

/* The boot checkpoint's stock call (profile [boot_hooks.autoload]). The
 * build points the branch-with-link at call_site to
 * nlr_boot_autoload_checkpoint (core/boot_autoload.c), which makes this
 * call itself and returns its result unchanged. Generated only where the
 * profile declares it. */
struct nlr_boot_autoload {
    uintptr_t call_site; /* informational; the builder checks and installs it */
    void *(*callee)(void);
};
extern const struct nlr_boot_autoload nlr_boot_autoload;
void *nlr_boot_autoload_checkpoint(void);

#endif
