#ifndef NLR_NATIVE_CARD_H
#define NLR_NATIVE_CARD_H

#include "nlr/card_state.h"

/* Profile-owned, independently checked native layout. Runtime addresses and
 * function pointers are injected; these structures contain no camera pins.
 * The same layout serves every slot: the loader's root names the volume,
 * the volume names its media entry, and the media entry names its stock
 * slot. NLoader counts real mount/unmount observations separately; the card
 * is the same while that count, the volume index and the media entry stay
 * the same. */
struct nlr_native_card_layout {
    uintptr_t runtime_ram_start;
    uintptr_t runtime_ram_end;
    const uint8_t *volume_table;
    uint32_t volume_count;
    uint32_t volume_stride;
    uint32_t volume_device_offset;
    uint32_t volume_name_offset;
    uint32_t volume_state_offset;
    uint32_t volume_type_offset;
    uint32_t volume_sector_bytes_offset;
    uint32_t volume_cluster_sectors_offset;
    uint32_t volume_sector_shift_offset;
    uint32_t volume_cluster_shift_offset;
    uint32_t volume_cluster_heap_offset;
    uint32_t exfat_type;
    const uint8_t *media_table;
    uint32_t media_count;
    uint32_t media_stride;
    uint32_t media_slot_offset;
    /* Stock storage slots, one per card slot. A media entry's slot field
     * indexes them, and so does the stock per-slot flush. */
    uint32_t slot_count;
    uint32_t stat_size_offset;
    uint32_t stat_attributes_offset;
    const uint8_t *fcb_table;
    uint32_t fcb_volume_count;
    uint32_t fcb_slot_count;
    uint32_t fcb_volume_stride;
    uint32_t fcb_slot_stride;
    uint32_t fcb_flags_offset;
    uint32_t fcb_ready_mask;
    uint32_t fcb_reject_mask;
    uint32_t fcb_valid_size_offset;
    uint32_t fcb_data_size_offset;
    uint32_t fcb_first_cluster_offset;
    uint32_t fcb_last_cluster_offset;
    uint32_t fcb_no_fat_chain_offset;
};

struct nlr_native_card_mount {
    uintptr_t call_site; /* informational; builder installs the checked hook */
    int32_t (*callee)(const char *volume, void *device, void *parameters);
};
struct nlr_native_card_unmount {
    uintptr_t call_site;
    int32_t (*callee)(const char *volume);
};

struct nlr_native_card_menu {
    uintptr_t call_site;
    void *(*callee)(void); /* original menu flag-reference getter */
    uint32_t wake_mask; /* accepted, non-dispatched bit proved by loop bytes */
    uint32_t target_context_offset; /* publishing waits for target context=0 */
    /* Optional GUI owner route. Absent pins refuse deferred MENU replay;
     * window/firmware addresses are generated from checked profile data. */
    void (*dispatch)(uint32_t event, uint8_t *out);
    void *(*current_window)(void);
    const void *loader_window;
    const volatile uint32_t *gui_state;
    uint32_t menu_press_code;
};

struct nlr_native_card_rpc {
    uintptr_t wait_call_site;
    int32_t (*wait_callee)(void *flag, uint32_t mask, uint32_t *out_bits);
    const void *reply_flag;
    const uint8_t *shared_frame;
};

struct nlr_native_card_services {
    int32_t (*claim)(void (*callback)(void *request));
    /* This is the native submit function, not its temporary-frame wrapper.
     * Entire native frame and user data must remain heap-owned until an
     * unambiguous real reply; timeout never frees/reuses either object. */
    int32_t (*submit_frame)(void *owned_native_frame);
    uintptr_t submit_wrapper; /* ABI evidence only, never called */
    void (*const *callback_table)(void *request);
    uintptr_t dispatcher; /* independent dispatch evidence */
    const void *dispatch_table;
    uint32_t callback_slot;
    uint32_t request_bytes;
    uint32_t request_volume_offset;
    uint32_t request_user_offset;
    uint32_t request_callback_offset;
    uint32_t request_operation_offset;
    uint32_t request_result_offset;
    uint32_t request_priority_offset;
    uint32_t operation;
    void *mutex;
    /* Original APIs are void. Their arbitrary W0 is not a success code. */
    void (*lock)(void *mutex);
    void (*unlock)(void *mutex);
    /* Called only within one FILESRV callback holding the native FS mutex;
     * these are direct low-library calls and may not submit another RPC. */
    int32_t (*open)(const char *path, uint32_t flags, uint32_t mode);
    int32_t (*read)(int32_t fd, void *data, uint32_t bytes, uint32_t *read);
    int32_t (*write)(int32_t fd, const void *data, uint32_t bytes, uint32_t *written);
    uint32_t (*seek)(int32_t fd, int32_t offset, int32_t whence);
    int32_t (*close)(int32_t fd);
    int32_t (*stat)(const char *path, void *stat_data);
    uint32_t stat_bytes;
    uint32_t not_found; /* only this exact full reason establishes absence */
    uint32_t write_flags;
    uint32_t create_flags; /* initialization only; never a normal slot write */
    /* Existing STATE only: the native read-only fast path does not initialize
     * the complete FCB extent witness. This mode neither creates nor truncates. */
    uint32_t journal_read_flags;
    uint32_t file_mode;
    int32_t (*volume_sync)(const char *volume);
    int32_t (*volume_index)(const char *volume);
    int32_t (*volume_ready)(int32_t index);
    int32_t (*fcb_get)(int32_t volume, int32_t slot, void **out);
    /* The stock per-slot flush that the filesystem service itself calls
     * after a write: the slot table's flush entry, which is the device
     * flush where the slot's driver has one and success where stock has
     * none. Its answer is kept as the native reason. */
    int32_t (*slot_flush)(uint32_t slot);
    void (*clean_source)(void *data, uint32_t bytes);
    void (*volume_lock)(void);
    void (*volume_unlock)(void);
    int32_t (*low_unmount)(const char *volume);
    struct nlr_native_card_rpc rpc;
    struct nlr_native_card_layout layout;
    struct nlr_native_card_mount mount;
    struct nlr_native_card_unmount unmount;
    struct nlr_native_card_menu menu;
};

/* The native low-level seek's third whence beside NLR_SEEK_SET and
 * NLR_SEEK_END: from the current position. The answer is the new absolute
 * position, or UINT32_MAX when the seek was refused. */
#define NLR_NATIVE_CARD_SEEK_CUR 1

/* A card read never asks the low-level read to start inside one of these:
 * it starts at the file position rounded down to this unit, a multiple of
 * every exFAT sector size (512 to 4096 bytes), and hands back only the
 * bytes asked for. */
#define NLR_NATIVE_CARD_READ_ALIGN 4096u

#define NLR_NATIVE_CARD_FRAME_BYTES 0x118u
#define NLR_NATIVE_CARD_PATH_BYTES 129u
#define NLR_NATIVE_CARD_STAT_BYTES 0x220u

enum {
    NLR_NATIVE_CARD_REQUEST_IDLE = 0,
    NLR_NATIVE_CARD_REQUEST_QUEUED,
    NLR_NATIVE_CARD_REQUEST_RUNNING,
    NLR_NATIVE_CARD_REQUEST_DONE,
    NLR_NATIVE_CARD_REQUEST_UNCERTAIN,
};
enum {
    NLR_NATIVE_CARD_SNAPSHOT = 0,
    NLR_NATIVE_CARD_COMMIT,
    NLR_NATIVE_CARD_PROBE,
    NLR_NATIVE_CARD_OPEN,
    NLR_NATIVE_CARD_READ,
    NLR_NATIVE_CARD_SEEK,
    NLR_NATIVE_CARD_CLOSE,
    NLR_NATIVE_CARD_WRITE,
};

/* One identity rule for every slot: the mount epoch NLoader observed, the
 * volume the root names and the media entry that volume is bound to. The
 * slot is read from that media entry; it selects the stock flush. */
struct nlr_native_card_owner {
    uint64_t epoch; /* NLoader observations; never a stock MediaId/counter */
    uint32_t volume_index;
    uint32_t slot;
    uintptr_t device;
};

/* Every member including the native transport frame and all callback data
 * lives in one retained heap allocation with explicit 64-byte padding/alignment.
 * No callback holds a caller stack buffer or a pointer to a temporary wrapper.
 * Production uses only real FILESRV and IO replies to populate this object. */
struct nlr_native_card_request {
    _Alignas(NLR_CACHE_LINE) uint8_t native_frame[NLR_NATIVE_CARD_FRAME_BYTES];
    uint32_t magic;
    uint32_t version;
    uint32_t bytes;
    uint32_t state; /* atomic handoff */
    uint32_t operation;
    uint32_t purpose;
    uint64_t sequence;
    int32_t result;
    int32_t native_submit_result;
    uint32_t native_reply_bits; /* observed original wait output, never injected */
    uint64_t native_reason;
    struct nlr_native_card_owner owner;
    char volume[3];
    char path[NLR_NATIVE_CARD_PATH_BYTES];
    int32_t fd;
    /* OPEN only: 0 reads; otherwise exactly the declared write_flags
     * (overwrite in place) or create_flags (create or truncate). */
    uint32_t open_flags;
    int32_t offset;
    int32_t whence;
    uint32_t count;
    uint32_t transferred;
    /* READ only: where the delivered bytes start in data (the read began at
     * the aligned position below the file position), and whether the
     * low-level read answered short (the end of the file). */
    uint32_t data_offset;
    uint32_t at_end;
    uint32_t present;
    uint32_t file_bytes;
    uint32_t journal_present;
    struct nlr_card_state_selection selection;
    struct nlr_card_state desired;
    struct nlr_card_state_commit commit;
    struct nlr_manifest manifest;
    struct nlr_enabled legacy;
    _Alignas(NLR_CACHE_LINE) uint8_t data[NLR_CARD_STATE_FILE_BYTES];
    _Alignas(NLR_CACHE_LINE) uint8_t candidate[NLR_CARD_STATE_SLOT_BYTES];
    _Alignas(NLR_CACHE_LINE) uint8_t readback[NLR_CARD_STATE_SLOT_BYTES];
    _Alignas(NLR_CACHE_LINE) uint8_t stat_data[NLR_NATIVE_CARD_STAT_BYTES];
    _Alignas(NLR_CACHE_LINE) uint8_t legacy_data[NLR_ENABLED_BYTES];
};

struct nlr_native_card_runtime;
struct nlr_runtime;

/* These public helpers are for the loader's existing native service table,
 * not an SDK extension RPC surface. Feature-disabled builds never call them. */
int nlr_native_card_attach(struct nlr_runtime *runtime);
int nlr_native_card_snapshot(struct nlr_runtime *runtime);
int nlr_native_card_commit_state(struct nlr_runtime *runtime,
                                 const struct nlr_card_state *desired,
                                 enum nlr_card_state_purpose purpose);
int nlr_native_card_probe(struct nlr_runtime *runtime, const char *path,
                          uint32_t *present);
int nlr_native_card_uncertain(const struct nlr_runtime *runtime);
int nlr_native_card_status(const struct nlr_runtime *runtime);
int nlr_native_card_safe_guard(void);
void nlr_native_card_wake(struct nlr_runtime *runtime);
const struct nlr_card_store *nlr_native_card_store(void);
int nlr_native_card_read_settings(struct nlr_runtime *runtime,
                                  struct nlr_enabled *enabled);
int nlr_native_card_guard(struct nlr_runtime *runtime, uint32_t expect_pending);
int nlr_native_card_pending(struct nlr_runtime *runtime, uint32_t pending);
int nlr_native_card_save_enabled(struct nlr_runtime *runtime,
                                  const struct nlr_enabled *desired);
void *nlr_native_card_menu_checkpoint(void);
int32_t nlr_native_card_file_open(const char *path, uint32_t flags, uint32_t mode);
int32_t nlr_native_card_file_read(int32_t fd, void *data, uint32_t bytes,
                                 uint32_t *read);
int32_t nlr_native_card_file_seek(int32_t fd, int32_t whence, uint32_t offset,
                                 uint32_t *position);
int32_t nlr_native_card_file_close(int32_t fd);
int32_t nlr_native_card_file_write(int32_t fd, const void *data, uint32_t bytes,
                                  uint32_t *written);

/* Registered in native slot0 only after the real claim and table readback.
 * The handler discovers the existing runtime first and compares userptr to
 * its retained request before dereferencing any user-supplied header. */
void nlr_native_card_transaction(void *userptr);
int32_t nlr_native_card_reply_observe(void *flag, uint32_t mask, uint32_t *out_bits);
int32_t nlr_native_card_low_unmount_observe(const char *volume);
/* Argument/result preserving firmware call hooks; original calls execute
 * unchanged, and observation conservatively invalidates the bound epoch.
 * Assembly tail targets come exclusively from the injected service table. */
int32_t nlr_native_card_mount_observe(const char *volume, void *device,
                                    void *parameters);
int32_t nlr_native_card_unmount_observe(const char *volume);

#endif
