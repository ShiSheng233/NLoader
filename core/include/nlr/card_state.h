#ifndef NLR_CARD_STATE_H
#define NLR_CARD_STATE_H

#include "nlr/manifest.h"

/* Pure codec and transaction acknowledgements, not a filesystem backend.
 * Both slots belong to one fixed, previously allocated 8192-byte file.
 * In-place writes target only the inactive 4096-byte slot; the protocol
 * neither truncates, extends, deletes nor renames that file.
 *
 * Common header (little endian), retained by future formats:
 *   00 magic[8]="NLRSTAT1", 08 format u32, 0c frame bytes u32,
 *   10 generation u64, 18 pending u32, 1c enabled count u32,
 *   20 IEEE CRC32 of all 4096 bytes with 20..23 treated as zero.
 * Format 1 reserves 24..3f as zero. At 40 are 64 NUL-terminated,
 * zero-padded 33-byte ID fields; unused fields and the tail are zero.
 * Format 2 (PLAN 6.2, 2026-10-17) keeps all of that and adds the boot
 * program's record: 24 boot mark u32 (NLR_BOOT_MARK_*), 28 boot result
 * s32, and at 880 the program's ID in one more 33-byte field. 2c..3f and
 * 8a1.. stay zero. A format 1 record reads as format 2 with no boot record;
 * every commit writes format 2, so a card moves to it with its next save
 * and is never rewritten only to change its format. An older core reading
 * format 2 sees an unknown format and pauses, the safe direction.
 * The record carries the complete enabled order and pending flag together.
 * CRC detects corruption; it is not authentication or physical atomicity.
 * A checksum-valid unknown format or illegal semantics pauses globally.
 * Only a known-format checksum failure or an all-zero uninitialized slot
 * may be ignored when the other slot is valid. Any IO/short read pauses. */
#define NLR_CARD_STATE_SLOT_BYTES 4096u
#define NLR_CARD_STATE_FILE_BYTES (2u * NLR_CARD_STATE_SLOT_BYTES)
#define NLR_CARD_STATE_HEADER_BYTES 64u
#define NLR_CARD_STATE_CRC_OFFSET 32u
#define NLR_CARD_STATE_FORMAT 2u   /* the format every commit writes */
#define NLR_CARD_STATE_FORMAT_1 1u /* read, and migrated by the next commit */
#define NLR_CARD_STATE_BOOT_MARK_OFFSET 0x24u
#define NLR_CARD_STATE_BOOT_RESULT_OFFSET 0x28u
#define NLR_CARD_STATE_BOOT_ID_OFFSET 0x880u
#define NLR_CARD_STATE_NO_SLOT UINT32_MAX

enum {
    NLR_CARD_STATE_OK = 0,
    NLR_CARD_STATE_IN_PROGRESS = 1,
    NLR_CARD_STATE_EMPTY = -100,
    NLR_CARD_STATE_CORRUPT = -101,
    NLR_CARD_STATE_UNSUPPORTED = -102,
    NLR_CARD_STATE_CONFLICT = -103,
    NLR_CARD_STATE_IO = -104,
    NLR_CARD_STATE_BOUNDS = -105,
    NLR_CARD_STATE_GENERATION_EXHAUSTED = -106,
    NLR_CARD_STATE_NEEDS_MIGRATION = -107,
    NLR_CARD_STATE_DISABLED = -108,
    NLR_CARD_STATE_BUSY = -109,
    NLR_CARD_STATE_REJECTED = -110,
    NLR_CARD_STATE_COMMIT_UNCERTAIN = -111,
    /* A card is mounted and its root has no loader directory (the native
     * card's snapshot): nothing on it is the loader's, nothing is written. */
    NLR_CARD_STATE_NO_DIRECTORY = -112,
};

struct nlr_card_state {
    uint64_t generation;
    uint32_t pending;
    uint32_t enabled_count;
    char enabled_id[NLR_MANIFEST_MAX_ENTRIES][NLR_MANIFEST_ID_MAX + 1u];
    /* The boot program's record (format 2; zero in a format 1 record). */
    uint32_t boot_mark;
    int32_t boot_result;
    char boot_id[NLR_MANIFEST_ID_MAX + 1u];
};

struct nlr_card_state_slot {
    const uint8_t *data;
    uint32_t bytes;
    int32_t read_result; /* zero only after all requested bytes were read */
};

struct nlr_card_state_selection {
    uint32_t slot; /* NO_SLOT on any failure */
    uint32_t mirrored;
    int32_t slot_result[2];
    struct nlr_card_state state; /* only valid when select returns OK */
};

int nlr_card_state_encode(const struct nlr_card_state *state, uint8_t *frame,
                          uint32_t bytes);
int nlr_card_state_decode(const uint8_t *frame, uint32_t bytes,
                          struct nlr_card_state *state);
int nlr_card_state_select(const struct nlr_card_state_slot slots[2],
                          uint32_t file_bytes,
                          struct nlr_card_state_selection *selection);
/* The caller must have parsed ENABLED against the actual MANIFEST already.
 * Reliable absence is distinct from a probe/read error. No empty defaults,
 * file removal, legacy override or production IO are performed here. The
 * output has generation zero and can only prepare a first migration write;
 * an existing pending flag stays set and cannot authorize initialization. */
int nlr_card_state_import_legacy(struct nlr_card_state *state,
                                 const struct nlr_enabled *enabled,
                                 int32_t safe_result, uint32_t safe_present,
                                 int32_t pending_result, uint32_t pending_present);

enum nlr_card_state_purpose {
    NLR_CARD_STATE_MIGRATE = 0,
    NLR_CARD_STATE_ARM_INIT,
    NLR_CARD_STATE_SAVE_SETTINGS,
    NLR_CARD_STATE_CLEAR_PENDING,
    /* Only the boot record changes, outside any pass (pending 0 before and
     * after, the enabled order unchanged): RUN from anything but RUN;
     * SKIPPED from RUN; OK or FAILED from RUN of the same ID. Every other
     * purpose must carry the current boot record unchanged, and the first
     * migration has none. */
    NLR_CARD_STATE_BOOT_MARK,
};
enum nlr_card_state_phase {
    NLR_CARD_STATE_IDLE = 0,
    NLR_CARD_STATE_WRITE_INACTIVE,
    NLR_CARD_STATE_SYNC_FILE,
    NLR_CARD_STATE_FLUSH_MEDIA,
    NLR_CARD_STATE_VERIFY_READBACK,
    NLR_CARD_STATE_CONFIRMED,
    NLR_CARD_STATE_FAILED_BEFORE_WRITE,
    NLR_CARD_STATE_UNCERTAIN,
};

struct nlr_card_state_commit {
    uint32_t phase;
    uint32_t purpose;
    uint32_t target_slot;
    uint32_t write_submitted;
    uint64_t generation;
    uint32_t checksum;
    uint32_t pending;
    uint32_t enabled_count;
    const uint8_t *frame; /* caller-owned, immutable until terminal outcome */
    int32_t result;
};

/* begin emits the candidate, but does not submit or confirm any IO. The
 * caller must validate native owner, file size/allocation, guards and the
 * current generation within the same real filesystem transaction first.
 * Buffers and state objects may not overlap. Migration additionally needs
 * a reliable missing/empty-new state and the checked legacy proposal. */
int nlr_card_state_commit_begin(struct nlr_card_state_commit *commit,
                                const struct nlr_card_state *current,
                                uint32_t active_slot,
                                const struct nlr_card_state *desired,
                                enum nlr_card_state_purpose purpose,
                                uint8_t *frame, uint32_t bytes);
int nlr_card_state_commit_submit(struct nlr_card_state_commit *commit);
/* Reject is only legal before the write was handed to the real backend.
 * Any failure after submission can leave a complete higher-generation
 * record and is COMMIT_UNCERTAIN, including write/sync/readback failures.
 * An uncertain commit cannot be reset or retried through this API. */
int nlr_card_state_commit_reject(struct nlr_card_state_commit *commit);
int nlr_card_state_commit_ack(struct nlr_card_state_commit *commit,
                              enum nlr_card_state_phase completed,
                              int32_t io_result);
int nlr_card_state_commit_readback(struct nlr_card_state_commit *commit,
                                   const uint8_t *frame, uint32_t bytes,
                                   int32_t read_result);
/* Readback must be in a separate buffer; reading into the expected candidate
 * would erase the full-frame comparison and cannot confirm a transaction. */
/* Only a confirmed ARM_INIT transition can permit a caller to initialize
 * extensions; migration, settings saves, partial progress and uncertainties
 * never do. Resource/mount/readiness checks remain the caller's duties. */
int nlr_card_state_commit_allows_init(const struct nlr_card_state_commit *commit);

#endif
