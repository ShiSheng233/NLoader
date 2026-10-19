#include "nlr/card_state.h"

_Static_assert(NLR_CARD_STATE_HEADER_BYTES +
               NLR_MANIFEST_MAX_ENTRIES * (NLR_MANIFEST_ID_MAX + 1u) <=
               NLR_CARD_STATE_SLOT_BYTES, "complete enabled list fits one state slot");
_Static_assert(NLR_CARD_STATE_BOOT_ID_OFFSET == NLR_CARD_STATE_HEADER_BYTES +
               NLR_MANIFEST_MAX_ENTRIES * (NLR_MANIFEST_ID_MAX + 1u),
               "the boot ID follows the enabled list");
_Static_assert(NLR_CARD_STATE_BOOT_ID_OFFSET + NLR_MANIFEST_ID_MAX + 1u <=
               NLR_CARD_STATE_SLOT_BYTES, "the boot ID fits one state slot");

static int overlaps(const void *a, uint32_t a_bytes, const void *b, uint32_t b_bytes)
{
    uintptr_t left = (uintptr_t)a, right = (uintptr_t)b;
    return left <= right ? right - left < a_bytes : left - right < b_bytes;
}

static uint32_t frame_crc(const uint8_t *frame)
{
    uint32_t crc = UINT32_MAX;
    for (uint32_t n = 0; n < NLR_CARD_STATE_SLOT_BYTES; n++) {
        uint8_t byte = n >= NLR_CARD_STATE_CRC_OFFSET &&
                       n < NLR_CARD_STATE_CRC_OFFSET + 4u ? 0 : frame[n];
        crc ^= byte;
        for (uint32_t bit = 0; bit < 8u; bit++)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static int all_zero(const uint8_t *bytes, uint32_t count)
{
    for (uint32_t n = 0; n < count; n++)
        if (bytes[n])
            return 0;
    return 1;
}

static int equal_bytes(const uint8_t *a, const uint8_t *b, uint32_t bytes)
{
    for (uint32_t n = 0; n < bytes; n++)
        if (a[n] != b[n])
            return 0;
    return 1;
}

static uint8_t fold(uint8_t c)
{
    return c >= 'A' && c <= 'Z' ? (uint8_t)(c + ('a' - 'A')) : c;
}

static int same_id(const char *a, const char *b)
{
    for (uint32_t n = 0; n <= NLR_MANIFEST_ID_MAX; n++) {
        if (fold((uint8_t)a[n]) != fold((uint8_t)b[n]))
            return 0;
        if (!a[n])
            return 1;
    }
    return 0;
}

static int valid_ids(uint32_t count,
                     const char ids[NLR_MANIFEST_MAX_ENTRIES][NLR_MANIFEST_ID_MAX + 1u])
{
    if (count > NLR_MANIFEST_MAX_ENTRIES)
        return 0;
    for (uint32_t n = 0; n < count; n++) {
        uint32_t length = 0;
        while (length <= NLR_MANIFEST_ID_MAX && ids[n][length]) {
            if (!nlr_manifest_token_byte((uint8_t)ids[n][length]))
                return 0;
            length++;
        }
        if (!length || length > NLR_MANIFEST_ID_MAX)
            return 0;
        for (uint32_t prior = 0; prior < n; prior++)
            if (same_id(ids[n], ids[prior]))
                return 0;
    }
    return 1;
}

/* One ID field: 1..32 MANIFEST token bytes, NUL-terminated inside it. */
static int valid_token(const char *id)
{
    uint32_t length = 0;
    while (length <= NLR_MANIFEST_ID_MAX && id[length]) {
        if (!nlr_manifest_token_byte((uint8_t)id[length]))
            return 0;
        length++;
    }
    return length && length <= NLR_MANIFEST_ID_MAX;
}

/* The boot record's semantics: no record is all zero; any other mark names
 * the program; only FAILED carries a (nonzero) result. */
static int valid_boot(uint32_t mark, int32_t result, const char *id)
{
    if (mark > NLR_BOOT_MARK_FAILED)
        return 0;
    if (mark == NLR_BOOT_MARK_NONE)
        return !result && !id[0];
    if (!valid_token(id))
        return 0;
    return mark == NLR_BOOT_MARK_FAILED ? result != 0 : result == 0;
}

static int valid_payload(const struct nlr_card_state *state)
{
    return state && state->pending <= 1u &&
           valid_ids(state->enabled_count, state->enabled_id) &&
           valid_boot(state->boot_mark, state->boot_result, state->boot_id);
}

static void copy_id(char out[NLR_MANIFEST_ID_MAX + 1u], const char *in)
{
    int ended = 0;
    for (uint32_t k = 0; k <= NLR_MANIFEST_ID_MAX; k++) {
        char byte = ended ? 0 : in[k];
        if (!byte)
            ended = 1;
        out[k] = byte;
    }
}

static void copy_ids(char out[NLR_MANIFEST_MAX_ENTRIES][NLR_MANIFEST_ID_MAX + 1u],
                      const char in[NLR_MANIFEST_MAX_ENTRIES][NLR_MANIFEST_ID_MAX + 1u],
                      uint32_t count)
{
    for (uint32_t n = 0; n < NLR_MANIFEST_MAX_ENTRIES; n++) {
        int ended = n >= count;
        for (uint32_t k = 0; k <= NLR_MANIFEST_ID_MAX; k++) {
            char byte = ended ? 0 : in[n][k];
            if (!byte)
                ended = 1;
            out[n][k] = byte;
        }
    }
}

static void put32(uint8_t *out, uint32_t value)
{
    for (uint32_t n = 0; n < 4u; n++)
        out[n] = (uint8_t)(value >> (n * 8u));
}

static void put64(uint8_t *out, uint64_t value)
{
    for (uint32_t n = 0; n < 8u; n++)
        out[n] = (uint8_t)(value >> (n * 8u));
}

static uint64_t get64(const uint8_t *in)
{
    return (uint64_t)nlr_le32(in) | (uint64_t)nlr_le32(in + 4) << 32;
}

static int encode_generation(const struct nlr_card_state *state, uint64_t generation,
                              uint8_t *frame, uint32_t bytes)
{
    if (!frame || bytes != NLR_CARD_STATE_SLOT_BYTES)
        return NLR_CARD_STATE_BOUNDS;
    if (state && overlaps(state, (uint32_t)sizeof *state, frame, bytes))
        return NLR_CARD_STATE_BOUNDS;
    if (!valid_payload(state) || !generation)
        return NLR_CARD_STATE_CONFLICT;
    for (uint32_t n = 0; n < bytes; n++)
        frame[n] = 0;
    const char *magic = "NLRSTAT1";
    for (uint32_t n = 0; n < 8u; n++)
        frame[n] = (uint8_t)magic[n];
    put32(frame + 8, NLR_CARD_STATE_FORMAT);
    put32(frame + 12, NLR_CARD_STATE_SLOT_BYTES);
    put64(frame + 16, generation);
    put32(frame + 24, state->pending);
    put32(frame + 28, state->enabled_count);
    put32(frame + NLR_CARD_STATE_BOOT_MARK_OFFSET, state->boot_mark);
    put32(frame + NLR_CARD_STATE_BOOT_RESULT_OFFSET, (uint32_t)state->boot_result);
    for (uint32_t n = 0; n < state->enabled_count; n++)
        for (uint32_t k = 0; state->enabled_id[n][k]; k++)
            frame[NLR_CARD_STATE_HEADER_BYTES +
                  n * (NLR_MANIFEST_ID_MAX + 1u) + k] = (uint8_t)state->enabled_id[n][k];
    if (state->boot_mark != NLR_BOOT_MARK_NONE)
        for (uint32_t k = 0; state->boot_id[k]; k++)
            frame[NLR_CARD_STATE_BOOT_ID_OFFSET + k] = (uint8_t)state->boot_id[k];
    put32(frame + NLR_CARD_STATE_CRC_OFFSET, frame_crc(frame));
    return NLR_CARD_STATE_OK;
}

int nlr_card_state_encode(const struct nlr_card_state *state, uint8_t *frame,
                          uint32_t bytes)
{
    return encode_generation(state, state ? state->generation : 0, frame, bytes);
}

struct frame_view {
    uint64_t generation;
    uint32_t pending;
    uint32_t count;
    uint32_t boot_mark;
    int32_t boot_result;
    const char *boot_id; /* inside the frame; all zero in format 1 */
};

static int frame_validate(const uint8_t *frame, uint32_t bytes,
                           struct frame_view *view)
{
    if (!frame || bytes != NLR_CARD_STATE_SLOT_BYTES)
        return NLR_CARD_STATE_IO;
    if (all_zero(frame, bytes))
        return NLR_CARD_STATE_EMPTY;
    uint32_t format = nlr_le32(frame + 8);
    if (!equal_bytes(frame, (const uint8_t *)"NLRSTAT1", 8u) ||
        (format != NLR_CARD_STATE_FORMAT_1 && format != NLR_CARD_STATE_FORMAT) ||
        nlr_le32(frame + 12) != NLR_CARD_STATE_SLOT_BYTES)
        return NLR_CARD_STATE_UNSUPPORTED;
    if (frame_crc(frame) != nlr_le32(frame + NLR_CARD_STATE_CRC_OFFSET))
        return NLR_CARD_STATE_CORRUPT;
    /* Format 1 reserves the whole rest of the header; format 2 uses 24..2b
     * for the boot record and reserves the rest. */
    const uint32_t reserved = format == NLR_CARD_STATE_FORMAT_1
        ? NLR_CARD_STATE_BOOT_MARK_OFFSET : NLR_CARD_STATE_BOOT_RESULT_OFFSET + 4u;
    if (!all_zero(frame + reserved, NLR_CARD_STATE_HEADER_BYTES - reserved))
        return NLR_CARD_STATE_UNSUPPORTED;
    uint64_t generation = get64(frame + 16);
    uint32_t pending = nlr_le32(frame + 24), count = nlr_le32(frame + 28);
    if (!generation || pending > 1u || count > NLR_MANIFEST_MAX_ENTRIES)
        return NLR_CARD_STATE_CONFLICT;
    for (uint32_t n = 0; n < NLR_MANIFEST_MAX_ENTRIES; n++) {
        const uint8_t *id = frame + NLR_CARD_STATE_HEADER_BYTES +
                            n * (NLR_MANIFEST_ID_MAX + 1u);
        uint32_t length = 0;
        while (length <= NLR_MANIFEST_ID_MAX && id[length])
            length++;
        if (length > NLR_MANIFEST_ID_MAX ||
            (n < count && !length) ||
            (n >= count && length) ||
            !all_zero(id + length, NLR_MANIFEST_ID_MAX + 1u - length))
            return NLR_CARD_STATE_CONFLICT;
    }
    uint32_t tail = NLR_CARD_STATE_BOOT_ID_OFFSET;
    const char *boot_id = (const char *)(frame + NLR_CARD_STATE_BOOT_ID_OFFSET);
    uint32_t boot_mark = 0;
    int32_t boot_result = 0;
    if (format == NLR_CARD_STATE_FORMAT) {
        boot_mark = nlr_le32(frame + NLR_CARD_STATE_BOOT_MARK_OFFSET);
        boot_result = (int32_t)nlr_le32(frame + NLR_CARD_STATE_BOOT_RESULT_OFFSET);
        uint32_t length = 0;
        while (length <= NLR_MANIFEST_ID_MAX && boot_id[length])
            length++;
        if (length > NLR_MANIFEST_ID_MAX ||
            !all_zero((const uint8_t *)boot_id + length, NLR_MANIFEST_ID_MAX + 1u - length) ||
            !valid_boot(boot_mark, boot_result, boot_id))
            return NLR_CARD_STATE_CONFLICT;
        tail += NLR_MANIFEST_ID_MAX + 1u;
    }
    const char (*ids)[NLR_MANIFEST_ID_MAX + 1u] =
        (const void *)(frame + NLR_CARD_STATE_HEADER_BYTES);
    if (!all_zero(frame + tail, bytes - tail) || !valid_ids(count, ids))
        return NLR_CARD_STATE_CONFLICT;
    view->generation = generation;
    view->pending = pending;
    view->count = count;
    view->boot_mark = boot_mark;
    view->boot_result = boot_result;
    view->boot_id = boot_id; /* zero in format 1: the tail check covered it */
    return NLR_CARD_STATE_OK;
}

int nlr_card_state_decode(const uint8_t *frame, uint32_t bytes,
                          struct nlr_card_state *state)
{
    if (!state)
        return NLR_CARD_STATE_BOUNDS;
    struct frame_view view;
    int result = frame_validate(frame, bytes, &view);
    if (result != NLR_CARD_STATE_OK)
        return result;
    if (overlaps(frame, bytes, state, (uint32_t)sizeof *state))
        return NLR_CARD_STATE_BOUNDS;
    state->generation = view.generation;
    state->pending = view.pending;
    state->enabled_count = view.count;
    const char (*ids)[NLR_MANIFEST_ID_MAX + 1u] =
        (const void *)(frame + NLR_CARD_STATE_HEADER_BYTES);
    copy_ids(state->enabled_id, ids, view.count);
    state->boot_mark = view.boot_mark;
    state->boot_result = view.boot_result;
    copy_id(state->boot_id, view.boot_id);
    return NLR_CARD_STATE_OK;
}

int nlr_card_state_select(const struct nlr_card_state_slot slots[2],
                          uint32_t file_bytes,
                          struct nlr_card_state_selection *selection)
{
    if (!selection)
        return NLR_CARD_STATE_BOUNDS;
    selection->slot = NLR_CARD_STATE_NO_SLOT;
    selection->mirrored = 0;
    selection->slot_result[0] = selection->slot_result[1] = NLR_CARD_STATE_IO;
    if (!slots || file_bytes != NLR_CARD_STATE_FILE_BYTES)
        return NLR_CARD_STATE_IO;
    struct frame_view decoded[2];
    for (uint32_t n = 0; n < 2u; n++)
        if (!slots[n].read_result && slots[n].data &&
            slots[n].bytes == NLR_CARD_STATE_SLOT_BYTES)
            selection->slot_result[n] = frame_validate(slots[n].data,
                                                       slots[n].bytes, &decoded[n]);
    for (uint32_t n = 0; n < 2u; n++) {
        if (selection->slot_result[n] == NLR_CARD_STATE_IO)
            return NLR_CARD_STATE_IO;
        if (selection->slot_result[n] == NLR_CARD_STATE_UNSUPPORTED)
            return NLR_CARD_STATE_UNSUPPORTED;
        if (selection->slot_result[n] == NLR_CARD_STATE_CONFLICT)
            return NLR_CARD_STATE_CONFLICT;
    }
    int valid0 = selection->slot_result[0] == NLR_CARD_STATE_OK;
    int valid1 = selection->slot_result[1] == NLR_CARD_STATE_OK;
    if (!valid0 && !valid1)
        return selection->slot_result[0] == NLR_CARD_STATE_EMPTY &&
               selection->slot_result[1] == NLR_CARD_STATE_EMPTY
                   ? NLR_CARD_STATE_NEEDS_MIGRATION : NLR_CARD_STATE_CORRUPT;
    uint32_t chosen = valid0 ? 0u : 1u;
    if (valid0 && valid1) {
        if (decoded[0].generation == decoded[1].generation) {
            if (!equal_bytes(slots[0].data, slots[1].data, NLR_CARD_STATE_SLOT_BYTES))
                return NLR_CARD_STATE_CONFLICT;
            selection->mirrored = 1;
        } else if (decoded[1].generation > decoded[0].generation) {
            chosen = 1;
        }
    }
    int result = nlr_card_state_decode(slots[chosen].data, slots[chosen].bytes,
                                       &selection->state);
    if (result != NLR_CARD_STATE_OK)
        return result;
    selection->slot = chosen;
    return NLR_CARD_STATE_OK;
}

int nlr_card_state_import_legacy(struct nlr_card_state *state,
                                 const struct nlr_enabled *enabled,
                                 int32_t safe_result, uint32_t safe_present,
                                 int32_t pending_result, uint32_t pending_present)
{
    if (!state || !enabled || safe_result || safe_present > 1u ||
        pending_result || pending_present > 1u)
        return NLR_CARD_STATE_IO;
    if (safe_present)
        return NLR_CARD_STATE_DISABLED;
    if (enabled->error != NLR_EN_OK || !valid_ids(enabled->count, enabled->id))
        return NLR_CARD_STATE_CONFLICT;
    state->generation = 0;
    state->pending = pending_present;
    state->enabled_count = enabled->count;
    copy_ids(state->enabled_id, enabled->id, enabled->count);
    state->boot_mark = NLR_BOOT_MARK_NONE;
    state->boot_result = 0;
    copy_id(state->boot_id, "");
    return NLR_CARD_STATE_OK;
}

static int same_enabled(const struct nlr_card_state *a,
                         const struct nlr_card_state *b)
{
    if (a->enabled_count != b->enabled_count)
        return 0;
    for (uint32_t n = 0; n < a->enabled_count; n++)
        if (!same_id(a->enabled_id[n], b->enabled_id[n]))
            return 0;
    return 1;
}

/* The boot record exactly as it is: every purpose but BOOT_MARK keeps it. */
static int same_boot(const struct nlr_card_state *a,
                     const struct nlr_card_state *b)
{
    if (a->boot_mark != b->boot_mark || a->boot_result != b->boot_result)
        return 0;
    for (uint32_t k = 0; k <= NLR_MANIFEST_ID_MAX; k++) {
        if (a->boot_id[k] != b->boot_id[k])
            return 0;
        if (!a->boot_id[k])
            return 1;
    }
    return 0;
}

static int boot_transition(const struct nlr_card_state *current,
                           const struct nlr_card_state *desired)
{
    switch (desired->boot_mark) {
    case NLR_BOOT_MARK_RUN:
        return current->boot_mark != NLR_BOOT_MARK_RUN;
    case NLR_BOOT_MARK_SKIPPED:
        return current->boot_mark == NLR_BOOT_MARK_RUN;
    case NLR_BOOT_MARK_OK:
    case NLR_BOOT_MARK_FAILED:
        return current->boot_mark == NLR_BOOT_MARK_RUN &&
               same_id(current->boot_id, desired->boot_id);
    default:
        return 0;
    }
}

int nlr_card_state_commit_begin(struct nlr_card_state_commit *commit,
                                const struct nlr_card_state *current,
                                uint32_t active_slot,
                                const struct nlr_card_state *desired,
                                enum nlr_card_state_purpose purpose,
                                uint8_t *frame, uint32_t bytes)
{
    if (!commit || !frame || bytes != NLR_CARD_STATE_SLOT_BYTES)
        return NLR_CARD_STATE_BOUNDS;
    if (commit->phase == NLR_CARD_STATE_UNCERTAIN)
        return NLR_CARD_STATE_COMMIT_UNCERTAIN;
    if (commit->phase != NLR_CARD_STATE_IDLE &&
        commit->phase != NLR_CARD_STATE_CONFIRMED &&
        commit->phase != NLR_CARD_STATE_FAILED_BEFORE_WRITE)
        return NLR_CARD_STATE_BUSY;
    if (!valid_payload(desired))
        return NLR_CARD_STATE_CONFLICT;
    uint64_t generation;
    uint32_t target;
    if (purpose == NLR_CARD_STATE_MIGRATE) {
        if (current || active_slot != NLR_CARD_STATE_NO_SLOT || desired->generation ||
            commit->phase == NLR_CARD_STATE_CONFIRMED ||
            desired->boot_mark != NLR_BOOT_MARK_NONE)
            return NLR_CARD_STATE_CONFLICT;
        generation = 1;
        target = 0;
    } else {
        if (!valid_payload(current) || !current->generation || active_slot > 1u)
            return NLR_CARD_STATE_CONFLICT;
        if (current->generation == UINT64_MAX)
            return NLR_CARD_STATE_GENERATION_EXHAUSTED;
        if (commit->phase == NLR_CARD_STATE_CONFIRMED &&
            (current->generation < commit->generation ||
             (current->generation == commit->generation && active_slot != commit->target_slot)))
            return NLR_CARD_STATE_CONFLICT;
        if (purpose == NLR_CARD_STATE_BOOT_MARK) {
            if (current->pending || desired->pending ||
                !same_enabled(current, desired) || !boot_transition(current, desired))
                return NLR_CARD_STATE_CONFLICT;
        } else if (!same_boot(current, desired)) {
            return NLR_CARD_STATE_CONFLICT;
        } else if (purpose == NLR_CARD_STATE_ARM_INIT) {
            if (current->pending || desired->pending != 1u ||
                !desired->enabled_count || !same_enabled(current, desired))
                return NLR_CARD_STATE_CONFLICT;
        } else if (purpose == NLR_CARD_STATE_SAVE_SETTINGS) {
            if (desired->pending != current->pending)
                return NLR_CARD_STATE_CONFLICT;
        } else if (purpose == NLR_CARD_STATE_CLEAR_PENDING) {
            if (current->pending != 1u || desired->pending ||
                !same_enabled(current, desired))
                return NLR_CARD_STATE_CONFLICT;
        } else {
            return NLR_CARD_STATE_UNSUPPORTED;
        }
        generation = current->generation + 1u;
        target = active_slot ^ 1u;
    }
    int result = encode_generation(desired, generation, frame, bytes);
    if (result != NLR_CARD_STATE_OK)
        return result;
    commit->phase = NLR_CARD_STATE_WRITE_INACTIVE;
    commit->purpose = (uint32_t)purpose;
    commit->target_slot = target;
    commit->write_submitted = 0;
    commit->generation = generation;
    commit->checksum = nlr_le32(frame + NLR_CARD_STATE_CRC_OFFSET);
    commit->pending = desired->pending;
    commit->enabled_count = desired->enabled_count;
    commit->frame = frame;
    return commit->result = NLR_CARD_STATE_IN_PROGRESS;
}

int nlr_card_state_commit_submit(struct nlr_card_state_commit *commit)
{
    if (!commit || commit->phase != NLR_CARD_STATE_WRITE_INACTIVE ||
        commit->write_submitted)
        return NLR_CARD_STATE_CONFLICT;
    commit->write_submitted = 1;
    return NLR_CARD_STATE_IN_PROGRESS;
}

int nlr_card_state_commit_reject(struct nlr_card_state_commit *commit)
{
    if (!commit || commit->phase != NLR_CARD_STATE_WRITE_INACTIVE ||
        commit->write_submitted)
        return NLR_CARD_STATE_CONFLICT;
    commit->phase = NLR_CARD_STATE_FAILED_BEFORE_WRITE;
    return commit->result = NLR_CARD_STATE_REJECTED;
}

static int commit_uncertain(struct nlr_card_state_commit *commit)
{
    commit->phase = NLR_CARD_STATE_UNCERTAIN;
    return commit->result = NLR_CARD_STATE_COMMIT_UNCERTAIN;
}

int nlr_card_state_commit_ack(struct nlr_card_state_commit *commit,
                              enum nlr_card_state_phase completed,
                              int32_t io_result)
{
    if (!commit || !commit->write_submitted || commit->phase != (uint32_t)completed ||
        completed < NLR_CARD_STATE_WRITE_INACTIVE || completed > NLR_CARD_STATE_FLUSH_MEDIA)
        return NLR_CARD_STATE_CONFLICT;
    if (io_result)
        return commit_uncertain(commit);
    commit->phase++;
    return commit->result = NLR_CARD_STATE_IN_PROGRESS;
}

int nlr_card_state_commit_readback(struct nlr_card_state_commit *commit,
                                   const uint8_t *frame, uint32_t bytes,
                                   int32_t read_result)
{
    if (!commit || commit->phase != NLR_CARD_STATE_VERIFY_READBACK)
        return NLR_CARD_STATE_CONFLICT;
    struct frame_view view;
    if (!commit->frame || read_result ||
        (frame && overlaps(frame, bytes, commit->frame, NLR_CARD_STATE_SLOT_BYTES)) ||
        frame_validate(frame, bytes, &view) != NLR_CARD_STATE_OK ||
        view.generation != commit->generation ||
        nlr_le32(frame + NLR_CARD_STATE_CRC_OFFSET) != commit->checksum ||
        !equal_bytes(frame, commit->frame, NLR_CARD_STATE_SLOT_BYTES))
        return commit_uncertain(commit);
    commit->phase = NLR_CARD_STATE_CONFIRMED;
    return commit->result = NLR_CARD_STATE_OK;
}

int nlr_card_state_commit_allows_init(const struct nlr_card_state_commit *commit)
{
    return commit && commit->phase == NLR_CARD_STATE_CONFIRMED &&
           commit->purpose == NLR_CARD_STATE_ARM_INIT &&
           commit->pending == 1u && commit->enabled_count != 0;
}
