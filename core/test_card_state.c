#include "nlr/card_state.h"

#include <stdio.h>
#include <string.h>

static unsigned failures;
#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "line %u: %s\n", (unsigned)__LINE__, #value); failures++; \
} } while (0)

static void put32(uint8_t *out, uint32_t value)
{
    for (unsigned n = 0; n < 4; n++)
        out[n] = (uint8_t)(value >> (n * 8));
}

/* Independent MSB-first polynomial division with explicit input/output bit
 * reversal, unlike the reflected production loop. The fixed reference
 * vector below is additionally calculated using Python's zlib. */
static uint32_t reverse32(uint32_t value)
{
    uint32_t out = 0;
    for (unsigned n = 0; n < 32; n++) {
        out = (out << 1) | (value & 1);
        value >>= 1;
    }
    return out;
}

static uint32_t reference_crc(const uint8_t *frame)
{
    uint32_t crc = UINT32_MAX;
    for (unsigned n = 0; n < NLR_CARD_STATE_SLOT_BYTES; n++) {
        uint8_t byte = n >= 32 && n < 36 ? 0 : frame[n];
        for (unsigned bit = 0; bit < 8; bit++) {
            uint32_t high = (crc >> 31) ^ (uint32_t)((byte >> bit) & 1);
            crc = (crc << 1) ^ (high ? 0x04c11db7u : 0);
        }
    }
    return ~reverse32(crc);
}

static void checksum(uint8_t *frame)
{
    put32(frame + 32, reference_crc(frame));
}

static struct nlr_card_state sample(uint64_t generation, uint32_t pending)
{
    struct nlr_card_state state = {0};
    state.generation = generation;
    state.pending = pending;
    state.enabled_count = 2;
    strcpy(state.enabled_id[0], "EXT");
    strcpy(state.enabled_id[1], "two!?");
    return state;
}

static int select_frames(const uint8_t *a, const uint8_t *b,
                          struct nlr_card_state_selection *selection)
{
    struct nlr_card_state_slot slots[2] = {
        {a, NLR_CARD_STATE_SLOT_BYTES, 0},
        {b, NLR_CARD_STATE_SLOT_BYTES, 0},
    };
    return nlr_card_state_select(slots, NLR_CARD_STATE_FILE_BYTES, selection);
}

static void reference_frame_and_token_grammar(void)
{
    struct nlr_card_state state = sample(7, 1), decoded;
    uint8_t encoded[4096], expected[4096] = {0};
    /* Format 2 is what every encode writes; with no boot record its bytes
     * differ from format 1 only in the format word (and so the CRC). Both
     * CRCs below were also calculated with Python's zlib. */
    const uint8_t header[] = {
        0x4e,0x4c,0x52,0x53,0x54,0x41,0x54,0x31,
        2,0,0,0,0,0x10,0,0,7,0,0,0,0,0,0,0,
        1,0,0,0,2,0,0,0,0x94,0xd4,0x65,0x9d,
    };
    memcpy(expected, header, sizeof header);
    memcpy(expected + 64, "EXT", 3);
    memcpy(expected + 97, "two!?", 5);
    CHECK(reference_crc(expected) == 0x9d65d494u);
    CHECK(nlr_card_state_encode(&state, encoded, sizeof encoded) == NLR_CARD_STATE_OK);
    CHECK(memcmp(encoded, expected, sizeof encoded) == 0);
    CHECK(nlr_card_state_decode(encoded, sizeof encoded, &decoded) == NLR_CARD_STATE_OK);
    CHECK(decoded.generation == 7 && decoded.pending == 1 && decoded.enabled_count == 2);
    CHECK(strcmp(decoded.enabled_id[1], "two!?") == 0);
    CHECK(decoded.boot_mark == NLR_BOOT_MARK_NONE && !decoded.boot_result && !decoded.boot_id[0]);
    /* A format 1 record, as an older core wrote it, still reads: no boot
     * record. */
    uint8_t format1[4096];
    memcpy(format1, expected, sizeof format1);
    put32(format1 + 8, 1);
    checksum(format1);
    CHECK(reference_crc(format1) == 0x242433dbu);
    memset(&decoded, 0x5a, sizeof decoded);
    CHECK(nlr_card_state_decode(format1, sizeof format1, &decoded) == NLR_CARD_STATE_OK);
    CHECK(decoded.generation == 7 && decoded.pending == 1 && decoded.enabled_count == 2);
    CHECK(decoded.boot_mark == NLR_BOOT_MARK_NONE && !decoded.boot_result);
    for (unsigned k = 0; k <= NLR_MANIFEST_ID_MAX; k++)
        CHECK(decoded.boot_id[k] == 0);
    /* The boot record's own reference bytes. */
    state = sample(7, 1);
    state.boot_mark = NLR_BOOT_MARK_FAILED;
    state.boot_result = -7;
    strcpy(state.boot_id, "Shel");
    memcpy(expected, header, sizeof header);
    put32(expected + 0x24, NLR_BOOT_MARK_FAILED);
    put32(expected + 0x28, (uint32_t)-7);
    memcpy(expected + 0x880, "Shel", 4);
    checksum(expected);
    CHECK(reference_crc(expected) == 0x07ffa0b6u);
    CHECK(nlr_card_state_encode(&state, encoded, sizeof encoded) == NLR_CARD_STATE_OK);
    CHECK(memcmp(encoded, expected, sizeof encoded) == 0);
    CHECK(nlr_card_state_decode(encoded, sizeof encoded, &decoded) == NLR_CARD_STATE_OK);
    CHECK(decoded.boot_mark == NLR_BOOT_MARK_FAILED && decoded.boot_result == -7);
    CHECK(strcmp(decoded.boot_id, "Shel") == 0);
    for (unsigned byte = 0; byte < 256; byte++) {
        state = sample(7, 1);
        state.enabled_id[0][0] = (char)byte;
        state.enabled_id[0][1] = 0;
        int result = nlr_card_state_encode(&state, encoded, sizeof encoded);
        CHECK((result == NLR_CARD_STATE_OK) == nlr_manifest_token_byte((uint8_t)byte));
    }
    state = sample(1, 0);
    strcpy(state.enabled_id[1], "ext");
    CHECK(nlr_card_state_encode(&state, encoded, sizeof encoded) == NLR_CARD_STATE_CONFLICT);
    state = sample(1, 0);
    memset(state.enabled_id[0], 'x', sizeof state.enabled_id[0]);
    CHECK(nlr_card_state_encode(&state, encoded, sizeof encoded) == NLR_CARD_STATE_CONFLICT);
    state = sample(1, 0);
    CHECK(nlr_card_state_encode(&state, encoded, sizeof encoded - 1) == NLR_CARD_STATE_BOUNDS);
    state.enabled_count = NLR_MANIFEST_MAX_ENTRIES;
    for (unsigned n = 0; n < state.enabled_count; n++)
        snprintf(state.enabled_id[n], sizeof state.enabled_id[n], "id-%02u", n);
    memset(state.enabled_id[0], 'X', NLR_MANIFEST_ID_MAX);
    state.enabled_id[0][NLR_MANIFEST_ID_MAX] = 0;
    CHECK(nlr_card_state_encode(&state, encoded, sizeof encoded) == 0);
    CHECK(nlr_card_state_decode(encoded, sizeof encoded, &decoded) == 0);
    CHECK(decoded.enabled_count == 64 && strlen(decoded.enabled_id[0]) == 32);
}

static void selection_and_torn_writes(void)
{
    struct nlr_card_state old = sample(7, 0), next = sample(8, 1);
    struct nlr_card_state_selection selected;
    uint8_t a[4096], b[4096], torn[4096], empty[4096] = {0};
    CHECK(nlr_card_state_encode(&old, a, sizeof a) == 0);
    CHECK(nlr_card_state_encode(&next, b, sizeof b) == 0);
    CHECK(select_frames(a, b, &selected) == 0 && selected.slot == 1 && selected.state.pending == 1);
    CHECK(select_frames(b, a, &selected) == 0 && selected.slot == 0);
    CHECK(select_frames(a, a, &selected) == 0 && selected.slot == 0 && selected.mirrored);
    next.generation = old.generation;
    CHECK(nlr_card_state_encode(&next, torn, sizeof torn) == 0);
    CHECK(select_frames(a, torn, &selected) == NLR_CARD_STATE_CONFLICT);
    CHECK(selected.slot == NLR_CARD_STATE_NO_SLOT);
    CHECK(select_frames(empty, empty, &selected) == NLR_CARD_STATE_NEEDS_MIGRATION);
    CHECK(select_frames(empty, b, &selected) == 0 && selected.slot == 1);
    struct nlr_card_state maximum = sample(UINT64_MAX, 0), wrapped = sample(1, 1);
    CHECK(nlr_card_state_encode(&maximum, torn, sizeof torn) == 0);
    CHECK(nlr_card_state_encode(&wrapped, b, sizeof b) == 0);
    CHECK(select_frames(torn, b, &selected) == 0 && selected.state.generation == UINT64_MAX);
    next = sample(8, 1);
    CHECK(nlr_card_state_encode(&next, b, sizeof b) == 0);
    /* Every possible byte boundary for an interrupted overwrite of a known
     * inactive slot is read back as a full slot. Only old/new complete or
     * independently CRC-invalid data can be selected. */
    for (unsigned prefix = 0; prefix <= sizeof torn; prefix++) {
        memcpy(torn, a, sizeof torn);
        memcpy(torn, b, prefix);
        int result = select_frames(a, torn, &selected);
        CHECK(result == 0);
        if (memcmp(torn, b, sizeof torn) == 0)
            CHECK(selected.state.generation == 8 && selected.state.pending == 1);
        else
            CHECK(selected.state.generation == 7 && selected.state.pending == 0);
    }
    /* An unreadable other slot is never turned into a checksum failure. */
    struct nlr_card_state_slot slots[2] = {{a, sizeof a, 0}, {b, sizeof b, -1}};
    CHECK(nlr_card_state_select(slots, 8192, &selected) == NLR_CARD_STATE_IO);
    slots[1].read_result = 0;
    slots[1].bytes--;
    CHECK(nlr_card_state_select(slots, 8192, &selected) == NLR_CARD_STATE_IO);
    slots[1].bytes++;
    CHECK(nlr_card_state_select(slots, 8191, &selected) == NLR_CARD_STATE_IO);
    memcpy(torn, b, sizeof torn);
    torn[64] ^= 1;
    CHECK(select_frames(a, torn, &selected) == 0 && selected.state.generation == 7);
    CHECK(select_frames(torn, torn, &selected) == NLR_CARD_STATE_CORRUPT);
    /* Complete unknown/illegal records must pause, even beside valid old
     * data, or they could hide a higher-generation pending record. */
    for (unsigned which = 0; which < 8; which++) {
        memcpy(torn, b, sizeof torn);
        switch (which) {
        case 0: put32(torn + 8, 3); break;
        case 1: torn[36] = 1; break;
        case 2: put32(torn + 24, 2); break;
        case 3: put32(torn + 28, 65); break;
        case 4: memset(torn + 16, 0, 8); break;
        case 5: torn[68] = 1; break;
        case 6: torn[4095] = 1; break;
        case 7: torn[0] = 'X'; break;
        }
        checksum(torn);
        int result = select_frames(a, torn, &selected);
        CHECK(result == NLR_CARD_STATE_UNSUPPORTED || result == NLR_CARD_STATE_CONFLICT);
        CHECK(selected.slot == NLR_CARD_STATE_NO_SLOT);
    }
}

/* Format 2's boot record: its semantics are checked in both directions,
 * and a format 1 record may not carry one. */
static void boot_record_semantics(void)
{
    struct nlr_card_state state;
    struct nlr_card_state_selection selected;
    uint8_t good[4096], frame[4096];
    struct nlr_card_state old = sample(7, 0);
    CHECK(nlr_card_state_encode(&old, good, sizeof good) == 0);
    struct {
        uint32_t mark;
        int32_t result;
        const char *id;
        int valid;
    } cases[] = {
        {NLR_BOOT_MARK_NONE, 0, "", 1},
        {NLR_BOOT_MARK_RUN, 0, "shell", 1},
        {NLR_BOOT_MARK_OK, 0, "shell", 1},
        {NLR_BOOT_MARK_SKIPPED, 0, "shell", 1},
        {NLR_BOOT_MARK_FAILED, -3, "shell", 1},
        {NLR_BOOT_MARK_FAILED, 0, "shell", 0},
        {NLR_BOOT_MARK_RUN, -3, "shell", 0},
        {NLR_BOOT_MARK_OK, 1, "shell", 0},
        {NLR_BOOT_MARK_RUN, 0, "", 0},
        {NLR_BOOT_MARK_NONE, 0, "shell", 0},
        {NLR_BOOT_MARK_NONE, -1, "", 0},
        {NLR_BOOT_MARK_FAILED + 1u, 0, "shell", 0},
        {NLR_BOOT_MARK_RUN, 0, "sh ell", 0},
    };
    for (unsigned n = 0; n < sizeof cases / sizeof cases[0]; n++) {
        state = sample(8, 0);
        state.boot_mark = cases[n].mark;
        state.boot_result = cases[n].result;
        strcpy(state.boot_id, cases[n].id);
        int encoded = nlr_card_state_encode(&state, frame, sizeof frame);
        CHECK((encoded == NLR_CARD_STATE_OK) == cases[n].valid);
        /* The same record forged on the card, with a correct CRC: an
         * illegal one pauses, even beside a valid older slot. */
        state.boot_mark = NLR_BOOT_MARK_NONE;
        state.boot_result = 0;
        state.boot_id[0] = 0;
        CHECK(nlr_card_state_encode(&state, frame, sizeof frame) == 0);
        put32(frame + 0x24, cases[n].mark);
        put32(frame + 0x28, (uint32_t)cases[n].result);
        memcpy(frame + 0x880, cases[n].id, strlen(cases[n].id));
        checksum(frame);
        int result = select_frames(good, frame, &selected);
        if (cases[n].valid) {
            CHECK(result == 0 && selected.slot == 1 && selected.state.boot_mark == cases[n].mark);
            CHECK(strcmp(selected.state.boot_id, cases[n].id) == 0);
        } else {
            CHECK(result == NLR_CARD_STATE_CONFLICT && selected.slot == NLR_CARD_STATE_NO_SLOT);
        }
    }
    /* A 32-byte ID fills its field; padding after it and the tail after
     * the field stay zero; the reserved header words stay zero. */
    state = sample(8, 0);
    state.boot_mark = NLR_BOOT_MARK_RUN;
    memset(state.boot_id, 'B', NLR_MANIFEST_ID_MAX);
    state.boot_id[NLR_MANIFEST_ID_MAX] = 0;
    CHECK(nlr_card_state_encode(&state, frame, sizeof frame) == 0);
    CHECK(select_frames(good, frame, &selected) == 0 && strlen(selected.state.boot_id) == 32);
    for (unsigned which = 0; which < 5; which++) {
        uint8_t forged[4096];
        memcpy(forged, frame, sizeof forged);
        switch (which) {
        case 0: forged[0x880 + 32] = 'B'; break;  /* unterminated ID */
        case 1: forged[0x8a1] = 1; break;         /* tail after the ID */
        case 2: forged[0xfff] = 1; break;
        case 3: forged[0x2c] = 1; break;          /* reserved header */
        case 4: forged[0x3f] = 1; break;
        }
        checksum(forged);
        int result = select_frames(good, forged, &selected);
        CHECK(which >= 3 ? result == NLR_CARD_STATE_UNSUPPORTED
                         : result == NLR_CARD_STATE_CONFLICT);
        CHECK(selected.slot == NLR_CARD_STATE_NO_SLOT);
    }
    /* Format 1 has no boot record: the same bytes under format 1 pause. */
    uint8_t format1[4096];
    memcpy(format1, frame, sizeof format1);
    put32(format1 + 8, 1);
    checksum(format1);
    CHECK(select_frames(good, format1, &selected) == NLR_CARD_STATE_UNSUPPORTED);
    put32(format1 + 0x24, 0);
    checksum(format1);
    CHECK(select_frames(good, format1, &selected) == NLR_CARD_STATE_CONFLICT);
    /* Slot 0 in format 1, slot 1 in format 2: the newer one wins, and the
     * same generation in both formats is a conflict (different bytes). */
    uint8_t older[4096];
    memcpy(older, good, sizeof older);
    put32(older + 8, 1);
    checksum(older);
    CHECK(select_frames(older, frame, &selected) == 0 && selected.slot == 1);
    CHECK(selected.state.boot_mark == NLR_BOOT_MARK_RUN);
    struct nlr_card_state same = sample(7, 0);
    CHECK(nlr_card_state_encode(&same, frame, sizeof frame) == 0);
    CHECK(select_frames(older, frame, &selected) == NLR_CARD_STATE_CONFLICT);
}

static void legacy_guards_are_not_inferred(void)
{
    struct nlr_enabled enabled = {0};
    struct nlr_card_state imported;
    enabled.count = 1;
    strcpy(enabled.id[0], "ext");
    memset(&imported, 0x5a, sizeof imported);
    CHECK(nlr_card_state_import_legacy(&imported, &enabled, 0, 0, 0, 1) == 0);
    CHECK(imported.generation == 0 && imported.pending == 1 && imported.enabled_count == 1);
    CHECK(imported.boot_mark == NLR_BOOT_MARK_NONE && !imported.boot_result && !imported.boot_id[0]);
    CHECK(nlr_card_state_import_legacy(&imported, &enabled, -1, 0, 0, 0) == NLR_CARD_STATE_IO);
    CHECK(nlr_card_state_import_legacy(&imported, &enabled, 0, 0, -1, 0) == NLR_CARD_STATE_IO);
    CHECK(nlr_card_state_import_legacy(&imported, &enabled, 0, 0, 0, 2) == NLR_CARD_STATE_IO);
    CHECK(nlr_card_state_import_legacy(&imported, &enabled, 0, 1, 0, 0) == NLR_CARD_STATE_DISABLED);
    CHECK(nlr_card_state_import_legacy(&imported, 0, 0, 0, 0, 0) == NLR_CARD_STATE_IO);
    enabled.error = NLR_EN_UNKNOWN;
    CHECK(nlr_card_state_import_legacy(&imported, &enabled, 0, 0, 0, 0) == NLR_CARD_STATE_CONFLICT);
}

static void submit_and_confirm(struct nlr_card_state_commit *commit, const uint8_t *frame)
{
    uint8_t readback[NLR_CARD_STATE_SLOT_BYTES];
    memcpy(readback, frame, sizeof readback);
    CHECK(nlr_card_state_commit_submit(commit) == NLR_CARD_STATE_IN_PROGRESS);
    for (unsigned phase = NLR_CARD_STATE_WRITE_INACTIVE;
         phase <= NLR_CARD_STATE_FLUSH_MEDIA; phase++) {
        CHECK(nlr_card_state_commit_ack(commit, (enum nlr_card_state_phase)phase, 0) == NLR_CARD_STATE_IN_PROGRESS);
        CHECK(!nlr_card_state_commit_allows_init(commit));
    }
    CHECK(nlr_card_state_commit_readback(commit, readback, 4096, 0) == 0);
}

static void commits_do_not_guess_completion(void)
{
    struct nlr_card_state current = sample(7, 0), desired = sample(7, 1);
    uint8_t frame[4096], readback[4096];
    struct nlr_card_state_commit commit = {0};
    CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
          NLR_CARD_STATE_ARM_INIT, frame, sizeof frame) == NLR_CARD_STATE_IN_PROGRESS);
    CHECK(commit.target_slot == 1 && commit.generation == 8);
    CHECK(!nlr_card_state_commit_allows_init(&commit));
    CHECK(nlr_card_state_commit_ack(&commit, NLR_CARD_STATE_WRITE_INACTIVE, 0) == NLR_CARD_STATE_CONFLICT);
    memcpy(readback, frame, sizeof frame);
    submit_and_confirm(&commit, readback);
    CHECK(nlr_card_state_commit_allows_init(&commit));
    /* A stale caller cannot reuse its old active generation after commit. */
    CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
          NLR_CARD_STATE_ARM_INIT, frame, sizeof frame) == NLR_CARD_STATE_CONFLICT);
    for (unsigned failed = NLR_CARD_STATE_WRITE_INACTIVE;
         failed <= NLR_CARD_STATE_VERIFY_READBACK; failed++) {
        memset(&commit, 0, sizeof commit);
        CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
              NLR_CARD_STATE_ARM_INIT, frame, sizeof frame) == NLR_CARD_STATE_IN_PROGRESS);
        CHECK(nlr_card_state_commit_submit(&commit) == NLR_CARD_STATE_IN_PROGRESS);
        for (unsigned phase = NLR_CARD_STATE_WRITE_INACTIVE; phase < failed; phase++)
            CHECK(nlr_card_state_commit_ack(&commit, (enum nlr_card_state_phase)phase, 0) == NLR_CARD_STATE_IN_PROGRESS);
        int result = failed == NLR_CARD_STATE_VERIFY_READBACK
            ? nlr_card_state_commit_readback(&commit, frame, 4096, -1)
            : nlr_card_state_commit_ack(&commit, (enum nlr_card_state_phase)failed, -1);
        CHECK(result == NLR_CARD_STATE_COMMIT_UNCERTAIN);
        CHECK(!nlr_card_state_commit_allows_init(&commit));
        CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
              NLR_CARD_STATE_ARM_INIT, frame, sizeof frame) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
    }
    memset(&commit, 0, sizeof commit);
    CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
          NLR_CARD_STATE_ARM_INIT, frame, sizeof frame) == NLR_CARD_STATE_IN_PROGRESS);
    CHECK(nlr_card_state_commit_reject(&commit) == NLR_CARD_STATE_REJECTED);
    CHECK(!nlr_card_state_commit_allows_init(&commit));
    for (unsigned failure = 0; failure < 3; failure++) {
        memset(&commit, 0, sizeof commit);
        CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
              NLR_CARD_STATE_ARM_INIT, frame, sizeof frame) == NLR_CARD_STATE_IN_PROGRESS);
        CHECK(nlr_card_state_commit_submit(&commit) == NLR_CARD_STATE_IN_PROGRESS);
        for (unsigned phase = NLR_CARD_STATE_WRITE_INACTIVE; phase <= NLR_CARD_STATE_FLUSH_MEDIA; phase++)
            CHECK(nlr_card_state_commit_ack(&commit, (enum nlr_card_state_phase)phase, 0) == NLR_CARD_STATE_IN_PROGRESS);
        memcpy(readback, frame, sizeof readback);
        if (failure == 0)
            readback[64] ^= 1;
        const uint8_t *observed = failure == 2 ? frame : readback;
        uint32_t bytes = failure == 1 ? 4095u : 4096u;
        CHECK(nlr_card_state_commit_readback(&commit, observed, bytes, 0) == NLR_CARD_STATE_COMMIT_UNCERTAIN);
        CHECK(!nlr_card_state_commit_allows_init(&commit));
    }
    /* No wrap/restart at generation MAX and no illicit pending change. */
    memset(&commit, 0, sizeof commit);
    current.generation = UINT64_MAX;
    CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
          NLR_CARD_STATE_ARM_INIT, frame, sizeof frame) == NLR_CARD_STATE_GENERATION_EXHAUSTED);
    current = sample(7, 0);
    CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
          NLR_CARD_STATE_SAVE_SETTINGS, frame, sizeof frame) == NLR_CARD_STATE_CONFLICT);
    desired.pending = 0;
    CHECK(nlr_card_state_commit_begin(&commit, &current, 0, &desired,
          NLR_CARD_STATE_SAVE_SETTINGS, frame, sizeof frame) == NLR_CARD_STATE_IN_PROGRESS);
    memcpy(readback, frame, sizeof frame);
    submit_and_confirm(&commit, readback);
    CHECK(!nlr_card_state_commit_allows_init(&commit));
    memset(&commit, 0, sizeof commit);
    desired.generation = 0;
    desired.pending = 1;
    CHECK(nlr_card_state_commit_begin(&commit, 0, NLR_CARD_STATE_NO_SLOT, &desired,
          NLR_CARD_STATE_MIGRATE, frame, sizeof frame) == NLR_CARD_STATE_IN_PROGRESS);
    submit_and_confirm(&commit, frame);
    CHECK(commit.generation == 1 && !nlr_card_state_commit_allows_init(&commit));
    memset(&commit, 0, sizeof commit);
    current = sample(9, 1);
    desired = sample(9, 0);
    CHECK(nlr_card_state_commit_begin(&commit, &current, 1, &desired,
          NLR_CARD_STATE_CLEAR_PENDING, frame, sizeof frame) == NLR_CARD_STATE_IN_PROGRESS);
    submit_and_confirm(&commit, frame);
    CHECK(commit.target_slot == 0 && !nlr_card_state_commit_allows_init(&commit));
}

static struct nlr_card_state with_boot(struct nlr_card_state state, uint32_t mark,
                                       int32_t result, const char *id)
{
    state.boot_mark = mark;
    state.boot_result = result;
    memset(state.boot_id, 0, sizeof state.boot_id);
    strcpy(state.boot_id, id);
    return state;
}

static int begin(const struct nlr_card_state *current, const struct nlr_card_state *desired,
                 enum nlr_card_state_purpose purpose)
{
    struct nlr_card_state_commit commit = {0};
    uint8_t frame[4096];
    return nlr_card_state_commit_begin(&commit, current, 0, desired, purpose,
                                       frame, sizeof frame);
}

/* BOOT_MARK changes nothing but the boot record, outside a pass, along the
 * allowed transitions; every other purpose carries the record unchanged. */
static void boot_mark_commits(void)
{
    const int go = NLR_CARD_STATE_IN_PROGRESS, no = NLR_CARD_STATE_CONFLICT;
    struct nlr_card_state none = sample(7, 0);
    struct nlr_card_state run = with_boot(none, NLR_BOOT_MARK_RUN, 0, "Shell");
    struct nlr_card_state run_other = with_boot(none, NLR_BOOT_MARK_RUN, 0, "other");
    struct nlr_card_state ok = with_boot(none, NLR_BOOT_MARK_OK, 0, "shell");
    struct nlr_card_state ok_other = with_boot(none, NLR_BOOT_MARK_OK, 0, "other");
    struct nlr_card_state skipped = with_boot(none, NLR_BOOT_MARK_SKIPPED, 0, "Shell");
    struct nlr_card_state failed = with_boot(none, NLR_BOOT_MARK_FAILED, -5, "Shell");
    CHECK(begin(&none, &run, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&ok, &run, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&skipped, &run, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&failed, &run, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&run, &run, NLR_CARD_STATE_BOOT_MARK) == no);
    CHECK(begin(&run_other, &run, NLR_CARD_STATE_BOOT_MARK) == no);
    /* skipped after any RUN (the record of a start that never reported) */
    CHECK(begin(&run, &skipped, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&run_other, &skipped, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&none, &skipped, NLR_CARD_STATE_BOOT_MARK) == no);
    CHECK(begin(&ok, &skipped, NLR_CARD_STATE_BOOT_MARK) == no);
    /* outcomes only for the program the RUN names (case folded) */
    CHECK(begin(&run, &ok, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&run, &failed, NLR_CARD_STATE_BOOT_MARK) == go);
    CHECK(begin(&run, &ok_other, NLR_CARD_STATE_BOOT_MARK) == no);
    CHECK(begin(&none, &ok, NLR_CARD_STATE_BOOT_MARK) == no);
    CHECK(begin(&skipped, &failed, NLR_CARD_STATE_BOOT_MARK) == no);
    CHECK(begin(&run, &none, NLR_CARD_STATE_BOOT_MARK) == no);
    /* nothing else may change with it, and never inside a pass */
    struct nlr_card_state changed = run;
    changed.enabled_count = 1;
    CHECK(begin(&none, &changed, NLR_CARD_STATE_BOOT_MARK) == no);
    changed = run;
    changed.pending = 1;
    CHECK(begin(&none, &changed, NLR_CARD_STATE_BOOT_MARK) == no);
    struct nlr_card_state armed = sample(7, 1);
    struct nlr_card_state armed_run = with_boot(armed, NLR_BOOT_MARK_RUN, 0, "Shell");
    CHECK(begin(&armed, &armed_run, NLR_CARD_STATE_BOOT_MARK) == no);
    /* every other purpose keeps the record exactly */
    struct nlr_card_state run_armed = with_boot(sample(7, 1), NLR_BOOT_MARK_RUN, 0, "Shell");
    struct nlr_card_state run_armed_lower = with_boot(sample(7, 1), NLR_BOOT_MARK_RUN, 0, "shell");
    CHECK(begin(&run, &run_armed, NLR_CARD_STATE_ARM_INIT) == go);
    CHECK(begin(&run, &armed, NLR_CARD_STATE_ARM_INIT) == no);
    CHECK(begin(&run, &run_armed_lower, NLR_CARD_STATE_ARM_INIT) == no);
    CHECK(begin(&run_armed, &run, NLR_CARD_STATE_CLEAR_PENDING) == go);
    CHECK(begin(&run_armed, &none, NLR_CARD_STATE_CLEAR_PENDING) == no);
    struct nlr_card_state saved = run;
    saved.enabled_count = 1;
    CHECK(begin(&run, &saved, NLR_CARD_STATE_SAVE_SETTINGS) == go);
    saved = ok;
    saved.enabled_count = 1;
    CHECK(begin(&run, &saved, NLR_CARD_STATE_SAVE_SETTINGS) == no);
    /* the first record never has one */
    struct nlr_card_state first = with_boot(sample(0, 0), NLR_BOOT_MARK_RUN, 0, "Shell");
    struct nlr_card_state_commit commit = {0};
    uint8_t frame[4096];
    CHECK(nlr_card_state_commit_begin(&commit, 0, NLR_CARD_STATE_NO_SLOT, &first,
          NLR_CARD_STATE_MIGRATE, frame, sizeof frame) == no);
    /* a confirmed BOOT_MARK commit is no permission to initialize */
    memset(&commit, 0, sizeof commit);
    CHECK(nlr_card_state_commit_begin(&commit, &none, 0, &run, NLR_CARD_STATE_BOOT_MARK,
          frame, sizeof frame) == go);
    CHECK(nlr_le32(frame + 8) == NLR_CARD_STATE_FORMAT && commit.generation == 8);
    submit_and_confirm(&commit, frame);
    CHECK(commit.phase == NLR_CARD_STATE_CONFIRMED && !nlr_card_state_commit_allows_init(&commit));
    /* A format 1 record migrates with any commit: decoded, it is the
     * current state of a format 2 commit. */
    uint8_t format1[4096];
    struct nlr_card_state decoded;
    CHECK(nlr_card_state_encode(&none, format1, sizeof format1) == 0);
    put32(format1 + 8, 1);
    checksum(format1);
    CHECK(nlr_card_state_decode(format1, sizeof format1, &decoded) == 0);
    memset(&commit, 0, sizeof commit);
    CHECK(nlr_card_state_commit_begin(&commit, &decoded, 0, &run, NLR_CARD_STATE_BOOT_MARK,
          frame, sizeof frame) == go);
    CHECK(nlr_le32(frame + 8) == NLR_CARD_STATE_FORMAT);
}

int main(void)
{
    reference_frame_and_token_grammar();
    selection_and_torn_writes();
    boot_record_semantics();
    legacy_guards_are_not_inferred();
    commits_do_not_guess_completion();
    boot_mark_commits();
    if (failures) {
        fprintf(stderr, "%u card-state checks failed\n", failures);
        return 1;
    }
    puts("card state codec tests passed");
    return 0;
}
