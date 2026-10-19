#include "nlr/native_card_internal.h"

#if NLR_HAS_NATIVE_CARD

extern const struct nlr_identity nlr_identity;

#define STATE_PATH NLR_CARD_ROOT "STATE.NLS"

static int native_result(struct nlr_native_card_request *q, int32_t result)
{
    nlr_native_card_reason(q, (uint32_t)result);
    return result == 0 ? NLR_OK : NLR_IO;
}

static int probe(struct nlr_native_card_runtime *c, struct nlr_native_card_request *q,
                  const char *path, uint32_t *present)
{
    int32_t result = c->services->stat(path, q->stat_data);
    nlr_native_card_reason(q, (uint32_t)result);
    if (result == 0) { *present = 1; return NLR_OK; }
    if ((uint32_t)result == c->services->not_found) { *present = 0; return NLR_OK; }
    return NLR_IO;
}

static int safe_guard(struct nlr_native_card_runtime *c, struct nlr_native_card_request *q)
{
    uint32_t present;
    int result = probe(c, q, NLR_SAFE_MODE_PATH, &present);
    return result != NLR_OK ? result : present ? NLR_DISABLED : NLR_OK;
}

static int read_full(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                      struct nlr_native_card_request *q, int32_t fd,
                      uint8_t *data, uint32_t bytes)
{
    uint32_t total = 0;
    r->load.svc->cache_before_read(data, bytes);
    while (total < bytes) {
        uint32_t received = 0;
        int32_t native = c->services->read(fd, data + total, bytes - total, &received);
        nlr_native_card_reason(q, (uint32_t)native);
        if (native || !received || received > bytes - total)
            return NLR_IO;
        total += received;
    }
    r->load.svc->cache_after_read(data, bytes);
    return NLR_OK;
}

static int seek_exact(struct nlr_native_card_runtime *c,
                       struct nlr_native_card_request *q, int32_t fd, uint32_t offset)
{
    uint32_t position = c->services->seek(fd, (int32_t)offset, NLR_SEEK_SET);
    if (position == offset)
        return NLR_OK;
    nlr_native_card_reason(q, position);
    return NLR_IO;
}

static int read_file(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                      struct nlr_native_card_request *q, const char *path,
                      uint8_t *data, uint32_t capacity, uint32_t *bytes)
{
    int32_t fd = c->services->open(path, 0, 0);
    nlr_native_card_reason(q, (uint32_t)fd);
    if (fd < 0)
        return NLR_IO;
    uint32_t size = c->services->seek(fd, 0, NLR_SEEK_END);
    if (size == UINT32_MAX)
        nlr_native_card_reason(q, size);
    int result = size == UINT32_MAX ? NLR_IO : size > capacity ? NLR_BOUNDS : NLR_OK;
    if (result == NLR_OK)
        result = seek_exact(c, q, fd, 0);
    if (result == NLR_OK && size)
        result = read_full(r, c, q, fd, data, size);
    int32_t closed = c->services->close(fd);
    if (closed && result == NLR_OK)
        result = native_result(q, closed);
    if (result == NLR_OK)
        *bytes = size;
    return result;
}

/* The original decoder supplies valid/data length and NoFatChain separately.
 * An existing logical-sized file is not enough: use the real validated fd,
 * fixed native FCB table, volume and contiguous cluster map as a witness.
 * This does not audit an arbitrarily corrupted allocation bitmap. */
static int qualify(struct nlr_native_card_runtime *c, struct nlr_native_card_request *q,
                     int32_t fd, uint64_t *first_out, uint64_t *last_out)
{
    const struct nlr_native_card_services *s = c->services;
    const struct nlr_native_card_layout *l = &s->layout;
    if (fd < 0 || !l->fcb_volume_stride || !l->fcb_slot_stride)
        return NLR_NOT_READY;
    uint32_t volume = (uint32_t)fd >> 16, slot = (uint32_t)fd & 0xffffu;
    if (volume != q->owner.volume_index || volume >= l->fcb_volume_count ||
        slot >= l->fcb_slot_count)
        return NLR_REFUSED;
    int32_t ready = s->volume_ready((int32_t)volume);
    nlr_native_card_reason(q, (uint32_t)ready);
    if (ready)
        return NLR_NOT_READY;
    void *fcb = 0;
    int32_t raw = s->fcb_get((int32_t)volume, (int32_t)slot, &fcb);
    nlr_native_card_reason(q, (uint32_t)raw);
    uintptr_t expected = (uintptr_t)l->fcb_table + (uintptr_t)volume * l->fcb_volume_stride +
                         (uintptr_t)slot * l->fcb_slot_stride;
    if (raw || (uintptr_t)fcb != expected ||
        !nlr_native_card_ram_span(s, expected, l->fcb_slot_stride))
        return NLR_NOT_READY;
    const uint8_t *p = fcb;
    if (l->fcb_flags_offset >= l->fcb_slot_stride ||
        l->fcb_valid_size_offset > l->fcb_slot_stride - 8u ||
        l->fcb_data_size_offset > l->fcb_slot_stride - 8u ||
        l->fcb_first_cluster_offset > l->fcb_slot_stride - 8u ||
        l->fcb_last_cluster_offset > l->fcb_slot_stride - 8u ||
        l->fcb_no_fat_chain_offset >= l->fcb_slot_stride)
        return NLR_NOT_READY;
    if (!(p[l->fcb_flags_offset] & l->fcb_ready_mask) ||
        (p[l->fcb_flags_offset] & l->fcb_reject_mask) ||
        nlr_native_card_u64(p + l->fcb_valid_size_offset) != NLR_CARD_STATE_FILE_BYTES ||
        nlr_native_card_u64(p + l->fcb_data_size_offset) != NLR_CARD_STATE_FILE_BYTES ||
        p[l->fcb_no_fat_chain_offset] != 1u)
        return NLR_CARD_STATE_UNSUPPORTED;
    uintptr_t ve = (uintptr_t)l->volume_table + (uintptr_t)volume * l->volume_stride;
    if (!nlr_native_card_ram_span(s, ve, l->volume_stride) ||
        l->volume_sector_bytes_offset > l->volume_stride - 2u ||
        l->volume_cluster_sectors_offset > l->volume_stride - 4u)
        return NLR_NOT_READY;
    const uint8_t *v = (const void *)ve;
    uint32_t sector = (uint32_t)v[l->volume_sector_bytes_offset] |
                      (uint32_t)v[l->volume_sector_bytes_offset + 1u] << 8;
    uint32_t sectors = nlr_le32(v + l->volume_cluster_sectors_offset);
    if (!sector || (sector & (sector - 1u)) || !sectors || (sectors & (sectors - 1u)))
        return NLR_CARD_STATE_UNSUPPORTED;
    uint64_t cluster_bytes = (uint64_t)sector * sectors;
    if (cluster_bytes < sector || cluster_bytes > UINT32_MAX)
        return NLR_CARD_STATE_UNSUPPORTED;
    uint64_t first = nlr_native_card_u64(p + l->fcb_first_cluster_offset);
    uint64_t last = nlr_native_card_u64(p + l->fcb_last_cluster_offset);
    uint64_t clusters = (NLR_CARD_STATE_FILE_BYTES + cluster_bytes - 1u) / cluster_bytes;
    if (first < 2u || !clusters || first > UINT64_MAX - clusters + 1u ||
        last != first + clusters - 1u)
        return NLR_CARD_STATE_UNSUPPORTED;
    *first_out = first;
    *last_out = last;
    return NLR_OK;
}

static int snapshot(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                     struct nlr_native_card_request *q)
{
    int result = probe(c, q, STATE_PATH, &q->journal_present);
    if (result != NLR_OK)
        return result;
    if (!q->journal_present)
        return NLR_CARD_STATE_NEEDS_MIGRATION;
    const struct nlr_native_card_layout *l = &c->services->layout;
    if ((q->stat_data[l->stat_attributes_offset] & 0x10u) ||
        nlr_native_card_u64(q->stat_data + l->stat_size_offset) != NLR_CARD_STATE_FILE_BYTES)
        return NLR_CARD_STATE_UNSUPPORTED;
    int32_t fd = c->services->open(STATE_PATH, c->services->journal_read_flags,
                                  c->services->file_mode);
    nlr_native_card_reason(q, (uint32_t)fd);
    if (fd < 0)
        return NLR_IO;
    uint64_t first, last;
    result = qualify(c, q, fd, &first, &last);
    if (result == NLR_OK)
        result = seek_exact(c, q, fd, 0);
    if (result == NLR_OK)
        result = read_full(r, c, q, fd, q->data, sizeof q->data);
    int32_t closed = c->services->close(fd);
    if (closed && result == NLR_OK)
        result = native_result(q, closed);
    if (result != NLR_OK)
        return result;
    struct nlr_card_state_slot slots[2] = {
        {q->data, NLR_CARD_STATE_SLOT_BYTES, 0},
        {q->data + NLR_CARD_STATE_SLOT_BYTES, NLR_CARD_STATE_SLOT_BYTES, 0},
    };
    q->file_bytes = NLR_CARD_STATE_FILE_BYTES;
    return nlr_card_state_select(slots, q->file_bytes, &q->selection);
}

static int read_manifest(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                          struct nlr_native_card_request *q)
{
    uint32_t bytes = 0, listed = UINT32_MAX;
    int result = read_file(r, c, q, NLR_MANIFEST_PATH, q->data, sizeof q->data, &bytes);
    if (result == NLR_IO) {
        /* A card whose programs describe themselves need not carry a
         * MANIFEST. Only the exact native absence
         * reason says it has none; then the names are the loader's own
         * directory -- the described programs it listed, when it has read
         * them -- or none at all (a fresh card's empty selection). */
        uint32_t present = 1;
        if (probe(c, q, NLR_MANIFEST_PATH, &present) != NLR_OK || present)
            return NLR_IO;
        const struct nlr_manifest *d = &r->directory;
        if (r->directory_result == NLR_OK && d->buffer && d->bytes &&
            d->bytes <= sizeof q->data) {
            for (uint32_t n = 0; n < d->bytes; n++)
                q->data[n] = d->buffer[n];
            bytes = d->bytes;
            listed = 0; /* every line is a described or bundled program */
        }
        result = NLR_OK;
    } else if (result == NLR_OK) {
        /* With a MANIFEST, the names are still the loader's directory when
         * that directory was built on this very MANIFEST: it is MANIFEST
         * followed by the described and bundled programs MANIFEST does not
         * name, so an extension that describes itself can be enabled too.
         * A directory read from other MANIFEST bytes (the card changed
         * since) is not used: then only this MANIFEST's names count. */
        const struct nlr_manifest *d = &r->directory;
        uint32_t same = r->directory_result == NLR_OK && d->buffer &&
                        d->bytes > bytes && d->bytes <= sizeof q->data;
        for (uint32_t n = 0; same && n < bytes; n++)
            same = d->buffer[n] == q->data[n];
        if (same && bytes && q->data[bytes - 1u] != '\n')
            same = d->buffer[bytes] == '\n';
        if (same) {
            for (uint32_t n = bytes; n < d->bytes; n++)
                q->data[n] = d->buffer[n];
            listed = bytes;
            bytes = d->bytes;
        }
    }
    if (result != NLR_OK)
        return result;
    /* The loader's own lines may repeat an id as a greyed duplicate; the
     * card's MANIFEST lines may not (nlr_manifest_parse_listed). */
    result = nlr_manifest_parse_listed(&q->manifest, q->data, bytes, listed);
    if (result == NLR_OK) {
        (void)nlr_manifest_hide(&q->manifest);
        nlr_manifest_gate(&q->manifest, nlr_identity.model, nlr_identity.firmware);
    }
    return result;
}

static int legacy(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                   struct nlr_native_card_request *q, struct nlr_card_state *out)
{
    uint32_t pending;
    int result = probe(c, q, NLR_AUTOLOAD_PENDING_PATH, &pending);
    if (result != NLR_OK)
        return result;
    result = read_manifest(r, c, q);
    if (result != NLR_OK)
        return result;
    uint32_t present;
    result = probe(c, q, NLR_ENABLED_PATH, &present);
    if (result != NLR_OK)
        return result;
    uint32_t bytes = 0;
    if (present) {
        result = read_file(r, c, q, NLR_ENABLED_PATH, q->legacy_data,
                           sizeof q->legacy_data, &bytes);
        if (result != NLR_OK)
            return result;
    }
    /* A fresh card has no legacy selection. Only the exact native absence
     * reason permits parsing an empty list; IO never implies absence.
     * The pending marker above remains independent of this list. */
    result = nlr_enabled_parse(&q->legacy, &q->manifest, q->legacy_data, bytes);
    if (result != NLR_OK)
        return result;
    return nlr_card_state_import_legacy(out, &q->legacy, 0, 0, 0, pending);
}

static int validate_desired(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                             struct nlr_native_card_request *q)
{
    int result = read_manifest(r, c, q);
    if (result != NLR_OK)
        return result;
    uint32_t bytes = 0;
    if (q->desired.enabled_count > NLR_MANIFEST_MAX_ENTRIES)
        return NLR_BOUNDS;
    for (uint32_t n = 0; n < q->desired.enabled_count; n++) {
        uint32_t k = 0;
        while (k <= NLR_MANIFEST_ID_MAX && q->desired.enabled_id[n][k]) {
            if (bytes >= sizeof q->legacy_data)
                return NLR_BOUNDS;
            q->legacy_data[bytes++] = (uint8_t)q->desired.enabled_id[n][k++];
        }
        if (!k || k > NLR_MANIFEST_ID_MAX || bytes >= sizeof q->legacy_data)
            return NLR_FORMAT;
        q->legacy_data[bytes++] = '\n';
    }
    result = nlr_enabled_parse(&q->legacy, &q->manifest, q->legacy_data, bytes);
    if (result != NLR_OK)
        return result;
    for (uint32_t n = 0; n < q->legacy.count; n++)
        if (q->manifest.entries[q->legacy.index[n]].gate != NLR_GATE_OK)
            return NLR_REFUSED;
    return NLR_OK;
}

/* The device side of a commit, one rule for every slot: the stock
 * per-slot flush of the slot the card's media entry names, exactly what the
 * filesystem service calls after a stock write. The volume sync before it
 * only writes the filesystem's own buffers to the device; it reaches no
 * device flush. */
static int flush_slot(struct nlr_native_card_runtime *c, struct nlr_native_card_request *q)
{
    int32_t raw = c->services->slot_flush(q->owner.slot);
    nlr_native_card_reason(q, (uint32_t)raw);
    return raw == 0 ? NLR_OK : NLR_IO;
}

static int sync_media(struct nlr_native_card_runtime *c,
                       struct nlr_native_card_request *q)
{
    int32_t raw = c->services->volume_sync(q->volume);
    int result = native_result(q, raw);
    if (result != NLR_OK)
        return result;
    result = nlr_native_card_owner_check(c, q);
    if (result != NLR_OK)
        return result;
    return flush_slot(c, q);
}

static int initialize_file(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                            struct nlr_native_card_request *q)
{
    /* This one-time allocation is separate from slot commits. Once creation
     * has been attempted, any inability to confirm the complete preallocated
     * file is uncertain. No extension is permitted by this step. */
    int ownership = nlr_native_card_owner_check(c, q);
    if (ownership != NLR_OK)
        return ownership;
    int32_t fd = c->services->open(STATE_PATH, c->services->create_flags,
                                  c->services->file_mode);
    nlr_native_card_reason(q, (uint32_t)fd);
    if (fd < 0)
        return NLR_CARD_STATE_COMMIT_UNCERTAIN;
    nlr_native_card_zero(q->data, sizeof q->data);
    uint32_t total = 0;
    int result = NLR_OK;
    while (total < sizeof q->data) {
        uint32_t wrote = 0;
        if (nlr_native_card_owner_check(c, q) != NLR_OK) {
            result = NLR_REFUSED;
            break;
        }
        c->services->clean_source(q->data + total, (uint32_t)sizeof q->data - total);
        int32_t raw = c->services->write(fd, q->data + total,
                                        (uint32_t)sizeof q->data - total, &wrote);
        nlr_native_card_reason(q, (uint32_t)raw);
        if (raw || !wrote || wrote > sizeof q->data - total) {
            result = NLR_IO;
            break;
        }
        total += wrote;
    }
    int32_t closed = c->services->close(fd);
    if (closed && result == NLR_OK)
        result = native_result(q, closed);
    if (result == NLR_OK)
        result = sync_media(c, q);
    if (result == NLR_OK)
        result = snapshot(r, c, q);
    return result == NLR_CARD_STATE_NEEDS_MIGRATION && q->journal_present
        ? NLR_OK : NLR_CARD_STATE_COMMIT_UNCERTAIN;
}

static int commit(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                   struct nlr_native_card_request *q)
{
    int result = snapshot(r, c, q);
    if (q->purpose == NLR_CARD_STATE_MIGRATE) {
        if (result != NLR_CARD_STATE_NEEDS_MIGRATION)
            return result == NLR_OK ? NLR_CARD_STATE_CONFLICT : result;
        result = legacy(r, c, q, &q->selection.state);
        if (result != NLR_OK)
            return result;
        /* The boot snapshot cannot be replaced by later legacy edits during
         * bootstrap. The caller's proposal and the freshly checked input
         * must refer to the same pending state and ordered IDs. */
        /* Generation-zero proposals are intentionally not encodable until
         * commit_begin assigns the first generation; compare their payload
         * directly through the validated parser results below. */
        if (q->desired.pending != q->selection.state.pending ||
            q->desired.enabled_count != q->selection.state.enabled_count)
            return NLR_CARD_STATE_CONFLICT;
        for (uint32_t n = 0; n < q->desired.enabled_count; n++)
            for (uint32_t k = 0; k <= NLR_MANIFEST_ID_MAX; k++)
                if (q->desired.enabled_id[n][k] != q->selection.state.enabled_id[n][k])
                    return NLR_CARD_STATE_CONFLICT;
        if (!q->journal_present) {
            result = initialize_file(r, c, q);
            if (result != NLR_OK)
                return result;
        }
        result = nlr_card_state_commit_begin(&q->commit, 0, NLR_CARD_STATE_NO_SLOT,
                    &q->desired, NLR_CARD_STATE_MIGRATE, q->candidate, sizeof q->candidate);
    } else {
        if (result != NLR_OK)
            return result;
        if (!c->state_valid || q->selection.state.generation != c->current.generation)
            return NLR_CARD_STATE_CONFLICT;
        result = validate_desired(r, c, q);
        if (result != NLR_OK)
            return result;
        result = nlr_card_state_commit_begin(&q->commit, &q->selection.state, q->selection.slot,
                    &q->desired, (enum nlr_card_state_purpose)q->purpose,
                    q->candidate, sizeof q->candidate);
    }
    if (result != NLR_CARD_STATE_IN_PROGRESS)
        return result;
    int32_t fd = c->services->open(STATE_PATH, c->services->write_flags,
                                  c->services->file_mode);
    nlr_native_card_reason(q, (uint32_t)fd);
    if (fd < 0)
        return NLR_IO;
    uint64_t first, last;
    result = qualify(c, q, fd, &first, &last);
    uint32_t offset = q->commit.target_slot * NLR_CARD_STATE_SLOT_BYTES;
    if (result == NLR_OK)
        result = seek_exact(c, q, fd, offset);
    if (result == NLR_OK)
        result = nlr_native_card_owner_check(c, q);
    if (result != NLR_OK) {
        c->services->close(fd);
        nlr_card_state_commit_reject(&q->commit);
        return result;
    }
    nlr_card_state_commit_submit(&q->commit);
    uint32_t total = 0;
    while (total < sizeof q->candidate) {
        uint32_t wrote = 0;
        if (nlr_native_card_owner_check(c, q) != NLR_OK) {
            c->services->close(fd);
            return nlr_card_state_commit_ack(&q->commit, NLR_CARD_STATE_WRITE_INACTIVE, NLR_IO);
        }
        c->services->clean_source(q->candidate + total, (uint32_t)sizeof q->candidate - total);
        int32_t raw = c->services->write(fd, q->candidate + total,
                                        (uint32_t)sizeof q->candidate - total, &wrote);
        nlr_native_card_reason(q, (uint32_t)raw);
        if (raw || !wrote || wrote > sizeof q->candidate - total) {
            c->services->close(fd);
            return nlr_card_state_commit_ack(&q->commit, NLR_CARD_STATE_WRITE_INACTIVE, NLR_IO);
        }
        total += wrote;
    }
    result = nlr_card_state_commit_ack(&q->commit, NLR_CARD_STATE_WRITE_INACTIVE, NLR_OK);
    int32_t closed = c->services->close(fd);
    if (closed)
        return nlr_card_state_commit_ack(&q->commit, NLR_CARD_STATE_SYNC_FILE, native_result(q, closed));
    int32_t raw = c->services->volume_sync(q->volume);
    result = nlr_card_state_commit_ack(&q->commit, NLR_CARD_STATE_SYNC_FILE, native_result(q, raw));
    if (result != NLR_CARD_STATE_IN_PROGRESS)
        return result;
    if (nlr_native_card_owner_check(c, q) != NLR_OK)
        return nlr_card_state_commit_ack(&q->commit, NLR_CARD_STATE_FLUSH_MEDIA, NLR_IO);
    result = nlr_card_state_commit_ack(&q->commit, NLR_CARD_STATE_FLUSH_MEDIA, flush_slot(c, q));
    if (result != NLR_CARD_STATE_IN_PROGRESS)
        return result;
    fd = c->services->open(STATE_PATH, c->services->journal_read_flags,
                           c->services->file_mode);
    nlr_native_card_reason(q, (uint32_t)fd);
    if (fd < 0)
        return nlr_card_state_commit_readback(&q->commit, 0, 0, NLR_IO);
    uint64_t after_first, after_last;
    result = qualify(c, q, fd, &after_first, &after_last);
    if (result == NLR_OK && (first != after_first || last != after_last))
        result = NLR_REFUSED;
    if (result == NLR_OK)
        result = seek_exact(c, q, fd, offset);
    if (result == NLR_OK)
        result = read_full(r, c, q, fd, q->readback, sizeof q->readback);
    closed = c->services->close(fd);
    if (closed && result == NLR_OK)
        result = native_result(q, closed);
    return nlr_card_state_commit_readback(&q->commit, q->readback, sizeof q->readback, result);
}

/* The loader's own directory on the mounted card: its root path without
 * the final separator, asked of the filesystem by the exact absence reason.
 * A card without it holds no SAFE_MODE, no state and no programs of the
 * loader's, and a snapshot says so instead of proposing to create one. */
static int root_directory(struct nlr_native_card_runtime *c,
                          struct nlr_native_card_request *q)
{
    uint32_t n = 0;
    while (NLR_CARD_ROOT[n + 1u] && n + 1u < sizeof q->path) {
        q->path[n] = NLR_CARD_ROOT[n];
        n++;
    }
    q->path[n] = 0;
    uint32_t present = 0;
    int result = probe(c, q, q->path, &present);
    if (result != NLR_OK)
        return result;
    const struct nlr_native_card_layout *l = &c->services->layout;
    return present && (q->stat_data[l->stat_attributes_offset] & 0x10u)
        ? NLR_OK : NLR_CARD_STATE_NO_DIRECTORY;
}

int nlr_native_card_state_execute(struct nlr_runtime *r,
                                   struct nlr_native_card_runtime *c,
                                   struct nlr_native_card_request *q)
{
    int result = root_directory(c, q);
    if (result != NLR_OK)
        return result;
    result = safe_guard(c, q);
    if (result != NLR_OK)
        return result;
    if (q->operation == NLR_NATIVE_CARD_COMMIT)
        return commit(r, c, q);
    result = snapshot(r, c, q);
    if (result == NLR_CARD_STATE_NEEDS_MIGRATION) {
        result = legacy(r, c, q, &q->desired);
        return result == NLR_OK ? NLR_CARD_STATE_NEEDS_MIGRATION : result;
    }
    return result;
}

#endif
