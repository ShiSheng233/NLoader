#include "nlr/native_card_internal.h"
#include "nlr/time.h"

#if NLR_HAS_NATIVE_CARD

extern const struct nlr_services nlr_services;
extern const struct nlr_native_card_services nlr_native_card_services;

#define NLR_NATIVE_CARD_MAGIC 0x3152434eu /* NCR1, not a firmware pin */
#define NLR_NATIVE_CARD_VERSION 1u

void nlr_native_card_copy(void *out, const void *in, uint32_t bytes)
{
    uint8_t *to = out;
    const uint8_t *from = in;
    for (uint32_t n = 0; n < bytes; n++)
        to[n] = from[n];
}

void nlr_native_card_zero(void *out, uint32_t bytes)
{
    uint8_t *to = out;
    for (uint32_t n = 0; n < bytes; n++)
        to[n] = 0;
}

uint64_t nlr_native_card_u64(const uint8_t *in)
{
    return (uint64_t)nlr_le32(in) | (uint64_t)nlr_le32(in + 4) << 32;
}

static uint16_t u16(const uint8_t *in)
{
    return (uint16_t)((uint16_t)in[0] | (uint16_t)in[1] << 8);
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

int nlr_native_card_ram_span(const struct nlr_native_card_services *s,
                              uintptr_t address, uint32_t bytes)
{
    return s && bytes && address >= s->layout.runtime_ram_start &&
           address < s->layout.runtime_ram_end &&
           bytes <= s->layout.runtime_ram_end - address;
}

void nlr_native_card_reason(struct nlr_native_card_request *q, uint64_t reason)
{
    q->native_reason = reason;
}

static const uint8_t *at(const struct nlr_native_card_services *s,
                         uintptr_t base, uint32_t offset, uint32_t bytes)
{
    if (offset > UINTPTR_MAX - base)
        return 0;
    uintptr_t address = base + offset;
    return nlr_native_card_ram_span(s, address, bytes) ? (const uint8_t *)address : 0;
}

static int services_complete(const struct nlr_native_card_services *s)
{
    return s && s->claim && s->submit_frame && s->callback_table &&
           s->callback_slot == 0 && s->request_bytes == NLR_NATIVE_CARD_FRAME_BYTES &&
           s->request_volume_offset == 8u && s->request_user_offset == 0x100u &&
           s->request_callback_offset == 0x108u && s->request_operation_offset == 0x10cu &&
           s->request_result_offset == 0x110u && s->request_priority_offset == 0xf0u &&
           s->operation == 31u &&
           s->mutex && s->lock && s->unlock && s->open && s->read &&
           s->write && s->seek && s->close && s->stat && s->volume_sync &&
           s->volume_index && s->volume_ready && s->slot_flush && s->fcb_get && s->clean_source &&
           s->rpc.wait_callee && s->rpc.reply_flag && s->rpc.shared_frame &&
           s->low_unmount && s->volume_lock && s->volume_unlock &&
           s->journal_read_flags == 2u &&
           s->stat_bytes == NLR_NATIVE_CARD_STAT_BYTES &&
           s->layout.stat_size_offset <= s->stat_bytes - 8u &&
           s->layout.stat_attributes_offset < s->stat_bytes &&
           s->layout.volume_count && s->layout.media_count && s->layout.slot_count &&
           s->layout.volume_stride && s->layout.media_stride;
}

/* The card the loader's root names, by one rule for every slot.
 *
 * The root's drive letter names the volume (the stock lookup by name: the
 * volume index is whichever volume entry the slot was bound to, first free
 * at mount, so it is not the slot number), the volume must be mounted and
 * exFAT, and its device field must point at one of the media entries.
 * That media entry carries the stock slot, which selects the slot's own
 * flush. The card is the same card while NLoader has observed no mount or
 * unmount of this volume (the epoch, counted by the lifecycle hooks), the
 * volume index is the same and the volume is bound to the same media
 * entry. No driver-specific object is followed: the slot's device is the
 * stock filesystem's business, as it is for every stock write. */
int nlr_native_card_owner_read(struct nlr_native_card_runtime *c,
                               struct nlr_native_card_owner *owner)
{
    const struct nlr_native_card_services *s = c->services;
    const struct nlr_native_card_layout *l = &s->layout;
    char volume[3] = {NLR_CARD_ROOT[0], ':', 0};
    int32_t index = s->volume_index(volume);
    if (index < 0 || (uint32_t)index >= l->volume_count)
        return NLR_NOT_READY;
    int32_t ready = s->volume_ready(index);
    if (ready != 0)
        return NLR_NOT_READY;
    uintptr_t entry = (uintptr_t)l->volume_table + (uintptr_t)(uint32_t)index * l->volume_stride;
    const uint8_t *state = at(s, entry, l->volume_state_offset, 1);
    const uint8_t *type = at(s, entry, l->volume_type_offset, 1);
    const uint8_t *device_field = at(s, entry, l->volume_device_offset, 8);
    if (!state || !type || !device_field || state[0] != 1u ||
        type[0] != l->exfat_type)
        return NLR_NOT_READY;
    uintptr_t device = (uintptr_t)nlr_native_card_u64(device_field);
    uintptr_t media_table = (uintptr_t)l->media_table;
    if (device < media_table || (device - media_table) % l->media_stride ||
        (device - media_table) / l->media_stride >= l->media_count)
        return NLR_NOT_READY;
    /* The media entry's slot, a stock u16 that the slot's own driver and
     * the stock per-slot flush index by; a slot outside the stock slot
     * table is no card of this layout. */
    const uint8_t *slot = at(s, device, l->media_slot_offset, 2);
    if (!slot || u16(slot) >= l->slot_count)
        return NLR_NOT_READY;
    owner->epoch = __atomic_load_n(&c->epoch, __ATOMIC_ACQUIRE);
    owner->volume_index = (uint32_t)index;
    owner->slot = u16(slot);
    owner->device = device;
    return NLR_OK;
}

static int same_owner(const struct nlr_native_card_owner *a,
                       const struct nlr_native_card_owner *b)
{
    return a->epoch == b->epoch && a->volume_index == b->volume_index &&
           a->slot == b->slot && a->device == b->device;
}

int nlr_native_card_owner_check(struct nlr_native_card_runtime *c,
                                struct nlr_native_card_request *q)
{
    if (__atomic_load_n(&c->uncertain, __ATOMIC_ACQUIRE))
        return NLR_CARD_STATE_COMMIT_UNCERTAIN;
    if (__atomic_load_n(&c->changed, __ATOMIC_ACQUIRE))
        return NLR_REFUSED;
    if (__atomic_load_n(&c->transitions, __ATOMIC_ACQUIRE))
        return NLR_NOT_READY;
    int result = nlr_native_card_owner_read(c, &q->owner);
    if (result != NLR_OK)
        return result;
    if (__atomic_load_n(&c->transitions, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&c->epoch, __ATOMIC_ACQUIRE) != q->owner.epoch)
        return NLR_NOT_READY;
    if (__atomic_load_n(&c->bound, __ATOMIC_ACQUIRE) && !same_owner(&c->owner, &q->owner)) {
        __atomic_store_n(&c->changed, 1u, __ATOMIC_RELEASE);
        return NLR_REFUSED;
    }
    if (!__atomic_load_n(&c->bound, __ATOMIC_ACQUIRE)) {
        nlr_native_card_copy(&c->owner, &q->owner, (uint32_t)sizeof c->owner);
        __atomic_store_n(&c->bound, 1u, __ATOMIC_RELEASE);
    }
    if (__atomic_load_n(&c->transitions, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&c->epoch, __ATOMIC_ACQUIRE) != q->owner.epoch) {
        __atomic_store_n(&c->changed, 1u, __ATOMIC_RELEASE);
        return NLR_REFUSED;
    }
    return NLR_OK;
}

static int card_task_start(struct nlr_runtime *r, struct nlr_native_card_runtime *c);

int nlr_native_card_attach(struct nlr_runtime *r)
{
    if (!r || !r->load.svc ||
        !r->load.svc->cache_before_read || !r->load.svc->cache_after_read ||
        !services_complete(r->load.svc->native_card))
        return NLR_NOT_READY;
    if (r->native_card)
        return r->native_card->attach_result;
    const struct nlr_native_card_services *s = r->load.svc->native_card;
    if (!nlr_native_card_ram_span(s, (uintptr_t)s->callback_table, 8u))
        return NLR_NOT_READY;
    if (!nlr_native_card_ram_span(s, (uintptr_t)s->rpc.reply_flag, 4u) ||
        !nlr_native_card_ram_span(s, (uintptr_t)s->rpc.shared_frame, s->request_bytes))
        return NLR_NOT_READY;
    uint32_t bytes = (uint32_t)sizeof(struct nlr_native_card_runtime) + NLR_CACHE_LINE - 1u;
    void *allocation = nlr_alloc_whole(r->load.svc, bytes);
    if (!allocation)
        return NLR_NOT_READY;
    uintptr_t aligned = ((uintptr_t)allocation + NLR_CACHE_LINE - 1u) &
                         ~(uintptr_t)(NLR_CACHE_LINE - 1u);
    struct nlr_native_card_runtime *c = (void *)aligned;
    nlr_native_card_zero(c, (uint32_t)sizeof *c);
    c->allocation = allocation;
    c->services = s;
    c->active_slot = NLR_CARD_STATE_NO_SLOT;
    c->attach_result = NLR_NOT_READY;
    r->native_card = c;
    /* The claim does not submit a filesystem call. Never hold this mutex
     * across submit_frame: the real FILESRV callback must acquire it. */
    s->lock(s->mutex);
    int claimed = 0;
    if (!s->callback_table[s->callback_slot]) {
        int32_t result = s->claim(nlr_native_card_transaction);
        claimed = result == 0 &&
            s->callback_table[s->callback_slot] == nlr_native_card_transaction;
    }
    s->unlock(s->mutex);
    /* Requests are only ever submitted by the card task: no task, no card. */
    if (claimed) {
        c->claimed = 1;
        if (card_task_start(r, c))
            c->attach_result = NLR_OK;
    }
    return c->attach_result;
}

int nlr_native_card_uncertain(const struct nlr_runtime *r)
{
    return r && r->native_card &&
           (__atomic_load_n(&r->native_card->uncertain, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&r->native_card->changed, __ATOMIC_ACQUIRE));
}

int nlr_native_card_status(const struct nlr_runtime *r)
{
    if (!r || !r->native_card)
        return NLR_OK;
    if (__atomic_load_n(&r->native_card->uncertain, __ATOMIC_ACQUIRE))
        return NLR_CARD_STATE_COMMIT_UNCERTAIN;
    return __atomic_load_n(&r->native_card->changed, __ATOMIC_ACQUIRE) ? NLR_REFUSED : NLR_OK;
}

static int acquire_once(struct nlr_runtime *r)
{
    int result = nlr_native_card_attach(r);
    if (result != NLR_OK)
        return result;
    struct nlr_native_card_runtime *c = r->native_card;
    if (nlr_native_card_uncertain(r))
        return nlr_native_card_status(r);
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&c->busy, &expected, 1u, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return NLR_BUSY;
    return NLR_OK;
}

/* The one request, taken by the card task (and only by it) for the ticket
 * it serves: see "The card task" below. */
int nlr_native_card_acquire(struct nlr_runtime *r, uint32_t operation)
{
    int result = acquire_once(r);
    if (result != NLR_OK)
        return result;
    struct nlr_native_card_runtime *c = r->native_card;
    if (c->sequence == UINT64_MAX ||
        c->services->callback_table[c->services->callback_slot] != nlr_native_card_transaction) {
        __atomic_store_n(&c->uncertain, 1u, __ATOMIC_RELEASE);
        return NLR_CARD_STATE_COMMIT_UNCERTAIN;
    }
    struct nlr_native_card_request *q = &c->request;
    nlr_native_card_zero(q, (uint32_t)sizeof *q);
    q->magic = NLR_NATIVE_CARD_MAGIC;
    q->version = NLR_NATIVE_CARD_VERSION;
    q->bytes = (uint32_t)sizeof *q;
    q->sequence = ++c->sequence;
    q->operation = operation;
    q->result = NLR_NOT_READY;
    q->volume[0] = NLR_CARD_ROOT[0];
    q->volume[1] = ':';
    return NLR_OK;
}

void nlr_native_card_release(struct nlr_runtime *r)
{
    if (r && r->native_card && !nlr_native_card_uncertain(r))
        __atomic_store_n(&r->native_card->busy, 0u, __ATOMIC_RELEASE);
}

int nlr_native_card_submit(struct nlr_runtime *r)
{
    struct nlr_native_card_runtime *c = r->native_card;
    struct nlr_native_card_request *q = &c->request;
    const struct nlr_native_card_services *s = c->services;
    put32(q->native_frame, 1u); /* original family reply-mask field */
    put64(q->native_frame + s->request_volume_offset, (uintptr_t)q->volume);
    put64(q->native_frame + s->request_user_offset, (uintptr_t)q);
    put32(q->native_frame + s->request_callback_offset, s->callback_slot);
    put32(q->native_frame + s->request_operation_offset, s->operation);
    put32(q->native_frame + s->request_priority_offset, 0u);
    __atomic_store_n(&q->state, NLR_NATIVE_CARD_REQUEST_QUEUED, __ATOMIC_RELEASE);
    q->native_submit_result = s->submit_frame(q->native_frame);
    if (q->native_submit_result != 0 ||
        (__atomic_load_n(&q->native_reply_bits, __ATOMIC_ACQUIRE) & 1u) != 1u ||
        __atomic_load_n(&q->state, __ATOMIC_ACQUIRE) != NLR_NATIVE_CARD_REQUEST_DONE ||
        q->sequence != c->sequence) {
        __atomic_store_n(&q->state, NLR_NATIVE_CARD_REQUEST_UNCERTAIN, __ATOMIC_RELEASE);
        __atomic_store_n(&c->uncertain, 1u, __ATOMIC_RELEASE);
        return NLR_CARD_STATE_COMMIT_UNCERTAIN;
    }
    if (q->result == NLR_CARD_STATE_COMMIT_UNCERTAIN)
        __atomic_store_n(&c->uncertain, 1u, __ATOMIC_RELEASE);
    return q->result;
}

int32_t nlr_native_card_reply_observe(void *flag, uint32_t mask, uint32_t *out_bits)
{
    /* Preserve the original wait, including its normalization and output.
     * The audited kernel writes nonzero matching output only after a real
     * match; the stock caller initialized this output to zero beforehand. */
    int32_t original = nlr_native_card_services.rpc.wait_callee(flag, mask, out_bits);
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || !r->native_card || !out_bits)
        return original;
    struct nlr_native_card_runtime *c = r->native_card;
    const struct nlr_native_card_services *s = c->services;
    struct nlr_native_card_request *q = &c->request;
    const uint8_t *frame = s->rpc.shared_frame;
    if (flag != s->rpc.reply_flag || mask != 1u || (*out_bits & mask) != mask ||
        !nlr_native_card_ram_span(s, (uintptr_t)frame, s->request_bytes) ||
        q->magic != NLR_NATIVE_CARD_MAGIC || q->version != NLR_NATIVE_CARD_VERSION ||
        q->bytes != sizeof *q ||
        !__atomic_load_n(&c->busy, __ATOMIC_ACQUIRE) || q->sequence != c->sequence ||
        __atomic_load_n(&q->state, __ATOMIC_ACQUIRE) != NLR_NATIVE_CARD_REQUEST_DONE ||
        nlr_native_card_u64(frame + s->request_user_offset) != (uintptr_t)q ||
        nlr_native_card_u64(frame + s->request_volume_offset) != (uintptr_t)q->volume ||
        nlr_le32(frame + s->request_operation_offset) != s->operation ||
        nlr_le32(frame + s->request_callback_offset) != s->callback_slot ||
        nlr_le32(frame + s->request_priority_offset) != 0u)
        return original;
    __atomic_store_n(&q->native_reply_bits, *out_bits, __ATOMIC_RELEASE);
    return original;
}

/* The card's DCIM (ABI 9): a path on the loader's own drive -- the root up
 * to its first separator -- followed by "DCIM\\" and a name. The number of
 * bytes of that prefix, or 0 for any other path. */
static uint32_t media_prefix(const char *path)
{
    static const char dir[] = "DCIM\\";
    uint32_t drive = 0;
    while (NLR_CARD_ROOT[drive] && NLR_CARD_ROOT[drive] != '\\')
        drive++;
    if (!NLR_CARD_ROOT[drive])
        return 0;
    drive++;
    for (uint32_t n = 0; n < drive; n++)
        if (path[n] != NLR_CARD_ROOT[n])
            return 0;
    for (uint32_t n = 0; n < sizeof dir - 1u; n++)
        if (path[drive + n] != dir[n])
            return 0;
    return drive + (uint32_t)sizeof dir - 1u;
}

/* A path the card is asked about: below the loader's root, or -- with
 * `media`, for opening to read only -- below the card's DCIM. */
static int path_in(char out[NLR_NATIVE_CARD_PATH_BYTES], const char *path, int media)
{
    if (!path)
        return NLR_BOUNDS;
    uint32_t length = 0;
    while (length < NLR_NATIVE_CARD_PATH_BYTES && path[length])
        length++;
    if (length == NLR_NATIVE_CARD_PATH_BYTES)
        return NLR_BOUNDS;
    uint32_t n = 0;
    while (n < sizeof NLR_CARD_ROOT - 1u && path[n] == NLR_CARD_ROOT[n])
        n++;
    if (n != sizeof NLR_CARD_ROOT - 1u || !path[n]) {
        n = media ? media_prefix(path) : 0u;
        if (!n || !path[n])
            return NLR_REFUSED;
    }
    uint32_t component = n;
    for (uint32_t k = n; k <= length; k++) {
        if (path[k] == ':')
            return NLR_BOUNDS;
        if (!path[k] || path[k] == '/' || path[k] == '\\') {
            uint32_t bytes = k - component;
            if (!bytes || (bytes <= 2u && path[component] == '.' &&
                           (bytes == 1u || path[component + 1u] == '.')))
                return NLR_BOUNDS;
            component = k + 1u;
        }
    }
    uint32_t k = 0;
    do { out[k] = path[k]; } while (path[k++] && k < NLR_NATIVE_CARD_PATH_BYTES);
    return NLR_OK;
}

static int request_path_in(struct nlr_native_card_request *q, const char *path,
                           int media)
{
    return path_in(q->path, path, media);
}

static int request_path(struct nlr_native_card_request *q, const char *path)
{
    return request_path_in(q, path, 0);
}

_Static_assert(sizeof(((struct nlr_native_card_request *)0)->data) >=
                   2u * NLR_NATIVE_CARD_READ_ALIGN,
               "a read past the widest head still delivers at least one byte");
_Static_assert(sizeof(((struct nlr_native_card_request *)0)->data) % NLR_CACHE_LINE == 0,
               "line maintenance over the read buffer stays inside it");
_Static_assert((NLR_NATIVE_CARD_READ_ALIGN & (NLR_NATIVE_CARD_READ_ALIGN - 1u)) == 0,
               "the read alignment is a power of two");

/* One read request, by one rule for every slot: the low-level read always
 * starts at an aligned file position, into the start of the request's own
 * buffer.
 *
 * On the Z 8 with an SD card in B:, every read that started inside a
 * sector came back with zeros right after the bytes of that first partial
 * sector -- the 512 to 640 bytes of the request's buffer that follow them
 * -- while the file on the card was intact, and every read that started on
 * a sector came back whole (build/z8-c-20261017/sd-diag). The zeros began
 * at the first cache line the processor had not written while copying the
 * partial sector in, not at a sector boundary: stale lines in front of the
 * card's transfer, which the after-read maintenance bound on that body (a
 * clean, not an invalidate) does not drop. A read that starts on a sector
 * puts no processor copy in front of the transfer, so the read never
 * starts inside one; and after the transfer the buffer is cleaned and then
 * invalidated, which drops such lines whatever filled them (the general
 * rule; the alignment is the defence the body's correct reads match). The
 * position is asked for in
 * the same transaction, the bytes below it are read again and dropped,
 * and the position is left where the caller's read would have left it:
 * after the bytes delivered. A position the low-level seek does not
 * confirm is an I/O error, never a guess. The answer is short only when
 * the buffer ran out (at_end 0: the caller asks again) or the file ended
 * (at_end 1). */
static int read_aligned(struct nlr_runtime *r, const struct nlr_native_card_services *s,
                        struct nlr_native_card_request *q)
{
    uint32_t position = s->seek(q->fd, 0, NLR_NATIVE_CARD_SEEK_CUR);
    if (position == UINT32_MAX) {
        nlr_native_card_reason(q, UINT32_MAX);
        return NLR_IO;
    }
    uint32_t head = position & (NLR_NATIVE_CARD_READ_ALIGN - 1u);
    uint32_t start = position - head;
    uint32_t wanted = q->count < sizeof q->data - head ? q->count
                                                       : (uint32_t)sizeof q->data - head;
    if (head) {
        uint32_t at = s->seek(q->fd, -(int32_t)head, NLR_NATIVE_CARD_SEEK_CUR);
        if (at != start) {
            nlr_native_card_reason(q, at);
            return NLR_IO;
        }
    }
    uint32_t span = head + wanted, got = 0;
    r->load.svc->cache_before_read(q->data, span);
    int32_t native = s->read(q->fd, q->data, span, &got);
    /* After the transfer: the bound after-read maintenance (a clean on the
     * Z 8) writes back what the processor itself put into the buffer (the
     * partial sectors the filesystem copies), then the before-read
     * invalidate drops every line of the buffer, including any the cache
     * filled while the card's transfer was in flight; the bytes copied out
     * below are then the ones in memory. q->data is line-aligned and a
     * whole number of lines, so neither operation reaches another field. */
    r->load.svc->cache_after_read(q->data, span);
    r->load.svc->cache_before_read(q->data, span);
    nlr_native_card_reason(q, (uint32_t)native);
    if (native != 0 || got > span)
        return NLR_IO;
    uint32_t delivered = got > head ? got - head : 0;
    if (head) {
        /* After the read the file is at start + got; the caller's read
         * leaves it after the bytes delivered (the same place unless the
         * position was past the end of the file). */
        uint32_t target = position + delivered;
        uint32_t at = s->seek(q->fd, (int32_t)(target - (start + got)), NLR_NATIVE_CARD_SEEK_CUR);
        if (at != target) {
            nlr_native_card_reason(q, at);
            return NLR_IO;
        }
    }
    q->data_offset = head;
    q->transferred = delivered;
    q->at_end = got < span;
    return NLR_OK;
}

static int execute_file(struct nlr_runtime *r, struct nlr_native_card_runtime *c,
                         struct nlr_native_card_request *q)
{
    const struct nlr_native_card_services *s = c->services;
    int32_t native;
    if (q->operation == NLR_NATIVE_CARD_PROBE || q->operation == NLR_NATIVE_CARD_OPEN) {
        /* checked again on this side; only an open to read reaches DCIM */
        int result = request_path_in(q, q->path,
                                     q->operation == NLR_NATIVE_CARD_OPEN && !q->open_flags);
        if (result != NLR_OK)
            return result;
    } else if (q->fd < 0 || (uint32_t)q->fd >> 16 != q->owner.volume_index) {
        return NLR_REFUSED;
    }
    switch (q->operation) {
    case NLR_NATIVE_CARD_PROBE:
        native = s->stat(q->path, q->stat_data);
        nlr_native_card_reason(q, (uint32_t)native);
        if (native == 0) { q->present = 1; return NLR_OK; }
        if ((uint32_t)native == s->not_found) { q->present = 0; return NLR_OK; }
        return NLR_IO;
    case NLR_NATIVE_CARD_OPEN:
        /* Reading keeps the plain mode the loader always used. A program's
         * write access may ask only for the two modes the state file
         * already uses on this filesystem, with that file's mode word:
         * nothing else reaches the low-level open. */
        if (q->open_flags && q->open_flags != s->write_flags &&
            q->open_flags != s->create_flags)
            return NLR_BOUNDS;
        native = s->open(q->path, q->open_flags, q->open_flags ? s->file_mode : 0);
        nlr_native_card_reason(q, (uint32_t)native);
        q->fd = native;
        return native < 0 || (uint32_t)native >> 16 != q->owner.volume_index ? NLR_IO : NLR_OK;
    case NLR_NATIVE_CARD_READ:
        if (!q->count || q->count > sizeof q->data || q->fd < 0)
            return NLR_BOUNDS;
        return read_aligned(r, s, q);
    case NLR_NATIVE_CARD_SEEK:
        q->transferred = s->seek(q->fd, q->offset, q->whence);
        nlr_native_card_reason(q, q->transferred == UINT32_MAX ? UINT32_MAX : 0);
        return q->transferred == UINT32_MAX ? NLR_IO : NLR_OK;
    case NLR_NATIVE_CARD_CLOSE:
        native = s->close(q->fd);
        nlr_native_card_reason(q, (uint32_t)native);
        return native == 0 ? NLR_OK : NLR_IO;
    case NLR_NATIVE_CARD_WRITE:
        if (!q->count || q->count > sizeof q->data)
            return NLR_BOUNDS;
        /* The bytes leave the request's own buffer, which the card's DMA
         * may fetch directly: the same clean the state file's writes use. */
        s->clean_source(q->data, q->count);
        native = s->write(q->fd, q->data, q->count, &q->transferred);
        nlr_native_card_reason(q, (uint32_t)native);
        return native != 0 || q->transferred > q->count ? NLR_IO : NLR_OK;
    default: return NLR_NOT_READY;
    }
}

void nlr_native_card_transaction(void *userptr)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || !r->native_card || userptr != &r->native_card->request)
        return; /* reject before ever reading an arbitrary user header */
    struct nlr_native_card_runtime *c = r->native_card;
    struct nlr_native_card_request *q = userptr;
    if (q->magic != NLR_NATIVE_CARD_MAGIC || q->version != NLR_NATIVE_CARD_VERSION ||
        q->bytes != sizeof *q || q->sequence != c->sequence ||
        __atomic_load_n(&q->state, __ATOMIC_ACQUIRE) != NLR_NATIVE_CARD_REQUEST_QUEUED ||
        __atomic_load_n(&c->uncertain, __ATOMIC_ACQUIRE))
        return;
    __atomic_store_n(&q->state, NLR_NATIVE_CARD_REQUEST_RUNNING, __ATOMIC_RELEASE);
    const struct nlr_native_card_services *s = c->services;
    s->lock(s->mutex);
    /* Same verified order as stock mount/unmount middleware. Only those
     * lifecycle functions take the inner lock; direct file primitives do
     * not recursively acquire it. This pins the mounted filesystem for the
     * whole transaction, including direct format/unmount bypass callers. */
    s->volume_lock();
    int result = __atomic_load_n(&c->uncertain, __ATOMIC_ACQUIRE)
        ? NLR_CARD_STATE_COMMIT_UNCERTAIN : nlr_native_card_owner_check(c, q);
    if (result == NLR_OK)
        result = q->operation == NLR_NATIVE_CARD_SNAPSHOT || q->operation == NLR_NATIVE_CARD_COMMIT
            ? nlr_native_card_state_execute(r, c, q) : execute_file(r, c, q);
    if (result == NLR_OK && nlr_native_card_owner_check(c, q) != NLR_OK)
        result = q->operation == NLR_NATIVE_CARD_COMMIT
            ? NLR_CARD_STATE_COMMIT_UNCERTAIN : NLR_REFUSED;
    s->volume_unlock();
    s->unlock(s->mutex);
    q->result = __atomic_load_n(&c->uncertain, __ATOMIC_ACQUIRE)
        ? NLR_CARD_STATE_COMMIT_UNCERTAIN : result;
    /* Only an existing genuine GUI flag can be notified. No synthetic
     * input, result injection or cross-thread menu publication occurs here. */
    if (q->operation == NLR_NATIVE_CARD_COMMIT)
        nlr_native_card_wake(r);
    uint32_t running = NLR_NATIVE_CARD_REQUEST_RUNNING;
    /* A wait failure may have quarantined a callback already in flight.
     * Its late completion cannot turn that request back into reusable DONE. */
    __atomic_compare_exchange_n(&q->state, &running, NLR_NATIVE_CARD_REQUEST_DONE, 0,
                                  __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

void nlr_native_card_wake(struct nlr_runtime *r)
{
    if (!r || !r->native_card)
        return;
    const struct nlr_native_card_services *s = r->native_card->services;
    if (s->menu.callee && s->menu.wake_mask && r->load.svc->flag_set) {
        void *reference = s->menu.callee();
        if (nlr_native_card_ram_span(s, (uintptr_t)reference, 8)) {
            uintptr_t flag = (uintptr_t)nlr_native_card_u64(reference);
            if (nlr_native_card_ram_span(s, flag, NLR_WORKER_SIZE))
                r->load.svc->flag_set((void *)flag, s->menu.wake_mask);
        }
    }
}

static struct nlr_runtime *current_runtime(void)
{
    return nlr_runtime_find(&nlr_services, 0);
}

/* ---- The card task ---------------------------------------------------- *
 *
 * The card answers one request at a time, and the original submit (the
 * profile's services.native_card.submit_frame) holds its channel's
 * semaphore from copying the frame until it has read the reply, on the
 * Z 8 as disassembled for the profile. A request submitted from a task
 * that then does not run again leaves that semaphore and the request held:
 * STORESPY's service task (priority 30) was starved in the Z 8 QEMU right
 * after its open was answered -- the filesystem had finished it (request
 * state done) but the task never came back from the original wait (no
 * reply observed, still inside submit) -- and every later request waited
 * out its bound and reported busy, so the pass stopped at CLEAR
 * (qemu-fc-321/322, qemu-s1-004). Who gives the card back must not depend
 * on who asked for it.
 *
 * So only two tasks submit: the loader's card task and the worker, both at
 * the worker's priority. Any other caller fills a ticket of its own and
 * queues it; the card task takes the tickets in order, runs each as one
 * request, writes the result into the ticket and gives the request back
 * the moment the filesystem has answered. The caller collects the result
 * whenever it next runs; a caller that never runs again holds its ticket
 * and nothing else. The worker submits its own requests (ticket_call): a
 * hand-over per request delayed a program's start by about 20 ms in QEMU,
 * enough to change which keys it saw (ctl_events, qemu-s1-041/042).
 *
 * The waits. A ticket is waited for twice: for a free ticket and for the
 * card task to start it, both bounded; then for its own request, which the
 * filesystem always finishes (as a direct file call waits for the
 * filesystem). The bound is NLR_NATIVE_CARD_WAIT_MS on the loader's own
 * tasks (the worker and the programs' service tasks), as before: a sequence
 * of calls (a log append's open, seek, write, close) must not fail half way
 * because another task's request was in front (qemu-ki-072, qemu-fc-011).
 * On any other task -- the camera's menu task above all, and a stock task
 * running a program's hook -- the bound is NLR_NATIVE_CARD_CAMERA_WAIT_MS,
 * well below anything the camera's own GUI waits for: the queue in front
 * of a ticket is other tickets' transactions only (no caller's scheduling
 * any more), and past the bound the answer is busy, which the menu's
 * checkpoint takes as "carry on at the next turn" and asks for that turn
 * (menu_turn). */
#define NLR_NATIVE_CARD_WAIT_MS 3000u
#define NLR_NATIVE_CARD_CAMERA_WAIT_MS 250u
#define NLR_NATIVE_CARD_WAIT_STEP_MS 1u

static uint32_t ticket_budget(const struct nlr_runtime *r)
{
    return nlr_runtime_on_loader_task(r) ? NLR_NATIVE_CARD_WAIT_MS
                                         : NLR_NATIVE_CARD_CAMERA_WAIT_MS;
}

/* One step of a wait, about a millisecond, that lets other tasks run: the
 * time service's measured delay (the Z 8 declares no plain delay), else the
 * model's plain delay. 0 when neither is there or the delay failed. */
static int card_pause(const struct nlr_services *svc)
{
    if (svc->time && svc->time->delay_ms && svc->time->clock_ms)
        return nlr_time_sleep(svc->time, NLR_NATIVE_CARD_WAIT_STEP_MS, 0, 0) == 0;
    if (svc->sleep_ms) {
        svc->sleep_ms(NLR_NATIVE_CARD_WAIT_STEP_MS);
        return 1;
    }
    return 0;
}

static void serve(struct nlr_runtime *r, struct nlr_native_card_ticket *t);

/* The request served on the calling task, once the one request is free:
 * a busy answer from serve means only that the other submitter (the card
 * task, or the worker) holds it for its transaction. */
static int serve_waiting(struct nlr_runtime *r, struct nlr_native_card_ticket *t)
{
    for (uint32_t waited = 0;; waited += NLR_NATIVE_CARD_WAIT_STEP_MS) {
        serve(r, t);
        if (t->result != NLR_BUSY || waited >= NLR_NATIVE_CARD_WAIT_MS ||
            !card_pause(r->load.svc))
            return t->result;
    }
}

/* One request for `want`: its operation and arguments in, its result and
 * answers out. The worker submits its own (serve_waiting): it runs at the
 * card task's priority, so whatever could keep it from giving the request
 * back would keep the card task from it too, and a program's file reads
 * on the worker pay no hand-over. Every other task hands a ticket to the
 * card task. */
static int ticket_call(struct nlr_runtime *r, struct nlr_native_card_ticket *want)
{
    int result = nlr_native_card_attach(r);
    if (result != NLR_OK)
        return result;
    struct nlr_native_card_runtime *c = r->native_card;
    if (nlr_native_card_uncertain(r))
        return nlr_native_card_status(r);
    if (nlr_runtime_on_worker(r))
        return serve_waiting(r, want);
    const struct nlr_services *svc = r->load.svc;
    uint32_t budget = ticket_budget(r), waited = 0;
    struct nlr_native_card_ticket *t = 0;
    for (;;) {
        for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS && !t; n++) {
            uint32_t free_state = NLR_NATIVE_CARD_TICKET_FREE;
            if (__atomic_compare_exchange_n(&c->tickets[n].state, &free_state,
                                            NLR_NATIVE_CARD_TICKET_FILLING, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                t = &c->tickets[n];
        }
        if (t)
            break;
        if (waited >= budget || !card_pause(svc))
            return NLR_BUSY;
        waited += NLR_NATIVE_CARD_WAIT_STEP_MS;
    }
    t->operation = want->operation;
    t->purpose = want->purpose;
    t->open_flags = want->open_flags;
    t->fd = want->fd;
    t->whence = want->whence;
    t->offset = want->offset;
    t->count = want->count;
    t->source = want->source;
    t->sink = want->sink;
    t->desired = want->desired;
    t->result = NLR_NOT_READY;
    t->transferred = t->at_end = t->present = 0;
    t->queued_ms = nlr_clock_ms();
    nlr_native_card_copy(t->path, want->path, (uint32_t)sizeof t->path);
    t->sequence = __atomic_add_fetch(&c->tickets_issued, 1u, __ATOMIC_ACQ_REL);
    __atomic_store_n(&t->state, NLR_NATIVE_CARD_TICKET_QUEUED, __ATOMIC_RELEASE);
    if (svc->flag_set(c->card_worker.opaque + NLR_WORKER_FLAG_OFFSET, 1u) != NLR_OK) {
        uint32_t queued = NLR_NATIVE_CARD_TICKET_QUEUED;
        if (__atomic_compare_exchange_n(&t->state, &queued, NLR_NATIVE_CARD_TICKET_FREE, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return NLR_IO;
    }
    for (;;) {
        uint32_t state = __atomic_load_n(&t->state, __ATOMIC_ACQUIRE);
        if (state == NLR_NATIVE_CARD_TICKET_DONE)
            break;
        if (state == NLR_NATIVE_CARD_TICKET_QUEUED && waited >= budget) {
            /* never started: taken back, nothing was asked of the card */
            if (__atomic_compare_exchange_n(&t->state, &state, NLR_NATIVE_CARD_TICKET_FREE, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return NLR_BUSY;
            continue;
        }
        /* A delay that fails while queued ends the wait as the bound
         * would; once the card task has it, the answer is waited for. */
        if (!card_pause(svc) && state == NLR_NATIVE_CARD_TICKET_QUEUED)
            waited = budget;
        else if (state == NLR_NATIVE_CARD_TICKET_QUEUED)
            waited += NLR_NATIVE_CARD_WAIT_STEP_MS;
    }
    want->result = t->result;
    want->transferred = t->transferred;
    want->at_end = t->at_end;
    want->present = t->present;
    want->fd = t->fd;
    __atomic_store_n(&t->state, NLR_NATIVE_CARD_TICKET_FREE, __ATOMIC_RELEASE);
    return want->result;
}

/* What the card task does with one ticket: exactly what a caller used to do
 * with the request, on this task. */
static int serve_snapshot(struct nlr_runtime *r)
{
    int result = nlr_native_card_acquire(r, NLR_NATIVE_CARD_SNAPSHOT);
    if (result != NLR_OK)
        return result;
    result = nlr_native_card_submit(r);
    struct nlr_native_card_runtime *c = r->native_card;
    if (result == NLR_OK || result == NLR_CARD_STATE_NEEDS_MIGRATION) {
        const struct nlr_card_state *state = result == NLR_OK
            ? &c->request.selection.state : &c->request.desired;
        nlr_native_card_copy(&c->current, state, (uint32_t)sizeof c->current);
        c->active_slot = result == NLR_OK ? c->request.selection.slot : NLR_CARD_STATE_NO_SLOT;
        c->state_valid = 1;
        c->journal_present = c->request.journal_present;
    } else {
        c->state_valid = 0;
    }
    nlr_native_card_release(r);
    return result;
}

static int serve_commit(struct nlr_runtime *r, const struct nlr_card_state *desired,
                        uint32_t purpose)
{
    int result = nlr_native_card_acquire(r, NLR_NATIVE_CARD_COMMIT);
    if (result != NLR_OK)
        return result;
    struct nlr_native_card_runtime *c = r->native_card;
    nlr_native_card_copy(&c->request.desired, desired, (uint32_t)sizeof *desired);
    c->request.purpose = purpose;
    result = nlr_native_card_submit(r);
    if (result == NLR_OK) {
        result = nlr_card_state_decode(c->request.readback, NLR_CARD_STATE_SLOT_BYTES, &c->current);
        if (result == NLR_OK) {
            c->active_slot = c->request.commit.target_slot;
            c->state_valid = c->journal_present = 1;
        } else {
            __atomic_store_n(&c->uncertain, 1u, __ATOMIC_RELEASE);
            result = NLR_CARD_STATE_COMMIT_UNCERTAIN;
        }
    }
    nlr_native_card_release(r);
    return result;
}

static int serve_file(struct nlr_runtime *r, struct nlr_native_card_ticket *t)
{
    int result = nlr_native_card_acquire(r, t->operation);
    if (result != NLR_OK)
        return result;
    struct nlr_native_card_runtime *c = r->native_card;
    const struct nlr_native_card_services *s = c->services;
    struct nlr_native_card_request *q = &c->request;
    switch (t->operation) {
    case NLR_NATIVE_CARD_PROBE:
        result = request_path(q, t->path);
        break;
    case NLR_NATIVE_CARD_OPEN:
        if (t->open_flags && t->open_flags != s->write_flags &&
            t->open_flags != s->create_flags) {
            result = NLR_BOUNDS;
            break;
        }
        q->open_flags = t->open_flags;
        /* reading may also reach the card's DCIM; writing stays in the root */
        result = request_path_in(q, t->path, !t->open_flags);
        break;
    case NLR_NATIVE_CARD_READ:
        q->fd = t->fd;
        q->count = t->count;
        result = t->count <= sizeof q->data ? NLR_OK : NLR_BOUNDS;
        break;
    case NLR_NATIVE_CARD_WRITE:
        q->fd = t->fd;
        q->count = t->count;
        result = t->count <= sizeof q->data ? NLR_OK : NLR_BOUNDS;
        if (result == NLR_OK)
            nlr_native_card_copy(q->data, t->source, t->count);
        break;
    case NLR_NATIVE_CARD_SEEK:
        q->fd = t->fd;
        q->offset = t->offset;
        q->whence = t->whence;
        break;
    case NLR_NATIVE_CARD_CLOSE:
        q->fd = t->fd;
        break;
    default:
        result = NLR_BOUNDS;
        break;
    }
    if (result == NLR_OK)
        result = nlr_native_card_submit(r);
    if (result == NLR_OK) {
        t->present = q->present;
        t->fd = q->fd;
        t->transferred = q->transferred;
        t->at_end = q->at_end;
        if (t->operation == NLR_NATIVE_CARD_READ)
            nlr_native_card_copy(t->sink, q->data + q->data_offset, q->transferred);
    }
    nlr_native_card_release(r);
    return result;
}

static void serve(struct nlr_runtime *r, struct nlr_native_card_ticket *t)
{
    switch (t->operation) {
    case NLR_NATIVE_CARD_SNAPSHOT:
        t->result = serve_snapshot(r);
        break;
    case NLR_NATIVE_CARD_COMMIT:
        t->result = serve_commit(r, t->desired, t->purpose);
        break;
    default:
        t->result = serve_file(r, t);
        break;
    }
}

/* The card task's event: every queued ticket, oldest first. A ticket
 * queued while this runs sets the flag again, so none is left behind. */
static void card_task(void *self, uint32_t events)
{
    (void)events;
    struct nlr_runtime *r = current_runtime();
    if (!r || !r->native_card || self != &r->native_card->card_worker)
        return;
    struct nlr_native_card_runtime *c = r->native_card;
    for (;;) {
        struct nlr_native_card_ticket *next = 0;
        for (uint32_t n = 0; n < NLR_NATIVE_CARD_TICKETS; n++) {
            struct nlr_native_card_ticket *t = &c->tickets[n];
            if (__atomic_load_n(&t->state, __ATOMIC_ACQUIRE) == NLR_NATIVE_CARD_TICKET_QUEUED &&
                (!next || t->sequence < next->sequence))
                next = t;
        }
        if (!next)
            return;
        uint32_t queued = NLR_NATIVE_CARD_TICKET_QUEUED;
        if (!__atomic_compare_exchange_n(&next->state, &queued, NLR_NATIVE_CARD_TICKET_RUNNING,
                                         0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue; /* its caller took it back */
        uint32_t started = nlr_clock_ms();
        serve_waiting(r, next);
        uint32_t ended = nlr_clock_ms();
        /* Observation only: how long tickets waited and ran (QEMU). */
        if (started - next->queued_ms > c->longest_wait_ms)
            c->longest_wait_ms = started - next->queued_ms;
        if (ended - started > c->longest_run_ms)
            c->longest_run_ms = ended - started;
        c->served++;
        __atomic_store_n(&next->state, NLR_NATIVE_CARD_TICKET_DONE, __ATOMIC_RELEASE);
    }
}

/* The card task, made once with the card's area: the loader worker's core
 * and priority, its own name. No task, no card (attach). */
static int card_task_start(struct nlr_runtime *r, struct nlr_native_card_runtime *c)
{
    const struct nlr_services *svc = r->load.svc;
    /* a caller waits for its ticket with a delay that lets the card task
     * run: no delay, no card task */
    if (!svc->worker_init || !svc->worker_start || !svc->flag_set ||
        (!(svc->time && svc->time->delay_ms && svc->time->clock_ms) && !svc->sleep_ms))
        return 0;
    static const char name[NLR_TASK_NAME_SIZE] = "NLRCARD";
    c->card_task.core = r->load.task.core;
    c->card_task.priority = r->load.task.priority;
    c->card_task.stack_bytes = 0x4000u;
    for (uint32_t n = 0; n < NLR_TASK_NAME_SIZE; n++)
        c->card_task.name[n] = name[n];
    svc->worker_init(&c->card_worker, card_task, 1u, &c->card_task);
    uint32_t task_id = nlr_le32(c->card_worker.opaque + NLR_WORKER_ID_OFFSET);
    uint32_t flag_id = nlr_le32(c->card_worker.opaque + NLR_WORKER_FLAG_OFFSET);
    /* worker_init cannot report a failure; ids that cannot be real mean no
     * task came of it. The memory stays: kernel objects may point in. */
    if (!task_id || task_id > NLR_REGISTRY_IDS || !flag_id || flag_id > NLR_REGISTRY_IDS)
        return 0;
    svc->worker_start(&c->card_worker);
    __atomic_store_n(&c->card_task_started, 1u, __ATOMIC_RELEASE);
    return 1;
}

/* ---- What callers ask -------------------------------------------------- */

/* A caller's ticket on its own stack, zeroed by hand: core is built
 * without a C library, so no aggregate initializer may call memset. */
static void ticket_init(struct nlr_native_card_ticket *want, uint32_t operation)
{
    nlr_native_card_zero(want, (uint32_t)sizeof *want);
    want->operation = operation;
}

int nlr_native_card_snapshot(struct nlr_runtime *r)
{
    struct nlr_native_card_ticket want;
    ticket_init(&want, NLR_NATIVE_CARD_SNAPSHOT);
    return ticket_call(r, &want);
}

int nlr_native_card_commit_state(struct nlr_runtime *r,
                                 const struct nlr_card_state *desired,
                                 enum nlr_card_state_purpose purpose)
{
    if (!desired)
        return NLR_BOUNDS;
    if (r && r->native_card) {
        uintptr_t start = (uintptr_t)&r->native_card->request;
        uintptr_t argument = (uintptr_t)desired;
        if (argument >= start && argument - start < sizeof r->native_card->request)
            return NLR_BOUNDS; /* acquire clears the entire owned request */
    }
    struct nlr_native_card_ticket want;
    ticket_init(&want, NLR_NATIVE_CARD_COMMIT);
    want.desired = desired;
    want.purpose = (uint32_t)purpose;
    return ticket_call(r, &want);
}

/* A path this side of the card: the root's (or, `media`, the card's DCIM
 * for reading), checked here before it is queued and again on the card
 * task, which copies it into the request. */
static int ticket_path(struct nlr_native_card_ticket *want, const char *path, int media)
{
    return path_in(want->path, path, media);
}

int nlr_native_card_probe(struct nlr_runtime *r, const char *path, uint32_t *present)
{
    if (!present)
        return NLR_BOUNDS;
    struct nlr_native_card_ticket want;
    ticket_init(&want, NLR_NATIVE_CARD_PROBE);
    int result = ticket_path(&want, path, 0);
    if (result == NLR_OK)
        result = ticket_call(r, &want);
    if (result == NLR_OK)
        *present = want.present;
    return result;
}

/* `flags` 0 with `mode` 0 opens for reading. A write access names one of
 * the state file's two modes together with that file's mode word, which is
 * what the profile's program write flags are checked to be on this family;
 * any other combination is refused before the card is asked. */
int32_t nlr_native_card_file_open(const char *path, uint32_t flags, uint32_t mode)
{
    struct nlr_runtime *r = current_runtime();
    if (!r || (!flags && mode) || nlr_native_card_attach(r) != NLR_OK)
        return -1;
    const struct nlr_native_card_services *s = r->native_card->services;
    if (flags && ((flags != s->write_flags && flags != s->create_flags) ||
                  mode != s->file_mode))
        return -1;
    struct nlr_native_card_ticket want;
    ticket_init(&want, NLR_NATIVE_CARD_OPEN);
    want.open_flags = flags;
    /* reading may also reach the card's DCIM; writing stays in the root */
    if (ticket_path(&want, path, !flags) != NLR_OK)
        return -1;
    return ticket_call(r, &want) == NLR_OK ? want.fd : -1;
}

/* Reads and writes go a request's buffer at a time, one ticket each. A
 * read request may deliver less than a buffer when the file position was
 * not aligned (read_aligned); only the end of the file ends the read. */
#define NLR_NATIVE_CARD_CHUNK ((uint32_t)sizeof(((struct nlr_native_card_request *)0)->data))

int32_t nlr_native_card_file_read(int32_t fd, void *data, uint32_t bytes, uint32_t *read)
{
    struct nlr_runtime *r = current_runtime();
    if (!r || !read || (!data && bytes))
        return NLR_BOUNDS;
    uint32_t total = 0;
    *read = 0;
    while (total < bytes) {
        uint32_t requested = bytes - total < NLR_NATIVE_CARD_CHUNK
            ? bytes - total : NLR_NATIVE_CARD_CHUNK;
        struct nlr_native_card_ticket want;
        ticket_init(&want, NLR_NATIVE_CARD_READ);
        want.fd = fd;
        want.count = requested;
        want.sink = (uint8_t *)data + total;
        int result = ticket_call(r, &want);
        if (result != NLR_OK)
            return result;
        total += want.transferred;
        *read = total;
        if (want.at_end || !want.transferred)
            break;
    }
    return NLR_OK;
}

int32_t nlr_native_card_file_write(int32_t fd, const void *data, uint32_t bytes,
                                  uint32_t *written)
{
    struct nlr_runtime *r = current_runtime();
    if (!r || !written || (!data && bytes))
        return NLR_BOUNDS;
    uint32_t total = 0;
    *written = 0;
    while (total < bytes) {
        uint32_t requested = bytes - total < NLR_NATIVE_CARD_CHUNK
            ? bytes - total : NLR_NATIVE_CARD_CHUNK;
        struct nlr_native_card_ticket want;
        ticket_init(&want, NLR_NATIVE_CARD_WRITE);
        want.fd = fd;
        want.count = requested;
        want.source = (const uint8_t *)data + total;
        int result = ticket_call(r, &want);
        if (result != NLR_OK)
            return result;
        total += want.transferred;
        *written = total;
        /* A short answer (a full card) ends the write; the caller sees how
         * much went out. */
        if (want.transferred < requested)
            break;
    }
    return NLR_OK;
}

int32_t nlr_native_card_file_seek(int32_t fd, int32_t whence, uint32_t offset,
                                 uint32_t *position)
{
    struct nlr_runtime *r = current_runtime();
    if (!r || !position || offset > INT32_MAX)
        return NLR_BOUNDS;
    struct nlr_native_card_ticket want;
    ticket_init(&want, NLR_NATIVE_CARD_SEEK);
    want.fd = fd;
    want.offset = (int32_t)offset;
    want.whence = whence;
    int result = ticket_call(r, &want);
    if (result == NLR_OK)
        *position = want.transferred;
    return result;
}

int32_t nlr_native_card_file_close(int32_t fd)
{
    struct nlr_runtime *r = current_runtime();
    if (!r)
        return NLR_NOT_READY;
    struct nlr_native_card_ticket want;
    ticket_init(&want, NLR_NATIVE_CARD_CLOSE);
    want.fd = fd;
    return ticket_call(r, &want);
}

static void observe_epoch(struct nlr_native_card_runtime *c)
{
    uint64_t before = __atomic_load_n(&c->epoch, __ATOMIC_ACQUIRE);
    for (;;) {
        if (before == UINT64_MAX) {
            __atomic_store_n(&c->uncertain, 1u, __ATOMIC_RELEASE);
            break;
        }
        if (__atomic_compare_exchange_n(&c->epoch, &before, before + 1u, 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    if (__atomic_load_n(&c->bound, __ATOMIC_ACQUIRE))
        __atomic_store_n(&c->changed, 1u, __ATOMIC_RELEASE);
}

static struct nlr_native_card_runtime *lifecycle_begin(const char *volume)
{
    if (!volume || volume[0] != NLR_CARD_ROOT[0] || volume[1] != ':' || volume[2])
        return 0;
    struct nlr_runtime *r = current_runtime();
    if (!r || !r->native_card)
        return 0;
    struct nlr_native_card_runtime *c = r->native_card;
    uint32_t before = __atomic_load_n(&c->transitions, __ATOMIC_ACQUIRE);
    for (;;) {
        if (before == UINT32_MAX) {
            __atomic_store_n(&c->uncertain, 1u, __ATOMIC_RELEASE);
            return 0;
        }
        if (__atomic_compare_exchange_n(&c->transitions, &before, before + 1u, 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    observe_epoch(c);
    return c;
}

static void lifecycle_end(struct nlr_native_card_runtime *c)
{
    if (c) {
        observe_epoch(c);
        uint32_t before = __atomic_load_n(&c->transitions, __ATOMIC_ACQUIRE);
        for (;;) {
            if (!before) {
                __atomic_store_n(&c->uncertain, 1u, __ATOMIC_RELEASE);
                break;
            }
            if (__atomic_compare_exchange_n(&c->transitions, &before, before - 1u, 0,
                                              __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                break;
        }
    }
    /* A runtime created during an earlier lifecycle operation can be woken
     * after completion, but must never decrement a counter it did not own. */
    nlr_native_card_wake(current_runtime());
}

static int32_t store_probe(const char *path, uint32_t *present)
{
    return nlr_native_card_probe(current_runtime(), path, present);
}

/* The card's own stat reason tells absence (only its exact "not found"):
 * no file beside it is needed. No card mounted is NLR_NOT_READY. */
static int32_t store_probe_beside(const char *path, const char *beside, uint32_t *present)
{
    (void)beside;
    return store_probe(path, present);
}

int nlr_native_card_safe_guard(void)
{
    uint32_t present = 0;
    int result = store_probe(NLR_SAFE_MODE_PATH, &present);
    return result != NLR_OK ? result : present ? NLR_DISABLED : NLR_OK;
}

/* The boot program's record lives in the journal (STATE.NLS format 2): read
 * from a fresh snapshot, written as a BOOT_MARK commit of the current record
 * with only its boot fields changed. Each answer is the journal's own:
 * success only after the reply, both syncs and the independent readback;
 * an uncertain commit stays uncertain for the rest of this boot. */
static int32_t store_boot_mark_get(struct nlr_boot_mark *out)
{
    struct nlr_runtime *r = current_runtime();
    if (!out)
        return NLR_BOUNDS;
    int result = nlr_native_card_snapshot(r);
    if (result != NLR_OK)
        return result;
    const struct nlr_card_state *state = &r->native_card->current;
    out->mark = state->boot_mark;
    out->result = state->boot_result;
    nlr_native_card_copy(out->id, state->boot_id, (uint32_t)sizeof out->id);
    return NLR_OK;
}

static int32_t store_boot_mark_set(const struct nlr_boot_mark *mark)
{
    struct nlr_runtime *r = current_runtime();
    if (!mark)
        return NLR_BOUNDS;
    int result = nlr_native_card_snapshot(r);
    if (result != NLR_OK)
        return result;
    struct nlr_native_card_runtime *c = r->native_card;
    nlr_native_card_copy(&c->boot_proposal, &c->current, (uint32_t)sizeof c->boot_proposal);
    c->boot_proposal.boot_mark = mark->mark;
    c->boot_proposal.boot_result = mark->result;
    nlr_native_card_zero(c->boot_proposal.boot_id, (uint32_t)sizeof c->boot_proposal.boot_id);
    for (uint32_t k = 0; k < NLR_MANIFEST_ID_MAX && mark->id[k]; k++)
        c->boot_proposal.boot_id[k] = mark->id[k];
    return nlr_native_card_commit_state(r, &c->boot_proposal, NLR_CARD_STATE_BOOT_MARK);
}

const struct nlr_card_store *nlr_native_card_store(void)
{
    /* Only reliable presence belongs to the old file interface. Its atomic
     * replace/remove methods stay unavailable: native state uses the journal,
     * the boot record included. */
    static const struct nlr_card_store store = {
        .probe = store_probe,
        .boot_mark_get = store_boot_mark_get,
        .boot_mark_set = store_boot_mark_set,
        .probe_beside = store_probe_beside,
    };
    return &store;
}

int nlr_native_card_read_settings(struct nlr_runtime *r, struct nlr_enabled *enabled)
{
    int result = nlr_native_card_snapshot(r);
    if (result == NLR_CARD_STATE_NEEDS_MIGRATION)
        result = nlr_native_card_commit_state(r, &r->native_card->current, NLR_CARD_STATE_MIGRATE);
    if (result != NLR_OK)
        return result;
    result = nlr_runtime_read_directory(r);
    if (result != NLR_OK)
        return result;
    uint32_t bytes = 0;
    const struct nlr_card_state *state = &r->native_card->current;
    for (uint32_t n = 0; n < state->enabled_count; n++) {
        for (uint32_t k = 0; state->enabled_id[n][k]; k++) {
            if (bytes >= r->load.capacity)
                return NLR_BOUNDS;
            r->load.arena[bytes++] = (uint8_t)state->enabled_id[n][k];
        }
        if (bytes >= r->load.capacity)
            return NLR_BOUNDS;
        r->load.arena[bytes++] = '\n';
    }
    return nlr_enabled_parse(enabled, &r->directory, r->load.arena, bytes);
}

int nlr_native_card_guard(struct nlr_runtime *r, uint32_t expect_pending)
{
    int result = nlr_native_card_snapshot(r);
    if (result != NLR_OK)
        return result;
    return r->native_card->current.pending == expect_pending ? NLR_OK :
           expect_pending ? NLR_IO : NLR_AUTOLOAD_PAUSED;
}

int nlr_native_card_pending(struct nlr_runtime *r, uint32_t pending)
{
    if (!r || !r->native_card || !r->native_card->state_valid || pending > 1u)
        return NLR_NOT_READY;
    struct nlr_native_card_runtime *c = r->native_card;
    nlr_native_card_copy(&c->proposal, &c->current, sizeof c->proposal);
    c->proposal.pending = pending;
    return nlr_native_card_commit_state(r, &c->proposal,
                pending ? NLR_CARD_STATE_ARM_INIT : NLR_CARD_STATE_CLEAR_PENDING);
}

int nlr_native_card_save_enabled(struct nlr_runtime *r, const struct nlr_enabled *desired)
{
    if (!r || !r->native_card || !desired || desired->count > NLR_MANIFEST_MAX_ENTRIES)
        return NLR_BOUNDS;
    int result = nlr_native_card_snapshot(r);
    if (result != NLR_OK)
        return result;
    struct nlr_native_card_runtime *c = r->native_card;
    nlr_native_card_zero(&c->proposal, sizeof c->proposal);
    c->proposal.generation = c->current.generation;
    c->proposal.pending = c->current.pending;
    /* Saving settings keeps the boot record as it is (format 2). */
    c->proposal.boot_mark = c->current.boot_mark;
    c->proposal.boot_result = c->current.boot_result;
    nlr_native_card_copy(c->proposal.boot_id, c->current.boot_id,
                         (uint32_t)sizeof c->proposal.boot_id);
    c->proposal.enabled_count = desired->count;
    for (uint32_t n = 0; n < desired->count; n++)
        for (uint32_t k = 0; k <= NLR_MANIFEST_ID_MAX; k++) {
            c->proposal.enabled_id[n][k] = desired->id[n][k];
            if (!desired->id[n][k])
                break;
        }
    result = nlr_native_card_commit_state(r, &c->proposal, NLR_CARD_STATE_SAVE_SETTINGS);
    if (result == NLR_OK)
        nlr_enabled_copy(&r->saved_enabled, desired);
    return result;
}

int32_t nlr_native_card_mount_observe(const char *volume, void *device, void *parameters)
{
    struct nlr_native_card_runtime *transition = lifecycle_begin(volume);
    int32_t result = nlr_native_card_services.mount.callee(volume, device, parameters);
    /* Binding can begin while another FILESRV task waits for the mutex.
     * Observe completion too, so that a bind between attempt and completion
     * cannot mistake the resulting reused slot for its earlier volume. */
    lifecycle_end(transition);
    return result;
}

int32_t nlr_native_card_unmount_observe(const char *volume)
{
    struct nlr_native_card_runtime *transition = lifecycle_begin(volume);
    int32_t result = nlr_native_card_services.unmount.callee(volume);
    lifecycle_end(transition);
    return result;
}

int32_t nlr_native_card_low_unmount_observe(const char *volume)
{
    struct nlr_native_card_runtime *transition = lifecycle_begin(volume);
    int32_t result = nlr_native_card_services.low_unmount(volume);
    lifecycle_end(transition);
    return result;
}

static void *menu_turn(struct nlr_runtime *r);

void *nlr_native_card_menu_checkpoint(void)
{
    unsigned named = 0;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, &named);
    if (!r && !named) {
        /* This call site follows GuiMe initialization and prepare, even when
         * NLoader has never been opened. A named partial worker is retained. */
        if (nlr_runtime_create(&r, &nlr_services, NLR_ARENA_BYTES) != NLR_OK)
            return nlr_native_card_services.menu.callee();
    }
    if (!r || nlr_runtime_find(&nlr_services, 0) != r)
        return nlr_native_card_services.menu.callee();
    /* The menu task is never a hold point: a shell opened from
     * Apps closes the menu with menu.leave, and the menu's own exit must
     * run as in stock -- holding it here stalls the switch to shooting, and
     * the first live-view draw after the release is then cancelled, which
     * left the screen black (QEMU). The hold, the veil and the redraw are
     * taken at the profile's GUI turns (services.platform.gui_turns,
     * nlr_platform_gui_turn). */
    return menu_turn(r);
}

static void *menu_turn(struct nlr_runtime *r)
{
    nlr_runtime_exit_menu_checkpoint(r);
#if NLR_HAS_GRAPHICS
    nlr_graphics_runtime_checkpoint(r);
#endif
    void *original = nlr_native_card_services.menu.callee();
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return original;
    if (nlr_native_card_attach(r) != NLR_OK)
        return original;
    if (nlr_native_card_uncertain(r)) {
        nlr_runtime_autoload_interrupt(r, nlr_native_card_status(r));
        return original;
    }
    /* A boot program's outcome a busy journal refused (runtime.c). */
    nlr_runtime_boot_mark_settle(r);
    const struct nlr_resource_services *resources = r->load.svc->resources;
    if (!resources || !resources->can_publish ||
        resources->can_publish(resources->context) != NLR_OK)
        return original;
    if (r->autoload.phase == NLR_AUTOLOAD_NEW) {
        /* The escape before anything is asked of the card, SAFE_MODE and
         * STATE.NLS included, as boot_step has it: held, it answers like
         * SAFE_MODE and nothing is read or written this boot. Until the
         * scan's hook is in, the pass waits for it. */
        int escape = nlr_runtime_boot_escape(r);
        if (escape == NLR_NOT_READY)
            return original;
        if (escape != NLR_OK) {
            r->autoload.store = nlr_native_card_store();
            r->autoload.enabled_result = r->autoload.result = escape;
            __atomic_store_n(&r->autoload.phase, NLR_AUTOLOAD_STOPPED, __ATOMIC_RELEASE);
            return original;
        }
        /* The card is asked on the turns boot_step would ask it, and no
         * more once the boot has stopped asking. */
        if (!nlr_runtime_boot_ask_due(r, nlr_clock_ms()))
            return original;
        /* Mount absence is retried only before binding; once bound, all
         * read/format/commit errors stop this boot rather than invent input. */
        int result = nlr_native_card_snapshot(r);
        if (result == NLR_FORMAT && r->directory_result != NLR_OK &&
            nlr_runtime_read_directory(r) == NLR_OK) {
            /* A card with no STATE.NLS yet is read from its old ENABLED,
             * and on a card without MANIFEST its names are the programs
             * that describe themselves -- known only once the directory
             * has been listed (sp-007: "Paused: check enabled list"). */
            result = nlr_native_card_snapshot(r);
        }
        if (result == NLR_BUSY) {
            /* the card task had other tickets in front for longer than the
             * menu task waits: asked again at the next turn, which is
             * asked for now */
            nlr_native_card_wake(r);
            return original;
        }
        if (result == NLR_NOT_READY && !__atomic_load_n(&r->native_card->bound, __ATOMIC_ACQUIRE)) {
            /* no card yet: the release bundle's boot program in time */
            nlr_runtime_boot_no_card(r, 0);
            return original;
        }
        if (result == NLR_CARD_STATE_NO_DIRECTORY) {
            /* a card with nothing of the loader's: the bundle at once,
             * and nothing is created on the card */
            nlr_runtime_boot_no_card(r, 1);
            return original;
        }
        r->autoload.store = nlr_native_card_store();
        if (result != NLR_OK && result != NLR_CARD_STATE_NEEDS_MIGRATION) {
            r->autoload.enabled_result = r->autoload.result = result;
            __atomic_store_n(&r->autoload.phase, NLR_AUTOLOAD_STOPPED, __ATOMIC_RELEASE);
            return original;
        }
        nlr_runtime_autoload_begin(r, r->autoload.store);
    }
    int published = nlr_runtime_menu_publish(r);
    if (published == NLR_OK)
        nlr_runtime_autoload_step_owned(r);
    /* more to carry on: the next turn soon (a boot program's start a busy
     * card put off included) */
    if (r->autoload.phase == NLR_AUTOLOAD_READY || r->autoload.phase == NLR_AUTOLOAD_CLEAR ||
        __atomic_load_n(&r->autoload.boot_record, __ATOMIC_ACQUIRE) == NLR_BOOT_RECORD_START)
        nlr_native_card_wake(r);
    return original;
}

#endif
