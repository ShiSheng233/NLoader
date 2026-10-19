#include "nlr/runtime.h"
#if NLR_HAS_NATIVE_CARD
#include "nlr/native_card.h"
#endif

/* The loader's own state on an ordinary card, for a model whose native
 * filesystem services are not ported: the autoload lifecycle (PLAN 5.5)
 * needs to know reliably whether SAFE_MODE is there and whether a pass was
 * interrupted, and it needs a durable way to say that one started.
 *
 * Reliable presence. A failed open says nothing by itself — this reader
 * cannot tell a missing file from an unreadable card — so absence is only
 * reported when the card's own MANIFEST opens in the same pass: the card is
 * readable and the file is not there. Anything else is an IO error, which
 * pauses the lifecycle instead of inventing an answer.
 *
 * Durability without a delete service. The marker's protocol asks the store
 * whether a pass is outstanding, and this model's checked file services can
 * create, truncate and write, but not remove. The marker therefore carries
 * presence in its content: it is written empty while a pass runs and holds
 * one NLR_MARKER_CLEARED byte once the pass finished. A write that fails
 * part way leaves it empty, which is the pending answer, so the detector
 * keeps failing safe. Its content is the second question, never the first:
 * a marker that opens and then cannot be read is still a marker. Only this
 * file is read that way; every other path is present when it opens,
 * whatever it contains.
 *
 * Nothing here is atomic. Writing a payload truncates the file first, so an
 * interruption can leave it short; the marker is the only thing written
 * through this store, and its payload is one byte or none. A real payload
 * (saving ENABLED from the page) is refused rather than written without the
 * atomic replace the store contract promises. */

extern const struct nlr_services nlr_services;

#define NLR_MARKER_CLEARED 'C'

static int same_path(const char *a, const char *b)
{
    uint32_t n = 0;
    while (a[n] && a[n] == b[n])
        n++;
    return a[n] == b[n];
}

/* Write `bytes` of `data` as the whole content of `path`. */
static int32_t store_write(const char *path, const uint8_t *data,
                           uint32_t bytes)
{
    const struct nlr_services *s = &nlr_services;
    if (!s->file_open || !s->file_close || !s->file_write ||
        !s->file_open_write)
        return NLR_NOT_READY;
    int32_t fd = s->file_open(path, s->file_open_write,
                              s->file_create_attributes);
    if (fd < 0)
        return NLR_IO;
    int result = NLR_OK;
    uint32_t written = 0;
    /* The marker's byte has to be out of the data cache before the card
     * can fetch it, the same as any other write (api.c). */
    if (bytes && s->cache_clean)
        s->cache_clean((void *)(uintptr_t)data, bytes);
    while (result == NLR_OK && written < bytes) {
        uint32_t done = 0;
        if (s->file_write(fd, data + written, bytes - written, &done) != 0 ||
            done == 0 || done > bytes - written)
            result = NLR_IO;
        else
            written += done;
    }
    if (s->file_close(fd) != 0 && result == NLR_OK)
        result = NLR_IO;
    return result;
}

/* Absence is only established by a card that answers for another file:
 * MANIFEST, or -- on a card whose programs describe themselves and which
 * has none -- BOOT or ENABLED. Any of them opening
 * says the card is mounted and reading: NLR_OK with *present 0. None of
 * them opening is NLR_NOT_READY; a close that fails is NLR_IO. */
static int32_t anchored_absence(const char *path, uint32_t *present)
{
    const struct nlr_services *s = &nlr_services;
    for (uint32_t n = 0; n < 3u; n++) {
        const char *other = n == 0 ? NLR_MANIFEST_PATH
                          : n == 1 ? NLR_CARD_ROOT "BOOT" : NLR_ENABLED_PATH;
        if (same_path(path, other))
            continue;
        int32_t anchor = s->file_open(other, 0, 0);
        if (anchor < 0)
            continue;
        if (s->file_close(anchor) != 0)
            return NLR_IO;
        *present = 0;
        return NLR_OK;
    }
    return NLR_NOT_READY;
}

static int32_t store_probe(const char *path, uint32_t *present)
{
    const struct nlr_services *s = &nlr_services;
    if (!path || !present || !s->file_open || !s->file_close)
        return NLR_NOT_READY;
    if (same_path(path, NLR_AUTOLOAD_PENDING_PATH)) {
        /* The marker's content is its presence, but the file being there
         * comes first: one that opens and then cannot be read is a marker
         * all the same. Only its own cleared byte, read whole, says the
         * pass it belongs to finished; a read error, a short read or any
         * other content leaves it standing. Calling it absent would be the
         * one unsafe direction — a pass that crashed the camera would look
         * clean and be tried again. A buffer of whole cache lines is what
         * the card reader may invalidate around. */
        int32_t marker = s->file_open(path, 0, 0);
        if (marker >= 0) {
            if (s->file_close(marker) != 0)
                return NLR_IO;
            _Alignas(NLR_CACHE_LINE) uint8_t frame[NLR_CACHE_LINE];
            uint32_t bytes = 0;
            *present = 1;
            if (nlr_card_read(s, path, frame, sizeof frame, &bytes, 0) ==
                NLR_OK)
                *present = !(bytes == 1u && frame[0] == NLR_MARKER_CLEARED);
            return NLR_OK;
        }
    } else {
        int32_t fd = s->file_open(path, 0, 0);
        if (fd >= 0) {
            if (s->file_close(fd) != 0)
                return NLR_IO;
            *present = 1;
            return NLR_OK;
        }
    }
    int32_t result = anchored_absence(path, present);
    return result == NLR_NOT_READY ? NLR_IO : result;
}

/* A file is present when it opens. Absence needs the card to answer for
 * another file. `beside` is one: a file of this card the caller reads in
 * the same attempt -- read whole already, or read next, where a read that
 * fails ends the attempt -- so with it a failed open is absence, and no
 * second open is made. Without it the store's own anchors answer. A card
 * that answers for nothing -- none mounted, or no anchor opens -- is
 * NLR_NOT_READY: this reader cannot tell a missing card from an unreadable
 * one, and says so. */
static int32_t store_probe_beside(const char *path, const char *beside,
                                  uint32_t *present)
{
    const struct nlr_services *s = &nlr_services;
    if (!path || !present || !s->file_open || !s->file_close)
        return NLR_NOT_READY;
    int32_t fd = s->file_open(path, 0, 0);
    if (fd >= 0) {
        if (s->file_close(fd) != 0)
            return NLR_IO;
        *present = 1;
        return NLR_OK;
    }
    if (beside) {
        *present = 0;
        return NLR_OK;
    }
    return anchored_absence(path, present);
}

static int32_t store_replace(const char *path, const uint8_t *data,
                             uint32_t bytes)
{
    if (!path)
        return NLR_NOT_READY;
    /* The boot program's record (runtime.c boot_program): whether the last
     * start ran well. A few bytes, and nothing else. */
    if (same_path(path, NLR_CARD_ROOT "BOOTRUN") && bytes <= 16u && (data || !bytes))
        return store_write(path, data, bytes);
    /* The loader's own pages: which program the boot
     * starts (BOOT: its id, or nothing) and the NLoader switch (MASTER:
     * "on" or "off"). Each a few bytes, written whole; a write cut short
     * leaves BOOT naming no program and MASTER reading as on, which is what
     * a card without either does. */
    if (same_path(path, NLR_BOOT_PATH) && bytes <= NLR_MANIFEST_ID_MAX &&
        (data || !bytes))
        return store_write(path, data, bytes);
    if (same_path(path, NLR_MASTER_PATH) && data &&
        ((bytes == 2u && data[0] == 'o' && data[1] == 'n') ||
         (bytes == 3u && data[0] == 'o' && data[1] == 'f' && data[2] == 'f')))
        return store_write(path, data, bytes);
    /* Dev firmware's stage 0 keeps the same kind of record for the core it
     * loads from the card (stage0.c). */
    if (same_path(path, NLR_CARD_ROOT "CORERUN") && bytes <= 16u && (data || !bytes))
        return store_write(path, data, bytes);
    /* Only the marker, whose payload is empty: see the note above. */
    if (bytes || data || !same_path(path, NLR_AUTOLOAD_PENDING_PATH))
        return NLR_NOT_READY;
    return store_write(path, 0, 0);
}

static int32_t store_remove(const char *path)
{
    if (!path || !same_path(path, NLR_AUTOLOAD_PENDING_PATH))
        return NLR_NOT_READY;
    const uint8_t cleared = NLR_MARKER_CLEARED;
    return store_write(path, &cleared, 1u);
}

const struct nlr_card_store *nlr_file_store(void)
{
    static const struct nlr_card_store store = {
        .probe = store_probe,
        .replace = store_replace,
        .remove = store_remove,
        .probe_beside = store_probe_beside,
    };
    /* Without the create/truncate flags and the write service there is no
     * durable marker, and the lifecycle must not start a pass it cannot
     * record. */
    if (!nlr_services.file_write || !nlr_services.file_open_write)
        return 0;
    return &store;
}

const struct nlr_card_store *nlr_card_presence_store(const struct nlr_services *svc)
{
#if NLR_HAS_NATIVE_CARD
    if (svc && svc->native_card)
        return nlr_native_card_store();
#else
    (void)svc;
#endif
    /* Reading needs no write service: presence is asked on every body
     * that can open a file. */
    static const struct nlr_card_store presence = {
        .probe = store_probe,
        .probe_beside = store_probe_beside,
    };
    return svc && svc->file_open && svc->file_close ? &presence : 0;
}
