#include "nlr/load.h"
#include "nlr/exec.h"
#include "nlr/api.h"
#include "nlr/manifest.h"
#include "nlr/runtime.h"
#include "nlr/platform.h"
#if NLR_HAS_NATIVE_CARD
#include "nlr/native_card.h"
#endif

/* Injected by the generated bindings in the stage builds that run programs;
 * referenced only under the stage guards below. */
extern const struct nlr_api nlr_api;
extern const struct nlr_exec_services nlr_exec_services;

_Static_assert(offsetof(struct nlr_load, worker) == 0, "worker callback ABI");

/* ASCII phases kept in .stage after a failure: I init, O open, S seek,
 * H header, V validate, D data, K checksum, C close. */
enum { NLR_CHUNK_MAX = NLR_LOAD_CHUNK };
_Static_assert(NLR_LOAD_CHUNK % NLR_CACHE_LINE == 0,
               "every chunk of a line-aligned arena starts on a line");

static int read_segment(struct nlr_load *l, int32_t fd, uint32_t offset,
                        uint32_t n)
{
    uint32_t done_total = 0;
    while (done_total < n) {
        uint32_t count = n - done_total, received = 0;
        if (count > NLR_CHUNK_MAX)
            count = NLR_CHUNK_MAX;
        if (l->mem) {
            /* The release bundle: a copy, chunk by chunk as from the card,
             * so a reader of the chunks sees the same pace. */
            if (count > l->mem_bytes - l->mem_pos) {
                nlr_trace_record(l, 'R', (int32_t)(l->mem_bytes - l->mem_pos));
                return NLR_IO;
            }
            for (uint32_t k = 0; k < count; k++)
                l->arena[offset + done_total + k] = l->mem[l->mem_pos + k];
            l->mem_pos += count;
            done_total += count;
            void (*chunk)(struct nlr_load *) =
                __atomic_load_n(&l->chunk_read, __ATOMIC_ACQUIRE);
            if (chunk)
                chunk(l);
            continue;
        }
        /* Invalidate once per disjoint chunk, not again after a short read:
         * another invalidation could discard bytes already received. */
        l->svc->cache_before_read(l->arena + offset + done_total, count);
        while (received < count) {
            uint32_t done = 0;
            int32_t r = l->svc->file_read(fd, l->arena + offset + done_total + received,
                                          count - received, &done);
            if (r != 0 || done == 0 || done > count - received) {
                nlr_trace_record(l, 'R', (int32_t)done);
                return NLR_IO;
            }
            received += done;
        }
        l->svc->cache_after_read(l->arena + offset + done_total, count);
        done_total += count;
        void (*chunk)(struct nlr_load *) =
            __atomic_load_n(&l->chunk_read, __ATOMIC_ACQUIRE);
        if (chunk)
            chunk(l);
    }
    return NLR_OK;
}

static int read_exact(struct nlr_load *l, int32_t fd, uint32_t n)
{
    return read_segment(l, fd, 0, n);
}

static uint32_t crc32(const uint8_t *p, uint32_t n)
{
    uint32_t c = ~0u;
    while (n--) {
        c ^= *p++;
        for (unsigned b = 0; b < 8; b++)
            c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
    }
    return ~c;
}

uint32_t nlr_crc32(const uint8_t *p, uint32_t n)
{
    return crc32(p, n);
}

static void spill_restore_home(struct nlr_load *l)
{
    if (l->home_arena) {
        l->arena = l->home_arena;
        l->capacity = l->home_capacity;
    }
}

/* A non-successful release cannot prove whether the allocator still owns
 * the region. Keep its record, never retry or dereference it, and stop
 * future loads. The separate base arena remains safe for status handling. */
static int unspill(struct nlr_load *l)
{
    if (__atomic_load_n(&l->spill_uncertain, __ATOMIC_ACQUIRE))
        return NLR_EXEC_RESTORE;
    if (!l->spill_request) return NLR_OK;
    if (!l->svc->release || l->svc->release(l->spill_request) != NLR_OK) {
        spill_restore_home(l);
        __atomic_store_n(&l->spill_uncertain, 1u, __ATOMIC_RELEASE);
        nlr_trace_record(l, 'b', -1);
        return NLR_EXEC_RESTORE;
    }
    spill_restore_home(l);
    l->spill_request = 0;
    l->spill_bytes = 0;
    l->home_arena = 0;
    l->home_capacity = 0;
    return NLR_OK;
}

/* Header and per-segment limits have passed before this allocation. Cache
 * maintenance may touch complete lines, so all alignment/padding is owned. */
static int spill(struct nlr_load *l, uint32_t bytes)
{
    if (l->spill_request || __atomic_load_n(&l->spill_uncertain, __ATOMIC_ACQUIRE))
        return NLR_EXEC_RESTORE;
    if (!l->svc->release) return NLR_NOT_READY;
    uint32_t lines = nlr_cache_lines(bytes);
    if (!bytes || lines < bytes || lines > UINT32_MAX - NLR_CACHE_LINE)
        return NLR_BOUNDS;
    /* The spill is the largest block the loader takes besides the
     * program's regions, and the model's allocator may answer it with a
     * smaller node while mapping the whole span over memory it still calls
     * free: where the loader can read its books, it is granted whole
     * (nlr_alloc_whole). */
    void *request = nlr_alloc_whole(l->svc, lines + NLR_CACHE_LINE);
    if (!request) return NLR_NOT_READY;
    l->home_arena = l->arena;
    l->home_capacity = l->capacity;
    l->spill_request = request;
    l->spill_bytes = lines + NLR_CACHE_LINE;
    if ((uintptr_t)request > UINTPTR_MAX - l->spill_bytes) {
        int result = unspill(l);
        return result == NLR_OK ? NLR_NOT_READY : result;
    }
    l->arena = (uint8_t *)(((uintptr_t)request + NLR_CACHE_LINE - 1u) &
                           ~(uintptr_t)(NLR_CACHE_LINE - 1u));
    l->capacity = lines;
    nlr_trace_record(l, 'b', (int32_t)lines);
    return NLR_OK;
}

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
/* The program's bytes are in its blocks: the spill can go back before the
 * entry runs. A failed release is recorded by unspill() and refuses later
 * loads; the running program never reads the spill. */
static void segments_consumed(void *context)
{
    (void)unspill(context);
}
#endif

static void relocation_kind_store(uint8_t *entry, uint32_t kind)
{
    for (uint32_t n = 0; n < 4; n++)
        entry[8u + n] = (uint8_t)(kind >> (8u * n));
}

static void relocation_swap(uint8_t *table, uint32_t a, uint32_t b)
{
    for (uint32_t n = 0; n < NLR_RELOC_ENTRY_SIZE; n++) {
        uint8_t saved = table[a * NLR_RELOC_ENTRY_SIZE + n];
        table[a * NLR_RELOC_ENTRY_SIZE + n] = table[b * NLR_RELOC_ENTRY_SIZE + n];
        table[b * NLR_RELOC_ENTRY_SIZE + n] = saved;
    }
}

static int relocation_less(const uint8_t *table, uint32_t a, uint32_t b)
{
    const uint8_t *left = table + a * NLR_RELOC_ENTRY_SIZE;
    const uint8_t *right = table + b * NLR_RELOC_ENTRY_SIZE;
    uint32_t left_data = (nlr_le32(left + 8) & 3u) != NLR_RELOC_ADRP;
    uint32_t right_data = (nlr_le32(right + 8) & 3u) != NLR_RELOC_ADRP;
    return left_data != right_data ? left_data < right_data :
                                      nlr_le32(left) < nlr_le32(right);
}

static void relocation_sift(uint8_t *table, uint32_t root, uint32_t count)
{
    while (root < count / 2u) {
        uint32_t child = root * 2u + 1u;
        if (child + 1u < count && relocation_less(table, child, child + 1u))
            child++;
        if (!relocation_less(table, root, child))
            break;
        relocation_swap(table, root, child);
        root = child;
    }
}

/* CRC and kind/bounds checks run first. Temporarily sort metadata by its
 * destination to detect overlapping writes without quadratic work or extra
 * heap storage. The unused upper kind bits hold the original index; the
 * original bytes/order are restored before either success or refusal. A
 * u32 byte length divided by 12 guarantees the index fits in 30 bits. */
static int relocation_writes_unique(uint8_t *table, uint32_t bytes)
{
    uint32_t count = bytes / NLR_RELOC_ENTRY_SIZE;
    for (uint32_t n = 0; n < count; n++) {
        uint8_t *entry = table + n * NLR_RELOC_ENTRY_SIZE;
        relocation_kind_store(entry, (n << 2) | nlr_le32(entry + 8));
    }
    for (uint32_t root = count / 2u; root > 0; root--)
        relocation_sift(table, root - 1u, count);
    for (uint32_t end = count; end > 1u;) {
        relocation_swap(table, 0, --end);
        relocation_sift(table, 0, end);
    }
    uint32_t previous_segment = UINT32_MAX;
    uint64_t previous_end = 0;
    int result = NLR_OK;
    for (uint32_t n = 0; n < count; n++) {
        const uint8_t *entry = table + n * NLR_RELOC_ENTRY_SIZE;
        uint32_t segment = (nlr_le32(entry + 8) & 3u) != NLR_RELOC_ADRP;
        uint32_t offset = nlr_le32(entry);
        if (segment == previous_segment && offset < previous_end)
            result = NLR_FORMAT;
        previous_segment = segment;
        previous_end = (uint64_t)offset + (segment ? 8u : 4u);
    }
    for (uint32_t n = 0; n < count; n++) {
        uint32_t original;
        while ((original = nlr_le32(table + n * NLR_RELOC_ENTRY_SIZE + 8) >> 2) != n)
            relocation_swap(table, n, original);
    }
    for (uint32_t n = 0; n < count; n++) {
        uint8_t *entry = table + n * NLR_RELOC_ENTRY_SIZE;
        relocation_kind_store(entry, nlr_le32(entry + 8) & 3u);
    }
    return result;
}

/* Generic v2 program (PLAN 6.3 M2-T4): the 64-byte header, relocation
 * table, image and initialized data are validated in file order; the
 * segments are left in the arena as [reloc][image][data] for the executor.
 * The v1 and probe paths in nlr_load_file are untouched by this. */
static int load_generic(struct nlr_load *l, int32_t fd, uint32_t size,
                        uint8_t *h)
{
    if (h[0] != 'N' || h[1] != 'P' || h[2] != 'L' || h[3] != 'D') {
        nlr_trace_record(l, 'V', NLR_FORMAT);
        return NLR_FORMAT;
    }
    /* The header itself declares 64 bytes; a shorter file is a size error
     * before any further read, as for the common-fields check above. */
    if (size < NLR_GENERIC_HEADER_SIZE) {
        nlr_trace_record(l, 'V', NLR_BOUNDS);
        return NLR_BOUNDS;
    }
    l->stage = 'H';
    int result = read_exact(l, fd, NLR_GENERIC_HEADER_SIZE - NPLD_HEADER_SIZE);
    if (result) {
        nlr_trace_record(l, 'H', -1);
        return result;
    }
    for (uint32_t n = NPLD_HEADER_SIZE; n < NLR_GENERIC_HEADER_SIZE; n++)
        h[n] = l->arena[n - NPLD_HEADER_SIZE];
    l->stage = 'V';
    uint32_t image = nlr_le32(h + 0xc);
    uint32_t bss = nlr_le32(h + 0x10);
    uint32_t entry = nlr_le32(h + 0x14);
    uint32_t abi = nlr_le32(h + 0x18);
    uint32_t image_crc = nlr_le32(h + 0x1c);
    uint32_t kind = nlr_le32(h + 0x20);
    uint32_t reloc = nlr_le32(h + 0x24);
    uint32_t data_crc = nlr_le32(h + 0x30);
    uint32_t reloc_crc = nlr_le32(h + 0x34);
    /* Version 3 carries the program's description behind the header; in
     * version 2 those two words are reserved like the rest. */
    uint32_t v3 = nlr_le16(h + 4) == NLR_NPLD_META_VERSION;
    uint32_t meta = v3 ? nlr_le32(h + 0x28) : 0;
    uint32_t meta_crc = v3 ? nlr_le32(h + 0x2c) : 0;
    l->meta_memory = 0;
    /* Reserved fields stay zero, so the format can grow without an old
     * loader silently accepting programs it cannot parse (PLAN 6.3). */
    if ((!v3 && (nlr_le32(h + 0x28) || nlr_le32(h + 0x2c))) ||
        nlr_le32(h + 0x38) || nlr_le32(h + 0x3c) ||
        (v3 && (!meta || meta > NLR_META_MAX || (meta & 7u)))) {
        nlr_trace_record(l, 'V', NLR_FORMAT);
        return NLR_FORMAT;
    }
    if (meta) {
        if (size < NLR_GENERIC_HEADER_SIZE + meta) {
            nlr_trace_record(l, 'V', NLR_BOUNDS);
            return NLR_BOUNDS;
        }
        l->stage = 'H';
        result = read_exact(l, fd, meta);
        if (result) {
            nlr_trace_record(l, 'H', -2);
            return result;
        }
        if (crc32(l->arena, meta) != meta_crc) {
            nlr_trace_record(l, 'K', NLR_CHECKSUM);
            return NLR_CHECKSUM;
        }
        l->meta_memory = nlr_meta_memory(l->arena, meta);
        l->stage = 'V';
        /* What follows is laid out as in version 2, after the block. */
        size -= meta;
    }
    if ((kind != NLR_KIND_RESOURCE_EXTENSION && kind != NLR_KIND_FOREGROUND) ||
        kind != l->manifest_kind || !abi || abi > NLR_ABI_VERSION || abi == 3u ||
        reloc % NLR_RELOC_ENTRY_SIZE != 0) {
        nlr_trace_record(l, 'V', NLR_FORMAT);
        return NLR_FORMAT;
    }
    /* data_size is not a header field: the layout header→reloc→image→data
     * is fixed, so the file length states it. Every segment must fit
     * one execution block. A larger file uses a bounded temporary read
     * buffer until the executor copies its segments out. */
    if ((uint64_t)size < (uint64_t)NLR_GENERIC_HEADER_SIZE + reloc + image) {
        nlr_trace_record(l, 'V', NLR_BOUNDS);
        return NLR_BOUNDS;
    }
    uint64_t data64 = (uint64_t)size - NLR_GENERIC_HEADER_SIZE - reloc - image;
    if (image < 4 || (entry & 3) || entry > image - 4 ||
        data64 > UINT32_MAX || image > NLR_EXEC_BLOCK_SIZE ||
        data64 > NLR_EXEC_BLOCK_SIZE ||
        bss > NLR_EXEC_BLOCK_SIZE - (uint32_t)data64 ||
        reloc > NLR_LOAD_RELOC_MAX ||
        (uint64_t)reloc + image + data64 > NLR_LOAD_SPILL_MAX) {
        nlr_trace_record(l, 'V', NLR_BOUNDS);
        return NLR_BOUNDS;
    }
    if ((uint64_t)reloc + image + data64 > l->capacity) {
        l->stage = 'B';
        result = spill(l, (uint32_t)((uint64_t)reloc + image + data64));
        if (result != NLR_OK) {
            nlr_trace_record(l, 'b', result);
            return result;
        }
    }
    uint32_t data = (uint32_t)data64;
    /* One contiguous read: the file stores reloc, image and data back to
     * back, and every chunk of a single read starts on a cache line of the
     * line-aligned arena, which separate segment reads could not. */
    l->stage = 'D';
    uint32_t segments = reloc + image + data;
    if (segments && (result = read_segment(l, fd, 0, segments)) != 0) {
        nlr_trace_record(l, 'D', -1);
        return result;
    }
    l->stage = 'K';
    if (crc32(l->arena + reloc, image) != image_crc ||
        (data ? crc32(l->arena + reloc + image, data) : 0) != data_crc ||
        (reloc ? crc32(l->arena, reloc) : 0) != reloc_crc) {
        nlr_trace_record(l, 'K', NLR_CHECKSUM);
        return NLR_CHECKSUM;
    }
    /* Relocation entries are pre-validated here: a rejection before any
     * execution memory is touched reads as "refused", not as a runtime
     * failure (PLAN 6.3). kind 0 fixes an ADRP inside the image and may
     * target any byte of the data segment; kind 1 writes a code pointer
     * into the data segment. */
    for (uint32_t n = 0; n < reloc; n += NLR_RELOC_ENTRY_SIZE) {
        const uint8_t *e = l->arena + n;
        uint32_t offset = nlr_le32(e);
        uint32_t target = nlr_le32(e + 4);
        uint32_t kind_entry = nlr_le32(e + 8);
        if (kind_entry == NLR_RELOC_ADRP) {
            if ((offset & 3) || (uint64_t)offset + 4 > image ||
                target >= (uint64_t)data + bss) {
                nlr_trace_record(l, 'V', NLR_BOUNDS);
                return NLR_BOUNDS;
            }
        } else if (kind_entry == NLR_RELOC_ABS64) {
            if ((offset & 7u) || (uint64_t)offset + 8 > (uint64_t)data + bss || target >= image) {
                nlr_trace_record(l, 'V', NLR_BOUNDS);
                return NLR_BOUNDS;
            }
        } else if (kind_entry == NLR_RELOC_ABS64_DATA) {
            if ((offset & 7u) || (uint64_t)offset + 8 > data ||
                target >= (uint64_t)data + bss) {
                nlr_trace_record(l, 'V', NLR_BOUNDS);
                return NLR_BOUNDS;
            }
        } else {
            nlr_trace_record(l, 'V', NLR_FORMAT);
            return NLR_FORMAT;
        }
    }
    result = relocation_writes_unique(l->arena, reloc);
    if (result != NLR_OK) {
        nlr_trace_record(l, 'V', result);
        return result;
    }
    for (uint32_t n = 0; n < NLR_GENERIC_HEADER_SIZE; n++)
        l->header[n] = h[n];
    l->stage = 'V';
    l->image_bytes = image;
    l->entry_offset = entry;
    l->bss_bytes = bss;
    l->abi_version = abi;
    l->data_bytes = data;
    l->reloc_bytes = reloc;
    l->program_kind = kind;
    l->header_bytes = NLR_GENERIC_HEADER_SIZE;
    nlr_trace_record(l, 'V', 0);
    return NLR_OK;
}

/* 1 when the attempt's path names a program of the release bundle and the
 * bundle holds it whole (the memory source is set), 0 for a card path,
 * -1 for a bundle path the bundle cannot serve. */
static const char bundle_prefix[] = NLR_PROGRAM_ROOT NLR_BUNDLE_DIR;

/* The length of the bundle prefix when the attempt's path has it, else 0. */
static uint32_t load_bundle_path(const struct nlr_load *l)
{
    uint32_t n = 0;
    while (bundle_prefix[n] && l->path[n] == bundle_prefix[n])
        n++;
    return bundle_prefix[n] ? 0 : n;
}

static int load_bundle_open(struct nlr_load *l)
{
    uint32_t n = load_bundle_path(l);
    if (!n)
        return 0;
    const struct nlr_platform_services *pl = l->svc->platform;
    const uint8_t *file = 0;
    uint32_t bytes = 0;
    if (!pl || !pl->bundle ||
        nlr_bundle_find(pl->bundle, pl->bundle_bytes, l->path + n, 1, &file,
                        &bytes) != 0)
        return -1;
    l->mem = file;
    l->mem_bytes = bytes;
    l->mem_pos = 0;
    return 1;
}

/* SAFE_MODE, as the card's presence store answers it -- before the attempt
 * reads anything and again once a program has been read whole (attempt),
 * on every body: the store decides whether the file is there (the native
 * card by its exact "not found", the file reader by the program's own file
 * opening beside it), not which card interface the body has. Another
 * task's card request may hold the card for a moment: waited for, a
 * bounded while. A card that answers for nothing holds no SAFE_MODE a
 * program of the release bundle has to respect; a
 * card program cannot be read from it either way. */
static int load_safe_guard(struct nlr_load *l)
{
    uint32_t bundled = load_bundle_path(l);
    const struct nlr_card_store *store = nlr_card_presence_store(l->svc);
    if (!store || !store->probe_beside)
        return NLR_NOT_READY;
    uint32_t present = UINT32_MAX;
    int result = store->probe_beside(NLR_SAFE_MODE_PATH, bundled ? 0 : l->path, &present);
    for (uint32_t tries = 0; result == NLR_BUSY && tries < 100u && l->svc->sleep_ms;
         tries++) {
        l->svc->sleep_ms(10u);
        result = store->probe_beside(NLR_SAFE_MODE_PATH, bundled ? 0 : l->path, &present);
    }
    if (result == NLR_NOT_READY && bundled)
        return NLR_OK;
    if (result != NLR_OK)
        return result;
    return present == 1u ? NLR_DISABLED : present == 0u ? NLR_OK : NLR_IO;
}

int nlr_load_file(struct nlr_load *l)
{
    if (!l || !l->svc) return NLR_NOT_READY;
    int released = unspill(l);
    if (released != NLR_OK) return released;
    l->stage = 'I';
    l->image_bytes = l->entry_offset = l->bss_bytes = l->abi_version = 0;
    l->header_bytes = 0;
    l->data_bytes = l->reloc_bytes = l->program_kind = 0;
    if (!l->svc || !l->path || !l->arena || l->capacity < NPLD_HEADER_SIZE)
        return NLR_NOT_READY;
    /* PLAN 4.4: the SAFE_MODE check is the first card operation of every
     * attempt, even right after a directory read, because the card may have
     * changed in between. Presence disables loading; nothing else on the
     * card is touched. */
    l->stage = 'M';
    int guarded = load_safe_guard(l);
    if (guarded != NLR_OK) {
        nlr_trace_record(l, 'M', guarded);
        return guarded;
    }
    l->stage = 'O';
    /* A program of the release bundle is read from memory: found by its
     * name and checked against the bundle's CRC first. Everything else is
     * a card file, read exactly as it always was. */
    l->mem = 0;
    l->mem_bytes = l->mem_pos = 0;
    int bundled = load_bundle_open(l);
    if (bundled < 0) {
        nlr_trace_record(l, 'O', -2);
        return NLR_IO;
    }
    int32_t fd = bundled ? 0 : l->svc->file_open(l->path, 0, 0);
    if (fd < 0) {
        nlr_trace_record(l, 'O', -1);
        return NLR_IO;
    }
    nlr_trace_record(l, 'O', fd);
    uint32_t size = 0, position = 0;
    int result = NLR_IO;
    l->stage = 'S';
    if (bundled) {
        size = l->mem_bytes;
    } else if (l->svc->file_seek(fd, NLR_SEEK_END, 0, &size) != 0 ||
               l->svc->file_seek(fd, NLR_SEEK_SET, 0, &position) != 0) {
        nlr_trace_record(l, 'S', -1);
        goto close;
    }
    /* The header itself plus the smallest meaningful image must exist. */
    if (size < NPLD_HEADER_SIZE + 4 || position != 0) {
        nlr_trace_record(l, 'S', -2);
        result = NLR_FORMAT;
        goto close;
    }
    l->stage = 'H';
    result = read_exact(l, fd, NPLD_HEADER_SIZE);
    if (result) {
        nlr_trace_record(l, 'H', -1);
        goto close;
    }
    l->stage = 'V';
    /* Header fields are cached before the image read overwrites the arena.
     * 64 bytes: the generic v2 header is read into the same buffer. */
    uint8_t h[NLR_GENERIC_HEADER_SIZE];
    for (uint32_t n = 0; n < NPLD_HEADER_SIZE; n++)
        h[n] = l->arena[n];
    uint32_t version = nlr_le16(h + 4), header_size = nlr_le16(h + 6);
    uint32_t image = nlr_le32(h + 0xc), bss = nlr_le32(h + 0x10);
    uint32_t entry = nlr_le32(h + 0x14), checksum = nlr_le32(h + 0x1c);
    l->abi_version = nlr_le32(h + 0x18);
    /* Generic v2 program (PLAN 6.3 M2-T4): 64-byte header with flags 0.
     * It takes its own validation path; the v1 and probe branches below
     * stay exactly as they were. */
    if ((version == 2 || version == NLR_NPLD_META_VERSION) &&
        header_size == NLR_GENERIC_HEADER_SIZE && nlr_le32(h + 8) == 0) {
        result = load_generic(l, fd, size, h);
        goto close;
    }
    if (h[0] != 'N' || h[1] != 'P' || h[2] != 'L' || h[3] != 'D' ||
        bss != 0 ||
        !((version == 1 && header_size == NPLD_HEADER_SIZE && nlr_le32(h + 8) == 0) ||
          (version == 2 && header_size == NLR_PROBE_HEADER_SIZE &&
           nlr_le32(h + 8) == 1 && image == NLR_PROBE_IMAGE_SIZE))) {
        nlr_trace_record(l, 'V', NLR_FORMAT);
        result = NLR_FORMAT;
        goto close;
    }
    /* The common fields already fix the file length, so a file cut short is
     * a size error before any further header byte is read. */
    if (image < 4 || image > l->capacity ||
        image > UINT32_MAX - NPLD_HEADER_SIZE ||
        size != image + header_size || (entry & 3) || entry > image - 4) {
        nlr_trace_record(l, 'V', NLR_BOUNDS);
        result = NLR_BOUNDS;
        goto close;
    }
    if (version == 2) {
        l->stage = 'H';
        result = read_exact(l, fd, NLR_PROBE_HEADER_SIZE - NPLD_HEADER_SIZE);
        if (result) {
            nlr_trace_record(l, 'H', -1);
            goto close;
        }
        for (uint32_t n = NPLD_HEADER_SIZE; n < header_size; n++)
            h[n] = l->arena[n - NPLD_HEADER_SIZE];
        l->stage = 'V';
    }
    l->stage = 'D';
    result = read_exact(l, fd, image);
    if (result) {
        nlr_trace_record(l, 'D', -1);
        goto close;
    }
    l->stage = 'K';
    if (crc32(l->arena, image) != checksum) {
        nlr_trace_record(l, 'K', NLR_CHECKSUM);
        result = NLR_CHECKSUM;
        goto close;
    }
    if (version == 2) {
        uint8_t probe[NLR_PROBE_FILE_SIZE];
        for (uint32_t n = 0; n < header_size; n++)
            probe[n] = h[n];
        for (uint32_t n = 0; n < image; n++)
            probe[header_size + n] = l->arena[n];
        result = nlr_probe_validate(probe, sizeof probe, l->manifest_kind);
        if (result)
            goto close;
    }
    for (uint32_t n = 0; n < header_size; n++)
        l->header[n] = h[n];
    l->header_bytes = header_size;
    l->stage = 'V';
    l->image_bytes = image;
    l->entry_offset = entry;
    l->bss_bytes = 0;
    nlr_trace_record(l, 'V', 0);
close:
    if (bundled) {
        l->mem = 0;
        l->mem_bytes = l->mem_pos = 0;
    } else if (l->svc->file_close(fd) != 0 && result == NLR_OK) {
        l->stage = 'C';
        nlr_trace_record(l, 'C', -1);
        result = NLR_IO;
    }
    if (result) {
        l->image_bytes = l->entry_offset = l->bss_bytes = l->abi_version = 0;
        l->header_bytes = 0;
        l->data_bytes = l->reloc_bytes = l->program_kind = 0;
    }
    return result;
}

/* Both normal entry return and the reactivated wrapper publish completion
 * only after the same worker-owned cleanup has finished. */
static int complete_attempt(struct nlr_load *l, int result)
{
    int retain = result == NLR_EXEC_RESTORE || l->program.code_allocation ||
        l->program.data_allocation || l->probe.allocation;
#if NLR_HAS_NATIVE_CARD
    if (l->svc->native_card && nlr_native_card_uncertain((struct nlr_runtime *)l)) retain = 1;
#endif
    if (l->spill_request && retain) {
        spill_restore_home(l);
        __atomic_store_n(&l->spill_uncertain, 1u, __ATOMIC_RELEASE);
        result = NLR_EXEC_RESTORE;
    } else if (unspill(l) != NLR_OK) result = NLR_EXEC_RESTORE;
    l->last_result = result;
    nlr_trace_record(l, 'E', result);
    if (result != NLR_OK)
        nlr_journal(l->journal, "attempt failed: %d at stage %c", result,
                    l->stage ? (int)l->stage : '-');
    __atomic_store_n(&l->state, 0, __ATOMIC_RELEASE);
#if NLR_HAS_NATIVE_CARD
    nlr_native_card_wake((struct nlr_runtime *)l);
#endif
    /* what the attempt (a program's whole run, often) left in the log */
    (void)nlr_journal_flush(l->journal, l->svc, 0);
    return result;
}

/* The worker has just finished a job of its own, and what it finished may
 * be one step of an autoload pass. On a model with no mount-time
 * checkpoint the only other driver is a page visit, and a visit cannot
 * take in a result the worker produces after it has returned — so the
 * pass would advance one step per visit and a camera switched off after
 * the first would find the marker still there. Carrying it on from here
 * is what lets a single visit finish it, marker and all.
 *
 * Only from the worker's event: the loader is also driven synchronously
 * (the manifest recheck inside a start), and running the state machine
 * from inside its own start would re-enter it. The loader is exercised as
 * a bare object too, which owns no pass at all. */
static void continue_autoload(struct nlr_load *l)
{
    if (!l->in_runtime)
        return;
    /* The boot program's record first, on this task, which the program's
     * own card files already use: when the attempt just finished was the
     * boot program's, its outcome is written here (runtime.c). */
    nlr_runtime_boot_completed((struct nlr_runtime *)l);
#if NLR_HAS_NATIVE_CARD
    if (l->svc->native_card)
        return;
#endif
    nlr_runtime_autoload_continue((struct nlr_runtime *)l);
}

/* The attempt itself, once the caller owns the loading state. */
static int attempt(struct nlr_load *l)
{
    int result = NLR_OK;
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    if (l->probe_mode && l->probe.allocation) {
        /* An earlier cleanup failed and kept its region: nothing may run
         * again, and that attempt's record (phase, flags, response) is the
         * evidence of the failure, so it is left exactly as it was. */
        result = NLR_EXEC_RESTORE;
    } else if (l->probe_mode) {
        l->probe.phase = 'M';
        l->probe.prepared = l->probe.entry_started = l->probe.returned = 0;
        l->probe.expected = l->probe.response = 0;
        extern int nlr_runtime_probe_recheck(struct nlr_load *load);
        result = nlr_runtime_probe_recheck(l);
        if (result == NLR_OK)
            l->probe.phase = 'L';
    }
    if (l->program_mode && l->program.code_allocation) {
        /* An earlier run's cleanup could not restore or release its blocks;
         * nothing may run again and that attempt's record stays as it was. */
        result = NLR_EXEC_RESTORE;
    } else if (l->program_mode) {
        l->program.phase = 'M';
        l->program.prepared = l->program.entry_started = 0;
        l->program.returned = l->program.kept = l->program.exit_requested = 0;
        l->program.exit_code = 0;
        __atomic_store_n(&l->program.jump_armed, 0u, __ATOMIC_RELEASE);
        result = nlr_runtime_program_recheck(l);
        if (result == NLR_OK)
            l->program.phase = 'L';
    }
#endif
    if (result == NLR_OK)
        result = nlr_load_file(l);
    /* The card may have changed while the program was read: SAFE_MODE is
     * asked again before anything runs, the same way on every body. */
    if (result == NLR_OK && (l->program_mode || l->probe_mode)) {
        result = load_safe_guard(l);
        if (result != NLR_OK)
            nlr_trace_record(l, 'M', result);
    }
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    if (l->probe_mode) {
        l->probe_attempted = 1;
        if (result == NLR_OK) {
            extern const struct nlr_exec_services nlr_exec_services;
            if (l->header_bytes != NLR_PROBE_HEADER_SIZE ||
                l->image_bytes != NLR_PROBE_IMAGE_SIZE) {
                result = NLR_FORMAT;
            } else {
                uint8_t file[NLR_PROBE_FILE_SIZE];
                for (uint32_t n = 0; n < NLR_PROBE_HEADER_SIZE; n++)
                    file[n] = l->header[n];
                for (uint32_t n = 0; n < NLR_PROBE_IMAGE_SIZE; n++)
                    file[NLR_PROBE_HEADER_SIZE + n] = l->arena[n];
                uint64_t challenge = ++l->probe_sequence * UINT64_C(0x9e3779b97f4a7c15);
                nlr_trace_record(l, 'p', (int32_t)l->probe_sequence);
                result = nlr_probe_run(&l->probe, &nlr_exec_services, file,
                    sizeof file, l->manifest_kind, challenge, l->probe_mode == 1);
                nlr_trace_record(l, 'x', (int32_t)l->probe.phase);
                nlr_trace_record(l, 'r', (int32_t)l->probe.response);
                nlr_trace_record(l, 's', (int32_t)(l->probe.response >> 32));
            }
        }
        l->probe_mode = 0;
    }
    if (l->program_mode) {
        l->program_attempted = 1;
        if (result == NLR_OK) {
            if (l->header_bytes != NLR_GENERIC_HEADER_SIZE) {
                result = NLR_FORMAT;
            } else {
                /* The arena holds [reloc][image][data]; BSS is a size the
                 * executor zeroes into the data block. */
                struct nlr_program_segments segments = {
                    .reloc = l->reloc_bytes ? l->arena : 0,
                    .image = l->arena + l->reloc_bytes,
                    .data = (l->data_bytes || l->bss_bytes)
                                ? l->arena + l->reloc_bytes + l->image_bytes
                                : 0,
                    .image_size = l->image_bytes,
                    .data_size = l->data_bytes,
                    .bss_size = l->bss_bytes,
                    .entry_offset = l->entry_offset,
                    .reloc_size = l->reloc_bytes,
                    .kind = l->program_kind,
                    .abi_version = l->abi_version,
                    .consumed = segments_consumed,
                    .consumed_context = l,
                };
                int input_owner = l->program_mode == 2 &&
                    l->program_kind == NLR_KIND_FOREGROUND;
                /* The log reaches the card before the program runs: one
                 * that waits (for a choice, a key) does not end its
                 * attempt, and the attempt's own flush below would come
                 * only then -- a start that left no line looked like a
                 * tap that did nothing (Z 8 SD, Files). The worker's own
                 * reads are over here. */
                (void)nlr_journal_flush(l->journal, l->svc, 0);
                if (input_owner)
                    result = nlr_runtime_input_begin(l);
                if (result == NLR_OK)
                    result = nlr_program_run(&l->program, &nlr_exec_services,
                                             &segments, &nlr_api,
                                             l->program_mode == 1);
                if (input_owner)
                    nlr_runtime_input_end(l);
                nlr_trace_record(l, 'g', (int32_t)l->program.phase);
                if (l->program.returned)
                    nlr_trace_record(l, 'h', l->program.exit_code);
                /* In brackets the executor's phase (A: the heap's blocks);
                 * the attempt's own failure line names the file stage. A
                 * line holds NLR_JOURNAL_TEXT - 1 characters. */
                nlr_journal(l->journal, "program ran: %d (%c), returned %u code %d, stop %u, exit %u",
                            result, l->program.phase ? (int)l->program.phase : '-',
                            l->program.returned, l->program.exit_code,
                            l->program.stop_requested, l->program.exit_requested);
                if (l->program.kept) {
                    /* A resource extension whose entry ran: the blocks stay
                     * resident and their ownership moves to the runtime,
                     * for a successful and a failed initialization alike. A
                     * failed registration keeps the state retained, so
                     * later runs are refused instead of silently unowned. */
                    if (nlr_runtime_register_resident(l) == NLR_OK)
                        for (size_t n = 0; n < sizeof l->program; n++)
                            ((uint8_t *)&l->program)[n] = 0;
                    else
                        result = NLR_EXEC_RESTORE;
                }
            }
        }
        l->program_mode = 0;
    }
#endif
    return complete_attempt(l, result);
}

void nlr_load_event(void *self, uint32_t events)
{
    struct nlr_load *l = self;
    if (!l)
        return;
    if (!__atomic_load_n(&l->worker_stack_hi, __ATOMIC_ACQUIRE)) {
        /* The frames above this one are the worker loop's (well under
         * 4 KiB); the range stops 4 KiB short of the stack's bottom. */
        uint64_t here = (uint64_t)(uintptr_t)__builtin_frame_address(0);
        l->worker_stack_lo = here - l->task.stack_bytes + 0x1000u;
        __atomic_store_n(&l->worker_stack_hi, here + 0x400u, __ATOMIC_RELEASE);
    }
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    uint32_t stopped = 3;
    if ((events & NLR_LOAD_STOP_EVENT) &&
        __atomic_compare_exchange_n(&l->state, &stopped, 2, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        extern const struct nlr_exec_services nlr_exec_services;
        int result = nlr_program_finish_stopped(&l->program, &nlr_exec_services);
        nlr_runtime_input_end(l);
        l->program_attempted = 1;
        l->program_mode = 0;
        nlr_trace_record(l, 'g', (int32_t)l->program.phase);
        if (l->program.returned)
            nlr_trace_record(l, 'h', l->program.exit_code);
        nlr_journal(l->journal, "program stopped: %d", result);
        complete_attempt(l, result);
        continue_autoload(l);
        return;
    }
#endif
    uint32_t expected = 1;
    if (!(events & NLR_LOAD_RUN_EVENT) ||
        !__atomic_compare_exchange_n(&l->state, &expected, 2, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    attempt(l);
    continue_autoload(l);
}

int nlr_load_now(struct nlr_load *l)
{
    if (!l || !l->svc || l->probe_mode || l->program_mode)
        return NLR_NOT_READY;
    if (__atomic_load_n(&l->spill_uncertain, __ATOMIC_ACQUIRE)) return NLR_EXEC_RESTORE;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&l->state, &expected, 2, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        nlr_trace_record(l, 'E', NLR_BUSY);
        return NLR_BUSY;
    }
    return attempt(l);
}

int nlr_load_init(struct nlr_load *l, const struct nlr_services *svc,
                  uint8_t *arena, uint32_t capacity,
                  const struct nlr_task_config *task)
{
    /* Card reads invalidate the arena line by line before each chunk; it has
     * to start on a line and own whole lines (services.h). */
    if (!l || !svc || !arena || !task || !nlr_cache_aligned(arena, capacity) ||
        capacity < NPLD_HEADER_SIZE || task->core > NLR_TASK_CORE_MAX ||
        task->priority == 0 || task->priority > 256 || task->stack_bytes == 0 ||
        task->stack_bytes > UINT32_MAX - 15)
        return NLR_NOT_READY;
    if (l->ready)
        return NLR_BUSY;
    l->svc = svc;
    l->path = 0;
    l->arena = arena;
    l->capacity = capacity;
    l->task = *task;
    l->state = 0;
    l->last_result = NLR_OK;
    l->image_bytes = l->entry_offset = l->bss_bytes = l->abi_version = 0;
    l->data_bytes = l->reloc_bytes = l->program_kind = 0;
    l->home_arena = 0;
    l->home_capacity = l->spill_bytes = l->spill_uncertain = 0;
    l->spill_request = 0;
    l->program_mode = l->program_attempted = 0;
    l->chunk_read = 0;
    l->worker_stack_lo = l->worker_stack_hi = 0;
    l->stage = 'I';
    /* Called once from initialized task context; the caller publishes the
     * ready flag afterwards. worker_init cannot report a kernel failure
     * directly, so an undiscoverable task or flag id becomes NLR_PARTIAL. */
    uint32_t mask = NLR_LOAD_RUN_EVENT;
    if (svc->exit)
        mask |= NLR_LOAD_STOP_EVENT;
    svc->worker_init(&l->worker, nlr_load_event, mask, &l->task);
    /* Ids must be discoverable by the family scan: zero, or an id beyond the
     * registry scan range, can never be found again — the same failure class
     * as a kernel object that was never created. */
    uint32_t task_id = nlr_le32(l->worker.opaque + NLR_WORKER_ID_OFFSET);
    uint32_t flag_id = nlr_le32(l->worker.opaque + NLR_WORKER_FLAG_OFFSET);
    if (task_id == 0 || task_id > NLR_REGISTRY_IDS || flag_id == 0 ||
        flag_id > NLR_REGISTRY_IDS) {
        nlr_trace_record(l, 'W', 0);
        return NLR_PARTIAL; /* firmware objects may exist; do not unwind */
    }
    nlr_trace_record(l, 'W', (int32_t)task_id);
    svc->worker_start(&l->worker);
    __atomic_store_n(&l->ready, 1, __ATOMIC_RELEASE);
    return NLR_OK;
}

int nlr_load_enqueue_once(struct nlr_load *l)
{
    if (!l || !l->svc)
        return NLR_NOT_READY;
    if (__atomic_load_n(&l->spill_uncertain, __ATOMIC_ACQUIRE)) return NLR_EXEC_RESTORE;
    if (!__atomic_load_n(&l->ready, __ATOMIC_ACQUIRE))
        return NLR_NOT_READY;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&l->state, &expected, 1, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        nlr_trace_record(l, 'Q', NLR_BUSY);
        return NLR_BUSY;
    }
    int32_t r = l->svc->flag_set(
        l->worker.opaque + NLR_WORKER_FLAG_OFFSET, 1);
    if (r != 0) {
        nlr_trace_record(l, 'Q', NLR_IO);
        __atomic_store_n(&l->state, 0, __ATOMIC_RELEASE);
        return NLR_IO;
    }
    nlr_trace_record(l, 'Q', 0);
    return NLR_OK;
}
