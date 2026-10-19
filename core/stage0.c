#include "nlr/stage0.h"

#include "nlr/card.h"
#include "nlr/load.h"
#include "nlr/manifest.h"

/*
 * Dev firmware's stage 0. Built into the module in place of the loader: the boot
 * checkpoint lands here, and so does nothing else. Every turn it makes the
 * stock call first and returns what that returned; in between it either
 * waits for the card, decides this boot stays stock, or hands the turn to
 * the core it loaded from the card.
 *
 * What runs here runs on every boot of a camera that carries it, so the
 * rules of the recovery paths hold for all of it: DISP held at power-on,
 * no card, no core, a core that did not start well last time -- each ends
 * this boot's stage 0 with nothing more than reading the card, and the
 * camera is the stock one. Nothing is written to the card but the start
 * mark: "run" as a core is about to start, "ok" when the core says it has
 * run well, "skipped" or "refused" when it is not started.
 *
 * Stage 0 keeps its state in a small allocation of its own, found again
 * each turn through the firmware's task registry, as the loader finds its
 * runtime: a worker object it creates (and never wakes) is the first member
 * and carries the name. The module holds no writable data.
 */

extern const struct nlr_services nlr_services;
extern const struct nlr_exec_services nlr_exec_services;
extern const struct nlr_task_config nlr_task_config;
const struct nlr_card_store *nlr_file_store(void);

#define STAGE0_NAME "NLRSTG0"

struct stage0_state {
    struct nlr_worker worker; /* first: the registry hands out its address */
    struct nlr_task_config task;
    uint32_t phase;           /* NLR_STAGE0_* */
    uint32_t why;             /* NLR_STAGE0_WHY_* while stock */
    uint32_t turns;
    uint32_t asks;
    uint32_t core_turns;      /* turns handed to the core (diagnosis) */
    int32_t result;           /* the last check or start result */
    struct nlr_stage0_handshake handshake;
    struct nlr_program_state program; /* the core's blocks, kept for good */
};

/* ---- pure parts (host-tested in test_stage0.c) ---------------------------- */

uint32_t nlr_stage0_mark_says(const uint8_t *mark, uint32_t bytes)
{
    return mark && bytes >= 3u && mark[0] == 'r' && mark[1] == 'u' && mark[2] == 'n'
               ? NLR_STAGE0_MARK_SKIP
               : NLR_STAGE0_MARK_START;
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

/* `value` is exactly the text of `key` in the description. */
static int meta_is(const uint8_t *meta, uint32_t bytes, const char *key,
                   const char *value)
{
    uint32_t length = 0;
    const uint8_t *v = nlr_meta_find(meta, bytes, key, &length);
    if (!v)
        return 0;
    uint32_t n = 0;
    while (n < length && value[n] && v[n] == (uint8_t)value[n])
        n++;
    return n == length && !value[n];
}

int nlr_stage0_check(const uint8_t *file, uint32_t bytes,
                     struct nlr_program_segments *out)
{
    if (!file || !out || bytes < NLR_GENERIC_HEADER_SIZE)
        return NLR_FORMAT;
    if (file[0] != 'N' || file[1] != 'P' || file[2] != 'L' || file[3] != 'D' ||
        nlr_le16(file + 4) != NLR_NPLD_META_VERSION ||
        nlr_le16(file + 6) != NLR_GENERIC_HEADER_SIZE || nlr_le32(file + 8) ||
        nlr_le32(file + 0x38) || nlr_le32(file + 0x3c))
        return NLR_FORMAT;
    uint32_t image = nlr_le32(file + 0xc), bss = nlr_le32(file + 0x10);
    uint32_t entry = nlr_le32(file + 0x14), abi = nlr_le32(file + 0x18);
    uint32_t kind = nlr_le32(file + 0x20), reloc = nlr_le32(file + 0x24);
    uint32_t meta = nlr_le32(file + 0x28);
    /* A core is a resident extension: its blocks stay for the boot. */
    if (kind != 1u)
        return NLR_REFUSED;
    if (!meta || meta > NLR_META_MAX || (meta & 7u) ||
        bytes - NLR_GENERIC_HEADER_SIZE < meta)
        return NLR_FORMAT;
    const uint8_t *m = file + NLR_GENERIC_HEADER_SIZE;
    if (crc32(m, meta) != nlr_le32(file + 0x2c))
        return NLR_CHECKSUM;
    /* The description says what it is and which stage 0 it was built for;
     * a core for another stage 0 has another handshake and is not run. */
    if (!meta_is(m, meta, "id", "core") || !meta_is(m, meta, "stage0", "1") ||
        !meta_is(m, meta, "data", "readonly") || bss)
        return NLR_REFUSED;
    uint64_t fixed = (uint64_t)NLR_GENERIC_HEADER_SIZE + meta + reloc + image;
    if (reloc % NLR_RELOC_ENTRY_SIZE || reloc > NLR_LOAD_RELOC_MAX ||
        fixed > bytes || image < 4u || (entry & 3u) || entry > image - 4u ||
        image > NLR_EXEC_BLOCK_SIZE)
        return NLR_BOUNDS;
    uint32_t data = (uint32_t)(bytes - fixed);
    if (data > NLR_EXEC_BLOCK_SIZE || bss > NLR_EXEC_BLOCK_SIZE - data ||
        (!data && !bss && reloc))
        return NLR_BOUNDS;
    const uint8_t *table = m + meta;
    const uint8_t *code = table + reloc;
    const uint8_t *init = code + image;
    if (crc32(code, image) != nlr_le32(file + 0x1c) ||
        (data ? crc32(init, data) : 0) != nlr_le32(file + 0x30) ||
        (reloc ? crc32(table, reloc) : 0) != nlr_le32(file + 0x34))
        return NLR_CHECKSUM;
    /* Every entry is checked here, before anything is allocated, exactly as
     * the loader checks a program's: nothing it writes may land outside its
     * own block. */
    for (uint32_t n = 0; n < reloc; n += NLR_RELOC_ENTRY_SIZE) {
        uint32_t offset = nlr_le32(table + n), target = nlr_le32(table + n + 4);
        uint32_t which = nlr_le32(table + n + 8);
        if (which == NLR_RELOC_ADRP) {
            if ((offset & 3u) || (uint64_t)offset + 4u > image ||
                target >= (uint64_t)data + bss)
                return NLR_BOUNDS;
        } else if (which == NLR_RELOC_ABS64) {
            if ((offset & 7u) || (uint64_t)offset + 8u > (uint64_t)data + bss ||
                target >= image)
                return NLR_BOUNDS;
        } else if (which == NLR_RELOC_ABS64_DATA) {
            if ((offset & 7u) || (uint64_t)offset + 8u > data ||
                target >= (uint64_t)data + bss)
                return NLR_BOUNDS;
        } else {
            return NLR_FORMAT;
        }
    }
    out->reloc = table;
    out->image = code;
    out->data = init;
    out->image_size = image;
    out->data_size = data;
    out->bss_size = bss;
    out->entry_offset = entry;
    out->reloc_size = reloc;
    out->kind = kind;
    out->abi_version = abi;
    out->consumed = 0;
    out->consumed_context = 0;
    /* The core's data is its pointer tables, read-only once relocated (its
     * build refuses any other writable data): one region holds all of it. */
    out->flat = 1;
    return NLR_OK;
}

#if !defined(NLR_STAGE0_HOST_TEST)
/* ---- the camera side ------------------------------------------------------- */

/* The executor's two outside needs in stage 0: a foreground program's API
 * cleanup (stage 0 only ever runs the core, a resident extension, so this
 * is never reached) and the check of other residents after a short grant
 * (stage 0 has no other residents). */
int nlr_api_program_cleanup(struct nlr_program_state *p)
{
    (void)p;
    return NLR_OK;
}

void nlr_exec_resident_recheck(const struct nlr_exec_services *services)
{
    (void)services;
}

static void stage0_event(void *self, uint32_t events)
{
    (void)self;
    (void)events;
}

/* Stage 0's state, through the registry. A named task that is not a whole
 * state is an earlier creation that failed half way: `named` counts it,
 * and no second one is made. */
static struct stage0_state *stage0_find(uint32_t *named)
{
    const struct nlr_services *svc = &nlr_services;
    struct stage0_state *found = 0;
    *named = 0;
    if (!svc->registry_lookup)
        return 0;
    for (uint32_t id = 1; id <= NLR_REGISTRY_IDS; id++) {
        void *object = 0;
        svc->registry_lookup(NLR_REGISTRY_TYPE_TASK, id, &object);
        uintptr_t address = (uintptr_t)object;
        if (!address || (address & 7))
            continue;
        const volatile uint8_t *w = (const volatile uint8_t *)address;
        if (*(const volatile uint32_t *)(w + NLR_WORKER_ID_OFFSET) != id)
            continue;
        unsigned n = 0;
        while (n < NLR_TASK_NAME_SIZE && w[NLR_WORKER_NAME_OFFSET + n] ==
                                             (uint8_t)STAGE0_NAME[n])
            n++;
        if (n != NLR_TASK_NAME_SIZE)
            continue;
        (*named)++;
        if (*(const volatile uint64_t *)(w + NLR_WORKER_SELF_OFFSET) != (uint64_t)address ||
            *(const volatile uint64_t *)(w + NLR_WORKER_CALLBACK_OFFSET) !=
                (uint64_t)(uintptr_t)stage0_event)
            continue;
        if (found && found != (struct stage0_state *)address)
            return 0;
        found = (struct stage0_state *)address;
    }
    return found;
}

static struct stage0_state *stage0_create(void)
{
    const struct nlr_services *svc = &nlr_services;
    if (!svc->worker_init || !svc->worker_start)
        return 0;
    void *memory = nlr_alloc_whole(svc, (uint32_t)sizeof(struct stage0_state) + 8u);
    if (!memory)
        return 0;
    struct stage0_state *s =
        (struct stage0_state *)(((uintptr_t)memory + 7u) & ~(uintptr_t)7u);
    for (uint32_t n = 0; n < sizeof *s; n++)
        ((uint8_t *)s)[n] = 0;
    s->task = nlr_task_config;
    for (uint32_t n = 0; n < NLR_TASK_NAME_SIZE; n++)
        s->task.name[n] = STAGE0_NAME[n];
    /* The task only exists to be found again: it never runs anything. */
    s->task.stack_bytes = 0x1000u;
    svc->worker_init(&s->worker, stage0_event, 1u, &s->task);
    uint32_t task = nlr_le32(s->worker.opaque + NLR_WORKER_ID_OFFSET);
    if (!task || task > NLR_REGISTRY_IDS)
        return 0; /* kernel objects may point in: the memory stays */
    svc->worker_start(&s->worker);
    return s;
}

static void stage0_stock(struct stage0_state *s, uint32_t why)
{
    s->why = why;
    __atomic_store_n(&s->phase, NLR_STAGE0_STOCK, __ATOMIC_RELEASE);
}

/* DISP held right now, from the scan object the input task fills; 0 also
 * when the model names no DISP. */
static int stage0_escape(void)
{
    const struct nlr_program_services *ps = nlr_services.program;
    if (!ps || !ps->input_object || ps->banks > 4u)
        return 0;
    const struct nlr_program_key *disp = &ps->keys[9];
    if (!disp->mask || disp->bank >= ps->banks)
        return 0;
    const volatile uint32_t *bank = (const volatile uint32_t *)(
        (const uint8_t *)ps->input_object + ps->bank_base + disp->bank * ps->bank_stride);
    return (bank[0] & disp->mask) != 0;
}

/* The input task has given its callback slot an occupant: its scan object
 * holds real scans from then on, so DISP reads true. Without a declared
 * slot there is nothing to wait for. */
static int stage0_input_ready(void)
{
    const struct nlr_program_services *ps = nlr_services.program;
    return !ps || !ps->input_slot ||
           __atomic_load_n(ps->input_slot, __ATOMIC_ACQUIRE) != 0;
}

/* The whole core file into whole owned cache lines. */
static int stage0_read(void **request, uint8_t **file, uint32_t *bytes)
{
    const struct nlr_services *svc = &nlr_services;
    *request = 0;
    *file = 0;
    *bytes = 0;
    int32_t fd = svc->file_open(NLR_STAGE0_CORE_PATH, 0, 0);
    if (fd < 0)
        return NLR_IO;
    uint32_t size = 0, position = 0;
    int result = NLR_IO;
    if (svc->file_seek(fd, NLR_SEEK_END, 0, &size) != 0 ||
        svc->file_seek(fd, NLR_SEEK_SET, 0, &position) != 0 || position)
        goto close;
    if (size < NLR_GENERIC_HEADER_SIZE || size > NLR_STAGE0_CORE_MAX) {
        result = NLR_BOUNDS;
        goto close;
    }
    uint32_t lines = nlr_cache_lines(size) + NLR_CACHE_LINE;
    /* Where the model's heap books can be read, the block is granted whole
     * (the executor's own discipline); else the allocator is taken at its
     * word (nlr_alloc_whole). */
    void *block = nlr_alloc_whole(svc, lines);
    if (!block) {
        result = NLR_NOT_READY;
        goto close;
    }
    *request = block;
    uint8_t *buffer = (uint8_t *)(((uintptr_t)block + NLR_CACHE_LINE - 1u) &
                                  ~(uintptr_t)(NLR_CACHE_LINE - 1u));
    for (uint32_t received = 0; received < size;) {
        uint32_t chunk = size - received < NLR_LOAD_CHUNK ? size - received : NLR_LOAD_CHUNK;
        if (svc->cache_before_read)
            svc->cache_before_read(buffer + received, chunk);
        for (uint32_t filled = 0; filled < chunk;) {
            uint32_t done = 0;
            if (svc->file_read(fd, buffer + received + filled, chunk - filled, &done) ||
                !done || done > chunk - filled)
                goto close;
            filled += done;
        }
        if (svc->cache_after_read)
            svc->cache_after_read(buffer + received, chunk);
        received += chunk;
    }
    *file = buffer;
    *bytes = size;
    result = NLR_OK;
close:
    if (svc->file_close(fd) != 0 && result == NLR_OK)
        result = NLR_IO;
    return result;
}

/* The core ran long enough on its own clock: the next boot may start it
 * again. Called by the core, on the task it runs on. */
static void stage0_started_well(void)
{
    const struct nlr_card_store *store = nlr_file_store();
    if (store && store->replace)
        (void)store->replace(NLR_STAGE0_MARK_PATH, (const uint8_t *)"ok", 2);
}

/* Read, check and start the core. NLR_OK with the core's turn in the
 * handshake, or the reason this boot stays stock. */
static uint32_t stage0_start(struct stage0_state *s)
{
    void *request = 0;
    uint8_t *file = 0;
    uint32_t bytes = 0;
    int result = stage0_read(&request, &file, &bytes);
    uint32_t why = NLR_STAGE0_WHY_NONE;
    struct nlr_program_segments segments;
    if (result == NLR_NOT_READY)
        why = NLR_STAGE0_WHY_MEMORY;
    else if (result != NLR_OK)
        why = NLR_STAGE0_WHY_IO;
    else if ((result = nlr_stage0_check(file, bytes, &segments)) != NLR_OK)
        why = NLR_STAGE0_WHY_REFUSED;
    if (!why) {
        s->handshake.magic = NLR_STAGE0_MAGIC;
        s->handshake.version = NLR_STAGE0_VERSION;
        s->handshake.turn = 0;
        s->handshake.started_well = stage0_started_well;
        s->handshake.reported = 0;
        /* The executor hands its third argument to the entry in x0: here
         * that is the handshake, not an API table. */
        result = nlr_program_run(&s->program, &nlr_exec_services, &segments,
                                 (const struct nlr_api *)(const void *)&s->handshake, 0);
        uintptr_t turn = (uintptr_t)s->handshake.turn;
        uintptr_t code = (uintptr_t)s->program.code_page;
        /* Only a core that started, stays, and whose turn is its own code
         * is ever called again. */
        if (result != NLR_OK || !s->program.kept || !turn || turn < code ||
            turn - code >= s->program.region_bytes || (turn & 3u))
            why = NLR_STAGE0_WHY_START;
    }
    s->result = result;
    if (request)
        nlr_services.release(request);
    return why;
}

static void stage0_turn(struct stage0_state *s)
{
    uint32_t phase = __atomic_load_n(&s->phase, __ATOMIC_ACQUIRE);
    if (phase == NLR_STAGE0_RUNNING) {
        s->core_turns++;
        s->handshake.turn(&s->handshake);
        return;
    }
    if (phase == NLR_STAGE0_STOCK)
        return;
    /* Nothing is asked before the buttons read true. */
    if (!stage0_input_ready())
        return;
    if (stage0_escape()) {
        stage0_stock(s, NLR_STAGE0_WHY_ESCAPE);
        return;
    }
    uint32_t turn = ++s->turns;
    if (turn & (turn - 1u))
        return;
    __atomic_store_n(&s->phase, NLR_STAGE0_WAITING, __ATOMIC_RELEASE);
    const struct nlr_card_store *store = nlr_file_store();
    uint32_t present = 0;
    if (!store || !store->probe || !store->replace) {
        stage0_stock(s, NLR_STAGE0_WHY_NO_CARD);
        return;
    }
    if (store->probe(NLR_STAGE0_CORE_PATH, &present) != NLR_OK) {
        /* a card still mounting answers with an error: ask again later */
        if (++s->asks >= NLR_STAGE0_CARD_ASKS)
            stage0_stock(s, NLR_STAGE0_WHY_NO_CARD);
        return;
    }
    if (!present) {
        stage0_stock(s, NLR_STAGE0_WHY_NO_CORE);
        return;
    }
    _Alignas(NLR_CACHE_LINE) uint8_t mark[NLR_CACHE_LINE];
    uint32_t bytes = 0;
    if (nlr_card_read(&nlr_services, NLR_STAGE0_MARK_PATH, mark, sizeof mark, &bytes, 0) !=
        NLR_OK)
        bytes = 0;
    if (nlr_stage0_mark_says(mark, bytes) == NLR_STAGE0_MARK_SKIP) {
        (void)store->replace(NLR_STAGE0_MARK_PATH, (const uint8_t *)"skipped", 7);
        stage0_stock(s, NLR_STAGE0_WHY_SKIPPED);
        return;
    }
    if (store->replace(NLR_STAGE0_MARK_PATH, (const uint8_t *)"run", 3) != NLR_OK) {
        stage0_stock(s, NLR_STAGE0_WHY_IO);
        return;
    }
    uint32_t why = stage0_start(s);
    if (why) {
        /* A file that was refused never ran: the mark says so, and the
         * next boot reads the card again. A start that failed after the
         * entry may have run keeps "run", so the next boot skips it. */
        if (why == NLR_STAGE0_WHY_REFUSED || why == NLR_STAGE0_WHY_IO ||
            why == NLR_STAGE0_WHY_MEMORY)
            (void)store->replace(NLR_STAGE0_MARK_PATH, (const uint8_t *)"refused", 7);
        stage0_stock(s, why);
        return;
    }
    __atomic_store_n(&s->phase, NLR_STAGE0_RUNNING, __ATOMIC_RELEASE);
    s->core_turns++;
    s->handshake.turn(&s->handshake);
}

/* The checkpoint the module's stock call is pointed at (the same entry the
 * loader build uses, so the boot hook patch is unchanged). */
void *nlr_boot_autoload_checkpoint(void)
{
    void *original = nlr_boot_autoload.callee();
    uint32_t named = 0;
    struct stage0_state *s = stage0_find(&named);
    if (!s && !named)
        s = stage0_create();
    if (s)
        stage0_turn(s);
    return original;
}
#endif
