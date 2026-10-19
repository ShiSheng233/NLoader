#ifndef NLR_LOAD_H
#define NLR_LOAD_H

#include "nlr/services.h"
#include "nlr/exec.h"
#include "nlr/card.h"
#include "nlr/journal.h"

/* NPLD program header for the load stage (header_version = 1, 32 bytes):
 * magic "NPLD", u16 version, u16 header size, u32 flags, u32 image size,
 * u32 bss size (must be zero here), u32 entry offset (checked, never
 * executed), u32 abi version (recorded only), u32 IEEE CRC32 of the image.
 * The file must be exactly header + image bytes long. Two v2 shapes are
 * accepted: the fixed return-probe diagnostic defined in exec.h
 * (header_size 48, flags 1) and the generic program header of PLAN 6.3
 * M2-T4 (header_size 64, flags 0, validated in load.c). */
#define NPLD_HEADER_SIZE 32u
/* Generic v2 execution header: 64 bytes. 0x00-0x1F carry the v1 common
 * fields with bss_size and abi_version holding real values; 0x20 kind,
 * 0x24 relocation size, 0x28/0x2C and 0x38-0x3F reserved zero, 0x30
 * CRC32(data), 0x34 CRC32(relocation table). data_size is not a header
 * field: the file layout header→reloc→image→data is fixed, so the file
 * length states it. */
#define NLR_GENERIC_HEADER_SIZE 64u
/* Version 3 of the generic header: the same 64 bytes,
 * with 0x28 the bytes of a metadata block that follows the header and 0x2C
 * its CRC32; the layout is header -> metadata -> reloc -> image -> data.
 * The block is the program's own description, "key=value" lines (see
 * nlr/manifest.h, nlr_meta_*), at most NLR_META_MAX bytes, a multiple of 8,
 * padded with NULs. */
#define NLR_NPLD_META_VERSION 3u
#define NLR_META_MAX 4096u
#define NLR_LOAD_CHUNK   0x1000u
#define NLR_LOAD_RUN_EVENT 1u
#define NLR_LOAD_STOP_EVENT 2u

/* In-RAM diagnostic ring. The loader records one entry per notable step and
 * the whole ring is read back over PTP (mem dump of the runtime allocation);
 * nothing is written to the card. Entry layout: high 32 bits carry
 * (sequence << 8) | ASCII tag, low 32 bits the value. The per-entry sequence
 * lets a raw dump order wrapped slots and detect torn reads; count locates
 * the newest entry at slot (count-1) & (NLR_TRACE_SLOTS-1). Runtime base for
 * a dump comes from the firmware registry scan; the ring starts at
 * offsetof(struct nlr_runtime, load) + offsetof(struct nlr_load, trace). */
#define NLR_TRACE_SLOTS 16

union nlr_trace_entry {
    struct {
        uint32_t seq_tag;
        int32_t value;
    };
    uint64_t packed;
};

struct nlr_trace {
    uint64_t count;
    union nlr_trace_entry entries[NLR_TRACE_SLOTS];
};

/* Tags: A attach, N create, W worker init, Q enqueue, E attempt done,
 * O open, S seek, H header read, V validate/publish, D data read, K crc,
 * C close, R short or failed read, M SAFE_MODE found (value: the handle the
 * open returned, so a dump tells a real flag file from a file service that
 * answered without a card). Directory reader: F file read, P parse,
 * G gate, I entries MANIFEST hides. Page: L program check requested (entry index),
 * B rows drawn (value: rows written << 16 | rows whose widget was found and
 * bound, one record per drawing). Probe: p sequence, x phase, r and s low
 * and high response words. api.log: T length, t text chunks (four message
 * bytes per entry). Generic program: g phase, h return value or exit code,
 * Z exit ignored (a resource extension used the foreground exit interface),
 * Y extension registered resident; b temporary file-read allocation bytes
 * (or negative failure, -1 for unconfirmed release). Value: result code,
 * fd, id, index or count. */

struct nlr_load {
    /* Must be first: the firmware hands the worker pointer to our callback. */
    struct nlr_worker worker;
    struct nlr_task_config task;
    const struct nlr_services *svc;
    /* Program file of the next attempt, a full card path the caller keeps
     * alive. The page selects it per check from the directory. */
    const char *path;
    uint8_t *arena;   /* owned RAM supplied by the creator; capacity below */
    uint32_t capacity;
    uint32_t state; /* atomic: 0 idle, 1 queued, 2 loading, 3 stopped cleanup,
                    * 4 uncertain stop (retained until reboot) */
    uint32_t ready;
    int32_t last_result;
    uint32_t image_bytes;
    uint32_t entry_offset;
    uint32_t bss_bytes;
    uint32_t abi_version;
    uint32_t stage; /* ASCII phase kept after a failure for diagnosis */
    struct nlr_trace trace;
    /* The loader's readable log (nlr/journal.h), or null: lines from the
     * load path, the runtime and the API go to the same ring. */
    struct nlr_journal *journal;
    /* The full header of the last attempt: 48 bytes for the probe, 64 for a
     * generic v2 program. */
    uint8_t header[NLR_GENERIC_HEADER_SIZE];
    uint32_t header_bytes;
    uint32_t manifest_kind;
    uint32_t probe_mode; /* 0 check, 1 prepare, 2 run; consumed by the worker */
    uint32_t probe_attempted;
    uint64_t probe_sequence;
    struct nlr_probe_state probe;

    /* Generic v2 program (PLAN 6.3 M2-T4), all zero unless the last attempt
     * loaded one: data_size is derived from the file length, and the arena
     * holds [reloc][image][data] for the executor. */
    uint32_t data_bytes;
    uint32_t reloc_bytes;
    uint32_t program_kind; /* 1 or 2 as declared by the file */
    uint32_t program_mode; /* 0 none, 1 prepare, 2 run; consumed by the worker */
    uint32_t program_attempted;
    struct nlr_program_state program;
    /* A bounded temporary file-read buffer, distinct from execution blocks.
     * Keep the original arena and the actual allocation owner separately;
     * uncertain release/cleanup stays recorded and forbids later loading. */
    uint8_t *home_arena;
    uint32_t home_capacity;
    void *spill_request;
    uint32_t spill_bytes;
    uint32_t spill_uncertain;
    /* Set by the loader's owner when this object really is the first
     * member of a runtime (core/runtime.c). The worker's completion then
     * carries an autoload pass on; a loader exercised on its own, as the
     * host ladders do, owns no pass and is never cast to one. */
    uint32_t in_runtime;
    /* The worker task's stack, from its first event down, 4 KiB short of
     * the bottom (as a service task's, api.c): which calls are the worker's
     * (nlr_runtime_on_loader_task). hi is 0 until the worker has run. */
    uint64_t worker_stack_lo;
    uint64_t worker_stack_hi;
    /* Called on the loading task after each chunk a load reads from the
     * card, or null; set and read atomically. The boot checkpoint sets it
     * while a boot program is started (runtime.c boot_program_start). */
    void (*chunk_read)(struct nlr_load *l);
    /* The memory the last loaded program declared in its metadata (v3
     * header, `memory=`), 0 for none; mem_reserved takes it for the
     * program (ABI 7). */
    uint32_t meta_memory;
    /* Set while a program is read from the release bundle instead of the
     * card (a path under NLR_BUNDLE_DIR): the file's bytes in memory and
     * the read position. Null for every card read. */
    const uint8_t *mem;
    uint32_t mem_bytes;
    uint32_t mem_pos;
};

/* The release bundle's programs appear under this directory of the card
 * root: a path there is read from the bundle, never
 * from the card. */
#define NLR_BUNDLE_DIR "BUNDLE\\"

#define NLR_LOAD_RELOC_MAX 0x100000u
#define NLR_LOAD_SPILL_MAX (2ull * NLR_EXEC_BLOCK_SIZE + NLR_LOAD_RELOC_MAX)

/* Ring writer shared by the loader and the directory reader: both record
 * into the same ring so one dump shows the whole attempt in order. */
static inline void nlr_trace_put(struct nlr_trace *t, char tag, int32_t value)
{
    if (!t)
        return;
    uint64_t n = __atomic_add_fetch(&t->count, 1, __ATOMIC_RELAXED);
    union nlr_trace_entry entry = {
        .seq_tag = (uint32_t)((n & 0xFFFFFFu) << 8) | (uint8_t)tag,
        .value = value,
    };
    /* Single 64-bit publish; a racing writer can only lose the slot, and the
     * embedded sequence exposes that to the reader. */
    __atomic_store_n(&t->entries[(n - 1) & (NLR_TRACE_SLOTS - 1)].packed,
                     entry.packed, __ATOMIC_RELAXED);
}

static inline void nlr_trace_record(struct nlr_load *l, char tag, int32_t value)
{
    nlr_trace_put(l ? &l->trace : 0, tag, value);
}

/* Construct the worker and its event flag, then start the task. Returns
 * NLR_PARTIAL when firmware objects may already reference our memory; that
 * state must be kept, never unwound. A PARTIAL result also means the caller
 * must not re-init the same struct: ready stays unset but kernel objects may
 * exist, and another worker_init could duplicate them. */
int nlr_load_init(struct nlr_load *l, const struct nlr_services *svc,
                  uint8_t *arena, uint32_t capacity,
                  const struct nlr_task_config *task);
/* IEEE CRC32, as the program header's checksums use it. */
uint32_t nlr_crc32(const uint8_t *p, uint32_t n);
/* Signal the worker exactly once while idle; NLR_BUSY otherwise. */
int nlr_load_enqueue_once(struct nlr_load *l);
/* Run one attempt in the caller's task. It takes the same idle-to-loading
 * transition as the worker, so the two can never read into the arena at
 * the same time; NLR_BUSY when an attempt is queued or running. */
int nlr_load_now(struct nlr_load *l);
/* SAFE_MODE first, then open, validate, read and CRC-check .path. No
 * execution here. */
int nlr_load_file(struct nlr_load *l);
/* Worker callback: the firmware passes the worker pointer it was given. */
void nlr_load_event(void *self, uint32_t events);

#endif
