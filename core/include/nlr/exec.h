#ifndef NLR_EXEC_H
#define NLR_EXEC_H

#include "nlr/services.h"

#include <stdint.h>

#define NLR_PROBE_HEADER_SIZE 48u
#define NLR_PROBE_IMAGE_SIZE 16u
#define NLR_PROBE_FILE_SIZE 64u
#define NLR_EXEC_PAGE_SIZE 4096u
#define NLR_EXEC_BLOCK_SIZE 2097152u

enum {
    NLR_EXEC_RESPONSE = -10,
    NLR_EXEC_RESTORE = -11,
    /* A generic program finished with a nonzero status (PLAN 5.1); the
     * value itself is in the program state's exit_code. */
    NLR_EXEC_APP = -12,
    /* The coexistence budget (M2-T2) refused the start: the blocks already
     * held by resident extensions and running programs, plus the blocks
     * this run would need, exceed the injected budget. Nothing ran. */
    NLR_EXEC_BUDGET = -13,
    NLR_EXEC_TIMEOUT = -14,
    NLR_AUTOLOAD_PAUSED = -15,
    NLR_AUTOLOAD_INTERRUPTED = -16,
};

/* Relocation table entry (PLAN 6.3 M2-T4): 12 bytes { u32 offset, u32
 * target, u32 kind }. kind 0 patches an ADRP page difference, kind 1 writes
 * an absolute 64-bit pointer into the data block. */
#define NLR_RELOC_ENTRY_SIZE 12u
#define NLR_RELOC_ADRP 0u
#define NLR_RELOC_ABS64 1u
/* A data-block word that points at another data-block address
 * (initialized data or BSS): data base + target. */
#define NLR_RELOC_ABS64_DATA 2u

/* How many words the worker-frame context needs (program_context.S). The
 * type is opaque here; the layout is an internal detail of the two assembly
 * helpers. */
#define NLR_CONTEXT_SLOTS 24u

/* Foreground API resources use fixed runtime slots: no bookkeeping heap and
 * no eviction of a resource that could still be referenced. */
#define NLR_APP_ALLOC_MAX 16u
#define NLR_APP_FILE_MAX 16u

/* How many blocks one region acquisition may take from the model's
 * allocator before giving up. A block the allocator granted short is held
 * rather than released, so each try moves the allocator's search on by one
 * of its own nodes; the held ones go back when the acquisition ends. */
#define NLR_EXEC_GRANT_TRIES 6u

/* Adapters must reject unsupported page tables, cache regions and CPU
 * context. The worker is pinned to one verified core; a before/after CPU
 * comparison alone is not a substitute for that scheduling guarantee. */
struct nlr_exec_services {
    /* Permission granule; must be one supported complete page or block.
     * Core over-allocates so this aligned region never shares storage with
     * another allocation or with the allocator's surrounding metadata. */
    uint32_t region_bytes;
    /* Encodings the model's permission service accepts for one writable and
     * one executable permission, injected from the validated profile. The
     * core only distinguishes the two semantics; what an encoding means in
     * page tables is adapter knowledge of the declared mapping family. */
    uint32_t flag_writable;
    uint32_t flag_executable;
    /* Coexistence budget (M2-T2), injected from the validated profile.
     * program_budget_blocks caps the whole execution blocks held at once by
     * resident extensions and running programs: a start is refused before
     * any allocation when the blocks already held plus the 1 or 2 blocks it
     * needs would exceed it. program_max_resident caps the resource
     * extensions kept resident. Both must be at least 1; validation and the
     * generated bindings refuse a profile without them. */
    uint32_t program_budget_blocks;
    uint32_t program_max_resident;
    int32_t (*allocate)(uint32_t bytes, void **out);
    int32_t (*release)(void *allocation);
    /* How much of a `bytes` request the model's allocator would really
     * grant if it were asked right now, or 0 when its own records cannot
     * say. Asking for more than that is not just answered short: this
     * allocator applies its default mapping to the whole span it was asked
     * for, so a request larger than the free memory it is about to hand
     * over re-maps whatever lives past it — on the Z 6III that took the
     * execute permission off a resident extension's code while it was
     * still hooked into the firmware. So a region is only ever requested in
     * a size the allocator can satisfy; a smaller answer means something
     * small is in the way, and the caller takes exactly that out of the way
     * first. */
    uint32_t (*grant_probe)(uint32_t bytes);
    /* The end of the memory the model's allocator really granted for
     * `allocation`, or 0 when its own records do not say. It exists because
     * an allocator may answer a request with less than it was asked for:
     * the Z 6III heap is a stack manager that hands over the first node of
     * its free list even when that node is smaller, and reports the granted
     * size through an argument its public entry discards. Without this
     * service nothing can be checked and the allocator is taken at its
     * word, which is what every model did before it existed; with it, no
     * byte is written and no permission changed until the region is known
     * to be inside the grant. */
    uint64_t (*grant_end)(void *allocation);
    /* Where the model's allocator would place its next grant -- the
     * pointer it would return -- with the bytes it keeps in front of every
     * grant in *guard; 0 when its books cannot say. With it a program's
     * blocks are placed on a boundary instead of being found inside slack
     * that stays allocated for the whole run. Optional. */
    uint64_t (*grant_next)(uint64_t *guard);
    int32_t (*audit)(void *page, uint32_t bytes, uint32_t expected_flags);
    int32_t (*protect)(void *page, uint64_t bytes, uint32_t flags);
    int32_t (*clean)(void *page, uint32_t bytes);
    int32_t (*invalidate_code)(void *page, uint64_t bytes);
    uint64_t (*call)(void *entry, uint64_t challenge);
    /* Optional synchronous worker-side init invocation; allocation, validation
     * and entry all stay on the pinned worker. It MUST NOT dispatch into the
     * menu task or modify firmware menu structures: the program's registration
     * API only prepares runtime RAM, consumed at a later menu checkpoint.
     * Success means *started == 1 and *exit_code is the completed init result.
     * Failure with started == 0 guarantees entry did not run/cannot run later;
     * started == 1 is uncertain and retains blocks, blocking later execution.
     * Output pointers are written synchronously and never retained. Missing
     * binding refuses before entry. The model adapter reuses its audited
     * worker entry-call mechanism; no menu-task dispatcher is required. */
    int32_t (*extension_call)(void *entry, uint64_t api, int32_t *exit_code,
                              uint32_t *started);
    /* Optional: `bytes` from the same heap `allocate` draws on, starting on
     * an `alignment` boundary, through the heap's own aligned entry -- which
     * gives the bytes in front of the boundary and past the end back to the
     * heap at once, where the slack method keeps up to a region of them for
     * as long as the block lives. 0 with *out set, or -1 with *out null; the
     * block goes back through `release`. A model whose heap may answer
     * short or re-map past a grant (the grant books above) leaves it null. */
    int32_t (*allocate_aligned)(uint32_t alignment, uint32_t bytes, void **out);
};

/* Implemented by the loader (core/runtime.c): look over the blocks resident
 * extensions still hold and put back any permission they have lost. It is
 * called when the model's allocator has just been caught granting less than
 * it was asked for, which is the one way those permissions can change
 * behind the loader's back: the grant probe keeps a request inside what the
 * allocator can give, but nothing locks the heap between the question and
 * the answer, so another task can still make a request short after the fact
 * — and this allocator maps the whole span it was asked for, over whatever
 * lies past the memory it really had. The window is small and the repair is
 * cheap, so it is simply made whenever the short grant shows up. */
void nlr_exec_resident_recheck(const struct nlr_exec_services *services);

/* One block outside a program's regions (API mem_alloc, the loader's
 * spill), taken with the caller's own allocate/release under the regions'
 * grant discipline, read from `books` (core/exec.c). 0 when the block
 * cannot be had whole. */
void *nlr_exec_grant_alloc(const struct nlr_exec_services *books,
                           int32_t (*allocate)(uint32_t bytes, void **out),
                           int32_t (*release)(void *allocation),
                           uint32_t bytes);

/* Zero-initialize once and retain across attempts. A non-null allocation
 * after an attempt must not be freed or reused by the caller: cleanup did
 * not establish safe ownership/permissions. Such a state rejects retries. */
struct nlr_probe_state {
    void *allocation;
    uint8_t *page;
    uint64_t challenge;
    uint64_t expected;
    uint64_t response;
    uint32_t phase; /* M manifest recheck, L file load (set by the
                    * attempt), V validate, A allocate, U audit, W RW,
                    * D copy, C clean, X RX, I I-cache, E entry, R response */
    uint32_t permissions_touched;
    uint32_t prepared;
    uint32_t entry_started;
    uint32_t returned;
    uint32_t region_bytes;
};

int nlr_probe_validate(const uint8_t *file, uint32_t bytes,
                       uint32_t manifest_kind);
uint64_t nlr_probe_response(uint64_t challenge);

/* prepare_only does the same region and cache preparation but never calls the
 * entry. Both paths restore RW and release only after successful auditing.
 * The complete freshly loaded file and its current manifest kind are needed. */
int nlr_probe_run(struct nlr_probe_state *state,
                  const struct nlr_exec_services *services,
                  const uint8_t *file, uint32_t bytes, uint32_t manifest_kind,
                  uint64_t challenge, uint32_t prepare_only);

/* ---- generic v2 programs (PLAN 6.3 M2-T4) -------------------------------- */

/* The program as loaded into the loader arena, laid out [reloc][image][data]
 * in file order; BSS exists only as a size (zeroed into the data block at
 * run time). Pointers may be null when their size is 0. kind is the file's
 * declared type (1 resource_extension, 2 foreground). */
struct nlr_program_segments {
    const uint8_t *reloc;
    const uint8_t *image;
    const uint8_t *data;
    uint32_t image_size;
    uint32_t data_size;
    uint32_t bss_size;
    uint32_t entry_offset;
    uint32_t reloc_size;
    uint32_t kind;
    uint32_t abi_version;
    /* Called once the segments are in the program's blocks and before the
     * entry runs: the bytes above may go back then. Optional. */
    void (*consumed)(void *context);
    void *consumed_context;
    /* A resident extension whose data is read-only once relocated (dev
     * firmware's core, nlr/stage0.h): one region holds the image and then
     * the data from the next page boundary, every relocation is applied
     * while it is writable, and the whole region is executable and
     * read-only afterwards. No BSS. Zero for every other program. */
    uint32_t flat;
};

/* One generic program run. A restore/release failure keeps both blocks and
 * the caller must refuse further runs; a successfully initialized resource
 * extension instead keeps its blocks resident and the loader moves their
 * ownership into the runtime record, so this state is cleared afterwards
 * and remains reusable. jump_armed is set only around the foreground entry
 * call: api.c's exit wrapper longjmps through the context below. */
struct nlr_program_state {
    /* One original allocation owns both complete execution regions. When
     * data exists, data_allocation aliases code_allocation; it is never
     * released separately. The aligned regions still have independent
     * permissions and audits. allocation_bytes includes alignment slack. */
    void *code_allocation;
    void *data_allocation;
    uint32_t allocation_bytes;
    uint8_t *code_page;
    uint8_t *data_page;
    uint32_t region_bytes;
    uint32_t phase; /* M manifest recheck, L file load, A allocate, U audit,
                     * W RW, D copy/relocate, C clean, X RX, I I-cache,
                     * B data block audit, E entry, R return */
    uint32_t permissions_touched;
    uint32_t prepared;
    uint32_t entry_started;
    uint32_t returned;
    uint32_t kept;           /* resident extension, blocks owned elsewhere */
    uint32_t exit_requested; /* the program used api->exit */
    int32_t exit_code;
    uint32_t jump_armed;
    uint64_t context[NLR_CONTEXT_SLOTS];
    void *api_allocation[NLR_APP_ALLOC_MAX];
    int32_t api_file[NLR_APP_FILE_MAX];
    uint32_t api_file_used;
    uint32_t api_active; /* atomic: SDK service calls not yet quiescent */
    uint32_t stop_requested; /* atomic: loader-owned ordinary exit request */
};

struct nlr_api;

/* Run a generic v2 program: prepare the code block (and the data block when
 * the program has one), apply the relocations, then call the entry with the
 * API table in x0. prepare_only does everything but the call. Returns
 * NLR_OK, NLR_EXEC_APP (nonzero program status, value in exit_code) or the
 * preparation/relocation failure that stopped the run. */
int nlr_program_run(struct nlr_program_state *state,
                    const struct nlr_exec_services *services,
                    const struct nlr_program_segments *segments,
                    const struct nlr_api *api, uint32_t prepare_only);

/* Worker-side completion after the caller has confirmed task termination.
 * Never resumes the abandoned program context; uses normal API/RW cleanup. */
int nlr_program_finish_stopped(struct nlr_program_state *state,
                               const struct nlr_exec_services *services);

/* Worker-frame context for api->exit. The freestanding aarch64-none-elf
 * build has no <setjmp.h> and clang rejects __builtin_setjmp on this
 * target, so the context is saved by program_context.S; the attribute is
 * what keeps the compiler from assuming the call returns only once. */
int nlr_program_setjmp(uint64_t *context) __attribute__((returns_twice));
void nlr_program_longjmp(const uint64_t *context, int value);

/* Called only after the foreground entry has stopped and SDK calls have
 * quiesced. A failed close/free keeps its ownership slot and execution
 * blocks; no later attempt may reuse them. */
int nlr_api_program_cleanup(struct nlr_program_state *state);

/* ADRP relocation (kind 0), applied to the code block while it is writable.
 * Also usable directly by the host tests: target only takes part in the
 * page arithmetic, so a fabricated data base tests the 21-bit range without
 * touching memory. Returns NLR_OK, NLR_BOUNDS (page difference does not fit
 * an ADRP immediate) or NLR_FORMAT (the patched instruction is not a legal
 * ADRP encoding). */
int nlr_program_patch_adrp(uint8_t *code_base, uint32_t offset,
                           const uint8_t *data_base, uint32_t target);

#endif
