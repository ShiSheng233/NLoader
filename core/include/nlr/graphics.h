#ifndef NLR_GRAPHICS_H
#define NLR_GRAPHICS_H

#include <stdint.h>

#define NLR_GRAPHICS_WIDTH 320u
#define NLR_GRAPHICS_HEIGHT 200u
#define NLR_GRAPHICS_STRIDE (NLR_GRAPHICS_WIDTH * 4u)
#define NLR_GRAPHICS_BYTES (NLR_GRAPHICS_STRIDE * NLR_GRAPHICS_HEIGHT)
#define NLR_GRAPHICS_CACHE_LINE 64u
#define NLR_GRAPHICS_RGBA8 1u

enum nlr_graphics_result {
    NLR_GRAPHICS_OK = 0,
    NLR_GRAPHICS_NOT_READY = -1,
    NLR_GRAPHICS_ARGUMENT = -2,
    NLR_GRAPHICS_BUSY = -3,
    NLR_GRAPHICS_OWNER = -4,
    NLR_GRAPHICS_CANCELLED = -5,
    NLR_GRAPHICS_IO = -6,
    NLR_GRAPHICS_UNCERTAIN = -7
};

enum nlr_graphics_phase {
    NLR_GRAPHICS_EMPTY = 0,
    NLR_GRAPHICS_IDLE = 1,
    NLR_GRAPHICS_WRITING = 2,
    NLR_GRAPHICS_QUEUED = 3,
    NLR_GRAPHICS_DRAWING = 4,
    NLR_GRAPHICS_COMPLETE = 5,
    NLR_GRAPHICS_CANCELLED_FRAME = 6,
    NLR_GRAPHICS_UNCERTAIN_FRAME = 7
};

struct nlr_graphics_frame {
    void *pixels;
    uint32_t width;
    uint32_t height;
    uint32_t stride_bytes;
    uint32_t format;
    uint64_t sequence;
};

/* Normalized, profile-backed services. No address, native descriptor or GUI
 * object layout belongs in this module. All callbacks return 0 on success.
 * The service object and context remain alive until cleanup succeeds. */
struct nlr_graphics_services {
    void *context;
    int32_t (*worker_owner)(void *context, uint64_t owner);
    int32_t (*gui_owner)(void *context);
    /* Called only by the verified GUI owner. CANCELLED means this run is
     * no longer the current self-owned page, before any drawing starts. */
    int32_t (*current_window)(void *context, uint64_t owner);
    int32_t (*allocate)(void *context, uint32_t bytes, void **out);
    int32_t (*release)(void *context, void *allocation);
    int32_t (*clean_source)(void *context, void *pixels, uint32_t bytes);
    int32_t (*wake_gui)(void *context);
    int32_t (*clock_ms)(void *context, uint64_t *out);
    int32_t (*sleep_ms)(void *context, uint32_t milliseconds);
    /* This is a synchronous GUI operation through the original self-canvas
     * callback and native display submit. Set started before the first
     * operation that can retain/use the source. Return 0 ONLY when the real
     * callback ran and native source use completed. 0 with started == 0 is
     * refused; any started failure is uncertain. Do not manufacture input,
     * draw completion or pixels. GUI never waits for the worker here. */
    int32_t (*render)(void *context, uint64_t owner,
                      const struct nlr_graphics_frame *frame, uint32_t *started);
    uint32_t timeout_ms; /* Finite worker-side bound; zero is unsupported. */
};

/* One loader-owned object per runtime, initially all zero. One verified
 * worker produces; one verified GUI owner consumes. Every transition uses
 * a short nonwaiting lock. No GUI call waits for that lock. Source storage
 * is never application-owned and is never freed on uncertain completion.
 * Read these fields only through snapshot or after execution is stopped. */
struct nlr_graphics {
    uint32_t lock;
    uint32_t uncertain; /* sticky atomic flag, also works if a lock is stuck */
    uint32_t phase;
    uint32_t waiter_active;
    uint32_t gui_active;
    int32_t result;
    int32_t backend_result;
    uint32_t render_started;
    uint64_t owner;
    uint64_t sequence;
    uint64_t completed_sequence;
    void *allocation;
    uint32_t allocation_bytes;
    struct nlr_graphics_frame frame;
    const struct nlr_graphics_services *services;
};

struct nlr_graphics_snapshot {
    uint32_t phase;
    uint32_t waiter_active;
    uint32_t gui_active;
    uint32_t render_started;
    int32_t result;
    int32_t backend_result;
    uint64_t owner;
    uint64_t sequence;
    uint64_t completed_sequence;
    void *allocation;
    uint32_t allocation_bytes;
    struct nlr_graphics_frame frame;
};

/* owner is a nonzero identity for this foreground run, not just its task ID.
 * begin grants a writable frame until end publishes it. An outstanding begin
 * cannot be repeated; queued/drawing storage is not granted to any caller.
 * An application must not retain write permission after publication: this
 * cooperative SDK does not isolate malicious writes to a remembered pointer. */
int nlr_graphics_begin(struct nlr_graphics *state,
                        const struct nlr_graphics_services *services,
                        uint64_t owner, struct nlr_graphics_frame *out);
/* The caller holds its SDK api_active count throughout this blocking call.
 * The raw sleep callback must return here before stop handling may unwind
 * the worker. Success means source use completed, not that LCD pixels have
 * independently passed image verification. A later begin starts the next
 * frame; end itself never grants another writable lease. */
int nlr_graphics_end(struct nlr_graphics *state, uint64_t owner);
/* Called at the natural GUI checkpoint, before the loader's worker-active
 * early return. Consumes at most one frame and never waits for the worker. */
int nlr_graphics_gui_consume(struct nlr_graphics *state);
/* GUI page-leave hook: only a not-yet-consumed frame can be cancelled. */
int nlr_graphics_gui_cancel(struct nlr_graphics *state);
/* After the program has stopped, before normal program-memory release.
 * Wrong owners, active users and uncertain completion retain all storage.
 * Map UNCERTAIN/failed release to the loader's NLR_EXEC_RESTORE, not success. */
int nlr_graphics_cleanup(struct nlr_graphics *state, uint64_t owner);
int nlr_graphics_snapshot(struct nlr_graphics *state,
                           struct nlr_graphics_snapshot *out);

#endif
