#ifndef NLR_NATIVE_CARD_INTERNAL_H
#define NLR_NATIVE_CARD_INTERNAL_H

#include "nlr/native_card.h"
#include "nlr/runtime.h"

/* A caller's request to the card task (native_card.c, "The card task"): what
 * to do, and the answer the card task writes back before it gives the
 * card's one request to the next ticket. A caller holds its own ticket from
 * FILLING until it has read DONE; the card task holds the request only
 * while it serves one, QUEUED to DONE. Pointers name the caller's own
 * buffers, which stay valid because the caller waits for DONE: a program
 * reaches the card only through an API call, and MENU+DELETE never
 * terminates a program inside one (runtime.c exit_foreground resumes it
 * while api_active), so its frame outlives its ticket. */
#define NLR_NATIVE_CARD_TICKETS 12u /* the worker, the eight service tasks, the menu, two more */
enum {
    NLR_NATIVE_CARD_TICKET_FREE = 0,
    NLR_NATIVE_CARD_TICKET_FILLING,
    NLR_NATIVE_CARD_TICKET_QUEUED,
    NLR_NATIVE_CARD_TICKET_RUNNING,
    NLR_NATIVE_CARD_TICKET_DONE,
};
struct nlr_native_card_ticket {
    uint32_t state; /* atomic */
    uint32_t operation;
    uint64_t sequence; /* the order the card task takes them in */
    uint32_t purpose;
    uint32_t open_flags;
    int32_t fd;
    int32_t whence;
    int32_t offset;
    uint32_t count;
    const void *source;                   /* WRITE: the caller's bytes */
    void *sink;                           /* READ: where they go */
    const struct nlr_card_state *desired; /* COMMIT */
    int32_t result;
    uint32_t transferred;
    uint32_t at_end;                      /* READ: the file ended */
    uint32_t present;
    uint32_t queued_ms;
    char path[NLR_NATIVE_CARD_PATH_BYTES];
};

/* Internal ownership never outlives the runtime/boot. The allocation pointer
 * owns the padded object; all alignas(64) members are reached only through
 * the separately aligned pointer, not an assumed allocator guarantee. */
struct nlr_native_card_runtime {
    void *allocation;
    const struct nlr_native_card_services *services;
    uint64_t epoch;
    uint64_t sequence;
    uint32_t transitions; /* paired original lifecycle operations in flight */
    uint32_t busy;
    uint32_t claimed;
    uint32_t bound;
    uint32_t changed;
    uint32_t uncertain;
    uint32_t state_valid;
    uint32_t active_slot;
    uint32_t journal_present;
    int32_t attach_result;
    struct nlr_native_card_owner owner;
    struct nlr_card_state current;
    struct nlr_card_state proposal; /* caller-owned across request reset */
    /* The boot record's proposal: its own, because its writers (the task
     * carrying the pass, then the worker the boot program ran on) are not
     * the page's, and the runtime lets one of them write at a time. */
    struct nlr_card_state boot_proposal;
    /* The card task: the only task that takes the request below. */
    struct nlr_worker card_worker;
    struct nlr_task_config card_task;
    uint32_t card_task_started;
    uint32_t served;          /* observation only: tickets served */
    uint32_t longest_wait_ms; /* observation only: queued to started */
    uint32_t longest_run_ms;  /* observation only: started to answered */
    uint64_t tickets_issued;
    struct nlr_native_card_ticket tickets[NLR_NATIVE_CARD_TICKETS];
    struct nlr_native_card_request request;
};

int nlr_native_card_ram_span(const struct nlr_native_card_services *services,
                              uintptr_t address, uint32_t bytes);
void nlr_native_card_copy(void *out, const void *in, uint32_t bytes);
void nlr_native_card_zero(void *out, uint32_t bytes);
uint64_t nlr_native_card_u64(const uint8_t *in);
void nlr_native_card_reason(struct nlr_native_card_request *request, uint64_t reason);
int nlr_native_card_owner_read(struct nlr_native_card_runtime *context,
                               struct nlr_native_card_owner *owner);
int nlr_native_card_owner_check(struct nlr_native_card_runtime *context,
                                struct nlr_native_card_request *request);
int nlr_native_card_state_execute(struct nlr_runtime *runtime,
                                   struct nlr_native_card_runtime *context,
                                   struct nlr_native_card_request *request);
int nlr_native_card_acquire(struct nlr_runtime *runtime, uint32_t operation);
int nlr_native_card_submit(struct nlr_runtime *runtime);
void nlr_native_card_release(struct nlr_runtime *runtime);

#endif
