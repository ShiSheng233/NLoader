#include "nlr/runtime.h"
#include "nlr/time.h"
#if defined(NLR_DEV_CORE)
#include "nlr/stage0.h"
#endif
#if NLR_HAS_NATIVE_CARD
#include "nlr/native_card_internal.h"
#endif

_Static_assert(offsetof(struct nlr_runtime, load) == 0, "worker callback ABI");

/* The generated bindings carry the task configuration from the profile; the
 * same name is used at construction and at registry discovery, so there is
 * exactly one truth for the task parameters (AUDIT C4). */
extern const struct nlr_task_config nlr_task_config;
/* Camera identity from the profile; the directory gate compares a program's
 * declaration against it. A build without it leaves the members null and the
 * gate reports "cannot confirm" instead of assuming a match. */
extern const struct nlr_identity nlr_identity;
extern const struct nlr_services nlr_services;


static void autoload_phase(struct nlr_runtime *r, uint32_t phase)
{
    __atomic_store_n(&r->autoload.phase, phase, __ATOMIC_RELEASE);
}
static int autoload_active(const struct nlr_runtime *r)
{
    return r->autoload.phase == NLR_AUTOLOAD_READY ||
           r->autoload.phase == NLR_AUTOLOAD_WAITING ||
           r->autoload.phase == NLR_AUTOLOAD_CLEAR;
}

/* Worker idle is the acquire boundary for resident/registration ownership. */
static int runtime_uncertain(const struct nlr_runtime *r)
{
    if (__atomic_load_n(&r->load.spill_uncertain, __ATOMIC_ACQUIRE)) return 1;
#if NLR_HAS_NATIVE_CARD
    if (nlr_native_card_uncertain(r))
        return 1;
#endif
    if (__atomic_load_n(&r->exit_uncertain, __ATOMIC_ACQUIRE) &&
        !(__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0 &&
          r->load.program.returned &&
          !__atomic_load_n(&r->load.program.api_active, __ATOMIC_ACQUIRE)))
        return 1;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++)
        if (r->menu_registration[i].state == NLR_MENU_REG_UNCERTAIN)
            return 1;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++)
        if (r->resident[i].used && r->resident[i].uncertain)
            return 1;
    return 0;
}

static int uncertain_result(const struct nlr_runtime *r)
{
    if (__atomic_load_n(&r->load.spill_uncertain, __ATOMIC_ACQUIRE)) return NLR_EXEC_RESTORE;
#if NLR_HAS_NATIVE_CARD
    if (nlr_native_card_uncertain(r))
        return nlr_native_card_status(r);
#else
    (void)r;
#endif
    return NLR_EXEC_TIMEOUT;
}

static int runtime_menu_pending(const struct nlr_runtime *r)
{
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++)
        if (r->menu_registration[i].state == NLR_MENU_REG_PENDING)
            return 1;
    return 0;
}

static int same_id(const char *a, const char *b)
{
    for (uint32_t n = 0; n <= NLR_MANIFEST_ID_MAX; n++) {
        if (a[n] != b[n])
            return 0;
        if (!a[n])
            return 1;
    }
    return 0;
}

int nlr_runtime_menu_register(struct nlr_runtime *r,
                              const struct nlr_menu_test_item *item)
{
    if (!r || !r->load.svc || !r->load.svc->resources ||
        !r->load.svc->resources->publish)
        return NLR_NOT_READY;
    if (!item || item->label_id >= 0xffffu || item->item_id >= 0xffffu)
        return NLR_BOUNDS;
    /* Only the worker's synchronous extension-init window owns this writer.
     * The menu task never reads the payload until state returns to idle. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 2 ||
        r->load.program_kind != NLR_KIND_RESOURCE_EXTENSION ||
        !r->load.program.entry_started || r->load.program.returned ||
        !r->program_id[0])
        return NLR_REFUSED;
    struct nlr_menu_registration *free_slot = 0;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++) {
        struct nlr_menu_registration *slot = &r->menu_registration[i];
        if (slot->state == NLR_MENU_REG_EMPTY) {
            if (!free_slot)
                free_slot = slot;
        } else if (slot->item.item_id == item->item_id ||
                   same_id(slot->owner, r->program_id)) {
            return NLR_BUSY;
        }
    }
    if (!free_slot)
        return NLR_BUSY;
    free_slot->item = *item;
    for (uint32_t n = 0; n < sizeof free_slot->owner; n++)
        free_slot->owner[n] = r->program_id[n];
    free_slot->result = NLR_NOT_READY;
    free_slot->state = NLR_MENU_REG_PENDING;
    return NLR_OK;
}

int nlr_runtime_menu_publish(struct nlr_runtime *r)
{
    if (!r || !r->load.svc)
        return NLR_NOT_READY;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return NLR_BUSY;
    if (runtime_uncertain(r))
        return uncertain_result(r);
    const struct nlr_resource_services *ready = r->load.svc->resources;
    if (ready && ready->can_publish) {
        int result = ready->can_publish(ready->context);
        if (result != NLR_OK)
            return result;
    }
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++) {
        struct nlr_menu_registration *slot = &r->menu_registration[i];
        if (slot->state != NLR_MENU_REG_PENDING)
            continue;
        struct nlr_program_record *owner = 0;
        for (uint32_t j = 0; j < NLR_RESIDENT_MAX; j++)
            if (r->resident[j].used &&
                r->resident[j].kind == NLR_KIND_RESOURCE_EXTENSION &&
                same_id(r->resident[j].id, slot->owner)) {
                owner = &r->resident[j];
                break;
            }
        const struct nlr_resource_services *resources = r->load.svc->resources;
        int result = owner && resources && resources->publish
            ? resources->publish(resources->context, &slot->item)
            : NLR_NOT_READY;
        slot->result = result;
        if (result != NLR_OK) {
            /* A failing adapter may already have published some references.
             * Never retry/free/advance, even for a claimed pre-write error. */
            slot->state = NLR_MENU_REG_UNCERTAIN;
            if (owner)
                owner->failed = owner->uncertain = 1;
            r->load.last_result = NLR_EXEC_TIMEOUT;
            nlr_runtime_autoload_interrupt(r, NLR_EXEC_TIMEOUT);
            nlr_trace_record(&r->load, 'J', result);
            return NLR_EXEC_TIMEOUT;
        }
        slot->state = NLR_MENU_REG_PUBLISHED;
        nlr_trace_record(&r->load, 'J', NLR_OK);
    }
    return NLR_OK;
}

static int card_probe(const struct nlr_card_store *store, const char *path,
                       uint32_t *present)
{
    if (!store || !store->probe)
        return NLR_NOT_READY;
    *present = UINT32_MAX;
    int result = store->probe(path, present);
    if (result != NLR_OK)
        return result;
    return *present <= 1u ? NLR_OK : NLR_IO;
}

static int autoload_guard(const struct nlr_card_store *store,
                           uint32_t expect_pending)
{
    uint32_t present = 0;
    int result = card_probe(store, NLR_SAFE_MODE_PATH, &present);
    if (result != NLR_OK || present)
        return result != NLR_OK ? result : NLR_DISABLED;
    result = card_probe(store, NLR_AUTOLOAD_PENDING_PATH, &present);
    if (result != NLR_OK)
        return result;
    if (present != expect_pending)
        return expect_pending ? NLR_IO : NLR_AUTOLOAD_PAUSED;
    return NLR_OK;
}

static int runtime_autoload_guard(struct nlr_runtime *r, uint32_t pending)
{
    /* The button escape answers like SAFE_MODE, and before it: a card whose
     * extension stops the camera can be recovered without a computer. It
     * is the escape held now, or held at power-on (latched within
     * NLR_BOOT_ESCAPE_MS of the boot checkpoint's first look), the same
     * rule on every body. */
    if (__atomic_load_n(&r->autoload.boot_escape, __ATOMIC_ACQUIRE) ||
        (nlr_program_keys_now() & NLR_AUTOLOAD_ESCAPE_KEYS))
        return NLR_DISABLED;
#if NLR_HAS_NATIVE_CARD
    if (r->load.svc->native_card)
        return nlr_native_card_guard(r, pending);
#endif
    return autoload_guard(r->autoload.store, pending);
}
/* A card buffer of `bytes` on whole cache lines: the pre-read invalidation
 * covers whole lines, and the allocator only promises 8-byte alignment, so
 * the buffer starts on the first line inside an allocation padded by one
 * line. Returns the buffer and the allocation to release, or null with
 * nothing held. */
static uint8_t *alloc_lines(const struct nlr_services *svc, uint32_t bytes,
                            void **allocation)
{
    *allocation = 0;
    if (bytes > UINT32_MAX - 2u * NLR_CACHE_LINE)
        return 0;
    uint32_t size = nlr_cache_lines(bytes) + NLR_CACHE_LINE;
    *allocation = nlr_alloc_whole(svc, size);
    if (!*allocation)
        return 0;
    uintptr_t base = (uintptr_t)*allocation;
    return (uint8_t *)((base + NLR_CACHE_LINE - 1u) &
                       ~(uintptr_t)(NLR_CACHE_LINE - 1u));
}

struct nlr_runtime *nlr_runtime_find(const struct nlr_services *svc,
                                     uint32_t *named)
{
    struct nlr_runtime *found = 0;
    if (named)
        *named = 0;
    if (!svc || !svc->registry_lookup)
        return 0;
    /* Only task objects are requested. The event flag registers itself as a
     * different type at worker+0x38, so a flag route would reach the same
     * worker through arithmetic and could accept a half-built runtime. */
    for (uint32_t id = 1; id <= NLR_REGISTRY_IDS; id++) {
        void *object = 0;
        svc->registry_lookup(NLR_REGISTRY_TYPE_TASK, id, &object);
        uintptr_t address = (uintptr_t)object;
        if (!address || (address & 7))
            continue;
        const volatile uint8_t *w = (const volatile uint8_t *)address;
        /* Field order matters: registry objects are not all this family's
         * 0x58-byte workers, and short ones end before +0x28. The id and the
         * name are checked first; only a name match reads further words. */
        if (*(const volatile uint32_t *)(w + NLR_WORKER_ID_OFFSET) != id)
            continue;
        unsigned n = 0;
        while (n < NLR_TASK_NAME_SIZE &&
               w[NLR_WORKER_NAME_OFFSET + n] == (uint8_t)nlr_task_config.name[n])
            n++;
        if (n != NLR_TASK_NAME_SIZE)
            continue;
        /* Named: a construction of ours reached task creation. Counted even
         * when the rest of the filter rejects the object. */
        if (named)
            (*named)++;
        if (*(const volatile uint64_t *)(w + NLR_WORKER_SELF_OFFSET) !=
            (uint64_t)address)
            continue;
        if (*(const volatile uint64_t *)(w + NLR_WORKER_CALLBACK_OFFSET) !=
            (uint64_t)(uintptr_t)nlr_load_event)
            continue;
        struct nlr_runtime *r = (struct nlr_runtime *)address;
        /* Our shape and our service table: this makes it our struct. */
        if (r->load.svc != svc)
            continue;
        if (found && found != r)
            return 0; /* ambiguous: never choose one */
        found = r;
    }
    return found;
}

static int exit_services_ready(const struct nlr_exit_services *exit)
{
    return exit && exit->input_callback && exit->mask && exit->suspend &&
           exit->resume && exit->terminate && exit->restart;
}

static void exit_install(struct nlr_runtime *r)
{
    const struct nlr_exit_services *exit = r->load.svc->exit;
    if (!exit_services_ready(exit))
        return;
    void (*original)(void *) =
        __atomic_load_n(exit->input_callback, __ATOMIC_ACQUIRE);
    if (!original || original == nlr_runtime_exit_input)
        return;
    r->exit_original_input = original;
    __atomic_store_n(exit->input_callback, nlr_runtime_exit_input,
                     __ATOMIC_RELEASE);
}

static void exit_uncertain(struct nlr_runtime *r, int result)
{
    __atomic_store_n(&r->exit_uncertain, 1u, __ATOMIC_RELEASE);
    r->load.last_result = NLR_EXEC_TIMEOUT;
    nlr_trace_record(&r->load, 'q', result);
}

/* Input-task control only. All close/free/permission changes remain on the
 * pinned worker, including after terminating a non-cooperative entry. */
static void exit_foreground(struct nlr_runtime *r)
{
    struct nlr_load *l = &r->load;
    const struct nlr_exit_services *exit = l->svc->exit;
    int result = exit->suspend(&l->worker);
    if (result != NLR_OK) {
        /* No freeze was proved: do not mutate worker-owned execution state
         * or release anything. A later natural return can prove quiescence. */
        exit_uncertain(r, result);
        return;
    }
    if (__atomic_load_n(&l->state, __ATOMIC_ACQUIRE) != 2 ||
        l->program_kind != NLR_KIND_FOREGROUND || !l->program.jump_armed) {
        result = exit->resume(&l->worker);
        if (result != NLR_OK)
            exit_uncertain(r, result);
        return;
    }
    r->detail_view = r->recovery_view = r->show_check = 0;
    /* the same line the program input hook writes for its stop; a line
     * into the RAM ring, safe while the worker is suspended */
    if (!__atomic_exchange_n(&l->program.stop_requested, 1u, __ATOMIC_ACQ_REL))
        nlr_journal(l->journal, "MENU+DELETE: the program is asked to stop");
    if (__atomic_load_n(&l->program.api_active, __ATOMIC_ACQUIRE)) {
        /* A firmware service may own locks/resources. It must finish on its
         * original frames; service_end leaves through the armed context. */
        result = exit->resume(&l->worker);
        if (result != NLR_OK)
            exit_uncertain(r, result);
        return;
    }
    result = exit->terminate(&l->worker);
    if (result != NLR_OK) {
        /* The native result did not prove termination. Keep the allocation
         * and suspension; there is no pure-compute cooperative fallback. */
        exit_uncertain(r, result);
        return;
    }
    /* The old context is dead. The wrapper starts fresh on this same task,
     * receives the stop event, and uses normal program_finish cleanup. */
    __atomic_store_n(&l->state, 3u, __ATOMIC_RELEASE);
    result = exit->restart(&l->worker);
    if (result == NLR_OK)
        result = l->svc->flag_set(l->worker.opaque + NLR_WORKER_FLAG_OFFSET,
                                  NLR_LOAD_STOP_EVENT);
    if (result != NLR_OK) {
        __atomic_store_n(&l->state, 4u, __ATOMIC_RELEASE);
        exit_uncertain(r, result);
    }
}

static int exit_menu_available(const struct nlr_runtime *r)
{
#if NLR_HAS_NATIVE_CARD
    const struct nlr_native_card_services *card = r->load.svc->native_card;
    return card && card->menu.dispatch && card->menu.current_window &&
        card->menu.loader_window && card->menu.gui_state &&
        card->menu.menu_press_code && card->menu.callee &&
        card->menu.wake_mask && r->load.svc->flag_set;
#else
    (void)r;
    return 0;
#endif
}

static void exit_menu_queue(struct nlr_runtime *r, uint32_t event)
{
#if NLR_HAS_NATIVE_CARD
    uint32_t empty = 0;
    if (!event || !__atomic_compare_exchange_n(&r->exit_menu_pending, &empty,
                                               event, 0, __ATOMIC_RELEASE,
                                               __ATOMIC_RELAXED)) {
        r->exit_menu_result = NLR_BUSY;
        return;
    }
    const struct nlr_native_card_menu *menu = &r->load.svc->native_card->menu;
    const struct nlr_native_card_services *card = r->load.svc->native_card;
    /* The original getter returns a pointer slot; the original setter first
     * dereferences it. Passing the slot itself would use an address as an ID. */
    void *reference = menu->callee();
    uintptr_t flag = 0;
    if (nlr_native_card_ram_span(card, (uintptr_t)reference, sizeof(uint64_t)))
        flag = (uintptr_t)nlr_native_card_u64(reference);
    r->exit_menu_result = nlr_native_card_ram_span(card, flag, sizeof(uint32_t)) ?
        r->load.svc->flag_set((void *)flag, menu->wake_mask) : NLR_NOT_READY;
#else
    (void)r; (void)event;
#endif
}

static int exit_menu_on_loader(const struct nlr_runtime *r)
{
#if NLR_HAS_NATIVE_CARD
    const struct nlr_native_card_menu *menu = &r->load.svc->native_card->menu;
    return *menu->gui_state == 1u && menu->current_window() == menu->loader_window;
#else
    (void)r;
    return 0;
#endif
}

static int input_worker(const struct nlr_runtime *r)
{
    const struct nlr_input_services *s = r->load.svc->input;
    uint32_t task = 0;
    return s && s->current_task && s->current_task(&task) == 0 &&
        task == nlr_le32(r->load.worker.opaque + NLR_WORKER_ID_OFFSET);
}

int nlr_runtime_input_begin(struct nlr_load *load)
{
    if (!load || load->abi_version < 4u || !load->svc || !load->svc->input)
        return NLR_OK;
    struct nlr_runtime *r = nlr_runtime_find(load->svc, 0);
    uint32_t masks[3], owner;
    if (!r || &r->load != load || !input_worker(r) ||
        !r->exit_original_input || !exit_menu_available(r) ||
        nlr_input_suppression_masks(load->svc->input, masks))
        return NLR_NOT_READY;
    int result = nlr_input_begin(&r->input,
        __atomic_load_n(&r->input_physical, __ATOMIC_ACQUIRE), &owner);
    if (result)
        return NLR_REFUSED;
    __atomic_store_n(&r->input_owner, owner, __ATOMIC_RELEASE);
    return NLR_OK;
}

void nlr_runtime_input_end(struct nlr_load *load)
{
    if (!load || !load->svc || !load->svc->input)
        return;
    struct nlr_runtime *r = nlr_runtime_find(load->svc, 0);
    if (!r || &r->load != load || !input_worker(r))
        return;
    uint32_t owner = __atomic_exchange_n(&r->input_owner, 0u, __ATOMIC_ACQ_REL);
    nlr_input_end(&r->input, owner);
}

static int input_access(struct nlr_runtime *r)
{
    if (!r || !r->load.svc || !r->load.svc->input)
        return -NLR_API_ENOSYS;
    if (!input_worker(r) ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 2 ||
        r->load.program_kind != NLR_KIND_FOREGROUND ||
        !__atomic_load_n(&r->load.program.jump_armed, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&r->load.program.stop_requested, __ATOMIC_ACQUIRE))
        return -NLR_API_EBUSY;
    if (!exit_menu_available(r) || !exit_menu_on_loader(r) ||
        __atomic_load_n(&r->io.list_active, __ATOMIC_ACQUIRE)) {
        nlr_input_focus_lost(&r->input,
            __atomic_load_n(&r->input_owner, __ATOMIC_ACQUIRE));
        return -NLR_API_EBUSY;
    }
    return 0;
}

int nlr_runtime_input_poll(struct nlr_runtime *r, struct nlr_key_event *event)
{
    int result = input_access(r);
    if (result)
        return result;
    if (!event)
        return -NLR_API_EINVAL;
    struct nlr_input_event next;
    result = nlr_input_poll(&r->input,
        __atomic_load_n(&r->input_owner, __ATOMIC_ACQUIRE), &next);
    if (result == 1 && (next.key & (NLR_INPUT_KEY_FN1 | NLR_INPUT_KEY_FN2)))
        return 0;
    if (result == 1) {
        event->key = next.key & 0x1fu;
        if (next.key & NLR_INPUT_KEY_PLAYBACK) event->key |= NLR_KEY_PLAY;
        if (next.key & NLR_INPUT_KEY_AF_ON) event->key |= NLR_KEY_AF_ON;
        if (next.key & NLR_INPUT_KEY_DISP) event->key |= NLR_KEY_DISP;
        if (next.key & NLR_INPUT_KEY_ZOOM_IN) event->key |= NLR_KEY_ZOOM_IN;
        if (next.key & NLR_INPUT_KEY_ZOOM_OUT) event->key |= NLR_KEY_ZOOM_OUT;
        event->down = next.pressed;
    }
    return result;
}

uint32_t nlr_runtime_input_raw(struct nlr_runtime *r)
{
    if (input_access(r)) return 0;
    uint32_t held = nlr_input_raw(&r->input,
        __atomic_load_n(&r->input_owner, __ATOMIC_ACQUIRE));
    uint32_t keys = held & 0x1fu;
    if (held & NLR_INPUT_KEY_PLAYBACK) keys |= NLR_KEY_PLAY;
    if (held & NLR_INPUT_KEY_AF_ON) keys |= NLR_KEY_AF_ON;
    if (held & NLR_INPUT_KEY_DISP) keys |= NLR_KEY_DISP;
    if (held & NLR_INPUT_KEY_ZOOM_IN) keys |= NLR_KEY_ZOOM_IN;
    if (held & NLR_INPUT_KEY_ZOOM_OUT) keys |= NLR_KEY_ZOOM_OUT;
    return keys;
}

/* Sole input producer. Observe physical state before either suppression
 * path changes it; owner-tagged publication rejects a late old callback. */
static void input_observe(struct nlr_runtime *r, uint32_t banks[3][5],
                           const uint32_t saved[3][5], uint32_t active,
                           uint64_t captured_request)
{
    const struct nlr_input_services *s = r->load.svc->input;
    uint32_t physical[3] = {saved[0][0], saved[1][0], saved[2][0]};
    uint32_t held, masks[3];
    if (nlr_input_map(s, physical, &held) || nlr_input_suppression_masks(s, masks))
        return;
    __atomic_store_n(&r->input_physical, held, __ATOMIC_RELEASE);
    uint32_t owner = __atomic_load_n(&r->input_owner, __ATOMIC_ACQUIRE);
    if (!owner)
        return;
    int focused = active && exit_menu_available(r) && exit_menu_on_loader(r) &&
        !__atomic_load_n(&r->io.list_active, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&r->load.program.stop_requested, __ATOMIC_ACQUIRE);
    int result = nlr_input_publish(&r->input, owner, focused ? held : 0);
    if (result != 0 && result != -NLR_API_EOVERFLOW)
        return;
    if (!focused) {
        if (r->input_focus_owner == owner) {
            /* Focus loss makes queued history incomplete; the consumer
             * receives an explicit resync error instead of stale presses. */
            __atomic_store_n(&r->input.overflow_owner, owner, __ATOMIC_RELEASE);
            r->input_focus_owner = 0;
        }
        return;
    }
    r->input_focus_owner = owner;
    nlr_input_focus_observed(&r->input, owner, captured_request);
    /* Where the body declares its own platform scan, the platform pass owns
     * the hides and does them per control route. The legacy binding masks
     * would otherwise take back a control the program routed to the
     * camera. */
    const struct nlr_platform_services *pl = r->load.svc->platform;
    if (pl && pl->scan)
        return;
    for (uint32_t bank = 0; bank < 3; bank++)
        for (uint32_t field = 0; field < 5; field++)
            banks[bank][field] &= ~masks[bank];
}

void nlr_runtime_exit_menu_checkpoint(struct nlr_runtime *r)
{
#if NLR_HAS_NATIVE_CARD
    if (!r || !exit_menu_available(r))
        return;
    uint32_t event = __atomic_load_n(&r->exit_menu_pending, __ATOMIC_ACQUIRE);
    if (!event)
        return;
    const struct nlr_native_card_menu *menu = &r->load.svc->native_card->menu;
    /* A previous physical edge is never delivered to another page. Discard
     * this queue entry with an explicit refusal; it must not fire later when
     * the user happens to return to NLoader. The retained fields stay audit data. */
    if (*menu->gui_state != 1u || menu->current_window() != menu->loader_window) {
        __atomic_compare_exchange_n(&r->exit_menu_pending, &event, 0u, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        r->exit_menu_result = NLR_REFUSED;
        nlr_trace_record(&r->load, '!', NLR_REFUSED);
        return;
    }
    if (!__atomic_compare_exchange_n(&r->exit_menu_pending, &event, 0u, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    uint8_t flags[8] = {0};
    menu->dispatch(event, flags);
    /* This only records dispatch. Screenshots and native window observations
     * must prove navigation; the original void function has no success code. */
    r->exit_menu_result = NLR_OK;
#else
    (void)r;
#endif
}

void nlr_runtime_exit_input(void *combined)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || !exit_services_ready(r->load.svc->exit))
        return;
    const struct nlr_exit_services *exit = r->load.svc->exit;
    void (*original)(void *) = r->exit_original_input;
    if (!combined) {
        if (original)
            original(combined);
        return;
    }
    uint64_t captured_request =
        __atomic_load_n(&r->input.resync_request, __ATOMIC_ACQUIRE);
    uint32_t (*banks)[5] = (uint32_t (*)[5])((uint8_t *)combined + 8u);
    uint32_t physical[3][5];
    for (uint32_t b = 0; b < 3; b++)
        for (uint32_t i = 0; i < 5; i++)
            physical[b][i] = banks[b][i];
    uint32_t *bank = banks[exit->bank];
    const uint32_t *saved = physical[exit->bank];
    uint32_t active = __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 2 &&
        __atomic_load_n(&r->load.program.jump_armed, __ATOMIC_ACQUIRE) &&
        r->load.program_kind == NLR_KIND_FOREGROUND;
    /* The platform pass for a body whose carrier is this callback: the same
     * controls, dials, hides and activity signal the program input hook
     * produces, from the same profile fields, so a program cannot tell
     * which task its events came from. It reads the physical object and
     * runs before the ABI 4 observation, which keeps its own snapshot. */
    struct nlr_scan_view view;
    uint8_t saved_dial[32];
    uint32_t dial_bytes = 0;
    int platform = 0;
    if (!__atomic_load_n(&r->io.hooked, __ATOMIC_ACQUIRE) &&
        nlr_platform_scan_view(r->load.svc, &view) &&
        view.dial_bytes <= sizeof saved_dial) {
        platform = 1;
        dial_bytes = view.dial_bytes;
        for (uint32_t n = 0; n < dial_bytes; n++)
            saved_dial[n] = ((const uint8_t *)combined)[view.dial_offset + n];
    }
    if (platform) {
        /* A native list owns the direction keys and OK while it runs; the
         * pass then reports and hides nothing, exactly as the program input
         * hook has it. The scan itself still runs: the held set and the
         * dials are the program's state, whoever is reading the buttons. */
        int capture = active &&
            !__atomic_load_n(&r->io.list_active, __ATOMIC_ACQUIRE);
        nlr_program_journal_scan(r, &view, combined, capture);
        (void)nlr_platform_input_pass(&r->plat, r->load.svc->platform, &view,
                                      combined, capture, nlr_clock_ms());
    }
    input_observe(r, banks, physical, active, captured_request);
    int defer = exit_menu_available(r) && exit->release_mask;
    if (!r->exit_swallow && (saved[0] & exit->mask) == exit->mask && active) {
        r->exit_swallow = 1;
        r->exit_menu_held = 0;
        __atomic_store_n(&r->exit_release_seen, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&r->exit_notify, 1u, __ATOMIC_RELEASE);
        if (!__atomic_load_n(&r->exit_uncertain, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&r->load.program.stop_requested, __ATOMIC_ACQUIRE))
            exit_foreground(r);
    }
    if (defer && !r->exit_swallow) {
        if (!r->exit_menu_held && active &&
            (saved[0] & saved[3] & exit->release_mask) &&
            !(saved[0] & (exit->mask & ~exit->release_mask)) &&
            exit_menu_on_loader(r)) {
            r->exit_menu_held = 1;
            for (uint32_t i = 0; i < 5; i++)
                r->exit_menu_fields[i] = saved[i] & exit->release_mask;
        }
        if (r->exit_menu_held) {
            for (uint32_t i = 0; i < 5; i++)
                bank[i] &= ~exit->release_mask;
            if (saved[4] & exit->release_mask) {
                r->exit_menu_held = 0;
#if NLR_HAS_NATIVE_CARD
                exit_menu_queue(r, r->load.svc->native_card->menu.menu_press_code);
#endif
            }
        }
    }
    if (r->exit_swallow) {
        for (uint32_t i = 0; i < 5; i++)
            bank[i] &= ~exit->mask;
        /* Permit only the real MENU release as a guarded loader GUI wake.
         * Press/held/DELETE edges remain swallowed; SDK draining need not
         * have finished, so the GUI must keep the actual loading state. */
        if (__atomic_load_n(&r->exit_notify, __ATOMIC_ACQUIRE))
            if (saved[4] & exit->release_mask & exit->mask) {
                __atomic_store_n(&r->exit_release_seen, 1u, __ATOMIC_RELEASE);
                if (defer)
                    exit_menu_queue(r, exit->menu_release_code);
                else
                    bank[4] |= saved[4] & exit->release_mask & exit->mask;
            }
        if (!(saved[0] & exit->mask))
            r->exit_swallow = 0;
    }
    if (original)
        original(combined);
    /* The native input owner still needs the physical state to compute its
     * next diff. Suppression is scoped to dispatch, never persisted: the
     * banks and the dial words the pass hid are put back. */
    for (uint32_t b = 0; b < 3; b++)
        for (uint32_t i = 0; i < 5; i++)
            banks[b][i] = physical[b][i];
    if (platform)
        for (uint32_t n = 0; n < dial_bytes; n++)
            ((uint8_t *)combined)[view.dial_offset + n] = saved_dial[n];
}

static void *boot_veil_alloc(const struct nlr_services *svc, uint32_t bytes);

/* A line in the loader's own log (nlr/journal.h). */
#define JLOG(r, ...) nlr_journal((r)->load.journal, __VA_ARGS__)

int nlr_runtime_create(struct nlr_runtime **out, const struct nlr_services *svc,
                       uint32_t arena_bytes)
{
    if (!out || *out)
        return NLR_BUSY;
    if (!svc || !svc->release || !svc->worker_init ||
        !svc->worker_start || !svc->registry_lookup || !svc->flag_set)
        return NLR_NOT_READY;
    void *memory = nlr_alloc_whole(svc, (uint32_t)sizeof(struct nlr_runtime));
    if (!memory)
        return NLR_NOT_READY;
    uint8_t *raw = memory;
    for (size_t n = 0; n < sizeof(struct nlr_runtime); n++)
        raw[n] = 0;
    *out = memory;
    void *arena_request = 0;
    uint8_t *arena = ((uintptr_t)memory & 7)
                         ? 0
                         : alloc_lines(svc, arena_bytes, &arena_request);
    if (!arena) {
        svc->release(memory);
        *out = 0;
        return NLR_NOT_READY;
    }
    /* Directory buffer: separate from the program arena, which a check
     * overwrites while the page still shows names from the directory. */
    void *directory_request = 0;
    uint8_t *directory = alloc_lines(svc, NLR_MANIFEST_BYTES, &directory_request);
    if (!directory) {
        svc->release(arena_request);
        svc->release(memory);
        *out = 0;
        return NLR_NOT_READY;
    }
    (*out)->directory_buffer = directory;
    (*out)->directory_result = NLR_NOT_READY;
    (*out)->enabled_save_result = NLR_NOT_READY;
    (*out)->autoload.enabled_result = NLR_NOT_READY;
    (*out)->autoload.recovery_result = NLR_NOT_READY;
    (*out)->autoload.boot_index = -1;
    (*out)->autoload.boot_result = NLR_NOT_READY;
    (*out)->checked = NLR_NO_CHECK;
    (*out)->check_result = NLR_NOT_READY;
#if NLR_HAS_GRAPHICS
    nlr_graphics_runtime_init(*out);
#endif
#if NLR_HAS_PRIVATE_TEXT
    if (nlr_private_text_pool_prepare(*out, svc) != NLR_OK) {
        svc->release(directory_request);
        svc->release(arena_request);
        svc->release(memory);
        *out = 0;
        return NLR_NOT_READY;
    }
#endif
    struct nlr_task_config task = nlr_task_config;
    int status = nlr_load_init(&(*out)->load, svc, arena, arena_bytes, &task);
    /* This loader is a runtime's own: its completions may carry an
     * autoload pass forward (core/load.c). */
    (*out)->load.in_runtime = 1;
    if (status == NLR_OK || status == NLR_PARTIAL)
        nlr_trace_record(&(*out)->load, 'N', status);
#if NLR_HAS_PRIVATE_TEXT
    if (status == NLR_OK && nlr_runtime_find(svc, 0) == *out)
        nlr_private_text_pool_publish(*out);
#endif
    if (status == NLR_OK && exit_services_ready(svc->exit) &&
        nlr_runtime_find(svc, 0) == *out)
        exit_install(*out);
    if (status == NLR_OK && nlr_runtime_find(svc, 0) == *out)
        if (!svc->input)
            nlr_program_io_install(*out);
    if (status && status != NLR_PARTIAL) {
        /* worker_init was never reached, so nothing kernel-side can reference
         * this memory and the attempt is fully reversible. Unwinding keeps a
         * repeated failure from leaking a runtime and an arena per attempt.
         * NLR_PARTIAL is retained instead: kernel objects may reference the
         * struct or the arena, and only their owner can resolve that. */
#if NLR_HAS_PRIVATE_TEXT
        svc->release((*out)->private_text);
#endif
        svc->release(directory_request);
        svc->release(arena_request);
        svc->release(memory);
        *out = 0;
    }
    /* The log, for a model that names its file: granted whole, kept for
     * the boot like the runtime. */
    if (*out && svc->journal_path) {
        struct nlr_journal *j = boot_veil_alloc(svc, (uint32_t)sizeof *j);
        if (j) {
            for (size_t n = 0; n < sizeof *j; n++)
                ((volatile uint8_t *)j)[n] = 0;
            (*out)->load.journal = j;
            nlr_journal(j, "---- boot: NLoader ABI %u, %s %s", NLR_ABI_VERSION,
                        nlr_identity.model, nlr_identity.firmware);
        }
    }
    return status;
}

struct nlr_runtime *nlr_runtime_attach(const struct nlr_services *svc,
                                       uint32_t arena_bytes, uint32_t *named)
{
    uint32_t count = 0;
    struct nlr_runtime *r = nlr_runtime_find(svc, &count);
    if (named)
        *named = count;
    /* A nonzero count with no match means an earlier attempt registered a
     * worker and then failed; retrying would leak a runtime per activation. */
    if (!r && !count) {
        nlr_runtime_create(&r, svc, arena_bytes);
        if (r && nlr_runtime_find(svc, 0) != r)
            r = 0; /* the registry names it ambiguously; refuse to choose */
    }
    if (r)
        nlr_trace_record(&r->load, 'A', count ? 0 : 1);
    return r;
}

/* ---- programs that describe themselves ------------- */

/* ASCII case-insensitive compare of a NUL-terminated name with `n` bytes. */
static int name_eq(const char *a, const uint8_t *b, uint32_t n)
{
    uint32_t i = 0;
    for (; i < n && a[i]; i++) {
        char x = a[i], y = (char)b[i];
        if (x >= 'a' && x <= 'z') x = (char)(x - 32);
        if (y >= 'a' && y <= 'z') y = (char)(y - 32);
        if (x == '\\') x = '/';
        if (y == '\\') y = '/';
        if (x != y)
            return 0;
    }
    return i == n && !a[i];
}

static int name_before(const char *a, const char *b)
{
    for (;; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'a' && x <= 'z') x = (char)(x - 32);
        if (y >= 'a' && y <= 'z') y = (char)(y - 32);
        if (x != y || !x)
            return (uint8_t)x < (uint8_t)y;
    }
}

struct discover_scratch {
    uint8_t head[NLR_GENERIC_HEADER_SIZE + NLR_META_MAX];
    char names[NLR_MANIFEST_MAX_ENTRIES][NLR_DIRENT_NAME_MAX];
    char line[NLR_MANIFEST_ID_MAX + NLR_MANIFEST_NAME_MAX + NLR_MANIFEST_FILE_MAX +
              NLR_MANIFEST_SUPPORT_MAX + 64u];
    struct nlr_manifest one;
    struct nlr_dirent entry;
};

/* One program that describes itself, its header (and metadata) at `head`
 * (`bytes` of it), to be named by `file` (f bytes) in the directory: its
 * line is appended unless it is no program of that kind, its description
 * breaks the grammar, or its id or file is named already -- by MANIFEST
 * (`m`, when `known`) or by a line added before it. 1 when appended. */
static int discover_add(struct discover_scratch *x, const struct nlr_manifest *m,
                        int known, uint8_t *buffer, uint32_t base, uint32_t *used,
                        const uint8_t *head, uint32_t bytes, const char *file,
                        uint32_t f)
{
    if (bytes < NLR_GENERIC_HEADER_SIZE || head[0] != 'N' || head[1] != 'P' ||
        head[2] != 'L' || head[3] != 'D' ||
        nlr_le16(head + 4) != NLR_NPLD_META_VERSION)
        return -1; /* not a program, or one that MANIFEST must name */
    uint32_t meta = nlr_le32(head + 0x28);
    uint32_t line = 0;
    if (meta && meta <= NLR_META_MAX &&
        bytes >= NLR_GENERIC_HEADER_SIZE + meta &&
        nlr_crc32(head + NLR_GENERIC_HEADER_SIZE, meta) == nlr_le32(head + 0x2c))
        line = nlr_meta_line(head + NLR_GENERIC_HEADER_SIZE, meta, file,
                             x->line, sizeof x->line);
    /* the line on its own must be one the parser takes */
    if (!line || nlr_manifest_parse(&x->one, (const uint8_t *)x->line, line) != NLR_OK ||
        x->one.count != 1)
        return 0;
    const struct nlr_manifest_entry *e = &x->one.entries[0];
    const uint8_t *id = (const uint8_t *)x->line + e->id_off;
    int named = 0, file_named = 0;
    /* already in MANIFEST, or added from an earlier file */
    for (uint32_t k = 0; known && k < m->count && !file_named; k++) {
        const struct nlr_manifest_entry *o = &m->entries[k];
        char other[NLR_MANIFEST_FILE_MAX + 1];
        uint32_t n = 0;
        for (; n < o->id_len && n < NLR_MANIFEST_ID_MAX; n++)
            other[n] = (char)m->buffer[o->id_off + n];
        other[n] = 0;
        if (name_eq(other, id, e->id_len))
            named = 1;
        for (n = 0; n < o->file_len && n < NLR_MANIFEST_FILE_MAX; n++)
            other[n] = (char)m->buffer[o->file_off + n];
        other[n] = 0;
        if (name_eq(other, (const uint8_t *)file, f))
            file_named = 1;
    }
    for (uint32_t at = base; !named && at < *used;) {
        uint32_t end = at;
        while (end < *used && buffer[end] != '\n')
            end++;
        uint32_t k = 0;
        while (k < e->id_len && at + k < end && buffer[at + k] != ' ')
            k++;
        char other[NLR_MANIFEST_ID_MAX + 1];
        uint32_t n = 0;
        for (; n < k && n < NLR_MANIFEST_ID_MAX; n++)
            other[n] = (char)buffer[at + n];
        other[n] = 0;
        if (at + k < end && buffer[at + k] == ' ' && name_eq(other, id, e->id_len))
            named = 1;
        at = end + 1u;
    }
    /* The file MANIFEST names already is its line; an id listed before is a
     * duplicate: its line is kept, and the parse marks it never to load
     * (nlr_manifest_parse_listed), so the page shows it as such. */
    /* A bundle program a card program of the same id replaces is not shown
     * at all. */
    int bundled = f > 7u && file[0] == 'B' && file[6] == '/';
    if (file_named || (named && bundled) || *used + line > NLR_MANIFEST_BYTES)
        return 0;
    for (uint32_t k = 0; k < line; k++)
        buffer[*used + k] = (uint8_t)x->line[k];
    *used += line;
    return 1;
}

/* The directory as the loader sees it: MANIFEST, when there is one, then a
 * line for every program in APPS that carries its own description (NPLD v3)
 * and is not already named there -- by id or by file -- then, last, the
 * programs of the release bundle the firmware carries, named BUNDLE/<file>: a card program with the same id comes first and
 * so wins. Card files are taken in name order, so of two with one id the
 * first by name wins; the other is left out (and the trace counts it). A
 * description that does not make a valid line is left out the same way:
 * one bad program never hides the others. Nothing here runs unless the
 * reader got past SAFE_MODE: a card that asks for safe mode, or a card read
 * that failed for any reason but a missing MANIFEST (which is also how no
 * card at all answers), is answered exactly as before. */
static void *boot_veil_alloc(const struct nlr_services *svc, uint32_t bytes);

static int discover_listed(struct nlr_runtime *r, struct nlr_manifest *m,
                           uint8_t *buffer, int result);

/* The directory, whole, with MANIFEST's "#!hide" lines applied last:
 * they name ids, and the ids of described and
 * bundled programs are known only now. */
static int discover_programs(struct nlr_runtime *r, struct nlr_manifest *m,
                             uint8_t *buffer, int result)
{
    result = discover_listed(r, m, buffer, result);
    if (result == NLR_OK) {
        uint32_t hidden = nlr_manifest_hide(m);
        if (hidden)
            nlr_trace_record(&r->load, 'I', (int32_t)hidden);
    }
    return result;
}

static int discover_listed(struct nlr_runtime *r, struct nlr_manifest *m,
                           uint8_t *buffer, int result)
{
    const struct nlr_services *svc = r->load.svc;
    const struct nlr_platform_services *pl = svc ? svc->platform : 0;
    int card_dir = svc && svc->program && svc->program->fs_enum;
    int bundle = pl && pl->bundle && nlr_bundle_count(pl->bundle, pl->bundle_bytes);
    if ((result != NLR_OK && result != NLR_IO) || (!card_dir && !bundle))
        return result;
    /* The scratch is granted whole (the heap's short-grant defect), and
     * the directory is listed in one pass of the firmware's enumerator:
     * this runs in the boot pass, on the stock GUI's task. */
    void *request = boot_veil_alloc(svc, (uint32_t)sizeof(struct discover_scratch) +
                                             NLR_CACHE_LINE);
    struct discover_scratch *x = request
        ? (struct discover_scratch *)(((uintptr_t)request + NLR_CACHE_LINE - 1u) &
                                      ~(uintptr_t)(NLR_CACHE_LINE - 1u))
        : 0;
    if (!x)
        return result;
    static const char apps[] = NLR_PROGRAM_ROOT "APPS";
    uint32_t count = 0;
    int listed = card_dir ? nlr_program_dir_all(r, apps, &x->names[0][0],
                                                NLR_MANIFEST_MAX_ENTRIES)
                          : 0;
    for (int i = 0; i < listed; i++) {
        char name[NLR_DIRENT_NAME_MAX];
        for (uint32_t k = 0; k < NLR_DIRENT_NAME_MAX; k++)
            name[k] = x->names[i][k];
        uint32_t n = 0;
        while (n < NLR_DIRENT_NAME_MAX && name[n])
            n++;
        if (n < 5 || !name_eq(".NLB", (const uint8_t *)name + n - 4, 4))
            continue;
        /* "._NAME.NLB" is the AppleDouble companion a Mac writes beside
         * NAME.NLB (its resource fork and attributes), never a program.
         * Decided 2026-10-17: the loader's own listing leaves these out
         * instead of reading each one only to refuse its header; a
         * program's own directory calls still see the card as it is. */
        if (name[0] == '.' && name[1] == '_')
            continue;
        /* kept in name order, in place: names[0..count) are the programs */
        uint32_t at = count++;
        while (at && name_before(name, x->names[at - 1])) {
            for (uint32_t k = 0; k < NLR_DIRENT_NAME_MAX; k++)
                x->names[at][k] = x->names[at - 1][k];
            at--;
        }
        for (uint32_t k = 0; k < NLR_DIRENT_NAME_MAX; k++)
            x->names[at][k] = name[k];
    }
    uint32_t base = result == NLR_OK ? m->bytes : 0, used = base, added = 0, left_out = 0;
    if (used && buffer[used - 1] != '\n' && used < NLR_MANIFEST_BYTES)
        buffer[used++] = '\n';
    for (uint32_t i = 0; i < count; i++) {
        char path[NLR_PATH_BYTES];
        char file[NLR_MANIFEST_FILE_MAX + 1];
        uint32_t p = 0, f = 0;
        for (const char *c = NLR_PROGRAM_ROOT "APPS\\"; *c && p + 1 < sizeof path; c++)
            path[p++] = *c;
        for (const char *c = "APPS/"; *c; c++)
            file[f++] = *c;
        for (const char *c = x->names[i]; *c && p + 1 < sizeof path &&
             f < NLR_MANIFEST_FILE_MAX; c++) {
            path[p++] = *c;
            file[f++] = *c;
        }
        path[p] = 0;
        file[f] = 0;
        uint32_t whole = 0;
        while (x->names[i][whole])
            whole++;
        if (f != 5u + whole || p + 1 >= sizeof path) {
            left_out++; /* a name the MANIFEST file column cannot hold */
            continue;
        }
        uint32_t bytes = 0;
        if (nlr_card_read_prefix(svc, path, x->head, sizeof x->head, &bytes,
                                 &r->load.trace) != NLR_OK)
            continue;
        int took = discover_add(x, m, result == NLR_OK, buffer, base, &used, x->head,
                                bytes, file, f);
        if (took > 0)
            added++;
        else if (!took)
            left_out++;
    }
    /* The bundle's programs: their headers are in memory already. */
    uint32_t entries = bundle ? nlr_bundle_count(pl->bundle, pl->bundle_bytes) : 0;
    for (uint32_t i = 0; i < entries; i++) {
        char name[NLR_BUNDLE_NAME_MAX + 1];
        const uint8_t *data = 0;
        uint32_t bytes = 0;
        if (nlr_bundle_entry(pl->bundle, pl->bundle_bytes, i, name, &data, &bytes))
            continue;
        uint32_t n = 0;
        while (name[n])
            n++;
        if (n < 5 || !name_eq(".NLB", (const uint8_t *)name + n - 4, 4))
            continue; /* BOOT, ENABLED: defaults, not programs */
        char file[NLR_MANIFEST_FILE_MAX + 1];
        uint32_t f = 0;
        for (const char *c = "BUNDLE/"; *c; c++)
            file[f++] = *c;
        for (uint32_t k = 0; k < n; k++)
            file[f++] = name[k];
        file[f] = 0;
        int took = discover_add(x, m, result == NLR_OK, buffer, base, &used, data,
                                bytes < sizeof x->head ? bytes : (uint32_t)sizeof x->head,
                                file, f);
        if (took > 0)
            added++;
        else if (!took)
            left_out++;
    }
    svc->release(request);
    nlr_trace_record(&r->load, 'p', (int32_t)(added << 16 | left_out));
    if (!added)
        return result;
    if (nlr_manifest_parse_listed(m, buffer, used, base) == NLR_OK)
        return NLR_OK;
    /* never: each line was taken alone and no id repeats; keep what was */
    if (result == NLR_OK)
        (void)nlr_manifest_parse(m, buffer, base);
    return result;
}

/* A shell opened from a menu: called on the menu
 * task right after its start was queued. The menu closes to live view --
 * the stock exit every menu page maps its leave event to, named
 * "menu.leave" in the profile -- and the stock GUI is held at its
 * checkpoint as for the boot program, so the shell's screen_claim finds the
 * live-view layer and nothing of the camera's draws over it. The hold is
 * taken on the live-view side only (the boot checkpoint, or the profile's
 * GUI turns); the menu task is never held, so its exit runs as in stock.
 * When the profile declares the hold to settle (services.platform.hold
 * when = "settle"), no hold point holds until the switch to live view has
 * settled (plat.leaving, hold_settling); "immediate" holds at the next
 * hold point. A start that fails leaves nothing behind: the hold ends as
 * soon as no program is loaded, and the shell mark with it. */
int nlr_runtime_shell_open(struct nlr_runtime *r)
{
    const struct nlr_platform_services *pl = r && r->load.svc ? r->load.svc->platform : 0;
    int i = nlr_platform_find_function(pl, "menu.leave");
    if (i < 0) {
        if (r)
            JLOG(r, "shell: no menu.leave, opened as an app");
        return NLR_NOT_READY;
    }
    uint32_t settle = pl->hold_when == NLR_HOLD_SETTLE;
    __atomic_store_n(&r->plat.shell, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->plat.turned, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->plat.leaving, settle, __ATOMIC_RELEASE);
    __atomic_store_n(&r->autoload.boot_hold, 1u, __ATOMIC_RELEASE);
    JLOG(r, "shell: leaving the menu, GUI to be held %s",
         settle ? "once it settles" : "at once");
    ((void (*)(void))pl->functions[i].address)();
    return NLR_OK;
}

int nlr_runtime_read_directory(struct nlr_runtime *r)
{
    if (!r || !r->load.svc || !r->directory_buffer)
        return NLR_NOT_READY;
#if NLR_HAS_PRIVATE_TEXT
    if (!nlr_private_text_pool_ready(r))
        return NLR_NOT_READY;
#endif
    if (autoload_active(r))
        return NLR_BUSY;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return NLR_BUSY;
    if (runtime_uncertain(r))
        return uncertain_result(r);
    if (runtime_menu_pending(r))
        return NLR_BUSY;
    nlr_runtime_outcome_keep(r);
    r->probe_pending = 0;
    r->program_pending = 0;
    r->checked = NLR_NO_CHECK;
    r->check_result = NLR_NOT_READY;
    r->show_check = 0;
    /* The reader checks SAFE_MODE before anything else on the card. */
    int result = nlr_manifest_read(&r->directory, r->load.svc,
                                   r->directory_buffer, NLR_MANIFEST_BYTES,
                                   &r->load.trace);
    if (result == NLR_BUSY) {
        /* The card was busy, not read: what was listed before stays, as
         * every other busy answer above leaves it, instead of a page that
         * says the MANIFEST was not read (Z8 QEMU fix-misc qemu-doom-002:
         * the page entered as a program's last log write held the card). */
        JLOG(r, "directory: card busy, %d kept", r->directory_result);
        return NLR_BUSY;
    }
    result = discover_programs(r, &r->directory, r->directory_buffer, result);
    if (result == NLR_OK) {
        nlr_manifest_gate(&r->directory, nlr_identity.model,
                          nlr_identity.firmware);
        nlr_trace_record(&r->load, 'G', (int32_t)r->directory.usable);
    }
    r->directory_result = result;
    JLOG(r, "directory: %d, %u programs, %u usable", result,
         result == NLR_OK ? r->directory.count : 0u,
         result == NLR_OK ? r->directory.usable : 0u);
    nlr_pages_directory_read(r);
    (void)nlr_journal_flush(r->load.journal, r->load.svc, 0);
    return result;
}

/* Every "open this application" of the NLoader pages comes here. A shell
 * (its directory entry says so) runs over the live picture: once its
 * start is queued, the stock menu closes under it and the GUI is held as
 * at boot (nlr_runtime_shell_open), and NLR_SHELL_OPENED tells the page
 * not to wait for the program on its window. */
int nlr_runtime_open_app(struct nlr_runtime *r, uint32_t index)
{
    int result = nlr_runtime_start_program(r, index, 2);
    if (r)
        JLOG(r, "open from the menu: %d%s", result,
             index < r->directory.count && r->directory.entries[index].shell ? " (a shell)" : "");
    if (result == NLR_OK && r && index < r->directory.count &&
        r->directory.entries[index].shell && nlr_runtime_shell_open(r) == NLR_OK)
        return NLR_SHELL_OPENED;
    return result;
}

static int runtime_check(struct nlr_runtime *r, uint32_t index)
{
    if (!r)
        return NLR_NOT_READY;
#if NLR_HAS_PRIVATE_TEXT
    if (!nlr_private_text_pool_ready(r))
        return NLR_NOT_READY;
#endif
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return NLR_BUSY;
    if (runtime_uncertain(r))
        return uncertain_result(r);
    if (runtime_menu_pending(r))
        return NLR_BUSY;
    nlr_runtime_outcome_keep(r);
    r->probe_pending = 0;
    r->program_pending = 0;
    int result;
    if (r->directory_result != NLR_OK) {
        result = NLR_NOT_READY;
    } else if (index >= r->directory.count) {
        result = NLR_BOUNDS;
    } else if (r->directory.entries[index].gate != NLR_GATE_OK) {
        result = NLR_REFUSED;
    } else {
        /* The file column is confined to APPS by the parser and written on
         * a host, so either separator may appear; the card path uses the
         * firmware's. */
        const struct nlr_manifest_entry *e = &r->directory.entries[index];
        const uint8_t *file = r->directory.buffer + e->file_off;
        uint32_t length = 0;
        for (const char *p = NLR_PROGRAM_ROOT; *p; p++)
            r->path[length++] = *p;
        for (uint32_t n = 0; n < e->file_len; n++)
            r->path[length++] = file[n] == '/' ? '\\' : (char)file[n];
        r->path[length] = 0;
        r->load.path = r->path;
        r->load.manifest_kind = e->kind;
        nlr_trace_record(&r->load, 'L', (int32_t)index);
        result = nlr_load_now(&r->load);
    }
    r->checked = index;
    r->check_result = result;
    return result;
}

int nlr_runtime_check(struct nlr_runtime *r, uint32_t index)
{
    if (r && autoload_active(r))
        return NLR_BUSY;
    return runtime_check(r, index);
}

int nlr_runtime_start_probe(struct nlr_runtime *r, uint32_t index, uint32_t mode)
{
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    if (!r || (mode != 1 && mode != 2))
        return NLR_NOT_READY;
#ifdef NLR_STAGE_PREPARE_ONLY
    if (mode != 1)
        return NLR_REFUSED;
#endif
    /* A region kept after a failed cleanup refuses every later run until
     * the camera restarts. Nothing is checked or queued, so the record of
     * that failure stays as the worker left it and the page keeps showing
     * it. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0 &&
        r->load.probe.allocation) {
        r->probe_pending = 1;
        r->check_result = NLR_EXEC_RESTORE;
        return NLR_EXEC_RESTORE;
    }
    int result = nlr_runtime_check(r, index);
    if (result != NLR_OK)
        return result;
    if (r->load.header_bytes != NLR_PROBE_HEADER_SIZE ||
        r->directory.entries[index].kind != NLR_KIND_FOREGROUND) {
        r->check_result = NLR_FORMAT;
        return NLR_FORMAT;
    }
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    for (uint32_t n = 0; n < e->id_len; n++)
        r->probe_id[n] = (char)r->directory.buffer[e->id_off + n];
    r->probe_id[e->id_len] = 0;
    r->load.probe_mode = mode;
    r->load.probe_attempted = 0;
    result = nlr_load_enqueue_once(&r->load);
    if (result != NLR_OK)
        r->load.probe_mode = 0;
    else
        r->probe_pending = 1;
    r->check_result = result;
    return result;
#else
    (void)r; (void)index; (void)mode;
    return NLR_REFUSED;
#endif
}

/* The worker rereads the directory into separate storage: the visible list
 * remains a stable snapshot while the job is in flight. Both the identity
 * and the selected file must still match; a replacement card cannot silently
 * redirect this queued request to another program. */
/* Shared tail of both rechecks: the worker re-reads the directory into
 * separate storage and the named entry must still exist, still be allowed by
 * the gate and still name the same file; require_kind 0 accepts the entry's
 * own kind (generic programs declare either kind), otherwise the kind must
 * match. */
static int recheck_manifest(struct nlr_load *load, const char *id,
                            uint32_t require_kind)
{
    struct nlr_runtime *r = (struct nlr_runtime *)load;
    const struct nlr_services *svc = load->svc;
    void *allocation = 0;
    uint8_t *buffer = alloc_lines(svc, NLR_MANIFEST_BYTES, &allocation);
    if (!buffer)
        return NLR_NOT_READY;
    struct nlr_manifest m;
    int result = nlr_manifest_read(&m, svc, buffer, NLR_MANIFEST_BYTES, &load->trace);
    result = discover_programs(r, &m, buffer, result);
    if (result == NLR_OK) {
        nlr_manifest_gate(&m, nlr_identity.model, nlr_identity.firmware);
        result = NLR_REFUSED;
        for (uint32_t i = 0; i < m.count; i++) {
            const struct nlr_manifest_entry *e = &m.entries[i];
            uint32_t n = 0;
            while (n < e->id_len && id[n] &&
                   id[n] == (char)m.buffer[e->id_off + n])
                n++;
            if (n != e->id_len || id[n] ||
                e->gate != NLR_GATE_OK ||
                (require_kind && e->kind != require_kind))
                continue;
            const char *file = r->path + sizeof(NLR_PROGRAM_ROOT) - 1;
            n = 0;
            while (n < e->file_len && file[n]) {
                char value = (char)m.buffer[e->file_off + n];
                if ((value == '/' ? '\\' : value) != file[n])
                    break;
                n++;
            }
            if (n == e->file_len && !file[n]) {
                load->manifest_kind = e->kind;
                result = NLR_OK;
            }
            break;
        }
    }
    if (svc->release(allocation) != NLR_OK && result == NLR_OK)
        result = NLR_NOT_READY;
    return result;
}

int nlr_runtime_probe_recheck(struct nlr_load *load)
{
    struct nlr_runtime *r = (struct nlr_runtime *)load;
    return recheck_manifest(load, r->probe_id, NLR_KIND_FOREGROUND);
}

int nlr_runtime_program_recheck(struct nlr_load *load)
{
    struct nlr_runtime *r = (struct nlr_runtime *)load;
    uint32_t phase = __atomic_load_n(&r->autoload.phase, __ATOMIC_ACQUIRE);
    if (r->autoload.store && phase != NLR_AUTOLOAD_NEW &&
        r->autoload.next < r->autoload.enabled.count &&
        r->autoload.item[r->autoload.next] == NLR_EXTENSION_INITIALIZING) {
        if (phase != NLR_AUTOLOAD_WAITING)
            return NLR_AUTOLOAD_INTERRUPTED;
        int result = runtime_autoload_guard(r, 1);
        /* The native card serves one request at a time; a resident
         * program's own file calls or a log flush may hold it a moment.
         * Busy is waited out, a bounded while, on this worker. */
        for (uint32_t tries = 0; result == NLR_BUSY && tries < 100u &&
             load->svc && load->svc->sleep_ms; tries++) {
            load->svc->sleep_ms(10u);
            result = runtime_autoload_guard(r, 1);
        }
        if (result != NLR_OK)
            return result;
    }
    return recheck_manifest(load, r->program_id, 0);
}

/* Ownership hand-over from the load worker: a resource extension whose
 * entry has run keeps its two execution blocks resident (PLAN 5.1) whether
 * it initialized successfully or returned nonzero — a failed initialization
 * may already have published resources, which are kept and marked. So
 * instead of restoring and releasing them the worker records them here.
 * Residents are never dropped by the registry; only the camera restart
 * clears them. */
int nlr_runtime_register_resident(struct nlr_load *load)
{
    struct nlr_runtime *r = (struct nlr_runtime *)load;
    if (!r || !load->program.kept ||
        load->program_kind != NLR_KIND_RESOURCE_EXTENSION)
        return NLR_NOT_READY;
    struct nlr_program_record *slot = 0;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX && !slot; i++)
        if (!r->resident[i].used)
            slot = &r->resident[i];
    if (!slot)
        return NLR_BUSY;
    slot->used = 1;
    slot->failed = !load->program.returned || load->program.exit_code != 0;
    slot->uncertain = !load->program.returned;
    slot->kind = load->program_kind;
    slot->abi_version = load->abi_version;
    slot->allocation = load->program.code_allocation;
    slot->allocation_bytes = load->program.allocation_bytes;
    slot->code_block = load->program.code_page;
    slot->code_bytes = load->program.code_page ? load->program.region_bytes : 0;
    slot->data_block = load->program.data_page;
    slot->data_bytes = load->program.data_page ? load->program.region_bytes : 0;
    for (uint32_t n = 0; n < sizeof slot->id; n++)
        slot->id[n] = r->program_id[n];
    nlr_trace_record(load, 'Y', (int32_t)(slot - r->resident));
    return NLR_OK;
}

/* Whole execution blocks currently held through the registry: every kept
 * extension contributes its code block and, when the program has a data
 * segment, its data block. Foreground records in the table are reservations
 * of runs that are queued or executing and count the same way. Only the
 * exec stages weigh starts against the budget, so the counters live under
 * the same stage switch. */
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
static uint32_t registry_blocks(const struct nlr_runtime *r)
{
    uint32_t blocks = 0;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++) {
        const struct nlr_program_record *rec = &r->resident[i];
        if (!rec->used)
            continue;
        if (rec->code_block || rec->code_bytes)
            blocks++;
        if (rec->data_block || rec->data_bytes)
            blocks++;
    }
    return blocks;
}

static uint32_t registry_extensions(const struct nlr_runtime *r)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++)
        if (r->resident[i].used &&
            r->resident[i].kind == NLR_KIND_RESOURCE_EXTENSION)
            count++;
    return count;
}
#endif

void nlr_runtime_settle_records(struct nlr_runtime *r)
{
    if (!r)
        return;
    /* A run in flight still holds its blocks, and a kept cleanup-failed
     * region is still held; only a fully ended attempt frees its foreground
     * record. Extension records are never touched: residents stay. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return;
    if (r->load.program.code_allocation || r->load.spill_uncertain)
        return;
    __atomic_store_n(&r->exit_uncertain, 0u, __ATOMIC_RELEASE);
    /* Consume only this stopped attempt's pending page result. The stop
     * diagnostic remains intact; later checks own their new detail page. */
    if (r->program_pending &&
        __atomic_load_n(&r->load.program.stop_requested, __ATOMIC_ACQUIRE)) {
        r->detail_view = r->recovery_view = r->show_check = 0;
        nlr_runtime_outcome_keep(r);
        r->program_pending = 0;
    }
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++) {
        struct nlr_program_record *rec = &r->resident[i];
        if (rec->used && rec->kind == NLR_KIND_FOREGROUND) {
            rec->used = 0;
            rec->kind = 0;
            rec->abi_version = 0;
            rec->failed = 0;
            rec->allocation = 0;
            rec->allocation_bytes = 0;
            rec->code_block = 0;
            rec->code_bytes = 0;
            rec->data_block = 0;
            rec->data_bytes = 0;
        }
    }
}

void nlr_runtime_outcome_fill(const struct nlr_runtime *r, struct nlr_outcome *out)
{
    for (uint32_t n = 0; n < sizeof out->id; n++)
        out->id[n] = n < NLR_MANIFEST_ID_MAX ? r->program_id[n] : 0;
    out->result = r->load.last_result;
    out->exit_code = r->load.program.exit_code;
    out->exit_requested = r->load.program.exit_requested ? 1u : 0u;
    out->returned = r->load.program.returned ? 1u : 0u;
    out->phase = (uint8_t)r->load.program.phase;
    out->stage = (uint8_t)r->load.stage;
    out->memory_bytes = 0;
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    extern const struct nlr_exec_services nlr_exec_services;
    /* Stopped where the executor asks the heap for its blocks (phase A)
     * and the heap could not give them whole: the code block and, with
     * initialized data or BSS, a data block, each a whole region. */
    if (out->phase == 'A' &&
        (out->result == NLR_NOT_READY || out->result == NLR_BOUNDS))
        out->memory_bytes = ((r->load.data_bytes || r->load.bss_bytes) ? 2u : 1u) *
                            nlr_exec_services.region_bytes;
#endif
}

static int outcome_id_is(const char *kept, const uint8_t *id, uint32_t length)
{
    if (!length || length > NLR_MANIFEST_ID_MAX || kept[length])
        return 0;
    for (uint32_t n = 0; n < length; n++) {
        uint8_t a = (uint8_t)kept[n], b = id[n];
        if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + 32u);
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32u);
        if (!a || a != b)
            return 0;
    }
    return 1;
}

const struct nlr_outcome *nlr_runtime_outcome_find(const struct nlr_runtime *r,
                                                   const uint8_t *id, uint32_t length)
{
    if (!r || !id)
        return 0;
    for (uint32_t i = 0; i < NLR_OUTCOMES_MAX; i++)
        if (outcome_id_is(r->outcomes.slot[i].id, id, length))
            return &r->outcomes.slot[i];
    return 0;
}

void nlr_runtime_outcome_keep(struct nlr_runtime *r)
{
    if (!r || !r->program_pending || !r->program_id[0] ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0 ||
        r->load.program.code_allocation)
        return;
    uint32_t length = 0;
    while (length < NLR_MANIFEST_ID_MAX && r->program_id[length])
        length++;
    struct nlr_outcome *slot =
        (struct nlr_outcome *)nlr_runtime_outcome_find(r, (const uint8_t *)r->program_id, length);
    for (uint32_t i = 0; i < NLR_OUTCOMES_MAX && !slot; i++)
        if (!r->outcomes.slot[i].id[0])
            slot = &r->outcomes.slot[i];
    if (!slot) {
        /* every slot names another id: the oldest new id gives way */
        slot = &r->outcomes.slot[r->outcomes.next % NLR_OUTCOMES_MAX];
        r->outcomes.next = (r->outcomes.next + 1u) % NLR_OUTCOMES_MAX;
    }
    nlr_runtime_outcome_fill(r, slot);
}

const struct nlr_program_record *nlr_runtime_resident_find(
    const struct nlr_runtime *r, const char *id)
{
    if (!r)
        return 0;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++) {
        const struct nlr_program_record *rec = &r->resident[i];
        if (!rec->used || rec->kind != NLR_KIND_RESOURCE_EXTENSION)
            continue;
        if (!id)
            return rec;
        uint32_t n = 0;
        while (n < NLR_MANIFEST_ID_MAX && id[n] && rec->id[n] == id[n])
            n++;
        if (!id[n] && !rec->id[n])
            return rec;
    }
    return 0;
}

void nlr_exec_resident_recheck(const struct nlr_exec_services *svc)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || !svc || !svc->audit || !svc->protect)
        return;
    for (uint32_t i = 0; i < NLR_RESIDENT_MAX; i++) {
        const struct nlr_program_record *rec = &r->resident[i];
        if (!rec->used)
            continue;
        /* Code must still be executable and data still writable. Each is
         * put back exactly as the loader set it, and only after the audit
         * says it is wrong — a block nobody disturbed is never touched.
         * The repair is then audited in turn: a block that is executable
         * again and one that could not be put back are not the same
         * thing, and only the second leaves the camera with a resident
         * extension the firmware may be about to call into. */
        const struct {
            void *block;
            uint32_t bytes;
            uint32_t flags;
        } regions[2] = {
            { rec->code_block, rec->code_bytes, svc->flag_executable },
            { rec->data_block, rec->data_bytes, svc->flag_writable },
        };
        for (uint32_t n = 0; n < 2u; n++) {
            if (!regions[n].block || !regions[n].bytes)
                continue;
            if (svc->audit(regions[n].block, regions[n].bytes,
                           regions[n].flags) == 0)
                continue;
            if (svc->protect(regions[n].block, regions[n].bytes,
                             regions[n].flags) == 0 &&
                svc->audit(regions[n].block, regions[n].bytes,
                           regions[n].flags) == 0)
                r->resident_restored++;
            else
                r->resident_unrepaired++;
        }
    }
}

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
extern const struct nlr_exec_services nlr_exec_services;
#endif

static int start_program_checked(struct nlr_runtime *r, uint32_t index,
                                 uint32_t mode);

/* Every start, by whatever path, in the log: which entry, how, the result
 * and how long the check and (for a boot program) the load took. */
static int start_program(struct nlr_runtime *r, uint32_t index, uint32_t mode)
{
    uint32_t t = nlr_clock_ms();
    int result = start_program_checked(r, index, mode);
    if (r && r->load.journal) {
        char id[NLR_MANIFEST_ID_MAX + 1];
        uint32_t n = 0;
        if (index < r->directory.count) {
            const struct nlr_manifest_entry *e = &r->directory.entries[index];
            for (; n < e->id_len && n < NLR_MANIFEST_ID_MAX; n++)
                id[n] = (char)r->directory.buffer[e->id_off + n];
        }
        id[n] = 0;
        JLOG(r, "start %s mode %u: %d, %u ms", n ? id : "?", mode, result,
             nlr_clock_ms() - t);
    }
    return result;
}

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
/* A start the file check refused (the program file could not be read, its
 * header or size is wrong, its CRC does not match, or SAFE_MODE is there)
 * is this program's attempt, recorded as the budget and resident-limit
 * refusals are: the list shows its word and the details its full reason.
 * Without it the open left nothing on either page (the Z 8's SD reads,
 * decision 16: "open from the menu: -4" with no word in the Apps list).
 * Only a refusal of the file itself: a busy loader, a directory not read
 * or an uncertain state say nothing about this program. */
static int file_refusal(int result)
{
    return result == NLR_FORMAT || result == NLR_BOUNDS || result == NLR_CHECKSUM ||
           result == NLR_IO || result == NLR_DISABLED;
}

static void record_refusal(struct nlr_runtime *r, uint32_t index, int result)
{
    if (!file_refusal(result) || r->directory_result != NLR_OK ||
        index >= r->directory.count || r->checked != index ||
        r->directory.entries[index].gate != NLR_GATE_OK ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return;
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    for (uint32_t n = 0; n < e->id_len; n++)
        r->program_id[n] = (char)r->directory.buffer[e->id_off + n];
    r->program_id[e->id_len] = 0;
    /* The worker is idle (state 0): the attempt's facts are the check's. */
    r->load.last_result = result;
    r->load.program.phase = 'L';
    r->load.program.returned = r->load.program.exit_requested = 0;
    r->load.program.exit_code = 0;
    r->program_pending = 1;
}
#endif

static int start_program_checked(struct nlr_runtime *r, uint32_t index,
                                 uint32_t mode)
{
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
    if (!r || (mode != 1 && mode != 2))
        return NLR_NOT_READY;
#ifdef NLR_STAGE_PREPARE_ONLY
    if (mode != 1)
        return NLR_REFUSED;
#endif
    /* A region kept after a failed cleanup refuses every later run until
     * the camera restarts. Nothing is checked or queued, so the record of
     * that failure stays as the worker left it and the page keeps showing
     * it. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0 &&
        r->load.program.code_allocation) {
        r->program_pending = 1;
        r->check_result = NLR_EXEC_RESTORE;
        return NLR_EXEC_RESTORE;
    }
    /* Uncertain init/publication is not termination, including for a later
     * foreground start. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0 &&
        runtime_uncertain(r))
        return uncertain_result(r);
    /* A finished foreground run released its blocks; its record must stop
     * counting against the budget before this start is weighed. */
    nlr_runtime_settle_records(r);
    int result = runtime_check(r, index);
    if (result != NLR_OK) {
        record_refusal(r, index, result);
        return result;
    }
    if (r->load.header_bytes != NLR_GENERIC_HEADER_SIZE) {
        r->check_result = NLR_FORMAT;
        record_refusal(r, index, NLR_FORMAT);
        return NLR_FORMAT;
    }
    /* Named before any refusal so the result row and the registry both
     * speak about the program this decision was made for. */
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    for (uint32_t n = 0; n < e->id_len; n++)
        r->program_id[n] = (char)r->directory.buffer[e->id_off + n];
    r->program_id[e->id_len] = 0;

    /* Blocks the new run will hold: always the code block, plus the data
     * block when the checked file has initialized data or BSS. */
    uint32_t needed = 1u + ((r->load.data_bytes || r->load.bss_bytes) ? 1u : 0u);
    const struct nlr_exec_services *exec = &nlr_exec_services;
    uint32_t budget = exec->program_budget_blocks;
    uint32_t max_resident = exec->program_max_resident;
    uint32_t kind = e->kind;
#if NLR_HAS_GRAPHICS
    if (kind == NLR_KIND_FOREGROUND && r->next_graphics_owner == UINT64_MAX)
        return NLR_REFUSED;
#endif

    if (kind == NLR_KIND_RESOURCE_EXTENSION &&
        (!max_resident || registry_extensions(r) >= max_resident)) {
        /* Nothing runs and no record changes: the limit is reached, and a
         * second resident extension would lose the first one's ownership
         * record. */
        r->check_result = NLR_BUSY;
        r->load.last_result = NLR_BUSY;
        r->program_pending = 1;
        return NLR_BUSY;
    }
    /* An unconfigured budget refuses instead of silently starting without
     * one; the validated profile always injects at least 1. */
    if (!budget || registry_blocks(r) + needed > budget) {
        r->check_result = NLR_EXEC_BUDGET;
        r->load.last_result = NLR_EXEC_BUDGET;
        r->program_pending = 1;
        return NLR_EXEC_BUDGET;
    }

    if (kind == NLR_KIND_FOREGROUND) {
        if (mode == 2)
            exit_install(r);
        /* The run is registered while it is queued or executing (PLAN 5.1);
         * the next observation after it ends clears the record. Its blocks
         * exist only inside the attempt, so the record reserves their sizes
         * and the live addresses stay in the load state. The worker is idle
         * here and extensions are capped below the table size, so a slot is
         * free. */
        struct nlr_program_record *slot = 0;
        for (uint32_t i = 0; i < NLR_RESIDENT_MAX && !slot; i++)
            if (!r->resident[i].used)
                slot = &r->resident[i];
        slot->used = 1;
        slot->failed = 0;
        slot->kind = kind;
        slot->abi_version = r->load.abi_version;
        slot->allocation = 0;
        slot->allocation_bytes = 0;
        slot->code_block = 0;
        slot->code_bytes = exec->region_bytes;
        slot->data_block = 0;
        slot->data_bytes = needed == 2u ? exec->region_bytes : 0;
        for (uint32_t n = 0; n < sizeof slot->id; n++)
            slot->id[n] = r->program_id[n];
    }

#if NLR_HAS_GRAPHICS
    if (kind == NLR_KIND_FOREGROUND) {
        r->graphics_owner = ++r->next_graphics_owner;
    }
#endif
    /* The text row is this run's from here on: whatever an earlier run left
     * in it must never show under this program's row. Nothing runs (the
     * check above saw the state at 0) and ui_draw_text refuses to publish
     * without a run, so no writer is active while it is emptied. */
    nlr_text_publish(&r->text, "");
    /* Before the worker can take it: the worker's flush before the entry
     * then carries this line (load.c). */
    JLOG(r, "queued %s mode %u", r->program_id, mode);
    r->load.program_mode = mode;
    r->load.program_attempted = 0;
    result = nlr_load_enqueue_once(&r->load);
    if (result != NLR_OK)
        r->load.program_mode = 0;
    else
        r->program_pending = 1;
    r->check_result = result;
    return result;
#else
    (void)r; (void)index; (void)mode;
    return NLR_REFUSED;
#endif
}

int nlr_runtime_start_program(struct nlr_runtime *r, uint32_t index,
                              uint32_t mode)
{
    if (r && autoload_active(r))
        return NLR_BUSY;
    return start_program(r, index, mode);
}

static int autoload_stop(struct nlr_runtime *r, int32_t result)
{
    autoload_phase(r, NLR_AUTOLOAD_STOPPED);
    r->autoload.result = result;
    JLOG(r, "pass stopped: %d", result);
    return result;
}
/* NLOADER/BOOT: one line naming a foreground program the camera starts at
 * boot once the autoload pass is done -- a program that takes the screen
 * and the buttons from the stock interface without anyone opening the
 * page. Absent, unreadable or naming anything but a foreground program,
 * nothing starts. */
#define NLR_BOOT_PATH NLR_CARD_ROOT "BOOT"
#define NLR_BOOTRUN_PATH NLR_CARD_ROOT "BOOTRUN"

static int boot_id_byte(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

/* A default file of the release bundle (BOOT, ENABLED), checked against
 * its CRC, or null. */
static const uint8_t *bundle_file(const struct nlr_runtime *r, const char *name,
                                  uint32_t *bytes)
{
    const struct nlr_platform_services *pl = r->load.svc ? r->load.svc->platform : 0;
    const uint8_t *file = 0;
    if (!pl || !pl->bundle ||
        nlr_bundle_find(pl->bundle, pl->bundle_bytes, name, 1, &file, bytes))
        return 0;
    return file;
}

static void boot_read(struct nlr_runtime *r)
{
    r->autoload.boot_index = -1;
    uint32_t bytes = 0;
    uint32_t capacity = r->load.capacity < 256u ? r->load.capacity : 256u;
    const uint8_t *b = r->load.arena;
    /* The card's BOOT decides whenever the card has one -- an empty BOOT
     * included, which is how a card turns a bundled boot program off. Only
     * without one does the release bundle's default apply. */
    if (nlr_card_read(r->load.svc, NLR_BOOT_PATH, r->load.arena, capacity,
                      &bytes, &r->load.trace) != NLR_OK) {
        b = bundle_file(r, "BOOT", &bytes);
        if (!b)
            return;
        if (bytes > 256u)
            bytes = 256u;
    }
    uint32_t start = 0;
    while (start < bytes && !boot_id_byte(b[start]))
        start++;
    uint32_t end = start;
    while (end < bytes && boot_id_byte(b[end]))
        end++;
    if (end == start)
        return;
    const struct nlr_manifest *m = &r->directory;
    for (uint32_t i = 0; i < m->count; i++) {
        const struct nlr_manifest_entry *e = &m->entries[i];
        if (e->kind != NLR_KIND_FOREGROUND || e->id_len != end - start)
            continue;
        uint32_t k = 0;
        while (k < e->id_len) {
            uint8_t x = m->buffer[e->id_off + k], y = b[start + k];
            if (x >= 'A' && x <= 'Z') x = (uint8_t)(x + 32);
            if (y >= 'A' && y <= 'Z') y = (uint8_t)(y + 32);
            if (x != y)
                break;
            k++;
        }
        if (k == e->id_len) {
            r->autoload.boot_index = (int32_t)i;
            return;
        }
    }
}

static int start_program(struct nlr_runtime *r, uint32_t index, uint32_t mode);

/* ---- the GUI layer while a boot program starts ---------------------------
 *
 * The stock GUI draws a first, half-built frame on the turn before the one
 * that starts a boot program, and the display shows it a moment later --
 * in the emulator a quarter of a second into the 1.3 s it takes to read a
 * 2.2 MB program from the card, on the GUI's own task, inside this
 * checkpoint. So while a boot program is read and until its entry runs,
 * and only while the GUI's task is inside the checkpoint (it draws nothing
 * then), the alpha plane the display shows for the GUI layer is cleared:
 * alpha 0 is the GUI's own "nothing here", the live picture shows through.
 * Again whenever the display moves to another buffer, and every
 * NLR_BOOT_VEIL_BLANK_MS of waiting besides. Only the alpha: the colour
 * plane is left alone.
 *
 * The stock GUI only redraws what changes, so the planes it goes on with
 * must be the ones it left: before a plane that holds anything is cleared,
 * a packed copy of it is kept, and when the GUI's task leaves the
 * checkpoint without the program's entry having run (no program, a start
 * that failed), the copies go back first (boot_veil_leave). A plane whose
 * copy does not fit is left as it is. Nothing here runs unless a boot
 * program is being started: not with DISP held, not without a card, not
 * without BOOT. Without the model's scanout registers or cache clean
 * nothing is cleared, and a buffer the registers name must lie whole in the
 * plane band. */
#ifndef NLR_BOOT_VEIL_BLANK_MS
#define NLR_BOOT_VEIL_BLANK_MS 100u
#endif
/* Cleans stay below the size at which the firmware's clean turns into a
 * whole-cache operation on every core (0x88000), as the loader's own
 * cleans do. */
#define NLR_VEIL_CLEAN_PIECE 0x80000u

/* The camera's clock where the model has one, else what the checkpoint
 * has waited. */
static uint32_t boot_veil_now(const struct nlr_runtime *r)
{
    const struct nlr_services *svc = r->load.svc;
    uint64_t ms = 0;
    if (svc && svc->time && svc->time->clock_ms && svc->time->clock_ms(&ms) == 0)
        return (uint32_t)ms;
    return r->autoload.veil_ms;
}

/* The bytes of one alpha plane, 0 when the model says nothing usable. */
static uint32_t boot_veil_bytes(const struct nlr_services *svc)
{
    const struct nlr_program_services *ps = svc ? svc->program : 0;
    if (!ps || !ps->scanout_alpha || !svc->cache_clean)
        return 0;
    uint64_t bytes = (uint64_t)ps->alpha_stride * ps->height;
    return bytes <= UINT32_MAX ? (uint32_t)bytes : 0;
}

static void boot_veil_clean(const struct nlr_services *svc, uint8_t *plane,
                            uint32_t bytes)
{
    for (uint32_t at = 0; at < bytes; at += NLR_VEIL_CLEAN_PIECE) {
        uint32_t piece = bytes - at < NLR_VEIL_CLEAN_PIECE ? bytes - at
                                                          : NLR_VEIL_CLEAN_PIECE;
        svc->cache_clean(plane + at, piece);
    }
}

static int boot_veil_any(const uint8_t *plane, uint32_t bytes)
{
    const uint64_t *word = (const uint64_t *)(const void *)plane;
    for (uint32_t i = 0; i < bytes / 8u; i++)
        if (word[i])
            return 1;
    for (uint32_t i = bytes & ~7u; i < bytes; i++)
        if (plane[i])
            return 1;
    return 0;
}

/* The packed copy: a control byte c < 0x80 is followed by c + 1 literal
 * bytes; c >= 0x80 and one more byte give a run of ((c & 0x7f) << 8 | b) + 1
 * copies of the value after them. 0 when it does not fit in `cap`. */
static uint32_t boot_veil_pack(const uint8_t *plane, uint32_t bytes,
                               uint8_t *out, uint32_t cap)
{
    uint32_t o = 0, lit = 0, lit_at = 0;
    for (uint32_t i = 0; i < bytes;) {
        uint32_t n = 1;
        while (i + n < bytes && plane[i + n] == plane[i] && n < 0x8000u)
            n++;
        if (n >= 3) {
            if (o + 3u > cap)
                return 0;
            out[o++] = (uint8_t)(0x80u | ((n - 1u) >> 8));
            out[o++] = (uint8_t)(n - 1u);
            out[o++] = plane[i];
            lit = 0;
            i += n;
            continue;
        }
        for (uint32_t k = 0; k < n; k++, i++) {
            if (!lit) {
                if (o + 1u > cap)
                    return 0;
                lit_at = o++;
            }
            if (o + 1u > cap)
                return 0;
            out[o++] = plane[i];
            out[lit_at] = (uint8_t)lit;
            if (++lit == 0x80u)
                lit = 0;
        }
    }
    return o;
}

/* A packed copy laid back under what the plane holds now: a byte the
 * plane has as 0 takes the copy's, anything else -- drawn since -- stays.
 * 0 when the copy does not describe exactly `bytes`. */
static int boot_veil_merge(uint8_t *plane, uint32_t bytes, const uint8_t *in,
                           uint32_t kept)
{
    uint32_t at = 0;
    for (uint32_t i = 0; i < kept;) {
        uint8_t c = in[i++];
        if (c < 0x80u) {
            uint32_t n = (uint32_t)c + 1u;
            if (i + n > kept || at + n > bytes)
                return 0;
            for (uint32_t k = 0; k < n; k++, at++)
                if (!plane[at])
                    plane[at] = in[i + k];
            i += n;
        } else {
            if (i + 2u > kept)
                return 0;
            uint32_t n = (((uint32_t)c & 0x7fu) << 8 | in[i]) + 1u;
            uint8_t value = in[i + 1];
            i += 2;
            if (at + n > bytes)
                return 0;
            if (value)
                for (uint32_t k = 0; k < n; k++)
                    if (!plane[at + k])
                        plane[at + k] = value;
            at += n;
        }
    }
    return at == bytes;
}

/* The room for the copies: where the loader can read the heap's books it
 * is granted whole, as every large block the loader takes. */
static void *boot_veil_alloc(const struct nlr_services *svc, uint32_t bytes)
{
    return nlr_alloc_whole(svc, bytes);
}

static int boot_veil_try_lock(struct nlr_runtime *r)
{
    return !__atomic_exchange_n(&r->autoload.veil_lock, 1u, __ATOMIC_ACQUIRE);
}

/* The lock, waited for a bounded while (a blank holds it a millisecond or
 * two); 0 when it never came free. */
static int boot_veil_lock(struct nlr_runtime *r)
{
    const struct nlr_services *svc = r->load.svc;
    for (uint32_t tries = 0; tries < 1000u; tries++) {
        if (boot_veil_try_lock(r))
            return 1;
        if (svc && svc->time && svc->time->delay_ms)
            (void)svc->time->delay_ms(1u);
        else if (svc && svc->sleep_ms)
            svc->sleep_ms(1u);
    }
    return 0;
}

static void boot_veil_unlock(struct nlr_runtime *r)
{
    __atomic_store_n(&r->autoload.veil_lock, 0u, __ATOMIC_RELEASE);
}

static void boot_veil_blank(struct nlr_runtime *r)
{
    const struct nlr_services *svc = r->load.svc;
    uint32_t bytes = boot_veil_bytes(svc);
    if (!bytes)
        return;
    const struct nlr_program_services *ps = svc->program;
    const volatile uint32_t *pair = ps->scanout_alpha;
    uint64_t bus = (uint64_t)pair[0] |
                   (uint64_t)(pair[1] & ps->scanout_high_mask) << 32;
    uint64_t alpha = bus >= ps->bus_offset ? bus - ps->bus_offset : 0;
    if (!alpha || (alpha & 31u) || alpha < ps->plane_lo ||
        alpha >= ps->plane_hi || bytes > ps->plane_hi - alpha)
        return;
    /* best effort: the other task is at it this moment */
    if (!boot_veil_try_lock(r))
        return;
    /* only while the GUI draws nothing, and never once the program's entry
     * has run: the layer is the program's from there on */
    if (!__atomic_load_n(&r->autoload.veil_inside, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&r->load.program.entry_started, __ATOMIC_ACQUIRE)) {
        boot_veil_unlock(r);
        return;
    }
    uint32_t now = boot_veil_now(r);
    struct nlr_veil_plane *plane = 0, *spare = 0;
    for (uint32_t i = 0; i < NLR_VEIL_PLANES; i++) {
        struct nlr_veil_plane *p = &r->autoload.veil_planes[i];
        if (p->address == alpha)
            plane = p;
        else if (!p->address && !spare)
            spare = p;
    }
    if (plane && (plane->refused ||
                  now - plane->blank_ms < NLR_BOOT_VEIL_BLANK_MS)) {
        boot_veil_unlock(r);
        return;
    }
    if (!plane) {
        if (!spare) {
            r->autoload.veil_refused++;
            boot_veil_unlock(r);
            return;
        }
        plane = spare;
        plane->address = alpha;
        plane->kept = 0;
        plane->refused = 0;
    }
    uint8_t *shown = (uint8_t *)(uintptr_t)alpha;
    if (boot_veil_any(shown, bytes)) {
        /* what is there: the GUI's frame, or what landed since the last
         * clear, laid over the copy kept then */
        if (!r->autoload.veil_keep)
            r->autoload.veil_keep = boot_veil_alloc(svc, NLR_VEIL_PLANES * NLR_VEIL_KEEP);
        uint8_t *keep = r->autoload.veil_keep
            ? r->autoload.veil_keep + (uint32_t)(plane - r->autoload.veil_planes) * NLR_VEIL_KEEP
            : 0;
        uint32_t kept = 0;
        if (keep && (!plane->kept || boot_veil_merge(shown, bytes, keep, plane->kept)))
            kept = boot_veil_pack(shown, bytes, keep, NLR_VEIL_KEEP);
        if (!kept) {
            /* no room: the plane stays as the GUI drew it (with the copy
             * laid back, when there was one) */
            plane->refused = 1;
            plane->kept = 0;
            boot_veil_clean(svc, shown, bytes);
            r->autoload.veil_refused++;
            boot_veil_unlock(r);
            return;
        }
        plane->kept = kept;
    }
    uint64_t *clear = (uint64_t *)(void *)shown;
    for (uint32_t i = 0; i < bytes / 8u; i++)
        clear[i] = 0;
    for (uint32_t i = bytes & ~7u; i < bytes; i++)
        shown[i] = 0;
    boot_veil_clean(svc, shown, bytes);
    plane->blank_ms = now;
    r->autoload.veil_blanks++;
    boot_veil_unlock(r);
}

/* The copies go: laid back under their planes (put_back), or only
 * dropped once the program has the layer. Called with the lock held. */
static void boot_veil_release(struct nlr_runtime *r, int put_back)
{
    const struct nlr_services *svc = r->load.svc;
    uint32_t bytes = boot_veil_bytes(svc);
    for (uint32_t i = 0; i < NLR_VEIL_PLANES; i++) {
        struct nlr_veil_plane *p = &r->autoload.veil_planes[i];
        if (put_back && bytes && p->kept && r->autoload.veil_keep) {
            uint8_t *shown = (uint8_t *)(uintptr_t)p->address;
            if (boot_veil_merge(shown, bytes, r->autoload.veil_keep + i * NLR_VEIL_KEEP,
                                p->kept))
                r->autoload.veil_restored++;
            boot_veil_clean(svc, shown, bytes);
        }
        p->address = 0;
        p->kept = 0;
        p->blank_ms = 0;
        p->refused = 0;
    }
    if (r->autoload.veil_keep && svc && svc->release)
        svc->release(r->autoload.veil_keep);
    r->autoload.veil_keep = 0;
}

/* The GUI's task leaves the checkpoint: what it drew goes back unless the
 * program's entry has run, before the task can draw again. */
static void boot_veil_leave(struct nlr_runtime *r)
{
    int locked = boot_veil_lock(r);
    if (locked)
        boot_veil_release(r, !__atomic_load_n(&r->load.program.entry_started,
                                               __ATOMIC_ACQUIRE));
    __atomic_store_n(&r->autoload.veil_inside, 0u, __ATOMIC_RELEASE);
    if (locked)
        boot_veil_unlock(r);
}

/* A chunk of the boot program has been read (nlr_load.chunk_read). */
static void boot_load_chunk(struct nlr_load *l)
{
    struct nlr_runtime *r = (struct nlr_runtime *)(void *)l;
    if (!__atomic_load_n(&r->autoload.boot_decided, __ATOMIC_ACQUIRE))
        boot_veil_blank(r);
}

/* ---- the boot record ------------------------------------------------------
 *
 * A boot loop is the risk a program started without anyone asking brings.
 * So the start is recorded before it is queued (RUN), and its outcome once
 * it reports back: OK when its entry ran and it either ended well or was
 * still running NLR_BOOT_GOOD_MS after the start, FAILED with the result
 * when it never reached its entry or ended in an error. A boot that finds
 * RUN still there -- the last start never reported back, the camera went
 * down under it -- skips the program this once and records SKIPPED, so the
 * boot after tries again. The record lives where the store keeps it: the
 * native card's journal (STATE.NLS format 2, with the program's id), or the
 * BOOTRUN file of an ordinary card ("run", "ok", "skipped", "failed"). */

static void boot_mark_name(const struct nlr_runtime *r, uint32_t index,
                           struct nlr_boot_mark *mark)
{
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    uint32_t n = 0;
    for (; n < e->id_len && n < NLR_MANIFEST_ID_MAX; n++)
        mark->id[n] = (char)r->directory.buffer[e->id_off + n];
    for (; n <= NLR_MANIFEST_ID_MAX; n++)
        mark->id[n] = 0;
}

static int boot_record_get(struct nlr_runtime *r, const struct nlr_card_store *store,
                           struct nlr_boot_mark *out)
{
    out->mark = NLR_BOOT_MARK_NONE;
    out->result = 0;
    out->id[0] = 0;
    if (store && store->boot_mark_get)
        return store->boot_mark_get(out);
    if (!store || !store->replace)
        return NLR_NOT_READY;
    /* BOOTRUN carries the mark alone. A missing or unreadable file is no
     * RUN, as it always was here: only a RUN that is read skips a start. */
    uint32_t bytes = 0;
    uint32_t capacity = r->load.capacity < 64u ? r->load.capacity : 64u;
    if (nlr_card_read(r->load.svc, NLR_BOOTRUN_PATH, r->load.arena, capacity,
                      &bytes, &r->load.trace) == NLR_OK &&
        bytes >= 3 && r->load.arena[0] == 'r' && r->load.arena[1] == 'u' &&
        r->load.arena[2] == 'n')
        out->mark = NLR_BOOT_MARK_RUN;
    return NLR_OK;
}

static int boot_record_set(const struct nlr_card_store *store,
                           const struct nlr_boot_mark *mark)
{
    if (store && store->boot_mark_set)
        return store->boot_mark_set(mark);
    if (!store || !store->replace)
        return NLR_NOT_READY;
    const char *text = mark->mark == NLR_BOOT_MARK_RUN ? "run"
                     : mark->mark == NLR_BOOT_MARK_OK ? "ok"
                     : mark->mark == NLR_BOOT_MARK_SKIPPED ? "skipped"
                     : mark->mark == NLR_BOOT_MARK_FAILED ? "failed" : 0;
    if (!text)
        return NLR_BOUNDS;
    uint32_t bytes = 0;
    while (text[bytes])
        bytes++;
    return store->replace(NLR_BOOTRUN_PATH, (const uint8_t *)text, bytes) == NLR_OK
               ? NLR_OK : NLR_IO;
}

/* The start's outcome, written once by whichever task claims it from
 * `from` (OWED with the outcome given here, or DUE with the outcome a busy
 * store refused earlier). A busy store leaves it DUE for the next settle;
 * anything else -- written, failed, uncertain -- ends it for this boot:
 * the record is a guard for the next boot, never retried into a store
 * that has said no, and an uncertain native commit stops every later
 * commit by itself. */
static void boot_record_finish(struct nlr_runtime *r, uint32_t from,
                               uint32_t mark, int32_t result)
{
    uint32_t expected = from;
    if (!__atomic_compare_exchange_n(&r->autoload.boot_record, &expected,
                                     NLR_BOOT_RECORD_WRITING, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    if (from == NLR_BOOT_RECORD_OWED) {
        r->autoload.boot_mark.mark = mark;
        r->autoload.boot_mark.result = mark != NLR_BOOT_MARK_FAILED ? 0
                                     : result != NLR_OK ? result : NLR_NOT_READY;
    }
    int written = boot_record_set(r->autoload.store, &r->autoload.boot_mark);
    r->autoload.boot_record_result = written;
    __atomic_store_n(&r->autoload.boot_record,
                     written == NLR_BUSY ? NLR_BOOT_RECORD_DUE : NLR_BOOT_RECORD_DONE,
                     __ATOMIC_RELEASE);
}

void nlr_runtime_boot_completed(struct nlr_runtime *r)
{
    if (!r || __atomic_load_n(&r->autoload.boot_record, __ATOMIC_ACQUIRE) !=
                  NLR_BOOT_RECORD_OWED)
        return;
    /* The one attempt that can complete while the record is owed is the
     * boot program's own: nothing else starts while it is queued or runs. */
    int32_t result = r->load.last_result;
    uint32_t entered = r->load.program.entry_started;
    boot_record_finish(r, NLR_BOOT_RECORD_OWED,
                       entered && result == NLR_OK ? NLR_BOOT_MARK_OK
                                                   : NLR_BOOT_MARK_FAILED,
                       result);
}

void nlr_runtime_boot_alive(struct nlr_runtime *r)
{
    if (!r || __atomic_load_n(&r->autoload.boot_record, __ATOMIC_ACQUIRE) !=
                  NLR_BOOT_RECORD_OWED ||
        !__atomic_load_n(&r->load.program.entry_started, __ATOMIC_ACQUIRE) ||
        nlr_clock_ms() - r->autoload.boot_record_ms < NLR_BOOT_GOOD_MS)
        return;
    boot_record_finish(r, NLR_BOOT_RECORD_OWED, NLR_BOOT_MARK_OK, NLR_OK);
}

static int boot_start_index(struct nlr_runtime *r, int32_t index);

void nlr_runtime_boot_mark_settle(struct nlr_runtime *r)
{
    if (!r)
        return;
    uint32_t record = __atomic_load_n(&r->autoload.boot_record, __ATOMIC_ACQUIRE);
    if (record == NLR_BOOT_RECORD_DUE) {
        boot_record_finish(r, NLR_BOOT_RECORD_DUE, 0, 0);
        return;
    }
    /* A start a busy store put off: one task takes it at a time. */
    uint32_t expected = NLR_BOOT_RECORD_START;
    if (record != NLR_BOOT_RECORD_START ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0 ||
        !__atomic_compare_exchange_n(&r->autoload.boot_record, &expected,
                                     NLR_BOOT_RECORD_WRITING, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    (void)boot_start_index(r, r->autoload.boot_start_index);
    if (__atomic_load_n(&r->autoload.boot_record, __ATOMIC_ACQUIRE) ==
        NLR_BOOT_RECORD_START)
        return; /* still busy and still in time: put off again */
    __atomic_store_n(&r->autoload.boot_decided, 1u, __ATOMIC_RELEASE);
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0)
        (void)nlr_journal_flush(r->load.journal, r->load.svc, 0);
}

/* The pass is done: start the boot program, once (the record above).
 * DISP held at power-on skips it like any autoload. */
static void boot_program_start(struct nlr_runtime *r);

static void boot_program(struct nlr_runtime *r)
{
    boot_program_start(r);
    /* a start a busy store put off is decided by its retry */
    if (__atomic_load_n(&r->autoload.boot_record, __ATOMIC_ACQUIRE) !=
        NLR_BOOT_RECORD_START)
        __atomic_store_n(&r->autoload.boot_decided, 1u, __ATOMIC_RELEASE);
    /* Only with nothing queued: a flush is a card write, and on the native
     * card it would hold the request the worker's own reads need while it
     * loads the boot program (QEMU sp-012: "attempt failed: -6"). A started
     * program's lines go out with the worker's own flush. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0)
        (void)nlr_journal_flush(r->load.journal, r->load.svc, 0);
}

static void boot_program_start(struct nlr_runtime *r)
{
    /* BOOT is read here and only here: once the pass has finished cleanly,
     * so a paused or failed pass asks the card for nothing more than it
     * always did. */
    boot_read(r);
    int32_t index = r->autoload.boot_index;
    JLOG(r, "pass done; BOOT names entry %d", index);
    if (index < 0)
        return;
    r->autoload.boot_index = -1;
    r->autoload.boot_start_ms = nlr_clock_ms();
    (void)boot_start_index(r, index);
}

/* A busy store (the native card's one request, held by another task past
 * its wait) has said neither yes nor no: the start is put off to the next
 * settle (NLR_BOOT_RECORD_START), not given up, until NLR_BOOT_START_WAIT_MS
 * after the first try. NLR_BUSY when put off again; otherwise the start
 * has been decided, queued or not. */
static int boot_start_deferred(struct nlr_runtime *r, int32_t index, int result)
{
    if (result != NLR_BUSY)
        return 0;
    uint32_t waited = nlr_clock_ms() - r->autoload.boot_start_ms;
    if (waited >= NLR_BOOT_START_WAIT_MS) {
        JLOG(r, "boot record busy for %u ms: boot program not started", waited);
        return 0;
    }
    r->autoload.boot_start_index = index;
    __atomic_store_n(&r->autoload.boot_record, NLR_BOOT_RECORD_START, __ATOMIC_RELEASE);
    return 1;
}

static int boot_start_index(struct nlr_runtime *r, int32_t index)
{
    const struct nlr_card_store *store = r->autoload.store;
    struct nlr_boot_mark *mark = &r->autoload.boot_mark;
    struct nlr_boot_mark prior;
    int result = boot_record_get(r, store, &prior);
    if (boot_start_deferred(r, index, result))
        return NLR_BUSY;
    if (result != NLR_OK) {
        /* No record can be read, so none can be trusted to guard the start:
         * it does not happen. */
        __atomic_store_n(&r->autoload.boot_record, NLR_BOOT_RECORD_DONE, __ATOMIC_RELEASE);
        r->autoload.boot_result = result;
        JLOG(r, "boot record not read (%d): boot program not started", result);
        return result;
    }
    boot_mark_name(r, (uint32_t)index, mark);
    mark->result = 0;
    if (prior.mark == NLR_BOOT_MARK_RUN) {
        mark->mark = NLR_BOOT_MARK_SKIPPED;
        r->autoload.boot_record_result = boot_record_set(store, mark);
        __atomic_store_n(&r->autoload.boot_record, NLR_BOOT_RECORD_DONE, __ATOMIC_RELEASE);
        r->autoload.boot_result = NLR_AUTOLOAD_PAUSED;
        JLOG(r, "boot record still said run: boot program skipped once");
        return NLR_OK;
    }
    mark->mark = NLR_BOOT_MARK_RUN;
    result = boot_record_set(store, mark);
    r->autoload.boot_record_result = result;
    if (boot_start_deferred(r, index, result))
        return NLR_BUSY;
    if (result != NLR_OK) {
        /* Not durable (or not known to be): the start is not queued. */
        __atomic_store_n(&r->autoload.boot_record, NLR_BOOT_RECORD_DONE, __ATOMIC_RELEASE);
        r->autoload.boot_result = result;
        JLOG(r, "boot record not written (%d): boot program not started", result);
        return result;
    }
    r->autoload.boot_record_ms = nlr_clock_ms();
    __atomic_store_n(&r->autoload.boot_record, NLR_BOOT_RECORD_OWED, __ATOMIC_RELEASE);
    /* The program is read from the card by the worker, and that takes a
     * while (1.3 s for 2.2 MB in the emulator): chunk by chunk, the GUI
     * layer is kept blank meanwhile. */
    __atomic_store_n(&r->load.chunk_read,
                     r->load.in_runtime ? boot_load_chunk : 0, __ATOMIC_RELEASE);
    /* what the pass decided reaches the card before the worker starts */
    (void)nlr_journal_flush(r->load.journal, r->load.svc, 0);
    r->autoload.boot_result = start_program(r, (uint32_t)index, 2);
    __atomic_store_n(&r->load.chunk_read, 0, __ATOMIC_RELEASE);
    if (r->autoload.boot_result == NLR_OK) {
        /* the shell: the one program that may hold the stock GUI (ABI 7
         * screen_claim), for as long as it runs */
        __atomic_store_n(&r->plat.shell, 1u, __ATOMIC_RELEASE);
        __atomic_store_n(&r->autoload.boot_hold, 1u, __ATOMIC_RELEASE);
    } else {
        /* refused before it was queued: the outcome is known now */
        boot_record_finish(r, NLR_BOOT_RECORD_OWED, NLR_BOOT_MARK_FAILED,
                           r->autoload.boot_result);
    }
    return NLR_OK;
}

static int autoload_read_settings(struct nlr_runtime *r)
{
#if NLR_HAS_NATIVE_CARD
    if (r->load.svc->native_card) {
        int result = nlr_native_card_read_settings(r, &r->autoload.enabled);
        if (result == NLR_OK)
            nlr_enabled_copy(&r->saved_enabled, &r->autoload.enabled);
        return r->autoload.enabled_result = result;
    }
#endif
    int result = nlr_runtime_read_directory(r);
    if (result != NLR_OK)
        return r->autoload.enabled_result = result;
    uint32_t bytes = 0;
    uint32_t capacity = r->load.capacity < NLR_ENABLED_BYTES
                            ? r->load.capacity : NLR_ENABLED_BYTES;
    result = nlr_card_read(r->load.svc, NLR_ENABLED_PATH, r->load.arena,
                           capacity, &bytes, &r->load.trace);
    if (result == NLR_IO) {
        /* The reader cannot tell a missing ENABLED from an unreadable
         * card. The reliable probe can, and a card that names nothing has
         * nothing to load: only a genuine error pauses this boot. */
        uint32_t present = 1;
        int probed = card_probe(r->autoload.store, NLR_ENABLED_PATH, &present);
        if (probed != NLR_OK)
            return r->autoload.enabled_result = probed;
        if (!present) {
            bytes = 0;
            result = NLR_OK;
        }
    }
    const uint8_t *enabled = r->load.arena;
    if (result == NLR_OK && !bytes) {
        /* A card that names nothing to load: the release bundle's default
         * list, when it has one (an empty ENABLED on the card is the same
         * as none: the bundle's list cannot be turned off by it; SAFE_MODE
         * and DISP can). */
        uint32_t defaults = 0;
        const uint8_t *list = bundle_file(r, "ENABLED", &defaults);
        if (list && defaults <= NLR_ENABLED_BYTES) {
            enabled = list;
            bytes = defaults;
        }
    }
    if (result == NLR_OK)
        result = nlr_enabled_parse(&r->autoload.enabled, &r->directory,
                                   enabled, bytes);
    if (result == NLR_OK)
        nlr_enabled_copy(&r->saved_enabled, &r->autoload.enabled);
    return r->autoload.enabled_result = result;
}


static uint32_t autoload_driver_take(struct nlr_runtime *r);
static int autoload_open(struct nlr_runtime *r,
                         const struct nlr_card_store *store);

/* Two tasks may open the pass: a boot checkpoint on its task and a page
 * visit on the menu task. Only one may read the settings and write the
 * marker, so opening takes the same driver the steps take; a caller that
 * finds it held leaves the pass to the holder. */
int nlr_runtime_autoload_begin(struct nlr_runtime *r,
                               const struct nlr_card_store *store)
{
    if (!r || !r->load.svc || !r->directory_buffer)
        return NLR_NOT_READY;
    if (r->autoload.phase != NLR_AUTOLOAD_NEW)
        return r->autoload.result;
    if (!autoload_driver_take(r))
        return NLR_BUSY;
    int result = autoload_open(r, store);
    __atomic_store_n(&r->autoload.driver, 0u, __ATOMIC_RELEASE);
    return result;
}

static int autoload_open(struct nlr_runtime *r,
                         const struct nlr_card_store *store)
{
    if (r->autoload.phase != NLR_AUTOLOAD_NEW)
        return r->autoload.result;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return NLR_BUSY;
    r->autoload.store = store;
    int result;
    /* The NLoader switch off: this boot writes nothing on the card, on
     * either body -- no pending marker, no boot record and no first
     * STATE.NLS migration, no LOADER.LOG lines (main session decision
     * 2026-10-18; neither body had a design). Only reads follow: the
     * directory is listed so the page can answer "NLoader is off" as
     * before. Turning the switch back on is the page's own checked write,
     * which lets the log go to the card again (menu_page.c). */
    if (nlr_master_off(r->load.svc, 0)) {
        /* the loader's own log included: it stays in RAM */
        nlr_journal_hold(r->load.journal, 1u);
        nlr_runtime_read_directory(r);
        r->autoload.enabled_result = NLR_DISABLED;
        return autoload_stop(r, NLR_DISABLED);
    }
#if NLR_HAS_NATIVE_CARD
    if (r->load.svc->native_card) {
        result = autoload_read_settings(r);
        if (result != NLR_OK)
            return autoload_stop(r, result);
    }
#endif
    result = runtime_autoload_guard(r, 0);
    if (result == NLR_AUTOLOAD_PAUSED) {
        /* Residual marker blocks execution, not inspection/correction of
         * the saved order. Reading settings cannot re-arm this boot. */
        autoload_stop(r, result);
#if NLR_HAS_NATIVE_CARD
        if (!r->load.svc->native_card)
#endif
            autoload_read_settings(r);
        return result;
    }
    if (result != NLR_OK)
        return autoload_stop(r, result);
#if !defined(NLR_STAGE_EXEC)
    return autoload_stop(r, NLR_REFUSED);
#else
    if (!store || ((!store->replace || !store->remove)
#if NLR_HAS_NATIVE_CARD
                   && !r->load.svc->native_card
#endif
                   ))
        return autoload_stop(r, NLR_NOT_READY);
    /* No earlier manually initialized extension can be silently counted as
     * this boot's successful ordered pass. Mount owner must begin first. */
    if (nlr_runtime_resident_find(r, 0))
        return autoload_stop(r, NLR_BUSY);
    result = NLR_OK;
#if NLR_HAS_NATIVE_CARD
    if (!r->load.svc->native_card)
#endif
        result = autoload_read_settings(r);
    if (result != NLR_OK)
        return autoload_stop(r, result);
    if (!r->autoload.enabled.count) {
        autoload_phase(r, NLR_AUTOLOAD_DONE);
        boot_program(r);
        return r->autoload.result = NLR_OK;
    }
    /* Reconfirm guards after reading settings and before durable commit.
     * A zero-byte marker is sufficient: existence, not content, is the
     * crash detector. No entry is queued before replace succeeds. */
    result = runtime_autoload_guard(r, 0);
    if (result == NLR_OK)
#if NLR_HAS_NATIVE_CARD
        result = r->load.svc->native_card ? nlr_native_card_pending(r, 1) :
#else
        result =
#endif
            store->replace(NLR_AUTOLOAD_PENDING_PATH, 0, 0);
    if (result != NLR_OK)
        return autoload_stop(r, result);
    result = runtime_autoload_guard(r, 1);
    if (result != NLR_OK)
        return autoload_stop(r, result);
    autoload_phase(r, NLR_AUTOLOAD_READY);
    return r->autoload.result = NLR_OK;
#endif
}

static void autoload_observe(struct nlr_runtime *r)
{
    uint32_t n = r->autoload.next;
    if (n >= r->autoload.enabled.count ||
        r->autoload.item[n] != NLR_EXTENSION_INITIALIZING)
        return;
    const struct nlr_program_record *rec =
        nlr_runtime_resident_find(r, r->autoload.enabled.id[n]);
    r->autoload.item[n] = rec
        ? (rec->failed ? NLR_EXTENSION_PARTIAL : NLR_EXTENSION_LOADED)
        : (r->load.program.entry_started ? NLR_EXTENSION_PARTIAL
                                         : NLR_EXTENSION_NOT_EXECUTED);
}

int nlr_runtime_autoload_step(struct nlr_runtime *r)
{
    if (!r)
        return NLR_NOT_READY;
    if (r->autoload.phase == NLR_AUTOLOAD_NEW)
        return NLR_NOT_READY;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return NLR_BUSY;
    if (r->autoload.phase == NLR_AUTOLOAD_STOPPED) {
        autoload_observe(r);
        return r->autoload.result;
    }
    if (r->autoload.phase == NLR_AUTOLOAD_DONE)
        return r->autoload.result;
    if (r->autoload.phase == NLR_AUTOLOAD_WAITING) {
        autoload_observe(r);
        if (r->load.last_result != NLR_OK ||
            r->autoload.item[r->autoload.next] != NLR_EXTENSION_LOADED)
            return autoload_stop(r, r->load.last_result != NLR_OK
                                      ? r->load.last_result : NLR_NOT_READY);
        /* Init returning zero is not the completed resource step: only the
         * menu owner can acknowledge publication. An absent menu cycle keeps
         * WAITING and the durable marker forever, with no later init/clear. */
        if (runtime_menu_pending(r)) {
            r->autoload.item[r->autoload.next] = NLR_EXTENSION_INITIALIZING;
            return NLR_BUSY;
        }
        r->autoload.next++;
        autoload_phase(r, r->autoload.next == r->autoload.enabled.count
                              ? NLR_AUTOLOAD_CLEAR : NLR_AUTOLOAD_READY);
        return NLR_OK;
    }
    int result = runtime_autoload_guard(r, 1);
    /* Busy is the native card's one request held by another task (a
     * resident program's file calls, a log flush) before anything was
     * read or written: the pass waits for its next step instead of
     * stopping and leaving the pending mark (QEMU qemu-ki-019, -022). */
    if (result == NLR_BUSY)
        return NLR_BUSY;
    if (result != NLR_OK)
        return autoload_stop(r, result);
    if (r->autoload.phase == NLR_AUTOLOAD_CLEAR) {
#if NLR_HAS_NATIVE_CARD
        result = r->load.svc->native_card ? nlr_native_card_pending(r, 0) :
#else
        result =
#endif
            r->autoload.store->remove(NLR_AUTOLOAD_PENDING_PATH);
        if (result == NLR_BUSY)
            return NLR_BUSY;
        if (result != NLR_OK)
            return autoload_stop(r, result);
        autoload_phase(r, NLR_AUTOLOAD_DONE);
        boot_program(r);
        return r->autoload.result = NLR_OK;
    }
    uint32_t n = r->autoload.next;
    /* Set WAITING before enqueue: a worker may immediately recheck. */
    r->autoload.item[n] = NLR_EXTENSION_INITIALIZING;
    autoload_phase(r, NLR_AUTOLOAD_WAITING);
    result = start_program(r, r->autoload.enabled.index[n], 2);
    if (result != NLR_OK) {
        r->autoload.item[n] = NLR_EXTENSION_NOT_EXECUTED;
        return autoload_stop(r, result);
    }
    return NLR_OK;
}

/* The pass, carried as far as it can go from here. One step is all a
 * single caller used to make: the page visit that starts the first
 * extension cannot also take in what it did, because the worker is only
 * then loading it. A camera switched off after that one visit found the
 * marker still on the card next boot and paused autoload, although
 * nothing had gone wrong. So every completed load lets the worker carry
 * the pass on — take in the result, start the next extension, and clear
 * the marker after the last one — and a page visit does the same. It
 * stops at the one thing neither can do alone: publishing a resource an
 * extension registered needs the menu owner, and the next page visit is
 * where that happens. */
/* The steps themselves. Exactly one task runs this at a time; see the
 * caller below. */
static void autoload_drive(struct nlr_runtime *r)
{
    /* Two moves per extension (start it, take it in) and one to clear. */
    for (uint32_t steps = 2u * NLR_MANIFEST_MAX_ENTRIES + 2u; steps; steps--) {
        if (!autoload_active(r) ||
            __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
            return;
        uint32_t phase = r->autoload.phase;
        uint32_t next = r->autoload.next;
        if (nlr_runtime_autoload_step(r) != NLR_OK)
            return;
        if (r->autoload.phase == phase && r->autoload.next == next)
            return;
    }
}

static uint32_t autoload_driver_take(struct nlr_runtime *r)
{
    uint32_t idle = 0;
    return __atomic_compare_exchange_n(&r->autoload.driver, &idle, 1u, 0,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

int nlr_runtime_autoload_step_owned(struct nlr_runtime *r)
{
    if (!r)
        return NLR_NOT_READY;
    if (!autoload_driver_take(r)) {
        __atomic_store_n(&r->autoload.pending, 1u, __ATOMIC_RELEASE);
        return NLR_BUSY;
    }
    int result = nlr_runtime_autoload_step(r);
    __atomic_store_n(&r->autoload.driver, 0u, __ATOMIC_RELEASE);
    return result;
}

void nlr_runtime_autoload_continue(struct nlr_runtime *r)
{
    if (!r)
        return;
    /* Both drivers arrive here, from different tasks, and a step must not
     * be taken twice: two callers would start the same extension, and the
     * one that lost would stop the whole pass with a busy and leave its
     * marker on the card — or they would move past the same extension and
     * one of them would never be loaded. So one task steps at a time. A
     * caller that finds the pass already being carried says it has
     * something new and leaves; the task holding it looks again before
     * stopping, so a load that finished inside that window is still taken
     * in. */
    __atomic_store_n(&r->autoload.pending, 1u, __ATOMIC_RELEASE);
    while (autoload_driver_take(r)) {
        __atomic_store_n(&r->autoload.pending, 0u, __ATOMIC_RELEASE);
        autoload_drive(r);
        __atomic_store_n(&r->autoload.driver, 0u, __ATOMIC_RELEASE);
        if (!__atomic_load_n(&r->autoload.pending, __ATOMIC_ACQUIRE))
            return;
    }
}

/* How many times a boot checkpoint asks the card for MANIFEST before it
 * leaves the pass to a page visit. The asks fall on the turns of the
 * firmware's loop that are powers of two -- 1, 2, 4, ... 2048 -- so a card
 * still mounting is asked often at first, and a camera with no card or no
 * loader directory soon stops paying for the question. At the Z 6III live
 * view's ~17 turns a second the last ask comes about two minutes in. */
#define NLR_BOOT_CARD_ASKS 12u

/* The boot program owns the screen. This checkpoint runs on the stock
 * live-view GUI's task, once a turn, before the task waits for work:
 * holding it here keeps the stock overlay from drawing or switching the GUI
 * layer's buffers under the program, for as long as the program runs. The
 * live picture, the buttons and everything else go on in their own tasks.
 * When the program ends, the task goes back to its loop and redraws. */
/* What the display shows while the GUI is held, in the log: the GUI is
 * stopped here, so a change of the layer's buffer comes from elsewhere --
 * and what the program draws is then not what the screen shows. */
static void hold_watch(struct nlr_runtime *r, uint64_t *colour, uint64_t *alpha,
                       uint32_t *changes)
{
    uint64_t c = 0, a = 0;
    if (!r->load.journal || nlr_program_scanout(&c, &a) != NLR_OK ||
        (c == *colour && a == *alpha))
        return;
    int claimed = __atomic_load_n(&r->plat.claimed, __ATOMIC_ACQUIRE) != 0;
    uint64_t ours_c = r->plat.colour, ours_a = r->plat.alpha;
    if (++*changes <= 64u)
        JLOG(r, "held: layer %lx/%lx%s", (unsigned long long)c, (unsigned long long)a,
             !claimed ? "" : c == ours_c && a == ours_a ? " ours" : " NOT the program's");
    else if (*changes == 65u)
        JLOG(r, "held: the layer keeps changing; no more of these");
    *colour = c;
    *alpha = a;
}

static void boot_hold_wait(struct nlr_runtime *r)
{
    const struct nlr_services *svc = r->load.svc;
    uint32_t entered = 0, since = nlr_clock_ms(), changes = 0;
    uint64_t shown_c = 0, shown_a = 0;
    boot_veil_blank(r);
    __atomic_store_n(&r->plat.inside, 1u, __ATOMIC_RELEASE);
    JLOG(r, "GUI held (shell %u)", (unsigned)__atomic_load_n(&r->plat.shell, __ATOMIC_ACQUIRE));
    hold_watch(r, &shown_c, &shown_a, &changes);
    /* Until the program ends, or gives the screen back and runs on
     * without it (ABI 7 screen_release). */
    while (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0 &&
           !__atomic_load_n(&r->plat.lent, __ATOMIC_ACQUIRE)) {
        if (svc && svc->time && svc->time->delay_ms)
            (void)svc->time->delay_ms(10u);
        else if (svc && svc->sleep_ms)
            svc->sleep_ms(10u);
        else
            break;
        r->autoload.veil_ms += 10u;
#if defined(NLR_DEV_CORE)
        /* the core's own health report goes on while it holds the GUI */
        nlr_core_alive(r);
#endif
        if (!entered &&
            __atomic_load_n(&r->load.program.entry_started, __ATOMIC_ACQUIRE)) {
            /* the layer is the program's: the copies are not needed */
            entered = 1;
            JLOG(r, "held: the program's entry runs, %u ms in", nlr_clock_ms() - since);
            if (boot_veil_lock(r)) {
                boot_veil_release(r, 0);
                boot_veil_unlock(r);
            }
        }
        boot_veil_blank(r);
        hold_watch(r, &shown_c, &shown_a, &changes);
        /* the log reaches the card while the program runs */
        (void)nlr_journal_flush(r->load.journal, svc, 2000u);
    }
    __atomic_store_n(&r->autoload.boot_hold, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&r->plat.inside, 0u, __ATOMIC_RELEASE);
    JLOG(r, "GUI released after %u ms: %s", nlr_clock_ms() - since,
         __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0 ? "the program ended"
         : __atomic_load_n(&r->plat.lent, __ATOMIC_ACQUIRE) ? "the screen was given back"
                                                             : "no delay service");
    (void)nlr_journal_flush(r->load.journal, svc, 0);
    /* A program that ended is no shell any more, whether or not its
     * cleanup ran. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0) {
        __atomic_store_n(&r->plat.shell, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&r->plat.leaving, 0u, __ATOMIC_RELEASE);
    }
}

static void boot_step(struct nlr_runtime *r, const struct nlr_card_store *store);

int nlr_runtime_boot_turn_enter(struct nlr_runtime *r)
{
    if (!r)
        return 0;
    __atomic_store_n(&r->autoload.veil_inside, 1u, __ATOMIC_RELEASE);
    if (!__atomic_load_n(&r->autoload.boot_hold, __ATOMIC_ACQUIRE))
        return 0;
    boot_hold_wait(r);
    return 1;
}

void nlr_runtime_boot_turn_leave(struct nlr_runtime *r)
{
    if (!r)
        return;
    /* A boot program started during this turn: the hold begins now, not a
     * turn later -- the rest of the GUI's turn would draw and switch the
     * layer's buffers under the program. */
    if (__atomic_load_n(&r->autoload.boot_hold, __ATOMIC_ACQUIRE))
        boot_hold_wait(r);
    boot_veil_leave(r);
    /* The screen came back from a program (ABI 7): the GUI draws all of it
     * again, here on its own task, before it draws anything else. */
    if (__atomic_exchange_n(&r->plat.redraw, 0u, __ATOMIC_ACQ_REL)) {
        const struct nlr_platform_services *pl = r->load.svc ? r->load.svc->platform : 0;
        if (pl && pl->gui_redraw)
            pl->gui_redraw();
    }
}

/* Whether a hold point lets this turn run without the hold: a shell's
 * menu exit is still settling (plat.leaving, set only when the profile
 * declares hold when = "settle"). The turn is noted, so the stock GUI's
 * next commit settles the exit (nlr_runtime_gui_committed). Every hold
 * point -- the boot checkpoint and each GUI turn -- asks the same. */
static int hold_settling(struct nlr_runtime *r)
{
    if (!__atomic_load_n(&r->plat.leaving, __ATOMIC_ACQUIRE))
        return 0;
    __atomic_store_n(&r->plat.turned, 1u, __ATOMIC_RELEASE);
    return 1;
}

/* A GUI turn (services.platform.gui_turns): the generated entry at one of
 * the stock GUI services' loop calls comes here with its index. The turn
 * is the boot checkpoint's without the card: the hold's two halves around
 * the stock call, so a boot program or shell that owns the screen keeps
 * this service's task here before it reads its events, draws or commits --
 * unless a shell's menu exit is still settling (hold_settling).
 * The stock call is made either way and its result returned unchanged. A
 * turn never makes the runtime: until the loader's worker exists there is
 * nothing to hold for. */
void *nlr_runtime_gui_turn(struct nlr_runtime *r, void *(*callee)(void))
{
    if (!r)
        return callee();
    if (hold_settling(r))
        return callee();
    (void)nlr_runtime_boot_turn_enter(r);
    void *original = callee();
    nlr_runtime_boot_turn_leave(r);
    return original;
}

void *nlr_platform_gui_turn(uint32_t index)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    if (!pl || index >= pl->gui_turn_count || !pl->gui_turns[index].callee)
        return 0; /* never: the build points only declared turns here */
    return nlr_runtime_gui_turn(nlr_runtime_find(&nlr_services, 0),
                                pl->gui_turns[index].callee);
}

void nlr_runtime_gui_committed(struct nlr_runtime *r)
{
    /* A commit before any hold point ran is still the menu's own. */
    if (r && __atomic_load_n(&r->plat.leaving, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&r->plat.turned, __ATOMIC_ACQUIRE))
        __atomic_store_n(&r->plat.leaving, 0u, __ATOMIC_RELEASE);
}

void nlr_runtime_commit_seen(struct nlr_runtime *r, int32_t result)
{
    if (!r)
        return;
#if NLR_HAS_GRAPHICS
    if (nlr_native_graphics_commit_seen(&r->native_graphics, result))
        return;
#endif
    if (result & 1)
        nlr_runtime_gui_committed(r);
}

/* The commit observer (services.platform.commit): each declared stock
 * commit call comes here. The stock call is made whatever the loader's
 * state and its result returned unchanged; the call never makes the
 * runtime. */
int32_t nlr_platform_gui_commit(uint32_t mask, void *request)
{
    const struct nlr_platform_services *pl = nlr_services.platform;
    if (!pl || !pl->commit)
        return 0; /* never: the build points only a declared commit here */
    int32_t result = pl->commit(mask, request);
    nlr_runtime_commit_seen(nlr_runtime_find(&nlr_services, 0), result);
    return result;
}

void nlr_runtime_boot_checkpoint(struct nlr_runtime *r,
                                 const struct nlr_card_store *store)
{
    if (!r)
        return;
    if (hold_settling(r)) {
        /* the menu's exit is still settling: the card is driven as on any
         * turn without a hold, and the hold's halves are left out */
        boot_step(r, store);
        nlr_runtime_boot_mark_settle(r);
        return;
    }
    if (!nlr_runtime_boot_turn_enter(r)) {
        boot_step(r, store);
        nlr_runtime_boot_mark_settle(r);
    }
    nlr_runtime_boot_turn_leave(r);
}

/* Whether the profile names a key for the escape at all: without one the
 * held set is always empty and there is nothing to wait for. */
static int escape_declared(const struct nlr_runtime *r)
{
    const struct nlr_program_services *ps = r->load.svc->program;
    for (uint32_t i = 0; ps && i < NLR_PROGRAM_KEYS; i++)
        if ((NLR_AUTOLOAD_ESCAPE_KEYS & (1u << i)) && ps->keys[i].mask)
            return 1;
    return 0;
}

/* The escape as boot_step reads it, for the native card's checkpoint: the
 * buttons first, and only once the hook that sees every scan is in -- until
 * the input task has filled its callback slot, the scan object may hold no
 * scan yet and DISP held through power-on would read as released. On the
 * Z 6III that hook is the program input slot's; on a body whose one scan
 * callback carries the exit service (the Z8), it is that callback, put in
 * here once the stock occupant is there, as runtime creation would have. */
/* The escape as a hold at power-on: looked at on the
 * boot checkpoint's turns, and latched only within NLR_BOOT_ESCAPE_MS of
 * its first look. A press after that -- with no card in, while the boot
 * still asks for one -- is not the escape: latched, it kept the loader off
 * for the rest of the boot, even once a card was put in. Later, the pass
 * still honours a key held at the moment it checks (the guard). 1 when
 * latched. */
static int boot_escape_latch(struct nlr_runtime *r)
{
    if (__atomic_load_n(&r->autoload.boot_escape, __ATOMIC_ACQUIRE))
        return 1;
    uint32_t now = nlr_clock_ms();
    if (!r->autoload.boot_escape_seen) {
        r->autoload.boot_escape_from = now;
        r->autoload.boot_escape_seen = 1;
    }
    if (now - r->autoload.boot_escape_from > NLR_BOOT_ESCAPE_MS ||
        !(nlr_program_keys_now() & NLR_AUTOLOAD_ESCAPE_KEYS))
        return 0;
    __atomic_store_n(&r->autoload.boot_escape, 1u, __ATOMIC_RELEASE);
    return 1;
}

int nlr_runtime_on_worker(const struct nlr_runtime *r)
{
    if (!r)
        return 0;
    uint64_t here = (uint64_t)(uintptr_t)__builtin_frame_address(0);
    uint64_t hi = __atomic_load_n(&r->load.worker_stack_hi, __ATOMIC_ACQUIRE);
    return hi && here < hi && here >= r->load.worker_stack_lo;
}

int nlr_runtime_on_loader_task(const struct nlr_runtime *r)
{
    if (!r)
        return 0;
    if (nlr_runtime_on_worker(r))
        return 1;
    uint64_t here = (uint64_t)(uintptr_t)__builtin_frame_address(0);
    uint64_t hi;
    for (uint32_t n = 0; n < NLR_PLATFORM_TASKS; n++) {
        hi = __atomic_load_n(&r->plat.task_stack[n].hi, __ATOMIC_ACQUIRE);
        if (hi && here < hi && here >= r->plat.task_stack[n].lo)
            return 1;
    }
    return 0;
}

int nlr_runtime_boot_escape(struct nlr_runtime *r)
{
    if (!r || !r->load.svc)
        return NLR_NOT_READY;
    if (__atomic_load_n(&r->autoload.boot_escape, __ATOMIC_ACQUIRE))
        return NLR_DISABLED;
    if (!escape_declared(r))
        return NLR_OK;
    nlr_program_io_install(r);
    if (nlr_program_io_wanted()) {
        if (!r->io.hooked)
            return NLR_NOT_READY;
    } else {
        const struct nlr_program_services *ps = r->load.svc->program;
        struct nlr_scan_view view;
        if (!ps->input_object &&
            (!nlr_platform_scan_view(r->load.svc, &view) || !view.object))
            return NLR_OK; /* no object to read: the escape reads nothing */
        if (exit_services_ready(r->load.svc->exit) && !ps->input_slot) {
            exit_install(r);
            if (!r->exit_original_input)
                return NLR_NOT_READY;
        }
    }
    return boot_escape_latch(r) ? NLR_DISABLED : NLR_OK;
}

/* How many turns of the live-view GUI a boot waits for a card to show its
 * NLOADER directory before it starts the release bundle's boot program on
 * its own: at ~17 turns a second, about four seconds -- the asks fall on
 * the power-of-two turns, so it is the ask at turn 64. A card that is
 * mounted and has no loader directory needs no wait. */
#define NLR_BUNDLE_WAIT_TURNS 64u

static int bundle_boot_due(const struct nlr_runtime *r, uint32_t turn, int mounted)
{
    const struct nlr_platform_services *pl = r->load.svc ? r->load.svc->platform : 0;
    uint32_t bytes = 0;
    if (!bundle_file(r, "BOOT", &bytes))
        return 0;
    if (turn >= NLR_BUNDLE_WAIT_TURNS || mounted)
        return 1;
    int slot = nlr_platform_card_slot(pl, NLR_PROGRAM_ROOT[0]);
    return slot >= 0 && nlr_platform_card(pl, (uint32_t)slot) == 1;
}

/* No card, or a card without the loader's directory: the release bundle's
 * boot program starts the way a card's would -- the directory read (the
 * bundle's programs), BOOT (the bundle's default), the GUI layer kept
 * blank while it loads and the stock GUI held once it runs -- but with no
 * card there is nowhere to keep BOOTRUN: a program that crashes the camera
 * is not skipped by itself at the next start. DISP held at power-on skips
 * it, as it skips every boot pass, and SAFE_MODE on a card still wins. */
/* NLR_BUSY: DISP is down this moment but was not held at power-on (not
 * latched) -- not the escape, and not the moment to start either: the
 * next ask decides again. Otherwise the start has been decided. */
static int boot_bundle(struct nlr_runtime *r)
{
    const struct nlr_services *svc = r->load.svc;
    if (__atomic_load_n(&r->autoload.boot_escape, __ATOMIC_ACQUIRE)) {
        r->autoload.boot_result = NLR_DISABLED;
        JLOG(r, "bundle: DISP held at power-on, nothing started");
        return NLR_OK;
    }
    if (nlr_program_keys_now() & NLR_AUTOLOAD_ESCAPE_KEYS) {
        JLOG(r, "bundle: DISP down now, the next ask decides");
        return NLR_BUSY;
    }
    /* SAFE_MODE as the card's presence store answers it (load.c, the same
     * on every body): there, nothing starts; a card that answers for
     * nothing holds none; a card request held for a moment is asked again
     * at the next ask; any other answer starts nothing either. */
    const struct nlr_card_store *presence = nlr_card_presence_store(svc);
    uint32_t present = UINT32_MAX;
    int32_t guard = presence && presence->probe_beside
        ? presence->probe_beside(NLR_SAFE_MODE_PATH, 0, &present) : NLR_NOT_READY;
    if (guard == NLR_BUSY)
        return NLR_BUSY;
    if (guard == NLR_OK && present == 1u) {
        r->autoload.boot_result = NLR_DISABLED;
        return NLR_OK;
    }
    if (guard != NLR_NOT_READY && !(guard == NLR_OK && present == 0u)) {
        r->autoload.boot_result = guard == NLR_OK ? NLR_IO : guard;
        JLOG(r, "bundle: SAFE_MODE unreadable (%d), nothing started", r->autoload.boot_result);
        return NLR_OK;
    }
    if (nlr_runtime_read_directory(r) != NLR_OK) {
        r->autoload.boot_result = r->directory_result;
        return NLR_OK;
    }
    boot_read(r);
    int32_t index = r->autoload.boot_index;
    if (index < 0)
        return NLR_OK;
    r->autoload.boot_index = -1;
    __atomic_store_n(&r->autoload.boot_bundled, 1u, __ATOMIC_RELEASE);
    JLOG(r, "bundle: the boot program is entry %d", index);
    __atomic_store_n(&r->load.chunk_read,
                     r->load.in_runtime ? boot_load_chunk : 0, __ATOMIC_RELEASE);
    r->autoload.boot_result = start_program(r, (uint32_t)index, 2);
    __atomic_store_n(&r->load.chunk_read, 0, __ATOMIC_RELEASE);
    if (r->autoload.boot_result == NLR_OK) {
        __atomic_store_n(&r->plat.shell, 1u, __ATOMIC_RELEASE);
        __atomic_store_n(&r->autoload.boot_hold, 1u, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&r->autoload.boot_decided, 1u, __ATOMIC_RELEASE);
    return NLR_OK;
}

static void boot_step(struct nlr_runtime *r, const struct nlr_card_store *store)
{
    if (!r || __atomic_load_n(&r->autoload.boot_done, __ATOMIC_ACQUIRE))
        return;
    /* The buttons first. The escape is read as the pass opens, and until
     * the input task has filled its callback slot -- which is when the
     * hook goes in -- its scan object may hold no scan yet: DISP held
     * through power-on would read as released. */
    nlr_program_io_install(r);
    if (nlr_program_io_wanted() && !r->io.hooked)
        return;
    /* A page visit opened it first; the pass is that visit's. */
    if (r->autoload.phase != NLR_AUTOLOAD_NEW) {
        __atomic_store_n(&r->autoload.boot_done, 1u, __ATOMIC_RELEASE);
        return;
    }
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return;
    uint32_t turn = ++r->autoload.boot_turns;
    if (turn & (turn - 1u))
        return;
    if (turn == 1u)
        JLOG(r, "checkpoint: first turn");
    if (!__atomic_load_n(&r->autoload.boot_escape, __ATOMIC_ACQUIRE) &&
        boot_escape_latch(r))
        JLOG(r, "checkpoint: DISP held at turn %u", turn);
    /* The card is ready when its MANIFEST opens. Nothing else is asked
     * before that: a card still mounting answers SAFE_MODE and the marker
     * with an IO error, which would stop this boot's pass for good. */
    uint32_t present = 0;
    int asked = store && store->probe ? store->probe(NLR_MANIFEST_PATH, &present)
                                      : NLR_NOT_READY;
    /* Programs may describe themselves, so a card
     * with no MANIFEST can still ask for something at boot: BOOT or
     * ENABLED opening says the same about the card as MANIFEST would. */
    if (asked == NLR_OK && !present)
        asked = store->probe(NLR_BOOT_PATH, &present);
    if (asked == NLR_OK && !present)
        asked = store->probe(NLR_ENABLED_PATH, &present);
    JLOG(r, "checkpoint: turn %u asks the card: %d, present %u", turn, asked, present);
    if (asked != NLR_OK || !present) {
        /* No loader directory on a card yet. The release bundle's boot
         * program goes ahead once a card shows it has none, or none has
         * come after a few seconds. */
        if (bundle_boot_due(r, turn, 0)) {
            __atomic_store_n(&r->autoload.boot_done, 1u, __ATOMIC_RELEASE);
            /* DISP down this moment: the next ask decides again */
            if (boot_bundle(r) == NLR_BUSY)
                __atomic_store_n(&r->autoload.boot_done, 0u, __ATOMIC_RELEASE);
            return;
        }
        if (!store || !store->probe ||
            ++r->autoload.boot_asks >= NLR_BOOT_CARD_ASKS)
            __atomic_store_n(&r->autoload.boot_done, 1u, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&r->autoload.boot_done, 1u, __ATOMIC_RELEASE);
    if (!r->autoload.store)
        r->autoload.store = store;
    /* Busy: a page visit is opening it this moment and carries it on. */
    JLOG(r, "pass begins at turn %u", turn);
    int begun = nlr_runtime_autoload_begin(r, r->autoload.store);
    if (begun != NLR_OK)
        JLOG(r, "pass begin: %d", begun);
    if (begun == NLR_BUSY)
        return;
    nlr_runtime_autoload_continue(r);
}

/* The same schedule for the native card's checkpoint, which opens the pass
 * itself (native_card.c menu_turn) and asks the card with a snapshot of
 * STATE.NLS: boot_step's turns, asks and end, without its probes. */
int nlr_runtime_boot_ask_due(struct nlr_runtime *r, uint32_t now_ms)
{
    if (!r || __atomic_load_n(&r->autoload.boot_done, __ATOMIC_ACQUIRE))
        return 0;
    uint32_t last = r->autoload.boot_turns;
    if (!last) {
        r->autoload.boot_first_ms = now_ms;
        r->autoload.boot_turns = 1;
        return 1;
    }
    uint32_t turn = 1u + (now_ms - r->autoload.boot_first_ms) / NLR_BOOT_TURN_MS;
    uint32_t next = 1;
    while (next <= last && next < 0x80000000u)
        next <<= 1;
    if (turn < next)
        return 0;
    r->autoload.boot_turns = turn;
    return 1;
}

void nlr_runtime_boot_no_card(struct nlr_runtime *r, int mounted)
{
    if (!r || __atomic_load_n(&r->autoload.boot_done, __ATOMIC_ACQUIRE))
        return;
    uint32_t turn = r->autoload.boot_turns;
    JLOG(r, "checkpoint: turn %u, %s", turn,
         mounted ? "the card has no loader directory" : "no card");
    if (!__atomic_load_n(&r->autoload.boot_decided, __ATOMIC_ACQUIRE) &&
        bundle_boot_due(r, turn, mounted)) {
        __atomic_store_n(&r->autoload.boot_done, 1u, __ATOMIC_RELEASE);
        /* DISP down this moment: the next ask decides again */
        if (boot_bundle(r) == NLR_BUSY)
            __atomic_store_n(&r->autoload.boot_done, 0u, __ATOMIC_RELEASE);
        return;
    }
    /* The Z 6III's last ask falls on turn 2048, its twelfth; turns far
     * apart reach that turn with fewer asks, and it ends there too. */
    if (mounted || ++r->autoload.boot_asks >= NLR_BOOT_CARD_ASKS ||
        turn >= 1u << (NLR_BOOT_CARD_ASKS - 1u))
        __atomic_store_n(&r->autoload.boot_done, 1u, __ATOMIC_RELEASE);
}

void nlr_runtime_boot_ask_again(struct nlr_runtime *r)
{
    if (!r || r->autoload.phase != NLR_AUTOLOAD_NEW ||
        !__atomic_load_n(&r->autoload.boot_done, __ATOMIC_ACQUIRE))
        return;
    r->autoload.boot_turns = 0;
    r->autoload.boot_first_ms = 0;
    r->autoload.boot_asks = NLR_BOOT_CARD_ASKS - 1u;
    __atomic_store_n(&r->autoload.boot_done, 0u, __ATOMIC_RELEASE);
}

int nlr_runtime_autoload_interrupt(struct nlr_runtime *r, int32_t reason)
{
    if (!r)
        return NLR_NOT_READY;
    if (!autoload_active(r))
        return r->autoload.result;
    return autoload_stop(r, reason == NLR_OK ? NLR_AUTOLOAD_INTERRUPTED : reason);
}
int nlr_runtime_autoload_recover(struct nlr_runtime *r)
{
    if (!r || !r->load.svc)
        return NLR_NOT_READY;
    int result;
    if (autoload_active(r) ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        result = NLR_BUSY;
    else if (runtime_uncertain(r))
        result = uncertain_result(r);
    else if (runtime_menu_pending(r))
        result = NLR_BUSY;
    else if (r->load.program.code_allocation || r->load.program.data_allocation ||
             r->load.probe.allocation)
        result = NLR_EXEC_RESTORE;
    else if (r->autoload.phase != NLR_AUTOLOAD_STOPPED)
        result = NLR_REFUSED;
    else if (!r->autoload.store || (!r->autoload.store->remove
#if NLR_HAS_NATIVE_CARD
                                   && !r->load.svc->native_card
#endif
                                   ))
        result = NLR_NOT_READY;
    else {
        /* SAFE_MODE is always the first card operation of this explicit
         * action. No resident, enabled byte or publication is touched. */
        result = runtime_autoload_guard(r,
                                  r->autoload.recovery_armed ? 0u : 1u);
        if (result == NLR_OK && !r->autoload.recovery_armed)
#if NLR_HAS_NATIVE_CARD
            result = r->load.svc->native_card ? nlr_native_card_pending(r, 0) :
#else
            result =
#endif
                r->autoload.store->remove(NLR_AUTOLOAD_PENDING_PATH);
        if (result == NLR_OK) {
            r->autoload.recovery_armed = 1;
            /* Deliberately remain STOPPED, including if no entry ran.
             * Re-entry, begin and step may not replay anything this boot. */
        }
    }
    return r->autoload.recovery_result = result;
}

static int directory_id_matches(const struct nlr_runtime *r, uint32_t index,
                                  const char *id)
{
    const struct nlr_manifest_entry *entry = &r->directory.entries[index];
    for (uint32_t n = 0; n < entry->id_len; n++)
        if (!id[n] || id[n] != (char)r->directory.buffer[entry->id_off + n])
            return 0;
    return id[entry->id_len] == 0;
}

uint32_t nlr_runtime_extension_status(const struct nlr_runtime *r,
                                      uint32_t index)
{
    if (!r || index >= r->directory.count)
        return NLR_EXTENSION_NOT_EXECUTED;
    /* The idle acquire is the publication boundary for worker-owned data. */
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0) {
        for (uint32_t n = 0; n < NLR_RESIDENT_MAX; n++) {
            const struct nlr_program_record *record = &r->resident[n];
            if (!record->used || record->kind != NLR_KIND_RESOURCE_EXTENSION ||
                !directory_id_matches(r, index, record->id))
                continue;
            if (record->failed || record->uncertain)
                return NLR_EXTENSION_PARTIAL;
            for (uint32_t j = 0; j < NLR_RESIDENT_MAX; j++)
                if (r->menu_registration[j].state == NLR_MENU_REG_PENDING &&
                    same_id(r->menu_registration[j].owner, record->id))
                    return NLR_EXTENSION_INITIALIZING;
            return NLR_EXTENSION_LOADED;
        }
    }
    for (uint32_t n = 0; n < r->autoload.enabled.count; n++)
        if (directory_id_matches(r, index, r->autoload.enabled.id[n]))
            return r->autoload.item[n];
    return NLR_EXTENSION_NOT_EXECUTED;
}


int nlr_runtime_save_enabled(struct nlr_runtime *r,
                             const struct nlr_enabled *desired,
                             const struct nlr_card_store *store)
{
    if (!r || !r->load.svc || r->directory_result != NLR_OK)
        return NLR_NOT_READY;
    if (autoload_active(r) ||
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return r->enabled_save_result = NLR_BUSY;
    if (runtime_uncertain(r))
        return r->enabled_save_result = uncertain_result(r);
    if (runtime_menu_pending(r))
        return r->enabled_save_result = NLR_BUSY;
#if NLR_HAS_NATIVE_CARD
    if (r->load.svc->native_card)
        return r->enabled_save_result = nlr_native_card_save_enabled(r, desired);
#endif
    uint32_t present = 0;
    int result = card_probe(store, NLR_SAFE_MODE_PATH, &present);
    if (result == NLR_OK && present)
        result = NLR_DISABLED;
    if (result == NLR_OK)
        result = nlr_enabled_save(&r->saved_enabled, desired, &r->directory,
                                  store, r->load.arena, r->load.capacity);
    return r->enabled_save_result = result;
}

/* ---- program settings ---------------------------------------------------- */

static uint8_t *settings_bytes(const struct nlr_runtime *r)
{
    uintptr_t at = (uintptr_t)r->settings.raw;
    return (uint8_t *)((at + NLR_CACHE_LINE - 1u) & ~(uintptr_t)(NLR_CACHE_LINE - 1u));
}

void nlr_settings_load(struct nlr_runtime *r)
{
    if (!r || r->checked >= r->directory.count ||
        r->settings.entry == r->checked + 1u)
        return;
    r->settings.entry = r->checked + 1u;
    r->settings.count = 0;
    r->settings.bytes = 0;
    r->settings.save_result = NLR_NOT_READY;
    /* <name>.SET beside the program: its path with the extension swapped. */
    uint32_t n = 0;
    while (n < NLR_PATH_BYTES && r->path[n])
        n++;
    if (n < 5 || n >= NLR_PATH_BYTES || r->path[n - 4] != '.')
        return;
    for (uint32_t k = 0; k <= n; k++)
        r->settings.path[k] = r->path[k];
    r->settings.path[n - 3] = 'S';
    r->settings.path[n - 2] = 'E';
    r->settings.path[n - 1] = 'T';
    uint8_t *b = settings_bytes(r);
    uint32_t bytes = 0;
    if (nlr_card_read(r->load.svc, r->settings.path, b, NLR_SETTINGS_BYTES,
                      &bytes, 0) != NLR_OK)
        return;
    uint32_t count = 0, at = 0;
    while (at < bytes) {
        uint32_t start = at, bars = 0, commas = 0;
        if (count == NLR_SETTINGS_MAX)
            return;
        for (; at < bytes && b[at] != '\n'; at++) {
            if (b[at] < 0x20 || b[at] > 0x7e)
                return;
            if (b[at] == '|')
                bars++;
            else if (b[at] == ',' && bars == 2)
                commas++;
        }
        /* key|label|choices|D and the newline: the digit names a choice. */
        if (at >= bytes || bars != 3 || at - start < 7 || b[at - 2] != '|' ||
            b[at - 1] < '0' || b[at - 1] > '9' ||
            (uint32_t)(b[at - 1] - '0') > commas || b[start] == '|')
            return;
        r->settings.line[count++] = (uint16_t)start;
        at++;
    }
    r->settings.bytes = bytes;
    r->settings.count = count;
}

int nlr_settings_field(const struct nlr_runtime *r, uint32_t setting,
                       uint32_t field, const char **text, uint32_t *length)
{
    if (!r || setting >= r->settings.count || field > 3)
        return 0;
    const uint8_t *b = settings_bytes(r);
    uint32_t at = r->settings.line[setting], from = at, f = 0;
    for (; at < r->settings.bytes && b[at] != '\n'; at++) {
        if (b[at] != '|')
            continue;
        if (f == field)
            break;
        f++;
        from = at + 1;
    }
    if (f != field)
        return 0;
    *text = (const char *)b + from;
    *length = at - from;
    return 1;
}

uint32_t nlr_settings_choices(const struct nlr_runtime *r, uint32_t setting)
{
    const char *t;
    uint32_t n, count = 1;
    if (!nlr_settings_field(r, setting, 2, &t, &n))
        return 0;
    for (uint32_t k = 0; k < n; k++)
        count += t[k] == ',';
    return count;
}

int nlr_settings_choice(const struct nlr_runtime *r, uint32_t setting,
                        uint32_t choice, const char **text, uint32_t *length)
{
    const char *t;
    uint32_t n, from = 0, index = 0;
    if (!nlr_settings_field(r, setting, 2, &t, &n))
        return 0;
    for (uint32_t k = 0; k <= n; k++) {
        if (k < n && t[k] != ',')
            continue;
        if (index++ == choice) {
            *text = t + from;
            *length = k - from;
            return 1;
        }
        from = k + 1;
    }
    return 0;
}

uint32_t nlr_settings_value(const struct nlr_runtime *r, uint32_t setting)
{
    const char *t;
    uint32_t n;
    return nlr_settings_field(r, setting, 3, &t, &n) && n == 1 ? (uint32_t)(t[0] - '0') : 0;
}

int32_t nlr_settings_find(const struct nlr_runtime *r, const char *key)
{
    for (uint32_t i = 0; key && r && i < r->settings.count; i++) {
        const char *t;
        uint32_t n, k = 0;
        if (!nlr_settings_field(r, i, 0, &t, &n))
            continue;
        while (k < n && key[k] == t[k])
            k++;
        if (k == n && !key[k])
            return (int32_t)nlr_settings_value(r, i);
    }
    return -1;
}

int nlr_settings_set(struct nlr_runtime *r, uint32_t setting, uint32_t value)
{
    const char *t;
    uint32_t n;
    if (!r || !r->load.svc)
        return NLR_NOT_READY;
    if (!nlr_settings_field(r, setting, 3, &t, &n) || n != 1 ||
        value >= nlr_settings_choices(r, setting) || value > 9)
        return NLR_BOUNDS;
    /* A write reply and close alone do not establish a durable save. The
     * current setting path has no verified filesystem/device sync and
     * independent readback, so refuse before any write or cache mutation. */
    return NLR_NOT_READY;
}
