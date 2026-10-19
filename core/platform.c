#include "nlr/platform.h"

#include "nlr/services.h"

_Static_assert(sizeof(struct nlr_event) == 16, "event ABI");
_Static_assert(sizeof(struct nlr_rect) == 8, "rect ABI");
_Static_assert(sizeof(struct nlr_prop_info) == 8, "prop info ABI");
_Static_assert((NLR_PLATFORM_EVENTS & (NLR_PLATFORM_EVENTS - 1u)) == 0,
               "event ring capacity is a power of two");
_Static_assert(NLR_CTL_COUNT == 64, "controls fit one 64-bit word");

#define CTL_BIT(c) (UINT64_C(1) << (c))
/* The controls a program takes by default but shares with the camera: the
 * shutter, so focus and capture go on under a replacement UI. */
#define SHARED_BY_DEFAULT (CTL_BIT(NLR_CTL_HALF) | CTL_BIT(NLR_CTL_FULL))

static uint32_t rd16(const volatile uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8;
}

static uint32_t rd32(const volatile uint8_t *p)
{
    return rd16(p) | rd16(p + 2) << 16;
}

static uint64_t rd64(const volatile uint8_t *p)
{
    return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32;
}

void nlr_platform_reset(struct nlr_platform *p)
{
    if (!p)
        return;
    for (uint32_t n = 0; n < sizeof *p; n++)
        ((volatile uint8_t *)p)[n] = 0;
}

void nlr_platform_take_input(struct nlr_platform *p, int share_shutter)
{
    if (!p || __atomic_load_n(&p->active, __ATOMIC_ACQUIRE))
        return;
    /* A fresh stream: whatever an earlier owner left is not this one's. */
    __atomic_store_n(&p->head, __atomic_load_n(&p->tail, __ATOMIC_ACQUIRE),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&p->overflow, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&p->route_report, ~UINT64_C(0), __ATOMIC_RELEASE);
    __atomic_store_n(&p->route_hide,
                     share_shutter ? ~SHARED_BY_DEFAULT : ~UINT64_C(0),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&p->active, 1u, __ATOMIC_RELEASE);
}

int nlr_platform_route(struct nlr_platform *p, const uint32_t *ctls,
                       uint32_t count, uint32_t route)
{
    if (!p || (!ctls && count) || count > NLR_CTL_COUNT ||
        route > NLR_ROUTE_BOTH)
        return -NLR_API_EINVAL;
    uint64_t chosen = 0;
    for (uint32_t n = 0; n < count; n++) {
        if (ctls[n] >= NLR_CTL_COUNT)
            return -NLR_API_EINVAL;
        chosen |= CTL_BIT(ctls[n]);
    }
    uint64_t hide = __atomic_load_n(&p->route_hide, __ATOMIC_ACQUIRE);
    uint64_t report = __atomic_load_n(&p->route_report, __ATOMIC_ACQUIRE);
    hide = route == NLR_ROUTE_PROGRAM ? hide | chosen : hide & ~chosen;
    report = route == NLR_ROUTE_CAMERA ? report & ~chosen : report | chosen;
    /* The input task reads both words once per scan; a scan between the
     * two stores sees an intermediate route for one scan, never a torn
     * word. Hiding is narrowed before reporting is widened, so a control
     * leaving the program is never both hidden and unreported. */
    __atomic_store_n(&p->route_hide, hide, __ATOMIC_RELEASE);
    __atomic_store_n(&p->route_report, report, __ATOMIC_RELEASE);
    return 0;
}

uint64_t nlr_platform_held(const struct nlr_platform_services *s,
                           const uint32_t *banks, uint32_t bank_count)
{
    uint64_t held = 0;
    if (!s || !s->controls || !banks)
        return 0;
    for (uint32_t n = 0; n < s->control_count && n < NLR_PLATFORM_CONTROLS_MAX; n++) {
        const struct nlr_platform_control *c = &s->controls[n];
        if (c->ctl < NLR_CTL_DIAL_MAIN && c->bank < bank_count &&
            (banks[c->bank] & c->mask))
            held |= CTL_BIT(c->ctl);
    }
    return held;
}

int nlr_platform_scan_view(const struct nlr_services *svc,
                           struct nlr_scan_view *out)
{
    if (!svc || !out)
        return 0;
    const struct nlr_platform_services *s = svc->platform;
    const struct nlr_program_services *ps = svc->program;
    if (s && s->scan) {
        const struct nlr_platform_scan *scan = s->scan;
        if (!scan->bank_stride || !scan->banks || scan->banks > 4u)
            return 0;
        *out = (struct nlr_scan_view){
            .object = scan->object,
            .bank_base = scan->bank_base,
            .bank_stride = scan->bank_stride,
            .banks = scan->banks,
            .keep_bank = scan->keep_bank,
            .keep_mask = scan->keep_mask,
            .dial_offset = scan->dial_offset,
            .dial_bytes = scan->dial_bytes,
            .activity = scan->activity,
        };
        return 1;
    }
    if (ps && ps->input_slot) {
        *out = (struct nlr_scan_view){
            .object = ps->input_object,
            .bank_base = ps->bank_base,
            .bank_stride = ps->bank_stride,
            .banks = ps->banks,
            .keep_bank = ps->keep_bank,
            .keep_mask = ps->keep_mask,
            .dial_offset = ps->dial_offset,
            .dial_bytes = ps->dial_bytes,
            .activity = ps->activity,
        };
        return 1;
    }
    return 0;
}

int nlr_platform_input_pass(struct nlr_platform *p,
                            const struct nlr_platform_services *s,
                            const struct nlr_scan_view *view, void *object,
                            int capture, uint32_t now)
{
    if (!p || !view || !object || !view->bank_stride ||
        !view->banks || view->banks > 4u)
        return -NLR_API_EINVAL;
    uint8_t *base = (uint8_t *)object + view->bank_base;
    uint32_t current[4] = {0, 0, 0, 0};
    for (uint32_t b = 0; b < view->banks; b++)
        current[b] = nlr_le32(base + b * view->bank_stride);
    int32_t dials[8] = {0};
    uint32_t dial_words = view->dial_bytes / 4u;
    for (uint32_t w = 0; w < dial_words && w < 8u; w++)
        dials[w] = (int32_t)nlr_le32((const uint8_t *)object + view->dial_offset + 4u * w);
    if (dial_words > 8u)
        dial_words = 8u;
    uint64_t held = nlr_platform_held(s, current, view->banks);
    nlr_platform_scan(p, s, held, dials, dial_words, now);
    uint64_t previous_hold = __atomic_load_n(&p->hold, __ATOMIC_ACQUIRE);
    if (capture) {
        /* Every control the program does not route to the camera is hidden
         * from it, and a dial word stays the camera's only when the profile
         * names it and the program routed that dial to the camera too. */
        uint32_t masks[4];
        int routed = __atomic_load_n(&p->active, __ATOMIC_ACQUIRE) && s;
        uint64_t hide = __atomic_load_n(&p->route_hide, __ATOMIC_ACQUIRE);
        if (routed)
            nlr_platform_hide_masks(s, hide, view->keep_bank, view->keep_mask,
                                    masks, view->banks);
        else
            for (uint32_t b = 0; b < view->banks; b++)
                masks[b] = b == view->keep_bank ? ~view->keep_mask : ~0u;
        uint32_t moved = 0;
        for (uint32_t b = 0; b < view->banks; b++)
            moved |= nlr_le32(base + b * view->bank_stride + 8u) & masks[b];
        uint8_t *dial = (uint8_t *)object + view->dial_offset;
        for (uint32_t w = 0; w < dial_words; w++) {
            int keep_dial = 0;
            for (uint32_t d = 0; routed && d < NLR_PLATFORM_DIALS; d++)
                if ((s->dial_word[d] == w + 1u || s->dial_alt[d] == w + 1u) &&
                    !(hide & CTL_BIT(NLR_CTL_DIAL_MAIN + d)))
                    keep_dial = 1;
            if (keep_dial)
                continue;
            if (dials[w])
                moved = 1;
            for (uint32_t n = 0; n < 4u; n++)
                dial[4u * w + n] = 0;
        }
        for (uint32_t n = dial_words * 4u; n < view->dial_bytes; n++)
            dial[n] = 0;
        if (moved && view->activity)
            view->activity();
        for (uint32_t b = 0; b < view->banks; b++) {
            uint32_t *words = (uint32_t *)(base + b * view->bank_stride);
            for (uint32_t i = 0; i < 5; i++)
                words[i] &= ~masks[b];
        }
        __atomic_store_n(&p->hold, routed ? held & hide : 0, __ATOMIC_RELEASE);
    } else if (previous_hold) {
        /* A held control the program ended with stays hidden until the user
         * releases it, so the camera never sees a press it never saw go
         * down. */
        uint64_t still = previous_hold & held;
        __atomic_store_n(&p->hold, still, __ATOMIC_RELEASE);
        if (s && s->controls)
            for (uint32_t n = 0; n < s->control_count && n < NLR_PLATFORM_CONTROLS_MAX; n++) {
                const struct nlr_platform_control *c = &s->controls[n];
                if (c->ctl >= NLR_CTL_DIAL_MAIN || c->bank >= view->banks ||
                    !(still & CTL_BIT(c->ctl)))
                    continue;
                uint32_t *words = (uint32_t *)(base + c->bank * view->bank_stride);
                for (uint32_t i = 0; i < 5; i++)
                    words[i] &= ~c->mask;
            }
    }
    return 0;
}

void nlr_platform_hide_masks(const struct nlr_platform_services *s,
                             uint64_t route_hide, uint32_t keep_bank,
                             uint32_t keep, uint32_t *masks,
                             uint32_t bank_count)
{
    if (!masks)
        return;
    for (uint32_t b = 0; b < bank_count; b++)
        masks[b] = ~0u;
    /* A bit no control names stays hidden: the camera reacting to a button
     * the program cannot even name is what taking the input must prevent. */
    if (s && s->controls)
        for (uint32_t n = 0; n < s->control_count && n < NLR_PLATFORM_CONTROLS_MAX; n++) {
            const struct nlr_platform_control *c = &s->controls[n];
            if (c->ctl < NLR_CTL_DIAL_MAIN && c->bank < bank_count &&
                !(route_hide & CTL_BIT(c->ctl)))
                masks[c->bank] &= ~c->mask;
        }
    if (keep_bank < bank_count)
        masks[keep_bank] &= ~keep;
}

int nlr_platform_push(struct nlr_platform *p, const struct nlr_event *ev)
{
    if (!p || !ev)
        return -NLR_API_EINVAL;
    uint32_t tail = __atomic_load_n(&p->tail, __ATOMIC_RELAXED);
    uint32_t head = __atomic_load_n(&p->head, __ATOMIC_ACQUIRE);
    if (tail - head >= NLR_PLATFORM_EVENTS) {
        __atomic_store_n(&p->overflow, 1u, __ATOMIC_RELEASE);
        return -NLR_API_EOVERFLOW;
    }
    p->events[tail & (NLR_PLATFORM_EVENTS - 1u)] = *ev;
    __atomic_store_n(&p->tail, tail + 1u, __ATOMIC_RELEASE);
    return 0;
}

int nlr_platform_pop(struct nlr_platform *p, struct nlr_event *ev)
{
    if (!p || !ev)
        return -NLR_API_EINVAL;
    if (__atomic_exchange_n(&p->overflow, 0u, __ATOMIC_ACQ_REL)) {
        /* What is queued is no longer a complete history: drop it and say
         * so once, so the program reads the state afresh. */
        __atomic_store_n(&p->head, __atomic_load_n(&p->tail, __ATOMIC_ACQUIRE),
                         __ATOMIC_RELEASE);
        struct nlr_event lost = { .type = NLR_EV_OVERFLOW };
        *ev = lost;
        return 1;
    }
    uint32_t head = __atomic_load_n(&p->head, __ATOMIC_RELAXED);
    if (head == __atomic_load_n(&p->tail, __ATOMIC_ACQUIRE))
        return 0;
    *ev = p->events[head & (NLR_PLATFORM_EVENTS - 1u)];
    __atomic_store_n(&p->head, head + 1u, __ATOMIC_RELEASE);
    return 1;
}

void nlr_platform_scan(struct nlr_platform *p,
                       const struct nlr_platform_services *s, uint64_t held,
                       const int32_t *dials, uint32_t dial_words, uint32_t now)
{
    if (!p)
        return;
    uint64_t before = __atomic_exchange_n(&p->held, held, __ATOMIC_ACQ_REL);
    if (!__atomic_load_n(&p->active, __ATOMIC_ACQUIRE))
        return;
    uint64_t report = __atomic_load_n(&p->route_report, __ATOMIC_ACQUIRE);
    uint64_t changed = (before ^ held) & report;
    for (uint32_t c = 0; changed && c < NLR_CTL_DIAL_MAIN; c++) {
        if (!(changed & CTL_BIT(c)))
            continue;
        changed &= ~CTL_BIT(c);
        struct nlr_event ev = {
            .type = NLR_EV_CONTROL, .code = (uint16_t)c,
            .value = (held & CTL_BIT(c)) ? 1 : 0, .t_ms = now,
        };
        (void)nlr_platform_push(p, &ev);
    }
    if (!s || !dials)
        return;
    for (uint32_t d = 0; d < NLR_PLATFORM_DIALS; d++) {
        uint32_t ctl = NLR_CTL_DIAL_MAIN + d;
        if (!(report & CTL_BIT(ctl)))
            continue;
        int32_t clicks = 0;
        uint32_t word = s->dial_word[d], alt = s->dial_alt[d];
        if (word && word - 1u < dial_words)
            clicks += dials[word - 1u];
        if (alt && alt - 1u < dial_words)
            clicks += dials[alt - 1u];
        if (!clicks)
            continue;
        struct nlr_event ev = {
            .type = NLR_EV_DIAL, .code = (uint16_t)ctl,
            .value = s->dial_sign[d] < 0 ? -clicks : clicks,
            .t_ms = now,
        };
        (void)nlr_platform_push(p, &ev);
    }
}

int nlr_platform_timer_start(struct nlr_platform *p, uint32_t period_ms,
                             uint32_t tag, uint32_t now)
{
    if (!p || !period_ms || period_ms > 0x7fffffffu)
        return -NLR_API_EINVAL;
    for (uint32_t t = 0; t < NLR_TIMERS_MAX; t++)
        if (!p->timers[t].used) {
            p->timers[t].period = period_ms;
            p->timers[t].tag = tag;
            p->timers[t].next = now + period_ms;
            p->timers[t].used = 1;
            return (int)t;
        }
    return -NLR_API_EBUSY;
}

int nlr_platform_timer_stop(struct nlr_platform *p, int32_t timer)
{
    if (!p || timer < 0 || (uint32_t)timer >= NLR_TIMERS_MAX ||
        !p->timers[timer].used)
        return -NLR_API_ENOENT;
    p->timers[timer].used = 0;
    return 0;
}

int nlr_platform_timer_due(struct nlr_platform *p, uint32_t now,
                           struct nlr_event *ev)
{
    if (!p || !ev)
        return 0;
    for (uint32_t t = 0; t < NLR_TIMERS_MAX; t++) {
        if (!p->timers[t].used || (int32_t)(now - p->timers[t].next) < 0)
            continue;
        /* A program that fell behind gets one tick, not a burst. */
        p->timers[t].next += p->timers[t].period;
        if ((int32_t)(now - p->timers[t].next) >= 0)
            p->timers[t].next = now + p->timers[t].period;
        struct nlr_event tick = {
            .type = NLR_EV_TIMER, .code = (uint16_t)t,
            .value = (int32_t)p->timers[t].tag, .t_ms = now,
        };
        *ev = tick;
        return 1;
    }
    return 0;
}

uint32_t nlr_platform_timer_wait(const struct nlr_platform *p, uint32_t now)
{
    uint32_t wait = UINT32_MAX;
    if (!p)
        return wait;
    for (uint32_t t = 0; t < NLR_TIMERS_MAX; t++) {
        if (!p->timers[t].used)
            continue;
        int32_t left = (int32_t)(p->timers[t].next - now);
        uint32_t w = left <= 0 ? 0u : (uint32_t)left;
        if (w < wait)
            wait = w;
    }
    return wait;
}

int nlr_platform_prop(const struct nlr_platform_services *s, uint32_t id,
                      const volatile uint8_t **value, uint32_t *size)
{
    if (!s || !s->prop_groups || !s->prop_items || !s->prop_group_bytes ||
        !s->prop_item_bytes)
        return -NLR_API_ENOSYS;
    if (id > 0xffffu || !value || !size)
        return -NLR_API_EINVAL;
    uint32_t group = id >> 8, item = id & 0xffu;
    if (group >= s->prop_group_count)
        return -NLR_API_ENOENT;
    const volatile uint8_t *g = s->prop_groups + group * s->prop_group_bytes;
    uint32_t first = rd16(g + s->group_first_at);
    if (!rd32(g + s->group_live_at) || item >= rd16(g + s->group_items_at) ||
        first + item >= s->prop_item_count)
        return -NLR_API_ENOENT;
    const volatile uint8_t *record = s->prop_items + (first + item) * s->prop_item_bytes;
    uint32_t bytes = rd32(record + s->item_size_at);
    uint64_t address = rd64(record + s->item_ram_at);
    /* Only what the store's own RAM holds is ever read: a record that
     * points anywhere else is reported missing, not followed. */
    if (!bytes || bytes > NLR_PROP_BYTES_MAX || address < s->prop_ram_lo ||
        address >= s->prop_ram_hi || bytes > s->prop_ram_hi - address)
        return -NLR_API_ENOENT;
    *value = (const volatile uint8_t *)(uintptr_t)address;
    *size = bytes;
    return 0;
}

static void watch_copy(uint8_t *to, const volatile uint8_t *from, uint32_t n)
{
    for (uint32_t k = 0; k < n; k++)
        to[k] = from[k];
}

int nlr_platform_watch(struct nlr_platform *p,
                       const struct nlr_platform_services *s,
                       const uint16_t *ids, uint32_t count)
{
    if (!p || (!ids && count) || count > NLR_WATCH_MAX)
        return -NLR_API_EINVAL;
    const volatile uint8_t *value;
    uint32_t size;
    /* All or nothing: one unknown item refuses the whole set and leaves
     * the previous one in place. */
    for (uint32_t n = 0; n < count; n++) {
        int result = nlr_platform_prop(s, ids[n], &value, &size);
        if (result)
            return result;
    }
    p->watch_count = 0;
    for (uint32_t n = 0; n < count; n++) {
        (void)nlr_platform_prop(s, ids[n], &value, &size);
        uint32_t keep = size < NLR_WATCH_BYTES ? size : NLR_WATCH_BYTES;
        p->watch_id[n] = ids[n];
        p->watch_size[n] = (uint8_t)keep;
        watch_copy(p->watch_value[n], value, keep);
    }
    p->watch_count = count;
    p->watch_due = 0;
    return 0;
}

int nlr_platform_watch_poll(struct nlr_platform *p,
                            const struct nlr_platform_services *s,
                            uint32_t now, struct nlr_event *ev)
{
    if (!p || !ev || !p->watch_count)
        return 0;
    if (p->watch_due && (int32_t)(now - p->watch_due) < 0)
        return 0;
    for (uint32_t n = 0; n < p->watch_count; n++) {
        const volatile uint8_t *value;
        uint32_t size;
        if (nlr_platform_prop(s, p->watch_id[n], &value, &size))
            continue;
        uint32_t keep = p->watch_size[n];
        uint32_t k = 0;
        while (k < keep && value[k] == p->watch_value[n][k])
            k++;
        if (k == keep)
            continue;
        watch_copy(p->watch_value[n], value, keep);
        uint32_t low = 0;
        for (uint32_t b = 0; b < keep && b < 4u; b++)
            low |= (uint32_t)p->watch_value[n][b] << (8u * b);
        struct nlr_event change = {
            .type = NLR_EV_PROP, .code = p->watch_id[n],
            .value = (int32_t)low, .t_ms = now,
        };
        *ev = change;
        /* More may have changed: the next call looks again at once. */
        return 1;
    }
    /* Nothing changed: look again in 20 ms, about a frame of the stock
     * GUI, which is as often as the camera's own display follows. */
    p->watch_due = (now + 20u) | 1u;
    return 0;
}

uint32_t nlr_platform_caps(const struct nlr_services *svc)
{
    uint32_t caps = 0;
    const struct nlr_platform_services *s = svc ? svc->platform : 0;
    const struct nlr_program_services *ps = svc ? svc->program : 0;
    if (!s)
        return 0;
    /* Family B needs a carrier that actually scans: the program input slot,
     * or the exit callback (a body whose input task registers one callback
     * only). The scan view tells where the controls and dials live. */
    const int carrier = (ps && ps->input_slot) ||
                        (svc->exit && svc->exit->input_callback);
    struct nlr_scan_view view;
    const int scan = carrier && nlr_platform_scan_view(svc, &view);
    if (s->controls && s->control_count && scan)
        caps |= NLR_CAP_CONTROLS;
    for (uint32_t d = 0; d < NLR_PLATFORM_DIALS; d++)
        if (s->dial_word[d] && scan && view.dial_bytes)
            caps |= NLR_CAP_DIALS;
    if (ps && ps->scanout_colour && ps->scanout_alpha)
        caps |= NLR_CAP_SCREEN;
    if (s->prop_groups && s->prop_items)
        caps |= NLR_CAP_PROPS;
    if (s->prop_groups && s->prop_items && s->prop_set)
        caps |= NLR_CAP_PROP_SET;
    if (svc->worker_init && svc->worker_start && svc->flag_set)
        caps |= NLR_CAP_TASKS;
    if (s->volumes && s->volume_count && s->card_slots)
        caps |= NLR_CAP_CARD;
    if (s->touch_slot && s->touch_original && s->touch_record_bytes >= 14u)
        caps |= NLR_CAP_TOUCH;
    if (s->eye_state)
        caps |= NLR_CAP_EYE;
    caps |= NLR_CAP_RESERVED;
    return caps;
}

int nlr_platform_card_slot(const struct nlr_platform_services *s, char letter)
{
    if (!s)
        return -1;
    for (uint32_t n = 0; n < s->card_slots && n < sizeof s->card_letters; n++)
        if (s->card_letters[n] == letter)
            return (int)n;
    return -1;
}

int nlr_platform_card(const struct nlr_platform_services *s, uint32_t slot)
{
    if (!s || !s->volumes || !s->volume_count || !s->card_slots ||
        s->volume_bytes < 3u || s->volume_state >= s->volume_bytes)
        return -NLR_API_ENOSYS;
    if (slot >= s->card_slots || slot >= sizeof s->card_letters)
        return -NLR_API_EINVAL;
    /* The table is in mount order, not slot order: by name. A volume whose
     * name is cleared or whose state is anything but mounted (an error
     * state answers every file call with an error) holds no card. */
    char letter = s->card_letters[slot];
    for (uint32_t v = 0; v < s->volume_count; v++) {
        const volatile uint8_t *rec = s->volumes + v * s->volume_bytes;
        if (rec[0] == (uint8_t)letter && rec[1] == ':' && !rec[2])
            return rec[s->volume_state] == s->mounted ? 1 : 0;
    }
    return 0;
}

int nlr_platform_card_poll(struct nlr_platform *p,
                           const struct nlr_platform_services *s,
                           uint32_t now, struct nlr_event *ev)
{
    if (!p || !ev || !s || !s->volumes || !s->card_slots)
        return 0;
    if ((p->card_last >> 31) && (int32_t)(now - p->card_due) < 0)
        return 0;
    uint32_t seen = 0;
    for (uint32_t slot = 0; slot < s->card_slots && slot < 4u; slot++)
        if (nlr_platform_card(s, slot) == 1)
            seen |= 1u << slot;
    uint32_t last = p->card_last;
    if (!(last >> 31)) {
        p->card_last = seen | 1u << 31;
        p->card_due = now + 100u;
        return 0;
    }
    uint32_t changed = (last ^ seen) & 0xfu;
    if (!changed) {
        p->card_due = now + 100u;
        return 0;
    }
    /* one slot per call: the lowest that changed; the next call (at once)
     * reports another */
    uint32_t slot = 0;
    while (!(changed & (1u << slot)))
        slot++;
    p->card_last ^= 1u << slot;
    struct nlr_event card = {
        .type = NLR_EV_CARD, .code = (uint16_t)slot,
        .value = (seen >> slot) & 1u ? 1 : 0, .t_ms = now,
    };
    *ev = card;
    return 1;
}

int nlr_platform_touch(struct nlr_platform *p,
                       const struct nlr_platform_services *s,
                       const uint8_t *record, uint32_t now)
{
    if (!p || !s || !record || s->touch_record_bytes < 14u ||
        !__atomic_load_n(&p->active, __ATOMIC_ACQUIRE))
        return 0;
    uint64_t bit = CTL_BIT(NLR_CTL_TOUCH);
    uint32_t fingers = record[5];
    if (__atomic_load_n(&p->route_report, __ATOMIC_ACQUIRE) & bit) {
        uint32_t phase = !fingers ? NLR_TOUCH_UP
                       : p->touching ? NLR_TOUCH_MOVE : NLR_TOUCH_DOWN;
        /* a release when no finger was down is nothing to report */
        if (fingers || p->touching) {
            uint32_t tail = __atomic_load_n(&p->ttail, __ATOMIC_RELAXED);
            uint32_t head = __atomic_load_n(&p->thead, __ATOMIC_ACQUIRE);
            /* A move behind a full queue is dropped (the next one says
             * where the finger is); a press or a release is never lost to
             * a move: it replaces the newest queued move. */
            if (tail - head >= 16u && phase != NLR_TOUCH_MOVE &&
                p->tevents[(tail - 1u) & 15u].code == NLR_TOUCH_MOVE)
                tail--;
            /* A release happens where the finger last was: the panel's
             * record says 0,0 once no finger is down, and a tap whose
             * release is reported in the corner is no tap. */
            if (phase != NLR_TOUCH_UP) {
                p->touch_x = (int16_t)(record[10] | record[11] << 8);
                p->touch_y = (int16_t)(record[12] | record[13] << 8);
            }
            if (tail - head < 16u) {
                struct nlr_event ev = {
                    .type = NLR_EV_TOUCH, .code = (uint16_t)phase,
                    .x = p->touch_x, .y = p->touch_y,
                    .t_ms = now,
                };
                p->tevents[tail & 15u] = ev;
                __atomic_store_n(&p->ttail, tail + 1u, __ATOMIC_RELEASE);
            }
            p->touching = fingers != 0;
        }
    }
    return (__atomic_load_n(&p->route_hide, __ATOMIC_ACQUIRE) & bit) != 0;
}

int nlr_platform_touch_pop(struct nlr_platform *p, struct nlr_event *ev)
{
    if (!p || !ev)
        return 0;
    uint32_t head = __atomic_load_n(&p->thead, __ATOMIC_RELAXED);
    if (head == __atomic_load_n(&p->ttail, __ATOMIC_ACQUIRE))
        return 0;
    *ev = p->tevents[head & 15u];
    __atomic_store_n(&p->thead, head + 1u, __ATOMIC_RELEASE);
    return 1;
}

int nlr_platform_eye_poll(struct nlr_platform *p,
                          const struct nlr_platform_services *s,
                          uint32_t now, struct nlr_event *ev)
{
    if (!p || !s || !s->eye_state || !ev)
        return 0;
    if (p->eye_due && (int32_t)(now - p->eye_due) < 0)
        return 0;
    p->eye_due = (now + 50u) | 1u;
    uint32_t state = *s->eye_state;
    uint32_t last = p->eye_last;
    /* 0 and 1 are states; anything else is "not reported yet". eye_last:
     * bit 1 a state was seen, bit 0 that state, bit 2 the sensor had
     * reported nothing when the program started watching. The first look
     * only learns, unless it learns the sensor's very first report. */
    if (state > 1u) {
        if (!(last & 2u))
            p->eye_last = last | 4u;
        return 0;
    }
    p->eye_last = state | 2u;
    if (!(last & 2u) ? !(last & 4u) : (last & 1u) == state)
        return 0;
    struct nlr_event eye = {
        .type = NLR_EV_EYE, .code = NLR_CTL_EYE, .value = (int32_t)state, .t_ms = now,
    };
    *ev = eye;
    return 1;
}

/* ---- ABI 8: names (families E and F) ------------------------------------- */

static int name_is(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    uint32_t n = 0;
    for (; n < 64u && a[n] && a[n] == b[n]; n++)
        ;
    return n < 64u && a[n] == b[n];
}

int nlr_platform_find_point(const struct nlr_platform_services *s, const char *name)
{
    for (uint32_t n = 0; s && s->points && n < s->point_count; n++)
        if (name_is(s->points[n].name, name))
            return (int)n;
    return -1;
}

int nlr_platform_find_table(const struct nlr_platform_services *s, const char *name)
{
    for (uint32_t n = 0; s && s->tables && n < s->table_count; n++)
        if (name_is(s->tables[n].name, name))
            return (int)n;
    return -1;
}

int nlr_platform_find_function(const struct nlr_platform_services *s, const char *name)
{
    for (uint32_t n = 0; s && s->functions && n < s->function_count; n++)
        if (name_is(s->functions[n].name, name))
            return (int)n;
    return -1;
}

int nlr_platform_find_device(const struct nlr_platform_services *s, const char *name)
{
    for (uint32_t n = 0; s && s->devices && n < s->device_count; n++)
        if (name_is(s->devices[n].name, name))
            return (int)n;
    return -1;
}

uint32_t nlr_platform_crc32(const volatile uint8_t *p, uint32_t n)
{
    uint32_t c = ~0u;
    while (n--) {
        c ^= *p++;
        for (unsigned b = 0; b < 8; b++)
            c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
    }
    return ~c;
}

int nlr_platform_post(struct nlr_platform *p, const struct nlr_event *ev)
{
    if (!p || !ev)
        return -NLR_API_EINVAL;
    uint32_t tail = __atomic_load_n(&p->ptail, __ATOMIC_ACQUIRE);
    do {
        if (tail - __atomic_load_n(&p->phead, __ATOMIC_ACQUIRE) >= 32u)
            return -NLR_API_EOVERFLOW;
    } while (!__atomic_compare_exchange_n(&p->ptail, &tail, tail + 1u, 1,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    p->posted[tail & 31u].ev = *ev;
    __atomic_store_n(&p->posted[tail & 31u].seq, tail + 1u, __ATOMIC_RELEASE);
    return 0;
}

int nlr_platform_posted(struct nlr_platform *p, struct nlr_event *ev)
{
    if (!p || !ev)
        return 0;
    uint32_t head = __atomic_load_n(&p->phead, __ATOMIC_RELAXED);
    if (__atomic_load_n(&p->posted[head & 31u].seq, __ATOMIC_ACQUIRE) != head + 1u)
        return 0; /* nothing, or reserved and not yet written */
    *ev = p->posted[head & 31u].ev;
    __atomic_store_n(&p->phead, head + 1u, __ATOMIC_RELEASE);
    return 1;
}

/* ---- the release bundle ----------------------------- */

static uint32_t le32_at(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

uint32_t nlr_bundle_count(const uint8_t *base, uint32_t bytes)
{
    if (!base || bytes < 0x20u || base[0] != 'N' || base[1] != 'L' ||
        base[2] != 'B' || base[3] != 'B' ||
        (base[4] | base[5] << 8) != 1u || (base[6] | base[7] << 8) != 32u)
        return 0;
    uint32_t count = le32_at(base + 8), total = le32_at(base + 12);
    for (uint32_t n = 0x14; n < 0x20; n++)
        if (base[n])
            return 0;
    if (!count || count > 64u || total > bytes ||
        total < 0x20u + 32u * count ||
        nlr_platform_crc32(base + 0x20, 32u * count) != le32_at(base + 16))
        return 0;
    /* every entry inside the total, named, on its boundary */
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = base + 0x20 + 32u * i;
        uint32_t offset = le32_at(e + 16), size = le32_at(e + 20);
        if (!e[0] || e[15] || (offset & 63u) || offset < 0x20u + 32u * count ||
            offset > total || size > total - offset || le32_at(e + 28))
            return 0;
    }
    return count;
}

int nlr_bundle_entry(const uint8_t *base, uint32_t bytes, uint32_t index,
                     char name[NLR_BUNDLE_NAME_MAX + 1], const uint8_t **file,
                     uint32_t *size)
{
    if (index >= nlr_bundle_count(base, bytes))
        return -NLR_API_ENOENT;
    const uint8_t *e = base + 0x20 + 32u * index;
    if (name) {
        for (uint32_t n = 0; n < NLR_BUNDLE_NAME_MAX; n++)
            name[n] = (char)e[n];
        name[NLR_BUNDLE_NAME_MAX] = 0;
    }
    if (file)
        *file = base + le32_at(e + 16);
    if (size)
        *size = le32_at(e + 20);
    return 0;
}

static char upper(char c)
{
    return c >= 'a' && c <= 'z' ? (char)(c - 32) : c;
}

int nlr_bundle_find(const uint8_t *base, uint32_t bytes, const char *name,
                    int verify, const uint8_t **file, uint32_t *size)
{
    uint32_t count = nlr_bundle_count(base, bytes);
    if (!name)
        return -NLR_API_EINVAL;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = base + 0x20 + 32u * i;
        uint32_t n = 0;
        while (n < NLR_BUNDLE_NAME_MAX && e[n] && name[n] &&
               upper((char)e[n]) == upper(name[n]))
            n++;
        if (n >= NLR_BUNDLE_NAME_MAX || e[n] || name[n])
            continue;
        const uint8_t *at = base + le32_at(e + 16);
        uint32_t length = le32_at(e + 20);
        if (verify && nlr_platform_crc32(at, length) != le32_at(e + 24))
            return -NLR_API_EIO;
        if (file)
            *file = at;
        if (size)
            *size = length;
        return 0;
    }
    return -NLR_API_ENOENT;
}
