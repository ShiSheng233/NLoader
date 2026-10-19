#include "nlr/runtime.h"
#include "nlr/native_card.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* Exercises actual input and GUI checkpoint code. Storage and program
 * execution are outside this test; the original input is called once per
 * physical snapshot, including its non-key payload. */
static struct nlr_runtime runtime;
static uint32_t gui_state = 1, menu_flag;
static uintptr_t menu_flag_pointer = (uintptr_t)&menu_flag;
static uint8_t loader_window[16], another_window[16];
static void *window = loader_window;
static uint32_t input_calls, wakes, dispatches, dispatched, stops;
static uint32_t forwarded[0x178 / 4];
static uint32_t forwarded_physical[0x178 / 4]; /* what send_banks was given */
static void (*callback)(void *);
static struct nlr_native_card_services card;
static struct nlr_exit_services exit_services;
static uint32_t current_task_id = 5, mutate_banks;
static int32_t task_query(uint32_t *out) { *out = current_task_id; return 0; }

/* The loader's log lives in core/api.c and core/journal.c, outside this
 * test; the runtime here has no journal, so the scan is never logged. */
void nlr_program_journal_scan(struct nlr_runtime *r, const struct nlr_scan_view *view,
                              const void *object, int taken)
{
    (void)view;
    (void)object;
    (void)taken;
    assert(!r || !r->load.journal);
}

void nlr_journal(struct nlr_journal *j, const char *fmt, ...)
{
    (void)fmt;
    assert(!j);
}

/* Family B on the exit carrier: configured per case; zero leaves the legacy
 * path (no platform scan declared). */
static uint32_t activity_calls;
static void sample_activity(void) { activity_calls++; }
static const struct nlr_platform_control scan_controls[] = {
    {NLR_CTL_UP, 0, 0, 0x1}, {NLR_CTL_OK, 1, 0, 0x1}, {NLR_CTL_DISP, 2, 0, 0x10},
};
static const struct nlr_platform_scan scan_geometry = {
    .bank_base = 8, .bank_stride = 20, .banks = 3,
    .keep_bank = 0, .keep_mask = 0,
    .dial_offset = 0x58, .dial_bytes = 16, .activity = sample_activity,
};
static struct nlr_platform_services platform_services;

static const struct nlr_input_binding bindings[] = {
    {NLR_KEY_UP, 0, 1}, {NLR_KEY_RIGHT, 0, 2},
    {NLR_KEY_OK, 1, 1}, {NLR_INPUT_KEY_DISP, 2, 16},
};
static const struct nlr_input_services input_services = {
    .bindings = bindings, .count = 4, .reserved = {0, 6, 0},
    .current_task = task_query,
};

void nlr_load_event(void *self, uint32_t events) { (void)self; (void)events; }
const struct nlr_task_config nlr_task_config = {.name = "NLOADER"};
static void registry(uint32_t type, uint32_t id, void **out)
{ assert(type == 0); *out = id == 5 ? &runtime : 0; }
static void original(void *data)
{
    input_calls++;
    if (!data) return;
    memcpy(forwarded, data, sizeof forwarded);
    if (mutate_banks) memset((uint8_t *)data + 8, 0xff, 15 * sizeof(uint32_t));
}
static int32_t suspend_worker(void *worker)
{ assert(worker == &runtime); stops++; return 0; }
static int32_t terminate_worker(void *worker)
{ assert(worker == &runtime); stops++; return 0; }
static int32_t restart_worker(void *worker)
{ assert(worker == &runtime); stops++; return 0; }
static int32_t resume_worker(void *worker)
{ assert(worker == &runtime); return 0; }
static int32_t flag_set(void *flag, uint32_t mask)
{
    if (flag == &menu_flag) { assert(mask == 8); wakes++; }
    else { assert(flag == runtime.load.worker.opaque + NLR_WORKER_FLAG_OFFSET); assert(mask == 2); }
    return 0;
}
static void *flag_get(void) { return &menu_flag_pointer; }
static void *window_get(void) { return window; }
static void dispatch(uint32_t event, uint8_t *out)
{ assert(gui_state == 1 && window == loader_window); dispatches++; dispatched = event; out[1] = 1; }

const struct nlr_services nlr_services = {
    .registry_lookup = registry, .flag_set = flag_set,
    .exit = &exit_services, .native_card = &card,
    .input = &input_services, .platform = &platform_services,
};

static void reset(void)
{
    memset(&runtime, 0, sizeof runtime);
    uint8_t *w = runtime.load.worker.opaque;
    uint32_t id = 5;
    uintptr_t self = (uintptr_t)&runtime, entry = (uintptr_t)nlr_load_event;
    memcpy(w, &id, 4); memcpy(w + NLR_WORKER_NAME_OFFSET, "NLOADER", 8);
    memcpy(w + NLR_WORKER_SELF_OFFSET, &self, 8);
    memcpy(w + NLR_WORKER_CALLBACK_OFFSET, &entry, 8);
    runtime.load.svc = &nlr_services;
    runtime.load.abi_version = 4u;
    runtime.load.ready = 1;
    runtime.load.state = 2;
    runtime.load.program.jump_armed = 1;
    runtime.load.program_kind = NLR_KIND_FOREGROUND;
    runtime.exit_original_input = original;
    exit_services = (struct nlr_exit_services){
        .input_callback = &callback, .bank = 1, .mask = 6,
        .release_mask = 2, .menu_release_code = 0x279,
        .suspend = suspend_worker, .resume = resume_worker,
        .terminate = terminate_worker, .restart = restart_worker,
    };
    card.menu = (struct nlr_native_card_menu){
        .callee = flag_get, .wake_mask = 8, .dispatch = dispatch,
        .current_window = window_get, .loader_window = loader_window,
        .gui_state = &gui_state, .menu_press_code = 0x27e,
    };
    card.layout.runtime_ram_start = 1;
    card.layout.runtime_ram_end = UINTPTR_MAX;
    window = loader_window; gui_state = 1;
    input_calls = wakes = dispatches = dispatched = stops = 0;
    current_task_id = 5; mutate_banks = 0;
    /* No family B scan unless a case declares one: the legacy path. */
    memset(&platform_services, 0, sizeof platform_services);
}

static void enable_platform_scan(void)
{
    platform_services = (struct nlr_platform_services){
        .controls = scan_controls, .control_count = 3, .scan = &scan_geometry,
        .dial_word = {1, 0, 0}, .dial_sign = {1, 1, 1},
    };
}

static void send_banks(uint32_t b0, uint32_t b1, uint32_t b2)
{
    uint32_t input[0x178 / 4], saved[0x178 / 4];
    for (uint32_t n = 0; n < sizeof input / sizeof input[0]; n++)
        input[n] = UINT32_C(0x22000000) + n;
    uint32_t current[3] = {b0, b1, b2};
    for (uint32_t bank = 0; bank < 3; bank++)
        for (uint32_t field = 0; field < 5; field++)
            input[2 + bank * 5 + field] = current[bank];
    memcpy(saved, input, sizeof input);
    memcpy(forwarded_physical, saved, sizeof saved);
    uint32_t calls = input_calls;
    nlr_runtime_exit_input(input);
    assert(input_calls == calls + 1 && !memcmp(input, saved, sizeof input));
    assert(!memcmp(forwarded, saved, 2 * sizeof(uint32_t)));
    assert(!memcmp(forwarded + 17, saved + 17, 5 * sizeof(uint32_t)));
    assert(!memcmp(forwarded + 26, saved + 26, sizeof input - 26 * sizeof(uint32_t)));
    /* The dial words at +0x58: hidden only while the platform pass runs with
     * the input taken, and the case that declares a scan asserts them where
     * they must survive (the native list). */
    if (!platform_services.scan)
        assert(!memcmp(forwarded + 22, saved + 22, 4 * sizeof(uint32_t)));
}

static void application_input(void)
{
    reset();
    send_banks(0, 1, 0); /* Real launch state is observed, not queued. */
    assert(nlr_runtime_input_begin(&runtime.load) == NLR_OK);
    uint32_t first = runtime.input_owner;
    struct nlr_key_event event = {99, 99};
    assert(nlr_runtime_input_raw(&runtime) == NLR_KEY_OK);
    assert(nlr_runtime_input_poll(&runtime, &event) == 0 && event.key == 99);
    send_banks(0, 0, 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == 1);
    assert(event.key == NLR_KEY_OK && event.down == 0);
    mutate_banks = 1;
    send_banks(3 | 128, 1 | 128, 16 | 128);
    for (uint32_t bank = 0; bank < 3; bank++)
        for (uint32_t field = 0; field < 5; field++)
            assert(forwarded[2 + bank * 5 + field] == 128);
    assert(nlr_runtime_input_raw(&runtime) ==
           (NLR_KEY_UP | NLR_KEY_RIGHT | NLR_KEY_OK | NLR_KEY_DISP));
    current_task_id = 6;
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EBUSY);
    assert(nlr_runtime_input_raw(&runtime) == 0);
    nlr_runtime_input_end(&runtime.load);
    assert(runtime.input_owner == first); /* A foreign task cannot end it. */
    current_task_id = 5;
    uint32_t keys = 0;
    for (uint32_t n = 0; n < 4; n++) {
        assert(nlr_runtime_input_poll(&runtime, &event) == 1 && event.down == 1);
        assert(event.key && !(event.key & (event.key - 1)));
        keys |= event.key;
    }
    assert(keys == nlr_runtime_input_raw(&runtime));
    window = another_window;
    assert(nlr_runtime_input_raw(&runtime) == 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EBUSY);
    send_banks(3, 1, 16);
    assert(forwarded[2] == 3 && forwarded[7] == 1 && forwarded[12] == 16);
    assert(nlr_input_raw(&runtime.input, first) == 0);
    window = loader_window;
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EBUSY);
    send_banks(0, 0, 0); /* Only a new focused physical sample may resume. */
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EOVERFLOW);
    assert(nlr_runtime_input_poll(&runtime, &event) == 0);
    send_banks(0, 0, 0);
    for (uint32_t n = 0; n < 40; n++) send_banks((n & 1) ? 0 : 1, 0, 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EOVERFLOW);
    assert(nlr_runtime_input_raw(&runtime) == 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == 0);
    send_banks(2, 0, 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == 1);
    assert(event.key == NLR_KEY_RIGHT && event.down == 1);
    nlr_runtime_input_end(&runtime.load);
    assert(!runtime.input_owner && !runtime.input.active_owner);
    assert(nlr_runtime_input_begin(&runtime.load) == NLR_OK);
    assert(runtime.input_owner > first);
    assert(nlr_input_publish(&runtime.input, first, NLR_KEY_UP) == -NLR_API_EBUSY);
    assert(nlr_runtime_input_poll(&runtime, &event) == 0);
    assert(nlr_runtime_input_raw(&runtime) == NLR_KEY_RIGHT);
    send_banks(1 | 128, 6, 0); /* Original exit combination remains exclusive. */
    assert(stops == 3 && runtime.exit_swallow && forwarded[2] == 128 && !forwarded[7]);
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EBUSY);
    nlr_runtime_input_end(&runtime.load);
    assert(!runtime.input_owner);
    uint32_t calls = input_calls;
    nlr_runtime_exit_input(0);
    assert(input_calls == calls + 1);
}

static void focus_without_input_callback(void)
{
    reset();
    assert(nlr_runtime_input_begin(&runtime.load) == NLR_OK);
    send_banks(1, 0, 0); /* This press has not been consumed. */
    struct nlr_key_event event = {99, 99};
    uint32_t calls = input_calls;
    window = another_window;
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EBUSY);
    assert(event.key == 99 && event.down == 99);
    assert(nlr_runtime_input_raw(&runtime) == 0);
    window = loader_window;
    assert(input_calls == calls); /* No SWSRV callback throughout loss/refocus. */
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EBUSY);
    assert(nlr_runtime_input_raw(&runtime) == 0 && event.key == 99);
    send_banks(1, 0, 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EOVERFLOW);
    assert(nlr_runtime_input_raw(&runtime) == NLR_KEY_UP);
    assert(nlr_runtime_input_poll(&runtime, &event) == 0 && event.key == 99);
    send_banks(0, 0, 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == 1);
    assert(event.key == NLR_KEY_UP && event.down == 0);
}

static void native_list_owns_direction_keys(void)
{
    reset();
    /* The native list's own navigation must survive the platform hides too:
     * this is the same rule the program input hook has always had. */
    enable_platform_scan();
    assert(nlr_runtime_input_begin(&runtime.load) == NLR_OK);
    send_banks(1, 0, 0);
    struct nlr_key_event event;
    assert(nlr_runtime_input_poll(&runtime, &event) == 1 && event.key == NLR_KEY_UP);
    runtime.io.list_active = 1;
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EBUSY);
    send_banks(2, 1, 16);
    assert(forwarded[2] == 2 && forwarded[7] == 1 && forwarded[12] == 16);
    /* The list's own dials too: nothing of it is hidden while it runs. */
    for (uint32_t n = 0x58 / 4; n < 0x68 / 4; n++)
        assert(forwarded[n] == forwarded_physical[n]);
    runtime.io.list_active = 0;
    send_banks(0, 0, 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == -NLR_API_EOVERFLOW);
    assert(nlr_runtime_input_poll(&runtime, &event) == 0);
    send_banks(2, 0, 0);
    assert(nlr_runtime_input_poll(&runtime, &event) == 1 && event.key == NLR_KEY_RIGHT);
}

static void send_platform(uint32_t current0, uint32_t current1, uint32_t current2,
                          int32_t dial)
{
    uint32_t input[0x178 / 4];
    for (uint32_t n = 0; n < sizeof input / sizeof input[0]; n++)
        input[n] = UINT32_C(0x33000000) + n;
    uint32_t current[3] = {current0, current1, current2};
    for (uint32_t bank = 0; bank < 3; bank++) {
        input[2 + bank * 5] = current[bank];           /* current */
        input[2 + bank * 5 + 2] = current[bank];       /* changed */
        input[2 + bank * 5 + 3] = current[bank];       /* pressed */
    }
    input[0x58 / 4] = (uint32_t)dial;
    nlr_runtime_exit_input(input);
}

static void platform_carrier_reports_and_hides(void)
{
    reset();
    activity_calls = 0;
    enable_platform_scan();
    assert(nlr_runtime_input_begin(&runtime.load) == NLR_OK);
    nlr_platform_take_input(&runtime.plat, 0);
    send_platform(1, 1, 0, 3);
    /* Every declared control and the dial reach the program: */
    struct nlr_event ev;
    assert(nlr_platform_pop(&runtime.plat, &ev) == 1 &&
           ev.type == NLR_EV_CONTROL && ev.code == NLR_CTL_UP && ev.value == 1);
    assert(nlr_platform_pop(&runtime.plat, &ev) == 1 &&
           ev.type == NLR_EV_CONTROL && ev.code == NLR_CTL_OK && ev.value == 1);
    assert(nlr_platform_pop(&runtime.plat, &ev) == 1 &&
           ev.type == NLR_EV_DIAL && ev.code == NLR_CTL_DIAL_MAIN && ev.value == 3);
    assert(nlr_platform_pop(&runtime.plat, &ev) == 0);
    /* Nothing is routed to the camera, so it sees none of them, and the
     * hidden change is user activity: the camera stays awake. */
    for (uint32_t bank = 0; bank < 3; bank++)
        for (uint32_t field = 0; field < 5; field++)
            assert(forwarded[2 + bank * 5 + field] == 0);
    assert(activity_calls == 1);
    /* A control routed to the camera is hidden from nobody and reported to
     * nobody: only the routed bit stays visible. */
    reset();
    activity_calls = 0;
    enable_platform_scan();
    assert(nlr_runtime_input_begin(&runtime.load) == NLR_OK);
    nlr_platform_take_input(&runtime.plat, 0);
    const uint32_t to_camera[] = {NLR_CTL_OK};
    assert(nlr_platform_route(&runtime.plat, to_camera, 1, NLR_ROUTE_CAMERA) == 0);
    send_platform(1, 1, 0, 0);
    assert(nlr_platform_pop(&runtime.plat, &ev) == 1 && ev.code == NLR_CTL_UP);
    assert(nlr_platform_pop(&runtime.plat, &ev) == 0); /* OK stays the camera's */
    assert((forwarded[2 + 5] & ~0x1u) == 0 && (forwarded[2 + 5] & 0x1u) == 1);
    assert((forwarded[2 + 2 * 5]) == 0);
    /* An ended program keeps hiding what is still held until it is let go. */
    reset();
    activity_calls = 0;
    enable_platform_scan();
    assert(nlr_runtime_input_begin(&runtime.load) == NLR_OK);
    nlr_platform_take_input(&runtime.plat, 0);
    send_platform(1, 0, 0, 0);
    assert(forwarded[2] == 0);
    runtime.load.state = 0; /* the program is gone */
    send_platform(1, 0, 0, 0); /* still held */
    assert(forwarded[2] == 0 && runtime.plat.hold == 0x1u);
    send_platform(0, 0, 0, 0); /* released */
    assert(forwarded[2] == 0 && runtime.plat.hold == 0);
    send_platform(0, 0, 0, 0);
    assert(forwarded[2] == 0);
    nlr_runtime_input_end(&runtime.load);
}

static void send(uint32_t current, uint32_t previous, uint32_t changed,
                 uint32_t pressed, uint32_t released)
{
    uint32_t input[0x178 / 4], saved[0x178 / 4];
    for (uint32_t n = 0; n < sizeof input / sizeof input[0]; n++)
        input[n] = UINT32_C(0x11000000) + n;
    uint32_t *bank = input + 7;
    bank[0] = current; bank[1] = previous; bank[2] = changed;
    bank[3] = pressed; bank[4] = released;
    memcpy(saved, input, sizeof input);
    uint32_t before = input_calls;
    nlr_runtime_exit_input(input);
    assert(input_calls == before + 1 && !memcmp(input, saved, sizeof input));
    assert(!memcmp(forwarded, saved, 7 * sizeof(uint32_t)));
    assert(!memcmp(forwarded + 12, saved + 12, sizeof input - 12 * sizeof(uint32_t)));
}

int main(void)
{
    platform_carrier_reports_and_hides();
    native_list_owns_direction_keys();
    application_input();
    focus_without_input_callback();
    reset();
    send(2, 0, 2, 2, 0);
    assert(runtime.exit_menu_held && !forwarded[7] && !stops && !wakes);
    send(0, 2, 2, 0, 2);
    assert(!runtime.exit_menu_held && runtime.exit_menu_pending == 0x27e && wakes == 1);
    nlr_runtime_exit_menu_checkpoint(&runtime);
    assert(dispatches == 1 && dispatched == 0x27e && input_calls == 2 && !stops);
    nlr_runtime_exit_menu_checkpoint(&runtime);
    assert(dispatches == 1); /* No extra MCU packet or duplicate dispatch. */

    for (uint32_t order = 0; order < 3; order++) {
        reset();
        if (order == 0) send(2, 0, 2, 2, 0);
        if (order == 1) { send(4, 0, 4, 4, 0); assert(forwarded[7] == 4); }
        send(6, order == 0 ? 2 : order == 1 ? 4 : 0,
               order == 0 ? 4 : order == 1 ? 2 : 6,
               order == 0 ? 4 : order == 1 ? 2 : 6, 0);
        assert(stops == 3 && runtime.exit_swallow && runtime.exit_notify);
        assert(!runtime.exit_release_seen && !runtime.exit_menu_pending && !forwarded[7]);
        send(6, 6, 0, 0, 0);
        assert(stops == 3 && !runtime.exit_release_seen);
        send(0, 6, 6, 0, 6);
        assert(runtime.exit_release_seen && !runtime.exit_swallow);
        nlr_runtime_exit_menu_checkpoint(&runtime);
        assert(dispatches == 1 && dispatched == 0x279);
    }

    reset(); send(2, 0, 2, 2, 0);
    runtime.load.state = runtime.load.program.jump_armed = 0;
    send(0, 2, 2, 0, 2);
    nlr_runtime_exit_menu_checkpoint(&runtime);
    assert(dispatches == 1 && dispatched == 0x27e); /* Natural return while held. */

    reset(); send(2, 0, 2, 2, 0); send(4, 2, 6, 4, 2);
    assert(forwarded[7] == 4 && !stops); /* No fabricated simultaneous chord. */
    nlr_runtime_exit_menu_checkpoint(&runtime);
    assert(dispatches == 1 && dispatched == 0x27e);

    reset(); send(2, 0, 2, 2, 0); send(0, 2, 2, 0, 2);
    window = another_window;
    nlr_runtime_exit_menu_checkpoint(&runtime);
    assert(!dispatches && !runtime.exit_menu_pending && runtime.exit_menu_result == NLR_REFUSED);
    window = loader_window;
    nlr_runtime_exit_menu_checkpoint(&runtime);
    assert(!dispatches); /* Returning later never replays an obsolete edge. */
    puts("retained MENU and actual-release GUI checks passed");
    return 0;
}
