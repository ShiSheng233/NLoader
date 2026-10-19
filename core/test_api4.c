/* Exercises the public ABI 4 boundary with the actual frame handoff and
 * time modules. Native services and runtime discovery are host fixtures. */
#include "nlr/runtime.h"
#include <assert.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct nlr_api nlr_api;
extern const struct nlr_services nlr_services;
static struct nlr_runtime runtime;
static uint64_t now;
static uint32_t delays, renders, clean_calls, enum_calls;
static uint32_t setting_queries;
static int deny_worker, fail_delay, fail_clock, answer_list, enum_error;
static int enum_mutates;
static int refuse_packed_release;
static uint8_t shown[8];
static char enumerated[128];
static jmp_buf stopped;
static int expect_stop;
static void (*input_callback)(void *);
static uint8_t forwarded_input[128];
static void original_input(void *object)
{
    memcpy(forwarded_input, object, sizeof forwarded_input);
    memset((uint8_t *)object + 8, 0xee, 60);
    memset((uint8_t *)object + 100, 0xee, 8);
}

/* The execution family is not part of this fixture: it has no heap books,
 * so the API's memory takes the plain service path and never asks for a
 * granted block. */
static uint32_t plane_cleaned;
static int32_t exec_clean(void *page, uint32_t bytes)
{ assert(page && bytes); plane_cleaned += bytes; return 0; }
const struct nlr_exec_services nlr_exec_services = {.clean = exec_clean};
void *nlr_exec_grant_alloc(const struct nlr_exec_services *books,
                           int32_t (*allocate)(uint32_t bytes, void **out),
                           int32_t (*release)(void *allocation),
                           uint32_t bytes)
{
    (void)books; (void)allocate; (void)release; (void)bytes;
    assert(0);
    return 0;
}

/* The heap has no block above 256 MiB (the host would hand out address
 * space lazily). */
static int32_t allocate(uint32_t bytes, void **out)
{
    *out = bytes <= 0x10000000u ? malloc(bytes) : 0;
    return *out ? NLR_OK : NLR_NOT_READY;
}
static int32_t release(void *memory)
{
    if (refuse_packed_release && memory == runtime.io.gfx_request) return NLR_IO;
    free(memory);
    return NLR_OK;
}
static int32_t clock_ms(uint64_t *out)
{ if (fail_clock) return NLR_IO; *out = now; return NLR_OK; }
/* A GUI turn that reaches its hold at this time (0: none comes), and a
 * moment after which the display shows another buffer (0: never). */
static uint64_t gui_turn_at, layer_moves_at;
static void scanout_show(volatile uint32_t *pair, const void *buffer);
static volatile uint32_t colour_scanout[2], alpha_scanout[2];
static _Alignas(32) uint8_t screen_colour[2][64 * 4], screen_alpha[2][32 * 4];
static int32_t delay_ms(uint32_t ms)
{
    assert(ms && ms <= 10u);
    delays++;
    if (fail_delay) return NLR_IO;
    now += ms;
    if (gui_turn_at && now >= gui_turn_at)
        runtime.plat.inside = 1;
    if (layer_moves_at && now >= layer_moves_at) {
        scanout_show(colour_scanout, screen_colour[1]);
        scanout_show(alpha_scanout, screen_alpha[1]);
        layer_moves_at = 0;
    }
    /* 1: the plain list the ui_list checks publish; 2: any list; 3: the
     * text entry the ui_input checks publish, saved as more text than it
     * holds; 4: any text entry, given up. */
    if (answer_list) {
        if (answer_list == 1) {
            assert(runtime.list.count == 2 && runtime.list.selected == 1);
            assert(!strcmp(runtime.list.rows[1], "second"));
        }
        runtime.list.choice = 1;
        if (answer_list == 3) {
            assert(runtime.list.dialog && runtime.list.count == 1);
            assert(!strcmp(runtime.list.title, "name") && !strcmp(runtime.list.rows[0], "name"));
            assert(!strcmp(runtime.own.text, "abc"));
            assert(runtime.own.length == 7 && runtime.own.charset == NLR_INPUT_UPPER);
            assert(runtime.list.rows_view && runtime.list.kinds[0] == NLR_ROW_SELECT);
            assert(!strcmp(runtime.list.values[0], "abc"));
            snprintf(runtime.own.taken, sizeof runtime.own.taken, "LONGER-THAN-7");
            runtime.list.choice = 13;
        } else if (answer_list == 4) {
            assert(runtime.list.dialog);
            runtime.list.choice = (int32_t)NLR_LIST_BACK;
        } else if (answer_list == 5) {
            /* 5: the caution the ui_caution checks publish, answered No. */
            assert(runtime.list.dialog == NLR_OWN_CAUTION && runtime.list.count == 1);
            assert(runtime.own.buttons == NLR_CAUTION_YES_NO);
            assert(!strcmp(runtime.own.message,
                           "Write failed. Restart the\ncamera before trying aga"));
            assert(!strcmp(runtime.list.rows[0],
                           "Write failed. Restart the camera before trying aga"));
            assert(!strcmp(runtime.list.title, runtime.list.rows[0]));
            runtime.list.choice = 0;
        }
        runtime.list.choice_seq++;
        answer_list = 0;
    }
    return NLR_OK;
}
static const struct nlr_time_services time_services = {clock_ms, delay_ms};

/* what the enumerator answers when `each` stops it: 0 here, a code of its
 * own on the Z 8 */
static uint32_t early_stop;
static uint32_t enumerate(const char *path, uint32_t mask,
                           uint32_t (*each)(const uint8_t *info))
{
    enum_calls++;
    snprintf(enumerated, sizeof enumerated, "%s", path);
    if (enum_error) return 77u;
    const char *names[] = {".", "DIR", "NOTE.TXT", "E~1.TXT"};
    for (uint32_t n = 0; n < 4; n++) {
        uint8_t info[128] = {0};
        memcpy(info, names[n], strlen(names[n]) + 1);
        if (n < 2) info[80] = 16;
        if ((mask == 16u) != (n < 2)) continue;
        if (n == 2) {
            const char *long_name = "Long Note.txt";
            for (uint32_t q = 0; long_name[q]; q++) info[16 + q * 2] = long_name[q];
            info[88] = 123;
        }
        if (n == 3) info[16] = 0xe9; /* non-ASCII long name uses its 8.3 name */
        if (each(info)) return early_stop;
    }
    if (enum_mutates) ((char *)path)[0] = 'X';
    return 99;
}
static struct nlr_program_services program_services = {
    .fs_enum = enumerate, .enum_done = 99, .mask_directories = 16,
    .mask_files = 32, .attr_directory = 16, .info_short = 0,
    .info_long = 16, .info_attr = 80, .info_size = 88, .info_long_unit = 2,
    .input_slot = &input_callback, .input_original = original_input,
    .bank_base = 8, .bank_stride = 20, .banks = 3, .keep_bank = 2,
    .keep_mask = 128, .dial_offset = 100, .dial_bytes = 8,
    .keys = {[0] = {0, 1}, [5] = {1, 2}, [7] = {1, 4}},
};
/* The GUI hold as the Z 8 declares it (services.platform.hold); the
 * screen test below changes the waits to show they are the profile's. */
static struct nlr_platform_services platform_services = {
    .hold_when = NLR_HOLD_SETTLE, .hold_wait_ms = 5000u, .scanout_stable_ms = 300u,
};
const struct nlr_services nlr_services = {
    .alloc = allocate, .release = release, .time = &time_services,
    .program = &program_services, .platform = &platform_services,
};
/* The allocation entry (core/exec.c) for a build without heap books. */
void *nlr_alloc_whole(const struct nlr_services *s, uint32_t bytes)
{ void *block = 0; return s->alloc(bytes, &block) == 0 ? block : 0; }

struct nlr_runtime *nlr_runtime_find(const struct nlr_services *s, uint32_t *id)
{ assert(s == &nlr_services); if (id) *id = 1; return &runtime; }
int nlr_runtime_input_poll(struct nlr_runtime *r, struct nlr_key_event *event)
{ (void)r; (void)event; return -NLR_API_ENOSYS; }
uint32_t nlr_runtime_input_raw(struct nlr_runtime *r)
{ (void)r; return 0; }
/* No boot program here: a program's waits owe no boot record. */
void nlr_runtime_boot_alive(struct nlr_runtime *r)
{ assert(r == &runtime); }
int nlr_runtime_menu_register(struct nlr_runtime *r, const struct nlr_menu_test_item *item)
{ (void)r; (void)item; return NLR_NOT_READY; }
int32_t nlr_settings_find(const struct nlr_runtime *r, const char *key)
{ assert(r == &runtime); setting_queries++; return !strcmp(key, "test") ? 2 : -1; }
void nlr_program_longjmp(const uint64_t *context, int value)
{ (void)context; assert(expect_stop); longjmp(stopped, value); }
int nlr_graphics_runtime_cleanup(struct nlr_runtime *r)
{ return nlr_graphics_cleanup(&r->graphics, r->graphics_owner) ? NLR_EXEC_RESTORE : NLR_OK; }
/* A published list wakes the menu's task; there is none here. */
static unsigned list_wakes;
void nlr_graphics_runtime_list_published(struct nlr_runtime *r)
{ assert(r == &runtime); list_wakes++; }

static int32_t worker_owner(void *context, uint64_t owner)
{ assert(context == &runtime && owner == runtime.graphics_owner); return deny_worker; }
static int32_t gui_owner(void *context)
{ assert(context == &runtime); return 0; }
static int32_t current_window(void *context, uint64_t owner)
{ assert(context == &runtime && owner == runtime.graphics_owner); return 0; }
static int32_t frame_allocate(void *context, uint32_t bytes, void **out)
{ assert(context == &runtime); return allocate(bytes, out); }
static int32_t frame_release(void *context, void *memory)
{ assert(context == &runtime); return release(memory); }
static int32_t clean(void *context, void *pixels, uint32_t bytes)
{
    assert(context == &runtime && pixels && bytes == 320u * 200u * 4u);
    clean_calls++;
    return 0;
}
static int32_t render(void *context, uint64_t owner,
                       const struct nlr_graphics_frame *frame, uint32_t *started)
{
    assert(context == &runtime && owner == runtime.graphics_owner);
    assert(frame->format == NLR_GRAPHICS_RGBA8 && frame->width == 320 && frame->height == 200);
    assert(frame->stride_bytes == 1280 && clean_calls > renders);
    memcpy(shown, frame->pixels, sizeof shown);
    *started = 1;
    renders++;
    return 0;
}
static int32_t wake(void *context)
{ assert(context == &runtime); return nlr_graphics_gui_consume(&runtime.graphics); }
static int32_t frame_clock(void *context, uint64_t *out)
{ assert(context == &runtime); return clock_ms(out); }
static int32_t frame_sleep(void *context, uint32_t ms)
{ assert(context == &runtime); return delay_ms(ms); }

static void initialize(void)
{
    memset(&runtime, 0, sizeof runtime);
    runtime.load.svc = &nlr_services;
    runtime.load.state = 2;
    runtime.load.program_kind = NLR_KIND_FOREGROUND;
    runtime.load.program.jump_armed = 1;
    runtime.load.abi_version = 4u;
    runtime.io.list_capacity = NLR_LIST_ROWS_MAX;
    runtime.graphics_owner = 7;
    runtime.graphics_canvas_ready = 1;
    runtime.graphics_services = (struct nlr_graphics_services){
        .context = &runtime, .worker_owner = worker_owner, .gui_owner = gui_owner,
        .current_window = current_window, .allocate = frame_allocate,
        .release = frame_release, .clean_source = clean, .wake_gui = wake,
        .clock_ms = frame_clock, .sleep_ms = frame_sleep, .render = render, .timeout_ms = 10,
    };
}

static void legacy_outputs_remain_untouched(void)
{
    for (uint32_t abi = 1; abi <= 2; abi++) {
        _Alignas(8) uint8_t old_surface[24], before[24];
        memset(old_surface, 0x5a, sizeof old_surface);
        memcpy(before, old_surface, sizeof before);
        runtime.load.abi_version = abi;
        assert(nlr_api.gfx_begin((struct nlr_surface *)old_surface) == -NLR_API_ENOSYS);
        assert(!memcmp(old_surface, before, sizeof old_surface));
        struct nlr_key_event old_event = {99, 99};
        assert(nlr_api.input_poll(&old_event) == -NLR_API_ENOSYS);
        assert(old_event.key == 99 && old_event.down == 99 && !nlr_api.input_raw());
        assert(nlr_api.ui_present() == -NLR_API_ENOSYS);
        assert(nlr_api.gfx_end() == -NLR_API_ENOSYS);
    }
    runtime.load.abi_version = 4u;
}

/* The screen and the buttons arrived with ABI 4 and stay with every later
 * version: a program built for ABI 5 (card writes, the code channel) owns
 * them as an ABI 4 one does, instead of meeting -ENOSYS. The buttons pass
 * the same gate; this fixture has no input channel to show it with. */
static void later_abi_keeps_screen_and_buttons(void)
{
    runtime.load.abi_version = 5u;
    struct nlr_surface surface = {0};
    assert(!nlr_api.gfx_begin(&surface) && surface.pixels);
    assert(!nlr_api.ui_present());
    assert(!nlr_api.gfx_end());
    assert(!nlr_api_program_cleanup(&runtime.load.program));
    runtime.load.abi_version = 4u;
}

/* The platform screen (family C) is there in this build too, where the
 * loader also draws its own canvas: undeclared scanout answers -ENOSYS, a
 * program that is not the shell is refused, and the shell gets the GUI
 * layer itself, transparent from the start, given back and taken again. */
static void scanout_show(volatile uint32_t *pair, const void *buffer)
{
    pair[0] = (uint32_t)(uintptr_t)buffer;
    pair[1] = (uint32_t)((uint64_t)(uintptr_t)buffer >> 32);
}

static void platform_screen_in_the_graphics_build(void)
{
    struct nlr_surface surface = {0};
    runtime.load.abi_version = 7u;
    assert(nlr_api.screen_claim(NLR_SCREEN_REAR, &surface) == -NLR_API_ENOSYS);
    assert(nlr_api.screen_present(NLR_SCREEN_REAR, 0, 0) == -NLR_API_ENOSYS);
    assert(nlr_api.screen_release(NLR_SCREEN_REAR) == -NLR_API_ENOSYS);

    uint64_t lo = (uintptr_t)screen_colour < (uintptr_t)screen_alpha
                      ? (uintptr_t)screen_colour : (uintptr_t)screen_alpha;
    uint64_t hi = (uintptr_t)screen_colour < (uintptr_t)screen_alpha
                      ? (uintptr_t)screen_alpha + sizeof screen_alpha
                      : (uintptr_t)screen_colour + sizeof screen_colour;
    program_services.scanout_colour = colour_scanout;
    program_services.scanout_alpha = alpha_scanout;
    program_services.scanout_high_mask = 0xffffffffu;
    program_services.bus_offset = 0;
    program_services.plane_lo = lo;
    program_services.plane_hi = hi;
    program_services.width = 32;
    program_services.height = 4;
    program_services.stride = 64;
    program_services.alpha_stride = 32;
    scanout_show(colour_scanout, screen_colour[0]);
    scanout_show(alpha_scanout, screen_alpha[0]);
    memset(screen_alpha, 0xff, sizeof screen_alpha);

    assert(nlr_api.screen_claim(NLR_SCREEN_EVF, &surface) == -NLR_API_ENOSYS);
    assert(nlr_api.screen_claim(NLR_SCREEN_REAR, 0) == -NLR_API_EINVAL);
    /* opened from the menu: the stock menu's buffers are not the program's */
    assert(nlr_api.screen_claim(NLR_SCREEN_REAR, &surface) == -NLR_API_EBUSY);
    assert(!surface.pixels && screen_alpha[0][0] == 0xff);

    runtime.plat.shell = 1;
    runtime.plat.inside = 1; /* the GUI's task is held at its checkpoint */
    plane_cleaned = 0;
    assert(!nlr_api.screen_claim(NLR_SCREEN_REAR, &surface));
    assert(surface.format == NLR_SURFACE_Y0Y1UV_A8 && surface.width == 32 &&
           surface.height == 4 && surface.stride == 64 && surface.alpha_stride == 32);
    assert(surface.pixels == screen_colour[0] && surface.alpha == screen_alpha[0]);
    for (uint32_t n = 0; n < sizeof screen_alpha[0]; n++)
        assert(!screen_alpha[0][n] && screen_alpha[1][n] == 0xff);
    assert(plane_cleaned == sizeof screen_alpha[0] && runtime.plat.claimed);

    plane_cleaned = 0;
    assert(!nlr_api.screen_present(NLR_SCREEN_REAR, 0, 0));
    assert(plane_cleaned == sizeof screen_colour[0] + sizeof screen_alpha[0]);
    struct nlr_rect damage = {30, 3, 8, 8};
    plane_cleaned = 0;
    assert(!nlr_api.screen_present(NLR_SCREEN_REAR, &damage, 1));
    assert(plane_cleaned == 2u * 2u + 2u);
    scanout_show(colour_scanout, screen_colour[1]); /* the GUI moved the layer */
    assert(nlr_api.screen_present(NLR_SCREEN_REAR, 0, 0) == -NLR_API_EIO);
    scanout_show(colour_scanout, screen_colour[0]);

    screen_alpha[0][5] = 0x80; /* the program drew */
    assert(!nlr_api.screen_release(NLR_SCREEN_REAR));
    assert(!screen_alpha[0][5] && runtime.plat.redraw && runtime.plat.lent);
    assert(!runtime.plat.claimed);
    assert(nlr_api.screen_release(NLR_SCREEN_REAR) == -NLR_API_ENOENT);
    assert(nlr_api.screen_present(NLR_SCREEN_REAR, 0, 0) == -NLR_API_EBUSY);
    /* taken again: the GUI is asked back to its checkpoint */
    assert(!nlr_api.screen_claim(NLR_SCREEN_REAR, &surface));
    assert(!runtime.plat.lent && runtime.autoload.boot_hold && runtime.plat.claimed);
    assert(!nlr_api.screen_release(NLR_SCREEN_REAR));
    /* the hold ended with the release: a claim waits for the next GUI turn
     * (the live-view service may still be starting, ~3 s in stock) */
    runtime.plat.inside = 0;
    runtime.autoload.boot_hold = 0;
    uint64_t asked = now;
    gui_turn_at = now + 3200u;
    assert(!nlr_api.screen_claim(NLR_SCREEN_REAR, &surface));
    assert(now >= asked + 3500u && now < asked + 5000u); /* + 300 ms steady */
    assert(!runtime.plat.lent && runtime.autoload.boot_hold && runtime.plat.claimed);
    assert(surface.pixels == screen_colour[0]);
    assert(!nlr_api.screen_release(NLR_SCREEN_REAR));
    /* the display turns to the GUI's last frame just after the hold: the
     * claim takes the buffers it settles on */
    runtime.plat.inside = 0;
    runtime.autoload.boot_hold = 0;
    asked = now;
    gui_turn_at = now + 100u;
    layer_moves_at = now + 250u;
    assert(!nlr_api.screen_claim(NLR_SCREEN_REAR, &surface));
    assert(now >= asked + 550u && now < asked + 1000u);
    assert(surface.pixels == screen_colour[1] && surface.alpha == screen_alpha[1]);
    assert(!nlr_api.screen_release(NLR_SCREEN_REAR));
    scanout_show(colour_scanout, screen_colour[0]);
    scanout_show(alpha_scanout, screen_alpha[0]);
    /* no turn comes: refused after five seconds, the GUI let go on */
    runtime.plat.inside = 0;
    runtime.autoload.boot_hold = 0;
    gui_turn_at = 0;
    asked = now;
    assert(nlr_api.screen_claim(NLR_SCREEN_REAR, &surface) == -NLR_API_EBUSY);
    assert(now >= asked + 5000u && now < asked + 5100u);
    assert(runtime.plat.lent && !runtime.plat.claimed);

    /* The waits are the profile's: a 2 s hold wait refuses after 2 s ... */
    platform_services.hold_wait_ms = 2000u;
    runtime.plat.inside = 0;
    runtime.autoload.boot_hold = 0;
    gui_turn_at = 0;
    asked = now;
    assert(nlr_api.screen_claim(NLR_SCREEN_REAR, &surface) == -NLR_API_EBUSY);
    assert(now >= asked + 2000u && now < asked + 2100u);
    assert(runtime.plat.lent && !runtime.plat.claimed);
    /* ... and takes a turn that comes in time; no scanout settle hands the
     * buffers out as soon as the hold is taken */
    platform_services.scanout_stable_ms = 0;
    runtime.plat.inside = 0;
    runtime.autoload.boot_hold = 0;
    asked = now;
    gui_turn_at = now + 1500u;
    assert(!nlr_api.screen_claim(NLR_SCREEN_REAR, &surface));
    assert(now >= asked + 1500u && now < asked + 1520u);
    assert(surface.pixels == screen_colour[0] && runtime.plat.claimed);
    assert(!nlr_api.screen_release(NLR_SCREEN_REAR));
    /* a body that declares no hold: a claim that would wait is refused at
     * once, the GUI let go on */
    platform_services.hold_when = 0;
    runtime.plat.inside = 0;
    runtime.autoload.boot_hold = 0;
    gui_turn_at = now + 100u;
    asked = now;
    assert(nlr_api.screen_claim(NLR_SCREEN_REAR, &surface) == -NLR_API_EBUSY);
    assert(now < asked + 10u && !runtime.plat.claimed);
    platform_services.hold_when = NLR_HOLD_SETTLE;
    platform_services.hold_wait_ms = 5000u;
    platform_services.scanout_stable_ms = 300u;
    gui_turn_at = 0;

    nlr_program_io_release(&runtime);
    runtime.plat = (struct nlr_platform){0};
    runtime.autoload.boot_hold = 0;
    program_services.scanout_colour = program_services.scanout_alpha = 0;
    program_services.width = program_services.height = 0;
    program_services.stride = program_services.alpha_stride = 0;
    program_services.plane_lo = program_services.plane_hi = 0;
    runtime.load.abi_version = 4u;
}

static void surface_lifecycle_and_conversion(void)
{
    struct nlr_surface surface = {0};
    deny_worker = 1;
    assert(nlr_api.gfx_begin(&surface) == -NLR_API_EIO && !surface.pixels);
    deny_worker = 0;
    assert(!nlr_api.gfx_begin(&surface));
    assert(surface.format == NLR_SURFACE_Y0Y1UV_A8 && surface.width == 320 && surface.height == 200);
    assert(surface.stride == 640 && surface.alpha_stride == 320 && surface.alpha);
    surface.pixels[0] = 16; surface.pixels[1] = 235;
    surface.pixels[2] = surface.pixels[3] = 128;
    surface.alpha[0] = 37; surface.alpha[1] = 73;
    assert(!nlr_api.ui_present());
    const uint8_t expected[] = {0, 0, 0, 37, 255, 255, 255, 73};
    assert(!memcmp(shown, expected, sizeof expected) && renders == 1);
    surface.pixels[0] = surface.pixels[1] = 82;
    surface.pixels[2] = 90; surface.pixels[3] = 240;
    assert(!nlr_api.ui_present() && renders == 2);
    assert(shown[0] == 255 && shown[1] <= 2 && shown[2] == 0 && shown[3] == 37);
    deny_worker = 1;
    assert(nlr_api.gfx_end() == -NLR_API_EBUSY && runtime.io.gfx_active);
    deny_worker = 0;
    struct nlr_surface denied = {0};
    assert(nlr_api.gfx_begin(&denied) == -NLR_API_EBUSY && !denied.pixels);
    const char *rows[] = {"first", "second"};
    assert(nlr_api.ui_list("list", rows, 2, 1) == -NLR_API_EBUSY);
    assert(!nlr_api.gfx_end());
    assert(nlr_api.ui_present() == -NLR_API_EBUSY);
    assert(!nlr_api.gfx_begin(&denied) && denied.pixels == surface.pixels);
    assert(!nlr_api.gfx_end());
    refuse_packed_release = 1;
    assert(nlr_api_program_cleanup(&runtime.load.program) == NLR_EXEC_RESTORE);
    assert(runtime.io.gfx_request);
    refuse_packed_release = 0;
    assert(!nlr_api_program_cleanup(&runtime.load.program));
    assert(!runtime.io.gfx_request && !runtime.graphics.allocation);
}

static void directory_and_list_contract(void)
{
    struct nlr_dirent entry;
    assert(!nlr_api.fs_dir("", 0, &entry));
    assert(!strcmp(enumerated, NLR_PROGRAM_ROOT) && !strcmp(entry.name, "DIR"));
    assert(entry.flags == NLR_DIRENT_DIR && entry.size == 0);
    enum_mutates = 1;
    assert(!nlr_api.fs_dir("APPS", 1, &entry));
    enum_mutates = 0;
    assert(!strcmp(enumerated, NLR_PROGRAM_ROOT "APPS"));
    assert(!strcmp(entry.name, "Long Note.txt") && entry.size == 123);
    for (uint32_t n = 14; n < sizeof entry.name; n++) assert(!entry.name[n]);
    assert(!nlr_api.fs_dir(NLR_PROGRAM_ROOT, 2, &entry) && !strcmp(entry.name, "E~1.TXT"));
    assert(nlr_api.fs_dir("", 3, &entry) == -NLR_API_ENOENT);
    /* ABI 9: the card's DCIM may be listed too, and every file name of a
     * directory comes in one pass */
    char dcim[32];
    snprintf(dcim, sizeof dcim, "%.3sDCIM", NLR_PROGRAM_ROOT);
    assert(!nlr_api.fs_dir("/DCIM", 0, &entry) && !strcmp(enumerated, dcim));
    assert(!nlr_api.fs_dir("\\dcim\\100NZ6_3", 1, &entry) && strstr(enumerated, "DCIM\\100NZ6_3") &&
           !strncmp(enumerated, NLR_PROGRAM_ROOT, 3));
    char names[4 * NLR_DIRENT_NAME_MAX];
    uint32_t before = enum_calls;
    assert(nlr_api.fs_dir_names("/DCIM/100NZ6_3", names, 4) == 2 && enum_calls == before + 1);
    assert(!strcmp(names, "Long Note.txt") && !strcmp(names + NLR_DIRENT_NAME_MAX, "E~1.TXT"));
    assert(nlr_api.fs_dir_names("APPS", names, 1) == 1);
    /* a full list is no error whatever the early-stop code; a walk that
     * ends on its own with an unknown code still is */
    early_stop = 0x4321u;
    assert(nlr_api.fs_dir_names("APPS", names, 1) == 1 && !strcmp(names, "Long Note.txt"));
    assert(!nlr_api.fs_dir("", 1, &entry));
    early_stop = 0;
    enum_error = 1;
    assert(nlr_api.fs_dir_names("APPS", names, 4) == -NLR_API_EIO);
    enum_error = 0;
    assert(nlr_api.fs_dir_names("/ETC", names, 4) == -NLR_API_EINVAL);
    assert(nlr_api.fs_dir_names("APPS", 0, 4) == -NLR_API_EINVAL);
    uint32_t calls = enum_calls;
    const char *bad[] = {"..", "APPS/../../DCIM", "C:\\DCIM", "B:\\DCIM", "/DCIMX", "/ETC",
                         "/DCIM/../NLOADER"};
    for (uint32_t n = 0; n < sizeof bad / sizeof bad[0]; n++)
        assert(nlr_api.fs_dir(bad[n], 0, &entry) == -NLR_API_EINVAL);
    assert(enum_calls == calls);
    enum_error = 1;
    assert(nlr_api.fs_dir("", 0, &entry) == -NLR_API_EIO);
    enum_error = 0;
    runtime.load.state = 0;
    assert(nlr_api.fs_dir("", 0, &entry) == -NLR_API_EBUSY && enum_calls == calls + 1);
    runtime.load.state = 2;
    runtime.settings.entry = runtime.checked + 1u;
    assert(nlr_api.setting("test") == 2 && setting_queries == 1);
    runtime.load.program_kind = NLR_KIND_RESOURCE_EXTENSION;
    assert(nlr_api.setting("test") == -NLR_API_EBUSY && setting_queries == 1);
    runtime.load.program_kind = NLR_KIND_FOREGROUND;
    runtime.load.state = 0;
    assert(nlr_api.setting("test") == -NLR_API_EBUSY && setting_queries == 1);
    runtime.load.state = 2;
    const char *rows[] = {"first", "second"};
    runtime.io.list_capacity = 0;
    uint32_t before_missing = delays, before_sequence = runtime.list.seq;
    assert(nlr_api.ui_list("list", rows, 2, 1) == -NLR_API_ENOSYS);
    assert(delays == before_missing && runtime.list.seq == before_sequence && !runtime.io.list_active);
    runtime.io.list_capacity = 1;
    assert(nlr_api.ui_list("list", rows, 2, 1) == -NLR_API_EINVAL);
    assert(delays == before_missing && runtime.list.seq == before_sequence);
    runtime.io.list_capacity = NLR_LIST_ROWS_MAX;
    answer_list = 1;
    assert(nlr_api.ui_list("list", rows, 2, 1) == 1);
    assert(!runtime.load.program.api_active);
    fail_delay = 1;
    assert(nlr_api.ui_list("list", rows, 2, 1) == -NLR_API_EIO);
    assert(!runtime.load.program.api_active);
    fail_delay = 0;

    /* ABI 6: rows of the camera's own kinds. An unknown kind or flag, more
     * rows than a page of kinds holds, or a kind the page cannot draw is
     * refused before anything is published. */
    struct nlr_row kinds[3] = {
        {NLR_ROW_SWITCH, NLR_ROW_ON, "switch", 0},
        {NLR_ROW_SELECT, 0, "choice", "Log3G10"},
        {NLR_ROW_TEXT, 0, "a line", "ignored"},
    };
    runtime.io.list_rows = 0;
    uint32_t before_rows = runtime.list.seq;
    assert(nlr_api.ui_rows("rows", kinds, 3, 0) == -NLR_API_ENOSYS);
    kinds[0].kind = NLR_ROW_TEXT + 1u;
    assert(nlr_api.ui_rows("rows", kinds, 3, 0) == -NLR_API_EINVAL);
    kinds[0].kind = NLR_ROW_SWITCH;
    kinds[1].flags = 4u;
    assert(nlr_api.ui_rows("rows", kinds, 3, 0) == -NLR_API_EINVAL);
    kinds[1].flags = 0;
    assert(nlr_api.ui_rows("rows", kinds, NLR_ROWS_MAX + 1u, 0) == -NLR_API_EINVAL);
    assert(runtime.list.seq == before_rows && !runtime.io.list_active);
    /* Entries alone need no row kinds from the page: as ui_list. */
    const struct nlr_row entries[2] = {
        {NLR_ROW_ENTRY, 0, "first", 0}, {NLR_ROW_ENTRY, 0, "second", 0},
    };
    answer_list = 2;
    assert(nlr_api.ui_rows("rows", entries, 2, 1) == 1);
    assert(runtime.list.rows_view && !strcmp(runtime.list.rows[1], "second"));
    assert(runtime.list.kinds[0] == NLR_ROW_ENTRY && !runtime.list.values[0][0]);
    runtime.io.list_rows = 1;
    answer_list = 2;
    assert(nlr_api.ui_rows("rows", kinds, 3, 0) == 1);
    assert(runtime.list.rows_view && runtime.list.count == 3);
    assert(runtime.list.kinds[0] == NLR_ROW_SWITCH && runtime.list.row_flags[0] == NLR_ROW_ON);
    assert(runtime.list.kinds[1] == NLR_ROW_SELECT && !strcmp(runtime.list.values[1], "Log3G10"));
    assert(runtime.list.kinds[2] == NLR_ROW_TEXT && !runtime.list.values[2][0]);
    assert(!strcmp(runtime.list.rows[2], "a line"));
    assert(!runtime.load.program.api_active && !runtime.io.list_active);
    /* A plain ui_list afterwards is all entries again. */
    answer_list = 1;
    unsigned wakes = list_wakes;
    assert(nlr_api.ui_list("list", rows, 2, 1) == 1);
    /* every published list wakes the menu's task once */
    assert(list_wakes == wakes + 1u);
    assert(!runtime.list.rows_view && runtime.list.kinds[0] == NLR_ROW_ENTRY &&
           !runtime.list.row_flags[0] && !runtime.list.values[1][0]);
    /* The keyboard needs its window installed by the page: none yet. */
    char text[8] = "abc";
    uint32_t before_input = runtime.list.seq;
    assert(nlr_api.ui_input("name", text, sizeof text, NLR_INPUT_ASCII) == -NLR_API_ENOSYS);
    runtime.own.ready = 1;
    /* Room for a character and its NUL, and a character set it offers. */
    assert(nlr_api.ui_input("name", text, 1, NLR_INPUT_ASCII) == -NLR_API_EINVAL);
    assert(nlr_api.ui_input("name", 0, sizeof text, NLR_INPUT_ASCII) == -NLR_API_EINVAL);
    assert(nlr_api.ui_input("name", text, sizeof text, 5u) == -NLR_API_EINVAL);
    assert(runtime.list.seq == before_input && !strcmp(text, "abc"));
    /* A text entry is a list of one row: its title, the text so far as
     * the value. What comes back is cut to the buffer, whatever the
     * answer claims. */
    answer_list = 3;
    assert(nlr_api.ui_input("name", text, sizeof text, NLR_INPUT_UPPER) == 7);
    assert(!strcmp(text, "LONGER-") && runtime.list.seq == before_input + 1u);
    assert(!runtime.load.program.api_active && !runtime.io.list_active);
    /* Given up: NLR_LIST_BACK, the buffer as it was. */
    snprintf(text, sizeof text, "abc");
    answer_list = 4;
    assert(nlr_api.ui_input("name", text, sizeof text, NLR_INPUT_ASCII) == (int32_t)NLR_LIST_BACK);
    assert(!strcmp(text, "abc"));
    /* The caution box: refused until the page installed it, and for
     * unknown buttons; its text is broken into lines of at most
     * NLR_CAUTION_LINE at spaces, and kept to NLR_CAUTION_MAX bytes. */
    uint32_t before_caution = runtime.list.seq;
    assert(nlr_api.ui_caution("x", NLR_CAUTION_OK) == -NLR_API_ENOSYS);
    runtime.own.caution_ready = 1;
    assert(nlr_api.ui_caution(0, NLR_CAUTION_OK) == -NLR_API_EINVAL);
    assert(nlr_api.ui_caution("x", 2u) == -NLR_API_EINVAL);
    assert(runtime.list.seq == before_caution);
    answer_list = 5;
    assert(nlr_api.ui_caution("Write failed. Restart the camera before trying again.",
                              NLR_CAUTION_YES_NO) == 0);
    answer_list = 2;
    assert(nlr_api.ui_caution("Done", NLR_CAUTION_OK) == 1);
    assert(runtime.own.buttons == NLR_CAUTION_OK && !strcmp(runtime.own.message, "Done"));
    answer_list = 4;
    assert(nlr_api.ui_caution("Done", NLR_CAUTION_OK) == (int32_t)NLR_LIST_BACK);
    runtime.own.caution_ready = 0;
    /* A plain ui_list afterwards is not a text entry. */
    answer_list = 1;
    assert(nlr_api.ui_list("list", rows, 2, 1) == 1);
    assert(!runtime.list.dialog && !runtime.list.rows_view);
    runtime.own.ready = 0;
    runtime.io.list_rows = 0;
}

static void native_input_restores_and_passes_every_key(void)
{
    input_callback = original_input;
    nlr_program_io_install(&runtime);
    assert(input_callback == nlr_program_input && runtime.io.hooked);
    assert(!nlr_api.input_raw()); /* Capture starts before the first change. */
    uint32_t object[32] = {0}, saved[32];
    for (uint32_t n = 0; n < 5; n++) {
        object[2 + n] = 1;
        object[7 + n] = 2;
        object[12 + n] = 128;
    }
    memset((uint8_t *)object + 100, 3, 8);
    memcpy(saved, object, sizeof saved);
    input_callback(object);
    assert(!memcmp(object, saved, sizeof object));
    assert(!((uint32_t *)forwarded_input)[2] && !((uint32_t *)forwarded_input)[7]);
    assert(((uint32_t *)forwarded_input)[12] == 128);
    for (uint32_t n = 100; n < 108; n++) assert(!forwarded_input[n]);
    /* MENU reaches the application too (alone it is not the stop chord). */
    assert(nlr_api.input_raw() == (NLR_KEY_UP | NLR_KEY_MENU));
    struct nlr_key_event event = {99, 99};
    assert(nlr_api.input_poll(&event) == 1 && event.key == NLR_KEY_UP && event.down == 1);
    assert(nlr_api.input_poll(&event) == 1 && event.key == NLR_KEY_MENU && event.down == 1);
    assert(!nlr_api.input_poll(&event));
    for (uint32_t n = 0; n < 40; n++) {
        for (uint32_t q = 0; q < 5; q++) object[2 + q] = n & 1u;
        input_callback(object);
    }
    event = (struct nlr_key_event){99, 99};
    assert(nlr_api.input_poll(&event) == -NLR_API_EOVERFLOW);
    assert(event.key == 99 && event.down == 99);
    assert(nlr_api.input_raw() == (NLR_KEY_UP | NLR_KEY_MENU) && !nlr_api.input_poll(&event));
    runtime.io.list_active = 1;
    for (uint32_t n = 0; n < 5; n++) object[2 + n] = 0;
    input_callback(object);
    for (uint32_t n = 0; n < 5; n++) object[2 + n] = 1;
    input_callback(object);
    assert(((uint32_t *)forwarded_input)[2] == 1);
    runtime.io.list_active = 0;
    assert(!nlr_api.input_poll(&event));
    nlr_program_io_release(&runtime);
}

/* mem_reserved (ABI 7): the description's `memory` taken whole at the
 * first call and the same block on later calls; a heap without a block
 * that large gives nothing and says 0 bytes -- never a smaller block; a
 * program that declared none gets nothing; the reservation ends with the
 * program (its allocation goes with the program's others). */
static void mem_reserved_whole_or_nothing(void)
{
    runtime.load.abi_version = 7u;
    uint32_t bytes = 1;
    runtime.load.meta_memory = 0;
    assert(nlr_api.mem_reserved(&bytes) == 0 && bytes == 0);
    runtime.load.meta_memory = 0x4000;
    uint8_t *block = nlr_api.mem_reserved(&bytes);
    assert(block && bytes == 0x4000);
    block[0] = 1;
    block[0x3fff] = 2;
    bytes = 0;
    assert(nlr_api.mem_reserved(&bytes) == block && bytes == 0x4000);
    assert(nlr_api.mem_reserved(0) == block);
    assert(!nlr_api_program_cleanup(&runtime.load.program));
    assert(!runtime.plat.reserved && !runtime.plat.reserved_bytes);
    /* larger than any block this heap gives: nothing, never part of it */
    runtime.load.meta_memory = 0xfff00000u;
    bytes = 1;
    assert(nlr_api.mem_reserved(&bytes) == 0 && bytes == 0);
    assert(!runtime.plat.reserved);
    runtime.load.meta_memory = 0;
    runtime.load.abi_version = 4u;
}

int main(void)
{
    initialize();
    mem_reserved_whole_or_nothing();
    assert(nlr_api.abi == 9u && sizeof(struct nlr_api) == 432u);
    /* ABI 7, 8 and 9 append; every earlier field keeps its offset. */
    assert(offsetof(struct nlr_api, ui_caution) == 216u &&
           offsetof(struct nlr_api, queue_wait) == 224u &&
           offsetof(struct nlr_api, platform_caps) == 344u &&
           offsetof(struct nlr_api, named) == 352u &&
           offsetof(struct nlr_api, bus_i2c) == 408u &&
           offsetof(struct nlr_api, queue_post) == 416u &&
           offsetof(struct nlr_api, fs_dir_names) == 424u);
    legacy_outputs_remain_untouched();
    surface_lifecycle_and_conversion();
    later_abi_keeps_screen_and_buttons();
    platform_screen_in_the_graphics_build();
    directory_and_list_contract();
    native_input_restores_and_passes_every_key();
    now = UINT64_C(0x100000005);
    assert(nlr_api.time_ms() == 5u);
    nlr_api.sleep_ms(1015);
    assert(now == UINT64_C(0x1000003fc) && delays > 100u);
    uint32_t before_yield = delays;
    nlr_api.sleep_ms(0);
    assert(delays == before_yield + 1u && now == UINT64_C(0x1000003fd));
    fail_clock = 1;
    assert(!nlr_api.time_ms());
    expect_stop = 1;
    if (!setjmp(stopped)) { nlr_api.sleep_ms(1); assert(0); }
    assert(runtime.load.program.exit_requested && runtime.load.program.exit_code == -NLR_API_EIO);
    assert(!runtime.load.program.api_active);
    puts("ABI 4 surface conversion, directory limits, list waits and time checks passed");
    return 0;
}
