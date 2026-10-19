/* ABI 4 acceptance program: the card write channel and the firmware-code
 * channel, on the dead thunk target.h describes.
 *
 * Every step records what it saw, nothing stops at the first surprise, and
 * the whole record is written to CODET.TXT on the card: the file is both
 * the result of the write channel and the evidence for the code channel.
 * The returned value is the first step that did not behave, or 0.
 *
 *   1 the target before anything is patched, and the extension's hook
 *     removed when one is found installed (which is what proves a hook
 *     outlives the program that installed it)
 *   2 code_patch changes one instruction and the target follows it
 *   3 code_patch puts the original instruction back
 *   4 a hook replaces the target
 *   5 code_unhook restores it
 *   6 a hook whose handler continues into the overwritten instructions
 *   7 code_unhook again
 *   8 the refusals: outside the window, a partial instruction, the wrong
 *     expected bytes, a second hook on one target, unhooking nothing
 *   9 the card: the record below, written and read back
 *  10 a hook left installed on purpose, with its handler in this
 *     program's own image: the loader has to take it off when the
 *     program's memory goes back, and the next run is the evidence --
 *     seeing NLR_TEST_LEFT at step 1 would mean the camera was one call
 *     away from branching into freed memory
 */

#include "nlr.h"

#include "target.h"

/* The continuation of the hooked target: the four instructions the detour
 * overwrote, then a branch past the detour. Only the first two are ever
 * reached here, because the second one is the target's own RET. */
NLR_HOOK_CONTINUE(target_continue, NLR_TEST_TARGET, NLR_TEST_W0, NLR_TEST_W1,
                  NLR_TEST_W2, NLR_TEST_W3)

static uint64_t replace_handler(uint64_t value)
{
    (void)value;
    return NLR_TEST_REPLACE;
}

static uint64_t continue_handler(uint64_t value)
{
    uint64_t (*original)(uint64_t) = (uint64_t (*)(uint64_t))target_continue;
    return original(value + 10u);
}

/* The handler of the hook this program installs and never removes. */
static uint64_t left_handler(uint64_t value)
{
    (void)value;
    return NLR_TEST_LEFT;
}

/* The first run writes the first file; a later run finds it there and
 * writes the second, so both records survive on the card. */
static const char note_path[] = "CODET.TXT";
static const char note_path_2[] = "CODET2.TXT";

/* The record: one line per observation, "<name> <hex>". A program keeps no
 * writable static data; the record lives on the caller's stack. */
#define RECORD_BYTES 640u
struct record {
    char text[RECORD_BYTES];
    uint32_t used;
    int32_t failed; /* the step that failed first, 0 while all behaved */
};

static void put_text(struct record *r, const char *text)
{
    while (*text && r->used < RECORD_BYTES - 1u)
        r->text[r->used++] = *text++;
}

static void put_hex(struct record *r, uint64_t value)
{
    char digits[16];
    uint32_t n = 0;
    do {
        uint32_t digit = (uint32_t)(value & 15u);
        digits[n++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
        value >>= 4;
    } while (value && n < sizeof digits);
    while (n)
        if (r->used < RECORD_BYTES - 1u)
            r->text[r->used++] = digits[--n];
        else
            n--;
}

static void note(struct record *r, const char *name, uint64_t value)
{
    put_text(r, name);
    put_text(r, " ");
    put_hex(r, value);
    put_text(r, "\n");
}

static void expect(struct record *r, int32_t step, uint64_t seen,
                   uint64_t wanted, const char *name)
{
    note(r, name, seen);
    if (seen != wanted && !r->failed)
        r->failed = step;
}

int32_t nlr_app_main(const struct nlr_api *api)
{
    if (!api || api->abi > NLR_ABI_VERSION)
        return 1;
    if (!api->code_patch || !api->code_hook || !api->code_unhook ||
        !api->fs_write) {
        api->ui_draw_text(0, 0, "code: no ABI 4 table");
        return 1;
    }
    struct record rec;
    rec.used = 0;
    rec.failed = 0;
    note(&rec, "abi", api->abi);

    /* 1: what the target does now. A hook found installed is the resource
     * extension's, still there after its entry returned; it belongs to the
     * loader, so this program may take it off. */
    uint64_t first = nlr_test_call(1);
    note(&rec, "call.first", first);
    /* A hook an earlier run of this program left behind must not be
     * there: the loader removes it with the memory it points into. */
    if (first == NLR_TEST_LEFT)
        rec.failed = 10;
    int found_extension = first == NLR_TEST_REPLACE;
    if (found_extension)
        expect(&rec, 1, (uint64_t)(int64_t)api->code_unhook((void *)NLR_TEST_TARGET),
               0, "unhook.ext");
    expect(&rec, 1, nlr_test_call(1), NLR_TEST_PLAIN, "call.plain");

    /* 2, 3: one instruction, changed and put back. ADD X0, X0, #2. */
    static const unsigned char plus_two[4] = { 0x00, 0x08, 0x00, 0x91 };
    expect(&rec, 2, (uint64_t)(int64_t)api->code_patch((void *)NLR_TEST_TARGET,
                                                 plus_two, 4),
           0, "patch.two");
    expect(&rec, 2, nlr_test_call(1), NLR_TEST_PLAIN + 1u, "call.two");
    expect(&rec, 3, (uint64_t)(int64_t)api->code_patch((void *)NLR_TEST_TARGET,
                                                 nlr_test_expect, 4),
           0, "patch.back");
    expect(&rec, 3, nlr_test_call(1), NLR_TEST_PLAIN, "call.back");

    /* 4, 5: a hook that replaces the function. */
    expect(&rec, 4, (uint64_t)(int64_t)api->code_hook((void *)NLR_TEST_TARGET,
                                                nlr_test_expect,
                                                (void *)replace_handler),
           0, "hook.replace");
    expect(&rec, 4, nlr_test_call(1), NLR_TEST_REPLACE, "call.replace");
    expect(&rec, 5, (uint64_t)(int64_t)api->code_unhook((void *)NLR_TEST_TARGET), 0,
           "unhook.replace");
    expect(&rec, 5, nlr_test_call(1), NLR_TEST_PLAIN, "call.unhooked");

    /* 6, 7: a hook that continues into what it replaced: ten from the
     * handler and one from the original instruction. */
    expect(&rec, 6, (uint64_t)(int64_t)api->code_hook((void *)NLR_TEST_TARGET,
                                                nlr_test_expect,
                                                (void *)continue_handler),
           0, "hook.continue");
    expect(&rec, 6, nlr_test_call(1), 1u + 10u + 1u, "call.continue");
    expect(&rec, 7, (uint64_t)(int64_t)api->code_unhook((void *)NLR_TEST_TARGET), 0,
           "unhook.continue");
    expect(&rec, 7, nlr_test_call(1), NLR_TEST_PLAIN, "call.restored");

    /* 8: what the channel refuses. The first address is the loader's own
     * read-only window, the second is not a whole instruction, the third
     * does not hold the bytes the program was built for. */
    expect(&rec, 8, (uint64_t)(int64_t)api->code_patch((void *)0x40196000UL,
                                                 nlr_test_expect, 4),
           (uint64_t)(int64_t)-NLR_API_EINVAL, "refuse.window");
    expect(&rec, 8, (uint64_t)(int64_t)api->code_patch((void *)NLR_TEST_TARGET,
                                                 nlr_test_expect, 3),
           (uint64_t)(int64_t)-NLR_API_EINVAL, "refuse.partial");
    expect(&rec, 8, (uint64_t)(int64_t)api->code_hook((void *)NLR_TEST_TARGET,
                                                plus_two,
                                                (void *)replace_handler),
           (uint64_t)(int64_t)-NLR_API_EINVAL, "refuse.expect");
    expect(&rec, 8, (uint64_t)(int64_t)api->code_unhook((void *)NLR_TEST_TARGET),
           (uint64_t)(int64_t)-NLR_API_ENOENT, "refuse.unhooked");
    expect(&rec, 8, (uint64_t)(int64_t)api->code_hook((void *)NLR_TEST_TARGET,
                                               nlr_test_expect,
                                               (void *)replace_handler),
           0, "hook.again");
    expect(&rec, 8, (uint64_t)(int64_t)api->code_hook((void *)NLR_TEST_TARGET,
                                               nlr_test_expect,
                                               (void *)replace_handler),
           (uint64_t)(int64_t)-NLR_API_EBUSY, "refuse.twice");
    expect(&rec, 8, (uint64_t)(int64_t)api->code_unhook((void *)NLR_TEST_TARGET), 0,
           "unhook.again");

    /* Whatever happened above, the firmware goes back to its own bytes
     * before this program ends: nothing of ours stays in the camera's
     * code. */
    note(&rec, "restore",
         (uint64_t)(int64_t)api->code_patch((void *)NLR_TEST_TARGET,
                                            nlr_test_expect, 16));
    note(&rec, "call.end", nlr_test_call(1));

    /* 10: and one hook that stays. Its handler is in this program's
     * image, which goes back to the allocator the moment the program
     * ends, so the loader has to remove it whether the program asked or
     * not. Nothing here undoes it; the next run reads the target. */
    expect(&rec, 10, (uint64_t)(int64_t)api->code_hook((void *)NLR_TEST_TARGET,
                                                 nlr_test_expect,
                                                 (void *)left_handler),
           0, "hook.left");
    expect(&rec, 10, nlr_test_call(1), NLR_TEST_LEFT, "call.left");

    note(&rec, "ext", (uint64_t)found_extension);
    note(&rec, "failed", (uint64_t)(uint32_t)rec.failed);

    /* 9: the card. The record goes out, comes back and is compared. */
    uint32_t length = rec.used;
    const char *path = note_path;
    int existing = api->fs_open(note_path, NLR_OPEN_READ);
    if (existing >= 0) {
        api->fs_close(existing);
        path = note_path_2;
    }
    int fd = api->fs_open(path, NLR_OPEN_WRITE);
    if (fd < 0) {
        api->log("code: open %d", fd);
        api->ui_draw_text(0, 0, "code: card open failed");
        return rec.failed ? rec.failed : 9;
    }
    int written = api->fs_write(fd, rec.text, length);
    int closed = api->fs_close(fd);
    if (written != (int)length || closed != 0) {
        api->log("code: write %d %d", written, closed);
        api->ui_draw_text(0, 0, "code: card write failed");
        return rec.failed ? rec.failed : 9;
    }
    char back[640];
    fd = api->fs_open(path, NLR_OPEN_READ);
    int got = fd < 0 ? fd : api->fs_read(fd, back, (uint32_t)sizeof back);
    if (fd >= 0)
        api->fs_close(fd);
    if (got != (int)length) {
        api->log("code: read %d", got);
        api->ui_draw_text(0, 0, "code: card read failed");
        return rec.failed ? rec.failed : 9;
    }
    for (uint32_t n = 0; n < length; n++)
        if (back[n] != rec.text[n]) {
            api->ui_draw_text(0, 0, "code: card compare failed");
            return rec.failed ? rec.failed : 9;
        }

    if (rec.failed) {
        api->log("code: step %d", rec.failed);
        api->log("code: %d bytes", (int)length);
        api->ui_draw_text(0, 0, "code: see CODET.TXT");
        return rec.failed;
    }
    api->log("code: ok %d bytes", (int)length);
    api->ui_draw_text(0, 0, found_extension ? "code+write ok, ext hook found"
                                            : "code+write ok, no ext hook");
    return 0;
}
