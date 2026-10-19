#ifndef NLR_H
#define NLR_H

#include <stdint.h>

/*
 * Camera program SDK for general NPLD v2 programs (PLAN 6.4, appendix B).
 *
 * The loader passes the API table in x0 when it calls the program's entry.
 * The field order and types below are the cross-language ABI contract: they
 * stay byte-identical with core's `struct nlr_api` (core/include/nlr/api.h),
 * and the table only ever grows at the end (existing fields keep position,
 * type and meaning). The loader fills `abi`; a program must refuse a table
 * whose version is older than the version it needs, and may only call
 * fields its own abi_version guarantees. ABI 4 replaces the incompatible
 * experimental ABI 3 layouts; old ABI 3 programs must not use this table.
 *
 * Every call goes through the table; a program never holds firmware
 * addresses. The data layouts below are part of the loader's ABI.
 */

/* Runtime API-table version this header describes. ABI 4 added directory
 * listing, native lists and settings, and fixed the new surface/key/time
 * layouts; ABI 5 adds card writing and the firmware-code channel; ABI 6
 * adds the camera's own row kinds (switch, choice, text), its keyboard and
 * its caution box; ABI 7 adds the platform: one event queue with every control, the dials, timers and watched
 * settings, the screen claimed over the live picture and given back, the
 * camera's settings read by item, and a service's own tasks; ABI 8 the
 * firmware by name (families E and F): hook points, data tables, firmware
 * functions and devices the body's profile names.
 * Programs built for the experimental ABI 3 are incompatible. */
#define NLR_ABI_VERSION 9u

/* fs_seek whence values. Only 0 (set) and 2 (end) are supported;
 * 1 (current) is refused with -NLR_API_EINVAL. */
#define NLR_SEEK_SET 0
#define NLR_SEEK_END 2

/* Result conventions (shared verbatim with core/include/nlr/api.h): the
 * values are the standard errno numbers; any negative fs result is a
 * failure, and a program may compare against these constants. */
#define NLR_API_ENOENT    2
#define NLR_API_EIO       5
#define NLR_API_ENODEV    19 /* ABI 7: the loader's card slot is empty */
#define NLR_API_EBADF     9
#define NLR_API_EACCES    13
#define NLR_API_EBUSY     16
#define NLR_API_EINVAL    22
#define NLR_API_ENOSYS    38
#define NLR_API_EOVERFLOW 75

/* Paths are relative to the loader's configured card root; an absolute path
 * with exactly that prefix is accepted as-is, everything else is prefixed.
 * Path traversal (".."), other drive letters, empty paths and relative
 * portions longer than NLR_API_PATH_MAX (64 bytes, excluding the root) are
 * refused with -NLR_API_EINVAL: the channel cannot
 * leave the configured directory (PLAN appendix B). Portable programs should
 * use relative paths, because the directory and card slot can vary.
 * ABI 9: one exception, for showing the card's pictures. A path that
 * starts with "/DCIM" names the DCIM folder of the loader's own card,
 * read-only: fs_open for reading, fs_dir and fs_dir_names; a write there
 * is refused with -NLR_API_EACCES. */
#define NLR_API_PATH_MAX 64u

/* Bound for one log call: a longer message is truncated and its full
 * length recorded in the loader's trace. */
#define NLR_API_LOG_MAX 32u

/* The shared types are spelled identically in sdk/nlr.h and
 * core/include/nlr/api.h; one guard lets a unit include both. */
#ifndef NLR_ABI4_TYPES
#define NLR_ABI4_TYPES
/* Pixel surface (ABI 4). gfx_begin hands the program the screen in the
 * display's own format; the program writes `pixels` (and `alpha`, when the
 * format has one) and calls ui_present to show the frame. */
#define NLR_SURFACE_Y0Y1UV_A8 1u /* 4:2:2: bytes Y0 Y1 U V per pixel pair
                                  * (BT.601, U/V offset 128), plus a
                                  * one-byte alpha plane (255 = opaque) */
struct nlr_surface {
    uint32_t format;        /* NLR_SURFACE_* */
    uint32_t width;         /* visible pixels */
    uint32_t height;
    uint32_t stride;        /* bytes from one row of `pixels` to the next */
    uint8_t *pixels;
    uint8_t *alpha;         /* 0 when the format has no alpha plane */
    uint32_t alpha_stride;
    uint32_t reserved;
};

/* Buttons (ABI 4): input_raw returns the held ones as a mask of these bits,
 * input_poll reports one change at a time. An unsupported button leaves
 * its bit at 0; Z8 does not synthesize the new half/full/i buttons from
 * unrelated original input bits. MENU/DELETE remain loader exit keys. */
#define NLR_KEY_UP        (1u << 0)
#define NLR_KEY_DOWN      (1u << 1)
#define NLR_KEY_LEFT      (1u << 2)
#define NLR_KEY_RIGHT     (1u << 3)
#define NLR_KEY_OK        (1u << 4)
#define NLR_KEY_MENU      (1u << 5)
#define NLR_KEY_PLAY      (1u << 6)
#define NLR_KEY_DELETE    (1u << 7)
#define NLR_KEY_INFO      (1u << 8)   /* i */
#define NLR_KEY_DISP      (1u << 9)
#define NLR_KEY_ZOOM_IN   (1u << 10)
#define NLR_KEY_ZOOM_OUT  (1u << 11)
#define NLR_KEY_AF_ON     (1u << 12)
#define NLR_KEY_HALF      (1u << 13)  /* shutter half-press */
#define NLR_KEY_FULL      (1u << 14)  /* shutter full press */
struct nlr_key_event {
    uint32_t key;           /* one NLR_KEY_* bit */
    uint32_t down;          /* 1 pressed, 0 released */
};

/* Directory entry (ABI 4), as fs_dir reports it. */
#define NLR_DIRENT_NAME_MAX 64u
#define NLR_DIRENT_DIR      1u
struct nlr_dirent {
    char name[NLR_DIRENT_NAME_MAX]; /* NUL-terminated ASCII, usable in a
                                     * path: the long name when it is
                                     * printable ASCII and fits, else the
                                     * card's 8.3 name */
    uint64_t size;
    uint32_t flags;                 /* NLR_DIRENT_DIR */
    uint32_t reserved;
};

/* Native list (ABI 4, ui_list): its limits and the back result. */
#define NLR_LIST_ROWS_MAX 64u
#define NLR_LIST_TEXT_MAX 50u       /* bytes a row or the title keeps */
#define NLR_LIST_BACK     0x7fffffff

/* Rows of the camera's own kinds (ABI 6, ui_rows), each drawn the way the
 * camera's menus draw theirs. */
#define NLR_ROW_ENTRY  0u /* a row with the > mark: OK chooses it */
#define NLR_ROW_SWITCH 1u /* the camera's ON / OFF toggle switch */
#define NLR_ROW_SELECT 2u /* `value`, the current choice, at the right */
#define NLR_ROW_TEXT   3u /* a line of text the cursor never lands on */
#define NLR_ROW_ON     1u /* flags: a switch that is on */
#define NLR_ROW_GREYED 2u /* flags: shown greyed; the cursor passes it */
#define NLR_ROWS_MAX   32u
struct nlr_row {
    uint32_t kind;          /* NLR_ROW_* */
    uint32_t flags;         /* NLR_ROW_ON, NLR_ROW_GREYED */
    const char *label;      /* at most NLR_LIST_TEXT_MAX bytes kept */
    const char *value;      /* NLR_ROW_SELECT: the value column's text */
};

/* Characters the camera's keyboard offers (ABI 6, ui_input). */
#define NLR_INPUT_ASCII    3u /* every printable ASCII character */
#define NLR_INPUT_UPPER    2u /* 0-9, A-Z and _ */
#define NLR_INPUT_DIGITS   6u /* 0-9 */
#define NLR_INPUT_MAX      254u

/* The camera's caution box (ABI 6, ui_caution): the "!" box over the
 * page, with OK, or with Yes and No. */
#define NLR_CAUTION_OK     0u  /* a message: OK closes it */
#define NLR_CAUTION_YES_NO 1u  /* a question: Yes or No, the cursor on No */
#define NLR_CAUTION_MAX    50u /* bytes of text it shows */
#define NLR_CAUTION_LINE   28u /* longest line; longer ones break at a space */

/* fs_open access (ABI 5). READ is the only one earlier versions defined;
 * WRITE creates the file when it is missing and truncates it when it is
 * not; UPDATE needs an existing file and neither creates nor truncates. */
#define NLR_OPEN_READ   0u
#define NLR_OPEN_WRITE  1u
#define NLR_OPEN_UPDATE 2u

/* Firmware-code channel (ABI 5). The patched bytes must sit in the writable
 * code window the loader declares, start on an instruction and be a whole
 * number of instructions; one call patches at most NLR_CODE_PATCH_MAX bytes
 * inside a single cache line, so instruction fetch on every core switches
 * from all the old bytes to all the new ones. A hook is one 16-byte
 * absolute detour: two instructions that load the handler's address from
 * the eight bytes behind them and branch to it. */
#define NLR_CODE_PATCH_MAX  64u
#define NLR_CODE_HOOK_BYTES 16u
#define NLR_CODE_HOOKS_MAX  16u

/* The continuation of a hooked function, for a handler that has to call
 * what it replaced: a function that runs the four instructions the detour
 * overwrote and then branches to `target` + NLR_CODE_HOOK_BYTES. The four
 * words are the same ones passed to code_hook as `expect`, so the two
 * cannot drift apart. They run from a different address, which is why
 * code_hook refuses position-dependent ones.
 *
 *   NLR_HOOK_CONTINUE(original_sub_x, 0x40e9dbdcUL,
 *                     0xa9bd7bfdU, 0x910003fdU, 0xa90153f3U, 0xaa0003f3U);
 *   static void handler(void *a) { log_it(a); original_sub_x(a); }
 *
 * The declared type is the hooked function's own: cast the symbol to it. */
#define NLR_HOOK_CONTINUE(name, target, w0, w1, w2, w3)                    \
    __attribute__((naked, noinline)) static void name(void)                \
    {                                                                      \
        __asm__ volatile(".inst %c0\n.inst %c1\n.inst %c2\n.inst %c3\n"    \
                         "ldr x16, 1f\nbr x16\n"                           \
                         ".balign 8\n1: .quad %c4\n"                       \
                         ::"i"(w0), "i"(w1), "i"(w2), "i"(w3),             \
                           "i"((unsigned long)(target) + 16UL));          \
    }
#endif /* NLR_ABI4_TYPES */

/* ABI 7 types, shared verbatim with core/include/nlr/platform.h. */
#ifndef NLR_ABI7_TYPES
#define NLR_ABI7_TYPES
/* Logical controls. The first fifteen are the NLR_KEY_* bits in the same
 * order, so key bit n and control n are one button. A body that lacks a
 * control never reports it. */
enum nlr_ctl {
    NLR_CTL_UP, NLR_CTL_DOWN, NLR_CTL_LEFT, NLR_CTL_RIGHT, NLR_CTL_OK,
    NLR_CTL_MENU, NLR_CTL_PLAY, NLR_CTL_DELETE, NLR_CTL_INFO, NLR_CTL_DISP,
    NLR_CTL_ZOOM_IN, NLR_CTL_ZOOM_OUT, NLR_CTL_AF_ON, NLR_CTL_HALF,
    NLR_CTL_FULL,
    NLR_CTL_SUB_UP, NLR_CTL_SUB_DOWN, NLR_CTL_SUB_LEFT, NLR_CTL_SUB_RIGHT,
    NLR_CTL_SUB_PRESS,
    NLR_CTL_FN1, NLR_CTL_FN2, NLR_CTL_FN_V, NLR_CTL_MOVIE, NLR_CTL_ISO,
    NLR_CTL_EXP_COMP, NLR_CTL_RELEASE_MODE, NLR_CTL_ILLUMINATE,
    NLR_CTL_AF_ON_V, NLR_CTL_REMOTE_FN,
    /* Not buttons: they report through other event types. */
    NLR_CTL_DIAL_MAIN = 40, NLR_CTL_DIAL_SUB, NLR_CTL_LENS_RING,
    NLR_CTL_TOUCH = 48, NLR_CTL_EYE,
    NLR_CTL_COUNT = 64
};

/* Where a control goes while a program has the input (input_route): to the
 * camera only, to the program only (the camera never sees it), or to both.
 * A program that takes the input starts with every control routed to it
 * alone; the shell (the program the boot started) starts with the
 * shutter's half and full press going to both, so focus and capture keep
 * working. The power switch always stays the camera's, and MENU with
 * DELETE together stays the loader's stop. */
#define NLR_ROUTE_CAMERA  0u
#define NLR_ROUTE_PROGRAM 1u
#define NLR_ROUTE_BOTH    2u

/* One event (queue_wait). `t_ms` is time_ms when the loader saw it. */
#define NLR_EV_CONTROL  1u /* code: NLR_CTL_*; value: 1 pressed, 0 released */
#define NLR_EV_DIAL     2u /* code: NLR_CTL_DIAL_* / LENS_RING; value: clicks,
                            * positive clockwise as the user sees the dial */
#define NLR_EV_TOUCH    3u /* code: NLR_TOUCH_*; x, y in screen pixels */
#define NLR_EV_PROP     4u /* code: item id; value: the item's first four
                            * bytes, little endian (prop_get has all of it) */
#define NLR_EV_TIMER    5u /* code: the timer; value: its tag */
#define NLR_EV_CARD     6u /* code: slot; value: 1 present, 0 gone */
#define NLR_EV_SCREEN   7u /* code: NLR_SCREEN_*; value: 1 shown, 0 taken away */
#define NLR_EV_OVERFLOW 8u /* events were lost: read the state again */
#define NLR_EV_EYE      9u /* value: 1 an eye at the finder, 0 gone */
#define NLR_EV_POSTED  10u /* queue_post: code and value are the program's */

#define NLR_TOUCH_UP   0u
#define NLR_TOUCH_DOWN 1u
#define NLR_TOUCH_MOVE 2u

struct nlr_event {
    uint16_t type;          /* NLR_EV_* */
    uint16_t code;
    int32_t value;
    int16_t x;
    int16_t y;
    uint32_t t_ms;
};

#define NLR_SCREEN_REAR 0u
#define NLR_SCREEN_EVF  1u

struct nlr_rect {
    uint16_t x, y, width, height;
};

/* An item of the camera's settings and status store (prop_info). */
#define NLR_PROP_READ  1u   /* prop_get reads it */
#define NLR_PROP_WRITE 2u   /* prop_set accepts it on this body */
struct nlr_prop_info {
    uint16_t id;
    uint16_t size;          /* bytes prop_get returns */
    uint32_t flags;         /* NLR_PROP_* */
};

/* What this body and loader provide (platform_caps): a program checks a bit
 * before it relies on the matching events or calls. */
#define NLR_CAP_CONTROLS   (1u << 0) /* controls beyond the fifteen keys */
#define NLR_CAP_DIALS      (1u << 1)
#define NLR_CAP_TOUCH      (1u << 2)
#define NLR_CAP_EYE        (1u << 3)
#define NLR_CAP_SCREEN     (1u << 4) /* screen_claim of the rear screen */
#define NLR_CAP_EVF        (1u << 5)
#define NLR_CAP_PROPS      (1u << 6) /* prop_get / prop_watch */
#define NLR_CAP_PROP_SET   (1u << 7)
#define NLR_CAP_TASKS      (1u << 8)
#define NLR_CAP_CARD       (1u << 9)
#define NLR_CAP_RESERVED   (1u << 10) /* mem_reserved */

#define NLR_QUEUE_FOREVER  0xffffffffu
#define NLR_TIMERS_MAX     8u
#define NLR_WATCH_MAX      64u
#define NLR_PROP_BYTES_MAX 256u
#endif /* NLR_ABI7_TYPES */

/* ABI 8 types, shared verbatim with core/include/nlr/platform.h. */
#ifndef NLR_ABI8_TYPES
#define NLR_ABI8_TYPES
/* ABI 8: the firmware by name. A name
 * is resolved by the body's profile, which carries its address, size and
 * fingerprint; a program never holds the address. */
#define NLR_NAMED_POINT    1u /* a hook point: hook_attach */
#define NLR_NAMED_TABLE    2u /* a data table: table_read / table_write */
#define NLR_NAMED_FUNCTION 3u /* a firmware function: fw_fn */
#define NLR_NAMED_DEVICE   4u /* a device on a bus: bus_i2c */
/* A table's class (nlr_named.flags low byte): where its bytes live and so
 * how the loader can change them. */
#define NLR_TABLE_RAM     0u /* RAM: written in place */
#define NLR_TABLE_TEXT    1u /* the firmware's code window: written through
                              * its writable alias, whole instructions */
#define NLR_TABLE_REPACK  2u /* flash or unmapped: only a firmware repack */
#define NLR_TABLE_POINTER 3u /* a RAM slot pointing at read-only data: a
                              * write goes to the loader's RAM copy, and the
                              * slot is pointed at it */
#define NLR_NAMED_STOCK   0x100u /* flags: the table holds its stock bytes */
#define NLR_NAMED_CHANGED 0x200u /* flags: written this boot (by anyone) */
struct nlr_named {
    uint32_t kind;          /* NLR_NAMED_* */
    uint32_t flags;         /* NLR_TABLE_* | NLR_NAMED_STOCK | _CHANGED */
    uint32_t size;          /* a table's bytes; a point's argument count */
    uint32_t crc;           /* a table's stock CRC-32 */
};
#endif /* NLR_ABI8_TYPES */

/* Minimal deferred menu request: label_id names an existing firmware
 * string, not a loader-owned runtime text slot. */
struct nlr_menu_test_item {
    uint32_t label_id;
    uint32_t item_id;
};

struct nlr_api {
    uint32_t abi; /* set by the loader; add-only table (appendix B) */

    /* Memory: owned by the program for its lifetime; attrs are
     * loader-defined allocation attributes. */
    void *(*mem_alloc)(uint32_t size, uint32_t attrs);
    void (*mem_free)(void *p);

    /* Files: access is confined to the configured root (see the path rules above).
     * fs_open returns the file handle (>= 0) or a negative error. mode is
     * NLR_OPEN_READ, or (ABI 5) NLR_OPEN_WRITE to create and truncate and
     * NLR_OPEN_UPDATE to read and write an existing file in place; another
     * value is refused with -NLR_API_EINVAL, and writing without the
     * model's write services with -NLR_API_ENOSYS. The loader's own files
     * (MANIFEST, ENABLED, SAFE_MODE and the interruption marker) can be
     * read but never opened for writing: -NLR_API_EACCES. */
    int (*fs_open)(const char *path, uint32_t mode);
    /* fs_read returns the number of bytes read, or a negative error. A
     * short read is retryable; a zero-byte result is an error, because the
     * normalized service family cannot report end-of-file. len == 0
     * returns 0 without touching the card. */
    int (*fs_read)(int fd, void *buf, uint32_t len);
    /* fs_seek returns the new absolute position or a negative error.
     * whence 0 (NLR_SEEK_SET) and 2 (NLR_SEEK_END) are supported;
     * 1 (current) is refused. */
    int (*fs_seek)(int fd, int64_t off, int whence);
    /* fs_close releases a handle: 0 on success, -1 on failure. After a
     * successful close the handle is invalid. */
    int (*fs_close)(int fd);

    /* Text channel: copies bounded text into the loader-owned result row.
     * x/y are currently ignored. A natural GUI refresh displays the latest
     * text; this call does not redraw from the program worker. The row
     * belongs to the run: it starts empty at each start, and a call from a
     * resident's service task or after the run fails with -NLR_API_EBUSY.
     * ui_present returns -NLR_API_ENOSYS until a cross-task refresh is
     * verified. */
    int (*ui_draw_text)(int x, int y, const char *s);
    int (*ui_present)(void);

    /* Pixel channel: display-native planes owned by the loader. Present
     * writes through ui_present; gfx_end releases the screen. Do not write
     * through a returned surface after release. Missing services fail with
     * -NLR_API_ENOSYS. */
    int (*gfx_begin)(struct nlr_surface *out);
    int (*gfx_end)(void);

    /* Input: the loader pre-filters global exit combinations. poll returns
     * 1 event, 0 empty or a negative error; output is unchanged on 0/error.
     * EOVERFLOW discards history: recover held keys from raw before polling
     * again. raw reports held NLR_KEY_* bits, or 0 without this channel. */
    int (*input_poll)(struct nlr_key_event *ev);
    uint32_t (*input_raw)(void);

    /* Logging: bounded (see NLR_API_LOG_MAX). Writes into the loader's RAM
     * trace ring, not to the card; keep format strings constant and small. */
    void (*log)(const char *fmt, ...);
    /* Exit: foreground applications only. It records the code and leaves
     * the application without returning into it. A resource extension
     * calling it is recorded in the trace and ignored; it is not an
     * extension stop interface. */
    void (*exit)(int code);

    /* Worker-side RAM request during resource-extension initialization.
     * Returns 0 on acceptance or a negative NLR_API_E* error; the menu task
     * publishes on next page enter, not during this call. Requests survive
     * a later initialization failure and publishing may have partial
     * effects. No injected publisher means -NLR_API_ENOSYS. */
    int (*menu_register)(const struct nlr_menu_test_item *item);

    /* ---- ABI 4 ---- */
    /* Milliseconds since the camera started; wraps after ~49 days. */
    uint32_t (*time_ms)(void);
    /* Give the CPU to other tasks for at least `ms` milliseconds (0: just
     * yield). A program that waits must sleep, never spin: the program
     * task outranks the camera's GUI. */
    void (*sleep_ms)(uint32_t ms);
    /* Directory listing, read-only, confined to the configured card root.
     * Empty path lists that root; other paths follow fs_open path rules.
     * Fills entry `index` (0, 1, ...) and returns 0,
     * or a negative error: -NLR_API_ENOENT past the last entry or for a
     * missing directory/card. */
    int (*fs_dir)(const char *path, uint32_t index, struct nlr_dirent *out);
    /* A list on the camera's own menu page, in its font and colours:
     * `count` rows (at most NLR_LIST_ROWS_MAX, each cut at
     * NLR_LIST_TEXT_MAX bytes; a null row is empty) under `title`, the
     * cursor on `selected`. Waits for the user and returns the row chosen
     * with OK, NLR_LIST_BACK for back, or a negative error. The texts are
     * copied. While the page stays open it keeps its longest length, so a
     * shorter list ends in empty rows. Not while the program holds the
     * screen (gfx_begin): -NLR_API_EBUSY. A profile without dynamic native
     * rows and the corresponding stay/reply route returns -NLR_API_ENOSYS
     * before publishing or waiting. Counts beyond the connected page's
     * capacity return -NLR_API_EINVAL. */
    int32_t (*ui_list)(const char *title, const char *const *rows,
                       uint32_t count, uint32_t selected);
    /* The program's setting `key`: the index of its current choice, as the
     * NLoader page's Settings view leaves it (the program's .json declares
     * them; `nloader program` writes <name>.SET beside the program), or
     * -NLR_API_ENOENT without such a setting. */
    int32_t (*setting)(const char *key);

    /* ---- ABI 5 ---- */
    /* Write to a handle opened with NLR_OPEN_WRITE or NLR_OPEN_UPDATE:
     * the number of bytes written, or a negative error. A short write is
     * retryable; a zero-byte result is an error; len == 0 returns 0
     * without touching the card. */
    int (*fs_write)(int fd, const void *buf, uint32_t len);

    /* The firmware's own code. These change what the camera does for the
     * rest of this boot, and nothing checks what the new code means: a
     * wrong address or a handler that breaks its caller's contract can
     * stop the camera until it is switched off and on again.
     *
     * code_patch replaces `len` bytes at `address` (4..NLR_CODE_PATCH_MAX,
     * a multiple of 4, 4-byte aligned, inside one 64-byte cache line and
     * inside the loader's code window) and does the cache maintenance all
     * cores need. 0, or -NLR_API_EINVAL / -NLR_API_ENOSYS /
     * -NLR_API_EIO; nothing is written on a refusal.
     *
     * code_hook detours `target` to `handler`. `expect` points at the
     * NLR_CODE_HOOK_BYTES this program was built against; the call is
     * refused with -NLR_API_EINVAL unless the firmware holds exactly
     * them, so a program never patches a build it does not know. The
     * target's first four instructions must be position-independent: a
     * branch, ADR/ADRP or a literal load there is refused, because a
     * handler that continues into the original has to run them from
     * somewhere else (NLR_HOOK_CONTINUE above). -NLR_API_EBUSY when the
     * target is hooked already or all NLR_CODE_HOOKS_MAX slots are taken.
     *
     * Two things about the target the loader cannot check, and the
     * program has to get right. The detour loads the handler's address
     * into X16, so the target must be a function's own first instruction:
     * anywhere else, X16 may be live and the function it belongs to will
     * be running with it destroyed. And nothing inside that function may
     * branch into bytes 4..15 of the target -- a loop head or a case
     * label there would land in the middle of the detour.
     *
     * `handler` must be code the loader owns -- a function in this
     * program's own image -- and mapped executable; anything else is
     * refused with -NLR_API_EINVAL. A hook belongs to the loader and
     * outlives the call that installed it, but never outlives the memory
     * it points into: a foreground program's hooks are removed when it
     * ends, whether or not it removed them itself, so only a resource
     * extension -- whose code stays resident for the boot -- can leave one
     * in place. code_unhook puts the original bytes back (-NLR_API_ENOENT
     * when the target has no hook). */
    int (*code_patch)(void *address, const void *bytes, uint32_t len);
    int (*code_hook)(void *target, const void *expect, void *handler);
    int (*code_unhook)(void *target);

    /* ---- ABI 6 ---- */
    /* A page of the camera's own row kinds (NLR_ROW_*): entries, the ON /
     * OFF toggle switch, rows showing their current choice at the right,
     * and lines of text the cursor skips (as greyed rows are). Waits like
     * ui_list and returns the row chosen with OK, NLR_LIST_BACK for back,
     * or a negative error. At most NLR_ROWS_MAX rows. OK on a switch only
     * reports the row: the program flips it and shows the page again,
     * which is what the camera's own switches look like. A row with a
     * choice opens the camera's choice page the same way: a ui_list of the
     * choices with the cursor on the current one. -NLR_API_ENOSYS when this
     * model's page cannot draw a kind other than an entry; -NLR_API_EINVAL
     * for an unknown kind or flag. */
    int32_t (*ui_rows)(const char *title, const struct nlr_row *rows,
                       uint32_t count, uint32_t selected);
    /* The camera's own keyboard page: `buf` (`size` bytes) holds the text
     * it starts with and receives the text entered, NUL-terminated, at
     * most min(size - 1, NLR_INPUT_MAX) characters of `charset`
     * (NLR_INPUT_*). Returns the length when the entry is saved (the
     * keyboard's own save key), NLR_LIST_BACK (and `buf` unchanged) when
     * it is left with MENU or back, or a negative error: -NLR_API_ENOSYS
     * when this loader has no keyboard. The keyboard page itself shows no
     * title: `title` labels the row the page shows for an entry still
     * open (the menu left with the shutter, say), with the text so far;
     * OK there opens the keyboard again. ASCII only; nothing is masked. */
    int32_t (*ui_input)(const char *title, char *buf, uint32_t size,
                        uint32_t charset);
    /* The camera's caution box over the page: the "!" mark, `text` (at
     * most NLR_CAUTION_MAX bytes; a line longer than NLR_CAUTION_LINE
     * breaks at a space, and '\n' breaks one), and OK
     * (NLR_CAUTION_OK) or Yes and No with the cursor on No
     * (NLR_CAUTION_YES_NO). Returns 1 for OK or Yes, 0 for No,
     * NLR_LIST_BACK when it is left with MENU or back, or a negative
     * error: -NLR_API_ENOSYS when this loader has no caution box. */
    int32_t (*ui_caution)(const char *text, uint32_t buttons);

    /* ---- ABI 7 ---- */
    /* The program's one event queue: a control pressed or released, dial
     * clicks, a due timer, a watched setting that changed (NLR_EV_*). It
     * returns 1 with `ev` filled, 0 when `timeout_ms` passed first
     * (NLR_QUEUE_FOREVER waits for good), or a negative error. The first
     * call takes the input: from then on the camera sees only the controls
     * routed to it (input_route); every other control reaches only the
     * program. NLR_EV_OVERFLOW says events were lost: read input_held and
     * the settings again. Foreground programs only. */
    int32_t (*queue_wait)(struct nlr_event *ev, uint32_t timeout_ms);
    /* A timer every `period_ms`, reported as NLR_EV_TIMER with `tag` as the
     * value; a program that falls behind gets one tick, not a burst. The
     * timer's number (0..NLR_TIMERS_MAX-1), or -NLR_API_EBUSY when all are
     * taken. timer_stop: 0, or -NLR_API_ENOENT. */
    int32_t (*timer_start)(uint32_t period_ms, uint32_t tag);
    int32_t (*timer_stop)(int32_t timer);
    /* Where `count` controls (NLR_CTL_*) go: NLR_ROUTE_CAMERA,
     * NLR_ROUTE_PROGRAM or NLR_ROUTE_BOTH. Taking the input routes every
     * control to the program alone except the shutter's half and full
     * press, which go to both. The power switch is always the camera's, and
     * MENU with DELETE together always stops the program. */
    int32_t (*input_route)(const uint32_t *ctls, uint32_t count, uint32_t route);
    /* The controls held at the last scan, as bits 1 << NLR_CTL_*. */
    uint64_t (*input_held)(void);
    /* The screen. screen_claim gives the program the layer the display
     * shows over the live picture (NLR_SCREEN_REAR; the EVF answers
     * -NLR_API_ENOSYS until a body supports it), cleared to transparent,
     * with the stock GUI held so that nothing of the camera's draws over
     * it. Only the program the boot started (NLOADER/BOOT) may: a program
     * opened from the menu runs over the menu and gets -NLR_API_EBUSY.
     * screen_present makes the damaged rectangles (count 0: all of it)
     * visible. screen_release clears the layer and gives it back to the
     * camera, whose GUI then draws its whole screen again; the program runs
     * on, and may claim it again later. */
    int32_t (*screen_claim)(uint32_t screen, struct nlr_surface *out);
    int32_t (*screen_present)(uint32_t screen, const struct nlr_rect *damage,
                              uint32_t count);
    int32_t (*screen_release)(uint32_t screen);
    /* The camera's settings and status store, by item id (0xGGII; names
     * come from the SDK's generated table, nlr_props.h). prop_get copies
     * the value (at most NLR_PROP_BYTES_MAX bytes) and its size: 0,
     * -NLR_API_ENOENT for an item this body does not have, or
     * -NLR_API_EOVERFLOW (size still set) when `cap` is too small. Any
     * program may read, from any of its tasks. prop_watch replaces the set
     * of items whose changes queue_wait reports (at most NLR_WATCH_MAX; a
     * value is compared up to its first 16 bytes, about every 20 ms);
     * count 0 stops watching. prop_set writes a setting the way the
     * camera's menus do: `id` must carry the item's type tag in its top
     * byte (nlr_prop_tagged() in nlr_props.h; 0x07000510 for white
     * balance) -- without it the camera would store the value and nothing
     * would follow, so it is refused with -NLR_API_EINVAL. A value of at
     * most four bytes (little endian, `size` 1..4) or a whole blob. 0 when
     * the camera took it (the stock GUI and derived values follow within
     * about 150 ms, on the camera's own tasks), -NLR_API_EACCES when it
     * refused, -NLR_API_ENOSYS where the body has no settings service.
     * Items the menus change together (white balance and its fine-tune,
     * AF-area mode and subject detection) are set one at a time here. */
    int32_t (*prop_get)(uint32_t id, void *buf, uint32_t cap, uint32_t *size);
    int32_t (*prop_info)(uint32_t id, struct nlr_prop_info *out);
    int32_t (*prop_watch)(const uint16_t *ids, uint32_t count);
    int32_t (*prop_set)(uint32_t id, const void *value, uint32_t size);
    /* A task of its own for a service: `fn(arg)` runs once on a new task of
     * `stack_bytes` (at least 16 KiB) and `priority` (0: the loader's own).
     * Only code that stays for the boot may become a task -- a resident
     * extension's, or a service's while it initializes -- else
     * -NLR_API_EACCES. The task's id, or a negative error. A task never
     * ends: when `fn` returns, it waits for good. */
    int32_t (*task_start)(void (*fn)(void *), void *arg, uint32_t stack_bytes,
                          uint32_t priority);
    /* The memory a foreground program declared in its description (the
     * program .json's description.memory, NPLD v3 `memory=`): taken whole
     * at the first call -- make it early, before the camera's heap is cut
     * up further -- and given back when the program ends. Null and 0 when
     * it declared none or the camera has no block that large. */
    void *(*mem_reserved)(uint32_t *bytes);
    /* 1 when card slot `slot` (0 the first) holds a card, 0 when not, or
     * -NLR_API_ENOSYS where the body does not say. */
    int32_t (*card_present)(uint32_t slot);
    /* What this body provides: NLR_CAP_* bits. */
    uint32_t (*platform_caps)(void);

    /* ---- ABI 8 ---- */
    /* The firmware by name: the body's profile resolves a name to its
     * address, size and fingerprint, so a program never holds one and runs
     * on any firmware whose profile has the name. named() says what a name
     * is (NLR_NAMED_*; for a table its class, size, stock CRC and whether
     * it holds its stock bytes now), or -NLR_API_ENOENT where this body has
     * no such thing: check before relying on it. */
    int32_t (*named)(const char *name, struct nlr_named *out);
    /* Detour hook point `point` (a firmware function's entry) to `handler`,
     * which must be a function of this program's own image. `original`
     * receives the hooked function's continuation, built into the loader
     * from the profile: calling it with the same arguments is calling the
     * original. A handler runs on the firmware's task: copy what it needs
     * and return quickly. A foreground program's hooks are removed when it
     * ends; a resident extension's stay. -NLR_API_EBUSY when the point is
     * hooked already. hook_detach removes it. */
    int32_t (*hook_attach)(const char *point, void *handler, void **original);
    int32_t (*hook_detach)(const char *point);
    /* Data tables. table_read copies `len` bytes from `offset`.
     * table_write changes them: the first write keeps the stock bytes and
     * is refused (-NLR_API_EBUSY) when the table does not hold them (another
     * program changed it, or the firmware is not the profile's); a table
     * only a firmware repack can change answers -NLR_API_EACCES. A pointer
     * table (NLR_TABLE_POINTER) is written in a RAM copy the loader makes,
     * and the camera is pointed at the copy. table_restore puts the stock
     * bytes back. A foreground program's writes are undone when it ends;
     * an extension's stay for the boot. */
    int32_t (*table_read)(const char *name, uint32_t offset, void *dst, uint32_t len);
    int32_t (*table_write)(const char *name, uint32_t offset, const void *src,
                           uint32_t len);
    int32_t (*table_restore)(const char *name);
    /* A firmware function by name (its entry, fingerprinted at build
     * time), or null. The caller must know its contract; it runs on the
     * caller's task. */
    void *(*fw_fn)(const char *name);
    /* One transfer with a device by name ("i2c:imu"): `txlen` bytes out,
     * then `rxlen` bytes in. 0, or -NLR_API_EIO / -NLR_API_ENOENT /
     * -NLR_API_ENOSYS. The loader attaches with a client of its own, never
     * one the camera's tasks use. */
    int32_t (*bus_i2c)(const char *device, const void *tx, uint32_t txlen,
                       void *rx, uint32_t rxlen);
    /* Post an event to the running foreground program's queue from any
     * task: a hook handler on the firmware's task (copy what it needs,
     * post, return), a service's task. queue_wait reports it as
     * NLR_EV_POSTED with the code and value given. 0, or
     * -NLR_API_EOVERFLOW when 32 posted events wait unread. Events posted
     * while no program reads them are dropped when the next one starts. */
    int32_t (*queue_post)(const struct nlr_event *ev);

    /* ---- ABI 9 ---- */
    /* Every file name of a directory in one pass (fs_dir walks the
     * directory again for each entry it reports): at most `cap` names of
     * NLR_DIRENT_NAME_MAX bytes each into `names`, files only, in the
     * card's order. The count -- `cap` when there may be more -- or a
     * negative error as fs_dir. The same directories as fs_dir, the card's
     * DCIM among them. */
    int32_t (*fs_dir_names)(const char *path, char *names, uint32_t cap);
};

/* Foreground entry: called once with the API table in x0. Returning ends
 * the foreground application; the value is the program's result (0 =
 * normal completion, nonzero = an error the loader reports). */
int32_t nlr_app_main(const struct nlr_api *api);

/* Resource-extension entry: called once on the worker with the API table in
 * x0. Returning 0 means initialization completed and stays resident;
 * nonzero records failure but retains queued requests for menu-side
 * consumption. Registered resources have no stop/unload interface. */
int32_t nlr_extension_init(const struct nlr_api *api);

#endif /* NLR_H */
