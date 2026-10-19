#ifndef NLR_API_H
#define NLR_API_H

#include <stddef.h>
#include <stdint.h>

/* The service table a program receives in x0 at either entry (PLAN 5.2,
 * appendix B). The field order and types below are the cross-language ABI
 * contract: they must stay byte-identical with sdk/nlr.h, and the table only
 * ever grows at the end (existing fields keep position, type and meaning).
 * ABI 4 adopts the surface, key-event and directory-entry layouts below.
 * ABI 3 programs use conflicting definitions and are explicitly refused.
 * ABI 5 appended card writing and the firmware-code channel (patch, hook,
 * unhook); ABI 6 appended native row kinds (ui_rows), the keyboard
 * (ui_input) and the caution box (ui_caution). */
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
 * input_poll reports one change at a time. A body without a button leaves
 * its bit at 0. MENU/DELETE remain loader-owned and are never reported. */
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
 * code window the profile declares, start on an instruction and be a whole
 * number of instructions; one call patches at most NLR_CODE_PATCH_MAX bytes
 * inside a single cache line, so instruction fetch on every core switches
 * from all the old bytes to all the new ones. A hook is one 16-byte
 * absolute detour: two instructions that load the handler's address from
 * the eight bytes behind them and branch to it. */
#define NLR_CODE_PATCH_MAX  64u
#define NLR_CODE_HOOK_BYTES 16u
#define NLR_CODE_HOOKS_MAX  16u
#endif /* NLR_ABI4_TYPES */

/* Minimal deferred menu request: label_id names an existing firmware
 * string, not a loader-owned runtime text slot. */
struct nlr_menu_test_item {
    uint32_t label_id;
    uint32_t item_id;
};

/* ABI 7 types (nlr/platform.h); the table only passes pointers to them. */
struct nlr_event;
struct nlr_rect;
struct nlr_prop_info;
struct nlr_named;

struct nlr_api {
    uint32_t abi;                       /* 只增字段，不改动语义 */
    /* 内存 */
    void  *(*mem_alloc)(uint32_t size, uint32_t attrs);
    void   (*mem_free)(void *p);
    /* 文件（限定在配置的卡目录下） */
    int    (*fs_open)(const char *path, uint32_t mode);
    int    (*fs_read)(int fd, void *buf, uint32_t len);
    int    (*fs_seek)(int fd, int64_t off, int whence);
    int    (*fs_close)(int fd);
    /* 文本通道（widget store/bind 封装；状态显示类应用） */
    int    (*ui_draw_text)(int x, int y, const char *s);
    int    (*ui_present)(void);
    /* 像素通道（全屏写入；surface 生命周期模型 M2 定案，图形实现前返回
     * -NLR_API_ENOSYS） */
    int    (*gfx_begin)(struct nlr_surface *out);
    int    (*gfx_end)(void);
    /* 输入（loader 预过滤：全局退出组合键不上传 payload） */
    int    (*input_poll)(struct nlr_key_event *ev);   /* 菜单事件通道 */
    uint32_t (*input_raw)(void);                       /* 原始按键位掩码 */
    /* 日志与生命周期 */
    void   (*log)(const char *fmt, ...);               /* 有界 */
    void   (*exit)(int code);                          /* 前台应用主动退出；不撤销资源扩展 */
    /* Worker-side RAM request; the menu task publishes on next page enter.
     * Returns 0 on acceptance or a negative NLR_API_E* error. */
    int (*menu_register)(const struct nlr_menu_test_item *item);
    /* ---- ABI 4 ---- */
    uint32_t (*time_ms)(void);
    void (*sleep_ms)(uint32_t ms);
    int (*fs_dir)(const char *path, uint32_t index, struct nlr_dirent *out);
    int32_t (*ui_list)(const char *title, const char *const *rows,
                       uint32_t count, uint32_t selected);
    int32_t (*setting)(const char *key);
    /* ---- ABI 5 ---- */
    int (*fs_write)(int fd, const void *buf, uint32_t len);
    int (*code_patch)(void *address, const void *bytes, uint32_t len);
    int (*code_hook)(void *target, const void *expect, void *handler);
    int (*code_unhook)(void *target);
    /* ---- ABI 6 ---- */
    int32_t (*ui_rows)(const char *title, const struct nlr_row *rows,
                       uint32_t count, uint32_t selected);
    int32_t (*ui_input)(const char *title, char *buf, uint32_t size,
                        uint32_t charset);
    int32_t (*ui_caution)(const char *text, uint32_t buttons);
    /* ---- ABI 7 (nlr/platform.h) ---- */
    int32_t (*queue_wait)(struct nlr_event *ev, uint32_t timeout_ms);
    int32_t (*timer_start)(uint32_t period_ms, uint32_t tag);
    int32_t (*timer_stop)(int32_t timer);
    int32_t (*input_route)(const uint32_t *ctls, uint32_t count, uint32_t route);
    uint64_t (*input_held)(void);
    int32_t (*screen_claim)(uint32_t screen, struct nlr_surface *out);
    int32_t (*screen_present)(uint32_t screen, const struct nlr_rect *damage,
                              uint32_t count);
    int32_t (*screen_release)(uint32_t screen);
    int32_t (*prop_get)(uint32_t id, void *buf, uint32_t cap, uint32_t *size);
    int32_t (*prop_info)(uint32_t id, struct nlr_prop_info *out);
    int32_t (*prop_watch)(const uint16_t *ids, uint32_t count);
    int32_t (*prop_set)(uint32_t id, const void *value, uint32_t size);
    int32_t (*task_start)(void (*fn)(void *), void *arg, uint32_t stack_bytes,
                          uint32_t priority);
    void *(*mem_reserved)(uint32_t *bytes);
    int32_t (*card_present)(uint32_t slot);
    uint32_t (*platform_caps)(void);
    /* ---- ABI 8 (nlr/platform.h) ---- */
    int32_t (*named)(const char *name, struct nlr_named *out);
    int32_t (*hook_attach)(const char *point, void *handler, void **original);
    int32_t (*hook_detach)(const char *point);
    int32_t (*table_read)(const char *name, uint32_t offset, void *dst, uint32_t len);
    int32_t (*table_write)(const char *name, uint32_t offset, const void *src,
                           uint32_t len);
    int32_t (*table_restore)(const char *name);
    void *(*fw_fn)(const char *name);
    int32_t (*bus_i2c)(const char *device, const void *tx, uint32_t txlen,
                       void *rx, uint32_t rxlen);
    int32_t (*queue_post)(const struct nlr_event *ev);
    /* ---- ABI 9 ---- */
    int32_t (*fs_dir_names)(const char *path, char *names, uint32_t cap);
};

/* Program-side entry names (appendix B). The core never links them; they
 * document which entry belongs to which kind. sdk/nlr.h declares them for
 * programs. */
int32_t nlr_app_main(const struct nlr_api *api);       /* 返回表示前台应用结束 */
int32_t nlr_extension_init(const struct nlr_api *api); /* 返回 0 表示初始化完成，常驻资源继续保留 */

/* Result conventions for the table above, fixed here so the freestanding
 * camera build (no <errno.h>) and sdk/nlr.h can share them verbatim. The
 * values are the standard errno numbers; a program treats any negative fs
 * result as failure and may compare against these constants. */
#define NLR_API_ENOENT    2
#define NLR_API_EIO       5
#define NLR_API_ENODEV    19 /* ABI 7: the loader's card slot is empty */
#define NLR_API_EBADF     9
#define NLR_API_EACCES    13
#define NLR_API_EBUSY     16
#define NLR_API_EINVAL    22
#define NLR_API_ENOSYS    38
#define NLR_API_EOVERFLOW 75

/* File semantics (POSIX-style; sdk/nlr.h carries the same wording):
 *
 *   fs_open  returns the file handle (>= 0) or a negative error. mode is
 *            NLR_OPEN_READ, NLR_OPEN_WRITE (create, truncate) or
 *            NLR_OPEN_UPDATE (an existing file, read and written in place);
 *            anything else is refused with -EINVAL, and a write access
 *            without the model's write services (or without the declared
 *            cache clean behind them) with -ENOSYS. The loader's own files
 *            -- MANIFEST, ENABLED, SAFE_MODE and the interruption marker --
 *            may be read but never opened for writing: -EACCES. They decide
 *            what runs by itself and how a crashed pass is recognized, and
 *            a program is not the one to rewrite them;
 *   fs_read  returns the number of bytes read, or a negative error. A short
 *            read is retryable, as for the loader itself; a zero-byte result
 *            is an error, because the normalized service family cannot
 *            report end-of-file. len == 0 returns 0 without touching the
 *            card;
 *   fs_seek  returns the new absolute position or a negative error; whence
 *            0 (set) and 2 (end) are supported, 1 (current) is refused;
 *   fs_close returns 0 or -1;
 *   fs_write returns the number of bytes written or a negative error; a
 *            short write is retryable, a zero-byte result is an error, and
 *            len == 0 returns 0 without touching the card. The handle must
 *            be one this program opened for writing (ABI 5).
 *
 * Paths are relative to the configured card root; an absolute path with
 * exactly that prefix is accepted as-is, everything else is prefixed.
 * Path traversal (".."), other drive letters, empty paths and relative
 * portions longer than NLR_API_PATH_MAX (64 bytes, excluding the root) are
 * refused with -EINVAL: the channel cannot leave the
 * configured directory (PLAN appendix B). */
#define NLR_API_PATH_MAX 64u

/* Text publishes a bounded latest-wins result row; x/y are ignored.
 * gfx_begin retains a writable packed surface until gfx_end. Each
 * ui_present submits a frame through the selected, checked graphics path.
 * Z8 uses its original GUI callback with an independently owned RGBA copy;
 * a model without graphics services reports -ENOSYS. */
/* Z8 input retains worker identity, foreground ownership and page focus.
 * Queue loss reports -EOVERFLOW so the caller can rebuild held keys with
 * input_raw. Unsupported model keys remain absent, never guessed. */
/* log writes into the loader's RAM trace ring (read back over PTP), not to
 * the card. Each call is bounded to NLR_API_LOG_MAX formatted bytes; a
 * longer message is truncated and its full length recorded. Ring slots
 * overflow like every trace entry — the ring keeps the most recent calls. */
#define NLR_API_LOG_MAX 32u

/* exit is a foreground-only interface (PLAN 5.1): it records the code and
 * leaves the application without returning into it, then the worker cleans
 * up as for a normal return. A resource extension calling it is recorded in
 * the trace and ignored; it is not an extension stop interface. */

/* The firmware-code channel (ABI 5) is how a card program changes what the
 * camera's own code does. It exists because the firmware's text is in DRAM
 * and the mapping service keeps a writable alias of those pages: core
 * translates the code address, writes through that alias, cleans the data
 * cache to the point of coherency and invalidates the instruction cache,
 * which the architecture broadcasts to every core.
 *
 *   code_patch  replaces len bytes at `address`: 4 <= len <=
 *               NLR_CODE_PATCH_MAX, a multiple of 4, 4-byte aligned, inside
 *               one 64-byte cache line and inside the declared code window.
 *               Returns 0, -EINVAL for a request outside those bounds,
 *               -ENOSYS without the model's code services and -EIO when the
 *               alias is missing or not writable (nothing is written).
 *   code_hook   detours `target` to `handler`. `expect` is the
 *               NLR_CODE_HOOK_BYTES the program was built against: the
 *               call is refused with -EINVAL unless the firmware really
 *               holds them, so a program cannot patch a build it does not
 *               know. The target needs NLR_CODE_HOOK_BYTES of room inside
 *               one cache line. Core saves the overwritten bytes for
 *               code_unhook but hands out no trampoline: it cannot own
 *               executable memory whose permissions change while another
 *               hook's code may be running in it. A handler that has to
 *               continue into the function it replaced carries its own
 *               continuation -- the four overwritten instructions and an
 *               absolute branch to target + 16 -- inside its own program
 *               image, where `expect` is exactly what it must reproduce.
 *               -EBUSY when the target is hooked already or all
 *               NLR_CODE_HOOKS_MAX slots are taken. `handler` must be
 *               mapped executable and lie inside a code block the loader
 *               owns -- the calling program's own, or a resident
 *               extension's -- or the call is refused with -EINVAL; a
 *               detour into firmware text needs no hook record and is a
 *               patch. The hook belongs to the loader, not to the program
 *               that asked for it, and stays installed until it is removed
 *               or the camera restarts; but it never outlives the memory
 *               it points into, so the hooks of a foreground program are
 *               removed when its block goes back, and only a resource
 *               extension (whose code stays resident) can leave one
 *               behind. Two rules core cannot check are the program's:
 *               the detour loads the handler address into X16, so the
 *               target must be a function's first instruction, and nothing
 *               in that function may branch into bytes 4..15 of it.
 *   code_unhook restores the bytes `target` had before its hook, or
 *               -ENOENT when it has none.
 *
 * Installing or removing a hook while the target is running on another core
 * is not safe to the letter of the architecture: instruction fetch switches
 * cache line at once, but a core already inside those four instructions
 * finishes them. Hook paths that the camera calls continuously should be
 * installed from a resource extension at load time. */

/* menu_register copies a request during resource-extension initialization;
 * it never calls firmware menu code from the worker. Success means queued,
 * not yet visible. Requests survive a later initialization failure and may
 * already have partial effects when menu-side publishing fails. Without an
 * injected publisher, registration fails closed with -NLR_API_ENOSYS. */

#endif
