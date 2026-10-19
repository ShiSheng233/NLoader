#ifndef NLR_PLATFORM_H
#define NLR_PLATFORM_H

#include <stdint.h>

#include "nlr/api.h"

struct nlr_services;

/*
 * ABI 7: every control as an event, one
 * event queue per program, timers, the screen claimed and given back, and
 * the camera's settings and status read and watched by item.
 *
 * The types between the guards below are shared verbatim with sdk/nlr.h, as
 * the ABI 4 ones are. Everything after them is the loader's own: the
 * profile's description of this body (struct nlr_platform_services) and the
 * state a boot keeps (struct nlr_platform, inside the runtime allocation,
 * because the loader runs from flash and owns no writable statics).
 */

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

/* ---- the loader's own ------------------------------------------------------ */

/* A control's physical bits in the scan object (u32[5] banks; see
 * nlr_program_services). One control may own several bits of one bank. */
struct nlr_platform_control {
    uint8_t ctl;            /* NLR_CTL_* below NLR_CTL_DIAL_MAIN */
    uint8_t bank;
    uint16_t reserved;
    uint32_t mask;
};

#define NLR_PLATFORM_CONTROLS_MAX 40u
#define NLR_PLATFORM_DIALS 3u   /* main, sub, lens ring */

/* Where the platform's controls and dials live, for a body whose input hook
 * is not the program input slot (the Z 8's exit callback carries the scan).
 * A body that declares the program input slot keeps the geometry there and
 * leaves this null; core then reads the same fields from
 * nlr_program_services, so one pass serves both carriers. */
struct nlr_platform_scan {
    uint32_t bank_base;     /* first bank record's offset in the object */
    uint32_t bank_stride;   /* bytes between bank records; 0: no scan */
    uint32_t banks;         /* bank records carrying controls */
    uint32_t keep_bank;     /* bits never hidden from the camera (the */
    uint32_t keep_mask;     /* power switch), masked within that bank */
    uint32_t dial_offset;   /* s32 dial words here, or 0 with dial_bytes 0 */
    uint32_t dial_bytes;
    void (*activity)(void); /* user activity: holds off auto power-off */
    void *object;           /* the object itself, for the boot escape */
};

/* What the profile says about this body for ABI 7. A zero or null field
 * leaves its part unavailable: the matching calls answer -ENOSYS and
 * platform_caps leaves the bit clear; nothing is guessed. */
struct nlr_platform_services {
    /* Every button the scan object carries, beyond the fifteen keys too. */
    const struct nlr_platform_control *controls;
    uint32_t control_count;
    /* The scan object's geometry when it is not the program input slot's
     * (see struct nlr_platform_scan). Null: the program fields describe it. */
    const struct nlr_platform_scan *scan;
    /* The scan object's s32 dial deltas (at the carrier's dial_offset: the
     * platform scan's, or nlr_program_services' when no scan is declared):
     * which word is the main dial, the sub dial and the lens
     * ring, as 1 + the word's index (0: the body has none), and -1 where
     * the word counts clockwise as negative. */
    uint8_t dial_word[NLR_PLATFORM_DIALS];
    int8_t dial_sign[NLR_PLATFORM_DIALS];
    /* A second word that turns the same dial (the battery grip's main and
     * sub dials), the same encoding; its clicks add to the first's. */
    uint8_t dial_alt[NLR_PLATFORM_DIALS];
    uint8_t reserved0;
    /* The settings and status store: a group table and an item table, both
     * in the module. Item id 0xGGII is group GG's item II: the group's
     * record says where its items start and how many there are, and the
     * item's record says how many bytes it has and where they live, which
     * must be inside [ram_lo, ram_hi). */
    const volatile uint8_t *prop_groups;
    uint32_t prop_group_count;
    uint32_t prop_group_bytes;
    uint16_t group_live_at;     /* u32: nonzero for a group in use */
    uint16_t group_first_at;    /* u16: index of its first item */
    uint16_t group_items_at;    /* u16: how many items it has */
    uint16_t item_size_at;      /* u32: the value's bytes */
    const volatile uint8_t *prop_items;
    uint32_t prop_item_count;
    uint32_t prop_item_bytes;
    uint16_t item_ram_at;       /* u64: the value's address */
    uint16_t reserved1;
    uint64_t prop_ram_lo;
    uint64_t prop_ram_hi;
    /* The camera's settings service, as its menus call it: one item of at
     * most four bytes, or one blob, by the item's TAGGED id (type tag in
     * the top byte: the service stores an untagged id too, but nothing that
     * depends on the item -- the in-effect value, the stock GUI, derived
     * values such as frames remaining -- follows). Bit 0 of the result:
     * the value was taken. Null: prop_set answers -ENOSYS. */
    uint64_t (*prop_set)(uint32_t tagged, uint32_t value);
    uint64_t (*prop_set_blob)(uint32_t tagged, const void *blob, uint32_t bytes);
    /* Called on the stock GUI's task as it leaves a hold, after a program
     * gave the screen back: makes the GUI draw its whole screen again
     * instead of only what changed. Null: the GUI redraws what changes. */
    void (*gui_redraw)(void);
    /* The card slots: the filesystem's volume table (records of
     * volume_bytes, "X:" at +0, the state byte at volume_state, `mounted`
     * when it serves files), searched by the slot's drive letter, slot n
     * being card_letters[n]. Zero volumes: card_present answers -ENOSYS. */
    /* Touch: the driver's report slot, its stock occupant (the camera's
     * gesture service), called on the driver task as fn(0, record): u8
     * finger count at +5 (0: released), finger 0's x and y as u16 at +10
     * and +12, in screen pixels; record_bytes in all. Null slot: no touch. */
    void (**touch_slot)(uint32_t, void *);
    void (*touch_original)(uint32_t, void *);
    uint32_t touch_record_bytes;
    /* The eye sensor's last state (0 none, 1 an eye at the finder; any
     * other value before its first report). Null: no eye events. */
    const volatile uint32_t *eye_state;
    /* ABI 8 names. */
    const struct nlr_platform_point *points;
    uint32_t point_count;
    uint32_t table_count;
    const struct nlr_platform_table *tables;
    const struct nlr_platform_function *functions;
    uint32_t function_count;
    uint32_t device_count;
    const struct nlr_platform_device *devices;
    /* The I2C service the devices use: attach the device's client handle
     * (bank << 16 | 1 << index, never one of the camera's), one transfer
     * message, detach. Null: bus_i2c answers -ENOSYS. */
    int32_t (*i2c_transfer)(uint32_t bank, uint32_t client, uint32_t address,
                            const void *tx, uint32_t txlen, void *rx,
                            uint32_t rxlen);
    const volatile uint8_t *volumes;
    uint32_t volume_count;
    uint32_t volume_bytes;
    uint16_t volume_state;
    uint8_t mounted;
    uint8_t card_slots;
    char card_letters[4];
    /* The release bundle: where the firmware package
     * keeps it -- a span of the module the build fills, read where the
     * camera has it at run time -- and the most it may span. Null: no
     * bundle; every program comes from the card, as before. */
    const uint8_t *bundle;
    uint32_t bundle_bytes;
    /* The stock GUI's turns (services.platform.gui_turns): on a body whose
     * GUI is several tasks taking turns (the Z 8's IDLE, LV, MSG and PLAY
     * services), the call each service's loop makes once a turn before it
     * waits for work. The build points each call at a generated entry that
     * runs nlr_platform_gui_turn(index), which calls `callee` and returns
     * what it returned. Zero: the body's hold point is elsewhere (the
     * boot checkpoint) or absent. */
    uint32_t gui_turn_count;
    const struct nlr_platform_gui_turn *gui_turns;
    /* The GUI hold (services.platform.hold), the same rules on every body:
     * `hold_when` says when a shell opened from a menu is held -- at the
     * next hold point (NLR_HOLD_IMMEDIATE), or only once the stock GUI has
     * committed a frame after a hold point ran (NLR_HOLD_SETTLE, told by
     * the commit observer below). screen_claim waits at most
     * `hold_wait_ms` for the hold, then for the shown buffers to stay the
     * same `scanout_stable_ms` (0: no such wait), never more than
     * NLR_PLATFORM_SCANOUT_WAIT_MS. Zero `hold_when`: no hold declared, a
     * claim that would have to wait is refused. */
    uint32_t hold_when;
    uint32_t hold_wait_ms;
    uint32_t scanout_stable_ms;
    uint32_t reserved_hold;
    /* The stock GUI's commit (services.platform.commit): the function its
     * commit calls reach. The build points each declared call at
     * nlr_platform_gui_commit, which makes this call and returns its
     * result unchanged. Null: no observer. */
    int32_t (*commit)(uint32_t mask, void *request);
};

#define NLR_HOLD_IMMEDIATE 1u
#define NLR_HOLD_SETTLE 2u
/* The longest a claim waits for the shown buffers to stay put. */
#define NLR_PLATFORM_SCANOUT_WAIT_MS 2000u

/* The commit observer (core/runtime.c): runs the stock commit, then tells
 * the hold a frame of the stock GUI's own was committed -- not one the
 * loader's canvas rendered (graphics) and not a refused commit. */
int32_t nlr_platform_gui_commit(uint32_t mask, void *request);

/* One GUI turn's stock call: no arguments, its result returned as is. */
struct nlr_platform_gui_turn {
    void *(*callee)(void);
};

/* A GUI turn (core/runtime.c): the boot hold's two halves around the stock
 * call, on the stock GUI task that makes it, once the GUI has settled after
 * a shell closed the menu. Without a runtime the call passes straight
 * through; it never makes one. */
void *nlr_platform_gui_turn(uint32_t index);

/* ABI 8: the profile's names. A point's continuation runs the four
 * instructions its detour overwrote and branches to target + 16; the build
 * generates it into the loader's own image from the profile's expect
 * words, so a handler calls the original through it without holding an
 * address. */
struct nlr_platform_point {
    const char *name;
    uint64_t target;
    uint32_t expect[4];
    void (*continuation)(void);
    uint32_t args;
};
struct nlr_platform_table {
    const char *name;
    uint64_t address;       /* the bytes, or (pointer class) the slot */
    uint32_t size;
    uint32_t cls;           /* NLR_TABLE_* */
    uint32_t crc;           /* CRC-32 of the stock bytes */
    uint32_t reserved;
    uint64_t stock_pointer; /* pointer class: the slot's stock value */
};
struct nlr_platform_function {
    const char *name;
    void *address;
};
struct nlr_platform_device {
    const char *name;
    uint32_t bank;
    uint32_t address;
    uint32_t client;
    uint32_t reserved;
};

/* Bytes of one watched value the loader compares. */
#define NLR_WATCH_BYTES 16u
#define NLR_PLATFORM_EVENTS 64u
#define NLR_PLATFORM_TASKS 8u
#define NLR_PLATFORM_TABLE_SLOTS 16u
#define NLR_PLATFORM_TABLE_MAX 0x40000u /* bytes a writable table may have */

/* A boot's ABI 7 state, in the runtime allocation. The input task is the
 * only producer of `events` (head is the program's, tail the input
 * task's); everything else belongs to the running program's task, except
 * the screen words, which the GUI checkpoint reads. */
struct nlr_platform {
    /* Set when the running program takes the input through ABI 7: the hook
     * then routes per control instead of hiding everything. */
    uint32_t active;
    uint32_t overflow;
    uint64_t held;              /* controls held at the last scan */
    uint64_t hold;              /* hidden controls still held when the
                                 * program ended: hidden until released */
    uint64_t route_hide;        /* controls the camera does not see */
    uint64_t route_report;      /* controls the program hears about */
    uint32_t head;
    uint32_t tail;
    struct nlr_event events[NLR_PLATFORM_EVENTS];
    struct {
        uint32_t period;
        uint32_t tag;
        uint32_t next;
        uint32_t used;
    } timers[NLR_TIMERS_MAX];
    uint32_t watch_count;
    uint32_t watch_due;
    uint16_t watch_id[NLR_WATCH_MAX];
    uint8_t watch_size[NLR_WATCH_MAX];
    uint8_t watch_value[NLR_WATCH_MAX][NLR_WATCH_BYTES];
    /* The screen. `claimed`: the program draws the GUI layer. `lent`: the
     * program gave it back and runs on without it, so the GUI checkpoint
     * must not hold the stock GUI. `redraw`: the GUI owes a full redraw.
     * `inside`: the stock GUI task is held at the checkpoint right now. */
    uint32_t claimed;
    uint32_t lent;
    uint32_t redraw;
    uint32_t inside;
    /* Set while the running program is the one the boot started (the
     * shell): only it may hold the stock GUI. */
    uint32_t shell;
    /* A shell was opened from the menu and the stock GUI is still on its
     * way to live view: no GUI turn holds it until the GUI has committed a
     * frame after a GUI turn ran (`turned`) -- in stock that first commit
     * is live view's first full draw, after which the display turns the
     * GUI layer on. Holding earlier stalls the switch to live view (even a
     * second idle turn comes before it), and the first live-view draw
     * after the release is then cancelled by the events that piled up: no
     * commit, the GUI layer is stopped, the screen stays black (Z 8 QEMU,
     * build/z8-c-20261017 qemu-scr-005 and -007). */
    uint32_t leaving;
    uint32_t turned;
    uint64_t colour;            /* the claimed buffers */
    uint64_t alpha;
    uint32_t tasks;             /* service tasks started this boot */
    struct {
        uint64_t lo;            /* each service task's stack, as it began */
        uint64_t hi;
    } task_stack[NLR_PLATFORM_TASKS];
    /* The memory a program declared (mem_reserved): taken before its entry
     * runs, given back with the rest of its allocations. */
    void *reserved;
    uint32_t reserved_bytes;
    /* Slots holding a mounted card at the last look (bit n: slot n), bit
     * 31 once looked at; the next look is due at card_due. */
    uint32_t card_last;
    uint32_t card_due;
    /* Touch: the driver task is the only producer of tevents (thead the
     * program's, ttail the driver task's). `touching` the program's
     * finger is down; `camera_touch` the camera's gesture service saw a
     * finger go down and not yet up. */
    uint32_t thead;
    uint32_t ttail;
    struct nlr_event tevents[16];
    uint32_t touching;
    uint32_t camera_touch;
    /* where the program's finger last was: a release reports it (the panel
     * says 0,0 once the finger is off) */
    int16_t touch_x, touch_y;
    uint32_t touch_installed;
    /* queue_post (ABI 8): any task may post, so producers reserve a slot
     * by compare-and-swap on ptail and publish it with its sequence; the
     * program's task reads in order and stops at a slot not yet
     * published. */
    uint32_t phead;
    uint32_t ptail;
    struct {
        uint32_t seq;
        uint32_t reserved;
        struct nlr_event ev;
    } posted[32];
    /* The eye sensor at the last look, and when to look again. */
    /* The log (nlr/journal.h): the controls and raw bank words at the last
     * line, when a dial was last reported, and how many presents found the
     * layer on another buffer. */
    uint64_t journal_held;
    uint32_t journal_banks[4];
    uint32_t journal_raw_lines;
    uint32_t journal_dial_at;
    uint32_t journal_present_fail;
    uint32_t eye_last;
    uint32_t eye_due;
    /* ABI 8 tables written this boot: the table, the stock bytes kept to
     * put back (or, pointer class, the loader's RAM copy), and whether a
     * foreground program wrote it -- its writes are undone when it ends,
     * an extension's stay for the boot. */
    struct {
        uint32_t used;
        uint32_t table;
        uint32_t foreground;
        uint32_t bytes;
        uint8_t *keep;
        void *request;
    } tables[NLR_PLATFORM_TABLE_SLOTS];
};

/* ---- pure parts, shared by the loader and its host tests ------------------ */

void nlr_platform_reset(struct nlr_platform *p);
/* Start routing for a program that takes the input: every control to the
 * program, and -- for the shell, which runs over the live picture --
 * half and full press to both, so focus and capture go on. A program over
 * the stock menu keeps the shutter too: a half press would leave the menu
 * under it. */
void nlr_platform_take_input(struct nlr_platform *p, int share_shutter);
int nlr_platform_route(struct nlr_platform *p, const uint32_t *ctls,
                       uint32_t count, uint32_t route);
/* The controls held in `banks` (each the bank's current word). */
uint64_t nlr_platform_held(const struct nlr_platform_services *s,
                           const uint32_t *banks, uint32_t bank_count);
/* The scan object as the carrier hook receives it: the platform pass reads
 * the bank records and dial words here and hides what the camera must not
 * see. Filled from [services.platform].scan, or, when the platform declares
 * no scan of its own, from the program input slot's geometry -- one view,
 * whichever of the two hooks a body runs it on. */
struct nlr_scan_view {
    void *object;           /* the object itself, for the boot escape */
    uint32_t bank_base;
    uint32_t bank_stride;
    uint32_t banks;
    uint32_t keep_bank;
    uint32_t keep_mask;
    uint32_t dial_offset;
    uint32_t dial_bytes;
    void (*activity)(void);
};
/* Fill `out` from `svc`'s platform scan or program input slot. 0 when the
 * body names neither; the pass then never runs and controls answer -ENOSYS. */
int nlr_platform_scan_view(const struct nlr_services *svc,
                           struct nlr_scan_view *out);
/* One platform input pass over `object`, run by the input task from
 * whichever carrier hook exists: report control and dial events, hide the
 * bits of `capture` that the camera must not see (each routed control
 * excepted, and the keep bits), and signal activity when a hidden bit
 * moved. `now` is the clock the events carry. */
int nlr_platform_input_pass(struct nlr_platform *p,
                            const struct nlr_platform_services *s,
                            const struct nlr_scan_view *view, void *object,
                            int capture, uint32_t now);
/* Bits of each bank the camera must not see under the current routes:
 * every bit except those of controls routed to the camera or to both, and
 * except `keep` in bank `keep_bank`. */
void nlr_platform_hide_masks(const struct nlr_platform_services *s,
                             uint64_t route_hide, uint32_t keep_bank,
                             uint32_t keep, uint32_t *masks,
                             uint32_t bank_count);
/* Producer and consumer of the event ring. push reports 0, or
 * -NLR_API_EOVERFLOW (the ring was full; pop then reports one
 * NLR_EV_OVERFLOW first). */
int nlr_platform_push(struct nlr_platform *p, const struct nlr_event *ev);
int nlr_platform_pop(struct nlr_platform *p, struct nlr_event *ev);
/* Turn one scan into events: control edges for reported controls, and dial
 * clicks from the s32 words at `dials`. */
void nlr_platform_scan(struct nlr_platform *p,
                       const struct nlr_platform_services *s, uint64_t held,
                       const int32_t *dials, uint32_t dial_words, uint32_t now);
/* Timers: start returns the timer number or -NLR_API_EBUSY. */
int nlr_platform_timer_start(struct nlr_platform *p, uint32_t period_ms,
                             uint32_t tag, uint32_t now);
int nlr_platform_timer_stop(struct nlr_platform *p, int32_t timer);
int nlr_platform_timer_due(struct nlr_platform *p, uint32_t now,
                           struct nlr_event *ev);
/* Milliseconds until the next timer is due (0: due now), or UINT32_MAX. */
uint32_t nlr_platform_timer_wait(const struct nlr_platform *p, uint32_t now);
/* The store: where item `id` lives and how big it is. */
int nlr_platform_prop(const struct nlr_platform_services *s, uint32_t id,
                      const volatile uint8_t **value, uint32_t *size);
int nlr_platform_watch(struct nlr_platform *p,
                       const struct nlr_platform_services *s,
                       const uint16_t *ids, uint32_t count);
/* The first watched item whose value changed since the last report, as an
 * event; 0 when none did. */
int nlr_platform_watch_poll(struct nlr_platform *p,
                            const struct nlr_platform_services *s,
                            uint32_t now, struct nlr_event *ev);
uint32_t nlr_platform_caps(const struct nlr_services *svc);
/* 1 when slot `slot` holds a mounted card, 0 when not, -NLR_API_ENOSYS
 * where the profile names no volume table, -NLR_API_EINVAL past the slots. */
int nlr_platform_card(const struct nlr_platform_services *s, uint32_t slot);
/* One touch report as the driver gives it, from the driver's task: a
 * touch event for the program when it hears about touch (DOWN, MOVE, UP).
 * Returns 1 when the camera must not see the report. */
int nlr_platform_touch(struct nlr_platform *p,
                       const struct nlr_platform_services *s,
                       const uint8_t *record, uint32_t now);
int nlr_platform_touch_pop(struct nlr_platform *p, struct nlr_event *ev);
/* The eye sensor's state changed since the last look (every 50 ms). */
int nlr_platform_eye_poll(struct nlr_platform *p,
                          const struct nlr_platform_services *s,
                          uint32_t now, struct nlr_event *ev);
/* queue_post's ring: post from any task (0, or -EOVERFLOW when 32 wait),
 * take on the program's. */
int nlr_platform_post(struct nlr_platform *p, const struct nlr_event *ev);
int nlr_platform_posted(struct nlr_platform *p, struct nlr_event *ev);
/* ABI 8 lookups: the index of `name` in the profile's list, or -1. */
int nlr_platform_find_point(const struct nlr_platform_services *s, const char *name);
int nlr_platform_find_table(const struct nlr_platform_services *s, const char *name);
int nlr_platform_find_function(const struct nlr_platform_services *s, const char *name);
int nlr_platform_find_device(const struct nlr_platform_services *s, const char *name);
uint32_t nlr_platform_crc32(const volatile uint8_t *p, uint32_t n);
/* The release bundle: a read-only set of the files
 * a card's NLOADER directory would hold -- programs (NPLD v3, so each says
 * what it is) and the defaults BOOT and ENABLED -- placed in the firmware
 * package. Layout, all little endian:
 *
 *   0x00 "NLBB"   0x04 u16 version (1)   0x06 u16 entry bytes (32)
 *   0x08 u32 entries   0x0C u32 total bytes (header, table and files)
 *   0x10 u32 CRC-32 of the entry table   0x14..0x1F zero
 *   0x20 entries: { char name[16] (an 8.3 name, NUL padded), u32 offset
 *        from the bundle's start, u32 bytes, u32 CRC-32 of the file,
 *        u32 zero }
 *   files, each on a 64-byte boundary, inside the total.
 *
 * nlr_bundle_count: the entries of a well-formed bundle in `bytes` of
 * memory at `base`, or 0 (no bundle, or one that fails its own checks:
 * then nothing of it is ever used). nlr_bundle_entry: entry `index`'s name
 * (NUL-terminated), file and size. nlr_bundle_find: the file called
 * `name` (ASCII case-insensitive); with `verify`, its CRC must match, else
 * it is not found. */
#define NLR_BUNDLE_NAME_MAX 16u
uint32_t nlr_bundle_count(const uint8_t *base, uint32_t bytes);
int nlr_bundle_entry(const uint8_t *base, uint32_t bytes, uint32_t index,
                     char name[NLR_BUNDLE_NAME_MAX + 1], const uint8_t **file,
                     uint32_t *size);
int nlr_bundle_find(const uint8_t *base, uint32_t bytes, const char *name,
                    int verify, const uint8_t **file, uint32_t *size);

/* The slot whose drive letter `letter` is, or -1. */
int nlr_platform_card_slot(const struct nlr_platform_services *s, char letter);
/* A card that came or went since the last look, as an NLR_EV_CARD event
 * (one per call); looks every 100 ms. The first look only learns. */
int nlr_platform_card_poll(struct nlr_platform *p,
                           const struct nlr_platform_services *s,
                           uint32_t now, struct nlr_event *ev);

#endif
