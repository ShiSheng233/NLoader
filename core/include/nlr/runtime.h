#ifndef NLR_RUNTIME_H
#define NLR_RUNTIME_H

#include "nlr/manifest.h"
#include "nlr/menu.h"
#include "nlr/text.h"
#include "nlr/input.h"

#include "nlr/api.h"
#include "nlr/platform.h"
#include "nlr/resource.h"

#ifndef NLR_HAS_GRAPHICS
#define NLR_HAS_GRAPHICS 0
#endif
#if NLR_HAS_GRAPHICS
#include "nlr/native_graphics.h"
#include "nlr/graphics_runtime.h"
#endif

struct nlr_native_card_runtime;

/* Base read arena. Valid generic files that outgrow it use a separately
 * owned bounded temporary buffer; execution-block limits stay unchanged. */
#ifndef NLR_PROGRAM_ARENA_BYTES
#define NLR_PROGRAM_ARENA_BYTES 65536u /* explicit standalone-host fallback */
#endif
#define NLR_ARENA_BYTES NLR_PROGRAM_ARENA_BYTES
_Static_assert(NLR_ARENA_BYTES >= 65536u && NLR_ARENA_BYTES <= 1048576u &&
               NLR_ARENA_BYTES % 64u == 0u, "program arena profile bounds");

/* Program paths combine the configured root and the manifest's relative
 * file column, already confined to APPS. Include room for the terminator. */
#define NLR_PATH_BYTES   (sizeof NLR_PROGRAM_ROOT + NLR_MANIFEST_FILE_MAX)
/* Levels of the loader's own pages. */
#define NLR_PAGES_DEPTH  6u

/* No check has run since the directory was last read. */
#define NLR_NO_CHECK 0xffffffffu
/* A program's settings file (<name>.SET beside it, `nloader program`):
 * lines a program may declare, and bytes the file may hold. */
#define NLR_SETTINGS_MAX   8u
#define NLR_SETTINGS_BYTES 2048u

/* Registry capacity (M2-T2): the injected program_max_resident plus the one
 * foreground program that may run beside the residents. The generated
 * bindings carry a static assertion that the profile's limit fits this
 * table, so an oversized declaration fails the build instead of being
 * silently clipped at run time. */
#define NLR_RESIDENT_MAX 8u

/* A program run's outcome as facts, kept by program id for the rest of
 * the boot (struct nlr_runtime outcomes): what the details page needs to
 * say the full reason, and the list its short word, after the page has
 * moved on to other checks or read the directory again. `result` is the
 * attempt's last_result; `memory_bytes` is nonzero only when the camera's
 * heap refused the attempt's blocks, and says how many it asked for;
 * `phase` and `stage` say where a refusal happened. A slot with an empty
 * id is free. */
#define NLR_OUTCOMES_MAX 8u
struct nlr_outcome {
    char id[NLR_MANIFEST_ID_MAX + 1];
    int32_t result;
    int32_t exit_code;
    uint32_t memory_bytes;
    uint8_t exit_requested;
    uint8_t returned;
    uint8_t phase;
    uint8_t stage;
};

/* One ownership record of the program registry (PLAN 5.1/5.2, M2-T2).
 * Resource extension records are kept for the whole boot: their two
 * execution blocks stay allocated — code executable, data writable — and
 * the camera may keep calling into them after the entry returned, whether
 * initialization succeeded or not (failed marks a possibly partially
 * effective one). The foreground program is registered while its run is
 * queued or executing and cleared at the next observation after it ends:
 * its blocks live only inside that attempt and are released with it, so its
 * record carries the reserved block sizes with null addresses, and the live
 * addresses are the load state's. A block that does not exist has a null
 * pointer and a byte count of 0; block byte counts are whole execution
 * regions. */
struct nlr_program_record {
    uint32_t used;
    uint32_t kind;        /* NLR_KIND_RESOURCE_EXTENSION or FOREGROUND */
    uint32_t abi_version; /* as declared by the program header */
    uint32_t failed;      /* init failed/uncertain: possibly partially
                           * effective, kept exactly the same way */
    uint32_t uncertain;   /* init/publication not confirmed; restart required */
    /* Residents retain their original owner and actual requested length,
     * including alignment slack. Queued/running foreground records keep
     * these zero: their live allocation is held in load.program instead. */
    void *allocation;
    uint32_t allocation_bytes;
    void *code_block;     /* RX, still resident */
    uint32_t code_bytes;  /* 0 when there is no code block */
    void *data_block;     /* RW; null when the program has no data segment */
    uint32_t data_bytes;  /* 0 when there is no data block */
    char id[NLR_MANIFEST_ID_MAX + 1];
};

/* Pending program text (M2-T4, PLAN 5.6): the single latest-wins slot a
 * running program fills through ui_draw_text and the page drains into the
 * result row on each redraw. Writer is the worker task alone, reader the
 * GUI task alone, no lock: the payload lives in atomic words published by
 * an atomic generation counter, the same single-publish shape as the
 * diagnostic trace ring. Generation parity carries the protocol: odd means
 * a writer is mid-publish, even means the words hold a complete text. The
 * capacity matches the result row's text slot (NLR_SLOT_TEXT_MAX), so what
 * is published is exactly what a row can show. Every payload store is
 * release and every payload load acquire: a reader that touches any byte
 * of the next generation synchronizes with that store, so its final
 * generation load then reads that generation or later — an odd value or a
 * newer even one — and discards the scan. A mixed-generation text can
 * therefore never be adopted. */
#define NLR_TEXT_WORDS ((NLR_SLOT_TEXT_MAX + 1u + 7u) / 8u)

struct nlr_text_slot {
    /* Each word packs eight text bytes, lowest byte first; the text is
     * NUL-terminated inside the published words and every byte from the
     * NUL on within a published word is zero. Words past the text keep
     * older content: the reader stops at the NUL, so stale bytes are never
     * shown. Every access goes through the atomic builtins — a plain read
     * of concurrently overwritten storage would be a data race, which no
     * later generation check can undo. */
    uint64_t words[NLR_TEXT_WORDS];
    uint32_t generation; /* atomic: even = stable, odd = publishing */
};

_Static_assert(NLR_TEXT_WORDS * 8u >= NLR_SLOT_TEXT_MAX + 1u,
               "text words must hold capacity and NUL");

/* Test seam fired after each payload load so host tests can interleave a
 * writer deterministically inside the read. The default is nothing; only
 * test_core.c defines the macro, before including this header. */
#ifndef NLR_TEXT_READ_PAUSE
#define NLR_TEXT_READ_PAUSE() ((void)0)
#endif

/* Writer side (worker task): publishes s truncated to the row capacity.
 * The generation goes odd for the payload stores and even again on the
 * release, so a reader either adopts the whole text or retries. */
static inline void nlr_text_publish(struct nlr_text_slot *t, const char *s)
{
    uint32_t generation = __atomic_load_n(&t->generation, __ATOMIC_RELAXED);
    __atomic_store_n(&t->generation, generation + 1u, __ATOMIC_RELEASE);
    uint32_t length = 0;
    if (s)
        while (s[length] && length < NLR_SLOT_TEXT_MAX)
            length++;
    uint32_t words = (length + 1u + 7u) / 8u;
    for (uint32_t w = 0; w < words; w++) {
        uint64_t value = 0;
        for (uint32_t b = 0; b < 8; b++) {
            uint32_t index = w * 8u + b;
            uint8_t byte = 0;
            if (index < length)
                byte = (uint8_t)s[index];
            /* index == length is the NUL; past it the word stays zero. */
            value |= (uint64_t)byte << (8 * b);
        }
        /* Release: the reader's acquire of any next-generation word makes
         * its final generation load see that generation or later. */
        __atomic_store_n(&t->words[w], value, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&t->generation, generation + 2u, __ATOMIC_RELEASE);
}

/* Reader side (GUI task): copies the published text into out (row capacity
 * plus NUL) and returns its length. Zero means "no text to show" — either
 * nothing was published or every attempt raced a writer, and the caller
 * falls back to the status text instead of showing half a text. Four
 * attempts: a program that keeps publishing through every attempt wins by
 * design (latest-wins), the row just falls back for this redraw. */
static inline uint32_t nlr_text_read(const struct nlr_text_slot *t, char *out)
{
    for (uint32_t attempt = 0; attempt < 4; attempt++) {
        uint32_t generation =
            __atomic_load_n(&t->generation, __ATOMIC_ACQUIRE);
        if (generation & 1u)
            continue; /* mid-publish: nothing complete to read yet */
        uint32_t length = 0;
        for (uint32_t w = 0; w < NLR_TEXT_WORDS; w++) {
            uint64_t value =
                __atomic_load_n(&t->words[w], __ATOMIC_ACQUIRE);
            NLR_TEXT_READ_PAUSE();
            for (uint32_t b = 0; b < 8 && length < NLR_SLOT_TEXT_MAX; b++) {
                char byte = (char)(value >> (8 * b));
                if (!byte)
                    goto scanned;
                out[length++] = byte;
            }
        }
        /* No NUL inside the capacity: the clamped text still reads as one
         * bounded string (the writer never publishes without its NUL). */
    scanned:
        out[length] = 0;
        if (__atomic_load_n(&t->generation, __ATOMIC_ACQUIRE) == generation)
            return length;
    }
    out[0] = 0;
    return 0;
}

enum {
    NLR_AUTOLOAD_NEW = 0,
    NLR_AUTOLOAD_READY,       /* marker committed, before next entry */
    NLR_AUTOLOAD_WAITING,     /* one worker attempt outstanding */
    NLR_AUTOLOAD_CLEAR,       /* all succeeded, marker still present */
    NLR_AUTOLOAD_DONE,
    NLR_AUTOLOAD_STOPPED,     /* failure/disable/pending/interrupt; no retry */
};

enum {
    NLR_EXTENSION_NOT_STARTED = 0,
    NLR_EXTENSION_INITIALIZING,
    NLR_EXTENSION_LOADED,
    NLR_EXTENSION_NOT_EXECUTED, /* refused before entry */
    NLR_EXTENSION_PARTIAL,      /* failed/uncertain entry, possibly effective */
};

/* The GUI-layer buffers the boot checkpoint keeps track of (the GUI rotates
 * a few), and the room for each one's packed alpha (a stock frame packs to
 * 40-50 KB). */
#define NLR_VEIL_PLANES 3u
#define NLR_VEIL_KEEP 0x14000u

struct nlr_autoload {
    const struct nlr_card_store *store;
    struct nlr_enabled enabled; /* boot snapshot; saving never changes it */
    uint32_t phase;
    int32_t result;
    uint32_t next;
    int32_t enabled_result; /* settings read result, including paused boots */
    int32_t recovery_result; /* last explicit recovery action */
    uint32_t recovery_armed; /* marker cleared; only a fresh boot may retry */
    /* Who is carrying the pass forward. Two tasks ask for it -- the worker
     * after every load it finishes, the menu task on every page visit --
     * and they must not take the same step: both would start the same
     * extension, and the one that loses would stop the whole pass with a
     * busy, leaving the marker behind. `driver` is held by the one task
     * that is stepping; `pending` is what a caller that found it held
     * leaves behind, so the holder looks once more before putting it
     * down and a load finishing inside that window is never lost. */
    uint32_t driver;
    uint32_t pending;
    /* The boot checkpoint (nlr_runtime_boot_checkpoint): the turns of the
     * firmware's loop it has counted, the times it asked the card for
     * MANIFEST, and whether it is finished for this boot. */
    uint32_t boot_turns;
    uint32_t boot_asks;
    uint32_t boot_done;
    /* The native card's checkpoint (nlr_runtime_boot_ask_due): the clock
     * at its first turn. Its turns are far apart (seconds, QEMU), so its
     * boot turns are counted in time, NLR_BOOT_TURN_MS each. */
    uint32_t boot_first_ms;
    /* The escape (DISP) was held at power-on: at a look of the boot
     * checkpoint within NLR_BOOT_ESCAPE_MS of its first (boot_escape_from,
     * set once boot_escape_seen). Latched, so the pass and a boot from the
     * release bundle seconds later still honour it. */
    uint32_t boot_escape;
    uint32_t boot_escape_seen;
    uint32_t boot_escape_from;
    /* A boot program started from the release bundle with no card to
     * keep BOOTRUN on: nothing remembers a crash; DISP is the escape. */
    uint32_t boot_bundled;
    uint8_t item[NLR_MANIFEST_MAX_ENTRIES]; /* in ENABLED order */
    /* The foreground program NLOADER/BOOT names: its directory index (or
     * -1), started once the pass is done, and how that start went. */
    int32_t boot_index;
    int32_t boot_result;
    /* Set while the boot program runs: the task the checkpoint lives in
     * (the stock live-view GUI) waits at the checkpoint instead of drawing. */
    uint32_t boot_hold;
    /* Set once boot_program() has returned: this boot knows whether a boot
     * program starts. */
    uint32_t boot_decided;
    /* The boot record (runtime.c boot_record_*): NLR_BOOT_RECORD_* below,
     * the clock when the RUN record became durable, the last record write's
     * result, and the record being written (the program's id and, once the
     * start reports back, its outcome). One task writes it at a time: the
     * one that moves `boot_record` to WRITING. */
    uint32_t boot_record;
    uint32_t boot_record_ms;
    /* The start deferred by a busy store (NLR_BOOT_RECORD_START): the
     * directory index it starts, and the clock when it was first put off. */
    int32_t boot_start_index;
    uint32_t boot_start_ms;
    int32_t boot_record_result;
    struct nlr_boot_mark boot_mark;
    /* The GUI layer while a boot program starts (runtime.c boot_veil_blank):
     * the alpha planes cleared, each with a packed copy of what the stock
     * GUI had drawn there (kept bytes, 0 when the plane was empty), so that
     * a start that does not reach the program's entry gives the GUI its
     * planes back. veil_inside: the stock GUI's task is inside the
     * checkpoint -- held, or carrying the pass -- and draws nothing. */
    struct nlr_veil_plane {
        uint64_t address;
        uint32_t kept;
        uint32_t blank_ms;
        uint32_t refused;   /* no room for its copy: left as it is */
    } veil_planes[NLR_VEIL_PLANES];
    uint8_t *veil_keep;     /* NLR_VEIL_PLANES copies of NLR_VEIL_KEEP bytes */
    uint32_t veil_inside;
    uint32_t veil_lock;
    uint32_t veil_ms;       /* milliseconds the checkpoint waited (no clock) */
    uint32_t veil_blanks;
    uint32_t veil_restored;
    uint32_t veil_refused;
};

enum {
    NLR_MENU_REG_EMPTY = 0,
    NLR_MENU_REG_PENDING,
    NLR_MENU_REG_PUBLISHED,
    NLR_MENU_REG_UNCERTAIN,
};

/* One request per resident extension. Worker writes while load.state != 0;
 * the menu task reads/publishes only after acquiring idle state. Payloads
 * are copied, never borrowed from an extension's stack. Published requests
 * and failed publication ownership stay live for the entire boot. */
struct nlr_menu_registration {
    uint32_t state;
    struct nlr_menu_test_item item;
    char owner[NLR_MANIFEST_ID_MAX + 1];
    int32_t result;
};

/* ABI 4 program I/O state, shared by the input task's hook (writer of the
 * key state and events), the worker's API calls (readers; owners of the
 * capture and screen flags) and the filesystem task (directory callbacks).
 * Words are read and written whole; the event ring has one producer (the
 * input task) and one consumer (the program). */
#define NLR_KEY_EVENTS 16u
struct nlr_program_io {
    uint32_t hooked;            /* the input hook sits in the slot */
    uint32_t captured;          /* a foreground program owns the buttons */
    uint32_t list_active;       /* native menu owns input during ui_list */
    uint32_t keys;              /* NLR_KEY_* held at the last scan */
    uint32_t hold;              /* bits still hidden after a program ended,
                                 * until they are released */
    uint32_t event_head;        /* consumer index */
    uint32_t event_tail;        /* producer index */
    uint32_t event_overflow;    /* consumer discards incomplete history */
    struct nlr_key_event events[NLR_KEY_EVENTS];
    void *gfx_request;          /* loader-owned ABI 4 packed source */
    uint32_t gfx_active;        /* the program owns the screen */
    uint32_t activity_ms;       /* last user-activity signal sent */
    uint8_t *gfx_pixels;        /* the surface handed out, cleaned to the */
    uint8_t *gfx_alpha;         /* display on every present */
    uint32_t gfx_pixel_bytes;
    uint32_t gfx_alpha_bytes;
    uint32_t gfx_follows;       /* presents copied onto another shown buffer */
    /* The directory query in flight (one at a time, from the worker). */
    struct nlr_dirent *dir_out;
    uint32_t dir_want;
    uint32_t dir_seen;
    uint32_t dir_found;
    uint32_t dir_directories;   /* which enumeration pass is running */
    char dir_path[128];         /* the directory, as the filesystem sees it */
    /* nlr_program_dir_all's list, while it runs (else null) */
    char *dir_all;
    uint32_t dir_all_cap;
    uint32_t dir_all_count;
    uint32_t list_capacity;     /* confirmed by the actual native page */
    uint32_t list_rows;         /* the page can draw row kinds (ABI 6) */
};

struct nlr_runtime {
    /* Must be first: worker callbacks cast the object to the load. */
    struct nlr_load load;
    /* The card directory as last read. It lives in the runtime allocation,
     * never in static storage, because XIP carries no writable data. */
    struct nlr_manifest directory;
    uint8_t *directory_buffer;
    int32_t directory_result; /* NLR_NOT_READY until the first read */
    /* The last program check: its directory entry and result. */
    uint32_t checked;
    int32_t check_result;
    /* Set when a check waits to be shown: the row's OK re-enters the page,
     * and that entry shows the check once instead of reading the card. */
    uint32_t show_check;
    uint32_t detail_view;
    uint32_t recovery_view; /* explicit recovery page, separate from programs */
    uint32_t list_cursor;
    uint32_t probe_pending;
    char probe_id[NLR_MANIFEST_ID_MAX + 1];
    /* Same lifecycle as probe_pending for generic v2 programs: set when a
     * run is queued (or a kept region refuses a new one), cleared when the
     * directory or another check replaces the result. */
    uint32_t program_pending;
    char path[NLR_PATH_BYTES];
    /* Generic program (PLAN 6.3 M2-T4): the id of the queued run and the
     * ownership registry (M2-T2): a record per resident extension — kept
     * for the whole boot — plus one per foreground program while its run is
     * queued or executing. Extension records are written by the worker
     * before it republishes state == 0, foreground records by the page task
     * when it queues the run, so a reader that sees the attempt finished
     * sees the records too. */
    char program_id[NLR_MANIFEST_ID_MAX + 1];
    /* The program's pending text (see struct nlr_text_slot): written by
     * the worker while a program runs, drained by the page into the result
     * row. Lives in the runtime allocation because XIP carries no writable
     * data. */
    struct nlr_text_slot text;
    struct nlr_program_record resident[NLR_RESIDENT_MAX];
    struct nlr_menu_registration menu_registration[NLR_RESIDENT_MAX];
    struct nlr_resource_clone resource_clone;
    struct nlr_autoload autoload;
    struct nlr_enabled saved_enabled;
    int32_t enabled_save_result;
    void (*exit_original_input)(void *);
    uint32_t exit_swallow; /* input-task latch through both chord releases */
    uint32_t exit_uncertain; /* atomic: retain ownership, reboot required */
    uint32_t exit_notify; /* atomic: accepted chord, consumed by GUI guard/action */
    uint32_t exit_release_seen; /* actual MENU release, not a generic no-key event */
    uint32_t exit_menu_held; /* input owner defers this real MENU until release */
    uint32_t exit_menu_fields[5]; /* retained genuine per-key bank fields */
    uint32_t exit_menu_pending; /* atomic native event, consumed only by GUI */
    int32_t exit_menu_result; /* explicit wake/context refusal, never fake success */
    /* Initialized once for the whole boot; only the worker begins/ends an
     * owner, only the original input task publishes physical transitions. */
    struct nlr_input_state input;
    uint32_t input_owner;
    uint32_t input_physical; /* atomic seed, never a borrowed bank pointer */
    uint32_t input_focus_owner; /* input-producer-only focus transition tag */
#if NLR_HAS_GRAPHICS
    struct nlr_graphics graphics;
    struct nlr_native_graphics native_graphics;
    struct nlr_graphics_services graphics_services;
    uint64_t next_graphics_owner;
    uint64_t graphics_owner;
    uint32_t graphics_canvas_ready;
    uint32_t graphics_restore_pending;
    int32_t graphics_restore_result;
#endif
#if NLR_HAS_NATIVE_CARD
    struct nlr_native_card_runtime *native_card;
#endif
#if NLR_HAS_BITMAP
    void *bitmap_probe;
#endif
#if NLR_HAS_PAINT
    void *paint_probe;
#endif
#if NLR_HAS_PRIVATE_TEXT
    /* Native widgets can retain these descriptor/buffer pointers. The
     * runtime owns their allocation until the end of this boot. */
    struct nlr_private_text_pool *private_text;
#endif
    /* ABI 4 program I/O (buttons, screen, directory queries); last, so no
     * field above moves. */
    struct nlr_program_io io;
    /* The details keep their status row for the rest of a visit once it is
     * shown: their window is never entered again with fewer rows. */
    uint32_t status_kept;
    uint32_t detail_fresh;  /* the details' window opens: cursor on top */
    /* The detail rows as last drawn: a row action means the row the user
     * saw, whatever the state has become since. */
    uint32_t detail_shown;
    uint8_t detail_kinds[4];
    /* The longest the page has been built since its window was opened:
     * re-entering it never builds fewer rows (the firmware does not repaint
     * what shorter builds leave uncovered). */
    uint32_t page_max;
    /* A program's native list (ABI 4 ui_list), shared by the program's
     * task and the menu task: the program publishes a list (seq) and waits
     * for a choice (choice_seq); the page draws it (shown) and answers. */
    uint32_t list_view;
    struct {
        char title[NLR_LIST_TEXT_MAX + 1];
        char rows[NLR_LIST_ROWS_MAX][NLR_LIST_TEXT_MAX + 1];
        /* ABI 6 ui_rows: each row's NLR_ROW_* kind and flags and a value
         * row's text; a plain ui_list is all entries (rows_view 0). */
        uint32_t rows_view;
        /* ABI 6: the list is the program's text entry (ui_input) or its
         * caution (ui_caution), one row whose OK opens the loader's own
         * window (NLR_OWN_*); 0 for a list. */
        uint32_t dialog;
        uint8_t kinds[NLR_ROWS_MAX];
        uint8_t row_flags[NLR_ROWS_MAX];
        char values[NLR_ROWS_MAX][NLR_LIST_TEXT_MAX + 1];
        uint32_t count;
        uint32_t selected;
        uint32_t seq;
        uint32_t shown;
        uint32_t choice_seq;
        int32_t choice;
    } list;
    /* The page's item records, copied out of the module on the first build
     * of a page of row kinds and installed in the page record in place of
     * the module's, which are flash: a row's kind lives in two words of its
     * record (menu.h). `module` keeps the module's records, whose words are
     * every row's own when it is an entry. */
    struct {
        uint32_t installed;
        const uint8_t *module;
        _Alignas(8) uint8_t records[NLR_LIST_ROWS_MAX * 44u];
    } items;
    /* The checked program's settings, read when its details are drawn
     * (entry: the directory index + 1 they were read for, 0 for none) and
     * shown read-only until the complete native save path is verified. */
    uint32_t settings_view;
    struct {
        uint32_t entry;
        uint32_t count;
        uint32_t bytes;
        int32_t save_result; /* unsupported until durable save is verified */
        uint16_t line[NLR_SETTINGS_MAX];
        char path[NLR_PATH_BYTES];
        uint8_t raw[NLR_SETTINGS_BYTES + NLR_CACHE_LINE];
    } settings;
    /* Firmware code this boot has patched (ABI 4 code_hook): the target,
     * the handler now reached from it, the loader-owned code block that
     * handler lives in, and the bytes the target held. A record belongs to
     * the loader, not to the program that asked for it, but it can never
     * outlive the memory it points into: the handler must sit in a code
     * block the loader owns, and the hook is removed when that block is
     * given back. A resident extension's block is never given back, so its
     * hooks last until the camera restarts; a foreground program's block is
     * released when it ends, so its hooks go with it whether or not the
     * program remembered to remove them. A free record has target 0. */
    struct {
        uint32_t count;
        struct {
            uint64_t target;
            uint64_t handler;
            uint64_t owner_base;
            uint32_t owner_bytes;
            uint8_t original[NLR_CODE_HOOK_BYTES];
        } slot[NLR_CODE_HOOKS_MAX];
    } hooks;
    /* Resident blocks that lost a permission to the model's allocator
     * (core/exec.c, after a short grant): how many were put back and
     * audited as put back, and how many could not be. Either being
     * nonzero means the heap race the grant probe narrows was really met;
     * the second also means a resident extension's code is not what the
     * loader left, which the firmware may be about to call into. */
    uint32_t resident_restored;
    uint32_t resident_unrepaired;
    /* The loader's own window (ABI 6, menu_page.c): the camera's keyboard
     * (ui_input) or its caution box (ui_caution), one at a time on the
     * window-table entry the page record was built into. Installed on the
     * page's first opening: NLoader's page record moved here, and the
     * records of both, which the firmware reads for the rest of the boot;
     * the window record names one of them while it is up. `open` is the
     * one up for the program's request `seq`, `answered` the last request
     * it answered. The keyboard's `text` is what the program starts it
     * with (written before the request is published), `taken` what the
     * user saved (written by the menu task before the answer); `message`
     * is the caution's text and `buttons` its NLR_CAUTION_*. */
    struct {
        uint32_t ready;
        uint32_t open;
        uint32_t seq;
        uint32_t answered;
        _Alignas(16) uint8_t page_record[NLR_MENU_PAGE_BYTES];
        /* the keyboard */
        uint32_t length;
        uint32_t charset;
        _Alignas(16) uint8_t kbd_page[NLR_MENU_PAGE_BYTES];
        _Alignas(16) uint8_t kbd_events[NLR_INPUT_EVENTS_MAX * NLR_MENU_EVENT_BYTES];
        uint64_t kbd_tables[1];
        uint64_t kbd_handlers[NLR_MENU_HANDLERS];
        char text[NLR_INPUT_MAX + 1];
        char taken[NLR_INPUT_MAX + 2];
        /* the caution box */
        uint32_t caution_ready;
        uint32_t buttons;
        _Alignas(16) uint8_t caution_page[NLR_MENU_PAGE_BYTES];
        _Alignas(8) uint8_t caution_items[2u * NLR_MENU_ITEM_BYTES];
        _Alignas(16) uint8_t caution_events[2][NLR_INPUT_EVENTS_MAX * NLR_MENU_EVENT_BYTES];
        uint64_t caution_tables[2];
        uint64_t caution_handlers[NLR_MENU_HANDLERS];
        char message[NLR_CAUTION_MAX + 1];
    } own;
    /* ABI 7: the running program's events, routes, timers, watched
     * settings and screen (nlr/platform.h). */
    struct nlr_platform plat;
    /* Dev firmware (core_entry.c): stage 0's handshake, and when this core
     * first ran on its own clock; null and 0 in a loader built into the
     * module. */
    void *stage0;
    uint32_t stage0_since;
    /* The loader's own pages, all
     * on its one window: a stack of pages (the Apps list, NLoader's root,
     * the plugin list, a plugin, its details, About), each with the row the
     * cursor was on. `shown` says the list the page draws (`list`) is the
     * top page's, not a program's. `master` is the NLoader switch as this
     * boot has it (0 not read yet, 1 on, 2 off), `master_changed` once the
     * page changed it and `master_saved` whether the card took that; `boot_id` what BOOT names (`boot_known` once read)
     * and `boot_saved` the last write. `visited` is set the first time a
     * page of the loader is opened; `apps_hidden` once the Apps row was
     * left out of Setup. `go` and `arg` are what OK on each row does. */
    struct {
        uint32_t depth;
        struct {
            uint8_t kind;
            uint8_t reserved;
            uint16_t cursor;
            uint32_t index;
        } stack[NLR_PAGES_DEPTH];
        uint32_t shown;
        uint32_t master;
        uint32_t master_changed;
        int32_t master_saved;
        uint32_t boot_known;
        int32_t boot_saved;
        char boot_id[NLR_MANIFEST_ID_MAX + 1];
        uint32_t visited;
        uint32_t apps_hidden;
        uint8_t go[NLR_ROWS_MAX];
        uint8_t arg[NLR_ROWS_MAX];
    } pages;
    /* The last outcome of each program run this boot, by id
     * (nlr_runtime_outcome_keep), written and read by the page's task
     * only; `next` is the slot the next new id takes once all are used. */
    struct {
        uint32_t next;
        struct nlr_outcome slot[NLR_OUTCOMES_MAX];
    } outcomes;
    /* Set by the menu task when it redrew the page for a program that gave
     * the screen back before its end was recorded: the page is rebuilt
     * once more after the end, so the row shows the outcome
     * (graphics_runtime.c). */
    uint32_t outcome_redraw;
};

/* Open a foreground application a page chose (the Apps list, the details'
 * Open): one place, so how an application opens changes for all of them
 * at once (core/runtime.c). */
int nlr_runtime_open_app(struct nlr_runtime *r, uint32_t index);
/* nlr_runtime_open_app: the application started as a shell and the menu is
 * closing under it. */
#define NLR_SHELL_OPENED 0x5348

/* Leave the stock menu for a shell just started from it (core/runtime.c). */
int nlr_runtime_shell_open(struct nlr_runtime *r);
/* The buffers the GUI layer's registers name at this moment (core/api.c):
 * NLR_OK, or NLR_NOT_READY on a model that does not name them. */
int nlr_program_scanout(uint64_t *colour, uint64_t *alpha);
/* While a program is loaded, the changes of one physical scan in the
 * loader's log (core/api.c), from whichever carrier hook reads the input:
 * `taken` is whether that carrier hides the scan from the camera. */
struct nlr_scan_view;
void nlr_program_journal_scan(struct nlr_runtime *r,
                              const struct nlr_scan_view *view,
                              const void *object, int taken);
/* A directory entry for the loader itself (core/api.c): see there. */
int nlr_program_dir(struct nlr_runtime *r, const char *full, uint32_t index,
                    struct nlr_dirent *out);
int nlr_program_dir_all(struct nlr_runtime *r, const char *full, char *names,
                        uint32_t cap);

/* The firmware-code channel (core/hook.c). nlr_code_patch replaces whole
 * instructions inside one cache line; nlr_code_hook detours a target whose
 * current bytes equal `expect` and records what it overwrote, and
 * nlr_code_unhook puts those bytes back.
 *
 * nlr_code_hook refuses a handler that is not mapped executable and one
 * that is not inside a code block this loader owns — the running program's
 * own block, or a resident extension's. The block it found is the hook's
 * owner, and nlr_code_unhook_region removes every hook owned by a block
 * that is about to be released: a handler in freed memory is the one way
 * this channel could crash a camera long after the program ended. It
 * answers NLR_OK only when every one of them was really put back. */
int nlr_code_patch(const struct nlr_code_services *services, uint64_t address,
                   const uint8_t *bytes, uint32_t len);
int nlr_code_hook(struct nlr_runtime *r, uint64_t target, const uint8_t *expect,
                  uint64_t handler);
int nlr_code_unhook(struct nlr_runtime *r, uint64_t target);
int nlr_code_unhook_region(struct nlr_runtime *r, const void *base,
                           uint32_t bytes);

/* The buttons held by the user right now (api.c), read from the input
 * task's scan object: 0 when the model does not name it. */
uint32_t nlr_program_keys_now(void);

/* The loader's own state on an ordinary card (core/file_store.c), for a
 * model whose native filesystem services are not ported. Null when this
 * model's file services cannot keep that state durably, and then nothing
 * is ever loaded by itself. */
const struct nlr_card_store *nlr_file_store(void);

/* The store that says whether a file is on the card (probe_beside): the
 * native card's when the profile declares one, else the file reader's,
 * which needs no write service. The only place the choice is made. */
const struct nlr_card_store *nlr_card_presence_store(const struct nlr_services *svc);

/* Held while the loader would start loading, this asks for the same pause
 * SAFE_MODE asks for: the escape that needs no computer, for a card whose
 * extension stops the camera. It is read before every card operation of
 * the pass, so it stops one already under way as well as one about to
 * begin.
 *
 * On the Z 6III the pass begins when the NLoader page opens, and the
 * firmware's menu does not act on OK while another button is already
 * held (measured with DISP, AF-ON, i, DELETE and zoom-in; AF-ON leaves
 * the menu for the live view altogether). So the gesture here is the
 * other way round: press OK, and before letting it go press DISP as
 * well, keeping it down while the page appears. The OK was registered on
 * its own, and DISP is down by the time the page is built, which is when
 * this is read. Letting OK go first is too late -- the page is built at
 * once. All three timings are driven in hello/fixcheck.py (leg
 * `escape`); only that one pauses the pass.
 *
 * A model with a boot checkpoint (boot_hooks.autoload) begins the pass in
 * the first seconds of the live view instead, without the page. There the
 * gesture is the usual one for a start-up escape: hold DISP while
 * switching the camera on, until the live view is up. The pass begins
 * only once the input task is scanning (the input hook is in), so a
 * button held since power-on is read as held. */
#define NLR_AUTOLOAD_ESCAPE_KEYS NLR_KEY_DISP

/* ABI 4 program I/O (api.c): the input task's hook, its one-time install
 * over the stock slot occupant, and the hand-back when a program ends. */
void nlr_program_input(void *object);
void nlr_program_io_install(struct nlr_runtime *r);
/* Whether this model's buttons reach programs through that hook: then the
 * input task's scan is only known to run once the hook is in. */
int nlr_program_io_wanted(void);
void nlr_program_io_release(struct nlr_runtime *r);

/* Allocate and construct a fresh runtime. On NLR_PARTIAL the object stays
 * allocated because kernel-side references may exist; other failures unwind
 * completely. */
int nlr_runtime_create(struct nlr_runtime **out, const struct nlr_services *svc,
                       uint32_t arena_bytes);
/* Discover our runtime through the firmware task registry. *named counts
 * registry objects carrying our task name even when the full filter rejects
 * them; a nonzero count with no return means a previous attempt left
 * something behind and must not be retried. Ambiguity returns NULL. */
struct nlr_runtime *nlr_runtime_find(const struct nlr_services *svc,
                                     uint32_t *named);
/* Find or construct exactly once per boot; construction only happens when no
 * named object exists. The worker task is what makes the runtime findable
 * again from the next page entry or row action, since XIP code keeps no
 * writable state of its own. Registration by the firmware task creator is
 * assumed visible before create returns, as measured on the PoC body; if a
 * model registers asynchronously, a repeat attach could construct a second
 * runtime, which the registry ambiguity check then refuses — never retry on
 * that refusal. */
struct nlr_runtime *nlr_runtime_attach(const struct nlr_services *svc,
                                       uint32_t arena_bytes, uint32_t *named);

/* Installed only through the optional, complete exit service contract.
 * Suppresses handled chord bits while forwarding unrelated combined input. */
void nlr_runtime_exit_input(void *combined);
int nlr_runtime_input_begin(struct nlr_load *load);
void nlr_runtime_input_end(struct nlr_load *load);
int nlr_runtime_input_poll(struct nlr_runtime *runtime, struct nlr_key_event *event);
uint32_t nlr_runtime_input_raw(struct nlr_runtime *runtime);
/* Called only from the verified natural GUI checkpoint. Never replays a
 * complete MCU snapshot or processes other keys a second time. */
void nlr_runtime_exit_menu_checkpoint(struct nlr_runtime *runtime);

/* PLAN 4.3 SAFE_CHECK, MANIFEST and GATE, run in the caller's task. The
 * outcome stays in the runtime for the page to show, and any earlier program
 * check is forgotten because the list it referred to was replaced. */
int nlr_runtime_read_directory(struct nlr_runtime *r);
/* PLAN 4.3 LOAD for one directory entry, in the caller's task: header,
 * bounds, size and CRC are checked, nothing is executed. Refused without
 * touching the card when the directory was not read (NLR_NOT_READY), the
 * index is past its end (NLR_BOUNDS) or the gate refused the entry
 * (NLR_REFUSED). */
int nlr_runtime_check(struct nlr_runtime *r, uint32_t index);

int nlr_runtime_start_probe(struct nlr_runtime *r, uint32_t index, uint32_t mode);
int nlr_runtime_probe_recheck(struct nlr_load *load);

/* Generic v2 programs (PLAN 6.3 M2-T4). start_program mirrors start_probe:
 * mode 1 prepares only, mode 2 runs; both are stage builds. The file's
 * declared kind must still match the manifest entry (checked by the load).
 * Before anything is queued (M2-T2) the start is settled and then refused
 * with NLR_BUSY when the resident extension limit is reached and with
 * NLR_EXEC_BUDGET when the blocks already held plus the ones this run needs
 * would exceed the injected budget; refusals run nothing and rewrite no
 * record. The foreground run is registered (reserved block sizes, null
 * addresses) before it is queued. */
int nlr_runtime_start_program(struct nlr_runtime *r, uint32_t index,
                              uint32_t mode);
int nlr_runtime_program_recheck(struct nlr_load *load);
/* Ownership hand-over called by the load worker after a resource extension
 * initialized — successfully or not; a failed initialization may already
 * have published resources, which are kept and marked. The caller clears
 * the program state afterwards so later runs are not blocked by the
 * resident blocks. Refused with NLR_BUSY when no registry slot is free: the
 * caller keeps the blocks and refuses further runs instead of leaving them
 * unowned. */
int nlr_runtime_register_resident(struct nlr_load *load);
/* The resident extension record with this id, or null; a null id returns
 * the first resident extension. Foreground records are never returned:
 * they end with their run and nothing of them stays resident. */
const struct nlr_program_record *nlr_runtime_resident_find(
    const struct nlr_runtime *r, const char *id);
/* Clear the foreground records of runs that have ended: a finished attempt
 * released its blocks, so its reservation stops counting against the
 * coexistence budget. Called wherever the page observes the runtime — page
 * entry and every start decision — and left as a no-op while an attempt is
 * in flight or a cleanup-failed region is still held. Extension records
 * are never cleared here: residents are kept until the camera restarts. */
void nlr_runtime_settle_records(struct nlr_runtime *r);

/* The checked program's attempt as facts (struct nlr_outcome), read from
 * the load state; nlr_runtime_outcome_keep files them under the program's
 * id before anything replaces them -- the directory read again, another
 * check, a stop consumed -- once the attempt has ended. A cleanup that
 * failed is never filed: it is shown from the load state until restart.
 * nlr_runtime_outcome_find returns the kept outcome of an id, or null. */
/* The page rebuilt in place for an outcome recorded after its last redraw
 * (menu_page.c); NLR_NOT_READY when the profile declares no rebuild. */
int nlr_page_rebuild_outcome(struct nlr_runtime *r, const void *window);
/* A running program's list published after the page stopped following
 * its start, taken by the page and rebuilt in place (menu_page.c);
 * NLR_NOT_READY when there is none or no rebuild is declared. */
int nlr_page_show_late_list(struct nlr_runtime *r, const void *window);
/* Whether the running program reads the controls itself (ABI 7 input
 * taken or an ABI 4 input owner): the page then stops waiting for its
 * first list on the menu's task at once (menu_page.c wait_program). */
int nlr_page_program_reads_input(const struct nlr_runtime *r);
void nlr_runtime_outcome_fill(const struct nlr_runtime *r, struct nlr_outcome *out);
void nlr_runtime_outcome_keep(struct nlr_runtime *r);
const struct nlr_outcome *nlr_runtime_outcome_find(const struct nlr_runtime *r,
                                                   const uint8_t *id, uint32_t length);

/* Worker-side preparation only, restricted to the current extension init.
 * No firmware menu pointer is touched here. Missing resource binding refuses
 * registration; duplicate owner/item IDs are rejected without changing RAM. */
int nlr_runtime_menu_register(struct nlr_runtime *r,
                              const struct nlr_menu_test_item *item);
/* Menu-task owner, at the verified public checkpoint or page refresh. Active
 * target contexts defer publication; uncertain publication never retries. */
int nlr_runtime_menu_publish(struct nlr_runtime *r);

/* Lifecycle owner calls from menu task, only after a verified card mount and
 * resource-modification point. begin is once per runtime/boot, never from
 * page re-entry. Native cards read the complete dual-slot state after the
 * SAFE_MODE guard; legacy files are imported only on first initialization.
 * Pending is committed and confirmed before any init is queued. Worker init
 * prepares registrations; the public GuiMe checkpoint publishes them before
 * step advances. Clear is a separate confirmed commit. Owner change or any
 * uncertain commit stops this boot and retains its requests. Feature-disabled
 * legacy test stores retain their explicit file-operation contract. */
int nlr_runtime_autoload_begin(struct nlr_runtime *r,
                               const struct nlr_card_store *store);
/* One step, for a caller that is already the only one driving the pass:
 * the models whose lifecycle runs entirely on the menu task (the
 * mount-time checkpoint and the page there). Anywhere two tasks can ask,
 * they ask through nlr_runtime_autoload_continue below, which lets one of
 * them step at a time. */
int nlr_runtime_autoload_step(struct nlr_runtime *r);
/* Step until the pass needs something this caller cannot give it: the
 * worker (after every completed load) and a page visit both use it, so a
 * pass that opens the page once still reaches its end — including the
 * marker clear that tells the next boot it was not interrupted. An
 * extension that registers a menu item is the exception: only the menu
 * owner may publish it, and on the visit that starts the extension there
 * is nothing to publish yet, so that pass needs a second visit. Exactly
 * one caller steps at a time; a second one leaves a mark and returns. */
void nlr_runtime_autoload_continue(struct nlr_runtime *r);
/* One step of the pass under the same driver: the native card's menu
 * checkpoint and page visit take a single step each, as they always did,
 * but never at the same time as the worker carrying the pass on -- two
 * steps at once both start the same extension, and the one that loses
 * stops the pass with a busy and leaves the pending mark (QEMU qemu-ki-019).
 * A caller that finds the driver held leaves `pending` for the holder and
 * gets NLR_BUSY. */
int nlr_runtime_autoload_step_owned(struct nlr_runtime *r);
/* One turn of a boot checkpoint: a stock call the firmware makes by
 * itself, early in every boot and again and again, in a task allowed to
 * read the card (core/boot_autoload.c). It opens the boot's pass once the
 * input hook is in and MANIFEST opens on `store`, and from then on the
 * pass is carried the usual way. A card that does not answer within a
 * bounded number of asks leaves the pass to a page visit, as before. */
void nlr_runtime_boot_checkpoint(struct nlr_runtime *r,
                                 const struct nlr_card_store *store);
/* The two halves of a checkpoint turn, for a model whose checkpoint opens
 * the pass its own way (the native card's GUI checkpoint). enter: on the
 * GUI's task as the turn begins; holds it there while a boot program or
 * shell owns the screen, and answers 1 when it did. leave: as the turn
 * ends, on every path out; holds it if a program started during the turn,
 * puts back what the veil cleared when no entry ran, and makes the GUI
 * redraw once a program gave the screen back. Neither touches the card. */
int nlr_runtime_boot_turn_enter(struct nlr_runtime *r);
void nlr_runtime_boot_turn_leave(struct nlr_runtime *r);
/* One stock GUI turn (nlr_platform_gui_turn): the two halves above around
 * the stock call `callee`, whose result is returned unchanged; with no
 * runtime the call passes straight through. While a shell's menu exit is
 * still settling (plat.leaving) the halves are left out. No card, no menu
 * work. */
void *nlr_runtime_gui_turn(struct nlr_runtime *r, void *(*callee)(void));
/* The stock GUI committed a frame (the declared commit observer, on the
 * committing GUI task): a menu exit that a hold point has followed is
 * settled, and the next hold point may hold. */
void nlr_runtime_gui_committed(struct nlr_runtime *r);
/* What the commit observer saw: a stock commit returned `result`. A frame
 * the loader's own canvas rendered is the graphics path's to count; any
 * other accepted commit (bit 0) is the stock GUI's and settles the hold. */
void nlr_runtime_commit_seen(struct nlr_runtime *r, int32_t result);
/* The start-up escape for a model whose pass is opened by the native card's
 * menu checkpoint (no boot_hooks.autoload), asked on every turn before the
 * pass opens and before the card is asked anything -- SAFE_MODE and
 * STATE.NLS included. NLR_OK: go on. NLR_NOT_READY: an escape key is
 * declared but the hook that carries the scan (the program input slot, or
 * on a body whose one scan callback is the exit service's, that callback)
 * is not in yet, so a key held since power-on would read as released; ask
 * again next turn. NLR_DISABLED: the escape is latched (autoload.boot_escape):
 * held at this turn or an earlier one within NLR_BOOT_ESCAPE_MS of the first
 * look -- the power-on hold. A press after that window is not latched (the
 * Z 6III boot checkpoint's rule too): the pass's own guard still sees a key
 * held at the moment it checks. */
#define NLR_BOOT_ESCAPE_MS 4000u
int nlr_runtime_boot_escape(struct nlr_runtime *r);
/* Whether the calling task is one of the loader's own -- the worker or a
 * program's service task -- told by the stack the call runs on (each
 * records its range when it first runs). Any other task is the camera's:
 * its menu task, or a stock task running a program's hook. */
int nlr_runtime_on_loader_task(const struct nlr_runtime *r);
/* The same, for the loader worker alone. */
int nlr_runtime_on_worker(const struct nlr_runtime *r);
/* The native card's checkpoint before the pass opens: whether this turn, at clock `now_ms`,
 * may ask the card at all. The Z 6III asks on the boot turns that are
 * powers of two -- 1, 2, 4, ... -- of a loop that turns ~17 times a second;
 * the Z 8's menu checkpoint turns only now and then, so its boot turn is
 * the time since its first turn in NLR_BOOT_TURN_MS steps, and a turn asks
 * when that has reached the next power of two after the last ask. None
 * asks once the boot has stopped asking (no card after NLR_BOOT_CARD_ASKS
 * asks, or a card without the loader's directory). */
#define NLR_BOOT_TURN_MS 59u
int nlr_runtime_boot_ask_due(struct nlr_runtime *r, uint32_t now_ms);
/* The card was asked and has nothing for the loader: no card is mounted
 * (`mounted` 0), or one is and has no loader directory (`mounted` 1). The
 * release bundle's boot program starts once a card has shown it has no
 * directory, or none has come after NLR_BUNDLE_WAIT_TURNS turns; with no
 * bundle boot program the boot stops asking after NLR_BOOT_CARD_ASKS asks,
 * or at once for a card without a directory. DISP held and SAFE_MODE skip
 * the bundle as they skip every pass. */
void nlr_runtime_boot_no_card(struct nlr_runtime *r, int mounted);
/* A visit to the NLoader page while no pass has opened and the boot has
 * stopped asking: the next checkpoint turn asks the card once more (a card
 * put in after the asks ran out), and stops again if there is none. */
void nlr_runtime_boot_ask_again(struct nlr_runtime *r);
/* The boot record (STATE.NLS format 2, or BOOTRUN): the worker's hook once
 * an attempt has completed (core/load.c), which records the boot program's
 * outcome -- OK when its entry ran and it ended well, FAILED with the
 * result otherwise; and a write a busy store refused, retried from a task
 * that may use the card (the native menu checkpoint, the boot checkpoint).
 * The settle also retries a start whose own record read or RUN write met a
 * busy store (NLR_BOOT_RECORD_START), until NLR_BOOT_START_WAIT_MS have
 * passed: a busy card never silently skips the boot program. Neither does
 * anything when no boot program's record is owed. */
void nlr_runtime_boot_completed(struct nlr_runtime *r);
void nlr_runtime_boot_mark_settle(struct nlr_runtime *r);
/* How long a boot program runs before its start counts as good (OK) while
 * it is still running: asked at its waits (api.c sleep_ms, queue_wait), at
 * their entry and at every step while they wait, on the worker it runs on. The same ten seconds as the dev core's own health
 * report (stage 0, CORERUN). */
#define NLR_BOOT_GOOD_MS 10000u
void nlr_runtime_boot_alive(struct nlr_runtime *r);
enum {
    NLR_BOOT_RECORD_IDLE = 0, /* nothing owed this boot */
    NLR_BOOT_RECORD_OWED,     /* RUN durable; the start has not reported */
    NLR_BOOT_RECORD_WRITING,  /* one task is writing the record */
    NLR_BOOT_RECORD_DUE,      /* outcome known; the store was busy */
    NLR_BOOT_RECORD_DONE,     /* written, or refused for good */
    NLR_BOOT_RECORD_START,    /* the start's own record read or RUN write
                               * met a busy store: retried (settle) */
};
/* How long a boot program's start waits for a busy store to read its
 * record and write RUN, retried at the boot record's settle points, before
 * the start is given up for this boot (logged, boot_result NLR_BUSY). */
#define NLR_BOOT_START_WAIT_MS 60000u
/* Explicit menu action only: clear the interruption marker for the next
 * effective reboot, never restart this runtime's pass or change residents.
 * Refuses active work, retained failed cleanup, pending/uncertain publication
 * and SAFE_MODE. A failed clear remains paused and is never acknowledged. */
int nlr_runtime_autoload_recover(struct nlr_runtime *r);
/* Current-boot status by directory ID, from the existing resident,
 * registration and autoload records; never from next-boot settings. */
uint32_t nlr_runtime_extension_status(const struct nlr_runtime *r,
                                      uint32_t index);
/* Stops scheduling; does not cancel execution, roll back, release blocks or
 * clear the marker. A running item's final record is observed by step. */
int nlr_runtime_autoload_interrupt(struct nlr_runtime *r, int32_t reason);
/* Only changes last successfully saved settings, never the boot snapshot or
 * resident records. The explicit result prevents displaying failed saves
 * as acknowledged settings. */
int nlr_runtime_save_enabled(struct nlr_runtime *r,
                             const struct nlr_enabled *desired,
                             const struct nlr_card_store *store);

/* Settings of the checked program: one "key|label|choice,choice|D" line
 * each, D the current choice as one digit just before the newline. Load
 * reads <name>.SET beside r->path once per program and keeps it only when
 * every line is well formed. A field is text inside the loaded file:
 * 0 key, 1 label, 2 the comma-separated choices, 3 the value digit. */
void nlr_settings_load(struct nlr_runtime *r);
int nlr_settings_field(const struct nlr_runtime *r, uint32_t setting,
                       uint32_t field, const char **text, uint32_t *length);
uint32_t nlr_settings_choices(const struct nlr_runtime *r, uint32_t setting);
int nlr_settings_choice(const struct nlr_runtime *r, uint32_t setting,
                        uint32_t choice, const char **text, uint32_t *length);
uint32_t nlr_settings_value(const struct nlr_runtime *r, uint32_t setting);
/* The value of `key`, or -1 when the loaded settings have no such key. */
int32_t nlr_settings_find(const struct nlr_runtime *r, const char *key);
/* Saving is refused until filesystem/device synchronization and independent
 * readback have a verified binding. Neither card nor cached value changes. */
int nlr_settings_set(struct nlr_runtime *r, uint32_t setting, uint32_t value);

#endif
