#ifndef NLR_MANIFEST_H
#define NLR_MANIFEST_H

#include "nlr/load.h"
#include "nlr/card.h"

/* Exact token grammar shared by MANIFEST, ENABLED and card-state records. */
static inline int nlr_manifest_token_byte(uint8_t c)
{
    return c > 0x20 && c < 0x7f;
}

/* Card directory of loadable programs (PLAN 6.1/6.2). Line-based text, at
 * most 64 entries, display names at most 24 characters:
 *
 *   # id | kind | name | file | min_abi | model/firmware (optional)
 *   hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11
 *
 * The parser never rewrites the buffer: entries are offsets into the bytes
 * that were read, so the file can be re-parsed and a caller can show the
 * original text. A rejected line fails the whole file with its line number
 * and a reason; nothing is skipped silently. A line starting "#!" is a
 * directive (nlr_manifest_hide below), any other "#" line a comment. */
#define NLR_MANIFEST_MAX_ENTRIES 64u
#define NLR_MANIFEST_BYTES       0x2000u /* buffer budget for the whole file */
#define NLR_MANIFEST_ID_MAX      32u
#define NLR_MANIFEST_NAME_MAX    24u
#define NLR_MANIFEST_FILE_MAX    64u
#define NLR_MANIFEST_SUPPORT_MAX 128u


/* ENABLED encoding: ASCII, one manifest ID per line, LF or CRLF accepted,
 * optional final newline, blank lines ignored. No comments or whitespace
 * trimming: every nonempty line is exactly an ID. Matching and duplicate
 * detection are ASCII case-insensitive, like MANIFEST. Saving uses the
 * manifest's spelling and LF after each ID; an empty list is a zero-byte
 * file. Unknown IDs, foreground IDs and repeated IDs reject the whole file;
 * an ID MANIFEST hides (#!hide) is passed over instead. */
#define NLR_ENABLED_BYTES 4096u

enum {
    NLR_EN_OK = 0,
    NLR_EN_ID,
    NLR_EN_UNKNOWN,
    NLR_EN_KIND,
    NLR_EN_DUPLICATE,
    NLR_EN_COUNT,
    NLR_EN_SIZE,
};

struct nlr_enabled {
    uint32_t count;
    uint32_t error;
    uint32_t error_line;
    uint8_t index[NLR_MANIFEST_MAX_ENTRIES];
    /* Owned IDs survive directory refresh; index is a parse-time mapping. */
    char id[NLR_MANIFEST_MAX_ENTRIES][NLR_MANIFEST_ID_MAX + 1];
};

/* Copy only a validated list's live entries. Explicit scalar copies avoid
 * a freestanding large-struct assignment needing a libc memcpy symbol. */
static inline void nlr_enabled_copy(struct nlr_enabled *to,
                                     const struct nlr_enabled *from)
{
    to->count = from->count;
    to->error = from->error;
    to->error_line = from->error_line;
    for (uint32_t n = 0; n < from->count; n++) {
        to->index[n] = from->index[n];
        uint32_t k = 0;
        do {
            to->id[n][k] = from->id[n][k];
        } while (from->id[n][k++] && k <= NLR_MANIFEST_ID_MAX);
    }
}

/* Legacy file-store contract, retained for non-journal callers/tests.
 * Native production state deliberately supplies no replace/remove callbacks:
 * its full settings+pending journal and uncertain policy live in card_state.
 * Read-only firmware services cannot infer
 * absence from file_open failure. probe returns NLR_OK and writes 0/1 only
 * after reliably establishing absence/presence; card/IO uncertainty is an
 * error. replace/remove return success only after durable commit.
 *
 * replace is atomic: interruption leaves either the previous complete file
 * or the new complete file, never a partial file. The backend must commit
 * data before publishing its name and persist the directory update. A new
 * marker survives reset after success; an interrupted marker creation may
 * leave it absent, but no entry has run yet. Interrupted marker removal
 * leaves it present or absent: removal is attempted only after every entry
 * succeeded. Failed writes leave the old file or a complete new file and
 * MUST return failure, so the page must not claim its settings were saved.
 * remove must preserve an existing marker on a reported error. Backends
 * without these guarantees are unsupported, not replaced by open/close.
 * All callbacks are synchronous; buffers are no longer referenced on return.
 * This logic-batch contract is provisional: production stock write/commit
 * semantics must be researched and verified before a backend is connected. */
/* The boot program's record (runtime.c boot_program): what the last start
 * of the program NLOADER/BOOT names came to. RUN is written, durably,
 * before the start is queued; a boot that finds RUN still there skips the
 * program once (SKIPPED), because the start it records never reported
 * back. OK and FAILED are the start's own outcome. `result` is nonzero
 * only for FAILED; `id` is the program's MANIFEST id, empty only for NONE. */
enum {
    NLR_BOOT_MARK_NONE = 0,
    NLR_BOOT_MARK_RUN = 1,
    NLR_BOOT_MARK_OK = 2,
    NLR_BOOT_MARK_SKIPPED = 3,
    NLR_BOOT_MARK_FAILED = 4,
};
struct nlr_boot_mark {
    uint32_t mark;
    int32_t result;
    char id[NLR_MANIFEST_ID_MAX + 1u];
};

struct nlr_card_store {
    int32_t (*probe)(const char *path, uint32_t *present);
    int32_t (*replace)(const char *path, const uint8_t *data, uint32_t bytes);
    int32_t (*remove)(const char *path);
    /* Optional: a store that keeps the boot record in its own journal
     * (the native card's STATE.NLS, format 2) instead of a BOOTRUN file.
     * get reads the current record; set succeeds only once the new record
     * is durable and read back, and any later uncertainty is the store's
     * to report, as for its other commits. */
    int32_t (*boot_mark_get)(struct nlr_boot_mark *out);
    int32_t (*boot_mark_set)(const struct nlr_boot_mark *mark);
    /* Presence of `path` when `beside` (or null) names a file of this card
     * the caller is reading: that file opening is the card answering, so
     * a store that cannot tell absence by itself may take a failed open of
     * `path` as absence. NLR_NOT_READY when the card answers for nothing
     * (none mounted, or nothing on it opens). The SAFE_MODE checks around a
     * load ask this (load.c), on every body. */
    int32_t (*probe_beside)(const char *path, const char *beside, uint32_t *present);
};
/* Program ABI this load stage understands. A program asking for more is
 * refused by the gate; the number is a core contract, not a firmware
 * address. */
#define NLR_ABI_VERSION 9u

/* kind is mandatory and closed (PLAN 6.2). The list offers extension
 * settings or application open per kind; the load stage only checks. */
enum {
    NLR_KIND_NONE = 0,
    NLR_KIND_RESOURCE_EXTENSION = 1,
    NLR_KIND_FOREGROUND = 2,
};

/* Why the file was rejected. error_line is the 1-based source line, or 0
 * when the fault belongs to the file as a whole. */
enum {
    NLR_MF_OK = 0,
    NLR_MF_FIELDS = 1,    /* not 5 or 6 '|' separated fields */
    NLR_MF_ID = 2,        /* empty, too long, or not printable */
    NLR_MF_KIND = 3,      /* missing or outside the closed set */
    NLR_MF_NAME = 4,      /* empty, longer than 24, or not displayable */
    NLR_MF_FILE = 5,      /* empty, too long, or outside APPS */
    NLR_MF_ABI = 6,       /* missing or not a decimal number */
    NLR_MF_SUPPORT = 7,   /* malformed model/firmware list */
    NLR_MF_DUPLICATE = 8, /* id repeated */
    NLR_MF_COUNT = 9,     /* more than 64 entries */
    NLR_MF_SIZE = 10,     /* file larger than the buffer */
    NLR_MF_SWITCHED_OFF = 11, /* not read: the NLoader switch is off */
    NLR_MF_DIRECTIVE = 12,  /* a "#!" line that is no directive this parser takes */
};

/* Per-entry compatibility verdict (PLAN 4.3 GATE). */
enum {
    NLR_GATE_OK = 0,
    NLR_GATE_ABI = 1,     /* min_abi above what this build loads */
    NLR_GATE_MODEL = 2,   /* declaration does not cover this camera */
    NLR_GATE_UNKNOWN = 3, /* a declaration exists but our identity is absent */
    /* a program that describes itself with an id listed before it (MANIFEST
     * or an earlier file by name): shown, never loaded */
    NLR_GATE_DUPLICATE = 4,
};

/* Camera identity used by the gate. The generated bindings carry the model
 * and firmware strings from the profile; core holds no identity of its
 * own. */
struct nlr_identity {
    const char *model;
    const char *firmware;
};

struct nlr_manifest_entry {
    uint16_t id_off, id_len;
    uint16_t name_off, name_len;
    uint16_t file_off, file_len;
    uint16_t support_off, support_len; /* len 0 when the column is absent */
    uint16_t line;                     /* 1-based source line */
    uint8_t kind;                      /* NLR_KIND_* */
    uint8_t gate;                      /* NLR_GATE_* after the gate ran */
    uint32_t min_abi;
    /* A foreground program that runs over the live picture (kind column
     * "shell"): it may start at boot and, opened from
     * a menu, the menu closes under it. */
    uint8_t shell;
};

struct nlr_manifest {
    const uint8_t *buffer; /* the bytes the entries point into */
    uint32_t capacity;
    uint32_t bytes;
    uint32_t count;
    uint32_t usable; /* entries with gate == NLR_GATE_OK */
    uint32_t error;  /* NLR_MF_* */
    uint32_t error_line;
    struct nlr_manifest_entry entries[NLR_MANIFEST_MAX_ENTRIES];
};

/* Read the directory from the card into the caller's buffer. SAFE_MODE is
 * checked first, as it must be for every card operation (PLAN 4.4), and its
 * presence returns NLR_DISABLED without touching anything else. A failed
 * open returns NLR_IO: the firmware reports a missing card and a missing
 * file the same way, so the cause must be reported as "cannot read", never
 * guessed. trace may be null. */
int nlr_manifest_read(struct nlr_manifest *m, const struct nlr_services *svc,
                      uint8_t *buffer, uint32_t capacity,
                      struct nlr_trace *trace);
/* Parse bytes already in memory. Returns NLR_OK, NLR_FORMAT for a rejected
 * line or NLR_BOUNDS for too many entries; error/error_line say which. */
int nlr_manifest_parse(struct nlr_manifest *m, const uint8_t *buffer,
                       uint32_t bytes);
/* MANIFEST as an override: "#!hide <id>" lines.
 * nlr_manifest_hidden: 1 when a hide line of the parsed text names `id`
 *   (ASCII case-insensitive), whether or not any entry has that id.
 * nlr_manifest_hide: drop every entry a hide line names -- MANIFEST's own,
 *   a program that describes itself, a bundled one -- and return how many.
 *   Run once the directory is whole and before the gate; a hidden program
 *   is then not listed, not started by BOOT, and an ENABLED line naming it
 *   is passed over (nlr_enabled_parse), not an error. */
int nlr_manifest_hidden(const struct nlr_manifest *m, const uint8_t *id,
                        uint32_t len);
uint32_t nlr_manifest_hide(struct nlr_manifest *m);
/* The same, for a directory whose lines from byte `listed` on were added
 * from programs that describe themselves: such a line may repeat an id
 * listed before it, and is kept with gate NLR_GATE_DUPLICATE (which the
 * gate leaves as it is) instead of rejecting the directory. MANIFEST's own
 * lines, before `listed`, still may not repeat an id. */
int nlr_manifest_parse_listed(struct nlr_manifest *m, const uint8_t *buffer,
                              uint32_t bytes, uint32_t listed);
/* Decide per entry whether this build and camera may load it. model and
 * firmware come from the generated bindings; a null identity cannot confirm
 * a declaration and yields NLR_GATE_UNKNOWN rather than a guess. Matching is
 * ASCII case-insensitive, because the card text is written by hand. */
int nlr_manifest_gate(struct nlr_manifest *m, const char *model,
                      const char *firmware);

/* A program's own description (NPLD v3 metadata):
 * UTF-8 "key=value" lines ended by LF, NULs as padding at the end. Keys:
 * id, kind (app, shell, extension, service), name, name.<lang>,
 * description, description.<lang>, version, author, licence, min_abi,
 * targets (model/firmware list as in MANIFEST), memory (bytes, or with a K
 * or M suffix), uses (comma list), setting (repeated), icon. Unknown keys
 * are kept for later and ignored.
 *
 * nlr_meta_find: the value of the first `key` line, or 0.
 * nlr_meta_memory: the declared memory in bytes, 0 for none or a value
 *   that is not a size (at most 64 MiB).
 * nlr_meta_line: the MANIFEST line the description stands for, the program
 *   being `file` (an APPS/ path): "id | kind | name | file | min_abi
 *   [| targets]" and LF, written to `out`; its length, or 0 when the
 *   description lacks a field or a field breaks the MANIFEST grammar. */
const uint8_t *nlr_meta_find(const uint8_t *meta, uint32_t bytes,
                             const char *key, uint32_t *length);
uint32_t nlr_meta_memory(const uint8_t *meta, uint32_t bytes);
uint32_t nlr_meta_line(const uint8_t *meta, uint32_t bytes, const char *file,
                       char *out, uint32_t capacity);

/* The NLoader switch as the card keeps it (NLR_MASTER_PATH): 1 when the
 * file says "off", 0 when it says anything else, is missing or cannot be
 * read -- the switch only ever stops loading, never starts it. */
int nlr_master_off(const struct nlr_services *svc, struct nlr_trace *trace);
/* nlr_manifest_read on a native card whose one request is held elsewhere
 * answers NLR_BUSY and leaves `m` exactly as it was. */

/* Read the first `capacity` bytes of a file (all of it when shorter) into
 * whole owned cache lines; no SAFE_MODE check. */
int nlr_card_read_prefix(const struct nlr_services *svc, const char *path,
                         uint8_t *buffer, uint32_t capacity, uint32_t *bytes,
                         struct nlr_trace *trace);

/* Read an ordinary file into whole owned cache lines; no SAFE_MODE check.
 * The lifecycle owner must reliably check its guard before calling. */
int nlr_card_read(const struct nlr_services *svc, const char *path,
                  uint8_t *buffer, uint32_t capacity, uint32_t *bytes,
                  struct nlr_trace *trace);
int nlr_enabled_parse(struct nlr_enabled *enabled, const struct nlr_manifest *m,
                      const uint8_t *buffer, uint32_t bytes);
int nlr_enabled_encode(const struct nlr_enabled *enabled,
                       const struct nlr_manifest *m, uint8_t *buffer,
                       uint32_t capacity, uint32_t *bytes);
/* saved is changed only after durable success; desired may alias saved.
 * The return value, not an edited list, is the save acknowledgement. */
int nlr_enabled_save(struct nlr_enabled *saved,
                     const struct nlr_enabled *desired,
                     const struct nlr_manifest *m,
                     const struct nlr_card_store *store, uint8_t *buffer,
                     uint32_t capacity);

#endif
