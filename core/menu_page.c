#include "nlr/menu.h"
#include "nlr/runtime.h"
#if NLR_HAS_NATIVE_CARD
#include "nlr/card_state.h"
#endif

/* The rung decides what the page does beyond its title: the page rung
 * rewrites the row, load-only and later read the card from it. */
#if defined(NLR_STAGE_LOAD_ONLY) || defined(NLR_STAGE_PREPARE_ONLY) || \
    defined(NLR_STAGE_EXEC)
#define PAGE_READS_CARD 1
#endif
#if defined(PAGE_READS_CARD) || defined(NLR_STAGE_PAGE)
#define PAGE_WRITES_ROW 1
#endif

/* Generated with the menu data when the profile declares the page. */
extern const struct nlr_menu_page nlr_menu_page;
/* The labels of the Setup page's two rows, and the camera the build is for
 * (generated bindings). */
extern const struct nlr_menu_prefill nlr_menu_prefill;
extern const struct nlr_identity nlr_identity;
/* The generated bindings carry the service table the card checks use. */
extern const struct nlr_services nlr_services;

#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
enum detail_operation {
    DETAIL_CHECK_AGAIN,
    DETAIL_PROGRAM,
    DETAIL_PROBE,
};

static enum detail_operation detail_operation_kind(const struct nlr_runtime *r)
{
    /* These flags belong to the menu owner and describe the queued attempt.
     * The worker clears/replaces its live header while rereading the file. */
    if (r->program_pending && r->probe_pending)
        return DETAIL_CHECK_AGAIN;
    if (r->program_pending)
        return DETAIL_PROGRAM;
    if (r->probe_pending)
        return DETAIL_PROBE;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return DETAIL_CHECK_AGAIN;
    if (r->load.header_bytes == NLR_GENERIC_HEADER_SIZE)
        return DETAIL_PROGRAM;
    if (r->load.header_bytes == NLR_PROBE_HEADER_SIZE)
        return DETAIL_PROBE;
    return DETAIL_CHECK_AGAIN;
}
#endif

static int store_text(const struct nlr_menu_page *p, const char *text,
                       uint32_t token, uint32_t style)
{
#if NLR_HAS_PRIVATE_TEXT
#ifdef PAGE_WRITES_ROW
    (void)p;
    return nlr_private_text_writer(text, token, style);
#else
    /* HookOnly has static ROM labels and must not create a writable pool. */
    (void)p;
    (void)text;
    (void)style;
    return nlr_private_text_token(token, 0) ? NLR_OK : NLR_NOT_READY;
#endif
#else
    p->text_store(text, token, style);
    return NLR_OK;
#endif
}

static int bind_text(const struct nlr_menu_page *p, void *widget, uint32_t token)
{
#if NLR_HAS_PRIVATE_TEXT
    if (nlr_private_text_token(token, 0))
        return nlr_private_text_bind(widget, token);
#endif
    p->text_bind(widget, token);
    return NLR_OK;
}

#ifdef PAGE_WRITES_ROW

/* Row text under construction. Automatic storage only: XIP carries no
 * writable data, and the original writer copies out of this buffer before
 * it returns. Text past the writer's clamp is dropped here, so what is
 * stored is what is shown. */
struct row_text {
    char bytes[NLR_SLOT_TEXT_MAX + 1];
    uint32_t length;
};

static void put(struct row_text *t, const char *text)
{
    while (text && *text && t->length < NLR_SLOT_TEXT_MAX)
        t->bytes[t->length++] = *text++;
    t->bytes[t->length] = 0;
}

/* Every visible row owns a separate original text slot. */
static uint32_t row_slot(const struct nlr_menu_page *p, uint32_t row)
{
    return p->row_slots ? p->row_slots[row] : p->row_slot;
}

static void *row_widget(const struct nlr_menu_page *p, void *container,
                         uint32_t row)
{
    return p->widget_find ? p->widget_find(p->row_widget + row, container) : 0;
}

static uint32_t row_store(const struct nlr_menu_page *p, void *widget,
                      uint32_t row, const struct row_text *t)
{
    uint32_t slot = row_slot(p, row);
    int stored = store_text(p, t->bytes, slot, p->row_style);
    int bound = widget ? bind_text(p, widget, slot) : NLR_NOT_READY;
    /* Even a rejected private write must invalidate an old cached label:
     * getter then supplies its ROM failure, never the previous success. */
    return stored == NLR_OK && bound == NLR_OK;
}

#endif

#ifdef PAGE_READS_CARD
enum { DETAIL_OPERATION, DETAIL_RESULT, DETAIL_BACK, DETAIL_ROWS };
enum {
    EXT_TOGGLE, EXT_CURRENT, EXT_NEXT, EXT_EARLIER, EXT_LATER,
    EXT_RECOVER, EXT_BACK, EXT_ROWS
};

/* A foreground program's or probe's detail rows, by kind: the operation,
 * the status when it says something, back. */
enum { ROW_OPERATION, ROW_STATUS, ROW_SETTINGS, ROW_BACK, ROW_KINDS_MAX = 4 };

static uint32_t view_rows(const struct nlr_menu_page *p,
                          const struct nlr_runtime *r, uint8_t *kinds);

/* A word of the page record, wherever the record is now: in the window
 * table entry it was built into until the loader's own window is
 * installed, in the runtime after (own_install). */
static void *page_word(const struct nlr_menu_page *p, struct nlr_runtime *r,
                       void *built)
{
    uintptr_t at = (uintptr_t)built, base = (uintptr_t)p->page_record;
    if (r && base && __atomic_load_n(&r->own.ready, __ATOMIC_ACQUIRE) &&
        at >= base && at < base + NLR_MENU_PAGE_BYTES)
        return r->own.page_record + (at - base);
    return built;
}

/* The firmware builds as many rows as the page record counts. */
static void size_page(const struct nlr_menu_page *p, struct nlr_runtime *r,
                      uint32_t count)
{
    if (p->page_count)
        *(uint16_t *)page_word(p, r, p->page_count) = (uint16_t)(count ? count : 1);
}

_Static_assert(NLR_MENU_ITEM_BYTES == 44u, "runtime.h sizes the record copy");
_Static_assert(NLR_MENU_ROWS_SLOTS == 2u * NLR_ROWS_MAX,
               "a page of row kinds has a label and a value slot per row");

/* The page's item records the firmware builds from: the runtime's copy,
 * installed in the page record the first time a page of row kinds is
 * built. Until then the page keeps the module's own (flash) records. The
 * page also takes the flag that lets the cursor pass disabled rows: only
 * text and greyed rows are ever disabled on it. */
static uint8_t *page_records(const struct nlr_menu_page *p,
                             struct nlr_runtime *r)
{
    if (!nlr_menu_rows_available(p) || p->row_count > NLR_LIST_ROWS_MAX)
        return 0;
    if (!r->items.installed) {
        void **items = page_word(p, r, p->page_items);
        const uint8_t *module = (const uint8_t *)*items;
        if (!module)
            return 0;
        for (uint32_t n = 0; n < p->row_count * NLR_MENU_ITEM_BYTES; n++)
            r->items.records[n] = module[n];
        r->items.module = module;
        *items = r->items.records;
        *(uint32_t *)((uint8_t *)items - NLR_MENU_PAGE_ITEMS) |= p->skip_flag;
        r->items.installed = 1;
    }
    return r->items.records;
}

/* The rows of a page of row kinds now on show (at most NLR_ROWS_MAX). */
static uint32_t kind_rows(const struct nlr_runtime *r)
{
    if (!r->list_view || !r->list.rows_view)
        return 0;
    return r->list.count < NLR_ROWS_MAX ? r->list.count : NLR_ROWS_MAX;
}

/* Before a build: every row takes its own flags and value words back, and
 * a row of another kind its kind's -- a switch the switch flags and its ON
 * or OFF picture, a row with a choice the text-value flags and its value
 * slot (the upper half of the row slots), a text row no > mark. A value is
 * stored in its slot now: the build binds the slot, and a store after it
 * would not redraw the value. Nothing happens on a page that never showed
 * a row of another kind. */
static void stage_rows(const struct nlr_menu_page *p, struct nlr_runtime *r)
{
    uint32_t shown = kind_rows(r), any = 0;
    for (uint32_t k = 0; k < shown; k++)
        any |= r->list.kinds[k] != NLR_ROW_ENTRY ||
               (r->list.row_flags[k] & NLR_ROW_GREYED);
    if (!any && !r->items.installed)
        return;
    uint8_t *records = page_records(p, r);
    if (!records)
        return;
    for (uint32_t k = 0; k < p->row_count; k++) {
        uint32_t at = k * NLR_MENU_ITEM_BYTES;
        const uint8_t *own = r->items.module + at;
        uint32_t flags = *(const uint32_t *)(own + NLR_MENU_ITEM_FLAGS);
        uint32_t value = *(const uint32_t *)(own + NLR_MENU_ITEM_VALUE);
        uint32_t style = *(const uint32_t *)(own + NLR_MENU_ITEM_STYLE);
        switch (k < shown ? r->list.kinds[k] : NLR_ROW_ENTRY) {
        case NLR_ROW_SWITCH:
            flags = (flags & ~NLR_MENU_ITEM_MARK) | p->switch_flags;
            value = r->list.row_flags[k] & NLR_ROW_ON ? p->switch_on : p->switch_off;
            break;
        case NLR_ROW_SELECT:
            flags |= p->select_flags;
            /* a greyed row opens nothing: no > mark, and the value keeps
             * the room the mark took (Z8 QEMU, qemu-gh-005) */
            if (r->list.row_flags[k] & NLR_ROW_GREYED)
                flags &= ~NLR_MENU_ITEM_MARK;
            value = row_slot(p, NLR_ROWS_MAX + k);
            store_text(p, r->list.values[k], value, p->select_format);
            if (p->select_style)
                style = p->select_style;
            break;
        case NLR_ROW_TEXT:
            flags &= ~NLR_MENU_ITEM_MARK;
            break;
        default:
            break;
        }
        *(uint32_t *)(records + at + NLR_MENU_ITEM_FLAGS) = flags;
        *(uint32_t *)(records + at + NLR_MENU_ITEM_VALUE) = value;
        *(uint32_t *)(records + at + NLR_MENU_ITEM_STYLE) = style;
    }
}

/* After a build, what the records cannot say: a switch's state on the
 * toggle the firmware built for it, and the text and greyed rows disabled
 * (greyed; the cursor passes them). The values are stored again, for a
 * redraw that does not rebuild. */
static void finish_rows(const struct nlr_menu_page *p, void *window,
                        void *container, struct nlr_runtime *r)
{
    uint32_t shown = kind_rows(r);
    if (!shown || !r->items.installed)
        return;
    void *table = *(void **)((uint8_t *)window + p->widget_table);
    for (uint32_t k = 0; k < shown; k++) {
        uint32_t kind = r->list.kinds[k], flags = r->list.row_flags[k];
        if (kind == NLR_ROW_SELECT)
            store_text(p, r->list.values[k], row_slot(p, NLR_ROWS_MAX + k),
                       p->select_format);
        if (kind == NLR_ROW_SWITCH && table) {
            void *row = p->row_get(table, k, 0);
            if (row)
                p->switch_set(row, flags & NLR_ROW_ON ? 1u : 0u);
        }
        if (kind == NLR_ROW_TEXT || (flags & NLR_ROW_GREYED)) {
            void *row = row_widget(p, container, k);
            if (row)
                p->widget_enable(row, p->widget_enable_inverted ? 1u : 0u);
        }
    }
}

/* A window opened anew is repainted whole: it is built at its view's
 * length. Entered again, it never shrinks: the firmware repaints only what
 * the new rows cover, so the extra rows are drawn empty instead. */
static void size_fresh(const struct nlr_menu_page *p, struct nlr_runtime *r,
                       uint32_t count)
{
    r->page_max = count;
    size_page(p, r, count);
    stage_rows(p, r);
}

static void size_again(const struct nlr_menu_page *p, struct nlr_runtime *r,
                       uint32_t count)
{
    if (count < r->page_max)
        count = r->page_max;
    r->page_max = count;
    size_page(p, r, count);
    stage_rows(p, r);
}

#if defined(NLR_STAGE_EXEC)
static void pages_resume(struct nlr_runtime *r);
#endif

void nlr_page_prepare_redraw(struct nlr_runtime *r)
{
    if (!r) return;
#if defined(NLR_STAGE_EXEC)
    /* A program that held the screen gives it back: the page it was opened
     * from is what the redraw shows, sized for its own rows. */
    pages_resume(r);
#endif
    uint8_t kinds[ROW_KINDS_MAX];
    size_again(&nlr_menu_page, r, view_rows(&nlr_menu_page, r, kinds));
}

/* A program gave the screen back before its end was recorded, so the
 * redraw then had no outcome to show (graphics_runtime.c). Now that the
 * attempt is over, the page is rebuilt once more with the stock in-place
 * rebuild (`menu.page.rebuild`), as a row action rebuilds it: sized for
 * the page's own rows, its row kinds staged, then shown. Without the
 * declared rebuild nothing is done and the outcome waits for the page's
 * next drawing, as before. */
int nlr_page_rebuild_outcome(struct nlr_runtime *r, const void *window)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    if (!r || !window || !p->page_rebuild || !p->present)
        return NLR_NOT_READY;
#if defined(NLR_STAGE_EXEC)
    pages_resume(r);
#endif
    r->show_check = 1;
    uint8_t kinds[ROW_KINDS_MAX];
    size_fresh(p, r, view_rows(p, r, kinds));
    p->page_rebuild(*(const uint16_t *)window,
                    *(const uint16_t *)((const uint8_t *)window + NLR_MENU_WINDOW_ID));
    p->present(p->present_source, p->present_a, p->present_b);
    /* Re-armed, as refresh_page does after the stock refresh: a display
     * entry that follows the rebuild keeps the directory and outcome just
     * drawn instead of reading the card again. Here the worker that just
     * ended may still hold the card's one request for its log, and a read
     * answered busy would replace the list with "MANIFEST not read" (Z8
     * QEMU fix-misc qemu-doom-002). */
    r->show_check = 1;
    return NLR_OK;
}

#if defined(NLR_STAGE_EXEC)
/* A running program's list that the page has not taken: published after
 * the page stopped following the program's start (follow_program waits
 * LIST_WAIT_MS on the menu's task, then leaves the page as it is). A
 * program that lists its card first -- Files reads its directory one
 * entry per enumeration -- publishes later than that, and without this
 * its list was never drawn: the row looked dead and the program waited
 * for a choice nobody could make. */
static int late_program_list(const struct nlr_runtime *r)
{
    return __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0 &&
           __atomic_load_n(&r->io.list_active, __ATOMIC_ACQUIRE) &&
           __atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE) != r->list.shown &&
           !r->list_view && !r->settings_view;
}

/* The menu's turn after a program published a list (api.c wakes it): the
 * page takes the list and is rebuilt in place, once, as for an outcome. */
int nlr_page_show_late_list(struct nlr_runtime *r, const void *window)
{
    if (!r || !window || !late_program_list(r))
        return NLR_NOT_READY;
    r->list_view = 1;
    r->detail_view = r->recovery_view = 0;
    int result = nlr_page_rebuild_outcome(r, window);
    if (result != NLR_OK)
        r->list_view = 0; /* the next drawing or row action takes it */
    return result;
}
#endif

/* The window the page is on is the details' own. */
static int on_details(const struct nlr_menu_page *p, const void *window)
{
    return p->detail_next && p->detail_record && window == p->detail_record;
}

/* Leave the details' window for the list: size the page for the list the
 * pop rebuilds, then pop. */
static void pop_details(struct nlr_menu_nav *nav, struct nlr_runtime *r)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    uint8_t kinds[ROW_KINDS_MAX];
    size_fresh(p, r, view_rows(p, r, kinds));
    nav->next = p->back_next;
}

static void refresh_page(struct nlr_menu_nav *nav, struct nlr_runtime *r)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    uint8_t kinds[ROW_KINDS_MAX];
    if (p->page_rebuild && p->present && p->stay_next) {
        /* Rebuilt in place on a cleared layer: built at the view's own
         * length, as a window opened anew is. The entry runs inside the
         * rebuild and takes show_check; the window's widgets are new
         * after it, so nothing found before is used again. */
        const uint8_t *window = nav->window;
        size_fresh(p, r, view_rows(p, r, kinds));
        p->page_rebuild(*(const uint16_t *)window,
                        *(const uint16_t *)(window + NLR_MENU_WINDOW_ID));
        p->present(p->present_source, p->present_a, p->present_b);
        nav->next = p->stay_next;
        return;
    }
    size_again(p, r, view_rows(p, r, kinds));
    if (p->page_refresh) {
        /* Keep the old visible-row count and viewport available to the
         * original refresh while the entry handler supplies the new rows. */
        p->page_refresh(nav->window);
        /* The refresh consumes show_check. Re-arm it for the following
         * native widget/image reconstruction so this display-only entry
         * keeps the checked directory and result without another read. */
        r->show_check = 1;
    }
    nav->next = p->reenter_next;
}


static void put_bytes(struct row_text *t, const uint8_t *bytes, uint32_t count)
{
    for (uint32_t n = 0; n < count && t->length < NLR_SLOT_TEXT_MAX; n++)
        t->bytes[t->length++] = (char)bytes[n];
    t->bytes[t->length] = 0;
}

static void put_number(struct row_text *t, uint32_t value)
{
    char digits[10];
    uint32_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value && count < sizeof digits);
    while (count && t->length < NLR_SLOT_TEXT_MAX)
        t->bytes[t->length++] = digits[--count];
    t->bytes[t->length] = 0;
}

static void put_name(struct row_text *t, const struct nlr_runtime *r,
                     uint32_t index)
{
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    put_bytes(t, r->directory.buffer + e->name_off, e->name_len);
}
static int entry_id_matches(const struct nlr_runtime *r, uint32_t index,
                             const char *id)
{
    const struct nlr_manifest_entry *entry = &r->directory.entries[index];
    for (uint32_t n = 0; n < entry->id_len; n++)
        if (!id[n] || id[n] != (char)r->directory.buffer[entry->id_off + n])
            return 0;
    return id[entry->id_len] == 0;
}

static uint32_t enabled_position(const struct nlr_runtime *r, uint32_t index)
{
    for (uint32_t n = 0; n < r->saved_enabled.count; n++)
        if (entry_id_matches(r, index, r->saved_enabled.id[n]))
            return n;
    return NLR_NO_CHECK;
}

static int extension_detail(const struct nlr_runtime *r)
{
    return r && r->autoload.store && r->detail_view &&
           r->checked < r->directory.count &&
           r->directory.entries[r->checked].kind == NLR_KIND_RESOURCE_EXTENSION;
}

static void describe_extension(struct row_text *t, const struct nlr_runtime *r,
                                 uint32_t index)
{
    switch (nlr_runtime_extension_status(r, index)) {
    case NLR_EXTENSION_LOADED: put(t, "loaded"); break;
    case NLR_EXTENSION_PARTIAL:
#ifdef NLR_STAGE_EXEC
        put(t, "failed; may be active");
#else
        put(t, "failed; possibly partial");
#endif
        break;
    case NLR_EXTENSION_INITIALIZING:
#ifdef NLR_STAGE_EXEC
        put(t, "initializing");
#else
        put(t, "initializing; publication pending");
#endif
        break;
    default: put(t, "not executed"); break;
    }
}

#ifdef NLR_STAGE_EXEC
/* Keep list status short beside the complete manifest name. The settings
 * view retains the partial-failure warning; this marker does not imply rollback. */
static void describe_extension_list(struct row_text *t, const struct nlr_runtime *r,
                                    uint32_t index)
{
    switch (nlr_runtime_extension_status(r, index)) {
    case NLR_EXTENSION_LOADED: put(t, ": loaded"); break;
    case NLR_EXTENSION_PARTIAL: put(t, ": failed"); break;
    case NLR_EXTENSION_INITIALIZING: put(t, ": init"); break;
    default: put(t, ": not run"); break;
    }
}

static int resource_save_uncertain(const struct nlr_runtime *r)
{
#if NLR_HAS_NATIVE_CARD
    return r->autoload.result == NLR_CARD_STATE_COMMIT_UNCERTAIN ||
           r->autoload.enabled_result == NLR_CARD_STATE_COMMIT_UNCERTAIN ||
           r->autoload.recovery_result == NLR_CARD_STATE_COMMIT_UNCERTAIN ||
           r->enabled_save_result == NLR_CARD_STATE_COMMIT_UNCERTAIN;
#else
    (void)r;
    return 0;
#endif
}

static int recovery_reboot_required(const struct nlr_runtime *r)
{
    return resource_save_uncertain(r) ||
           r->autoload.recovery_result == NLR_EXEC_TIMEOUT ||
           r->autoload.recovery_result == NLR_EXEC_RESTORE;
}
#endif

static void describe_recovery(struct row_text *t, const struct nlr_runtime *r)
{
#ifdef NLR_STAGE_EXEC
    if (resource_save_uncertain(r)) {
        put(t, "Save uncertain; loading stopped");
        return;
    }
    if (r->autoload.recovery_armed) {
        put(t, "Still paused; reboot required");
        return;
    }
    switch (r->autoload.recovery_result) {
    case NLR_NOT_READY: put(t, "Paused: check enabled list"); break;
    case NLR_DISABLED: put(t, "Paused: SAFE_MODE"); break;
    case NLR_BUSY: put(t, "Paused: work pending"); break;
    case NLR_EXEC_TIMEOUT: put(t, "State uncertain; reboot required"); break;
    case NLR_EXEC_RESTORE: put(t, "Cleanup failed; reboot required"); break;
    default: put(t, "Recovery failed; still paused"); break;
    }
#else
    if (r->autoload.recovery_armed) {
        put(t, "Recovery armed; effective reboot required");
        return;
    }
    switch (r->autoload.recovery_result) {
#if NLR_HAS_NATIVE_CARD
    case NLR_CARD_STATE_COMMIT_UNCERTAIN:
        put(t, "Commit uncertain; loading stopped; reboot required"); break;
#endif
    case NLR_NOT_READY: put(t, "Autoload paused; correct enabled list first"); break;
    case NLR_DISABLED: put(t, "Recovery blocked: SAFE_MODE; still paused"); break;
    case NLR_BUSY: put(t, "Recovery blocked: work pending; still paused"); break;
    case NLR_EXEC_TIMEOUT: put(t, "State uncertain; effective reboot required"); break;
    case NLR_EXEC_RESTORE: put(t, "Cleanup failed; effective reboot required"); break;
    default: put(t, "Recovery failed; still paused"); break;
    }
#endif
}

static void change_extension_setting(struct nlr_runtime *r, uint32_t row)
{
    if (r->autoload.enabled_result != NLR_OK) {
        r->enabled_save_result = r->autoload.enabled_result;
        return;
    }
    struct nlr_enabled desired;
    nlr_enabled_copy(&desired, &r->saved_enabled);
    uint32_t position = enabled_position(r, r->checked);
    if (row == EXT_TOGGLE) {
        if (position != NLR_NO_CHECK) {
            for (uint32_t n = position; n + 1 < desired.count; n++) {
                desired.index[n] = desired.index[n + 1];
                for (uint32_t c = 0; c < sizeof desired.id[n]; c++) {
                    desired.id[n][c] = desired.id[n + 1][c];
                    if (!desired.id[n][c])
                        break;
                }
            }
            desired.count--;
        } else {
            if (desired.count == NLR_MANIFEST_MAX_ENTRIES) {
                r->enabled_save_result = NLR_BOUNDS;
                return;
            }
            const struct nlr_manifest_entry *entry = &r->directory.entries[r->checked];
            uint32_t n = desired.count++;
            desired.index[n] = (uint8_t)r->checked;
            for (uint32_t c = 0; c < entry->id_len; c++)
                desired.id[n][c] = (char)r->directory.buffer[entry->id_off + c];
            desired.id[n][entry->id_len] = 0;
        }
    } else {
        if (position == NLR_NO_CHECK ||
            (row == EXT_EARLIER && position == 0) ||
            (row == EXT_LATER && position + 1 == desired.count))
            return;
        uint32_t other = row == EXT_EARLIER ? position - 1 : position + 1;
        uint8_t index = desired.index[position];
        desired.index[position] = desired.index[other];
        desired.index[other] = index;
        uint32_t left_done = 0, right_done = 0;
        for (uint32_t c = 0; c < sizeof desired.id[position]; c++) {
            char left = left_done ? 0 : desired.id[position][c];
            char right = right_done ? 0 : desired.id[other][c];
            desired.id[position][c] = right;
            desired.id[other][c] = left;
            left_done |= left == 0;
            right_done |= right == 0;
            if (left_done && right_done)
                break;
        }
    }
    nlr_runtime_save_enabled(r, &desired, r->autoload.store);
}


static const char *manifest_reason(uint32_t error)
{
    switch (error) {
    case NLR_MF_FIELDS: return "bad fields";
    case NLR_MF_ID: return "bad id";
    case NLR_MF_KIND: return "bad kind";
    case NLR_MF_NAME: return "bad name";
    case NLR_MF_FILE: return "bad file";
    case NLR_MF_ABI: return "bad min_abi";
    case NLR_MF_SUPPORT: return "bad model list";
    case NLR_MF_DUPLICATE: return "duplicate id";
    case NLR_MF_DIRECTIVE: return "bad directive";
    default: return "rejected";
    }
}

static const char *gate_reason(uint32_t gate)
{
    switch (gate) {
    case NLR_GATE_ABI: return "needs newer NLoader";
    case NLR_GATE_MODEL: return "not for this camera";
    case NLR_GATE_DUPLICATE: return "duplicate id: never loaded";
    default: return "cannot confirm camera";
    }
}

/* The same, short enough for a row's value column (Z8 QEMU: about eleven
 * characters fit before the row's > mark); the details keep the full
 * reason. */
#if defined(NLR_STAGE_EXEC)
static const char *gate_short(uint32_t gate)
{
    switch (gate) {
    case NLR_GATE_ABI: return "newer ABI";
    case NLR_GATE_MODEL: return "other body";
    case NLR_GATE_DUPLICATE: return "duplicate";
    default: return "unconfirmed";
    }
}
#endif

/* What a refused attempt asked of the heap (struct nlr_outcome
 * memory_bytes: its code block and, with initialized data or BSS, a data
 * block, each a whole region) -- in MiB, or in KiB below one. */
static void put_program_memory(struct row_text *t, uint32_t bytes)
{
    put_number(t, bytes >= 0x100000u ? bytes >> 20 : bytes >> 10);
    put(t, bytes >= 0x100000u ? " MiB" : " KiB");
}

/* PLAN 4.3: DISABLED for SAFE_MODE, an error for no card, no file or a
 * rejected file, otherwise the program the row stands for. Missing card and
 * missing file look the same through the file service, so neither is
 * named. */
static void describe_directory(struct row_text *t, const struct nlr_runtime *r)
{
    if (!r) {
        put(t, "NLoader unavailable");
        return;
    }
    const struct nlr_manifest *m = &r->directory;
    switch (r->directory_result) {
    case NLR_OK:
        break;
    case NLR_DISABLED:
        put(t, m->error == NLR_MF_SWITCHED_OFF ? "NLoader is off"
                                                : "DISABLED (SAFE_MODE)");
        return;
    case NLR_IO:
        put(t, "Cannot read MANIFEST");
        return;
    case NLR_FORMAT:
        put(t, "MANIFEST line ");
        put_number(t, m->error_line);
        put(t, ": ");
        put(t, manifest_reason(m->error));
        return;
    case NLR_BOUNDS:
        put(t, m->error == NLR_MF_COUNT ? "MANIFEST: over 64 programs"
                                        : "MANIFEST too large");
        return;
    default:
        put(t, "MANIFEST not read");
        return;
    }
    if (!m->count) {
        put(t, "MANIFEST: no programs");
        return;
    }

}

/* A program attempt's full outcome for the details' status row, from its
 * facts: the checked program's live attempt or the one kept for its id
 * (nlr_runtime_outcome_keep). Zero for a clean return, which says
 * nothing. */
static int outcome_reason(struct row_text *t, const struct nlr_outcome *o)
{
    switch (o->result) {
    case NLR_OK:
#ifdef NLR_STAGE_PREPARE_ONLY
        put(t, "Application preparation passed");
#else
        if (o->exit_requested && !o->exit_code) {
            put(t, "Application stopped");
        } else if (o->returned && !o->exit_code) {
            return 0;
        } else {
            put(t, "Application exited (code ");
            put_number(t, (uint32_t)o->exit_code);
            put(t, ")");
        }
#endif
        break;
    case NLR_EXEC_APP:
        put(t, "Application exited (code ");
        put_number(t, (uint32_t)o->exit_code);
        put(t, ")");
        break;
    case NLR_DISABLED: put(t, "DISABLED (SAFE_MODE)"); break;
    case NLR_REFUSED: put(t, "Program changed; reopen list"); break;
    case NLR_BUSY: put(t, "Extension already resident"); break;
    case NLR_EXEC_BUDGET:
        put(t, "Program memory budget exhausted");
        break;
    case NLR_FORMAT: put(t, "Not a supported program"); break;
    case NLR_CHECKSUM: put(t, "Program file changed or damaged"); break;
    case NLR_IO: put(t, "Cannot read program or MANIFEST"); break;
    default: {
        if (o->memory_bytes) {
            /* The camera's heap had no whole aligned block left: a
             * limit of this moment (residents, the camera's own use),
             * not a fault in the file. */
            put(t, "Not enough camera memory (needs ");
            put_program_memory(t, o->memory_bytes);
            put(t, ")");
            break;
        }
        /* L: the recheck passed and the file load failed, so the
         * loader's own stage says where; otherwise the program phase. */
        int file = o->phase == 'L';
        put(t, file ? "Program file refused at stage " : "Program refused at stage ");
        char phase[2] = {(char)(file ? o->stage : o->phase), 0};
        put(t, phase);
        break;
    }
    }
    return 1;
}

/* The outcome kept for the checked program's id, when the live attempt is
 * no longer the page's (the directory was read again, another program was
 * checked): the details can still say the full reason. */
static const struct nlr_outcome *checked_outcome(const struct nlr_runtime *r)
{
    if (r->checked >= r->directory.count || r->directory_result != NLR_OK)
        return 0;
    const struct nlr_manifest_entry *e = &r->directory.entries[r->checked];
    return nlr_runtime_outcome_find(r, r->directory.buffer + e->id_off, e->id_len);
}

/* PLAN 4.3 RESULT for the checked program. The stage kept by the loader
 * separates a file that cannot be opened from one that fails while being
 * read. */
/* The detail page's status line. Nonzero when it has something to say: a
 * program's own text, a failure, a non-zero exit, a refusal. A clean check
 * or a clean return says nothing, so the row is left out. */
static int describe_check(struct row_text *t, const struct nlr_runtime *r)
{
    if (__atomic_load_n(&r->load.spill_uncertain, __ATOMIC_ACQUIRE)) {
        put(t, "Read buffer cleanup uncertain; reboot required");
        return 1;
    }
    if (__atomic_load_n(&r->exit_uncertain, __ATOMIC_ACQUIRE)) {
        put(t, "Application stop uncertain; effective reboot required");
        return 1;
    }
    if (r->program_pending) {
        /* Generic v2 programs (PLAN 6.3 M2-T4). The worker publishes the
         * outcome before it republishes state == 0, so a finished state
         * always reads a complete record. */
        if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0) {
            /* While the program runs, its own text wins (M2-T4, PLAN 5.6);
             * with nothing published the row keeps the standing status.
             * The slot is read only here, so a text left over from an
             * earlier run cannot mask a result or a refusal: those appear
             * once the run ends and the state reads 0. Each start empties
             * the slot, so another program's text never shows here. */
            char text[NLR_SLOT_TEXT_MAX + 1];
            if (!nlr_text_read(&r->text, text))
                return 0;
            put(t, text);
            return 1;
        }
        if (r->load.program.code_allocation) {
            put(t, "Application cleanup failed; restart required");
            return 1;
        }
        const struct nlr_program_record *res =
            nlr_runtime_resident_find(r, r->program_id);
        if (res) {
            /* A resident extension keeps its blocks by design even when its
             * initialization failed: the record says which, not the memory. */
            put(t, "Extension ");
            describe_extension(t, r, r->checked);
            return 1;
        }
        struct nlr_outcome o;
        nlr_runtime_outcome_fill(r, &o);
        return outcome_reason(t, &o);
    }

    if (r->probe_pending) {
        if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0) {
            put(t, "Probe running; OK to refresh");
            return 1;
        }
        /* A region kept after a failed cleanup outlives later checks of
         * other programs, which replace last_result: it is shown from the
         * probe state itself until the camera restarts. */
        if (r->load.probe.allocation) {
            put(t, "Probe cleanup failed; restart required");
            return 1;
        }
        switch (r->load.last_result) {
        case NLR_OK:
            put(t, r->load.probe.returned ? "Probe returned correctly" : "Probe preparation passed");
            break;
        case NLR_DISABLED: put(t, "DISABLED (SAFE_MODE)"); break;
        case NLR_REFUSED: put(t, "Program changed; reopen list"); break;
        case NLR_EXEC_RESPONSE: put(t, "Probe response mismatch"); break;
        case NLR_EXEC_RESTORE: put(t, "Probe cleanup failed; restart required"); break;
        case NLR_FORMAT: put(t, "Not a supported return probe"); break;
        case NLR_CHECKSUM: put(t, "Probe file changed or damaged"); break;
        case NLR_IO: put(t, "Cannot read probe or MANIFEST"); break;
        default: {
            /* L: the recheck passed and the file load failed, so the
             * loader's own stage says where; otherwise the probe phase. */
            int file = r->load.probe.phase == 'L';
            put(t, file ? "Probe file refused at stage " : "Probe refused at stage ");
            char phase[2] = {(char)(file ? r->load.stage : r->load.probe.phase), 0};
            put(t, phase);
            break;
        }
        }
        return 1;
    }

    if (r->check_result == NLR_DISABLED) {
        put(t, "DISABLED (SAFE_MODE)");
        return 1;
    }
    if (r->check_result == NLR_REFUSED) {
        put(t, gate_reason(r->directory.entries[r->checked].gate));
        return 1;
    }
    /* The detail title already carries the full name. Keep failure reasons
     * separate so a long name cannot push the cause behind the row arrow. */
    switch (r->check_result) {
    case NLR_OK: {
        const struct nlr_outcome *kept = checked_outcome(r);
        return kept ? outcome_reason(t, kept) : 0;
    }
    case NLR_IO: put(t, r->load.stage == 'O' ? "cannot open" : "read error"); break;
    case NLR_FORMAT: put(t, "bad header"); break;
    case NLR_BOUNDS: put(t, "bad size"); break;
    case NLR_CHECKSUM: put(t, "CRC mismatch"); break;
    case NLR_BUSY: put(t, "busy"); break;
    default: put(t, "not checked"); break;
    }
    return 1;
}

#if defined(NLR_STAGE_EXEC)
/* The same outcome as describe_check, as one short word for a list row's
 * value column: the column is centred left of the row's > mark and holds
 * about six characters before it reaches the mark (Z8 QEMU). The details
 * keep the full reason. Nothing while the program runs: a list row is not
 * redrawn when the run ends, so a running state would outlast it; the
 * program's own text belongs to its details. */
/* "exit 3": a code of one digit keeps the word within the column; a longer
 * (or negative) one is left to the details. */
static void put_exit_short(struct row_text *t, int32_t code)
{
    put(t, "exit");
    if (code > 0 && code < 10) {
        put(t, " ");
        put_number(t, (uint32_t)code);
    }
}

/* An attempt's outcome as the list's one word, from its facts (the live
 * attempt, or the one kept for a row's id). Zero for a clean return. */
static int outcome_word(struct row_text *t, const struct nlr_outcome *o, int probe)
{
    switch (o->result) {
    case NLR_OK:
        if (probe) {
            put(t, "ok");
        } else if (o->exit_requested && !o->exit_code) {
            put(t, "ended");
        } else if (o->returned && !o->exit_code) {
            return 0;
        } else {
            put_exit_short(t, o->exit_code);
        }
        break;
    case NLR_EXEC_APP:
        put_exit_short(t, o->exit_code);
        break;
    case NLR_DISABLED: put(t, "safe"); break;
    case NLR_REFUSED: put(t, "reopen"); break;
    case NLR_BUSY: put(t, "busy"); break;
    case NLR_EXEC_BUDGET: put(t, "limit"); break;
    case NLR_EXEC_RESTORE: put(t, "reboot"); break;
    case NLR_FORMAT: put(t, "format"); break;
    case NLR_CHECKSUM: put(t, "broken"); break;
    case NLR_IO: put(t, "error"); break;
    default:
        put(t, !probe && o->memory_bytes ? "memory" : "failed");
        break;
    }
    return 1;
}

static int list_short(struct row_text *t, const struct nlr_runtime *r)
{
    if (__atomic_load_n(&r->load.spill_uncertain, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&r->exit_uncertain, __ATOMIC_ACQUIRE)) {
        put(t, "reboot");
        return 1;
    }
    if (!r->program_pending && !r->probe_pending)
        return 0;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
        return 0;
    if (r->program_pending ? r->load.program.code_allocation != 0
                           : r->load.probe.allocation != 0) {
        put(t, "reboot");
        return 1;
    }
    if (r->program_pending && nlr_runtime_resident_find(r, r->program_id)) {
        put(t, "loaded");
        return 1;
    }
    struct nlr_outcome o;
    nlr_runtime_outcome_fill(r, &o);
    return outcome_word(t, &o, r->probe_pending);
}
#endif

static uint32_t detail_rows(const struct nlr_runtime *r, uint8_t *kinds)
{
    struct row_text t = {{0}, 0};
    uint32_t n = 0;
    kinds[n++] = ROW_OPERATION;
    if (describe_check(&t, r) || r->status_kept)
        kinds[n++] = ROW_STATUS;
#if defined(NLR_STAGE_EXEC)
    if (r->settings.count && r->settings.entry == r->checked + 1u &&
        r->directory.entries[r->checked].kind == NLR_KIND_FOREGROUND)
        kinds[n++] = ROW_SETTINGS;
#endif
    kinds[n++] = ROW_BACK;
    return n;
}

/* The rows the page shows in the state `r` is in; `kinds` receives a
 * program's detail rows. */
static uint32_t view_rows(const struct nlr_menu_page *p,
                          const struct nlr_runtime *r, uint8_t *kinds)
{
    uint32_t capacity = p->row_count ? p->row_count : 1;
    uint32_t count = 1;
    if (r && r->list_view)
        count = r->list.count ? r->list.count : 1;
    else if (r && r->settings_view)
        count = r->settings.count + 2u;
    else if (r && r->recovery_view)
        count = DETAIL_ROWS;
    else if (r && r->detail_view && r->checked < r->directory.count)
        count = extension_detail(r) ? EXT_ROWS : detail_rows(r, kinds);
    else if (r && r->directory_result == NLR_OK && r->directory.count)
        count = r->directory.count;
    return count > capacity ? capacity : count;
}

/* Writes one row; nonzero when its widget was found and bound. */
static uint32_t show(const struct nlr_menu_page *p, void *container,
                     uint32_t row, const struct row_text *t)
{
    void *widget = row_widget(p, container, row);
    return row_store(p, widget, row, t);
}

static uint32_t selected_row(const struct nlr_menu_page *p, void *window)
{
    return *(const uint16_t *)((const uint8_t *)window + p->selected_offset);
}

static void select_row(const struct nlr_menu_page *p, void *window, uint32_t row)
{
    *(uint16_t *)((uint8_t *)window + p->selected_offset) = (uint16_t)row;
}

static void show_rows(const struct nlr_menu_page *p, void *window,
                      void *container, struct nlr_runtime *r)
{
    uint32_t capacity = p->row_count ? p->row_count : 1;
    uint8_t kinds[ROW_KINDS_MAX] = {0};
    uint32_t count = view_rows(p, r, kinds);
    int list = r && r->list_view;
    int settings = !list && r && r->settings_view;
    int recovery = !list && !settings && r && r->recovery_view;
    int detail = !list && !settings && r && r->detail_view &&
                 r->checked < r->directory.count;
    int extension = !list && !settings && extension_detail(r);
    /* The rows the firmware built: the view's, then empty ones up to the
     * page's longest length (size_again). */
    const uint16_t *page_count = p->page_count ? page_word(p, r, p->page_count) : 0;
    uint32_t built = page_count && *page_count > count ? *page_count : count;
    if (built > capacity)
        built = capacity;
    /* A page of row kinds keeps its values in the upper half of the row
     * slots: rows there stay hidden, so no value shows as a label. */
    if (list && r->list.rows_view && built > NLR_ROWS_MAX)
        built = NLR_ROWS_MAX;
    uint32_t bound = 0;
    if (r) {
        r->detail_shown = detail && !extension && !recovery ? count : 0;
        for (uint32_t k = 0; k < ROW_KINDS_MAX; k++)
            r->detail_kinds[k] = kinds[k];
    }
    for (uint32_t row = 0; row < capacity; row++) {
        if (p->row_hide)
            p->row_hide(window, row, row >= built);
        if (row >= built)
            continue;
        struct row_text t = {{0}, 0};
        if (row >= count) {
            /* An empty row of a longer earlier build. */
        } else if (list) {
            put(&t, r->list.rows[row]);
        } else if (settings) {
            const char *text;
            uint32_t length;
            if (row < r->settings.count) {
                if (nlr_settings_field(r, row, 1, &text, &length))
                    put_bytes(&t, (const uint8_t *)text, length);
                put(&t, ": ");
                if (nlr_settings_choice(r, row, nlr_settings_value(r, row), &text, &length))
                    put_bytes(&t, (const uint8_t *)text, length);
            } else if (row == r->settings.count) {
                put(&t, "Read-only: saving unavailable");
            } else {
                put(&t, "Back");
            }
        } else if (recovery) {
            if (row == DETAIL_OPERATION)
#ifdef NLR_STAGE_EXEC
                put(&t, recovery_reboot_required(r) ? "Reboot required" :
                        r->autoload.recovery_armed ? "Recovery set for next reboot" :
                                                   "Recover after reboot");
#else
                put(&t, r->autoload.recovery_armed
                            ? "Recovery armed for next effective reboot"
                            : "Recover autoload for next effective reboot");
#endif
            else if (row == DETAIL_RESULT)
                describe_recovery(&t, r);
            else
                put(&t, "Back to enabled list");
        } else if (extension) {
            uint32_t position = enabled_position(r, r->checked);
            switch (row) {
            case EXT_TOGGLE:
#ifdef NLR_STAGE_EXEC
                put(&t, position == NLR_NO_CHECK ? "Enable on next reboot"
                                                : "Disable on next reboot");
#else
                put(&t, position == NLR_NO_CHECK ? "Enable after effective reboot"
                                                : "Disable after effective reboot");
#endif
                break;
            case EXT_CURRENT:
#ifdef NLR_STAGE_EXEC
                put(&t, "Now: ");
#else
                put(&t, "Current: ");
#endif
                describe_extension(&t, r, r->checked);
                break;
            case EXT_NEXT:
#ifdef NLR_STAGE_EXEC
                if (resource_save_uncertain(r))
                    put(&t, "Save uncertain; loading stopped");
                else
#endif
                if (r->autoload.enabled_result != NLR_OK)
                    put(&t,
#ifdef NLR_STAGE_EXEC
                        "Settings unreadable; not saved");
#else
                        "Cannot read ENABLED; settings not saved");
#endif
                else if (
#if NLR_HAS_NATIVE_CARD
                         r->enabled_save_result == NLR_CARD_STATE_COMMIT_UNCERTAIN)
                    put(&t,
#ifdef NLR_STAGE_EXEC
                        "Save uncertain; loading stopped");
#else
                        "Commit uncertain; loading stopped; reboot required");
#endif
                else if (
#endif
                         r->enabled_save_result != NLR_NOT_READY &&
                         r->enabled_save_result != NLR_OK)
                    put(&t,
#ifdef NLR_STAGE_EXEC
                        "Save failed; not confirmed");
#else
                        "Save failed; reboot settings not confirmed");
#endif
                else {
                    put(&t, "Next reboot: ");
                    if (position == NLR_NO_CHECK)
                        put(&t, "disabled");
                    else {
                        put(&t, "enabled, order ");
                        put_number(&t, position + 1);
                    }
                }
                break;
            case EXT_EARLIER:
#ifdef NLR_STAGE_EXEC
                put(&t, "Move earlier for next reboot");
#else
                put(&t, "Move earlier after effective reboot");
#endif
                break;
            case EXT_LATER:
#ifdef NLR_STAGE_EXEC
                put(&t, "Move later for next reboot");
#else
                put(&t, "Move later after effective reboot");
#endif
                break;
            case EXT_RECOVER:
#ifdef NLR_STAGE_EXEC
                if (recovery_reboot_required(r))
                    put(&t, "Reboot required");
                else
#endif
                if (r->autoload.phase == NLR_AUTOLOAD_STOPPED)
                    describe_recovery(&t, r);
                else
                    put(&t, "Recovery not needed");
                break;
            default: put(&t, "Back to list"); break;
            }
        } else if (detail) {
            if (kinds[row] == ROW_OPERATION) {
                uint32_t kind = r->directory.entries[r->checked].kind;
                if (kind != NLR_KIND_FOREGROUND) {
                    put(&t, "Extension settings (check only)");
                } else {
#if defined(NLR_STAGE_PREPARE_ONLY) || defined(NLR_STAGE_EXEC)
                    enum detail_operation operation = detail_operation_kind(r);
                    if (operation == DETAIL_PROGRAM) {
                        /* A generic v2 program runs through the two-block
                         * executor with the API table; the probe keeps its own
                         * closed calling convention (PLAN 6.3). */
#if defined(NLR_STAGE_EXEC)
                        put(&t, "Open application");
#elif defined(NLR_STAGE_PREPARE_ONLY)
                        put(&t, "Prepare application");
#endif
                    } else if (operation == DETAIL_PROBE) {
#if defined(NLR_STAGE_EXEC)
                        put(&t, "Run return probe");
#elif defined(NLR_STAGE_PREPARE_ONLY)
                        put(&t, "Prepare return probe");
#endif
                    } else {
                        put(&t, r->program_pending && r->probe_pending
                                    ? "Operation unavailable" : "Check application again");
                    }
#else
                    put(&t, "Open application (check only)");
#endif
                }
            } else if (kinds[row] == ROW_SETTINGS) {
                put(&t, "Settings");
            } else if (kinds[row] == ROW_STATUS) {
                /* Once shown, the row stays for the visit (the window is
                 * not entered again shorter); when it has nothing new to
                 * say it says what happened last. */
                if (!describe_check(&t, r)) {
                    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)
                        put(&t, "Application running");
                    else if (r->program_pending)
                        put(&t, "Application returned");
                    else {
                        put_name(&t, r, r->checked);
                        put(&t, ": OK");
                    }
                }
                if (p->page_count || p->detail_next)
                    r->status_kept = 1;
            } else {
                put(&t, "Back to list");
            }
        } else if (r && r->directory_result == NLR_OK && r->directory.count) {
            put_name(&t, r, row);
            /* The detail view carries the full rejection reason. Keep the
             * list marker short, and do not hide it behind resource state. */
            if (r->directory.entries[row].gate != NLR_GATE_OK) {
                put(&t, ": blocked");
            } else if (r->autoload.store &&
                       r->directory.entries[row].kind == NLR_KIND_RESOURCE_EXTENSION) {
#ifdef NLR_STAGE_EXEC
                describe_extension_list(&t, r, row);
#else
                put(&t, ": ");
                describe_extension(&t, r, row);
#endif
            }
        } else {
            describe_directory(&t, r);
        }
        bound += show(p, container, row, &t);
    }
    /* One record per drawing, not per row: the ring has 16 slots and a
     * per-row record would push out the card steps a dump must show. */
    if (r)
        nlr_trace_record(&r->load, 'B', (int32_t)(count << 16 | bound));
    if (list)
        finish_rows(p, window, container, r);
    if (list) {
        /* A list drawn for the first time starts on the program's row. */
        uint32_t seq = __atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE);
        if (r->list.shown != seq) {
            r->list.shown = seq;
            select_row(p, window, r->list.selected);
        }
    }
    /* The stock selector corrects hidden rows too, but keep the value in
     * bounds before it consults the event-pointer array. */
    if (selected_row(p, window) >= built)
        select_row(p, window, built - 1);
}

#endif

#if defined(NLR_STAGE_EXEC)
static void pages_build(struct nlr_runtime *r);
#endif

void *nlr_page_enter(void *window)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    if (!window || !p->widget_find || !p->text_bind || !p->text_store)
        return window;
    void *container = (void *)((uint8_t *)window + p->container_offset);

#if defined(PAGE_READS_CARD) || (NLR_HAS_PRIVATE_TEXT && defined(NLR_STAGE_PAGE))
    struct nlr_runtime *r = nlr_runtime_attach(&nlr_services, NLR_ARENA_BYTES, 0);
#endif
#if NLR_HAS_PRIVATE_TEXT && defined(PAGE_WRITES_ROW)
    if (!nlr_private_text_pool_ready(r)) {
        /* The original constructor's private row token resolves to a valid
         * ROM error without an owner. Rebind it to discard any old cache;
         * the unprepared runtime-text title stays hidden. */
        void *failed_title = p->widget_find(p->title_widget, container);
        if (failed_title && p->widget_show)
            p->widget_show(failed_title, 0);
        for (uint32_t row = 0; row < p->row_count; row++)
            if (p->row_hide)
                p->row_hide(window, row, row != 0);
        void *widget = row_widget(p, container, 0);
        if (widget)
            nlr_private_text_bind(widget, row_slot(p, 0));
        return window;
    }
#endif

#if defined(NLR_STAGE_EXEC)
    if (r) __atomic_store_n(&r->io.list_capacity,
        nlr_menu_native_list_capacity(p), __ATOMIC_RELEASE);
    if (r) __atomic_store_n(&r->io.list_rows,
        (uint32_t)nlr_menu_rows_available(p), __ATOMIC_RELEASE);
#endif

    /* The title element is runtime text, which the page builder creates
     * hidden. Stock pages that title themselves this way store the text,
     * bind the widget to the slot and then show it; this is that chain. */
    void *title = p->widget_find(p->title_widget, container);
    if (title && p->title_text && p->widget_show) {
        int stored = store_text(p, p->title_text, p->title_slot, p->title_format);
        int bound = bind_text(p, title, p->title_slot);
        if (stored == NLR_OK && bound == NLR_OK)
            p->widget_show(title, 1);
        else
            p->widget_show(title, 0);
    }

#if defined(PAGE_READS_CARD)
    if (r) {
        /* Observing the page is where a finished foreground program stops
         * counting against the coexistence budget (M2-T2). */
        nlr_runtime_settle_records(r);
        /* No mount/store binding is inferred from a page visit. A verified
         * owner supplies the store; only then does this natural menu cycle
         * drive its once-per-boot lifecycle without waiting on the worker.
         * Without the native filesystem services the owner is the ordinary
         * card store, whose reliability argument is its own (file_store.c);
         * binding it here means the lifecycle runs from this page, the
         * first card operation of the boot, and never earlier. */
        if (!r->autoload.store && !r->load.svc->native_card)
            r->autoload.store = nlr_file_store();
        if (r->autoload.store && r->autoload.phase == NLR_AUTOLOAD_NEW)
            nlr_runtime_autoload_begin(r, r->autoload.store);
#if NLR_HAS_NATIVE_CARD
        /* The checkpoint stopped asking for a card: this visit lets it ask
         * once more, for a card put in since. */
        if (r->load.svc->native_card && !r->autoload.store)
            nlr_runtime_boot_ask_again(r);
#endif
        nlr_runtime_menu_publish(r);
        if (r->autoload.store) {
#if NLR_HAS_NATIVE_CARD
            /* A model with a mount-time checkpoint has its own driver and
             * keeps the step it has always taken here. */
            if (r->load.svc->native_card)
                nlr_runtime_autoload_step_owned(r);
            else
#endif
                /* As far as the pass can go now that anything registered
                 * has been published: a visit that moved it a single step
                 * could leave the marker behind on a card whose pass had
                 * in fact succeeded. */
                nlr_runtime_autoload_continue(r);
        }
        if (r->show_check) {
            r->show_check = 0;
        } else if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0 &&
                   ((!p->page_count && !p->detail_next) || !r->detail_view)) {
            /* A sized page keeps the details it was left on when the menu
             * reopens on it: the firmware built their rows. The Setup row's
             * open action has already gone back to the list. */
            r->detail_view = 0;
            nlr_runtime_read_directory(r);
            r->recovery_view = r->autoload.store &&
                               r->autoload.phase == NLR_AUTOLOAD_STOPPED;
        }
        if (r->list_view && !r->pages.shown &&
            __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0)
            r->list_view = 0;
#if defined(NLR_STAGE_EXEC)
        if (late_program_list(r)) {
            r->list_view = 1;
            r->detail_view = r->recovery_view = 0;
        }
        /* One of the loader's own pages, drawn from what the card says now
         * -- unless a program's list is up. */
        r->pages.visited = 1;
        if (r->pages.depth && !(r->list_view && !r->pages.shown))
            pages_build(r);
#endif
        if (r->list_view && title) {
            int stored = store_text(p, r->list.title, p->title_slot, p->title_format);
            int bound = bind_text(p, title, p->title_slot);
            if ((stored != NLR_OK || bound != NLR_OK) && p->widget_show)
                p->widget_show(title, 0);
        } else if (r->detail_view && r->checked < r->directory.count && title) {
            struct row_text name = {{0}, 0};
            put_name(&name, r, r->checked);
            int stored = store_text(p, name.bytes, p->title_slot, p->title_format);
            int bound = bind_text(p, title, p->title_slot);
            if ((stored != NLR_OK || bound != NLR_OK) && p->widget_show)
                p->widget_show(title, 0);
        }
    }
    if (r && r->detail_view && !r->list_view)
        nlr_settings_load(r);
    if (r && r->detail_fresh && on_details(p, window)) {
        r->detail_fresh = 0;
        select_row(p, window, DETAIL_OPERATION);
    }
    show_rows(p, window, container, r);
#elif defined(NLR_STAGE_PAGE)
    /* The page rung proves the row can be rewritten on entry: its label
     * plus 'W' when the widget was found and re-bound, 'X' when only the
     * slot could be written, so a failed lookup cannot look like a
     * success. */
    struct row_text t = {{0}, 0};
    void *widget = row_widget(p, container, 0);
    put(&t, p->row_text);
    put(&t, widget ? " W" : " X");
    row_store(p, widget, 0, &t);
#endif
#ifndef PAGE_READS_CARD
    if (p->row_hide)
        for (uint32_t row = 1; row < p->row_count; row++)
            p->row_hide(window, row, 1);
#endif
    return window;
}

#if defined(NLR_STAGE_EXEC)
/* How long the menu task waits for a program's next move. */
#define LIST_WAIT_MS 3000u

enum { WAIT_LIST, WAIT_ENDED, WAIT_SCREEN, WAIT_TIMEOUT };

/* After handing the program something (a start, a choice), wait on the
 * menu task, a few milliseconds at a time, until it publishes a list,
 * takes the screen or ends. The program's task outranks this one, so it
 * runs meanwhile; past the limit the page stays as it is. */
int nlr_page_program_reads_input(const struct nlr_runtime *r)
{
    return r && (__atomic_load_n(&r->plat.active, __ATOMIC_ACQUIRE) ||
                 __atomic_load_n(&r->input_owner, __ATOMIC_ACQUIRE));
}

static uint32_t wait_program(struct nlr_runtime *r, uint32_t seq)
{
    for (uint32_t waited = 0; waited < LIST_WAIT_MS; waited += 10u) {
        if (__atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE) != seq)
            return WAIT_LIST;
        if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0)
            return WAIT_ENDED;
        if (__atomic_load_n(&r->io.gfx_active, __ATOMIC_ACQUIRE))
            return WAIT_SCREEN;
        /* The program reads the controls itself (ABI 7 input taken, or an
         * ABI 4 input owner): it is not about to show a list, and the
         * camera must go on reading what the program routes to it. This
         * task is the menu's own: held here, the menu takes one queued
         * key when it is let go and loses the taps in between (a single
         * UP routed to the camera did not move the cursor, Z8 QEMU
         * b-input; fix-misc qemu-tap-002). Left at once, exactly as the
         * timeout below leaves it. */
        if (nlr_page_program_reads_input(r))
            return WAIT_TIMEOUT;
        if (nlr_services.time && nlr_services.time->delay_ms) {
            if (nlr_services.time->delay_ms(10u) != NLR_OK) break;
        } else if (nlr_services.sleep_ms) nlr_services.sleep_ms(10u);
        else break;
    }
    return WAIT_TIMEOUT;
}

/* A program opened from one of the loader's pages is over (or has not
 * shown a list of its own yet): the page it came from is built again now,
 * before the window is sized, so the rebuild is sized for that page's rows
 * -- not for the whole directory, which would leave empty rows below it --
 * and its row kinds (a status value) are staged before the build. */
static void pages_resume(struct nlr_runtime *r)
{
    if (r->pages.depth && !r->list_view)
        pages_build(r);
}

static void open_own(struct nlr_menu_nav *nav, struct nlr_runtime *r,
                     uint32_t seq);
static void own_answer(struct nlr_menu_nav *nav, struct nlr_runtime *r,
                       int32_t choice);

/* Show what the program did next: its list or its outcome on this window
 * (never shorter), the keyboard or the caution box when it asks for one,
 * or leave the page
 * while it holds the screen or works. */
static void follow_program(struct nlr_menu_nav *nav, struct nlr_runtime *r,
                           uint32_t seq)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    uint32_t why = wait_program(r, seq);
    if (why == WAIT_LIST && r->list.dialog &&
        __atomic_load_n(&r->own.ready, __ATOMIC_ACQUIRE)) {
        open_own(nav, r, __atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE));
        return;
    }
    if (why == WAIT_LIST)
        r->list_view = 1;
    else if (why == WAIT_ENDED)
        r->list_view = 0;
    else if (p->stay_next) {
        nav->next = p->stay_next;
        return;
    }
    pages_resume(r);
    r->show_check = 1;
    refresh_page(nav, r);
}

/* The program's list: a row or back goes to the program, which answers
 * with its next list or ends. A list the page has not drawn yet, a row
 * past the list, or a program already over only redraw. OK on a text
 * entry's or a caution's row opens the loader's own window again, unless
 * the request is answered already. */
static int list_action(struct nlr_menu_nav *nav, struct nlr_runtime *r,
                       int32_t choice)
{
    if (!r || !r->list_view)
        return 0;
    uint32_t seq = __atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0) {
        r->list_view = 0;
    } else if (seq == r->list.shown && r->list.dialog && choice != NLR_LIST_BACK) {
        if ((uint32_t)choice < r->list.count && r->own.answered != seq &&
            __atomic_load_n(&r->own.ready, __ATOMIC_ACQUIRE)) {
            open_own(nav, r, seq);
            return 1;
        }
    } else if (seq == r->list.shown &&
               (choice == NLR_LIST_BACK || (uint32_t)choice < r->list.count)) {
        __atomic_store_n(&r->list.choice, choice, __ATOMIC_RELEASE);
        __atomic_add_fetch(&r->list.choice_seq, 1u, __ATOMIC_RELEASE);
        follow_program(nav, r, seq);
        return 1;
    }
    pages_resume(r);
    r->show_check = 1;
    refresh_page(nav, r);
    return 1;
}

/* ---- the loader's own pages -------------------------
 *
 * Everything NLoader shows itself lives on its one window, as a stack of
 * pages drawn with the camera's own row kinds (the ABI 6 page of row kinds,
 * `list`): the Apps list the Setup page's first row opens, and NLoader's
 * root -- the switch, Plugin settings, About -- its last row opens. OK on
 * an entry pushes a page and the window is rebuilt in place (refresh_page),
 * back pops one, back from the first page leaves to Setup by the record's
 * own navigation, and MENU stays the camera's. A program a page opened
 * takes the list over with its own (follow_program); when it ends, the page
 * it was opened from is drawn again. */

enum {
    PAGE_APPS = 1, PAGE_ROOT, PAGE_PLUGINS, PAGE_PLUGIN, PAGE_DETAILS, PAGE_ABOUT,
};
/* What OK on a row does. */
enum {
    GO_NONE, GO_APP, GO_RECOVER, GO_SWITCH, GO_PLUGINS, GO_ABOUT, GO_PLUGIN,
    GO_ENABLED, GO_BOOT, GO_DETAILS, GO_OPEN,
};

static void list_copy(char *to, const char *from)
{
    uint32_t n = 0;
    while (from && from[n] && n < NLR_LIST_TEXT_MAX) {
        to[n] = from[n];
        n++;
    }
    to[n] = 0;
}

static void page_row(struct nlr_runtime *r, uint32_t kind, uint32_t flags,
                     const char *label, const char *value, uint32_t go,
                     uint32_t arg)
{
    uint32_t n = r->list.count;
    if (n >= NLR_ROWS_MAX || n >= nlr_menu_page.row_count)
        return;
    list_copy(r->list.rows[n], label);
    list_copy(r->list.values[n], value);
    r->list.kinds[n] = (uint8_t)kind;
    r->list.row_flags[n] = (uint8_t)flags;
    r->pages.go[n] = (uint8_t)go;
    r->pages.arg[n] = (uint8_t)arg;
    r->list.count = n + 1u;
}

/* A text row holds one line. The camera draws a row's label with the row's
 * style and, when the text is wider than the row, wraps it onto a second
 * line inside the same fixed-height row, over the row above (Z 8 QEMU,
 * build/z8-c-20261017/fix-misc/qemu-oc-002, details page). This text path
 * applies no fit or ellipsis, and the page's item records offer no taller
 * row: the declared row kinds are entry, switch and value rows of one
 * height. So the core splits a long text over rows itself, at a space where
 * there is one. The row's font draws ASCII at one width (about 25 of the
 * LCD's 1024 pixels a character there): 34 characters fill a row and the
 * 35th wrapped; 32 keep two in hand. Bytes of one UTF-8 character are never
 * split. */
#define NLR_TEXT_ROW_CHARS 32u

static void page_text_bytes(struct nlr_runtime *r, const char *text, uint32_t length)
{
    if (!length) {
        page_row(r, NLR_ROW_TEXT, 0, "", 0, GO_NONE, 0);
        return;
    }
    uint32_t at = 0;
    while (at < length) {
        uint32_t take = length - at;
        if (take > NLR_TEXT_ROW_CHARS) {
            uint32_t space = NLR_TEXT_ROW_CHARS;
            while (space && text[at + space] != ' ')
                space--;
            take = space ? space : NLR_TEXT_ROW_CHARS;
            while (!space && take && ((uint8_t)text[at + take] & 0xc0u) == 0x80u)
                take--;
            if (!take)
                take = NLR_TEXT_ROW_CHARS;
        }
        char row[NLR_TEXT_ROW_CHARS + 1];
        for (uint32_t n = 0; n < take; n++)
            row[n] = text[at + n];
        row[take] = 0;
        page_row(r, NLR_ROW_TEXT, 0, row, 0, GO_NONE, 0);
        at += take;
        while (at < length && text[at] == ' ')
            at++;
    }
}

static void page_text(struct nlr_runtime *r, const char *label)
{
    uint32_t length = 0;
    while (label && label[length])
        length++;
    page_text_bytes(r, label ? label : "", length);
}

static void entry_text(struct row_text *t, const struct nlr_runtime *r,
                       uint32_t offset, uint32_t length)
{
    put_bytes(t, r->directory.buffer + offset, length);
}

/* The NLoader switch as this boot has it: read from the card once. */
static uint32_t pages_switch(struct nlr_runtime *r)
{
    if (!r->pages.master)
        r->pages.master = nlr_master_off(r->load.svc, 0) ? 2u : 1u;
    return r->pages.master;
}

/* What BOOT names, read once; the page writes it after that. */
static const char *pages_boot(struct nlr_runtime *r)
{
    if (!r->pages.boot_known) {
        r->pages.boot_known = 1;
        r->pages.boot_id[0] = 0;
        _Alignas(NLR_CACHE_LINE) uint8_t frame[NLR_CACHE_LINE];
        uint32_t bytes = 0;
        if (nlr_card_read_prefix(r->load.svc, NLR_BOOT_PATH, frame, sizeof frame,
                                 &bytes, 0) == NLR_OK) {
            uint32_t n = 0, k = 0;
            while (n < bytes && !nlr_manifest_token_byte(frame[n]))
                n++;
            while (n < bytes && nlr_manifest_token_byte(frame[n]) &&
                   k < NLR_MANIFEST_ID_MAX)
                r->pages.boot_id[k++] = (char)frame[n++];
            r->pages.boot_id[k] = 0;
        }
    }
    return r->pages.boot_id;
}

static int boot_names(struct nlr_runtime *r, uint32_t index)
{
    const char *id = pages_boot(r);
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    if (!id[0] || e->kind != NLR_KIND_FOREGROUND)
        return 0;
    for (uint32_t n = 0; n < e->id_len; n++) {
        char a = id[n], b = (char)r->directory.buffer[e->id_off + n];
        if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
        if (!a || a != b)
            return 0;
    }
    return id[e->id_len] == 0;
}

static int directory_ready(const struct nlr_runtime *r)
{
    return r->directory_result == NLR_OK && r->directory.count;
}

/* The directory as a row, when it cannot be listed. */
static void directory_row(struct nlr_runtime *r)
{
    struct row_text t = {{0}, 0};
    if (r->directory_result == NLR_DISABLED &&
        r->directory.error == NLR_MF_SWITCHED_OFF)
        put(&t, "NLoader is off");
    else if (r->directory_result == NLR_OK && !r->directory.count)
        put(&t, "No programs on the card");
    else
        describe_directory(&t, r);
    page_text(r, t.bytes);
}

/* The settings of program `index`, read beside it (<name>.SET), as the
 * details' Settings view reads them. Only while nothing runs: the checked
 * program and its path are the menu task's then. */
static void page_settings(struct nlr_runtime *r, uint32_t index)
{
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0 ||
        index >= r->directory.count)
        return;
    if (r->checked != index) {
        const struct nlr_manifest_entry *e = &r->directory.entries[index];
        uint32_t length = 0;
        for (const char *c = NLR_PROGRAM_ROOT; *c; c++)
            r->path[length++] = *c;
        for (uint32_t n = 0; n < e->file_len && length + 1 < NLR_PATH_BYTES; n++) {
            char c = (char)r->directory.buffer[e->file_off + n];
            r->path[length++] = c == '/' ? '\\' : c;
        }
        r->path[length] = 0;
        r->checked = index;
        nlr_runtime_outcome_keep(r);
        r->program_pending = r->probe_pending = 0;
        r->check_result = NLR_NOT_READY;
        r->settings.entry = 0;
    }
    nlr_settings_load(r);
}

static void build_apps(struct nlr_runtime *r)
{
    list_copy(r->list.title, nlr_menu_prefill.apps_text ? nlr_menu_prefill.apps_text
                                                       : "Apps");
    if (!directory_ready(r)) {
        directory_row(r);
        return;
    }
    for (uint32_t i = 0; i < r->directory.count; i++) {
        const struct nlr_manifest_entry *e = &r->directory.entries[i];
        if (e->kind != NLR_KIND_FOREGROUND)
            continue;
        struct row_text name = {{0}, 0}, value = {{0}, 0};
        entry_text(&name, r, e->name_off, e->name_len);
        if (e->gate != NLR_GATE_OK) {
            /* shown greyed, with why; the cursor passes it */
            page_row(r, NLR_ROW_SELECT, NLR_ROW_GREYED, name.bytes,
                     gate_short(e->gate), GO_NONE, i);
            continue;
        }
        /* The live attempt's word for the checked row (none while it
         * runs); any other row, or the checked one once the page has
         * moved on, shows the outcome kept for its id this boot. */
        int live = r->checked == i && (r->program_pending || r->probe_pending);
        const struct nlr_outcome *kept =
            live ? 0 : nlr_runtime_outcome_find(r, r->directory.buffer + e->id_off, e->id_len);
        if (live ? list_short(&value, r) : kept && outcome_word(&value, kept, 0))
            page_row(r, NLR_ROW_SELECT, 0, name.bytes, value.bytes, GO_APP, i);
        else
            page_row(r, NLR_ROW_ENTRY, 0, name.bytes, 0, GO_APP, i);
    }
    if (!r->list.count)
        page_text(r, "No applications on the card");
}

static void build_root(struct nlr_runtime *r)
{
    list_copy(r->list.title, nlr_menu_prefill.text ? nlr_menu_prefill.text : "NLoader");
    uint32_t on = pages_switch(r) != 2u;
    /* A pass that stopped: recovery first, as the page always showed it --
     * unless the switch stopped it, which is no failure to recover from. */
    if (r->autoload.store && r->autoload.phase == NLR_AUTOLOAD_STOPPED &&
        !(r->directory_result == NLR_DISABLED &&
          r->directory.error == NLR_MF_SWITCHED_OFF)) {
        struct row_text t = {{0}, 0};
        page_row(r, NLR_ROW_ENTRY, 0,
                 recovery_reboot_required(r) ? "Reboot required" :
                 r->autoload.recovery_armed ? "Recovery set for next reboot" :
                                              "Recover after reboot",
                 0, GO_RECOVER, 0);
        describe_recovery(&t, r);
        page_text(r, t.bytes);
    }
    page_row(r, NLR_ROW_SWITCH, on ? NLR_ROW_ON : 0, "NLoader", 0, GO_SWITCH, 0);
    /* What the switch means now: changed on this page (from the next power
     * on, or only until power off when the card did not take it), or off
     * since this power on. */
    if (r->pages.master_changed && r->pages.master_saved != NLR_OK)
        page_text(r, "Not saved: lasts until power off");
    else if (r->pages.master_changed)
        page_text(r, on ? "On from the next power on" : "Off from the next power on");
    else if (!on)
        page_text(r, "Off: nothing was loaded");
    page_row(r, NLR_ROW_ENTRY, 0, "Plugin settings", 0, GO_PLUGINS, 0);
    page_row(r, NLR_ROW_ENTRY, 0, "About", 0, GO_ABOUT, 0);
}

static void build_plugins(struct nlr_runtime *r)
{
    list_copy(r->list.title, "Plugin settings");
    if (!directory_ready(r)) {
        directory_row(r);
        return;
    }
    for (uint32_t i = 0; i < r->directory.count; i++) {
        const struct nlr_manifest_entry *e = &r->directory.entries[i];
        struct row_text name = {{0}, 0}, state = {{0}, 0};
        entry_text(&name, r, e->name_off, e->name_len);
        if (e->gate != NLR_GATE_OK) {
            page_row(r, NLR_ROW_SELECT, NLR_ROW_GREYED, name.bytes,
                     gate_short(e->gate), GO_NONE, i);
            continue;
        }
        if (e->kind == NLR_KIND_RESOURCE_EXTENSION) {
            /* One word, as the value column holds (list_short): a failed
             * initialization first, whatever the switch says now; then the
             * switch, and "loaded" for one that is on and running. The
             * plugin's page has both, in full. */
            uint32_t status = nlr_runtime_extension_status(r, i);
            uint32_t on = enabled_position(r, i) != NLR_NO_CHECK;
            put(&state, status == NLR_EXTENSION_PARTIAL ? "failed"
                        : !on ? "off"
                        : status == NLR_EXTENSION_LOADED ? "loaded" : "on");
        } else {
            put(&state, boot_names(r, i) ? "at boot" : "app");
        }
        page_row(r, NLR_ROW_SELECT, 0, name.bytes, state.bytes, GO_PLUGIN, i);
    }
}

static void build_plugin(struct nlr_runtime *r, uint32_t index)
{
    if (!directory_ready(r) || index >= r->directory.count) {
        list_copy(r->list.title, "Plugin settings");
        directory_row(r);
        return;
    }
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    struct row_text name = {{0}, 0};
    entry_text(&name, r, e->name_off, e->name_len);
    list_copy(r->list.title, name.bytes);
    if (e->kind == NLR_KIND_RESOURCE_EXTENSION) {
        uint32_t enabled = enabled_position(r, index) != NLR_NO_CHECK;
        page_row(r, NLR_ROW_SWITCH, enabled ? NLR_ROW_ON : 0, "Enabled", 0,
                 GO_ENABLED, index);
        struct row_text now = {{0}, 0};
        put(&now, "Now: ");
        describe_extension(&now, r, index);
        page_text(r, now.bytes);
        if (r->enabled_save_result != NLR_NOT_READY &&
            r->enabled_save_result != NLR_OK)
            page_text(r, "Not saved");
    } else {
        page_row(r, NLR_ROW_SWITCH, boot_names(r, index) ? NLR_ROW_ON : 0,
                 "Start at boot", 0, GO_BOOT, index);
        if (r->pages.boot_saved != NLR_OK)
            page_text(r, "Not saved");
    }
    /* Its own settings, as it declares them: shown, not yet written (the
     * settings file has no verified save path, nlr_settings_set). */
    page_settings(r, index);
    if (r->settings.entry == index + 1u) {
        for (uint32_t k = 0; k < r->settings.count; k++) {
            struct row_text label = {{0}, 0}, value = {{0}, 0};
            const char *text;
            uint32_t length;
            if (nlr_settings_field(r, k, 1, &text, &length))
                put_bytes(&label, (const uint8_t *)text, length);
            if (nlr_settings_choice(r, k, nlr_settings_value(r, k), &text, &length))
                put_bytes(&value, (const uint8_t *)text, length);
            page_row(r, NLR_ROW_SELECT, NLR_ROW_GREYED, label.bytes, value.bytes,
                     GO_NONE, index);
        }
    }
    page_row(r, NLR_ROW_ENTRY, 0, "Details", 0, GO_DETAILS, index);
}

/* What a card program says about itself (NPLD v3 metadata): version, author, what it uses and its summary, one text row each,
 * read from its file while nothing runs -- as the settings beside it are
 * (page_settings). A program without a description, a bundle program, or a
 * file that cannot be read adds nothing: the details keep their MANIFEST
 * rows. The header and metadata are read into an owned, line-aligned
 * allocation released before the rows are drawn. */
static void meta_row(struct nlr_runtime *r, const uint8_t *meta, uint32_t bytes,
                     const char *key, const char *prefix)
{
    uint32_t size = 0;
    const uint8_t *value = nlr_meta_find(meta, bytes, key, &size);
    if (!value || !size)
        return;
    /* over rows of their own (page_text_bytes), at most four of them */
    char text[4u * NLR_TEXT_ROW_CHARS];
    uint32_t n = 0;
    for (const char *p = prefix; *p && n < sizeof text; p++)
        text[n++] = *p;
    for (uint32_t k = 0; k < size && n < sizeof text; k++)
        text[n++] = (char)value[k];
    page_text_bytes(r, text, n);
}

static void details_meta(struct nlr_runtime *r, uint32_t index)
{
    const struct nlr_services *svc = r->load.svc;
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    static const char apps[] = "APPS/";
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0 || !svc ||
        !svc->release || e->file_len <= sizeof apps - 1u)
        return;
    for (uint32_t n = 0; n < sizeof apps - 1u; n++) {
        char c = (char)r->directory.buffer[e->file_off + n];
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 32);
        if (c != apps[n] && !(apps[n] == '/' && c == '\\'))
            return;
    }
    char path[NLR_PATH_BYTES];
    uint32_t length = 0;
    for (const char *c = NLR_PROGRAM_ROOT; *c && length + 1 < sizeof path; c++)
        path[length++] = *c;
    for (uint32_t n = 0; n < e->file_len && length + 1 < sizeof path; n++) {
        char c = (char)r->directory.buffer[e->file_off + n];
        path[length++] = c == '/' ? '\\' : c;
    }
    path[length] = 0;
    const uint32_t want = NLR_GENERIC_HEADER_SIZE + NLR_META_MAX;
    /* About 4 KiB on the menu task, from the same entry as every other
     * block: granted whole where the heap's books can be read. */
    void *allocation = nlr_alloc_whole(svc, want + NLR_CACHE_LINE);
    if (!allocation)
        return;
    uint8_t *head = (uint8_t *)(((uintptr_t)allocation + NLR_CACHE_LINE - 1u) &
                                ~(uintptr_t)(NLR_CACHE_LINE - 1u));
    uint32_t bytes = 0, meta = 0;
    if (nlr_card_read_prefix(svc, path, head, want, &bytes, 0) == NLR_OK &&
        bytes >= NLR_GENERIC_HEADER_SIZE && head[0] == 'N' && head[1] == 'P' &&
        head[2] == 'L' && head[3] == 'D' &&
        nlr_le16(head + 4) == NLR_NPLD_META_VERSION) {
        meta = nlr_le32(head + 0x28);
        if (!meta || meta > NLR_META_MAX || bytes < NLR_GENERIC_HEADER_SIZE + meta ||
            nlr_crc32(head + NLR_GENERIC_HEADER_SIZE, meta) != nlr_le32(head + 0x2c))
            meta = 0;
    }
    if (meta) {
        const uint8_t *m = head + NLR_GENERIC_HEADER_SIZE;
        meta_row(r, m, meta, "version", "Version ");
        meta_row(r, m, meta, "author", "By ");
        meta_row(r, m, meta, "uses", "Uses: ");
        meta_row(r, m, meta, "description", "");
    }
    svc->release(allocation);
}

static void build_details(struct nlr_runtime *r, uint32_t index)
{
    if (!directory_ready(r) || index >= r->directory.count) {
        list_copy(r->list.title, "Details");
        directory_row(r);
        return;
    }
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    struct row_text t = {{0}, 0};
    entry_text(&t, r, e->name_off, e->name_len);
    list_copy(r->list.title, t.bytes);
    t.length = 0;
    put(&t, e->kind == NLR_KIND_FOREGROUND ? "Application" : "Extension");
    if (e->kind == NLR_KIND_FOREGROUND && boot_names(r, index))
        put(&t, ", starts at boot");
    page_text(r, t.bytes);
    t.length = 0;
    put(&t, "File: ");
    entry_text(&t, r, e->file_off, e->file_len);
    page_text(r, t.bytes);
    t.length = 0;
    put(&t, "Needs NLoader ABI ");
    put_number(&t, e->min_abi);
    page_text(r, t.bytes);
    t.length = 0;
    put(&t, "For: ");
    if (e->support_len)
        entry_text(&t, r, e->support_off, e->support_len);
    else
        put(&t, "any camera");
    page_text(r, t.bytes);
    details_meta(r, index);
    if (e->gate != NLR_GATE_OK)
        page_text(r, gate_reason(e->gate));
    t.length = 0;
    /* The live attempt when it is this program's; otherwise the outcome
     * kept for its id this boot, so the full reason (a refusal's "Not
     * enough camera memory (needs N MiB)") is still here after the pages
     * read the directory again and the list kept only its word. */
    int live = r->checked == index && (r->program_pending || r->probe_pending);
    const struct nlr_outcome *kept =
        live ? 0 : nlr_runtime_outcome_find(r, r->directory.buffer + e->id_off, e->id_len);
    if (live ? describe_check(&t, r) : kept && outcome_reason(&t, kept))
        page_text(r, t.bytes);
    if (e->kind == NLR_KIND_FOREGROUND && e->gate == NLR_GATE_OK)
        page_row(r, NLR_ROW_ENTRY, 0, "Open", 0, GO_OPEN, index);
}

static void build_about(struct nlr_runtime *r)
{
    const struct nlr_menu_setup *s = &nlr_menu_setup;
    struct row_text t = {{0}, 0};
    list_copy(r->list.title, "About");
    put(&t, "NLoader ");
    put(&t, s->version ? s->version : "");
    put(&t, ", program ABI ");
    put_number(&t, NLR_ABI_VERSION);
    page_text(r, t.bytes);
    t.length = 0;
    put(&t, "Camera: ");
    put(&t, nlr_identity.model);
    put(&t, " ");
    put(&t, nlr_identity.firmware);
    page_text(r, t.bytes);
    if (s->module && s->module[0]) {
        t.length = 0;
        put(&t, "Firmware module ");
        put(&t, s->module);
        page_text(r, t.bytes);
    }
    page_text(r, "Copyright: see the NLoader project");
}

/* The top page into `list`, the cursor on its row. */
static void pages_build(struct nlr_runtime *r)
{
    if (!r->pages.depth)
        return;
    uint32_t top = r->pages.depth - 1u;
    uint32_t kind = r->pages.stack[top].kind, index = r->pages.stack[top].index;
    r->list.count = 0;
    r->list.rows_view = 1;
    r->list.dialog = 0;
    switch (kind) {
    case PAGE_APPS: build_apps(r); break;
    case PAGE_ROOT: build_root(r); break;
    case PAGE_PLUGINS: build_plugins(r); break;
    case PAGE_PLUGIN: build_plugin(r, index); break;
    case PAGE_DETAILS: build_details(r, index); break;
    default: build_about(r); break;
    }
    if (!r->list.count)
        page_text(r, "Nothing here");
    uint32_t cursor = r->pages.stack[top].cursor;
    /* a row the cursor cannot land on: the first one it can */
    if (cursor >= r->list.count || r->list.kinds[cursor] == NLR_ROW_TEXT ||
        (r->list.row_flags[cursor] & NLR_ROW_GREYED)) {
        cursor = 0;
        while (cursor + 1u < r->list.count &&
               (r->list.kinds[cursor] == NLR_ROW_TEXT ||
                (r->list.row_flags[cursor] & NLR_ROW_GREYED)))
            cursor++;
    }
    r->list.selected = cursor;
    r->list_view = 1;
    r->pages.shown = 1;
    /* drawn as a list the page has not shown yet: the cursor goes where
     * `selected` says (show_rows) */
    __atomic_add_fetch(&r->list.seq, 1u, __ATOMIC_RELEASE);
}

static void pages_reset(struct nlr_runtime *r, uint32_t kind)
{
    r->pages.depth = 1;
    r->pages.stack[0].kind = (uint8_t)kind;
    r->pages.stack[0].cursor = 0;
    r->pages.stack[0].index = 0;
    r->pages.visited = 1;
}

static void pages_push(struct nlr_runtime *r, uint32_t kind, uint32_t index)
{
    if (r->pages.depth >= NLR_PAGES_DEPTH)
        return;
    r->pages.stack[r->pages.depth].kind = (uint8_t)kind;
    r->pages.stack[r->pages.depth].cursor = 0;
    r->pages.stack[r->pages.depth].index = index;
    r->pages.depth++;
}

static void pages_leave(struct nlr_runtime *r)
{
    r->pages.depth = 0;
    if (r->pages.shown) {
        r->pages.shown = 0;
        r->list_view = 0;
    }
}

static void pages_toggle_switch(struct nlr_runtime *r)
{
    uint32_t off = pages_switch(r) != 2u;
    r->pages.master = off ? 2u : 1u;
    r->pages.master_changed = 1;
    const struct nlr_card_store *store = r->autoload.store;
    /* A model whose autoload store is the native journal (Z 8) has no
     * replace there: NLOADER/MASTER is written through the ordinary checked
     * file services instead, the path LOADER.LOG appends with, and only
     * when nothing runs. The
     * switch stays the Z 6III's file, read beside SAFE_MODE. */
    if ((!store || !store->replace) &&
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0)
        store = nlr_file_store();
    r->pages.master_saved =
        !store || !store->replace ? NLR_NOT_READY :
        off ? store->replace(NLR_MASTER_PATH, (const uint8_t *)"off", 3u)
            : store->replace(NLR_MASTER_PATH, (const uint8_t *)"on", 2u);
    /* Saved only when an independent read of the file says the same: a
     * write that went short reads as "on", which is never taken for an
     * "off" that was asked for. */
    if (r->pages.master_saved == NLR_OK &&
        (nlr_master_off(r->load.svc, 0) ? 1u : 0u) != off)
        r->pages.master_saved = NLR_IO;
    /* The loader's own log follows the switch the card now holds: held
     * while it is off (nothing of the loader's is written then), written
     * again once it is on (runtime.c autoload_open). */
    if (r->pages.master_saved == NLR_OK)
        nlr_journal_hold(r->load.journal, off);
}

static void pages_toggle_boot(struct nlr_runtime *r, uint32_t index)
{
    const struct nlr_card_store *store = r->autoload.store;
    if (index >= r->directory.count)
        return;
    const struct nlr_manifest_entry *e = &r->directory.entries[index];
    char id[NLR_MANIFEST_ID_MAX + 1];
    uint32_t length = 0;
    if (!boot_names(r, index))
        for (; length < e->id_len && length < NLR_MANIFEST_ID_MAX; length++)
            id[length] = (char)r->directory.buffer[e->id_off + length];
    id[length] = 0;
    /* As NLOADER/MASTER (pages_toggle_switch): a model whose autoload store
     * is the native journal (Z 8) has no replace there, so BOOT -- the
     * Z 6III's file, the program's id or nothing -- is written through the
     * ordinary checked file services, only when nothing runs. */
    if ((!store || !store->replace) &&
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0)
        store = nlr_file_store();
    r->pages.boot_saved = !store || !store->replace ? NLR_NOT_READY
        : store->replace(NLR_BOOT_PATH, (const uint8_t *)id, length);
    if (r->pages.boot_saved == NLR_OK) {
        /* Saved only when an independent read of the file holds exactly
         * what was written. */
        _Alignas(NLR_CACHE_LINE) uint8_t frame[NLR_CACHE_LINE];
        uint32_t bytes = 0;
        int read = nlr_card_read_prefix(r->load.svc, NLR_BOOT_PATH, frame,
                                        sizeof frame, &bytes, 0);
        if (length && (read != NLR_OK || bytes != length))
            r->pages.boot_saved = NLR_IO;
        else if (!length && read == NLR_OK && bytes != 0)
            r->pages.boot_saved = NLR_IO;
        for (uint32_t n = 0; r->pages.boot_saved == NLR_OK && n < length; n++)
            if (frame[n] != (uint8_t)id[n])
                r->pages.boot_saved = NLR_IO;
    }
    if (r->pages.boot_saved == NLR_OK)
        for (uint32_t n = 0; n <= length; n++)
            r->pages.boot_id[n] = id[n];
}

/* OK on a row of one of the loader's pages. */
static void pages_action(struct nlr_menu_nav *nav, struct nlr_runtime *r,
                         uint32_t row)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    uint32_t top = r->pages.depth - 1u;
    uint32_t go = row < r->list.count ? r->pages.go[row] : GO_NONE;
    uint32_t arg = row < r->list.count ? r->pages.arg[row] : 0;
    if (row < r->list.count)
        r->pages.stack[top].cursor = (uint16_t)row;
    int busy = __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0;
    switch (go) {
    case GO_APP:
    case GO_OPEN:
        if (busy)
            break;
        {
            /* The application's lists, its screen or its outcome follow on
             * this window; the page it came from is drawn again after. */
            uint32_t seq = __atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE);
            r->pages.shown = 0;
            r->list_view = 0;
            int result = nlr_runtime_open_app(r, arg);
            if (result == NLR_SHELL_OPENED)
                return; /* the menu is closing: the shell has the screen */
            if (result == NLR_OK && p->stay_next) {
                follow_program(nav, r, seq);
                return;
            }
        }
        break;
    case GO_RECOVER:
        nlr_runtime_autoload_recover(r);
        break;
    case GO_SWITCH:
        pages_toggle_switch(r);
        break;
    case GO_PLUGINS:
        pages_push(r, PAGE_PLUGINS, 0);
        break;
    case GO_ABOUT:
        pages_push(r, PAGE_ABOUT, 0);
        break;
    case GO_PLUGIN:
        pages_push(r, PAGE_PLUGIN, arg);
        break;
    case GO_DETAILS:
        pages_push(r, PAGE_DETAILS, arg);
        break;
    case GO_ENABLED:
        if (!busy && arg < r->directory.count) {
            r->checked = arg;
            change_extension_setting(r, EXT_TOGGLE);
        }
        break;
    case GO_BOOT:
        if (!busy)
            pages_toggle_boot(r, arg);
        break;
    default:
        break;
    }
    pages_build(r);
    r->show_check = 1;
    refresh_page(nav, r);
}

/* Back on one of the loader's pages: one page up, or -- from the first --
 * out to Setup by the record's own navigation. */
static void pages_back(struct nlr_menu_nav *nav, struct nlr_runtime *r)
{
    if (r->pages.depth > 1u) {
        r->pages.depth--;
        pages_build(r);
        r->show_check = 1;
        refresh_page(nav, r);
        return;
    }
    pages_leave(r);
}

/* ---- the loader's own window: keyboard and caution box (ABI 6) ----------- */

static void put_word(uint8_t *at, uint64_t value)
{
    *(uint64_t *)at = value;
}

/* A stock event table copied for the loader's own window: the events in
 * `swap` get the core's action and the navigation given, guard none; the
 * help event does nothing; every other event stays the engine's own. */
struct event_swap {
    uint32_t code;       /* the event, or 0 for the action below */
    uint64_t stock;      /* an action to replace wherever it is, or 0 */
    uint64_t action;
    uint32_t next;
};

static void copy_events(uint8_t *to, const uint8_t *from, uint32_t count,
                        const struct event_swap *swap, uint32_t swaps)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    for (uint32_t n = 0; n < count * NLR_MENU_EVENT_BYTES; n++)
        to[n] = from[n];
    for (uint32_t k = 0; k < count; k++) {
        uint8_t *event = to + k * NLR_MENU_EVENT_BYTES;
        uint32_t code = *(const uint32_t *)event;
        uint64_t action = *(const uint64_t *)(event + NLR_MENU_EVENT_ACTION);
        for (uint32_t w = 0; w < swaps; w++) {
            if (swap[w].code ? code != swap[w].code : action != swap[w].stock)
                continue;
            put_word(event + NLR_MENU_EVENT_ACTION, swap[w].action);
            put_word(event + NLR_MENU_EVENT_GUARD, 0);
            *(uint32_t *)(event + NLR_MENU_EVENT_NEXT) = swap[w].next;
            break;
        }
        if (p->input_help && code == p->input_help) {
            put_word(event + NLR_MENU_EVENT_ACTION, 0);
            put_word(event + NLR_MENU_EVENT_GUARD, 0);
            *(uint32_t *)(event + NLR_MENU_EVENT_NEXT) = p->stay_next;
        }
    }
}

/* The loader's own window record, written whole: the template's type and
 * parent, the handler block and page given, and nothing of the last use --
 * the window record keeps the cursor (+0x32) and the visible rows and the
 * scroll of its last build, and a cursor on the caution box's No would
 * index past the keyboard's one item. Written only while the window is
 * neither shown nor in the history; the type goes in last. */
static void own_window(uint8_t *entry, const uint8_t *template,
                       const void *handlers, const void *page)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    for (uint32_t n = 0; n < NLR_MENU_WINDOW_BYTES; n++)
        entry[n] = 0;
    put_word(entry + NLR_MENU_WINDOW_PARENT,
             *(const uint64_t *)(template + NLR_MENU_WINDOW_PARENT));
    put_word(entry + NLR_MENU_WINDOW_HANDLERS, (uint64_t)(uintptr_t)handlers);
    put_word(entry + NLR_MENU_WINDOW_PAGE, (uint64_t)(uintptr_t)page);
    *(uint16_t *)(entry + NLR_MENU_WINDOW_ID) = (uint16_t)p->input_window;
    __atomic_store_n((uint16_t *)entry, *(const uint16_t *)template, __ATOMIC_RELEASE);
}

/* The caution box's records: the stock popup's page on the core's items
 * and event tables -- Yes and No are the core's, MENU and back give up. */
static void caution_install(const struct nlr_menu_page *p, struct nlr_runtime *r)
{
    for (uint32_t n = 0; n < NLR_MENU_PAGE_BYTES; n++)
        r->own.caution_page[n] = p->caution_page[n];
    for (uint32_t n = 0; n < 2u * NLR_MENU_ITEM_BYTES; n++)
        r->own.caution_items[n] = p->caution_items[n];
    put_word(r->own.caution_page + NLR_MENU_PAGE_ITEMS,
             (uint64_t)(uintptr_t)r->own.caution_items);
    put_word(r->own.caution_page + NLR_MENU_PAGE_EVENTS,
             (uint64_t)(uintptr_t)r->own.caution_tables);
    const struct event_swap swap[] = {
        {0, p->caution_yes, (uint64_t)(uintptr_t)nlr_caution_yes_action, p->back_nav},
        {0, p->caution_no, (uint64_t)(uintptr_t)nlr_caution_no_action, p->back_nav},
        {p->input_menu, 0, (uint64_t)(uintptr_t)nlr_own_cancel_action, p->back_nav},
        {p->input_back, 0, (uint64_t)(uintptr_t)nlr_own_cancel_action, p->back_nav},
    };
    const uint32_t counts[2] = {p->caution_count_yes, p->caution_count_no};
    for (uint32_t k = 0; k < 2; k++) {
        copy_events(r->own.caution_events[k],
                    (const uint8_t *)(uintptr_t)p->caution_tables[k], counts[k],
                    swap, sizeof swap / sizeof swap[0]);
        r->own.caution_tables[k] = (uint64_t)(uintptr_t)r->own.caution_events[k];
    }
    r->own.caution_handlers[0] = (uint64_t)(uintptr_t)nlr_caution_enter;
    for (uint32_t k = 1; k < NLR_MENU_HANDLERS; k++)
        r->own.caution_handlers[k] = p->caution_handlers[k];
}

/* Install the loader's own window, once per boot, from the Setup page's
 * open record: no window is built on NLoader's page record then. The
 * record moves into the runtime first and both of the page's windows
 * follow it; only then does the entry it leaves take the keyboard's
 * window. A table that is not the one the build left (a window not on the
 * page record) gets nothing, and ui_input and ui_caution keep answering
 * that there is none. */
static void own_install(const struct nlr_menu_page *p, struct nlr_runtime *r)
{
    if (__atomic_load_n(&r->own.ready, __ATOMIC_ACQUIRE) ||
        !nlr_menu_input_available(p))
        return;
    uint8_t *entry = p->page_record;
    uint8_t *windows[2] = {p->page_window, (uint8_t *)(uintptr_t)p->detail_record};
    for (uint32_t k = 0; k < 2; k++)
        if (windows[k] &&
            *(uint8_t *const *)(windows[k] + NLR_MENU_WINDOW_PAGE) != entry)
            return;
    for (uint32_t n = 0; n < NLR_MENU_PAGE_BYTES; n++)
        r->own.page_record[n] = entry[n];
    for (uint32_t k = 0; k < 2; k++)
        if (windows[k])
            put_word(windows[k] + NLR_MENU_WINDOW_PAGE,
                     (uint64_t)(uintptr_t)r->own.page_record);

    /* The stock keyboard's page on an event table of the core's: save
     * hands the text over, MENU and back give up. */
    for (uint32_t n = 0; n < NLR_MENU_PAGE_BYTES; n++)
        r->own.kbd_page[n] = p->input_page[n];
    put_word(r->own.kbd_page + NLR_MENU_PAGE_EVENTS,
             (uint64_t)(uintptr_t)r->own.kbd_tables);
    r->own.kbd_tables[0] = (uint64_t)(uintptr_t)r->own.kbd_events;
    const struct event_swap swap[] = {
        {p->input_save, 0, (uint64_t)(uintptr_t)nlr_keyboard_save_action, p->back_nav},
        {p->input_menu, 0, (uint64_t)(uintptr_t)nlr_own_cancel_action, p->back_nav},
        {p->input_back, 0, (uint64_t)(uintptr_t)nlr_own_cancel_action, p->back_nav},
    };
    copy_events(r->own.kbd_events, p->input_events, p->input_event_count,
                swap, sizeof swap / sizeof swap[0]);
    r->own.kbd_handlers[0] = (uint64_t)(uintptr_t)nlr_keyboard_enter;
    for (uint32_t k = 1; k < NLR_MENU_HANDLERS; k++)
        r->own.kbd_handlers[k] = p->input_handlers[k];
    if (nlr_menu_caution_available(p)) {
        caution_install(p, r);
        r->own.caution_ready = 1;
    }

    /* Its window record names the keyboard until a caution asks for the
     * box. */
    own_window(entry, p->input_template, r->own.kbd_handlers, r->own.kbd_page);
    __atomic_store_n(&r->own.ready, 1u, __ATOMIC_RELEASE);
}

/* Open the loader's own window for the program's request `seq`: the
 * window record names the keyboard's or the caution box's records (the
 * window is neither shown nor in the history now: the request is opened
 * from the page), and a caution's page takes its buttons. A request this
 * loader cannot show (ui_caution refuses it first) stays a row. */
static void open_own(struct nlr_menu_nav *nav, struct nlr_runtime *r,
                     uint32_t seq)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    uint32_t kind = r->list.dialog;
    r->list_view = 1;
    if (kind == NLR_OWN_CAUTION && !r->own.caution_ready) {
        r->show_check = 1;
        refresh_page(nav, r);
        return;
    }
    r->list.shown = seq;
    r->own.seq = seq;
    uint8_t *entry = p->page_record;
    if (kind == NLR_OWN_CAUTION) {
        int message = r->own.buttons == NLR_CAUTION_OK;
        *(uint16_t *)(r->own.caution_page + NLR_MENU_PAGE_COUNT) = message ? 1u : 2u;
        *(uint32_t *)r->own.caution_items =
            message ? p->caution_ok_label : *(const uint32_t *)p->caution_items;
        own_window(entry, p->caution_template, r->own.caution_handlers,
                   r->own.caution_page);
    } else {
        own_window(entry, p->input_template, r->own.kbd_handlers, r->own.kbd_page);
    }
    r->own.open = kind;
    nav->next = p->input_window;
}

/* The keyboard's entry: the engine takes the program's text and limits.
 * Entered with no text entry open (the menu reopened on it after the
 * program moved on), it is an empty keyboard whose save and MENU both
 * only go back. */
void *nlr_keyboard_enter(void *window)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!window || !p->input_open || !p->input_shown)
        return window;
    int open = r && r->own.open == NLR_OWN_KEYBOARD;
    uint32_t length = open ? r->own.length : 2u * NLR_INPUT_FIELD_ROW;
    uint32_t rows = (length + NLR_INPUT_FIELD_ROW - 1u) / NLR_INPUT_FIELD_ROW;
    struct nlr_input_params params = {
        .text = open ? r->own.text : "",
        .validator = 0,
        .charset = (uint8_t)(open ? r->own.charset : NLR_INPUT_ASCII),
        .field = NLR_INPUT_FIELD,
        .pad = 0,
        .zero = 0,
        .rows = (uint16_t)(rows < 2u ? 2u : rows),
        .length = (uint16_t)length,
    };
    p->input_open(&params, window);
    p->input_shown(window, 0);
    return window;
}

/* The caution box's entry, once its widgets exist: the text in the
 * loader's slot, the message panel turned from its string to that slot,
 * and a question's cursor on No. */
void *nlr_caution_enter(void *window)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!window || !nlr_menu_caution_available(p))
        return window;
    int open = r && r->own.open == NLR_OWN_CAUTION;
    store_text(p, open ? r->own.message : "", p->caution_slot, p->caution_format);
    void *panel = p->widget_find(p->caution_panel,
                                 (uint8_t *)window + p->container_offset);
    if (panel) {
        p->panel_text(panel, 0, 1);
        p->panel_text(panel, p->caution_slot, 3);
    }
    if (open && r->own.buttons == NLR_CAUTION_YES_NO)
        p->cursor_set(window, p->caution_no_item);
    return window;
}

/* The answer to the request the loader's own window is open for, then
 * back to the page: the program's next list, the details when it ended,
 * or the page as it was when the program does not answer in time. A
 * program that took the screen keeps it: the window stays under it. The
 * page's window is opened anew, so it is built at its view's length. */
static void own_answer(struct nlr_menu_nav *nav, struct nlr_runtime *r,
                       int32_t choice)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    uint32_t seq = __atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE);
    uint32_t kind = r->own.open;
    r->own.open = 0;
    nav->next = p->back_nav;
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0) {
        r->list_view = 0;
    } else if (seq == r->own.seq && r->list_view && r->list.dialog == kind) {
        r->own.answered = seq;
        __atomic_store_n(&r->list.choice, choice, __ATOMIC_RELEASE);
        __atomic_add_fetch(&r->list.choice_seq, 1u, __ATOMIC_RELEASE);
        uint32_t why = wait_program(r, seq);
        if (why == WAIT_LIST)
            r->list_view = 1;
        else if (why == WAIT_ENDED)
            r->list_view = 0;
        else if (why == WAIT_SCREEN && p->stay_next) {
            nav->next = p->stay_next;
            return;
        }
    }
    r->show_check = 1;
    uint8_t kinds[ROW_KINDS_MAX];
    size_fresh(p, r, view_rows(p, r, kinds));
}

void nlr_keyboard_save_action(struct nlr_menu_nav *nav)
{
    const struct nlr_menu_page *p = &nlr_menu_page;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!nav)
        return;
    nav->next = p->back_nav;
    if (!r || r->own.open != NLR_OWN_KEYBOARD)
        return;
    /* The engine copies at most the entry's length and its NUL; bit 0 is
     * its validator's word, and there is none. */
    if (!(p->input_take(r->own.taken) & 1u)) {
        nav->next = p->stay_next;
        return;
    }
    uint32_t n = 0;
    while (n < r->own.length && r->own.taken[n])
        n++;
    r->own.taken[n] = 0;
    own_answer(nav, r, (int32_t)n);
}

void nlr_caution_yes_action(struct nlr_menu_nav *nav)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!nav)
        return;
    nav->next = nlr_menu_page.back_nav;
    if (r && r->own.open == NLR_OWN_CAUTION)
        own_answer(nav, r, 1);
}

/* No; a message has no No, and the keys that mean it there (left on its
 * one button) do nothing. */
void nlr_caution_no_action(struct nlr_menu_nav *nav)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!nav)
        return;
    nav->next = nlr_menu_page.back_nav;
    if (!r || r->own.open != NLR_OWN_CAUTION)
        return;
    if (r->own.buttons != NLR_CAUTION_YES_NO) {
        nav->next = nlr_menu_page.stay_next;
        return;
    }
    own_answer(nav, r, 0);
}

void nlr_own_cancel_action(struct nlr_menu_nav *nav)
{
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!nav)
        return;
    nav->next = nlr_menu_page.back_nav;
    if (r && r->own.open)
        own_answer(nav, r, (int32_t)NLR_LIST_BACK);
}
#endif

void nlr_page_row_action(struct nlr_menu_nav *nav)
{
#ifdef PAGE_READS_CARD
    if (!nav || !nav->window)
        return;
    const struct nlr_menu_page *p = &nlr_menu_page;
    struct nlr_runtime *r = nlr_runtime_attach(&nlr_services, NLR_ARENA_BYTES, 0);
#if NLR_HAS_PRIVATE_TEXT
    if (!nlr_private_text_pool_ready(r))
        return;
#endif
#if defined(NLR_STAGE_EXEC)
    if (r && late_program_list(r)) {
        r->list_view = 1;
        r->detail_view = r->recovery_view = 0;
        r->show_check = 1;
        refresh_page(nav, r);
        return;
    }
    if (r && r->pages.shown && r->list_view && r->pages.depth) {
        pages_action(nav, r, selected_row(p, nav->window));
        return;
    }
#endif
    if (r && r->recovery_view) {
        uint32_t row = selected_row(p, nav->window);
        if (row == DETAIL_BACK) {
            nlr_page_back_action(nav);
            return;
        }
        if (row == DETAIL_OPERATION)
            nlr_runtime_autoload_recover(r);
        r->show_check = 1;
        refresh_page(nav, r);
        return;
    }
#if defined(NLR_STAGE_EXEC)
    if (list_action(nav, r, r ? (int32_t)selected_row(p, nav->window) : 0))
        return;
#endif
    if (!r || r->directory_result != NLR_OK || !r->directory.count)
        return; /* Re-entry retries the directory, including SAFE_MODE. */
    uint32_t row = selected_row(p, nav->window);
#if defined(NLR_STAGE_EXEC)
    if (r->settings_view) {
        /* Keep choices visible, with an explicit refusal before writes. */
        if (row < r->settings.count) {
            uint32_t next = nlr_settings_value(r, row) + 1u;
            if (next >= nlr_settings_choices(r, row))
                next = 0;
            r->settings.save_result = nlr_settings_set(r, row, next);
        } else if (row > r->settings.count) {
            r->settings_view = 0;
            select_row(p, nav->window, 0);
        }
        r->show_check = 1;
        refresh_page(nav, r);
        return;
    }
#endif
    if (__atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0) {
        r->show_check = 1;
        refresh_page(nav, r);
        return;
    }
    if (extension_detail(r)) {
        if (row == EXT_BACK) {
            nlr_page_back_action(nav);
            return;
        }
        if (row == EXT_TOGGLE || row == EXT_EARLIER || row == EXT_LATER)
            change_extension_setting(r, row);
        else if (row == EXT_RECOVER &&
                 r->autoload.phase == NLR_AUTOLOAD_STOPPED) {
            r->recovery_view = 1;
            select_row(p, nav->window, DETAIL_OPERATION);
        }
        r->show_check = 1;
        refresh_page(nav, r);
        return;
    }
    if (r->detail_view) {
        uint8_t kinds[ROW_KINDS_MAX] = {0};
        uint32_t shown = view_rows(p, r, kinds);
        if (r->detail_shown) { /* the rows the user saw */
            shown = r->detail_shown;
            for (uint32_t k = 0; k < ROW_KINDS_MAX; k++)
                kinds[k] = r->detail_kinds[k];
        }
        if (row >= shown) { /* an empty row of a longer earlier build */
            r->show_check = 1;
            refresh_page(nav, r);
            return;
        }
        uint32_t kind = kinds[row];
        if (kind == ROW_SETTINGS) {
            r->settings_view = 1;
            select_row(p, nav->window, 0);
            r->show_check = 1;
            refresh_page(nav, r);
            return;
        }
        if (kind == ROW_BACK) {
            nlr_page_back_action(nav);
            return;
        }
        if (kind == ROW_OPERATION) {
#if defined(NLR_STAGE_EXEC) || defined(NLR_STAGE_PREPARE_ONLY)
            if (r->directory.entries[r->checked].kind == NLR_KIND_FOREGROUND) {
                uint32_t mode;
#ifdef NLR_STAGE_EXEC
                mode = 2;
#else
                mode = 1;
#endif
                enum detail_operation operation = detail_operation_kind(r);
                uint32_t list_seq = __atomic_load_n(&r->list.seq, __ATOMIC_ACQUIRE);
                (void)list_seq;
                int result;
                if (operation == DETAIL_PROGRAM && mode == 2)
                    result = nlr_runtime_open_app(r, r->checked);
                else if (operation == DETAIL_PROGRAM)
                    result = nlr_runtime_start_program(r, r->checked, mode);
                else if (operation == DETAIL_PROBE)
                    result = nlr_runtime_start_probe(r, r->checked, mode);
                else if (!r->program_pending && !r->probe_pending)
                    result = nlr_runtime_check(r, r->checked);
                else
                    result = NLR_NOT_READY; /* contradictory ownership; do nothing */
#ifdef NLR_STAGE_EXEC
                if (result == NLR_SHELL_OPENED)
                    return; /* the menu is closing: the shell has the screen */
                /* A foreground program shows a list, takes the screen or
                 * ends: the page follows it for a moment. A program that
                 * takes the screen and the buttons leaves the page as it is
                 * (drawing it again would only move the GUI to another of
                 * its buffers under the program). */
                if (result == NLR_OK && operation == DETAIL_PROGRAM && p->stay_next) {
                    follow_program(nav, r, list_seq);
                    return;
                }
#endif
                if (result == NLR_OK) {
                    shown = view_rows(p, r, kinds);
                    select_row(p, nav->window,
                               shown > 2 && kinds[1] == ROW_STATUS ? 1 : 0);
                }
            } else
#endif
                nlr_runtime_check(r, r->checked);
        }
    } else {
        if (row >= r->directory.count || row >= p->row_count)
            return;
        r->list_cursor = row;
        nlr_runtime_check(r, row);
        r->detail_view = 1;
        r->status_kept = 0;
        r->settings_view = 0;
        r->settings.entry = 0; /* read them again with the details */
#if defined(NLR_STAGE_EXEC)
        nlr_settings_load(r); /* before sizing: Settings is a details row */
#endif
        if (p->detail_next) {
            /* The details open in their own window, built fresh; the list
             * keeps its cursor in its own. */
            uint8_t kinds[ROW_KINDS_MAX];
            r->show_check = 1;
            r->detail_fresh = 1;
            size_fresh(p, r, view_rows(p, r, kinds));
            nav->next = p->detail_next;
            return;
        }
        select_row(p, nav->window, DETAIL_OPERATION);
    }
    r->show_check = 1;
    refresh_page(nav, r);
#else
    (void)nav;
#endif
}

/* The input hook forwards a genuine MENU release only as a loader-owned
 * notification. The guarded native row event executes here on the menu task,
 * never draws from SWSRV, and can show the list while SDK calls still drain. */
int32_t nlr_page_exit_guard(void)
{
#ifdef PAGE_READS_CARD
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    return r && __atomic_load_n(&r->exit_notify, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&r->exit_release_seen, __ATOMIC_ACQUIRE);
#else
    return 0;
#endif
}

void nlr_page_exit_action(struct nlr_menu_nav *nav)
{
#ifdef PAGE_READS_CARD
    if (!nav || !nav->window)
        return;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
    if (!r || !__atomic_load_n(&r->exit_release_seen, __ATOMIC_ACQUIRE) ||
        !__atomic_exchange_n(&r->exit_notify, 0u, __ATOMIC_ACQ_REL))
        return;
    __atomic_store_n(&r->exit_release_seen, 0u, __ATOMIC_RELEASE);
    r->recovery_view = 0;
    r->show_check = 1;
    if (__atomic_load_n(&r->exit_uncertain, __ATOMIC_ACQUIRE)) {
        r->detail_view = 1;
        if (nlr_menu_page.detail_next && !on_details(&nlr_menu_page, nav->window)) {
            uint8_t kinds[ROW_KINDS_MAX];
            r->detail_fresh = 1;
            size_fresh(&nlr_menu_page, r, view_rows(&nlr_menu_page, r, kinds));
            nav->next = nlr_menu_page.detail_next;
            return;
        }
        select_row(&nlr_menu_page, nav->window, DETAIL_RESULT);
    } else {
        r->detail_view = 0;
        if (on_details(&nlr_menu_page, nav->window)) {
            pop_details(nav, r);
            return;
        }
        select_row(&nlr_menu_page, nav->window, r->list_cursor);
    }
    refresh_page(nav, r);
#else
    (void)nav;
#endif
}

static void open_pages(struct nlr_menu_nav *nav, uint32_t kind)
{
#ifdef PAGE_READS_CARD
    const struct nlr_menu_page *p = &nlr_menu_page;
    (void)nav;
    (void)kind;
    if (!p->page_count)
        return;
    struct nlr_runtime *r = nlr_runtime_attach(&nlr_services, NLR_ARENA_BYTES, 0);
#if NLR_HAS_PRIVATE_TEXT
    if (!nlr_private_text_pool_ready(r)) {
        size_page(p, r, 1); /* the entry shows its one status row */
        return;
    }
#endif
#if defined(NLR_STAGE_EXEC)
    /* No window is built on the page record now: this is the Setup page's
     * open record. */
    if (r)
        own_install(p, r);
#endif
    if (r && !r->show_check &&
        __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) == 0) {
        /* What the entry will show: the list, read now so the page is built
         * with its rows; the entry reads it again in its own order. */
        r->detail_view = 0;
        nlr_runtime_read_directory(r);
        r->recovery_view = r->autoload.store &&
                           r->autoload.phase == NLR_AUTOLOAD_STOPPED;
    }
#if defined(NLR_STAGE_EXEC)
    /* The page the row stands for, first of its stack: built now, so the
     * page is sized for it before the dispatcher builds the window. */
    if (r && nlr_menu_setup.pages && nlr_menu_rows_available(p) &&
        !(r->list_view && !r->pages.shown &&
          __atomic_load_n(&r->load.state, __ATOMIC_ACQUIRE) != 0)) {
        pages_reset(r, kind);
        pages_build(r);
    }
#endif
    uint8_t kinds[ROW_KINDS_MAX];
    if (r)
        size_fresh(p, r, view_rows(p, r, kinds));
    else
        size_page(p, r, 1);
#else
    (void)nav;
    (void)kind;
#endif
}

/* NLoader's row: its root page (the switch, Plugin settings, About). */
void nlr_page_open_action(struct nlr_menu_nav *nav)
{
#if defined(NLR_STAGE_EXEC)
    open_pages(nav, PAGE_ROOT);
#else
    open_pages(nav, 0);
#endif
}

/* The Apps row: the list of applications. Without the loader's pages
 * (stages before execution) it opens what NLoader's row opens. */
void nlr_page_open_apps_action(struct nlr_menu_nav *nav)
{
#if defined(NLR_STAGE_EXEC)
    open_pages(nav, PAGE_APPS);
#else
    open_pages(nav, 0);
#endif
}

/* The Setup record names the build's own arrays from their first item
 * (Apps shown) or from their second (Apps left out at this boot); anything
 * else is not a layout this build made. */
uint32_t nlr_setup_layout(const struct nlr_menu_setup *s)
{
    if (!s || !s->apps_first || !s->fields || !s->items)
        return NLR_SETUP_LAYOUT_UNKNOWN;
    uint64_t items = *(const volatile uint64_t *)s->fields;
    uint64_t own = (uint64_t)(uintptr_t)s->items;
    if (items == own)
        return NLR_SETUP_APPS_SHOWN;
    if (items == own + NLR_MENU_ITEM_BYTES)
        return NLR_SETUP_APPS_HIDDEN;
    return NLR_SETUP_LAYOUT_UNKNOWN;
}

/* Rows of the page in `layout`: the stock rows, the NLoader row, and the
 * Apps row when it is shown. */
static uint32_t setup_rows(const struct nlr_menu_setup *s, uint32_t layout)
{
    if (layout == NLR_SETUP_LAYOUT_UNKNOWN)
        return s->stock_rows;
    return s->stock_rows + 1u + (layout == NLR_SETUP_APPS_SHOWN);
}

uint32_t nlr_setup_cursor_to_stock(const struct nlr_menu_setup *s,
                                   uint32_t layout, uint32_t row)
{
    if (!s || !s->stock_rows)
        return 0;
    if (layout == NLR_SETUP_LAYOUT_UNKNOWN)
        return row < s->stock_rows ? row : 0u;
    uint32_t apps = layout == NLR_SETUP_APPS_SHOWN;
    uint32_t entry = s->entry_index + apps;
    if (apps && row == 0)
        return 0;
    if (row == entry)
        return s->version_row;
    if (row >= setup_rows(s, layout))
        return 0;
    return row - apps - (row > entry);
}

uint32_t nlr_setup_cursor_from_stock(const struct nlr_menu_setup *s,
                                     uint32_t layout, uint32_t stock)
{
    if (!s || stock >= s->stock_rows)
        return 0;
    if (layout == NLR_SETUP_LAYOUT_UNKNOWN)
        return stock;
    uint32_t apps = layout == NLR_SETUP_APPS_SHOWN;
    if (apps && stock == 0)
        return 0;
    return stock + apps + (stock >= s->entry_index);
}

uint32_t nlr_setup_cursor_save(uint32_t id, uint32_t row)
{
    const struct nlr_menu_setup *s = &nlr_menu_setup;
    if (!s->cursor_set)
        return 0;
    if (s->cursor_setting && id == s->cursor_setting)
        row = nlr_setup_cursor_to_stock(s, nlr_setup_layout(s), row);
    return s->cursor_set(id, row);
}

uint32_t nlr_setup_cursor_restore(uint32_t id)
{
    const struct nlr_menu_setup *s = &nlr_menu_setup;
    if (!s->cursor_get)
        return 0;
    uint32_t value = s->cursor_get(id);
    if (!s->cursor_setting || id != s->cursor_setting)
        return value;
    uint32_t layout = nlr_setup_layout(s);
    /* The window record still has the cursor and scroll the menu closed
     * with (what the save stored, before mapping), until the restore
     * writes them below. */
    if (s->window && layout != NLR_SETUP_LAYOUT_UNKNOWN) {
        uint32_t last =
            (uint32_t)*(const volatile uint16_t *)(s->window + s->cursor_offset) +
            *(const volatile uint16_t *)(s->window + s->scroll_offset);
        if (last < setup_rows(s, layout) &&
            nlr_setup_cursor_to_stock(s, layout, last) == value)
            return last;
    }
    return nlr_setup_cursor_from_stock(s, layout, value);
}

/* At a boot whose NLoader switch is off, the Apps row is left out of the
 * Setup page before anyone opened the menu: the page record (RAM) starts
 * one item and one event pointer later and counts one row fewer, which
 * the firmware reads only when it builds the page. Once the menu was
 * opened the saved Setup cursor counts rows as they were, so a switch
 * turned off from the page takes effect at the next power-on. Only the
 * build's own arrays are moved, and only once. */
void nlr_pages_directory_read(struct nlr_runtime *r)
{
#if defined(NLR_STAGE_EXEC)
    const struct nlr_menu_setup *s = &nlr_menu_setup;
    if (!r || r->pages.visited || r->pages.apps_hidden || !s->apps_first ||
        !s->fields || !s->items || r->directory_result != NLR_DISABLED ||
        r->directory.error != NLR_MF_SWITCHED_OFF)
        return;
    /* Only while live view is up, or while the Setup window is not built:
     * the record is three words the firmware reads when it builds the page,
     * and a menu being built while they change -- or one already built from
     * them -- would give each row its neighbour's actions. The Z 8 reads
     * the card on the menu task between its events, so no build runs
     * meanwhile; the window's built-rows table says whether Setup is up
     * (null before the menu builds it and after it leaves it; Z8 QEMU). */
    const struct nlr_platform_services *pl = r->load.svc ? r->load.svc->platform : 0;
    int screen = nlr_platform_find_table(pl, "gui.screen.current");
    int live = screen >= 0 &&
        nlr_platform_crc32((const volatile uint8_t *)(uintptr_t)pl->tables[screen].address,
                           pl->tables[screen].size) == pl->tables[screen].crc;
    uint32_t table = nlr_menu_page.widget_table;
    int unbuilt = s->window && table &&
        *(const volatile uint64_t *)(s->window + table) == 0;
    if (!live && !unbuilt)
        return;
    uint8_t *f = s->fields;
    uint64_t items = *(volatile uint64_t *)f;
    uint64_t pointers = *(volatile uint64_t *)(f + 8);
    uint16_t count = *(volatile uint16_t *)(f + 16);
    if (items != (uint64_t)(uintptr_t)s->items || count < 2u)
        return;
    *(volatile uint64_t *)(f + 8) = pointers + 8u;
    *(volatile uint16_t *)(f + 16) = (uint16_t)(count - 1u);
    *(volatile uint64_t *)f = items + NLR_MENU_ITEM_BYTES;
    /* A cursor the menu already restored into the unbuilt window counted
     * the Apps row; it now names the same row one place up (Apps itself
     * becomes the stock first row). Restored later, it is mapped against
     * the new layout anyway. */
    if (s->cursor_setting && s->window) {
        volatile uint16_t *cursor = (volatile uint16_t *)(uintptr_t)(s->window + s->cursor_offset);
        volatile uint16_t *scroll = (volatile uint16_t *)(uintptr_t)(s->window + s->scroll_offset);
        uint32_t row = (uint32_t)*cursor + *scroll;
        *scroll = 0;
        *cursor = (uint16_t)(row ? row - 1u : 0u);
    }
    r->pages.apps_hidden = 1;
    r->pages.master = 2;
#else
    (void)r;
#endif
}

void nlr_page_back_action(struct nlr_menu_nav *nav)
{
#ifdef PAGE_READS_CARD
    if (!nav || !nav->window)
        return;
    struct nlr_runtime *r = nlr_runtime_find(&nlr_services, 0);
#if defined(NLR_STAGE_EXEC)
    if (r && r->pages.shown && r->list_view && r->pages.depth) {
        pages_back(nav, r);
        return;
    }
    if (list_action(nav, r, NLR_LIST_BACK))
        return;
    if (r && r->settings_view) {
        r->settings_view = 0;
        r->show_check = 1;
        select_row(&nlr_menu_page, nav->window, 0);
        refresh_page(nav, r);
        return;
    }
#endif
    if (r && (r->detail_view || r->recovery_view)) {
        r->recovery_view = 0;
        r->detail_view = 0;
        r->show_check = 1;
        if (on_details(&nlr_menu_page, nav->window)) {
            pop_details(nav, r);
            return;
        }
        select_row(&nlr_menu_page, nav->window, r->list_cursor);
        refresh_page(nav, r);
    }
#else
    (void)nav;
#endif
}
