#ifndef NLR_MENU_H
#define NLR_MENU_H

#include <stddef.h>
#include <stdint.h>

/* Menu platform addresses and the entry-row prefill, injected by the
 * generated bindings from the profile's [menu.text_platform]. Core code
 * reads this table; it never holds menu addresses itself. */
struct nlr_menu_prefill {
    uint64_t descriptor_base; /* 300 × slot_stride descriptors */
    uint32_t slot_stride;     /* descriptor stride (0x18) */
    uint64_t buffer_base;     /* original writer's initialized RAM buffers */
    uint32_t buffer_stride;
    uint64_t font_cache_base; /* style × 0x10 cache records */
    uint64_t font_record_base;
    uint32_t entry_slot;      /* the slot the entry label binds to */
    uint32_t entry_style;
    const char *text;         /* NUL-terminated label, lives in the blob */
    uint64_t prefill_call_site; /* informational: the patched init-tail site */
    uint64_t return_target;     /* the trampoline's tail-branch target */
    void (*text_store)(const char *text, uint32_t slot, uint32_t style);
    /* NLoader's own page row, filled in the same pass from its own slot.
     * A null text means no page is installed in this build. New members go
     * after this point: the trampoline depends on return_target's offset. */
    uint32_t page_slot;
    uint32_t page_style;
    const char *page_text;
    /* The Setup page's Apps row, its label in a slot
     * of its own; a null text means the build has no Apps row. */
    uint32_t apps_slot;
    uint32_t apps_style;
    const char *apps_text;
};

/* Field offsets the trampoline asm relies on. */
_Static_assert(offsetof(struct nlr_menu_prefill, return_target) == 0x48,
               "trampoline offset ABI");

/* Called from the init tail through the retargeted branch; writes the
 * entry-row label into the runtime text platform, then the trampoline
 * tail-branches to the original callee with the saved arguments. */
void nlr_menu_prefill_body(void);

/* The argument-preserving trampoline the branch patch targets. */
void nlr_menu_prefill_trampoline(void);

/* NLoader's own page, injected by the generated menu data when the profile
 * declares it and zero otherwise. The ids come from the cloned stock page
 * (the title element's control id, the row item's id); the functions are
 * the stock widget lookup, slot store, slot binding and visibility setter,
 * so the firmware keeps owning the widgets, the text buffers and the
 * redraw. */
struct nlr_menu_page {
    uint32_t title_widget;     /* control id of the title element */
    uint32_t title_slot;       /* the title's own text slot */
    uint32_t title_format;     /* format the stock title chain stores with */
    uint32_t row_widget;       /* the row item's id, which its widget carries */
    uint32_t row_slot;         /* slot the row label reads */
    uint32_t row_style;        /* style the row's text is written with */
    uint32_t container_offset; /* widget container at window + this */
    const char *title_text;    /* the entry row's text: the page is named like it */
    const char *row_text;      /* the row's prefilled label */
    void *(*widget_find)(uint32_t id, void *container);
    void (*text_store)(const char *text, uint32_t slot, uint32_t format);
    void (*text_bind)(void *widget, uint32_t slot);
    void (*widget_show)(void *widget, uint32_t visible);
    uint32_t row_count;
    const uint32_t *row_slots;
    uint32_t selected_offset;
    void (*row_hide)(void *window, uint32_t row_index, uint32_t hidden);
    /* Navigation code a row action leaves in nav->next so the dispatcher
     * enters this page again and its entry draws the result; the firmware
     * defines the value, the generated menu data carries it. */
    uint32_t reenter_next;
    /* Original menu-task refresh preserves the previous layout while slot 0
     * changes row visibility, then reflows and redraws the same window. */
    void (*page_refresh)(void *window);
    uint32_t refresh_next; /* native stay target after the synchronous refresh */
    /* The page record's item count, when the profile lets NLoader size the
     * page: the firmware builds that many rows, so a shorter view leaves no
     * rows of a longer one behind. Written before every build (the Setup
     * row's open, each re-entry, and the next fresh entry). Null keeps the
     * fixed count and the hiding. */
    uint16_t *page_count;
    /* The details' own window, opened from the list, and the navigation
     * that pops it; zero keeps the details on the list's window. */
    uint32_t detail_next;
    uint32_t back_next;
    const void *detail_record; /* the details' window record */
    /* Navigation code that leaves the page as it is after a row action (no
     * rebuild, no redraw); zero when undeclared. */
    uint32_t stay_next;
    /* The camera's own row kinds (profile `menu.page.rows`, ABI 6
     * ui_rows). The firmware builds a row from its item record, so a
     * switch or a row with a value differs in two words of it: flags at
     * +0x10 and the value at +0x14. The module's records are flash, so the
     * core points the page record's items pointer (this address; the page
     * record's flags are 0x10 before it) at a copy it owns. Zero: only
     * entries, and ui_rows asks for nothing else.
     *   switch_flags  record flags a switch adds (its > mark goes);
     *   switch_on/off the ON / OFF picture it starts from;
     *   select_flags  record flags a row with a text value adds; +0x14 is
     *                 then the text slot the value is stored in;
     *   select_format the format that value is stored with;
     *   select_style  the item styles (+0x1c) a row with a value takes --
     *                 a wider value column -- or 0 to keep the row's own;
     *   skip_flag     page flag: the cursor passes disabled rows;
     *   widget_table  window offset of the built rows' widget table;
     *   row_get       (table, row, 0): a built row's widget;
     *   switch_set    (row widget, on): the toggle switch's state;
     *   widget_enable (widget, enabled): greyed and passed by the cursor. */
    void **page_items;
    uint32_t switch_flags;
    uint32_t switch_on;
    uint32_t switch_off;
    uint32_t select_flags;
    uint32_t select_format;
    uint32_t select_style;
    uint32_t skip_flag;
    uint32_t widget_table;
    void *(*row_get)(void *table, uint32_t row, uint32_t zero);
    void (*switch_set)(void *row, uint32_t on);
    void (*widget_enable)(void *widget, uint32_t enabled);
    /* The camera's keyboard (profile `menu.page.input`, ABI 6 ui_input).
     * A window record has to sit in the window table, and the only entry
     * left is the one the page record was built into (page_record): the
     * first time the page opens, the core moves the page record into its
     * own memory, points the page's windows (page_window, detail_record)
     * at the copy and installs the keyboard's window in the entry. The
     * keyboard is a clone of a stock one (input_template, its page
     * input_page and event table input_events, input_event_count records
     * with the terminator, its handler block input_handlers): the same
     * engine and layout, the core's own enter (handler slot 0) and its
     * actions on save (input_save) and on
     * MENU and back (input_menu, input_back). Help (input_help) does
     * nothing: its text is the stock field's, and opening it would leave
     * the keyboard's window, which the core takes as giving up.
     *   input_open  (params, window): the engine takes the text and limits;
     *   input_take  (text): the text entered, bit 0 when accepted;
     *   input_shown (window, 0): what every stock keyboard's enter ends with.
     * back_nav pops the keyboard. Zero input_window: no keyboard. */
    uint8_t *page_record;
    uint8_t *page_window;
    uint32_t input_window;
    uint32_t back_nav;
    const uint8_t *input_template;
    const uint8_t *input_page;
    const uint8_t *input_events;
    uint32_t input_event_count;
    uint32_t input_save;
    uint32_t input_menu;
    uint32_t input_back;
    uint32_t input_help;
    const uint64_t *input_handlers; /* the template's handler block */
    void (*input_open)(const void *params, void *window);
    uint32_t (*input_take)(char *text);
    void (*input_shown)(void *window, uint32_t zero);
    /* The stock in-place rebuild of a window (profile `menu.page.rebuild`):
     * page_rebuild(type, id) runs the window's leave, tears it down,
     * builds it again from its page record -- the entry runs inside --
     * and, unlike a re-entry, clears the layer its rows draw on first, so
     * a view with fewer rows leaves nothing of a longer one behind. It
     * draws without showing: present(present_source, present_a,
     * present_b) shows it, as the firmware's own lists do after a
     * rebuild, and the action then stays (stay_next). Null: the page is
     * refreshed and re-entered and never shrinks. */
    void (*page_rebuild)(uint32_t type, uint32_t id);
    void (*present)(const void *source, uint32_t a, uint32_t b);
    const void *present_source;
    uint32_t present_a;
    uint32_t present_b;
    /* The camera's caution box (profile `menu.page.caution`, ABI 6
     * ui_caution), on the keyboard's window id: a clone of a stock Yes / No
     * popup (caution_template; its page caution_page, two item records
     * caution_items, each with its own event table, caution_tables, of
     * caution_count_yes / caution_count_no records with the terminator;
     * handler block caution_handlers). The core's entry (handler slot 0)
     * stores the text in caution_slot (caution_format) and turns the box's
     * message panel (widget caution_panel) from its string to that slot
     * with panel_text(panel, slot, mode): through mode 1, as the panel
     * cannot go from a string (2) to an 8-bit slot (3) directly. The
     * template's Yes and No actions (caution_yes, caution_no) become the
     * core's in the copies; input_menu and input_back give up. A message
     * has one button, labelled caution_ok_label; a question starts on No
     * (cursor_set(window, caution_no_item)). Zero caution_template: none. */
    const uint8_t *caution_template;
    const uint8_t *caution_page;
    const uint8_t *caution_items;
    const uint64_t *caution_tables;
    uint32_t caution_count_yes;
    uint32_t caution_count_no;
    const uint64_t *caution_handlers;
    uint64_t caution_yes;
    uint64_t caution_no;
    uint32_t caution_panel;
    uint32_t caution_slot;
    uint32_t caution_format;
    uint32_t caution_ok_label;
    uint32_t caution_no_item;
    void (*panel_text)(void *panel, uint32_t slot, uint32_t mode);
    void (*cursor_set)(void *window, uint32_t item);
    /* widget_enable's second argument means "disabled" (profile
     * `menu.page.rows.widget_enable_inverted`): the core passes 1 to grey
     * a row instead of 0. */
    uint32_t widget_enable_inverted;
};

/* An item record of the firmware's menu pages, and the two words of it a
 * row's value lives in. */
#define NLR_MENU_ITEM_BYTES  44u
#define NLR_MENU_ITEM_FLAGS  0x10u
#define NLR_MENU_ITEM_VALUE  0x14u
#define NLR_MENU_ITEM_STYLE  0x1cu  /* two u16 item styles, one per direction */
#define NLR_MENU_ITEM_MARK   0x40u  /* flag: the row's > mark */
/* The page record's items pointer, and its flags word that far before it. */
#define NLR_MENU_PAGE_ITEMS  0x10u
/* The rest of the records the keyboard is built from: a page record and
 * its per-item event-table pointers, a window record (type, id, parent,
 * handler block, page) and its five-slot handler block, an event record
 * (code, action, guard, next). */
#define NLR_MENU_PAGE_BYTES     80u
#define NLR_MENU_PAGE_EVENTS    0x18u
#define NLR_MENU_PAGE_COUNT     0x20u
#define NLR_MENU_WINDOW_BYTES   96u
#define NLR_MENU_WINDOW_ID      0x2u
#define NLR_MENU_WINDOW_PARENT  0x8u
#define NLR_MENU_WINDOW_HANDLERS 0x28u
#define NLR_MENU_WINDOW_PAGE    0x50u
#define NLR_MENU_HANDLERS       5u
#define NLR_MENU_EVENT_BYTES    32u
#define NLR_MENU_EVENT_ACTION   0x8u
#define NLR_MENU_EVENT_GUARD    0x10u
#define NLR_MENU_EVENT_NEXT     0x18u
/* Event records a keyboard's table may have, the terminator included. */
#define NLR_INPUT_EVENTS_MAX    24u

/* The loader's own window shows one of these (runtime own.open, and the
 * program's request in list.dialog). */
#define NLR_OWN_KEYBOARD 1u
#define NLR_OWN_CAUTION  2u

/* The keyboard engine's parameter block (input_open): the text it starts
 * with, a validator (none), the characters, the field's layout, the pad a
 * delete leaves, and the rows and characters it holds. */
struct nlr_input_params {
    const char *text;
    const void *validator;
    uint8_t charset;
    uint8_t field;
    uint8_t pad;
    uint8_t zero;
    uint16_t rows;
    uint16_t length;
};
_Static_assert(sizeof(struct nlr_input_params) == 24, "keyboard engine ABI");
_Static_assert(offsetof(struct nlr_input_params, charset) == 0x10, "keyboard engine ABI");
_Static_assert(offsetof(struct nlr_input_params, rows) == 0x14, "keyboard engine ABI");
_Static_assert(offsetof(struct nlr_input_params, length) == 0x16, "keyboard engine ABI");
/* The field every stock keyboard of 36 characters and more uses: two rows
 * of 18 on screen, scrolling past two. */
#define NLR_INPUT_FIELD     10u
#define NLR_INPUT_FIELD_ROW 18u

/* Native program lists need both dynamic row construction and a stay route
 * for the worker/menu reply handshake. A fixed diagnostic page is not a
 * usable list provider, even when a native task-delay service is present. */
static inline uint32_t nlr_menu_native_list_capacity(const struct nlr_menu_page *p)
{
    return p && p->page_count && !((uintptr_t)p->page_count & 1u) &&
        p->stay_next && p->row_count && p->row_count <= 64u && p->row_slots &&
        p->row_hide && p->widget_find && p->text_store && p->text_bind &&
        p->widget_show ? p->row_count : 0;
}

/* Row slots a page of row kinds needs: a label and a value slot for each
 * of NLR_ROWS_MAX rows (menu_page.c checks the two agree). */
#define NLR_MENU_ROWS_SLOTS 64u

/* The page can draw the camera's row kinds: a native list with room for
 * a value slot per row (the upper half of its row slots), the page
 * record's items pointer, and every part of the recipe. */
static inline int nlr_menu_rows_available(const struct nlr_menu_page *p)
{
    return nlr_menu_native_list_capacity(p) >= NLR_MENU_ROWS_SLOTS &&
        p->page_items && !((uintptr_t)p->page_items & 7u) &&
        p->switch_flags && p->switch_on && p->switch_off &&
        p->select_flags && p->skip_flag && p->widget_table && p->row_get &&
        p->switch_set && p->widget_enable;
}

/* The page can open the camera's keyboard: a page whose records the core
 * prepares, the entry it moves the page record out of, and every part of
 * the clone. */
static inline int nlr_menu_input_available(const struct nlr_menu_page *p)
{
    return nlr_menu_native_list_capacity(p) && p->input_window &&
        p->page_record && !((uintptr_t)p->page_record & 7u) && p->page_window &&
        p->back_nav && p->input_template && p->input_page && p->input_events &&
        p->input_event_count && p->input_event_count <= NLR_INPUT_EVENTS_MAX &&
        p->input_save && p->input_menu && p->input_back && p->input_handlers &&
        p->input_open && p->input_take && p->input_shown;
}

/* The page can open the camera's caution box: the keyboard's window, and
 * every part of the clone. */
static inline int nlr_menu_caution_available(const struct nlr_menu_page *p)
{
    return nlr_menu_input_available(p) && p->caution_template &&
        p->caution_page && p->caution_items && p->caution_tables &&
        p->caution_count_yes && p->caution_count_yes <= NLR_INPUT_EVENTS_MAX &&
        p->caution_count_no && p->caution_count_no <= NLR_INPUT_EVENTS_MAX &&
        p->caution_handlers && p->caution_yes && p->caution_no &&
        p->caution_panel && p->caution_slot && p->caution_ok_label &&
        p->caution_no_item && p->panel_text && p->cursor_set &&
        p->widget_find;
}

/* The loader's own window. The keyboard: its entry (handler slot 0; the
 * others are the template's), and the actions of its save. The caution
 * box: its entry, and the actions of Yes (or OK) and No. Either: MENU and
 * back give up. Leaving it any other way -- the shutter, playback,
 * standby -- leaves the request open: the page shows it as a row whose
 * OK opens it again. */
void *nlr_keyboard_enter(void *window);
void *nlr_caution_enter(void *window);
struct nlr_menu_nav;
void nlr_keyboard_save_action(struct nlr_menu_nav *nav);
void nlr_caution_yes_action(struct nlr_menu_nav *nav);
void nlr_caution_no_action(struct nlr_menu_nav *nav);
void nlr_own_cancel_action(struct nlr_menu_nav *nav);

/* Longest text the original writer keeps in a slot; it clamps there and
 * adds the NUL. */
#define NLR_SLOT_TEXT_MAX 50u

/* Entry handler of NLoader's page (slot 0 of its handler block), called
 * with the page's window record once its widgets exist. Titles the page the
 * way stock pages title themselves from a text slot (store, bind, show).
 * The page rung adds a status line to the row; from load-only on the entry
 * reads the card directory (PLAN 4.3 SAFE_CHECK, MANIFEST, GATE) and the
 * rows show the directory or why it cannot be displayed. The caller ignores the
 * result; the window comes back unchanged. */
void *nlr_page_enter(void *window);
struct nlr_runtime;
/* GUI-only preparation before the original redraw constructs row widgets.
 * It uses the same current-view/longest-page rule as native row actions. */
void nlr_page_prepare_redraw(struct nlr_runtime *runtime);

/* What the stock dispatcher hands a row action: the window the event
 * arrived on, the event code, and the next window or navigation sentinel,
 * which it reads back after the action returns. */
struct nlr_menu_nav {
    void *window;
    uint32_t code;
    uint32_t next;
};
_Static_assert(offsetof(struct nlr_menu_nav, code) == 0x8, "dispatcher ABI");
_Static_assert(offsetof(struct nlr_menu_nav, next) == 0xc, "dispatcher ABI");

/* List OK checks the selected program and re-enters to show its details.
 * Details distinguish the two kinds; load-only operations only check.
 * Execution diagnostics queue the pinned worker and select the result row.
 * Result-row OK refreshes the display without starting another operation. */
void nlr_page_row_action(struct nlr_menu_nav *nav);
/* Details return to the list; the list retains the stock return target. */
void nlr_page_back_action(struct nlr_menu_nav *nav);
/* The Setup row's open records: reads the card directory and sizes the page
 * before the dispatcher builds it; the navigation is the record's own. */
void nlr_page_open_action(struct nlr_menu_nav *nav);

/* The Setup page's Apps row: opens the same page on
 * the list of applications instead of NLoader's own settings. */
void nlr_page_open_apps_action(struct nlr_menu_nav *nav);

/* The Setup page as the loader's pages see it (generated bindings):
 * `pages` when the build has the Apps row and a page of row kinds, so the
 * two rows open the loader's own pages (0 keeps the one NLoader list);
 * where the Setup record keeps the item array, the event-pointer array and
 * the count (page + 0x10; null unless the Apps row is the first row), the
 * build's own item array the record names then, and what About says. */
struct nlr_menu_setup {
    uint32_t pages;
    uint32_t apps_first;
    uint8_t *fields;
    const uint8_t *items;
    const char *version;
    const char *module;
    /* The Setup page's window record (null unless apps_first). The loader
     * may move the record's arrays while that window is not built: its
     * built-rows table (window + nlr_menu_page.widget_table) is null then.
     * This is the Z 8's case, whose boot pass runs on the menu task between
     * its events, the menu already up. */
    const uint8_t *window;
    /* The Setup cursor the firmware keeps as a raw row number in one
     * setting (0 when the profile declares none): the stock page's row
     * count, the stock index the NLoader row goes before (the count when
     * it is the last row), the stock Firmware version row NLoader is saved
     * as, the window record's cursor and scroll half-words, and the stock
     * getter and setter the redirected calls make. */
    uint32_t cursor_setting;
    uint32_t stock_rows;
    uint32_t entry_index;
    uint32_t version_row;
    uint32_t cursor_offset;
    uint32_t scroll_offset;
    uint32_t (*cursor_get)(uint32_t id);
    uint32_t (*cursor_set)(uint32_t id, uint32_t value);
};
extern const struct nlr_menu_setup nlr_menu_setup;

/* The Setup cursor. The setting always holds a
 * stock row number, so a camera flashed back to stock firmware restores a
 * row its own page has: the Apps row is saved as the stock first row,
 * NLoader as Firmware version, every other row as the stock row it shows.
 * Back, the stock first row is the Apps row (the top row stays the top
 * row) and every other number the row showing that stock row; a number
 * past the stock page is the top row. `layout` is NLR_SETUP_APPS_SHOWN or
 * NLR_SETUP_APPS_HIDDEN as the Setup record names the arrays now, or
 * NLR_SETUP_LAYOUT_UNKNOWN, where only stock numbers pass. */
#define NLR_SETUP_LAYOUT_UNKNOWN 0u
#define NLR_SETUP_APPS_SHOWN 1u
#define NLR_SETUP_APPS_HIDDEN 2u
uint32_t nlr_setup_layout(const struct nlr_menu_setup *s);
uint32_t nlr_setup_cursor_to_stock(const struct nlr_menu_setup *s,
                                   uint32_t layout, uint32_t row);
uint32_t nlr_setup_cursor_from_stock(const struct nlr_menu_setup *s,
                                     uint32_t layout, uint32_t stock);
/* The redirected stock calls. The two writers' `bl setter(id, row)` reach
 * the save, which stores the mapped row when `id` is the cursor setting;
 * the restore's `bl getter(id)` reaches the restore, which maps the value
 * back -- unless the Setup window still holds the row it was left on and
 * that row saves as this value, which keeps Apps and NLoader apart from the
 * rows they share a stock number with during one power-on. Other ids pass
 * through unchanged. */
uint32_t nlr_setup_cursor_save(uint32_t id, uint32_t row);
uint32_t nlr_setup_cursor_restore(uint32_t id);

/* Called after every directory read (core/runtime.c): at a boot whose
 * NLoader switch is off, before anyone opened the menu, the Apps row is
 * left out of the Setup page. */
void nlr_pages_directory_read(struct nlr_runtime *runtime);

/* Optional native release route: guard/action execute in the GUI dispatcher,
 * never in the combined-input worker. Only an accepted exit owns notification. */
int32_t nlr_page_exit_guard(void);
void nlr_page_exit_action(struct nlr_menu_nav *nav);

#endif
