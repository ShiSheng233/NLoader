#ifndef NLR_RESOURCE_H
#define NLR_RESOURCE_H

#include "nlr/api.h"
#include "nlr/services.h"

/* Registration only records a RAM request on the worker. The runtime calls
 * publish on the menu task after the worker is idle and its result is handed
 * off. Return NLR_OK or a negative NLR_* service result. No callback means
 * registration is unavailable. Bindings inject a verified target/config;
 * this callback contract itself contains no firmware addresses. */
struct nlr_resource_services {
    int32_t (*publish)(void *context, const struct nlr_menu_test_item *item);
    void *context;
    int32_t (*can_publish)(void *context);
};

/* The audited 64-bit native list-page layout, not camera addresses. Unknown
 * words and rectangles are preserved, never repurposed as scratch storage. */
struct nlr_resource_item {
    uint32_t words[11];
};

struct nlr_resource_event {
    uint32_t code;
    uint32_t reserved0;
    const void *action;
    const void *guard;
    uint32_t next;
    uint32_t reserved1;
};

struct nlr_resource_layout {
    uint16_t rows;
    uint8_t reserved0[6];
    const void *row_rectangles;
    const void *inner_rectangles;
    const void *value_rectangles;
    uint16_t extra_count;
    uint8_t reserved1[6];
    const void *extra_rectangles;
};

struct nlr_resource_page {
    uint32_t flags;
    uint32_t reserved0;
    const void *elements;
    const struct nlr_resource_item *items;
    const struct nlr_resource_event *const *events;
    uint16_t item_count;
    uint8_t rectangles[22];
    const void *v1_elements;
    const struct nlr_resource_layout *layout;
    uint32_t visible_rows;
    uint32_t reserved1;
};

struct nlr_resource_window {
    uint16_t category;
    uint16_t id;
    uint8_t preserved[0x4c];
    const struct nlr_resource_page *page;
    uint8_t tail[8];
};

_Static_assert(sizeof(struct nlr_resource_item) == 0x2c, "native item ABI");
_Static_assert(sizeof(struct nlr_resource_event) == 0x20, "native event ABI");
_Static_assert(offsetof(struct nlr_resource_event, action) == 8, "event action ABI");
_Static_assert(offsetof(struct nlr_resource_event, guard) == 0x10, "event guard ABI");
_Static_assert(offsetof(struct nlr_resource_event, next) == 0x18, "event next ABI");
_Static_assert(sizeof(struct nlr_resource_layout) == 0x30, "native layout ABI");
_Static_assert(sizeof(struct nlr_resource_page) == 0x50, "native page ABI");
_Static_assert(offsetof(struct nlr_resource_page, items) == 0x10, "page items ABI");
_Static_assert(offsetof(struct nlr_resource_page, events) == 0x18, "page events ABI");
_Static_assert(offsetof(struct nlr_resource_page, item_count) == 0x20, "page count ABI");
_Static_assert(offsetof(struct nlr_resource_page, layout) == 0x40, "page layout ABI");
_Static_assert(offsetof(struct nlr_resource_page, visible_rows) == 0x48, "page rows ABI");
_Static_assert(sizeof(struct nlr_resource_window) == 0x60, "native window ABI");
_Static_assert(offsetof(struct nlr_resource_window, page) == 0x50, "window page ABI");

#define NLR_RESOURCE_CLONE_MAX 8u
#define NLR_RESOURCE_EVENT_MAX 256u

/* The injector proves the pointed-to objects remain readable for this boot,
 * the item template is compatible with this window's callbacks and layout,
 * and the declared byte capacities cover the original native definitions.
 * The adapter accepts only ordinary category-2 v2 list pages with static
 * string labels; it does not acquire a runtime text slot. string_count is
 * the existing firmware bank's bound, not permission to create new strings.
 * The event terminator and no-jump value are model-injected semantics.
 * A compatible native event template retains stock navigation/back/menu
 * handlers. Declared opening events are omitted so lookup uses the stock
 * inert terminator instead of clearing the LCD for a matching open record;
 * the existing terminator must already have null action/guard and no_jump.
 * Publication must run at a menu-task safe point: no concurrent renderer,
 * event handler, worker or other publisher may consume/change the root while
 * it is replaced. The caller owns that synchronization and any rebuild. */
struct nlr_resource_clone_config {
    const struct nlr_services *allocator;
    struct nlr_resource_window *window;
    const struct nlr_resource_page *original_page;
    struct nlr_resource_item item_template;
    const struct nlr_resource_event *event_template;
    uint32_t event_template_bytes; /* exact list, including last terminator */
    const uint32_t *open_events;
    uint32_t open_event_count;
    uint32_t window_bytes;
    uint32_t page_bytes;
    uint32_t items_bytes;
    uint32_t event_pointers_bytes;
    uint32_t elements_bytes;
    uint32_t layout_bytes;
    uint32_t string_count;
    uint32_t event_terminator;
    uint32_t no_jump;
};

/* Only allocation (the exact allocator result), never page/items/events
 * subpointers, is owned. There is deliberately no release/unpublish API:
 * published references and every earlier clone remain live for the boot. */
struct nlr_resource_retained {
    void *allocation;
    uint32_t bytes;
    uint32_t item_id;
    const struct nlr_resource_page *page;
};

/* Initialize once by zeroing this stable boot-owned RAM object and assigning
 * config. Never reset, move or reconfigure it after publication. Supply this
 * object as the resource service context and the function below as publish. */
struct nlr_resource_clone {
    struct nlr_resource_clone_config config;
    struct nlr_resource_retained retained[NLR_RESOURCE_CLONE_MAX];
    uint32_t published_count;
};

int32_t nlr_resource_clone_publish(void *context,
                                  const struct nlr_menu_test_item *item);
/* GUI owner only. A live target context defers publication without failure;
 * the checked family injects its context-field offset, never a core pin. */
int32_t nlr_resource_clone_ready(struct nlr_resource_clone *clone,
                                 uint32_t target_context_offset);

#endif
