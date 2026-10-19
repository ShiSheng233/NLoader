#include "nlr/resource.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Firmware version: proven string ID 0x379 in the stock Setup page's
 * Firmware-version item (menu-ui/ui_definitions/menu_items.csv). */
#define LABEL_ID 0x379u

struct fixture {
    struct nlr_resource_clone clone;
    struct nlr_resource_window window;
    struct nlr_resource_page page;
    struct nlr_resource_layout layout;
    struct nlr_resource_item items[2];
    struct nlr_resource_event stock_events[2];
    const struct nlr_resource_event *events[2];
    struct nlr_resource_event event_template[7];
    uint32_t open_events[2];
    uint32_t elements[2][17];
    uint16_t rectangles[8][4];
    _Alignas(8) uint8_t storage[NLR_RESOURCE_CLONE_MAX][4096];
    uint32_t calls;
    uint32_t releases;
    int fail;
};

static struct fixture *active;

static int32_t allocate(uint32_t bytes, void **out)
{
    ++active->calls;
    *out = 0;
    if (active->fail == 1)
        return NLR_NOT_READY;
    assert(active->calls <= NLR_RESOURCE_CLONE_MAX);
    assert(bytes <= sizeof active->storage[0]);
    *out = active->storage[active->calls - 1u];
    if (active->fail == 2)
        return NLR_NOT_READY;
    if (active->fail == 3)
        *out = (uint8_t *)*out + 1;
    return NLR_OK;
}

static int32_t release(void *allocation)
{
    assert(allocation);
    ++active->releases;
    return NLR_OK;
}

static const struct nlr_services allocator = {
    .alloc = allocate,
    .release = release,
};

/* The allocation entry (core/exec.c) for a build without heap books: a
 * block handed over together with a failure is given back. */
void *nlr_alloc_whole(const struct nlr_services *s, uint32_t bytes)
{
    void *block = 0;
    if (s->alloc(bytes, &block) != NLR_OK || !block) {
        if (block)
            (void)s->release(block);
        return 0;
    }
    return block;
}

static void initialize(struct fixture *f)
{
    memset(f, 0, sizeof *f);
    active = f;
    memset(f->storage, 0xbd, sizeof f->storage);
    memset(&f->window, 0x51, sizeof f->window);
    memset(&f->page, 0x62, sizeof f->page);
    memset(f->items, 0x73, sizeof f->items);
    f->items[0].words[6] = 0x100;
    f->items[1].words[6] = 0x101;
    f->elements[0][1] = 1;
    f->layout.rows = 8;
    f->layout.row_rectangles = f->rectangles;
    f->layout.inner_rectangles = f->rectangles;
    f->layout.value_rectangles = f->rectangles;
    f->window.category = 2;
    f->window.page = &f->page;
    f->page.flags = 0x80000003;
    f->page.elements = f->elements;
    f->page.items = f->items;
    f->page.events = f->events;
    f->page.item_count = 2;
    f->page.v1_elements = 0;
    f->page.layout = &f->layout;
    f->page.visible_rows = 8;
    for (uint32_t i = 0; i < 2; ++i) {
        f->stock_events[i].code = 0x3bb;
        f->stock_events[i].next = 0x68c;
        f->events[i] = &f->stock_events[i];
    }
    const uint32_t codes[7] = { 0x283, 0x284, 0x285, 0x27e, 0x286, 0x28b, 0x3bb };
    for (uint32_t i = 0; i < 7; ++i) {
        f->event_template[i].code = codes[i];
        f->event_template[i].reserved0 = 0x1000 + i;
        f->event_template[i].reserved1 = 0x2000 + i;
        f->event_template[i].action = i == 6 ? 0 : f->rectangles;
        f->event_template[i].guard = i == 6 ? 0 : f->elements;
        f->event_template[i].next = i == 6 ? 0x68c : 0x68d;
    }
    f->open_events[0] = 0x286;
    f->open_events[1] = 0x28b;
    struct nlr_resource_clone_config *config = &f->clone.config;
    config->allocator = &allocator;
    config->window = &f->window;
    config->original_page = &f->page;
    config->item_template = f->items[1];
    config->item_template.words[0] = LABEL_ID;
    config->item_template.words[4] = 0x10000;
    config->event_template = f->event_template;
    config->event_template_bytes = sizeof f->event_template;
    config->open_events = f->open_events;
    config->open_event_count = 2;
    config->window_bytes = sizeof f->window;
    config->page_bytes = sizeof f->page;
    config->items_bytes = sizeof f->items;
    config->event_pointers_bytes = sizeof f->events;
    config->elements_bytes = sizeof f->elements;
    config->layout_bytes = sizeof f->layout;
    config->string_count = LABEL_ID + 1u;
    config->event_terminator = 0x3bb;
    config->no_jump = 0x68c;
}

static int owned(const struct nlr_resource_retained *owner,
                 const void *pointer, size_t bytes)
{
    uintptr_t base = (uintptr_t)owner->allocation;
    uintptr_t address = (uintptr_t)pointer;
    return address >= base && bytes <= owner->bytes &&
           address - base <= owner->bytes - bytes;
}

static void successful_publication(void)
{
    struct fixture f;
    initialize(&f);
    struct nlr_resource_window original_window = f.window;
    struct nlr_resource_page original_page = f.page;
    struct nlr_resource_item original_items[2];
    memcpy(original_items, f.items, sizeof original_items);
    const struct nlr_menu_test_item item = { LABEL_ID, 0x7ffd };
    const struct nlr_resource_services resources = {
        .publish = nlr_resource_clone_publish,
        .context = &f.clone,
    };
    assert(resources.publish(resources.context, &item) == NLR_OK);
    assert(f.calls == 1 && f.releases == 0);
    assert(f.clone.published_count == 1);
    const struct nlr_resource_retained *owner = &f.clone.retained[0];
    const struct nlr_resource_page *page = f.window.page;
    assert(page == owner->page && page == owner->allocation);
    assert(owner->item_id == item.item_id);
    assert(page->item_count == 3);
    assert(owner->bytes == 0x50 + 5 * sizeof f.event_template[0] + 3 * (8 + 0x2c));
    assert(owned(owner, page, sizeof *page));
    assert(owned(owner, page->items, 3 * sizeof *page->items));
    assert(owned(owner, page->events, 3 * sizeof *page->events));
    assert(owned(owner, page->events[2], 5 * sizeof f.event_template[0]));
    assert(!((uintptr_t)page->events & 7));
    assert(!((uintptr_t)page->events[2] & 7));
    assert(!((uintptr_t)page->items & 3));
    assert(memcmp(page->items, f.items, sizeof f.items) == 0);
    assert(page->events[0] == f.events[0]);
    assert(page->events[1] == f.events[1]);
    struct nlr_resource_item expected = f.clone.config.item_template;
    expected.words[0] = item.label_id;
    expected.words[6] = item.item_id;
    assert(memcmp(&page->items[2], &expected, sizeof expected) == 0);
    struct nlr_resource_event expected_events[5];
    memcpy(expected_events, f.event_template, 4 * sizeof *expected_events);
    expected_events[4] = f.event_template[6];
    assert(memcmp(page->events[2], expected_events, sizeof expected_events) == 0);
    /* Up/down/back/menu records retain every native word and pointer. */
    assert(memcmp(page->events[2], f.event_template, 4 * sizeof *expected_events) == 0);
    assert(memcmp(&page->events[2][4], &f.event_template[6],
                  sizeof f.event_template[6]) == 0);
    struct nlr_resource_page expected_page = original_page;
    expected_page.items = page->items;
    expected_page.events = page->events;
    expected_page.item_count = 3;
    assert(memcmp(page, &expected_page, sizeof expected_page) == 0);
    assert(memcmp(&f.page, &original_page, sizeof original_page) == 0);
    assert(memcmp(f.items, original_items, sizeof original_items) == 0);
    original_window.page = page;
    assert(memcmp(&f.window, &original_window, sizeof original_window) == 0);

    uint8_t first_snapshot[4096];
    memcpy(first_snapshot, owner->allocation, owner->bytes);
    struct nlr_menu_test_item next = { LABEL_ID, 0x7ffe };
    assert(resources.publish(resources.context, &next) == NLR_OK);
    assert(f.clone.published_count == 2 && f.calls == 2 && f.releases == 0);
    assert(f.window.page != page && f.window.page->item_count == 4);
    assert(memcmp(first_snapshot, owner->allocation, owner->bytes) == 0);
    assert(memcmp(f.window.page->items, page->items, 3 * sizeof *page->items) == 0);
    /* The first appended event is deliberately retained, not copied/free'd. */
    assert(f.window.page->events[2] == page->events[2]);
    assert(memcmp(f.window.page->events[3], expected_events, sizeof expected_events) == 0);
    const struct nlr_resource_page *latest = f.window.page;
    assert(resources.publish(resources.context, &item) == NLR_REFUSED);
    assert(resources.publish(resources.context, &next) == NLR_REFUSED);
    next.item_id = f.items[0].words[6];
    assert(resources.publish(resources.context, &next) == NLR_REFUSED);
    assert(f.calls == 2 && f.releases == 0 && f.window.page == latest);
    f.window.page = &f.page;
    next.item_id = 0x7fff;
    assert(resources.publish(resources.context, &next) == NLR_REFUSED);
    assert(f.calls == 2 && f.releases == 0);
}

static void failed_allocation(void)
{
    for (int failure = 1; failure <= 3; ++failure) {
        struct fixture f;
        initialize(&f);
        f.fail = failure;
        const struct nlr_menu_test_item item = { LABEL_ID, 0x7ffd };
        assert(nlr_resource_clone_publish(&f.clone, &item) == NLR_NOT_READY);
        assert(f.window.page == &f.page);
        assert(f.clone.published_count == 0);
        assert(f.clone.retained[0].allocation == 0);
        assert(f.calls == 1);
        assert(f.releases == (failure == 1 ? 0u : 1u));
    }
    struct fixture f;
    initialize(&f);
    struct nlr_menu_test_item item = { LABEL_ID, 0x7ffd };
    assert(nlr_resource_clone_publish(&f.clone, &item) == NLR_OK);
    const struct nlr_resource_page *published = f.window.page;
    f.fail = 1;
    ++item.item_id;
    assert(nlr_resource_clone_publish(&f.clone, &item) == NLR_NOT_READY);
    assert(f.window.page == published && f.clone.published_count == 1);
    assert(f.clone.retained[0].allocation == published && f.releases == 0);
}

static void declared_bounds_and_layout(void)
{
    struct fixture f;
    const struct nlr_menu_test_item item = { LABEL_ID, 0x7ffd };
#define REJECT(change, error) do { \
    initialize(&f); \
    change; \
    assert(nlr_resource_clone_publish(&f.clone, &item) == (error)); \
    assert(f.calls == 0 && f.releases == 0); \
    assert(f.window.page == &f.page && f.clone.published_count == 0); \
} while (0)
    REJECT(f.clone.config.window_bytes--, NLR_BOUNDS);
    REJECT(f.clone.config.page_bytes--, NLR_BOUNDS);
    REJECT(f.clone.config.items_bytes--, NLR_BOUNDS);
    REJECT(f.clone.config.event_pointers_bytes--, NLR_BOUNDS);
    REJECT(f.clone.config.layout_bytes--, NLR_BOUNDS);
    REJECT(f.clone.config.elements_bytes = 0x44, NLR_BOUNDS);
    REJECT(f.clone.config.string_count = LABEL_ID, NLR_BOUNDS);
    REJECT(f.clone.config.allocator = 0, NLR_NOT_READY);
    REJECT(f.window.category = 5, NLR_FORMAT);
    REJECT(f.page.flags = 0, NLR_FORMAT);
    REJECT(f.page.v1_elements = f.elements, NLR_FORMAT);
    REJECT(f.page.item_count = 0, NLR_FORMAT);
    REJECT(f.page.items = 0, NLR_FORMAT);
    REJECT(f.page.events = 0, NLR_FORMAT);
    REJECT(f.events[0] = 0, NLR_FORMAT);
    REJECT(f.layout.rows = 0, NLR_FORMAT);
    REJECT(f.page.visible_rows++, NLR_FORMAT);
    REJECT(f.layout.inner_rectangles = 0, NLR_FORMAT);
    REJECT(f.clone.config.item_template.words[4] = 1u << 4, NLR_FORMAT);
    REJECT(f.clone.config.item_template.words[4] = 1u << 9, NLR_FORMAT);
    REJECT(f.clone.config.item_template.words[4] = 1u << 13, NLR_FORMAT);
    REJECT(f.clone.config.event_terminator = 0, NLR_FORMAT);
    REJECT(f.clone.config.no_jump = 0, NLR_FORMAT);
    REJECT(f.clone.config.event_template = 0, NLR_FORMAT);
    REJECT(f.clone.config.event_template_bytes--, NLR_BOUNDS);
    REJECT(f.clone.config.event_template_bytes = 0, NLR_BOUNDS);
    REJECT(f.clone.config.open_events = 0, NLR_FORMAT);
    REJECT(f.clone.config.open_event_count = 0, NLR_FORMAT);
    REJECT(f.open_events[0] = 0x3bb, NLR_FORMAT);
    REJECT(f.open_events[1] = f.open_events[0], NLR_FORMAT);
    REJECT(f.event_template[6].code = 0x123, NLR_BOUNDS);
    REJECT(f.event_template[6].action = f.rectangles, NLR_FORMAT);
    REJECT(f.event_template[6].guard = f.elements, NLR_FORMAT);
    REJECT(f.event_template[6].next = 0x68d, NLR_FORMAT);
    REJECT(f.event_template[0].code = 0x3bb, NLR_FORMAT);
#undef REJECT
    initialize(&f);
    assert(nlr_resource_clone_publish(0, &item) == NLR_FORMAT);
    assert(nlr_resource_clone_publish(&f.clone, 0) == NLR_FORMAT);
    assert(f.calls == 0);
}

static void capacity_retains_every_clone(void)
{
    struct fixture f;
    initialize(&f);
    for (uint32_t i = 0; i < NLR_RESOURCE_CLONE_MAX; ++i) {
        const struct nlr_menu_test_item item = { LABEL_ID, 0x7f00 + i };
        assert(nlr_resource_clone_publish(&f.clone, &item) == NLR_OK);
        assert(f.clone.published_count == i + 1u);
        assert(f.window.page->item_count == 3u + i);
        for (uint32_t j = 0; j <= i; ++j) {
            const struct nlr_resource_retained *owner = &f.clone.retained[j];
            assert(owner->allocation == f.storage[j]);
            assert(owner->page == owner->allocation);
            assert(owner->page->item_count == 3u + j);
            assert(owner->page->items[2u + j].words[6] == 0x7f00 + j);
        }
    }
    const struct nlr_resource_page *latest = f.window.page;
    const struct nlr_menu_test_item overflow = { LABEL_ID, 0x7ff0 };
    assert(nlr_resource_clone_publish(&f.clone, &overflow) == NLR_BUSY);
    assert(f.window.page == latest);
    assert(f.calls == NLR_RESOURCE_CLONE_MAX && f.releases == 0);
}

static void active_context_defers_publication(void)
{
    struct fixture f;
    initialize(&f);
    assert(nlr_resource_clone_ready(&f.clone, 0x48) == NLR_BUSY);
    assert(f.calls == 0 && f.window.page == &f.page);
    memset((uint8_t *)&f.window + 0x48, 0, 8);
    assert(nlr_resource_clone_ready(&f.clone, 0x48) == NLR_OK);
    assert(nlr_resource_clone_ready(&f.clone, sizeof f.window) == NLR_NOT_READY);
    const struct nlr_menu_test_item item = { LABEL_ID, 0x7ffd };
    assert(nlr_resource_clone_publish(&f.clone, &item) == NLR_OK);
    assert(nlr_resource_clone_ready(&f.clone, 0x48) == NLR_OK);
    f.window.page = &f.page;
    assert(nlr_resource_clone_ready(&f.clone, 0x48) == NLR_REFUSED);
}

int main(void)
{
    successful_publication();
    failed_allocation();
    declared_bounds_and_layout();
    capacity_retains_every_clone();
    active_context_defers_publication();
    puts("resource behavior tests passed");
    return 0;
}
