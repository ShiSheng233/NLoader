#include "nlr/resource.h"

#define NLR_RESOURCE_ELEMENT_BYTES 0x44u
#define NLR_RESOURCE_STATIC_LABEL_MASK ((1u << 4) | (1u << 9) | (1u << 13))

static int aligned(const void *pointer, uintptr_t alignment)
{
    return pointer && !((uintptr_t)pointer & (alignment - 1u));
}

static void copy_bytes(void *destination, const void *source, uint32_t bytes)
{
    uint8_t *out = destination;
    const uint8_t *in = source;
    for (uint32_t i = 0; i < bytes; ++i)
        out[i] = in[i];
}

static int validate_events(const struct nlr_resource_clone_config *config)
{
    if (!aligned(config->event_template, 8) || !aligned(config->open_events, 4) ||
        !config->open_event_count ||
        config->open_event_count > NLR_RESOURCE_EVENT_MAX)
        return NLR_FORMAT;
    uint32_t count = config->event_template_bytes /
                     (uint32_t)sizeof(struct nlr_resource_event);
    if (!count || count > NLR_RESOURCE_EVENT_MAX ||
        config->event_template_bytes % sizeof(struct nlr_resource_event))
        return NLR_BOUNDS;
    for (uint32_t i = 0; i < config->open_event_count; ++i) {
        if (config->open_events[i] == config->event_terminator)
            return NLR_FORMAT;
        for (uint32_t previous = 0; previous < i; ++previous)
            if (config->open_events[previous] == config->open_events[i])
                return NLR_FORMAT;
        uint32_t matches = 0;
        for (uint32_t j = 0; j < count; ++j)
            if (config->event_template[j].code == config->open_events[i])
                ++matches;
        if (matches != 1u)
            return NLR_FORMAT;
    }
    for (uint32_t i = 0; i < count; ++i) {
        const struct nlr_resource_event *event = &config->event_template[i];
        if (event->code != config->event_terminator)
            continue;
        if (i + 1u != count || event->action || event->guard ||
            event->next != config->no_jump)
            return NLR_FORMAT;
        return NLR_OK;
    }
    return NLR_BOUNDS;
}

/* This checks only declared live native objects, not guessed firmware memory.
 * Event lists and rectangle arrays are reused under the injector's lifetime
 * and compatibility contract; the adapter does not change their contents. */
static int validate_original(const struct nlr_resource_clone_config *config)
{
    if (!config->allocator || !config->allocator->release)
        return NLR_NOT_READY;
    if (!aligned(config->window, 8) || !aligned(config->original_page, 8) ||
        config->window_bytes < sizeof(struct nlr_resource_window) ||
        config->page_bytes < sizeof(struct nlr_resource_page))
        return NLR_BOUNDS;
    const struct nlr_resource_page *page = config->original_page;
    if (config->window->category != 2 || !(page->flags & 0x80000000u) ||
        page->v1_elements || !page->item_count ||
        !aligned(page->items, 4) || !aligned(page->events, 8) ||
        !aligned(page->elements, 4) || !aligned(page->layout, 8))
        return NLR_FORMAT;
    if (config->items_bytes / sizeof(struct nlr_resource_item) < page->item_count ||
        config->event_pointers_bytes / sizeof(*page->events) < page->item_count ||
        config->layout_bytes < sizeof(struct nlr_resource_layout) ||
        config->elements_bytes < NLR_RESOURCE_ELEMENT_BYTES)
        return NLR_BOUNDS;
    if (!page->layout->rows || page->visible_rows != page->layout->rows ||
        !aligned(page->layout->row_rectangles, 2) ||
        !aligned(page->layout->inner_rectangles, 2) ||
        !aligned(page->layout->value_rectangles, 2) ||
        (page->layout->extra_count &&
         !aligned(page->layout->extra_rectangles, 2)))
        return NLR_FORMAT;
    if (!config->string_count || !config->event_terminator || !config->no_jump ||
        (config->item_template.words[4] & NLR_RESOURCE_STATIC_LABEL_MASK))
        return NLR_FORMAT;
    int event_result = validate_events(config);
    if (event_result != NLR_OK)
        return event_result;
    for (uint32_t i = 0; i < page->item_count; ++i) {
        if (!aligned(page->events[i], 8))
            return NLR_FORMAT;
    }
    const uint8_t *elements = page->elements;
    uint32_t records = config->elements_bytes / NLR_RESOURCE_ELEMENT_BYTES;
    for (uint32_t i = 0; i < records; ++i) {
        if (!nlr_le32(elements + i * NLR_RESOURCE_ELEMENT_BYTES + 4))
            return NLR_OK;
    }
    return NLR_BOUNDS;
}

int32_t nlr_resource_clone_ready(struct nlr_resource_clone *clone,
                                 uint32_t target_context_offset)
{
    if (!clone || target_context_offset > sizeof(struct nlr_resource_window) - 8u)
        return NLR_NOT_READY;
    int result = validate_original(&clone->config);
    if (result != NLR_OK)
        return result;
    const volatile uint8_t *context = (const volatile uint8_t *)clone->config.window +
                                      target_context_offset;
    for (uint32_t n = 0; n < 8u; n++)
        if (context[n])
            return NLR_BUSY;
    const struct nlr_resource_page *expected = clone->config.original_page;
    if (clone->published_count) {
        if (clone->published_count > NLR_RESOURCE_CLONE_MAX)
            return NLR_BOUNDS;
        const struct nlr_resource_retained *last = &clone->retained[clone->published_count - 1u];
        if (!last->allocation || last->page != last->allocation)
            return NLR_REFUSED;
        expected = last->page;
    }
    return clone->config.window->page == expected ? NLR_OK : NLR_REFUSED;
}

int32_t nlr_resource_clone_publish(void *context,
                                  const struct nlr_menu_test_item *item)
{
    if (!context || !item)
        return NLR_FORMAT;
    struct nlr_resource_clone *clone = context;
    if (clone->published_count > NLR_RESOURCE_CLONE_MAX)
        return NLR_BOUNDS;
    const struct nlr_resource_clone_config *config = &clone->config;
    int result = validate_original(config);
    if (result != NLR_OK)
        return result;
    if (item->label_id >= config->string_count)
        return NLR_BOUNDS;

    const struct nlr_resource_page *source = config->original_page;
    if (clone->published_count) {
        const struct nlr_resource_retained *last =
            &clone->retained[clone->published_count - 1u];
        if (!last->allocation || last->page != last->allocation)
            return NLR_REFUSED;
        source = last->page;
    }
    if (config->window->page != source)
        return NLR_REFUSED;
    if (source->item_count != config->original_page->item_count +
                              clone->published_count)
        return NLR_REFUSED;
    for (uint32_t i = 0; i < source->item_count; ++i) {
        if (source->items[i].words[6] == item->item_id)
            return NLR_REFUSED;
    }
    if (clone->published_count == NLR_RESOURCE_CLONE_MAX)
        return NLR_BUSY;
    if (source->item_count == UINT16_MAX)
        return NLR_BOUNDS;

    uint32_t count = (uint32_t)source->item_count + 1u;
    uint32_t pointers_bytes = count * (uint32_t)sizeof(*source->events);
    uint32_t items_bytes = count * (uint32_t)sizeof(*source->items);
    /* Page, event and event-pointer array are naturally 8-byte aligned;
     * items follow them at 4-byte alignment. One exact owner for all parts. */
    uint32_t event_bytes = config->event_template_bytes -
                          config->open_event_count * (uint32_t)sizeof(struct nlr_resource_event);
    uint32_t bytes = (uint32_t)sizeof(struct nlr_resource_page) +
                     event_bytes + pointers_bytes + items_bytes;
    void *allocation = nlr_alloc_whole(config->allocator, bytes);
    if (!allocation || !aligned(allocation, 8)) {
        if (allocation)
            config->allocator->release(allocation);
        return NLR_NOT_READY;
    }
    uint8_t *storage = allocation;
    struct nlr_resource_page *page = allocation;
    struct nlr_resource_event *event =
        (void *)(storage + sizeof(*page));
    const struct nlr_resource_event **events =
        (void *)(storage + sizeof(*page) + event_bytes);
    struct nlr_resource_item *items = (void *)((uint8_t *)events + pointers_bytes);
    copy_bytes(page, source, sizeof(*page));
    copy_bytes(items, source->items,
               (uint32_t)source->item_count * sizeof(*items));
    copy_bytes(events, source->events,
               (uint32_t)source->item_count * sizeof(*events));
    copy_bytes(&items[count - 1u], &config->item_template, sizeof(*items));
    items[count - 1u].words[0] = item->label_id;
    items[count - 1u].words[6] = item->item_id;
    /* Match the existing hook-only convention: an opening code must fall
     * through to the stock terminator. A matching null-action opening
     * record still clears the native LCD before its no-jump result. */
    uint32_t event_count = config->event_template_bytes / (uint32_t)sizeof(*event);
    uint32_t copied = 0;
    for (uint32_t i = 0; i < event_count; ++i) {
        int opening = 0;
        for (uint32_t j = 0; j < config->open_event_count; ++j) {
            if (config->event_template[i].code == config->open_events[j]) {
                opening = 1;
                break;
            }
        }
        if (!opening)
            copy_bytes(&event[copied++], &config->event_template[i], sizeof(*event));
    }
    events[count - 1u] = event;
    page->items = items;
    page->events = events;
    page->item_count = (uint16_t)count;

    struct nlr_resource_retained *retained =
        &clone->retained[clone->published_count];
    retained->allocation = allocation;
    retained->bytes = bytes;
    retained->item_id = item->item_id;
    retained->page = page;
    ++clone->published_count;
    /* Single root publication. Menu-task quiescence is a caller obligation;
     * release ordering does not turn this into cross-task GUI dispatch. */
    __atomic_store_n(&config->window->page, page, __ATOMIC_RELEASE);
    return NLR_OK;
}
